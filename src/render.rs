#[allow(unused_imports)]
use crate::rules_catalog::{
    CompletionShell, RULE_CATALOG, find_rule_doc, render_shell_completions,
};
#[allow(unused_imports)]
use crate::*;
#[allow(unused_imports)]
use anyhow::{Context, Result};
#[allow(unused_imports)]
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
#[allow(unused_imports)]
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, export_regression_tests, generate_patch_plan,
    provider_from_config, run_cegis_patch_loop, synthesize_deterministic_codemod_diff,
    verify_patch_in_isolated_copy,
};
#[allow(unused_imports)]
use smg_core::{
    DeltaStats, ScanOptions, ShellMindGuardConfig, StateStore, scan_repository,
    scan_repository_with_options,
};
#[allow(unused_imports)]
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase_cached,
    analyze_codebase_cached_changed_since, collect_deep_schema_findings, collect_git_changed_files,
    compute_rule_telemetry, deps::extract_resolved_dependencies, finding_matches_layer,
};
#[allow(unused_imports)]
use smg_report::{to_cyclonedx_vex_json, to_html_graph, to_sarif_json};
#[allow(unused_imports)]
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, detect_sandbox_backend,
    verify_deep_fuzz_blocking_with_config, verify_deep_fuzz_in_sandbox,
    verify_finding_blocking_with_config, verify_findings_batch_blocking_with_config,
    verify_findings_in_sandbox_with_config,
};
#[allow(unused_imports)]
use smg_tui::{TuiLaunchConfig, run_tui};
#[allow(unused_imports)]
use std::collections::{HashMap, HashSet};
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::io::{IsTerminal, Write};
#[allow(unused_imports)]
use std::net::SocketAddr;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::process::{Command, ExitCode};
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::sync::atomic::Ordering;
#[allow(unused_imports)]
use std::time::{Duration, Instant};

pub(crate) fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

pub(crate) fn verification_status_tag(st: &VerificationStatus) -> &'static str {
    match st {
        VerificationStatus::Proven => "PROVEN",
        VerificationStatus::Mitigated => "MITIGATED",
        VerificationStatus::SuspectUnverified => "SUSPECT",
        VerificationStatus::Unbootable => "UNBOOTABLE",
    }
}

pub(crate) fn should_fail_gate(
    findings: &[LatticeFinding],
    ci: bool,
    fail_on: Option<FailSeverity>,
) -> bool {
    if let Some(threshold) = fail_on {
        let min_rank = match threshold {
            FailSeverity::Critical => 4,
            FailSeverity::High => 3,
            FailSeverity::Medium => 2,
            FailSeverity::Low => 1,
        };
        return findings
            .iter()
            .any(|f| f.status != "MITIGATED" && severity_rank(&f.severity) >= min_rank);
    }
    if ci {
        return findings.iter().any(|f| {
            f.status == "PROVEN"
                || (f.status != "MITIGATED" && (f.severity == "CRITICAL" || f.severity == "HIGH"))
        });
    }
    false
}

pub(crate) struct RenderOptions<'a> {
    pub(crate) format: OutputFormat,
    pub(crate) sarif_payload: Option<&'a str>,
    pub(crate) patch: bool,
    pub(crate) color_mode: ColorMode,
    pub(crate) output: Option<&'a Path>,
}

pub(crate) fn read_source_snippet_lines(
    canon_root: Option<&Path>,
    rel_file: &str,
    line: usize,
    cache: &mut HashMap<String, Vec<String>>,
) -> Vec<(usize, String, bool)> {
    let Some(root) = canon_root else {
        return Vec::new();
    };
    if rel_file.is_empty() || line == 0 {
        return Vec::new();
    }
    if !cache.contains_key(rel_file) {
        let lines = fs::canonicalize(root.join(rel_file))
            .ok()
            .filter(|canon| canon.starts_with(root))
            .and_then(|canon| fs::read_to_string(canon).ok())
            .map(|raw| raw.lines().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        cache.insert(rel_file.to_string(), lines);
    }
    let Some(lines) = cache.get(rel_file) else {
        return Vec::new();
    };
    if line > lines.len() {
        return Vec::new();
    }
    let start = line.saturating_sub(1).max(1);
    let end = (line + 1).min(lines.len());
    (start..=end)
        .filter_map(|ln| lines.get(ln - 1).map(|text| (ln, text.clone(), ln == line)))
        .collect()
}

pub(crate) fn guard_category_tag(guard: GuardKind) -> &'static str {
    match guard {
        GuardKind::Auth | GuardKind::OwnershipCheck | GuardKind::CsrfProtection => "AUTH/IDOR",
        GuardKind::TxLock | GuardKind::LockOrdering => "RACE/LOCK",
        GuardKind::SqlSanitizer
        | GuardKind::CmdSanitizer
        | GuardKind::PathSanitizer
        | GuardKind::SsrfSanitizer
        | GuardKind::XssSanitizer => "INJECTION",
        GuardKind::SecretPolicy | GuardKind::ConfigPolicy => "SEC/CFG",
        GuardKind::DependencyPolicy => "DEPS",
        GuardKind::ResourceCleanup | GuardKind::MemoryBounds => "ENGINE/MEM",
        GuardKind::MobilePolicy => "MOBILE",
        GuardKind::FrontendContract | GuardKind::InputValidation => "FE/FUZZ",
    }
}

pub(crate) fn summarize_findings_counts(
    findings: &[LatticeFinding],
) -> (
    usize,
    usize,
    usize,
    usize,
    usize,
    Vec<(&'static str, usize)>,
) {
    let mut crit = 0usize;
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    let mut proven = 0usize;
    let mut cat_counts: HashMap<&'static str, usize> = HashMap::new();
    for f in findings {
        match f.severity.as_str() {
            "CRITICAL" => crit += 1,
            "HIGH" => high += 1,
            "MEDIUM" => med += 1,
            _ => low += 1,
        }
        if f.status == "PROVEN" || f.confidence == Confidence::Proven {
            proven += 1;
        }
        *cat_counts
            .entry(guard_category_tag(f.missing_guard))
            .or_default() += 1;
    }
    let mut cats: Vec<(&'static str, usize)> = cat_counts.into_iter().collect();
    cats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    (crit, high, med, low, proven, cats)
}

pub(crate) fn clip_str(s: &str, max_chars: usize) -> String {
    let len = s.chars().count();
    if len <= max_chars || max_chars == 0 {
        return s.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let mut out: String = s.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

pub(crate) fn write_rendered_output(output: Option<&Path>, text: &str) -> Result<()> {
    if let Some(out_path) = output {
        if let Some(parent) = out_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, text)?;
        eprintln!("[SMG] Wrote scan report -> {}", out_path.display());
    } else {
        print!("{}", text);
        let _ = std::io::stdout().flush();
    }
    Ok(())
}

pub(crate) fn format_scan_output(
    path: &Path,
    outcome: &ScanOutcome,
    verified_list: &[VerifiedFinding],
    opts: &RenderOptions<'_>,
) -> Result<String> {
    let effective_color = if opts.output.is_some() {
        ColorMode::Never
    } else {
        opts.color_mode
    };
    let pal = AnsiPalette::resolve(effective_color, std::io::stdout().is_terminal());

    let mut out = String::new();
    match opts.format {
        OutputFormat::Json => {
            out = serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "elapsed_ms": outcome.elapsed_ms,
                "findings_count": outcome.graph.findings.len(),
                "findings": outcome.graph.findings,
                "delta": outcome.delta,
                "graph": outcome.graph,
                "sandbox_verification": outcome.sandbox.as_ref().map(|(bwrap, res)| serde_json::json!({
                    "bwrap_isolated": bwrap,
                    "results": res,
                })),
            }))?;
            out.push('\n');
        }
        OutputFormat::Sarif => {
            if let Some(payload) = opts.sarif_payload {
                out.push_str(payload);
                if !payload.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        OutputFormat::Compact => {
            if outcome.graph.findings.is_empty() {
                out.push_str(&format!(
                    "{}\n",
                    pal.green(&format!(
                        "[OK] SMG Scan clean ({} files, {}ms)",
                        outcome.graph.parsed_files, outcome.elapsed_ms
                    ))
                ));
            } else {
                for f in &outcome.graph.findings {
                    let sev = match f.severity.as_str() {
                        "CRITICAL" => pal.purple(&f.severity),
                        "HIGH" => pal.coral(&f.severity),
                        "MEDIUM" => pal.amber(&f.severity),
                        _ => pal.dim(&f.severity),
                    };
                    let st = if f.status == "PROVEN" {
                        pal.red("PROVEN")
                    } else if f.status == "MITIGATED" {
                        pal.green("MITIGATED")
                    } else {
                        pal.amber(f.confidence.as_str())
                    };
                    out.push_str(&format!(
                        "[{}][{}] {} {} {}:{} — {} ({})\n",
                        sev,
                        st,
                        pal.bold(&f.id),
                        f.rule_id,
                        f.file,
                        f.line,
                        f.title,
                        f.entry_route
                    ));
                }
            }
        }
        OutputFormat::Table => {
            out.push_str(&format!(
                "{} | {} files | {}ms\n",
                pal.cyan("SMG · ShellMind Guard"),
                outcome.graph.parsed_files,
                outcome.elapsed_ms
            ));
            if outcome.graph.findings.is_empty() {
                out.push_str(&format!(
                    "  {}\n",
                    pal.green("[OK] No security or logic issues detected.")
                ));
            } else {
                out.push_str(&format!(
                    "{:<15} {:<8} {:<10} {:<14} {:<30} {}\n",
                    "ID", "SEV", "STATUS", "RULE", "LOCATION", "TITLE"
                ));
                out.push_str(&"-".repeat(108));
                out.push('\n');
                for f in &outcome.graph.findings {
                    let loc = clip_str(&format!("{}:{}", f.file, f.line), 30);
                    let title = clip_str(&f.title, 36);
                    let status = if f.status == "PROVEN" {
                        "PROVEN"
                    } else {
                        f.confidence.as_str()
                    };
                    out.push_str(&format!(
                        "{:<15} {:<8} {:<10} {:<14} {:<30} {}\n",
                        clip_str(&f.id, 15),
                        clip_str(&f.severity, 8),
                        clip_str(status, 10),
                        clip_str(&f.rule_id, 14),
                        loc,
                        title
                    ));
                }
                let (crit, high, med, low, proven, _) =
                    summarize_findings_counts(&outcome.graph.findings);
                out.push_str(&format!(
                    "\nTotal: {} (CRIT={}, HIGH={}, MED={}, LOW={}, PROVEN={})\n",
                    outcome.graph.findings.len(),
                    crit,
                    high,
                    med,
                    low,
                    proven
                ));
            }
        }
        OutputFormat::Markdown => {
            let (crit, high, med, low, proven, cats) =
                summarize_findings_counts(&outcome.graph.findings);
            out.push_str("# ShellMind Guard (`smg`) Security Report\n\n");
            out.push_str(&format!(
                "- **Files scanned:** {} ({} symbols, {} edges, {} routes) in {}ms\n",
                outcome.graph.parsed_files,
                outcome.graph.symbol_count,
                outcome.graph.edge_count,
                outcome.graph.route_entries,
                outcome.elapsed_ms
            ));
            out.push_str(&format!(
                "- **Findings:** {} total (`CRITICAL: {}` · `HIGH: {}` · `MEDIUM: {}` · `LOW: {}` · `PROVEN: {}`)\n",
                outcome.graph.findings.len(),
                crit,
                high,
                med,
                low,
                proven
            ));
            if !cats.is_empty() {
                let cat_str = cats
                    .iter()
                    .map(|(k, v)| format!("`{}: {}`", k, v))
                    .collect::<Vec<_>>()
                    .join(" · ");
                out.push_str(&format!("- **Categories:** {}\n", cat_str));
            }
            out.push('\n');
            if outcome.graph.findings.is_empty() {
                out.push_str("> **Clean:** No unguarded security or logic issues detected.\n");
            } else {
                out.push_str("| ID | Severity | Confidence | Rule | Location | Title |\n");
                out.push_str("|---|---|---|---|---|---|\n");
                for f in &outcome.graph.findings {
                    out.push_str(&format!(
                        "| `{}` | **{}** | `{}` | `{}` | `{}:{}` | {} |\n",
                        f.id,
                        f.severity,
                        f.confidence.as_str(),
                        f.rule_id,
                        f.file,
                        f.line,
                        f.title.replace('|', "\\|")
                    ));
                }
                out.push('\n');
                for f in &outcome.graph.findings {
                    out.push_str(&format!("### `{}` — {}\n", f.id, f.title));
                    out.push_str(&format!("- **Entry:** `{}`\n", f.entry_route));
                    if !f.remediation.is_empty() {
                        out.push_str(&format!("- **Fix:** {}\n", f.remediation));
                    }
                    out.push_str(&format!(
                        "- **Replay:** `smg replay {} {}`\n\n",
                        f.id,
                        path.display()
                    ));
                }
            }
        }
        OutputFormat::Text => {
            out.push_str(&format!(
                "{} | {} files ({} symbols, {} edges, {} routes) | {}ms (delta: +{} / {} cached)\n",
                pal.cyan("ShellMind Guard Scan"),
                outcome.graph.parsed_files,
                outcome.graph.symbol_count,
                outcome.graph.edge_count,
                outcome.graph.route_entries,
                outcome.elapsed_ms,
                outcome.delta.added_or_modified,
                outcome.delta.unchanged_cached
            ));
            if outcome.graph.findings.is_empty() {
                out.push_str(&format!(
                    "  {}\n",
                    pal.green("[OK] No security or logic issues detected.")
                ));
            } else {
                let (crit, high, med, low, proven, cats) =
                    summarize_findings_counts(&outcome.graph.findings);
                let cat_summary = cats
                    .iter()
                    .take(6)
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!(
                    "  {} finding(s) detected | CRIT:{} HIGH:{} MED:{} LOW:{} PROVEN:{} | [{}]\n",
                    pal.amber(&outcome.graph.findings.len().to_string()),
                    crit,
                    high,
                    med,
                    low,
                    proven,
                    cat_summary
                ));
                let canon_root = fs::canonicalize(path).ok();
                let mut src_cache: HashMap<String, Vec<String>> = HashMap::new();
                for f in &outcome.graph.findings {
                    let sev_badge = match f.severity.as_str() {
                        "CRITICAL" => pal.purple(&format!("[{}]", f.severity)),
                        "HIGH" => pal.coral(&format!("[{}]", f.severity)),
                        "MEDIUM" => pal.amber(&format!("[{}]", f.severity)),
                        _ => pal.dim(&format!("[{}]", f.severity)),
                    };
                    let conf_badge = if f.status == "PROVEN" || f.confidence == Confidence::Proven {
                        pal.red("[PROVEN]")
                    } else if f.status == "MITIGATED" {
                        pal.green("[MITIGATED]")
                    } else if f.confidence == Confidence::Confirmed {
                        pal.cyan("[CONFIRMED]")
                    } else {
                        pal.amber("[HEURISTIC]")
                    };
                    out.push_str(&format!(
                        "\n  {} {} {} ({}) -> {}\n",
                        sev_badge,
                        conf_badge,
                        pal.bold(&f.id),
                        f.rule_id,
                        f.title
                    ));
                    out.push_str(&format!("      Entry: {}\n", f.entry_route));
                    for (i, hop) in f.witness_path.iter().enumerate() {
                        out.push_str(&format!(
                            "      [{}] {}:{}  {}\n",
                            i + 1,
                            hop.file,
                            hop.line,
                            hop.symbol
                        ));
                    }
                    let (snip_file, snip_line) = f
                        .witness_path
                        .last()
                        .map(|h| (h.file.as_str(), h.line))
                        .unwrap_or((f.file.as_str(), f.line));
                    let snippet = read_source_snippet_lines(
                        canon_root.as_deref(),
                        snip_file,
                        snip_line,
                        &mut src_cache,
                    );
                    for (ln, code, is_target) in snippet {
                        let clipped = clip_str(code.trim_end(), 96);
                        if is_target {
                            out.push_str(&format!(
                                "      {} {:>4} │ {}\n",
                                pal.red(">"),
                                ln,
                                clipped
                            ));
                        } else {
                            out.push_str(&format!("        {:>4} │ {}\n", ln, pal.dim(&clipped)));
                        }
                    }
                    if !f.remediation.is_empty() {
                        out.push_str(&format!("      Fix  : {}\n", pal.green(&f.remediation)));
                    }
                }
            }

            if let Some((bwrap, verified)) = &outcome.sandbox {
                out.push_str(&format!(
                    "\n{} (bwrap={}):\n",
                    pal.cyan("ShellMind Guard Sandbox Proof"),
                    if *bwrap { "isolated" } else { "local-loopback" }
                ));
                for v in verified {
                    let tag = verification_status_tag(&v.status);
                    let colored_tag = match v.status {
                        VerificationStatus::Proven => pal.red(tag),
                        VerificationStatus::Mitigated => pal.green(tag),
                        _ => pal.amber(tag),
                    };
                    out.push_str(&format!(
                        "  [{}] {} ({}) -> {}\n",
                        colored_tag, v.finding_id, v.rule_id, v.evidence
                    ));
                }
            }

            if opts.patch {
                for f in &outcome.graph.findings {
                    let v_opt = verified_list.iter().find(|v| v.finding_id == f.id);
                    if let Ok(p) = build_minimal_patch_prompt(path, f, v_opt) {
                        out.push_str(&format!(
                            "\n=== Minimal Patch Context ({} bytes) ===\n{}\n",
                            p.len(),
                            p
                        ));
                    }
                }
            }
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_scan_output(
    path: &Path,
    format: OutputFormat,
    outcome: &ScanOutcome,
    verified_list: &[VerifiedFinding],
    sarif_payload: Option<&str>,
    patch: bool,
    color_mode: ColorMode,
    output: Option<&Path>,
) -> Result<()> {
    let opts = RenderOptions {
        format,
        sarif_payload,
        patch,
        color_mode,
        output,
    };
    let rendered = format_scan_output(path, outcome, verified_list, &opts)?;
    write_rendered_output(output, &rendered)
}
