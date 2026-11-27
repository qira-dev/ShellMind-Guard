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

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub(crate) struct BaselineEntry {
    rule_id: String,
    file: String,
    #[serde(default)]
    enclosing_symbol: String,
    #[serde(default)]
    sink_line_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    entry_route: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sink_symbol: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct BaselineFile {
    version: u32,
    entries: Vec<BaselineEntry>,
}

pub(crate) fn whitespace_normalized_line_hash(line: &str) -> String {
    let norm = line.split_whitespace().collect::<Vec<_>>().join(" ");
    blake3::hash(norm.as_bytes()).to_hex().to_string()
}

pub(crate) fn finding_fingerprint_with_root(
    canon_root: Option<&Path>,
    f: &LatticeFinding,
    file_cache: &mut HashMap<String, Vec<String>>,
) -> BaselineEntry {
    let primary_hop = f.witness_path.last().or_else(|| f.witness_path.first());
    let raw_file = primary_hop
        .map(|h| h.file.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| (!f.file.is_empty()).then_some(f.file.as_str()))
        .unwrap_or("");
    let file = smg_core::normalize_rel_path_posix_nfc(raw_file);
    let primary_line = primary_hop
        .map(|h| h.line)
        .filter(|&l| l > 0)
        .unwrap_or(f.line);
    let enclosing_symbol = primary_hop
        .map(|h| h.symbol.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| f.entry_route.clone());

    let sink_line_hash = if let Some(root) = canon_root
        && !file.is_empty()
        && primary_line > 0
    {
        if !file_cache.contains_key(&file) {
            let loaded = fs::canonicalize(root.join(&file))
                .ok()
                .filter(|canon| canon.starts_with(root))
                .and_then(|canon| fs::read_to_string(canon).ok())
                .map(|raw| {
                    smg_core::strip_utf8_bom(&raw)
                        .lines()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            file_cache.insert(file.clone(), loaded);
        }
        file_cache
            .get(&file)
            .and_then(|lines| lines.get(primary_line - 1))
            .map(|line| whitespace_normalized_line_hash(line))
            .unwrap_or_else(|| {
                whitespace_normalized_line_hash(&format!("{}|{}", enclosing_symbol, f.title))
            })
    } else {
        whitespace_normalized_line_hash(&format!("{}|{}", enclosing_symbol, f.title))
    };

    BaselineEntry {
        rule_id: f.rule_id.clone(),
        file,
        enclosing_symbol,
        sink_line_hash,
        entry_route: String::new(),
        sink_symbol: String::new(),
    }
}

pub(crate) fn finding_fingerprint(f: &LatticeFinding) -> BaselineEntry {
    let mut empty_cache = HashMap::new();
    finding_fingerprint_with_root(None, f, &mut empty_cache)
}

pub(crate) fn baseline_entry_matches(
    baseline_set: &HashSet<BaselineEntry>,
    v2: &BaselineEntry,
    f: &LatticeFinding,
) -> bool {
    if baseline_set.contains(v2) {
        return true;
    }
    // Backward-compatible matching for v1 baselines lacking `sink_line_hash`.
    let legacy = BaselineEntry {
        rule_id: f.rule_id.clone(),
        file: smg_core::normalize_rel_path_posix_nfc(&f.file),
        enclosing_symbol: String::new(),
        sink_line_hash: String::new(),
        entry_route: f.entry_route.clone(),
        sink_symbol: f
            .witness_path
            .last()
            .map(|h| h.symbol.clone())
            .unwrap_or_default(),
    };
    baseline_set.contains(&legacy)
}

pub(crate) fn has_unquoted_comment_before(prefix: &str) -> bool {
    let quote_count = prefix.bytes().filter(|&b| b == b'"').count();
    if !quote_count.is_multiple_of(2) {
        return false;
    }
    prefix.contains("//")
        || prefix.contains('#')
        || prefix.contains("/*")
        || prefix.contains("--")
        || prefix.contains("<!--")
}

pub(crate) fn line_suppresses_finding(raw_line: &str, rule_id: &str, finding_id: &str) -> bool {
    let lower = raw_line.to_ascii_lowercase();
    let Some(idx) = lower.find("smg-ignore") else {
        return false;
    };
    let before = &raw_line[..idx];
    if !has_unquoted_comment_before(before) {
        return false;
    }
    let after = raw_line[idx + "smg-ignore".len()..].trim();
    let after = after.trim_end_matches("*/").trim_end_matches("-->").trim();
    let explicit_rules: Vec<&str> = after
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':'))
        .map(str::trim)
        .filter(|tok| tok.to_ascii_uppercase().starts_with("SMG-"))
        .collect();
    if explicit_rules.is_empty() {
        true
    } else {
        explicit_rules
            .iter()
            .any(|tok| tok.eq_ignore_ascii_case(rule_id) || tok.eq_ignore_ascii_case(finding_id))
    }
}

pub(crate) fn is_inline_suppressed(
    canon_root: Option<&Path>,
    f: &LatticeFinding,
    file_cache: &mut HashMap<String, Vec<String>>,
) -> bool {
    let Some(root) = canon_root else {
        return false;
    };
    let mut locations: Vec<(&str, usize)> = vec![(&f.file, f.line)];
    if let Some(last_hop) = f.witness_path.last() {
        locations.push((&last_hop.file, last_hop.line));
    }
    for (rel_path, line) in locations {
        if rel_path.is_empty() || line == 0 {
            continue;
        }
        if !file_cache.contains_key(rel_path) {
            let loaded = fs::canonicalize(root.join(rel_path))
                .ok()
                .filter(|canon| canon.starts_with(root))
                .and_then(|canon| fs::read_to_string(canon).ok())
                .map(|raw| raw.lines().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            file_cache.insert(rel_path.to_string(), loaded);
        }
        if let Some(lines) = file_cache.get(rel_path) {
            for candidate_ln in [line.saturating_sub(1), line] {
                if candidate_ln > 0
                    && let Some(raw_line) = lines.get(candidate_ln - 1)
                    && line_suppresses_finding(raw_line, &f.rule_id, &f.id)
                {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn count_stale_smg_ignores(root: &Path, pre_findings: &[LatticeFinding]) -> usize {
    let Ok(cfg) = ShellMindGuardConfig::load_trusted_from_dir(root, false) else {
        return 0;
    };
    let Ok(summary) = scan_repository(root, &cfg) else {
        return 0;
    };
    let mut active_by_file: HashMap<String, Vec<&LatticeFinding>> = HashMap::new();
    for f in pre_findings {
        if !f.file.is_empty() {
            active_by_file.entry(f.file.clone()).or_default().push(f);
        }
        if let Some(last) = f.witness_path.last()
            && !last.file.is_empty()
            && last.file != f.file
        {
            active_by_file.entry(last.file.clone()).or_default().push(f);
        }
    }

    let mut stale = 0usize;
    for file in &summary.files {
        let Some(bytes) = &file.cached_bytes else {
            continue;
        };
        let Ok(txt) = std::str::from_utf8(bytes) else {
            continue;
        };
        if !txt.to_ascii_lowercase().contains("smg-ignore") {
            continue;
        }
        let candidates = active_by_file.get(&file.rel_path);
        for (idx, line) in txt.lines().enumerate() {
            if line.trim().starts_with("#[cfg(test)]") {
                break;
            }
            let lower = line.to_ascii_lowercase();
            let Some(ig_idx) = lower.find("smg-ignore") else {
                continue;
            };
            if !has_unquoted_comment_before(&line[..ig_idx]) {
                continue;
            }
            let comment_ln = idx + 1;
            let matched = candidates.is_some_and(|list| {
                list.iter().any(|f| {
                    let hit_ln = f
                        .witness_path
                        .last()
                        .map(|h| h.line)
                        .filter(|&l| l > 0)
                        .unwrap_or(f.line);
                    (hit_ln == comment_ln || hit_ln == comment_ln + 1)
                        && line_suppresses_finding(line, &f.rule_id, &f.id)
                })
            });
            if !matched {
                stale += 1;
            }
        }
    }
    stale
}

pub(crate) fn load_baseline_entries(path: &Path) -> Result<HashSet<BaselineEntry>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline '{}'", path.display()))?;
    if let Ok(parsed) = serde_json::from_str::<BaselineFile>(&raw) {
        return Ok(parsed.entries.into_iter().collect());
    }
    let list: Vec<BaselineEntry> = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid baseline JSON in '{}'", path.display()))?;
    Ok(list.into_iter().collect())
}

pub(crate) fn apply_suppressions_and_baseline(
    root: &Path,
    outcome: &mut ScanOutcome,
    verified_list: &mut Vec<VerifiedFinding>,
    exclude_rules: &[String],
    baseline_path: Option<&Path>,
    write_baseline_path: Option<&Path>,
) -> Result<()> {
    let exclude_norm: Vec<String> = exclude_rules
        .iter()
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    let canon_root = fs::canonicalize(root).ok();
    let mut file_cache: HashMap<String, Vec<String>> = HashMap::new();
    let mut inline_suppressed = 0usize;
    let mut rule_excluded = 0usize;

    outcome.graph.findings.retain(|f| {
        if !exclude_norm.is_empty()
            && (exclude_norm
                .iter()
                .any(|r| f.rule_id.eq_ignore_ascii_case(r) || f.id.eq_ignore_ascii_case(r)))
        {
            rule_excluded += 1;
            return false;
        }
        if is_inline_suppressed(canon_root.as_deref(), f, &mut file_cache) {
            inline_suppressed += 1;
            return false;
        }
        true
    });

    if let Some(wb_path) = write_baseline_path {
        let mut entries: Vec<BaselineEntry> = outcome
            .graph
            .findings
            .iter()
            .filter(|f| f.status != "MITIGATED")
            .map(|f| finding_fingerprint_with_root(canon_root.as_deref(), f, &mut file_cache))
            .collect();
        entries.sort();
        entries.dedup();
        if let Some(parent) = wb_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let payload = BaselineFile {
            version: 2,
            entries,
        };
        fs::write(wb_path, serde_json::to_string_pretty(&payload)?)?;
        eprintln!(
            "[SMG] Wrote {} baseline entry(s) -> {}",
            payload.entries.len(),
            wb_path.display()
        );
    }

    let mut baseline_suppressed = 0usize;
    if let Some(b_path) = baseline_path {
        let baseline_set = load_baseline_entries(b_path)?;
        outcome.graph.findings.retain(|f| {
            let fp = finding_fingerprint_with_root(canon_root.as_deref(), f, &mut file_cache);
            if baseline_entry_matches(&baseline_set, &fp, f) {
                baseline_suppressed += 1;
                false
            } else {
                true
            }
        });
    }

    let kept_ids: HashSet<String> = outcome
        .graph
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    verified_list.retain(|v| kept_ids.contains(&v.finding_id));
    if let Some((_, ref mut sbox_v)) = outcome.sandbox {
        sbox_v.retain(|v| kept_ids.contains(&v.finding_id));
    }

    if rule_excluded + inline_suppressed + baseline_suppressed > 0 {
        eprintln!(
            "[SMG] Suppressed {} finding(s) (exclude-rule: {}, smg-ignore: {}, baseline: {})",
            rule_excluded + inline_suppressed + baseline_suppressed,
            rule_excluded,
            inline_suppressed,
            baseline_suppressed
        );
    }
    Ok(())
}
