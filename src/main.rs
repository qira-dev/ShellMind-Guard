mod mcp;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use vf_ai::build_minimal_patch_prompt;
use vf_core::{DeltaStats, ShellMindGuardConfig, StateStore, scan_repository};
use vf_graph::{GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase_cached};
use vf_report::{to_html_graph, to_sarif_json};
use vf_sandbox::{
    VerificationStatus, VerifiedFinding, verify_finding_blocking, verify_findings_in_sandbox,
};
use vf_tui::{TuiLaunchConfig, run_tui};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum FailSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Subcommand, Debug)]
enum HookAction {
    /// Install non-destructive pre-commit hook into `.git/hooks/pre-commit`
    Install {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Remove ShellMind Guard block from `.git/hooks/pre-commit`
    Uninstall {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Check if ShellMind Guard git pre-commit hook is active
    Status {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

pub(crate) struct ScanRunOptions<'a> {
    pub path: &'a Path,
    pub layers: &'a [String],
    pub boot_cmd: Option<String>,
    pub port: u16,
    pub sync_race: usize,
    pub unsafe_host_fallback: bool,
}

pub(crate) struct ScanOutcome {
    pub elapsed_ms: u128,
    pub delta: DeltaStats,
    pub graph: GraphAnalysisResult,
    pub sandbox: Option<(bool, Vec<VerifiedFinding>)>,
}

#[derive(Parser, Debug)]
#[command(
    name = "shellmind-guard",
    version,
    about = "Zero-false-positive multi-file business-logic & AI-code security verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize `.shellmind-guard.toml` (and optionally `.github/workflows/shellmind-guard.yml` or git hook)
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        ci: bool,
        #[arg(long)]
        hook: bool,
    },
    /// Index a repository using parallel ignore walker, BLAKE3 hashing, and SQLite WAL delta cache
    Index {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Scan a repository across all 6 ShellMind Guard layers (with optional sandbox, SARIF, HTML, patch & CI gate)
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, help = "Shorthand for --format json")]
        json: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Filter active layers (auth,race,taint,sqli,cmdi,path,ssrf,idor,secrets,config,deps,frontend)"
        )]
        layers: Vec<String>,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
        #[arg(long)]
        sarif: Option<PathBuf>,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        patch: bool,
        /// Allow unsafe host execution if `/usr/bin/bwrap` is unavailable
        #[arg(long)]
        unsafe_host_fallback: bool,
        #[arg(long)]
        ci: bool,
        #[arg(
            long,
            value_enum,
            help = "Exit non-zero if any unmitigated finding meets this severity"
        )]
        fail_on: Option<FailSeverity>,
        #[arg(
            long,
            help = "Continuously watch repository and re-scan on file changes"
        )]
        watch: bool,
    },
    /// Replay the exact sandbox PoC for a specific finding ID (e.g., VF-RACE-002 or VF-AUTH-001)
    Replay {
        finding_id: String,
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
        #[arg(long)]
        unsafe_host_fallback: bool,
        #[arg(long)]
        patch: bool,
    },
    /// Launch interactive panic-safe ratatui TUI workspace
    Ui {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
        #[arg(long)]
        unsafe_host_fallback: bool,
    },
    /// Start stdio JSON-RPC 2.0 MCP server (exposes shellmind_guard_scan, shellmind_guard_explain_finding, shellmind_guard_init)
    Mcp,
    /// Manage standalone Git pre-commit hook for zero-AI local protection
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Inspect local environment, sandbox (`bwrap`), config, and hook readiness
    Doctor {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Internal probe executed inside `--unshare-net` Bubblewrap namespace
    #[command(name = "__probe-netns", hide = true)]
    ProbeNetns {
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
    },
}

pub(crate) fn write_ci_workflow(root: &Path) -> Result<PathBuf> {
    let wf_dir = root.join(".github").join("workflows");
    fs::create_dir_all(&wf_dir)?;
    let wf_path = wf_dir.join("shellmind-guard.yml");
    let content = r#"name: ShellMind Guard Security Gate

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  shellmind-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ShellMind Guard
        run: curl -fsSL https://raw.githubusercontent.com/qira-dev/ShellMind-Guard/main/install.sh | bash && echo "$HOME/.local/bin" >> $GITHUB_PATH
      - name: Run ShellMind Guard 6-Layer Scan (SARIF)
        run: shellmind-guard scan . --format sarif --sarif shellmind-guard.sarif --ci
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shellmind-guard.sarif
"#;
    fs::write(&wf_path, content)?;
    Ok(wf_path)
}

fn finding_matches_layer(f: &LatticeFinding, layer: &str) -> bool {
    let norm = layer.trim().to_ascii_lowercase();
    match norm.as_str() {
        "all" | "*" => true,
        "1" | "layer1" => matches!(f.missing_guard, GuardKind::Auth | GuardKind::SecretPolicy),
        "2" | "layer2" => matches!(
            f.missing_guard,
            GuardKind::SqlSanitizer
                | GuardKind::CmdSanitizer
                | GuardKind::PathSanitizer
                | GuardKind::SsrfSanitizer
                | GuardKind::OwnershipCheck
                | GuardKind::FrontendContract
        ),
        "3" | "layer3" | "deps" | "dep" | "dependencies" => {
            f.missing_guard == GuardKind::DependencyPolicy
        }
        "4" | "layer4" | "config" | "misconfig" => f.missing_guard == GuardKind::ConfigPolicy,
        "5" | "layer5" | "6" | "layer6" | "race" | "concurrency" => {
            f.missing_guard == GuardKind::TxLock
        }
        "auth" => f.missing_guard == GuardKind::Auth,
        "taint" | "injection" => matches!(
            f.missing_guard,
            GuardKind::SqlSanitizer
                | GuardKind::CmdSanitizer
                | GuardKind::PathSanitizer
                | GuardKind::SsrfSanitizer
        ),
        "sql" | "sqli" => f.missing_guard == GuardKind::SqlSanitizer,
        "cmd" | "cmdi" => f.missing_guard == GuardKind::CmdSanitizer,
        "path" => f.missing_guard == GuardKind::PathSanitizer,
        "ssrf" => f.missing_guard == GuardKind::SsrfSanitizer,
        "idor" => f.missing_guard == GuardKind::OwnershipCheck,
        "secrets" | "secret" => f.missing_guard == GuardKind::SecretPolicy,
        "frontend" | "fe" | "contract" => f.missing_guard == GuardKind::FrontendContract,
        other => {
            f.rule_id.to_ascii_lowercase().contains(other)
                || f.id.to_ascii_lowercase().contains(other)
        }
    }
}

pub(crate) fn execute_scan_pipeline(opts: ScanRunOptions<'_>) -> Result<ScanOutcome> {
    let t0 = Instant::now();
    let cfg = ShellMindGuardConfig::load_from_dir(opts.path)?;
    let summary = scan_repository(opts.path, &cfg)?;
    let mut store = StateStore::open(opts.path)?;
    let (delta, _) = store.sync_files(&summary.files)?;
    let mut graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;

    if !opts.layers.is_empty() {
        graph_res
            .findings
            .retain(|f| opts.layers.iter().any(|l| finding_matches_layer(f, l)));
    }

    let effective_boot = opts.boot_cmd.or_else(|| cfg.sandbox.boot_cmd.clone());
    let sandbox_res = if let Some(cmd) = effective_boot {
        if !graph_res.findings.is_empty() {
            Some(verify_findings_in_sandbox(
                opts.path,
                &cmd,
                opts.port,
                &graph_res.findings,
                opts.sync_race,
                opts.unsafe_host_fallback,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    let verified_list: Vec<VerifiedFinding> = sandbox_res
        .as_ref()
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    if !verified_list.is_empty() {
        let ver_map: HashMap<&str, &VerificationStatus> = verified_list
            .iter()
            .map(|v| (v.finding_id.as_str(), &v.status))
            .collect();
        for f in &mut graph_res.findings {
            if let Some(st) = ver_map.get(f.id.as_str()) {
                match st {
                    VerificationStatus::Proven => f.status = "PROVEN".into(),
                    VerificationStatus::Mitigated => f.status = "MITIGATED".into(),
                    VerificationStatus::SuspectUnverified => {}
                }
            }
        }
    }

    persist_scan_findings(
        &mut store,
        delta.scan_id,
        &graph_res.findings,
        &verified_list,
    )?;

    Ok(ScanOutcome {
        elapsed_ms: t0.elapsed().as_millis(),
        delta,
        graph: graph_res,
        sandbox: sandbox_res,
    })
}

fn persist_scan_findings(
    store: &mut StateStore,
    scan_id: i64,
    findings: &[LatticeFinding],
    verified: &[VerifiedFinding],
) -> Result<()> {
    let ver_map: HashMap<&str, &VerifiedFinding> = verified
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let mut owned_rows: Vec<(String, String, String, String, String, String)> =
        Vec::with_capacity(findings.len());
    for f in findings {
        let v_opt = ver_map.get(f.id.as_str()).copied();
        let status_str = match v_opt.map(|v| &v.status) {
            Some(VerificationStatus::Proven) => "PROVEN",
            Some(VerificationStatus::Mitigated) => "MITIGATED",
            _ => f.status.as_str(),
        };
        let trace_json = serde_json::to_string(f).unwrap_or_else(|_| "{}".into());
        let poc_cmd = v_opt
            .map(|v| v.replay_cmd.clone())
            .unwrap_or_else(|| format!("shellmind-guard replay {}", f.id));
        owned_rows.push((
            f.id.clone(),
            f.rule_id.clone(),
            f.severity.clone(),
            status_str.to_string(),
            trace_json,
            poc_cmd,
        ));
    }

    let borrowed: Vec<(&str, &str, &str, &str, &str, &str)> = owned_rows
        .iter()
        .map(|(a, b, c, d, e, f)| {
            (
                a.as_str(),
                b.as_str(),
                c.as_str(),
                d.as_str(),
                e.as_str(),
                f.as_str(),
            )
        })
        .collect();

    store.save_findings(scan_id, &borrowed)
}

fn resolve_finding_for_replay(
    path: &Path,
    finding_id: &str,
    cfg: &ShellMindGuardConfig,
    store: &mut StateStore,
) -> Result<LatticeFinding> {
    // B20: Always re-evaluate against current repository files so renamed/patched routes are never stale!
    let summary = scan_repository(path, cfg)?;
    let _ = store.sync_files(&summary.files)?;
    let graph_res = analyze_codebase_cached(&summary.files, cfg, store)?;
    let findings = graph_res.findings;
    findings
        .iter()
        .find(|f| f.id.eq_ignore_ascii_case(finding_id))
        .or_else(|| {
            findings
                .iter()
                .find(|f| f.rule_id.eq_ignore_ascii_case(finding_id))
        })
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Finding '{}' not found in current source of {}",
                finding_id,
                path.display()
            )
        })
}

fn main() -> Result<ExitCode> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Init { path, ci, hook } => {
            let (detected, out_path) = ShellMindGuardConfig::detect_and_write_init(&path)?;
            let mut extras = Vec::new();
            if ci {
                let ci_path = write_ci_workflow(&path)?;
                extras.push(ci_path.display().to_string());
            }
            if hook {
                let hook_path = install_git_hook(&path)?;
                extras.push(hook_path.display().to_string());
            }
            if extras.is_empty() {
                println!(
                    "ShellMind Guard Init | Detected: {} | Wrote {}",
                    detected.join(", "),
                    out_path.display()
                );
            } else {
                println!(
                    "ShellMind Guard Init | Detected: {} | Wrote {} and {}",
                    detected.join(", "),
                    out_path.display(),
                    extras.join(", ")
                );
            }
        }
        Commands::Index { path, json } => {
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _changed) = store.sync_files(&summary.files)?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "total_entries_seen": summary.total_entries_seen,
                        "source_files_hashed": summary.source_files_hashed,
                        "skipped": summary.skipped_ignored_or_binary,
                        "elapsed_ms": summary.elapsed_ms,
                        "delta": delta,
                    }))?
                );
            } else {
                println!(
                    "ShellMind Guard Index | {} source files ({} total entries) | {}ms | delta: +{} modified / {} cached / {} removed",
                    summary.source_files_hashed,
                    summary.total_entries_seen,
                    summary.elapsed_ms,
                    delta.added_or_modified,
                    delta.unchanged_cached,
                    delta.removed
                );
            }
        }
        Commands::Scan {
            path,
            json,
            format,
            layers,
            boot_cmd,
            port,
            sync_race,
            sarif,
            html,
            patch,
            unsafe_host_fallback,
            ci,
            fail_on,
            watch,
        } => {
            let effective_format = if json { OutputFormat::Json } else { format };
            let outcome = execute_scan_pipeline(ScanRunOptions {
                path: &path,
                layers: &layers,
                boot_cmd: boot_cmd.clone(),
                port,
                sync_race,
                unsafe_host_fallback,
            })?;
            let verified_list: Vec<VerifiedFinding> = outcome
                .sandbox
                .as_ref()
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let sarif_payload = if sarif.is_some() || effective_format == OutputFormat::Sarif {
                Some(to_sarif_json(&outcome.graph.findings, &verified_list))
            } else {
                None
            };

            if let Some(ref sarif_path) = sarif
                && let Some(ref payload) = sarif_payload
            {
                if let Some(parent) = sarif_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(sarif_path, payload)?;
            }
            if let Some(html_path) = html {
                if let Some(parent) = html_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(
                    &html_path,
                    to_html_graph(&path.display().to_string(), &outcome.graph, &verified_list),
                )?;
            }

            render_scan_output(
                &path,
                effective_format,
                &outcome,
                &verified_list,
                sarif_payload.as_deref(),
                patch,
            )?;

            if watch {
                eprintln!(
                    "[ShellMind Guard] Watching {} for changes (Ctrl+C to stop)...",
                    path.display()
                );
                let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                let mut store = StateStore::open(&path)?;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    let summary = scan_repository(&path, &cfg)?;
                    let (delta, _) = store.sync_files(&summary.files)?;
                    if delta.added_or_modified > 0 || delta.removed > 0 {
                        let next_outcome = execute_scan_pipeline(ScanRunOptions {
                            path: &path,
                            layers: &layers,
                            boot_cmd: boot_cmd.clone(),
                            port,
                            sync_race,
                            unsafe_host_fallback,
                        })?;
                        let next_verified: Vec<VerifiedFinding> = next_outcome
                            .sandbox
                            .as_ref()
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                        render_scan_output(
                            &path,
                            effective_format,
                            &next_outcome,
                            &next_verified,
                            None,
                            patch,
                        )?;
                    }
                }
            }

            if should_fail_gate(&outcome.graph.findings, ci, fail_on) {
                return Ok(ExitCode::from(2));
            }
        }
        Commands::Replay {
            finding_id,
            path,
            boot_cmd,
            port,
            sync_race,
            unsafe_host_fallback,
            patch,
        } => {
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let mut store = StateStore::open(&path)?;
            let finding = resolve_finding_for_replay(&path, &finding_id, &cfg, &mut store)?;
            let effective_boot = boot_cmd
                .or_else(|| cfg.sandbox.boot_cmd.clone())
                .unwrap_or_else(|| "node server.mjs".into());

            let (bwrap, verified) = verify_findings_in_sandbox(
                &path,
                &effective_boot,
                port,
                std::slice::from_ref(&finding),
                sync_race,
                unsafe_host_fallback,
            )?;

            println!(
                "ShellMind Guard Replay | {} ({}) | bwrap={}",
                finding.id,
                finding.entry_route,
                if bwrap { "isolated" } else { "local-loopback" }
            );
            for v in &verified {
                let tag = match v.status {
                    VerificationStatus::Proven => "PROVEN",
                    VerificationStatus::Mitigated => "MITIGATED",
                    VerificationStatus::SuspectUnverified => "SUSPECT",
                };
                println!("  [{}] {}", tag, v.evidence);
                println!("  Command: {}", v.replay_cmd);
            }
            if patch {
                let p = build_minimal_patch_prompt(&path, &finding, verified.first())?;
                println!("\n=== Minimal Patch Context ({} bytes) ===\n{}", p.len(), p);
            }
        }
        Commands::Ui {
            path,
            boot_cmd,
            port,
            sync_race,
            unsafe_host_fallback,
        } => {
            let t0 = Instant::now();
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _) = store.sync_files(&summary.files)?;
            let graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
            let effective_boot = boot_cmd.or_else(|| cfg.sandbox.boot_cmd.clone());
            let verified_list = if let Some(ref cmd) = effective_boot {
                if !graph_res.findings.is_empty() {
                    verify_findings_in_sandbox(
                        &path,
                        cmd,
                        port,
                        &graph_res.findings,
                        sync_race,
                        unsafe_host_fallback,
                    )?
                    .1
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            persist_scan_findings(
                &mut store,
                delta.scan_id,
                &graph_res.findings,
                &verified_list,
            )?;
            let total_ms = t0.elapsed().as_millis();
            run_tui(
                &path,
                graph_res,
                verified_list,
                total_ms,
                TuiLaunchConfig {
                    boot_cmd: effective_boot,
                    port,
                    sync_race,
                    unsafe_host_fallback,
                },
            )?;
        }
        Commands::Mcp => {
            mcp::run_stdio_server()?;
        }
        Commands::Hook { action } => match action {
            HookAction::Install { path } => {
                let p = install_git_hook(&path)?;
                println!(
                    "ShellMind Guard Hook | Installed pre-commit hook at {}",
                    p.display()
                );
            }
            HookAction::Uninstall { path } => {
                let removed = uninstall_git_hook(&path)?;
                if removed {
                    println!("ShellMind Guard Hook | Removed pre-commit hook block.");
                } else {
                    println!("ShellMind Guard Hook | Not installed.");
                }
            }
            HookAction::Status { path } => {
                let active = git_hook_status(&path);
                println!(
                    "ShellMind Guard Hook | {}",
                    if active {
                        "ACTIVE (.git/hooks/pre-commit)"
                    } else {
                        "NOT INSTALLED"
                    }
                );
            }
        },
        Commands::Doctor { path } => {
            run_doctor(&path);
        }
        Commands::ProbeNetns { port, sync_race } => {
            let finding_json = std::env::var("VF_FINDING_JSON")?;
            let finding: LatticeFinding = serde_json::from_str(&finding_json)?;
            let res = verify_finding_blocking(port, &finding, sync_race)?;
            println!("{}", serde_json::to_string(&res)?);
        }
    }

    Ok(ExitCode::SUCCESS)
}

const HOOK_START: &str = "# >>> shellmind-guard pre-commit >>>";
const HOOK_END: &str = "# <<< shellmind-guard pre-commit <<<";

fn resolve_git_hooks_dir(root: &Path) -> Result<PathBuf> {
    let git_dir = root.join(".git");
    if !git_dir.exists() {
        anyhow::bail!(
            "Not a git repository ({} has no .git directory)",
            root.display()
        );
    }
    Ok(git_dir.join("hooks"))
}

fn install_git_hook(root: &Path) -> Result<PathBuf> {
    let hooks_dir = resolve_git_hooks_dir(root)?;
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    let block = format!(
        "{}\nif command -v shellmind-guard >/dev/null 2>&1; then\n  shellmind-guard scan . --layers secrets,config --ci\nfi\n{}\n",
        HOOK_START, HOOK_END
    );

    let updated = if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)?;
        if existing.contains(HOOK_START) {
            existing
        } else if existing.ends_with('\n') {
            format!("{}\n{}", existing, block)
        } else {
            format!("{}\n\n{}", existing, block)
        }
    } else {
        format!("#!/usr/bin/env bash\nset -e\n\n{}", block)
    };

    fs::write(&hook_path, updated)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(hook_path)
}

fn uninstall_git_hook(root: &Path) -> Result<bool> {
    let Ok(hooks_dir) = resolve_git_hooks_dir(root) else {
        return Ok(false);
    };
    let hook_path = hooks_dir.join("pre-commit");
    if !hook_path.exists() {
        return Ok(false);
    }
    let existing = fs::read_to_string(&hook_path)?;
    let Some(start_idx) = existing.find(HOOK_START) else {
        return Ok(false);
    };
    let end_idx = existing[start_idx..]
        .find(HOOK_END)
        .map(|rel| start_idx + rel + HOOK_END.len())
        .unwrap_or(existing.len());
    let remaining = format!(
        "{}{}",
        existing[..start_idx].trim_end(),
        existing[end_idx..].trim_start()
    );
    let trimmed = remaining.trim();
    if trimmed.is_empty()
        || trimmed == "#!/usr/bin/env bash\nset -e"
        || trimmed == "#!/usr/bin/env bash"
        || trimmed == "#!/bin/sh"
    {
        fs::remove_file(&hook_path)?;
    } else {
        fs::write(&hook_path, format!("{}\n", trimmed))?;
    }
    Ok(true)
}

fn git_hook_status(root: &Path) -> bool {
    let Ok(hooks_dir) = resolve_git_hooks_dir(root) else {
        return false;
    };
    let hook_path = hooks_dir.join("pre-commit");
    fs::read_to_string(hook_path)
        .map(|s| s.contains(HOOK_START))
        .unwrap_or(false)
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn should_fail_gate(findings: &[LatticeFinding], ci: bool, fail_on: Option<FailSeverity>) -> bool {
    if let Some(threshold) = fail_on {
        let min_rank = match threshold {
            FailSeverity::Critical => 4,
            FailSeverity::High => 3,
            FailSeverity::Medium => 2,
            FailSeverity::Low => 1,
        };
        return findings.iter().any(|f| {
            f.status != "MITIGATED"
                && (f.status == "PROVEN" || severity_rank(&f.severity) >= min_rank)
        });
    }
    if ci {
        return findings.iter().any(|f| {
            f.status == "PROVEN"
                || (f.status != "MITIGATED" && (f.severity == "CRITICAL" || f.severity == "HIGH"))
        });
    }
    false
}

fn render_scan_output(
    path: &Path,
    format: OutputFormat,
    outcome: &ScanOutcome,
    verified_list: &[VerifiedFinding],
    sarif_payload: Option<&str>,
    patch: bool,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
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
                }))?
            );
        }
        OutputFormat::Sarif => {
            if let Some(payload) = sarif_payload {
                println!("{}", payload);
            }
        }
        OutputFormat::Text => {
            println!(
                "ShellMind Guard Scan | {} files ({} symbols, {} edges, {} routes) | {}ms (delta: +{} / {} cached)",
                outcome.graph.parsed_files,
                outcome.graph.symbol_count,
                outcome.graph.edge_count,
                outcome.graph.route_entries,
                outcome.elapsed_ms,
                outcome.delta.added_or_modified,
                outcome.delta.unchanged_cached
            );
            if outcome.graph.findings.is_empty() {
                println!("  [OK] No security or logic issues detected.");
            } else {
                println!(
                    "  [!] {} finding(s) detected:",
                    outcome.graph.findings.len()
                );
                for f in &outcome.graph.findings {
                    println!(
                        "\n  [{}] {} ({}) -> {}",
                        f.severity, f.id, f.rule_id, f.title
                    );
                    println!("      Entry: {}", f.entry_route);
                    for (i, hop) in f.witness_path.iter().enumerate() {
                        println!(
                            "      [{}] {}:{}  {}",
                            i + 1,
                            hop.file,
                            hop.line,
                            hop.symbol
                        );
                    }
                    if !f.remediation.is_empty() {
                        println!("      Fix  : {}", f.remediation);
                    }
                }
            }

            if let Some((bwrap, verified)) = &outcome.sandbox {
                println!(
                    "\nShellMind Guard Sandbox Proof (bwrap={}):",
                    if *bwrap { "isolated" } else { "local-loopback" }
                );
                for v in verified {
                    let tag = match v.status {
                        VerificationStatus::Proven => "PROVEN",
                        VerificationStatus::Mitigated => "MITIGATED",
                        VerificationStatus::SuspectUnverified => "SUSPECT",
                    };
                    println!(
                        "  [{}] {} ({}) -> {}",
                        tag, v.finding_id, v.rule_id, v.evidence
                    );
                }
            }

            if patch {
                for f in &outcome.graph.findings {
                    let v_opt = verified_list.iter().find(|v| v.finding_id == f.id);
                    if let Ok(p) = build_minimal_patch_prompt(path, f, v_opt) {
                        println!("\n=== Minimal Patch Context ({} bytes) ===", p.len());
                        println!("{}", p);
                    }
                }
            }
        }
    }
    Ok(())
}

fn run_doctor(path: &Path) {
    println!(
        "ShellMind Guard Doctor | v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let bwrap_ok = Path::new("/usr/bin/bwrap").exists();
    println!(
        "  Sandbox (bwrap) : {}",
        if bwrap_ok {
            "OK (/usr/bin/bwrap)"
        } else {
            "UNAVAILABLE (static 6-layer scan, TUI, SARIF & MCP work; live sandbox requires Linux bwrap)"
        }
    );
    let cfg_exists = path.join(".shellmind-guard.toml").exists();
    println!(
        "  Config          : {}",
        if cfg_exists {
            ".shellmind-guard.toml present"
        } else {
            "using built-in defaults (run `shellmind-guard init` to customize)"
        }
    );
    println!(
        "  Git Pre-Commit  : {}",
        if git_hook_status(path) {
            "ACTIVE"
        } else {
            "not installed (run `shellmind-guard hook install` for zero-AI commit protection)"
        }
    );
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn test_git_hook_install_preserves_existing_and_uninstalls_cleanly() {
        let tmp = std::env::temp_dir().join(format!("smg_hook_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".git").join("hooks")).unwrap();
        let hook_file = tmp.join(".git").join("hooks").join("pre-commit");
        fs::write(&hook_file, "#!/bin/sh\necho 'custom hook'\n").unwrap();

        install_git_hook(&tmp).unwrap();
        assert!(git_hook_status(&tmp));
        let content = fs::read_to_string(&hook_file).unwrap();
        assert!(content.contains("echo 'custom hook'"));
        assert!(content.contains(HOOK_START));

        // Idempotent second install
        install_git_hook(&tmp).unwrap();
        let content2 = fs::read_to_string(&hook_file).unwrap();
        assert_eq!(content2.matches(HOOK_START).count(), 1);

        // Uninstall preserves original custom hook
        assert!(uninstall_git_hook(&tmp).unwrap());
        assert!(!git_hook_status(&tmp));
        let after = fs::read_to_string(&hook_file).unwrap();
        assert!(after.contains("echo 'custom hook'"));
        assert!(!after.contains(HOOK_START));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_fail_on_severity_gate() {
        let med = LatticeFinding {
            id: "VF-FE-001".into(),
            rule_id: "VF-FE-ERR".into(),
            severity: "MEDIUM".into(),
            title: "Empty catch".into(),
            status: "SUSPECT_UNGUARDED".into(),
            entry_route: "app.ts:1".into(),
            file: "app.ts".into(),
            line: 1,
            sink_kind: vf_graph::SinkKind::SqlWrite,
            missing_guard: GuardKind::Auth,
            witness_path: vec![],
            remediation: String::new(),
        };
        assert!(!should_fail_gate(std::slice::from_ref(&med), true, None));
        assert!(should_fail_gate(
            std::slice::from_ref(&med),
            false,
            Some(FailSeverity::Medium)
        ));
        assert!(!should_fail_gate(&[med], false, Some(FailSeverity::High)));
    }
}
