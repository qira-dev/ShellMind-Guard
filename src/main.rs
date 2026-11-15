mod deps_sync;
mod mcp;

use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sh_ai::{
    apply_unified_diff_safely, build_minimal_patch_prompt, generate_patch_plan,
    provider_from_config,
};
use sh_core::{DeltaStats, ShellMindGuardConfig, StateStore, scan_repository};
use sh_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase,
    analyze_codebase_cached, collect_deep_schema_findings,
};
use sh_report::{to_html_graph, to_sarif_json};
use sh_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, detect_sandbox_backend,
    verify_deep_fuzz_blocking_with_config, verify_deep_fuzz_in_sandbox,
    verify_finding_blocking_with_config, verify_findings_in_sandbox_with_config,
};
use sh_tui::{TuiLaunchConfig, run_tui};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum ProbeMode {
    #[default]
    Verify,
    Fuzz,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum FailSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum MinConfidenceArg {
    Proven,
    Confirmed,
    Heuristic,
}

impl MinConfidenceArg {
    fn to_confidence(self) -> Confidence {
        match self {
            MinConfidenceArg::Proven => Confidence::Proven,
            MinConfidenceArg::Confirmed => Confidence::Confirmed,
            MinConfidenceArg::Heuristic => Confidence::Heuristic,
        }
    }
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
    /// Internal handler for Claude Code PreToolUse Bash hook (reads JSON from stdin)
    #[command(name = "claude-pre-commit", hide = true)]
    ClaudePreCommit,
}

#[derive(Subcommand, Debug)]
enum DepsAction {
    /// Explicitly sync OSV CVE/advisory metadata into local offline SQLite cache
    Sync {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            default_value = deps_sync::DEFAULT_OSV_BASE_URL,
            help = "OSV API base URL (https:// required for remote endpoints)"
        )]
        osv_url: String,
        #[arg(
            long,
            help = "Import OSV advisory JSON bundle offline instead of querying OSV HTTP API"
        )]
        from_file: Option<PathBuf>,
    },
    /// Inspect local offline SQLite CVE/advisory cache path, record count, and sync state
    Status,
}

pub(crate) struct ScanRunOptions<'a> {
    pub path: &'a Path,
    pub layers: &'a [String],
    pub min_confidence: Option<Confidence>,
    pub boot_cmd: Option<String>,
    pub port: u16,
    pub sync_race: usize,
    pub unsafe_host_fallback: bool,
    pub trust_repo_config: bool,
    pub deep: bool,
    pub sandbox_mem_mb: Option<u64>,
    pub sandbox_tls: bool,
    pub mock_shims: bool,
    pub cgroup_v2: bool,
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
            help = "Filter active layers (auth,race,taint,sqli,cmdi,path,ssrf,xss,csrf,idor,secrets,config,deps,frontend,engine,memory,mobile,deep)"
        )]
        layers: Vec<String>,
        #[arg(
            long,
            value_enum,
            help = "Hide findings below this confidence tier (proven, confirmed, heuristic)"
        )]
        min_confidence: Option<MinConfidenceArg>,
        #[arg(
            long,
            help = "Enable Phase 10 deep schema validation (VF-FUZZ-SCHEMA) & targeted route payload fuzzing"
        )]
        deep: bool,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
        #[arg(
            long,
            value_name = "MB",
            help = "Optional RLIMIT_AS / cgroups v2 memory limit (MiB) inside sandbox"
        )]
        sandbox_mem_mb: Option<u64>,
        #[arg(
            long,
            help = "Probe sandbox target over local loopback TLS using rustls"
        )]
        sandbox_tls: bool,
        #[arg(
            long,
            help = "Start deterministic loopback mock shims (/v1/charges, /oauth/token, /webhooks) inside sandbox"
        )]
        mock_shims: bool,
        #[arg(
            long,
            help = "Enforce systemd-run user cgroups v2 memory/task limits when available"
        )]
        cgroup_v2: bool,
        #[arg(long)]
        sarif: Option<PathBuf>,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        patch: bool,
        /// Allow unsafe host execution if `/usr/bin/bwrap` is unavailable
        #[arg(long)]
        unsafe_host_fallback: bool,
        /// Trust `sandbox.boot_cmd` defined in the scanned repo's `.shellmind-guard.toml`
        #[arg(long)]
        trust_repo_config: bool,
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
        trust_repo_config: bool,
        #[arg(long)]
        patch: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Apply an explicit unified diff file during --apply-check verification"
        )]
        patch_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Apply the patch inside an isolated temporary workspace copy and re-verify before exiting"
        )]
        apply_check: bool,
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
        #[arg(long)]
        trust_repo_config: bool,
    },
    /// Start stdio JSON-RPC 2.0 MCP server (exposes shellmind_guard_scan, shellmind_guard_explain_finding, shellmind_guard_init)
    Mcp,
    /// Manage standalone Git pre-commit hook for zero-AI local protection
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Manage high-speed offline SQLite CVE & OSV advisory cache
    Deps {
        #[command(subcommand)]
        action: DepsAction,
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
        #[arg(long, value_enum, default_value_t = ProbeMode::Verify)]
        mode: ProbeMode,
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
                | GuardKind::XssSanitizer
                | GuardKind::CsrfProtection
                | GuardKind::OwnershipCheck
                | GuardKind::FrontendContract
                | GuardKind::InputValidation
        ),
        "deep" | "fuzz" | "schema" => {
            f.missing_guard == GuardKind::InputValidation || f.rule_id.starts_with("VF-FUZZ-")
        }
        "3" | "layer3" | "deps" | "dep" | "dependencies" => {
            f.missing_guard == GuardKind::DependencyPolicy
        }
        "4" | "layer4" | "config" | "misconfig" => f.missing_guard == GuardKind::ConfigPolicy,
        "5" | "layer5" | "6" | "layer6" | "race" => f.missing_guard == GuardKind::TxLock,
        "concurrency" => matches!(f.missing_guard, GuardKind::TxLock | GuardKind::LockOrdering),
        "engine" | "deadlock" | "leak" | "int" => {
            matches!(
                f.missing_guard,
                GuardKind::LockOrdering | GuardKind::ResourceCleanup
            ) || f.rule_id.starts_with("VF-ENG-")
        }
        "memory" | "mem" | "bounds" => {
            f.missing_guard == GuardKind::MemoryBounds || f.rule_id.starts_with("VF-MEM-")
        }
        "mobile" | "mob" | "android" | "ios" | "flutter" => {
            f.missing_guard == GuardKind::MobilePolicy || f.rule_id.starts_with("VF-MOB-")
        }
        "auth" => f.missing_guard == GuardKind::Auth,
        "taint" | "injection" => matches!(
            f.missing_guard,
            GuardKind::SqlSanitizer
                | GuardKind::CmdSanitizer
                | GuardKind::PathSanitizer
                | GuardKind::SsrfSanitizer
                | GuardKind::XssSanitizer
        ),
        "sql" | "sqli" => f.missing_guard == GuardKind::SqlSanitizer,
        "cmd" | "cmdi" => f.missing_guard == GuardKind::CmdSanitizer,
        "path" => f.missing_guard == GuardKind::PathSanitizer,
        "ssrf" => f.missing_guard == GuardKind::SsrfSanitizer,
        "xss" => f.missing_guard == GuardKind::XssSanitizer,
        "csrf" => f.missing_guard == GuardKind::CsrfProtection,
        "idor" => f.missing_guard == GuardKind::OwnershipCheck,
        "secrets" | "secret" => f.missing_guard == GuardKind::SecretPolicy,
        "frontend" | "fe" | "contract" => f.missing_guard == GuardKind::FrontendContract,
        other => {
            f.rule_id.to_ascii_lowercase().contains(other)
                || f.id.to_ascii_lowercase().contains(other)
        }
    }
}

fn probe_config_from_cfg(cfg: &ShellMindGuardConfig) -> SandboxProbeConfig {
    SandboxProbeConfig {
        user_a_header: cfg.sandbox.user_a_header.clone(),
        user_b_header: cfg.sandbox.user_b_header.clone(),
        probe_body: cfg.sandbox.probe_body.clone(),
        memory_limit_mb: cfg.sandbox.memory_limit_mb,
        use_cgroup_v2: cfg.sandbox.use_cgroup_v2,
        use_tls: cfg.sandbox.is_tls(),
        mock_shims: cfg.sandbox.mock_shims,
        fuzz_routes: Vec::new(),
    }
}

fn probe_config_from_opts(
    cfg: &ShellMindGuardConfig,
    opts: &ScanRunOptions<'_>,
    fuzz_routes: Vec<sh_graph::RouteSchema>,
) -> SandboxProbeConfig {
    let mut probe_cfg = probe_config_from_cfg(cfg);
    if let Some(mb) = opts.sandbox_mem_mb {
        probe_cfg.memory_limit_mb = Some(mb);
    }
    if opts.cgroup_v2 {
        probe_cfg.use_cgroup_v2 = true;
    }
    if opts.sandbox_tls {
        probe_cfg.use_tls = true;
    }
    if opts.mock_shims {
        probe_cfg.mock_shims = true;
    }
    probe_cfg.fuzz_routes = fuzz_routes;
    probe_cfg
}

fn apply_verification_statuses(
    findings: &mut [LatticeFinding],
    ver_map: &HashMap<&str, &VerificationStatus>,
) {
    for f in findings {
        if let Some(st) = ver_map.get(f.id.as_str()) {
            match st {
                VerificationStatus::Proven => {
                    f.status = "PROVEN".into();
                    f.confidence = Confidence::Proven;
                }
                VerificationStatus::Mitigated => f.status = "MITIGATED".into(),
                VerificationStatus::Unbootable => f.status = "UNBOOTABLE".into(),
                VerificationStatus::SuspectUnverified => {}
            }
        }
    }
}

fn resolve_sandbox_port(cli_port: u16, cfg: &ShellMindGuardConfig) -> Result<u16> {
    if cli_port != 39911 {
        Ok(cli_port)
    } else {
        Ok(cfg.sandbox.loopback_port()?.unwrap_or(cli_port))
    }
}

pub(crate) fn execute_scan_pipeline(opts: ScanRunOptions<'_>) -> Result<ScanOutcome> {
    let t0 = Instant::now();
    let cfg = ShellMindGuardConfig::load_from_dir(opts.path)?;
    let summary = scan_repository(opts.path, &cfg)?;
    let mut store = StateStore::open(opts.path)?;
    let (delta, _) = store.sync_files(&summary.files)?;
    let mut graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;

    if opts.deep {
        graph_res
            .findings
            .extend(collect_deep_schema_findings(&graph_res));
    }
    let mut all_findings = graph_res.findings.clone();

    if !opts.layers.is_empty() {
        graph_res
            .findings
            .retain(|f| opts.layers.iter().any(|l| finding_matches_layer(f, l)));
    }

    let effective_boot = opts.boot_cmd.clone().or_else(|| {
        opts.trust_repo_config
            .then(|| cfg.sandbox.boot_cmd.clone())
            .flatten()
    });
    let effective_port = resolve_sandbox_port(opts.port, &cfg)?;
    let wants_deep_fuzz = opts.deep
        && !graph_res.route_schemas.is_empty()
        && (opts.layers.is_empty()
            || opts.layers.iter().any(|l| {
                matches!(
                    l.trim().to_ascii_lowercase().as_str(),
                    "all" | "*" | "deep" | "fuzz" | "schema" | "2" | "layer2"
                )
            }));
    let fuzz_routes = if wants_deep_fuzz {
        graph_res.route_schemas.clone()
    } else {
        Vec::new()
    };
    let probe_cfg = probe_config_from_opts(&cfg, &opts, fuzz_routes);
    let has_dynamic_targets = graph_res.findings.iter().any(|f| {
        matches!(
            f.missing_guard,
            GuardKind::Auth | GuardKind::TxLock | GuardKind::OwnershipCheck
        )
    });

    let mut sandbox_res: Option<(bool, Vec<VerifiedFinding>)> = None;
    if let Some(cmd) = effective_boot {
        if has_dynamic_targets {
            match verify_findings_in_sandbox_with_config(
                opts.path,
                &cmd,
                effective_port,
                &graph_res.findings,
                opts.sync_race,
                opts.unsafe_host_fallback,
                &probe_cfg,
            ) {
                Ok(res) => sandbox_res = Some(res),
                Err(e) => eprintln!("[ShellMind Guard] Sandbox verification failed: {}", e),
            }
        }
        if wants_deep_fuzz {
            match verify_deep_fuzz_in_sandbox(
                opts.path,
                &cmd,
                effective_port,
                opts.unsafe_host_fallback,
                &probe_cfg,
            ) {
                Ok((bwrap_iso, hits, unbootable_opt)) => {
                    let entry = sandbox_res.get_or_insert_with(|| (bwrap_iso, Vec::new()));
                    entry.0 = entry.0 || bwrap_iso;
                    let live_offset = all_findings
                        .iter()
                        .filter(|f| f.id.starts_with("VF-FUZZ-"))
                        .count()
                        + 1;
                    for (idx, mut hit) in hits.into_iter().enumerate() {
                        let live_id = format!("VF-FUZZ-LIVE-{:03}", live_offset + idx);
                        hit.finding.id = live_id.clone();
                        hit.finding.status = "PROVEN".into();
                        hit.finding.confidence = Confidence::Proven;
                        hit.verified.finding_id = live_id.clone();
                        hit.verified.replay_cmd = format!("shellmind-guard replay {}", live_id);

                        let layer_ok = opts.layers.is_empty()
                            || opts
                                .layers
                                .iter()
                                .any(|l| finding_matches_layer(&hit.finding, l));
                        if layer_ok {
                            graph_res.findings.push(hit.finding.clone());
                        }
                        all_findings.push(hit.finding);
                        entry.1.push(hit.verified);
                    }
                    if let Some(reason) = unbootable_opt {
                        eprintln!("[ShellMind Guard] Deep fuzz sandbox status: {}", reason);
                        if entry.1.is_empty() {
                            entry.1.push(VerifiedFinding {
                                finding_id: "VF-SANDBOX-BOOT".into(),
                                rule_id: "VF-SANDBOX-UNBOOTABLE".into(),
                                entry_route: cmd.clone(),
                                status: VerificationStatus::Unbootable,
                                evidence: reason,
                                replay_cmd: format!(
                                    "shellmind-guard scan {} --deep --boot-cmd {:?}",
                                    opts.path.display(),
                                    cmd
                                ),
                            });
                        }
                    }
                }
                Err(e) => eprintln!("[ShellMind Guard] Deep fuzz sandbox failed: {}", e),
            }
        }
    }

    let verified_list: Vec<VerifiedFinding> = sandbox_res
        .as_ref()
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    if !verified_list.is_empty() {
        let ver_map: HashMap<&str, &VerificationStatus> = verified_list
            .iter()
            .map(|v| (v.finding_id.as_str(), &v.status))
            .collect();
        apply_verification_statuses(&mut graph_res.findings, &ver_map);
        apply_verification_statuses(&mut all_findings, &ver_map);
    }

    if let Some(min_conf) = opts.min_confidence {
        graph_res.findings.retain(|f| f.confidence >= min_conf);
    }

    persist_scan_findings(&mut store, delta.scan_id, &all_findings, &verified_list)?;

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

    let mut owned_rows: Vec<(String, String, String, String, String, String, String)> =
        Vec::with_capacity(findings.len());
    for f in findings {
        let v_opt = ver_map.get(f.id.as_str()).copied();
        let status_str = match v_opt.map(|v| &v.status) {
            Some(VerificationStatus::Proven) => "PROVEN",
            Some(VerificationStatus::Mitigated) => "MITIGATED",
            Some(VerificationStatus::Unbootable) => "UNBOOTABLE",
            _ => f.status.as_str(),
        };
        let conf_str = if status_str == "PROVEN" || f.confidence == Confidence::Proven {
            Confidence::Proven.as_str()
        } else {
            f.confidence.as_str()
        };
        let trace_json = serde_json::to_string(f).unwrap_or_else(|_| "{}".into());
        let poc_cmd = v_opt
            .map(|v| v.replay_cmd.clone())
            .unwrap_or_else(|| format!("shellmind-guard replay {}", f.id));
        owned_rows.push((
            f.id.clone(),
            f.rule_id.clone(),
            f.severity.clone(),
            conf_str.to_string(),
            status_str.to_string(),
            trace_json,
            poc_cmd,
        ));
    }

    let borrowed: Vec<(&str, &str, &str, &str, &str, &str, &str)> = owned_rows
        .iter()
        .map(|(a, b, c, d, e, f, g)| {
            (
                a.as_str(),
                b.as_str(),
                c.as_str(),
                d.as_str(),
                e.as_str(),
                f.as_str(),
                g.as_str(),
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
            let existing_cfg = path.join(".shellmind-guard.toml");
            let (detected, out_path) = if existing_cfg.exists() {
                (vec!["existing config preserved".to_string()], existing_cfg)
            } else {
                ShellMindGuardConfig::detect_and_write_init(&path)?
            };
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
                    "ShellMind Guard Init | Detected: {} | Config: {}",
                    detected.join(", "),
                    out_path.display()
                );
            } else {
                println!(
                    "ShellMind Guard Init | Detected: {} | Config: {} and {}",
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
            min_confidence,
            deep,
            boot_cmd,
            port,
            sync_race,
            sandbox_mem_mb,
            sandbox_tls,
            mock_shims,
            cgroup_v2,
            sarif,
            html,
            patch,
            unsafe_host_fallback,
            trust_repo_config,
            ci,
            fail_on,
            watch,
        } => {
            let effective_format = if json { OutputFormat::Json } else { format };
            let min_conf = min_confidence.map(|m| m.to_confidence());
            let outcome = execute_scan_pipeline(ScanRunOptions {
                path: &path,
                layers: &layers,
                min_confidence: min_conf,
                boot_cmd: boot_cmd.clone(),
                port,
                sync_race,
                unsafe_host_fallback,
                trust_repo_config,
                deep,
                sandbox_mem_mb,
                sandbox_tls,
                mock_shims,
                cgroup_v2,
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
            if let Some(ref html_path) = html {
                if let Some(parent) = html_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(
                    html_path,
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
                let init_cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                let init_summary = scan_repository(&path, &init_cfg)?;
                let mut prev_sig: Vec<(String, i64, u64)> = init_summary
                    .files
                    .iter()
                    .map(|f| (f.rel_path.clone(), f.mtime_ns, f.size_bytes))
                    .collect();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                    let summary = scan_repository(&path, &cfg)?;
                    let cur_sig: Vec<(String, i64, u64)> = summary
                        .files
                        .iter()
                        .map(|f| (f.rel_path.clone(), f.mtime_ns, f.size_bytes))
                        .collect();
                    if cur_sig != prev_sig {
                        prev_sig = cur_sig;
                        let next_outcome = execute_scan_pipeline(ScanRunOptions {
                            path: &path,
                            layers: &layers,
                            min_confidence: min_conf,
                            boot_cmd: boot_cmd.clone(),
                            port,
                            sync_race,
                            unsafe_host_fallback,
                            trust_repo_config,
                            deep,
                            sandbox_mem_mb,
                            sandbox_tls,
                            mock_shims,
                            cgroup_v2,
                        })?;
                        let next_verified: Vec<VerifiedFinding> = next_outcome
                            .sandbox
                            .as_ref()
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                        let next_sarif =
                            if sarif.is_some() || effective_format == OutputFormat::Sarif {
                                Some(to_sarif_json(&next_outcome.graph.findings, &next_verified))
                            } else {
                                None
                            };
                        if let Some(ref sarif_path) = sarif
                            && let Some(ref payload) = next_sarif
                        {
                            let _ = fs::write(sarif_path, payload);
                        }
                        if let Some(ref html_path) = html {
                            let _ = fs::write(
                                html_path,
                                to_html_graph(
                                    &path.display().to_string(),
                                    &next_outcome.graph,
                                    &next_verified,
                                ),
                            );
                        }
                        render_scan_output(
                            &path,
                            effective_format,
                            &next_outcome,
                            &next_verified,
                            next_sarif.as_deref(),
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
            trust_repo_config,
            patch,
            patch_file,
            apply_check,
        } => {
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let mut store = StateStore::open(&path)?;
            let finding = resolve_finding_for_replay(&path, &finding_id, &cfg, &mut store)?;
            let effective_boot = boot_cmd.or_else(|| {
                trust_repo_config
                    .then(|| cfg.sandbox.boot_cmd.clone())
                    .flatten()
            });

            if !apply_check && effective_boot.is_none() {
                anyhow::bail!(
                    "No --boot-cmd provided (pass --boot-cmd \"...\" or --trust-repo-config if .shellmind-guard.toml defines one)"
                );
            }

            let effective_port = resolve_sandbox_port(port, &cfg)?;
            let probe_cfg = probe_config_from_cfg(&cfg);
            let mut verified = Vec::new();
            if let Some(ref boot) = effective_boot {
                let (bwrap, v) = verify_findings_in_sandbox_with_config(
                    &path,
                    boot,
                    effective_port,
                    std::slice::from_ref(&finding),
                    sync_race,
                    unsafe_host_fallback,
                    &probe_cfg,
                )?;
                println!(
                    "ShellMind Guard Replay | {} ({}) | bwrap={}",
                    finding.id,
                    finding.entry_route,
                    if bwrap { "isolated" } else { "local-loopback" }
                );
                for item in &v {
                    let tag = verification_status_tag(&item.status);
                    println!("  [{}] {}", tag, item.evidence);
                    println!("  Command: {}", item.replay_cmd);
                }
                verified = v;
            } else {
                println!(
                    "ShellMind Guard Replay | {} ({}) | static-only apply-check",
                    finding.id, finding.entry_route
                );
            }

            let mut ai_patch_text: Option<String> = None;
            let want_ai_or_prompt = patch || (apply_check && patch_file.is_none());
            if want_ai_or_prompt {
                if cfg.ai.is_enabled() {
                    if !trust_repo_config {
                        if apply_check && patch_file.is_none() {
                            anyhow::bail!(
                                "Repository config enables [ai] provider '{}'; pass --trust-repo-config (or --patch-file <FILE>) to authorize automated patch requests",
                                cfg.ai.provider
                            );
                        }
                        if patch {
                            eprintln!(
                                "[!] Ignoring [ai].provider='{}' in .shellmind-guard.toml without --trust-repo-config; showing offline minimal prompt.",
                                cfg.ai.provider
                            );
                            let p = build_minimal_patch_prompt(&path, &finding, verified.first())?;
                            println!("\n=== Minimal Patch Context ({} bytes) ===\n{}", p.len(), p);
                        }
                    } else {
                        let provider = provider_from_config(&cfg.ai)?;
                        if let Some(reply) =
                            generate_patch_plan(&provider, &path, &finding, verified.first())?
                        {
                            if patch {
                                println!("\n=== AI Generated Patch Plan ===\n{}", reply);
                            }
                            ai_patch_text = Some(reply);
                        }
                    }
                } else if patch {
                    let p = build_minimal_patch_prompt(&path, &finding, verified.first())?;
                    println!("\n=== Minimal Patch Context ({} bytes) ===\n{}", p.len(), p);
                }
            }

            if apply_check {
                let raw_diff = if let Some(ref pf) = patch_file {
                    fs::read_to_string(pf).with_context(|| {
                        format!("Failed to read --patch-file '{}'", pf.display())
                    })?
                } else if let Some(diff_reply) = ai_patch_text {
                    diff_reply
                } else {
                    anyhow::bail!(
                        "--apply-check requires --patch-file <FILE> or an enabled [ai] provider in .shellmind-guard.toml (with --trust-repo-config)"
                    );
                };

                let outcome = verify_patch_apply_check(&ApplyCheckParams {
                    project_root: &path,
                    cfg: &cfg,
                    finding: &finding,
                    raw_diff: &raw_diff,
                    boot_cmd: effective_boot.as_deref(),
                    port: effective_port,
                    sync_race,
                    unsafe_host_fallback,
                    probe_cfg: &probe_cfg,
                })?;

                println!(
                    "\n=== Isolated Patch Verification (modified: {:?}, hunks: {}) ===",
                    outcome.modified_files, outcome.hunks_applied
                );
                if outcome.mitigated {
                    println!("  [MITIGATED] {}", outcome.summary);
                } else {
                    eprintln!("  [UNMITIGATED] {}", outcome.summary);
                    return Ok(ExitCode::from(2));
                }
            }
        }
        Commands::Ui {
            path,
            boot_cmd,
            port,
            sync_race,
            unsafe_host_fallback,
            trust_repo_config,
        } => {
            let t0 = Instant::now();
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _) = store.sync_files(&summary.files)?;
            let graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
            let effective_boot = boot_cmd.or_else(|| {
                trust_repo_config
                    .then(|| cfg.sandbox.boot_cmd.clone())
                    .flatten()
            });
            let effective_port = resolve_sandbox_port(port, &cfg)?;
            let probe_cfg = probe_config_from_cfg(&cfg);
            let verified_list = if let Some(ref cmd) = effective_boot {
                if !graph_res.findings.is_empty() {
                    verify_findings_in_sandbox_with_config(
                        &path,
                        cmd,
                        effective_port,
                        &graph_res.findings,
                        sync_race,
                        unsafe_host_fallback,
                        &probe_cfg,
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
            HookAction::ClaudePreCommit => {
                return handle_claude_pre_commit();
            }
        },
        Commands::Deps { action } => match action {
            DepsAction::Sync {
                path,
                osv_url,
                from_file,
            } => {
                let db_path = sh_core::default_advisories_db_path();
                let mut store = sh_core::AdvisoryStore::open_default()?;
                if let Some(ref osv_file) = from_file {
                    let imported = deps_sync::import_osv_file_to_store(osv_file, &mut store)?;
                    let (total, _) = store.stats()?;
                    println!(
                        "ShellMind Guard Deps | Imported {} advisory range(s) from {} into {} (total cached: {})",
                        imported,
                        osv_file.display(),
                        db_path.display(),
                        total
                    );
                } else {
                    let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                    let deps = deps_sync::extract_project_dependencies(&path, &cfg)?;
                    if deps.is_empty() {
                        println!(
                            "ShellMind Guard Deps | No resolved lockfile/manifest dependencies found under {}; skipped network sync.",
                            path.display()
                        );
                    } else {
                        let summary = deps_sync::sync_osv_to_store(&osv_url, &deps, &mut store)?;
                        let (total, _) = store.stats()?;
                        println!(
                            "ShellMind Guard Deps | Queried {} dep(s), fetched {} vuln(s), upserted {} range(s) into {} (total cached: {})",
                            summary.dependencies_queried,
                            summary.unique_vulns_fetched,
                            summary.records_upserted,
                            db_path.display(),
                            total
                        );
                    }
                }
            }
            DepsAction::Status => {
                let db_path = sh_core::default_advisories_db_path();
                if !db_path.exists() {
                    println!(
                        "ShellMind Guard Deps | DB: {} | Status: NOT INITIALIZED (0 advisories; run `shellmind-guard deps sync`)",
                        db_path.display()
                    );
                } else {
                    let store = sh_core::AdvisoryStore::open_at(&db_path, true)?;
                    let (total, last_updated) = store.stats()?;
                    let ts_str = last_updated
                        .map(|ts| ts.to_string())
                        .unwrap_or_else(|| "never".to_string());
                    println!(
                        "ShellMind Guard Deps | DB: {} | Advisories: {} | Last Sync (UNIX): {}",
                        db_path.display(),
                        total,
                        ts_str
                    );
                }
            }
        },
        Commands::Doctor { path } => {
            run_doctor(&path);
        }
        Commands::ProbeNetns {
            port,
            sync_race,
            mode,
        } => {
            let probe_cfg: SandboxProbeConfig = std::env::var("VF_PROBE_CONFIG_JSON")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            match mode {
                ProbeMode::Verify => {
                    let finding_json = std::env::var("VF_FINDING_JSON")?;
                    let finding: LatticeFinding = serde_json::from_str(&finding_json)?;
                    let res =
                        verify_finding_blocking_with_config(port, &finding, sync_race, &probe_cfg)?;
                    println!("{}", serde_json::to_string(&res)?);
                }
                ProbeMode::Fuzz => {
                    let hits = verify_deep_fuzz_blocking_with_config(port, &probe_cfg)?;
                    println!("{}", serde_json::to_string(&hits)?);
                }
            }
        }
    }

    sh_sandbox::kill_active_sandbox_pgid();
    Ok(ExitCode::SUCCESS)
}

fn parse_git_commit_invocation(cmd_str: &str) -> Option<PathBuf> {
    let mut current_cd: Option<PathBuf> = None;
    for seg in cmd_str.split([';', '&', '|', '\n', '(', ')', '`']) {
        let mut tokens: Vec<&str> = seg.split_whitespace().collect();
        while let Some(&first) = tokens.first() {
            let unquoted = first.trim_matches(|c| c == '"' || c == '\'');
            let is_env_assign = unquoted.contains('=')
                && !unquoted.starts_with('-')
                && !unquoted.starts_with('/')
                && !unquoted.starts_with('.');
            if is_env_assign || matches!(unquoted, "sudo" | "env" | "command" | "nohup" | "$") {
                tokens.remove(0);
            } else {
                break;
            }
        }
        let Some(&cmd_tok) = tokens.first() else {
            continue;
        };
        let cmd_clean = cmd_tok.trim_matches(|c| c == '"' || c == '\'');
        if cmd_clean == "cd" {
            if let Some(&dir_tok) = tokens.get(1) {
                let dir_clean = dir_tok.trim_matches(|c| c == '"' || c == '\'');
                if !dir_clean.is_empty() && !dir_clean.starts_with('-') {
                    current_cd = Some(PathBuf::from(dir_clean));
                }
            }
            continue;
        }
        let is_git = cmd_clean == "git"
            || cmd_clean.ends_with("/git")
            || cmd_clean.ends_with("\\git")
            || cmd_clean.ends_with("/git.exe")
            || cmd_clean.ends_with("\\git.exe");
        if !is_git {
            continue;
        }

        let mut git_dir_override: Option<PathBuf> = None;
        let mut subcmd: Option<&str> = None;
        let mut i = 1usize;
        while i < tokens.len() {
            let t = tokens[i].trim_matches(|c| c == '"' || c == '\'');
            if t == "-C" || t == "--work-tree" {
                if let Some(&dir_arg) = tokens.get(i + 1) {
                    let clean_dir = dir_arg.trim_matches(|c| c == '"' || c == '\'');
                    git_dir_override = Some(PathBuf::from(clean_dir));
                }
                i += 2;
                continue;
            }
            if let Some(rest) = t.strip_prefix("-C").filter(|r| !r.is_empty()) {
                git_dir_override = Some(PathBuf::from(rest));
                i += 1;
                continue;
            }
            if let Some(rest) = t.strip_prefix("--work-tree=") {
                git_dir_override = Some(PathBuf::from(rest));
                i += 1;
                continue;
            }
            if matches!(t, "-c" | "--git-dir" | "--namespace" | "--exec-path") {
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            subcmd = Some(t);
            break;
        }

        if matches!(subcmd, Some("commit" | "ci")) {
            let resolved = match (&current_cd, git_dir_override) {
                (Some(cd), Some(ov)) if ov.is_relative() => cd.join(ov),
                (_, Some(ov)) => ov,
                (Some(cd), None) => cd.clone(),
                (None, None) => PathBuf::from("."),
            };
            return Some(resolved);
        }
    }
    None
}

fn handle_claude_pre_commit() -> Result<ExitCode> {
    use std::io::Read;
    let mut stdin_buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    let cmd_str = serde_json::from_str::<serde_json::Value>(&stdin_buf)
        .ok()
        .and_then(|v| {
            v.get("tool_input")
                .and_then(|ti| ti.get("command"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let Some(target_repo) = parse_git_commit_invocation(&cmd_str) else {
        return Ok(ExitCode::SUCCESS);
    };
    let scan_path = if target_repo.exists() {
        target_repo
    } else {
        PathBuf::from(".")
    };

    let layers = vec!["secrets".to_string(), "config".to_string()];
    let outcome = execute_scan_pipeline(ScanRunOptions {
        path: &scan_path,
        layers: &layers,
        min_confidence: None,
        boot_cmd: None,
        port: 39911,
        sync_race: 12,
        unsafe_host_fallback: false,
        trust_repo_config: false,
        deep: false,
        sandbox_mem_mb: None,
        sandbox_tls: false,
        mock_shims: false,
        cgroup_v2: false,
    })?;

    if should_fail_gate(&outcome.graph.findings, true, None) {
        eprintln!(
            "[ShellMind Guard] Blocked git commit: {} secret/config issue(s) found.",
            outcome.graph.findings.len()
        );
        for f in &outcome.graph.findings {
            eprintln!(
                "  [{}] {} -> {} ({}:{})",
                f.severity, f.id, f.title, f.file, f.line
            );
        }
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

const HOOK_START: &str = "# >>> shellmind-guard pre-commit >>>";
const HOOK_END: &str = "# <<< shellmind-guard pre-commit <<<";

fn resolve_git_hooks_dir(root: &Path) -> Result<PathBuf> {
    if let Ok(out) = std::process::Command::new("git")
        .args([
            "-C",
            &root.to_string_lossy(),
            "rev-parse",
            "--git-path",
            "hooks",
        ])
        .output()
        && out.status.success()
    {
        let rel = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !rel.is_empty() {
            let p = PathBuf::from(&rel);
            return Ok(if p.is_absolute() { p } else { root.join(p) });
        }
    }
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
    let Some(rel_end) = existing[start_idx..].find(HOOK_END) else {
        anyhow::bail!(
            "Found {} without matching {}; refusing partial hook edit",
            HOOK_START,
            HOOK_END
        );
    };
    let end_idx = start_idx + rel_end + HOOK_END.len();
    let before = existing[..start_idx].trim_end();
    let after = existing[end_idx..].trim_start();
    let remaining = match (before.is_empty(), after.is_empty()) {
        (true, true) => String::new(),
        (false, true) => before.to_string(),
        (true, false) => after.to_string(),
        (false, false) => format!("{}\n{}", before, after),
    };
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

fn verification_status_tag(st: &VerificationStatus) -> &'static str {
    match st {
        VerificationStatus::Proven => "PROVEN",
        VerificationStatus::Mitigated => "MITIGATED",
        VerificationStatus::SuspectUnverified => "SUSPECT",
        VerificationStatus::Unbootable => "UNBOOTABLE",
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
                        "\n  [{}] [{}] {} ({}) -> {}",
                        f.severity,
                        f.confidence.as_str(),
                        f.id,
                        f.rule_id,
                        f.title
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
                    let tag = verification_status_tag(&v.status);
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
    let backend = detect_sandbox_backend();
    let bwrap_ok = sh_sandbox::has_bwrap();
    println!("  Sandbox Backend : {}", backend.label());
    println!(
        "  Sandbox (bwrap) : {}",
        if bwrap_ok {
            "OK (bwrap available; --unshare-all netns isolation active)"
        } else {
            "UNAVAILABLE (static scan, TUI, SARIF & MCP work; fallback sandbox uses host loopback if authorized)"
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

static APPLY_CHECK_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirCleanup(PathBuf);

impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ApplyCheckParams<'a> {
    project_root: &'a Path,
    cfg: &'a ShellMindGuardConfig,
    finding: &'a LatticeFinding,
    raw_diff: &'a str,
    boot_cmd: Option<&'a str>,
    port: u16,
    sync_race: usize,
    unsafe_host_fallback: bool,
    probe_cfg: &'a SandboxProbeConfig,
}

#[derive(Debug)]
struct ApplyCheckOutcome {
    mitigated: bool,
    summary: String,
    modified_files: Vec<PathBuf>,
    hunks_applied: usize,
}

fn copy_workspace_for_apply_check(src_root: &Path, dst_root: &Path) -> Result<()> {
    let canon_src = fs::canonicalize(src_root)?;
    let canon_dst = fs::canonicalize(dst_root)?;
    copy_dir_recursive(&canon_src, &canon_dst, &canon_dst)
}

fn copy_dir_recursive(src: &Path, dst: &Path, canonical_dst_root: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if matches!(
            name_str.as_ref(),
            ".git" | "target" | ".shellmind-guard" | ".veriforge"
        ) {
            continue;
        }
        let meta = entry.metadata()?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let src_path = entry.path();
        if src_path == canonical_dst_root {
            continue;
        }
        let dst_path = dst.join(&name);
        if meta.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir_recursive(&src_path, &dst_path, canonical_dst_root)?;
        } else if meta.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn finding_still_present<'a>(
    post_findings: &'a [LatticeFinding],
    target: &LatticeFinding,
) -> Option<&'a LatticeFinding> {
    post_findings.iter().find(|f| {
        f.rule_id == target.rule_id
            && f.sink_kind == target.sink_kind
            && f.file == target.file
            && (f.entry_route == target.entry_route
                || (target.entry_route.contains(':') && f.title == target.title))
    })
}

fn verify_patch_apply_check(params: &ApplyCheckParams<'_>) -> Result<ApplyCheckOutcome> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = APPLY_CHECK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_root = std::env::temp_dir().join(format!(
        "smg_apply_check_{}_{}_{}",
        std::process::id(),
        nanos,
        seq
    ));
    fs::create_dir_all(&temp_root)?;
    let _cleanup = TempDirCleanup(temp_root.clone());

    copy_workspace_for_apply_check(params.project_root, &temp_root)?;
    let report = apply_unified_diff_safely(&temp_root, params.raw_diff)?;

    let post_summary = scan_repository(&temp_root, params.cfg)?;
    let post_graph = analyze_codebase(&post_summary.files, params.cfg)?;

    let Some(remaining) = finding_still_present(&post_graph.findings, params.finding) else {
        return Ok(ApplyCheckOutcome {
            mitigated: true,
            summary: format!(
                "Patch eliminated {} ({}) statically in isolated verification workspace",
                params.finding.id, params.finding.rule_id
            ),
            modified_files: report.modified_files,
            hunks_applied: report.hunks_applied,
        });
    };

    if matches!(
        remaining.missing_guard,
        GuardKind::Auth | GuardKind::TxLock | GuardKind::OwnershipCheck
    ) && let Some(boot) = params.boot_cmd
    {
        let (_, post_verified) = verify_findings_in_sandbox_with_config(
            &temp_root,
            boot,
            params.port,
            std::slice::from_ref(remaining),
            params.sync_race,
            params.unsafe_host_fallback,
            params.probe_cfg,
        )?;
        if let Some(first) = post_verified.first() {
            if first.status == VerificationStatus::Mitigated {
                return Ok(ApplyCheckOutcome {
                    mitigated: true,
                    summary: format!("Runtime sandbox proved mitigation: {}", first.evidence),
                    modified_files: report.modified_files,
                    hunks_applied: report.hunks_applied,
                });
            }
            return Ok(ApplyCheckOutcome {
                mitigated: false,
                summary: format!(
                    "Patch did not mitigate {} dynamically ({})",
                    remaining.id, first.evidence
                ),
                modified_files: report.modified_files,
                hunks_applied: report.hunks_applied,
            });
        }
    }

    Ok(ApplyCheckOutcome {
        mitigated: false,
        summary: format!(
            "Patch did not eliminate {} ({}) at {}:{}",
            remaining.id, remaining.rule_id, remaining.file, remaining.line
        ),
        modified_files: report.modified_files,
        hunks_applied: report.hunks_applied,
    })
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

        // Append trailing line after our block to verify uninstall preserves newline separation
        fs::write(&hook_file, format!("{}\necho 'after hook'\n", content)).unwrap();

        // Idempotent second install
        install_git_hook(&tmp).unwrap();
        let content2 = fs::read_to_string(&hook_file).unwrap();
        assert_eq!(content2.matches(HOOK_START).count(), 1);

        // Uninstall preserves original custom hook lines with newline separation
        assert!(uninstall_git_hook(&tmp).unwrap());
        assert!(!git_hook_status(&tmp));
        let after = fs::read_to_string(&hook_file).unwrap();
        assert!(after.contains("echo 'custom hook'\necho 'after hook'"));
        assert!(!after.contains(HOOK_START));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_parse_git_commit_invocation_variants() {
        assert_eq!(
            parse_git_commit_invocation("git commit -m 'fix'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation(
                "GIT_AUTHOR_NAME=a /usr/bin/git -c commit.gpgsign=false commit -m 'x'"
            ),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("git -C /tmp/subrepo commit -m 'x'"),
            Some(PathBuf::from("/tmp/subrepo"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd services/api && (git commit -am 'msg')"),
            Some(PathBuf::from("services/api"))
        );
        assert_eq!(parse_git_commit_invocation("git status && git diff"), None);
    }

    #[test]
    fn test_fail_on_severity_gate() {
        let med = LatticeFinding {
            id: "VF-FE-001".into(),
            rule_id: "VF-FE-ERR".into(),
            severity: "MEDIUM".into(),
            title: "Empty catch".into(),
            status: "SUSPECT_UNGUARDED".into(),
            confidence: Confidence::Heuristic,
            entry_route: "app.ts:1".into(),
            file: "app.ts".into(),
            line: 1,
            sink_kind: sh_graph::SinkKind::SqlWrite,
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

    #[test]
    fn test_apply_check_eliminates_sqli_without_mutating_source_and_detects_ineffective_patch() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let repo = std::env::temp_dir().join(format!("smg_apply_unit_{}", nanos));
        let _cleanup = TempDirCleanup(repo.clone());
        fs::create_dir_all(repo.join("src")).unwrap();
        let route_src = "import express from 'express';\nconst app = express();\napp.get('/api/items', async (req, res) => {\n  const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n  res.json(rows);\n});\n";
        fs::write(repo.join("src/app.ts"), route_src).unwrap();

        let cfg = ShellMindGuardConfig::default();
        let summary = scan_repository(&repo, &cfg).unwrap();
        let graph = analyze_codebase(&summary.files, &cfg).unwrap();
        let sqli = graph
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-SQLI-001")
            .expect("expected initial VF-SQLI-001 finding");

        let probe_cfg = probe_config_from_cfg(&cfg);
        let good_diff = "--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,6 +1,6 @@\n import express from 'express';\n const app = express();\n app.get('/api/items', async (req, res) => {\n-  const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n+  const rows = await db.query('SELECT * FROM items WHERE name = $1', [String(req.query.q)]);\n   res.json(rows);\n });\n";
        let ok = verify_patch_apply_check(&ApplyCheckParams {
            project_root: &repo,
            cfg: &cfg,
            finding: sqli,
            raw_diff: good_diff,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            probe_cfg: &probe_cfg,
        })
        .unwrap();
        assert!(ok.mitigated, "good diff failed: {}", ok.summary);
        assert_eq!(ok.modified_files, vec![PathBuf::from("src/app.ts")]);
        // Original repo file must remain untouched!
        assert_eq!(
            fs::read_to_string(repo.join("src/app.ts")).unwrap(),
            route_src
        );

        let ineffective_diff = "--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,6 +1,6 @@\n import express from 'express';\n const app = express();\n app.get('/api/items', async (req, res) => {\n+  // harmless comment\n   const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n   res.json(rows);\n });\n";
        let bad = verify_patch_apply_check(&ApplyCheckParams {
            project_root: &repo,
            cfg: &cfg,
            finding: sqli,
            raw_diff: ineffective_diff,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            probe_cfg: &probe_cfg,
        })
        .unwrap();
        assert!(!bad.mitigated, "ineffective diff should fail apply-check");

        let traversal_diff = "--- a/../escape.ts\n+++ b/../escape.ts\n@@ -1,1 +1,1 @@\n-a\n+b\n";
        assert!(
            verify_patch_apply_check(&ApplyCheckParams {
                project_root: &repo,
                cfg: &cfg,
                finding: sqli,
                raw_diff: traversal_diff,
                boot_cmd: None,
                port: 39911,
                sync_race: 12,
                unsafe_host_fallback: false,
                probe_cfg: &probe_cfg,
            })
            .is_err()
        );
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = entry.file_name();
            if name == ".shellmind-guard" {
                continue;
            }
            let target = dst.join(name);
            if path.is_dir() {
                copy_dir_recursive(&path, &target);
            } else {
                fs::copy(&path, &target).unwrap();
            }
        }
    }

    #[test]
    fn test_phase10_deep_scan_and_layers_filter_on_fixtures() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_p10_main_{}", nanos));
        let _cleanup = TempDirCleanup(tmp.clone());

        let pay_dir = tmp.join("vuln-payment-node");
        copy_dir_recursive(Path::new("fixtures/vuln-payment-node"), &pay_dir);

        let base_scan = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            !base_scan
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id == "VF-FUZZ-SCHEMA"),
            "deep=false must not emit VF-FUZZ-SCHEMA"
        );

        let deep_scan = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            deep_scan
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id == "VF-FUZZ-SCHEMA"),
            "deep=true must emit VF-FUZZ-SCHEMA on unvalidated payment route amount"
        );

        let deep_layer_only = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &["deep".to_string()],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(!deep_layer_only.graph.findings.is_empty());
        assert!(
            deep_layer_only
                .graph
                .findings
                .iter()
                .all(|f| f.missing_guard == GuardKind::InputValidation)
        );

        let auth_dir = tmp.join("vuln-auth-rust");
        copy_dir_recursive(Path::new("fixtures/vuln-auth-rust"), &auth_dir);
        let auth_deep = execute_scan_pipeline(ScanRunOptions {
            path: &auth_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            auth_deep
                .graph
                .findings
                .iter()
                .any(|f| f.missing_guard == GuardKind::Auth),
            "auth fixture must preserve Auth finding under --deep"
        );
    }
}
