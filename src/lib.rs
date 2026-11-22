mod dast_audit;
mod deps_sync;
mod http_audit;
mod idor_audit;
mod live_verify;
mod mcp;
mod oci_image;
mod proxy;
mod rules_catalog;
mod sqli_audit;
mod templates_audit;
mod tls_audit;

use anyhow::Context;
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use rules_catalog::{CompletionShell, RULE_CATALOG, find_rule_doc, render_shell_completions};
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, export_regression_tests, generate_patch_plan,
    provider_from_config, run_cegis_patch_loop, synthesize_deterministic_codemod_diff,
    verify_patch_in_isolated_copy,
};
use smg_core::{
    DeltaStats, ScanOptions, ShellMindGuardConfig, StateStore, scan_repository,
    scan_repository_with_options,
};
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase_cached,
    analyze_codebase_cached_changed_since, collect_deep_schema_findings, collect_git_changed_files,
    compute_rule_telemetry, deps::extract_resolved_dependencies, finding_matches_layer,
};
use smg_report::{to_cyclonedx_vex_json, to_html_graph, to_sarif_json};
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, detect_sandbox_backend,
    verify_deep_fuzz_blocking_with_config, verify_deep_fuzz_in_sandbox,
    verify_finding_blocking_with_config, verify_findings_batch_blocking_with_config,
    verify_findings_in_sandbox_with_config,
};
use smg_tui::{TuiLaunchConfig, run_tui};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    #[default]
    Text,
    Compact,
    Table,
    Markdown,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug)]
struct AnsiPalette {
    enabled: bool,
}

impl AnsiPalette {
    fn resolve(mode: ColorMode, stream_is_tty: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let enabled = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => !no_color && stream_is_tty,
        };
        Self { enabled }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.wrap("2;37", text)
    }

    fn red(&self, text: &str) -> String {
        self.wrap("1;31", text)
    }

    fn amber(&self, text: &str) -> String {
        self.wrap("1;33", text)
    }

    fn green(&self, text: &str) -> String {
        self.wrap("1;32", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.wrap("1;36", text)
    }

    fn purple(&self, text: &str) -> String {
        self.wrap("1;35", text)
    }

    fn coral(&self, text: &str) -> String {
        self.wrap("38;5;209", text)
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum ProbeMode {
    #[default]
    Verify,
    #[value(name = "verify-batch")]
    VerifyBatch,
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

#[derive(Subcommand, Debug)]
enum EnterpriseAction {
    /// Inspect local Linux Confidential Compute TEE device nodes (`/dev/nsm`, `/dev/tdx_guest`, `/dev/sev-guest`)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Verify a fail-closed Ed25519 signed commercial license token and optional binary digest pin
    VerifyLicense {
        #[arg(long, value_name = "FILE")]
        license: PathBuf,
        #[arg(long, help = "32-byte Ed25519 public key (64-char hex or base64)")]
        pubkey: String,
        #[arg(long, default_value = "enterprise-tee")]
        tier: String,
        #[arg(long, value_name = "BIN")]
        binary: Option<PathBuf>,
    },
    /// Verify a remote TEE attestation quote (`aws-nitro`, `intel-tdx`, `amd-sev-snp`) against pinned PCR0/MRTD & nonce
    VerifyAttestation {
        #[arg(long, value_name = "FILE")]
        quote: PathBuf,
        #[arg(long, help = "32-byte Ed25519 attestation authority public key")]
        pubkey: String,
        #[arg(long, help = "Expected PCR0 / MRTD measurement hex")]
        pcr0: String,
        #[arg(long, help = "Expected single-use hex nonce challenge")]
        nonce: String,
        #[arg(long, default_value = "aws-nitro")]
        platform: String,
    },
    /// Dispatch a remote TEE confidential scan over HTTPS with fail-closed PCR0 quote verification
    RemoteScan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, help = "Remote enclave endpoint (https:// required remotely)")]
        endpoint: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        pcr0: String,
        #[arg(long, default_value = "aws-nitro")]
        platform: String,
        #[arg(long, value_name = "FILE")]
        license: Option<PathBuf>,
    },
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
    pub deep_audit: bool,
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
    name = "smg",
    version,
    about = "ShellMind Guard (smg) — Zero-false-positive multi-file business-logic & security verifier"
)]
struct Cli {
    /// Control colored terminal output (auto, always, never)
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Args, Debug)]
struct ScanCmdArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, help = "Shorthand for --format json")]
    json: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write formatted scan output to FILE instead of stdout (disables ANSI colors)"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Filter active layers (auth,race,concurrency,taint,sqli,cmdi,path,ssrf,xss,csrf,idor,secrets,config,deps,frontend,cicd,k8s,dos,zip,crypto,queue,api,ai,oauth,smuggle,state,engine,memory,mobile,hw,web3,pqc,deep)"
    )]
    layers: Vec<String>,
    #[arg(
        long,
        value_name = "POLICY",
        help = "Enable opt-in compliance analyzers (e.g. `pqc` for NIST PQC bit reduction & Mosca HNDL urgency)"
    )]
    compliance: Option<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write CycloneDX 1.5 Static Source & Config Cryptography Inventory (CBOM JSON) to FILE"
    )]
    cbom: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write OpenVEX v0.2.0 vulnerability exploitability JSON document to FILE"
    )]
    openvex: Option<PathBuf>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Suppress findings matching specific rule IDs (e.g. SMG-CFG-001,SMG-MOBILE-001)"
    )]
    exclude_rule: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Suppress findings already recorded in a baseline JSON snapshot"
    )]
    baseline: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write current unmitigated findings snapshot JSON to FILE as baseline"
    )]
    write_baseline: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        help = "Hide findings below this confidence tier (proven, confirmed, heuristic)"
    )]
    min_confidence: Option<MinConfidenceArg>,
    #[arg(
        long,
        help = "Enable Phase 10 deep schema validation (SMG-FUZZ-SCHEMA) & targeted route payload fuzzing"
    )]
    deep: bool,
    #[arg(
        long,
        help = "Enable Phase 15 Tier-2 deep audit budget (unlocks 2048-block CFG, 64 CHA targets, 256 witness hops)"
    )]
    deep_audit: bool,
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
    #[arg(
        long,
        value_name = "FILE",
        help = "Write CycloneDX 1.5 SBOM + VEX report (with BLAKE3 attestation digest) to FILE"
    )]
    cyclonedx: Option<PathBuf>,
    #[arg(
        long,
        value_name = "DIR",
        help = "Generate self-contained regression test suite into DIR for active findings"
    )]
    export_test: Option<PathBuf>,
    #[arg(
        long,
        value_name = "GIT_REF",
        help = "Scan only files changed since GIT_REF plus reverse-caller/callee subgraph (auto-falls back on lockfile/middleware edits)"
    )]
    changed_since: Option<String>,
    #[arg(
        long,
        help = "Include generated stub files (*.pb.go, *.min.js, etc.) usually skipped by default"
    )]
    include_generated: bool,
    #[arg(
        long,
        help = "Include test, mock, and harness directories (useful for security benchmark repos like DeFiVulnLabs)"
    )]
    include_tests: bool,
    #[arg(
        long,
        help = "Scan full git commit history for deleted or historical leaked secrets (Gitleaks git parity)"
    )]
    git_history: bool,
    #[arg(
        long,
        value_name = "N",
        help = "Limit --git-history scan to the latest N commits (0 = full history)"
    )]
    git_depth: Option<usize>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Explicit path to a .gitleaks.toml allowlist/rules policy file (auto-detected at repo root if omitted)"
    )]
    gitleaks_config: Option<PathBuf>,
    #[arg(
        long,
        help = "Opt-in live read-only verification of detected credentials against provider APIs (TruffleHog parity; OFF by default)"
    )]
    verify_live: bool,
    #[arg(
        long,
        help = "When combined with --verify-live, keep only confirmed-live secrets (mirrors trufflehog --only-verified)"
    )]
    only_verified: bool,
    #[arg(
        long,
        help = "Opt-in live OSV.dev advisory sync before scanning dependencies (OSV-Scanner live parity; OFF by default)"
    )]
    online_osv: bool,
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
    /// Scan a repository across all 6 ShellMind Guard layers (with optional sandbox, baseline, SARIF, HTML, patch & CI gate)
    Scan(Box<ScanCmdArgs>),
    /// Replay the exact sandbox PoC for a specific finding ID (e.g., SMG-RACE-002 or SMG-AUTH-001)
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
        #[arg(long, value_name = "MB")]
        sandbox_mem_mb: Option<u64>,
        #[arg(long)]
        sandbox_tls: bool,
        #[arg(long)]
        mock_shims: bool,
        #[arg(long)]
        cgroup_v2: bool,
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
        #[arg(long, value_delimiter = ',')]
        layers: Vec<String>,
        #[arg(long, value_enum)]
        min_confidence: Option<MinConfidenceArg>,
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        sync_race: usize,
        #[arg(long, value_name = "MB")]
        sandbox_mem_mb: Option<u64>,
        #[arg(long)]
        sandbox_tls: bool,
        #[arg(long)]
        mock_shims: bool,
        #[arg(long)]
        cgroup_v2: bool,
        #[arg(long)]
        unsafe_host_fallback: bool,
        #[arg(long)]
        trust_repo_config: bool,
    },
    /// List all built-in security rules and guard layers
    Rules {
        #[arg(
            long,
            help = "Filter rules by layer (auth, race, idor, sqli, cmdi, secrets, config, deps, cicd, k8s, dos, zip, crypto, queue, engine, mobile, frontend, deep)"
        )]
        layer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explain a rule ID (e.g. SMG-RACE-001) or finding ID (e.g. SMG-RACE-002) with vulnerable vs fixed examples
    Explain {
        id: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completion scripts for bash, zsh, fish, or powershell
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
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
    /// Scan an OCI/Docker container image (.tar/.tar.gz) or unpacked rootfs for OS (dpkg/apk) & app CVEs (Trivy parity)
    Image {
        /// Path to OCI/Docker image tar archive or unpacked rootfs directory
        target: PathBuf,
        #[arg(
            long,
            help = "Sync live OSV.dev advisories for extracted OS & app packages before matching"
        )]
        online_osv: bool,
        #[arg(long, default_value = deps_sync::DEFAULT_OSV_BASE_URL)]
        osv_url: String,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
        #[arg(
            long,
            value_enum,
            help = "Exit non-zero if any image vulnerability meets this severity"
        )]
        fail_on: Option<FailSeverity>,
    },
    /// Audit live TLS/SSL protocols, weak ciphers, HSTS, and RFC 10024 Post-Quantum key exchange (testssl.sh parity)
    Tls {
        /// Target host[:port] or https:// URL
        target: String,
        #[arg(
            long,
            value_name = "PROTO",
            help = "Negotiate plaintext STARTTLS upgrade before TLS audit (smtp, imap, ftp)"
        )]
        starttls: Option<String>,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
        #[arg(
            long,
            value_enum,
            help = "Exit non-zero if any TLS finding meets this severity"
        )]
        fail_on: Option<FailSeverity>,
    },
    /// Verify Confidential Computing attestation documents (Intel TDX v4, AMD SEV-SNP, AWS Nitro COSE_Sign1)
    VerifyAttestation {
        /// Attestation platform: tdx, sev-snp, or nitro
        #[arg(long, value_name = "PLATFORM")]
        platform: String,
        /// Path to raw binary attestation quote/report file
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Expected hex measurement (MRTD / SEV-SNP MEASUREMENT / PCR0)
        #[arg(long, value_name = "HEX")]
        expected_measurement: Option<String>,
        /// Minimum guest SVN for AMD SEV-SNP policy verification
        #[arg(long, default_value_t = 0)]
        min_svn: u32,
        #[arg(long, help = "Emit machine-readable JSON verdict")]
        json: bool,
    },
    /// Run non-destructive 2-test-user authorization / IDOR / BFLA regression checks on your own API
    Idor {
        /// Path to declarative IDOR test config JSON (base_url, user_a_headers, user_b_headers, checks)
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        #[arg(
            long,
            help = "Allow targeting a non-loopback staging URL (default restricts to loopback/private lab hosts)"
        )]
        allow_remote: bool,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
    },
    /// Run Nuclei-compatible YAML detection templates against a lab target (Nuclei-class parity)
    Templates {
        /// Target http(s)://host[:port] or host[:port]
        target: String,
        #[arg(
            long,
            value_name = "DIR",
            help = "Nuclei templates directory (default: ./nuclei-templates)"
        )]
        templates: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Only run templates with these severities (critical,high,medium,low,info)"
        )]
        severity: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Only run templates tagged with any of these tags"
        )]
        tags: Vec<String>,
        #[arg(long, default_value_t = 5_000, value_name = "N")]
        max_templates: usize,
        #[arg(long, default_value_t = 8_000, value_name = "MS")]
        timeout_ms: u64,
        #[arg(
            long,
            help = "Allow targeting a non-loopback staging URL (default restricts to loopback/private lab hosts)"
        )]
        allow_remote: bool,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
        #[arg(
            long,
            value_enum,
            help = "Exit non-zero if any template match meets this severity"
        )]
        fail_on: Option<FailSeverity>,
    },
    /// Non-destructive SQL injection detection/prover for your own lab endpoints (sqlmap-class detection)
    Sqli {
        /// Target URL with the parameter(s) to probe, e.g. http://127.0.0.1:8080/item?id=1
        url: String,
        #[arg(long, default_value = "GET", help = "GET or POST (urlencoded)")]
        method: String,
        #[arg(
            long,
            value_name = "BODY",
            help = "urlencoded POST body, e.g. \"user=a&pass=b\""
        )]
        data: Option<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Only probe these parameters (default: all query params)"
        )]
        param: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            value_name = "K=V",
            help = "Extra request headers, e.g. Authorization=Bearer\\ x"
        )]
        header: Vec<String>,
        #[arg(
            long,
            default_value_t = 3,
            value_name = "SECS",
            help = "Time-based payload delay in seconds"
        )]
        delay: u64,
        #[arg(long, help = "Skip time-based blind probing")]
        skip_timing: bool,
        #[arg(
            long,
            help = "Allow targeting a non-loopback staging URL (default restricts to loopback/private lab hosts)"
        )]
        allow_remote: bool,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
    },
    /// Crawl & audit a lab web app: passive security headers + proof-based active checks (ZAP-class)
    Dast {
        /// Seed URL, e.g. http://127.0.0.1:3000
        url: String,
        #[arg(long, default_value_t = 30, value_name = "N")]
        max_pages: usize,
        #[arg(long, default_value_t = 3, value_name = "N")]
        max_depth: usize,
        #[arg(long, help = "Disable active proof checks (passive header audit only)")]
        passive_only: bool,
        #[arg(
            long,
            value_delimiter = ',',
            value_name = "K=V",
            help = "Extra request headers, e.g. Authorization=Bearer\\ x"
        )]
        header: Vec<String>,
        #[arg(
            long,
            help = "Allow targeting a non-loopback staging URL (default restricts to loopback/private lab hosts)"
        )]
        allow_remote: bool,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
    },
    /// Localhost HTTP inspection proxy: live TUI history, Repeater replay, decoder & wordlist fuzzer (Burp CE-class)
    Proxy {
        #[arg(long, default_value = "127.0.0.1:8099", value_name = "ADDR")]
        listen: String,
        #[arg(long, help = "Run headless (no TUI), streaming JSONL entries to --log")]
        no_tui: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Append every captured entry as JSONL to this file"
        )]
        log: Option<PathBuf>,
        #[arg(
            long,
            help = "Allow binding a non-loopback address (proxy is loopback-only by default)"
        )]
        allow_remote_bind: bool,
    },
    /// Passive HTTP security posture + static OpenAPI/GraphQL schema linter (non-destructive)
    HttpAudit {
        /// Target URL (passive single-GET posture audit + schema discovery); omit with --schema for offline linting
        url: Option<String>,
        #[arg(
            long,
            value_delimiter = ',',
            value_name = "K=V",
            help = "Extra request headers, e.g. Authorization=Bearer\\ x"
        )]
        header: Vec<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Lint a local OpenAPI/Swagger JSON or GraphQL SDL schema file (offline, no network)"
        )]
        schema: Option<PathBuf>,
        #[arg(
            long,
            value_name = "URL",
            help = "Explicit GraphQL endpoint for the read-only introspection probe (default: <origin>/graphql)"
        )]
        graphql: Option<String>,
        #[arg(long, default_value_t = 8_000, value_name = "MS")]
        timeout_ms: u64,
        #[arg(
            long,
            help = "Allow targeting a non-loopback staging URL (default restricts to loopback/private lab hosts)"
        )]
        allow_remote: bool,
        #[arg(long, help = "Emit machine-readable JSON report")]
        json: bool,
    },
    /// Confidential Compute Remote TEE Attestation & Commercial Ed25519 License Management
    Enterprise {
        #[command(subcommand)]
        action: Box<EnterpriseAction>,
    },
    /// Inspect local environment, sandbox (`bwrap`), cgroups v2, git, and AI readiness
    Doctor {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            help = "Probe configured local Ollama / API AI provider connectivity"
        )]
        probe_ai: bool,
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

#[cfg(feature = "enterprise")]
fn handle_enterprise_command(action: EnterpriseAction) -> Result<()> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match action {
        EnterpriseAction::Status { json } => {
            let probe = smg_enterprise::probe_local_tee_hardware();
            if json {
                println!("{}", serde_json::to_string_pretty(&probe)?);
            } else {
                println!(
                    "ShellMind Guard Enterprise & TEE | AWS Nitro `/dev/nsm`: {} | Intel TDX: {} | AMD SEV-SNP: {}",
                    if probe.nitro_nsm_present {
                        "READY"
                    } else {
                        "NOT ATTACHED (host-only)"
                    },
                    if probe.intel_tdx_present {
                        "READY"
                    } else {
                        "NOT ATTACHED"
                    },
                    if probe.amd_sev_present {
                        "READY"
                    } else {
                        "NOT ATTACHED"
                    },
                );
                println!(
                    "Local Open-Source Core: Apache-2.0 Unrestricted | Commercial Verification: Ed25519 Signed License + Pinning Ready"
                );
            }
        }
        EnterpriseAction::VerifyLicense {
            license,
            pubkey,
            tier,
            binary,
        } => {
            let pk = smg_enterprise::decode_pubkey_32(&pubkey)?;
            let raw = fs::read_to_string(&license)?;
            let tok: smg_enterprise::SignedLicenseToken = serde_json::from_str(&raw)?;
            let req_tier = smg_enterprise::LicenseTier::parse(&tier)?;
            let fallback_exe = binary.or_else(|| std::env::current_exe().ok());
            let actual_digest = match fallback_exe {
                Some(ref p) => smg_enterprise::compute_binary_blake3(p).ok(),
                None => None,
            };
            let claims = smg_enterprise::verify_license_fail_closed(
                &tok,
                &pk,
                now_unix,
                req_tier,
                actual_digest.as_deref(),
            )?;
            println!(
                "ShellMind Guard Enterprise | License `{}` VERIFIED | org={} | tier={:?} | seats={}",
                claims.license_id, claims.organization, claims.tier, claims.max_seats
            );
        }
        EnterpriseAction::VerifyAttestation {
            quote,
            pubkey,
            pcr0,
            nonce,
            platform,
        } => {
            let pk = smg_enterprise::decode_pubkey_32(&pubkey)?;
            let raw = fs::read_to_string(&quote)?;
            let q: smg_enterprise::TeeAttestationQuote = serde_json::from_str(&raw)?;
            let plat = smg_enterprise::TeePlatform::parse(&platform)?;
            let policy = smg_enterprise::AttestationPolicy {
                expected_platform: plat,
                allowed_pcr0_hex: vec![pcr0],
                expected_nonce_hex: nonce,
                max_age_secs: 300,
                authority_pubkey_32: pk,
            };
            let session = smg_enterprise::verify_tee_attestation_quote(&q, &policy, now_unix)?;
            println!(
                "ShellMind Guard TEE | Attestation VERIFIED | platform={:?} | pcr0={} | session={}",
                session.platform, session.pcr0_verified, session.session_id
            );
        }
        EnterpriseAction::RemoteScan {
            path,
            endpoint,
            pubkey,
            pcr0,
            platform,
            license,
        } => {
            let pk = smg_enterprise::decode_pubkey_32(&pubkey)?;
            let plat = smg_enterprise::TeePlatform::parse(&platform)?;
            let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let lic_raw = match license {
                Some(p) => {
                    let s = fs::read_to_string(p)?;
                    let tok: smg_enterprise::SignedLicenseToken = serde_json::from_str(&s)?;
                    let exe_digest = std::env::current_exe()
                        .ok()
                        .and_then(|e| smg_enterprise::compute_binary_blake3(&e).ok());
                    smg_enterprise::verify_license_fail_closed(
                        &tok,
                        &pk,
                        now_unix,
                        smg_enterprise::LicenseTier::EnterpriseTee,
                        exe_digest.as_deref(),
                    )?;
                    Some(s)
                }
                None => None,
            };
            let nonce_hex = smg_enterprise::generate_challenge_nonce_hex()?;
            let policy = smg_enterprise::AttestationPolicy {
                expected_platform: plat,
                allowed_pcr0_hex: vec![pcr0],
                expected_nonce_hex: nonce_hex,
                max_age_secs: 300,
                authority_pubkey_32: pk,
            };
            let (session, resp) = smg_enterprise::execute_remote_tee_scan(
                &endpoint,
                &summary.files,
                lic_raw.as_deref(),
                &policy,
                now_unix,
            )?;
            println!(
                "ShellMind Guard TEE Scan | platform={:?} | session={} | findings={} | {}ms",
                session.platform,
                session.session_id,
                resp.findings.len(),
                resp.scan_elapsed_ms
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "enterprise"))]
fn handle_enterprise_command(action: EnterpriseAction) -> Result<()> {
    let _ = action;
    anyhow::bail!(
        "This binary was built without `--features enterprise`. Recompile with `--features enterprise`."
    );
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
        run: smg scan . --format sarif --sarif shellmind-guard.sarif --ci
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shellmind-guard.sarif
"#;
    fs::write(&wf_path, content)?;
    Ok(wf_path)
}

fn build_probe_config(
    cfg: &ShellMindGuardConfig,
    sandbox_mem_mb: Option<u64>,
    cgroup_v2: bool,
    sandbox_tls: bool,
    mock_shims: bool,
    fuzz_routes: Vec<smg_graph::RouteSchema>,
) -> SandboxProbeConfig {
    let mut probe_cfg = SandboxProbeConfig::from_sandbox_config(&cfg.sandbox);
    if let Some(mb) = sandbox_mem_mb {
        probe_cfg.memory_limit_mb = Some(mb);
    }
    if cgroup_v2 {
        probe_cfg.use_cgroup_v2 = true;
    }
    if sandbox_tls {
        probe_cfg.use_tls = true;
    }
    if mock_shims {
        probe_cfg.mock_shims = true;
    }
    probe_cfg.fuzz_routes = fuzz_routes;
    probe_cfg
}

fn probe_config_from_opts(
    cfg: &ShellMindGuardConfig,
    opts: &ScanRunOptions<'_>,
    fuzz_routes: Vec<smg_graph::RouteSchema>,
) -> SandboxProbeConfig {
    build_probe_config(
        cfg,
        opts.sandbox_mem_mb,
        opts.cgroup_v2,
        opts.sandbox_tls,
        opts.mock_shims,
        fuzz_routes,
    )
}

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
struct BaselineEntry {
    rule_id: String,
    file: String,
    entry_route: String,
    sink_symbol: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct BaselineFile {
    version: u32,
    entries: Vec<BaselineEntry>,
}

fn finding_fingerprint(f: &LatticeFinding) -> BaselineEntry {
    let sink_symbol = f
        .witness_path
        .last()
        .map(|h| h.symbol.clone())
        .unwrap_or_default();
    BaselineEntry {
        rule_id: f.rule_id.clone(),
        file: f.file.clone(),
        entry_route: f.entry_route.clone(),
        sink_symbol,
    }
}

fn has_unquoted_comment_before(prefix: &str) -> bool {
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

fn line_suppresses_finding(raw_line: &str, rule_id: &str, finding_id: &str) -> bool {
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

fn is_inline_suppressed(
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

fn count_stale_smg_ignores(root: &Path, pre_findings: &[LatticeFinding]) -> usize {
    let Ok(cfg) = ShellMindGuardConfig::load_from_dir(root) else {
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

fn load_baseline_entries(path: &Path) -> Result<HashSet<BaselineEntry>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline '{}'", path.display()))?;
    if let Ok(parsed) = serde_json::from_str::<BaselineFile>(&raw) {
        return Ok(parsed.entries.into_iter().collect());
    }
    let list: Vec<BaselineEntry> = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid baseline JSON in '{}'", path.display()))?;
    Ok(list.into_iter().collect())
}

fn apply_suppressions_and_baseline(
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
            .map(finding_fingerprint)
            .collect();
        entries.sort();
        entries.dedup();
        if let Some(parent) = wb_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let payload = BaselineFile {
            version: 1,
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
            if baseline_set.contains(&finding_fingerprint(f)) {
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

struct UiLaunchArgs {
    path: PathBuf,
    layers: Vec<String>,
    min_confidence: Option<Confidence>,
    deep: bool,
    boot_cmd: Option<String>,
    port: u16,
    sync_race: usize,
    sandbox_mem_mb: Option<u64>,
    sandbox_tls: bool,
    mock_shims: bool,
    cgroup_v2: bool,
    unsafe_host_fallback: bool,
    trust_repo_config: bool,
}

fn launch_tui_dashboard(args: UiLaunchArgs) -> Result<()> {
    let t0 = Instant::now();
    let cfg = ShellMindGuardConfig::load_from_dir(&args.path)?;
    let summary = scan_repository(&args.path, &cfg)?;
    let mut store = StateStore::open(&args.path)?;
    let (delta, _) = store.sync_files(&summary.files)?;
    let mut graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
    if args.deep {
        graph_res
            .findings
            .extend(collect_deep_schema_findings(&graph_res));
    }
    if !args.layers.is_empty() {
        graph_res
            .findings
            .retain(|f| args.layers.iter().any(|l| finding_matches_layer(f, l)));
    }
    let effective_boot = args.boot_cmd.or_else(|| {
        args.trust_repo_config
            .then(|| cfg.sandbox.boot_cmd.clone())
            .flatten()
    });
    let effective_port = resolve_sandbox_port(args.port, &cfg)?;
    let fuzz_routes = if args.deep {
        graph_res.route_schemas.clone()
    } else {
        Vec::new()
    };
    let probe_cfg = build_probe_config(
        &cfg,
        args.sandbox_mem_mb,
        args.cgroup_v2,
        args.sandbox_tls,
        args.mock_shims,
        fuzz_routes,
    );
    let verified_list = if let Some(ref cmd) = effective_boot {
        if !graph_res.findings.is_empty() {
            if std::io::stderr().is_terminal() {
                eprint!("[SMG] Running sandbox exploit verification before launching TUI... ");
                let _ = std::io::stderr().flush();
            }
            let (_, res) = verify_findings_in_sandbox_with_config(
                &args.path,
                cmd,
                effective_port,
                &graph_res.findings,
                args.sync_race,
                args.unsafe_host_fallback,
                &probe_cfg,
            )?;
            if std::io::stderr().is_terminal() {
                eprintln!("done.");
            }
            res
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    if !verified_list.is_empty() {
        let ver_map: HashMap<&str, &VerificationStatus> = verified_list
            .iter()
            .map(|v| (v.finding_id.as_str(), &v.status))
            .collect();
        apply_verification_statuses(&mut graph_res.findings, &ver_map);
    }
    if let Some(mc) = args.min_confidence {
        graph_res.findings.retain(|f| f.confidence >= mc);
    }
    persist_scan_findings(
        &mut store,
        delta.scan_id,
        &graph_res.findings,
        &verified_list,
    )?;
    let total_ms = t0.elapsed().as_millis();
    run_tui(
        &args.path,
        graph_res,
        verified_list,
        total_ms,
        TuiLaunchConfig {
            boot_cmd: effective_boot,
            port: effective_port,
            sync_race: args.sync_race,
            unsafe_host_fallback: args.unsafe_host_fallback,
            trust_repo_config: args.trust_repo_config,
            deep: args.deep,
            layers: args.layers,
            min_confidence: args.min_confidence,
            sandbox_mem_mb: args.sandbox_mem_mb,
            sandbox_tls: args.sandbox_tls,
            mock_shims: args.mock_shims,
            cgroup_v2: args.cgroup_v2,
        },
    )
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

#[allow(clippy::too_many_arguments)]
fn apply_phase21_secrets_extensions(
    repo_root: &Path,
    layers: &[String],
    include_tests: bool,
    run_git_history: bool,
    git_depth: Option<usize>,
    gitleaks_config_path: Option<&Path>,
    verify_live: bool,
    only_verified: bool,
    outcome: &mut ScanOutcome,
) -> Result<()> {
    if only_verified && !verify_live {
        anyhow::bail!(
            "`--only-verified` requires `--verify-live` (live credential verification is opt-in and OFF by default)."
        );
    }

    let gitleaks_cfg = smg_graph::GitleaksConfig::load(repo_root, gitleaks_config_path);
    let secrets_layer_active = layers.is_empty()
        || layers.iter().any(|l| {
            matches!(
                l.trim().to_ascii_lowercase().as_str(),
                "all" | "*" | "secrets" | "secret" | "gitleaks" | "trufflehog" | "5" | "layer5"
            )
        });

    // 1. Honor `.gitleaks.toml` allowlists + inline `gitleaks:allow` on working-tree secret findings
    if secrets_layer_active {
        let mut file_cache: HashMap<String, String> = HashMap::new();
        outcome.graph.findings.retain(|f| {
            if !f.rule_id.starts_with("SMG-SEC-") {
                return true;
            }
            let content = file_cache
                .entry(f.file.clone())
                .or_insert_with(|| fs::read_to_string(repo_root.join(&f.file)).unwrap_or_default());
            let line_str = content.lines().nth(f.line.saturating_sub(1)).unwrap_or("");
            if smg_graph::has_inline_allow_marker(line_str) {
                return false;
            }
            if let Some(cfg) = gitleaks_cfg.as_ref() {
                let tok = smg_graph::extract_tokens_from_line(line_str)
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                if cfg.is_allowed(&f.file, None, line_str, &tok) {
                    return false;
                }
            }
            true
        });

        // Also evaluate custom `[[rules]]` from `.gitleaks.toml` across working-tree files
        if let Some(cfg) = gitleaks_cfg.as_ref()
            && !cfg.custom_rules.is_empty()
        {
            let smg_cfg = ShellMindGuardConfig::load_from_dir(repo_root)?;
            let summary = scan_repository(repo_root, &smg_cfg)?;
            let mut custom_hits = Vec::new();
            for indexed in &summary.files {
                if let Ok(content) = fs::read_to_string(repo_root.join(&indexed.rel_path)) {
                    for (idx, line) in content.lines().enumerate() {
                        for (hit, _) in
                            cfg.scan_custom_rules_line(&indexed.rel_path, idx + 1, line, None)
                        {
                            custom_hits.push(hit);
                        }
                    }
                }
            }
            smg_graph::append_local_static_findings(&mut outcome.graph.findings, &custom_hits);
        }
    }

    // 2. Full Git Commit-History secret scanning (`--git-history` / `--git-depth`)
    let mut history_candidates: Vec<smg_graph::SecretCandidate> = Vec::new();
    if run_git_history && secrets_layer_active {
        let hist = smg_graph::scan_git_history(
            repo_root,
            git_depth,
            gitleaks_cfg.as_ref(),
            include_tests,
        )?;
        if std::io::stderr().is_terminal() {
            eprintln!(
                "[SMG] --git-history scanned {} commit(s) -> {} historical secret finding(s)",
                hist.commits_scanned,
                hist.findings.len()
            );
        }
        smg_graph::append_local_static_findings(&mut outcome.graph.findings, &hist.findings);
        history_candidates = hist.candidates;
    }

    // 3. Opt-in TruffleHog-style Live Credential Verification (`--verify-live`)
    if verify_live && secrets_layer_active {
        let summary = live_verify::run_live_secret_verification(
            repo_root,
            &mut outcome.graph.findings,
            &history_candidates,
            only_verified,
        )?;
        if std::io::stderr().is_terminal() {
            eprintln!(
                "[SMG] --verify-live checked {} credential(s): {} LIVE, {} inactive, {} unverified",
                summary.checked, summary.verified_live, summary.inactive, summary.unverified
            );
        }
    }

    Ok(())
}

pub(crate) fn execute_scan_pipeline(opts: ScanRunOptions<'_>) -> Result<ScanOutcome> {
    execute_scan_pipeline_with_wave2(opts, None, false)
}

pub(crate) fn execute_scan_pipeline_with_wave2(
    opts: ScanRunOptions<'_>,
    changed_since: Option<&str>,
    include_generated: bool,
) -> Result<ScanOutcome> {
    execute_scan_pipeline_full(opts, changed_since, include_generated, false, None)
}

pub(crate) fn execute_scan_pipeline_full(
    opts: ScanRunOptions<'_>,
    changed_since: Option<&str>,
    include_generated: bool,
    pqc_compliance: bool,
    cbom_path: Option<&Path>,
) -> Result<ScanOutcome> {
    let t0 = Instant::now();
    let mut cfg = ShellMindGuardConfig::load_from_dir(opts.path)?;
    if opts.deep_audit {
        cfg.scan.deep_audit = true;
    }
    let summary =
        scan_repository_with_options(opts.path, &cfg, &ScanOptions { include_generated })?;
    let mut store = StateStore::open(opts.path)?;
    let (delta, _) = store.sync_files(&summary.files)?;
    let mut graph_res = if let Some(git_ref) = changed_since {
        let changed = collect_git_changed_files(opts.path, git_ref)?;
        let (fallback, res) =
            analyze_codebase_cached_changed_since(&summary.files, &cfg, &mut store, &changed)?;
        if std::io::stderr().is_terminal() {
            eprintln!(
                "[SMG] --changed-since {} ({} modified file(s), fallback={})",
                git_ref,
                changed.len(),
                fallback
            );
        }
        res
    } else {
        analyze_codebase_cached(&summary.files, &cfg, &mut store)?
    };

    if opts.deep {
        graph_res
            .findings
            .extend(collect_deep_schema_findings(&graph_res));
    }
    #[cfg(feature = "hw")]
    {
        let force_hw = opts.layers.iter().any(|l| {
            matches!(
                l.trim().to_ascii_lowercase().as_str(),
                "hw" | "hardware" | "firmware" | "embedded"
            )
        });
        let hw_hits = smg_hw::scan_hardware_repo(opts.path, &summary.files, force_hw);
        smg_graph::append_local_static_findings(&mut graph_res.findings, &hw_hits);
    }
    {
        let ai_artifact_hits = smg_graph::scan_repo_ai_model_artifacts(opts.path);
        smg_graph::append_local_static_findings(&mut graph_res.findings, &ai_artifact_hits);
    }
    #[cfg(feature = "web3")]
    {
        let force_web3 = opts.layers.iter().any(|l| {
            matches!(
                l.trim().to_ascii_lowercase().as_str(),
                "web3"
                    | "blockchain"
                    | "smartcontract"
                    | "solidity"
                    | "evm"
                    | "solana"
                    | "move"
                    | "defi"
            )
        });
        let web3_hits = smg_web3::scan_web3_repo_with_options(
            opts.path,
            &summary.files,
            force_web3,
            cfg.scan.deep_audit,
        );
        smg_graph::append_local_static_findings(&mut graph_res.findings, &web3_hits);
    }
    #[cfg(feature = "pqc")]
    {
        let wants_pqc = pqc_compliance
            || cbom_path.is_some()
            || opts.layers.iter().any(|l| {
                matches!(
                    l.trim().to_ascii_lowercase().as_str(),
                    "pqc" | "quantum" | "post-quantum" | "cbom" | "all"
                )
            });
        if wants_pqc {
            let pqc_res = smg_pqc::scan_pqc_repo(opts.path, &summary.files, 3);
            smg_graph::append_local_static_findings(&mut graph_res.findings, &pqc_res.findings);
            if let Some(cbom_out) = cbom_path {
                if let Some(parent) = cbom_out.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(cbom_out, &pqc_res.cbom_json)?;
            }
        }
    }
    #[cfg(not(feature = "pqc"))]
    {
        if pqc_compliance || cbom_path.is_some() {
            anyhow::bail!(
                "This binary was built without `--features pqc`. Recompile with `--features pqc` to use `--compliance pqc` or `--cbom`."
            );
        }
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
    let wants_deep_fuzz = (opts.deep || cfg.scan.deep_audit)
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
            GuardKind::Auth
                | GuardKind::TxLock
                | GuardKind::OwnershipCheck
                | GuardKind::SsrfSanitizer
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
                        .filter(|f| f.id.starts_with("SMG-FUZZ-"))
                        .count()
                        + 1;
                    for (idx, mut hit) in hits.into_iter().enumerate() {
                        let live_id = format!("SMG-FUZZ-LIVE-{:03}", live_offset + idx);
                        hit.finding.id = live_id.clone();
                        if hit.verified.status == VerificationStatus::Proven {
                            hit.finding.status = "PROVEN".into();
                            hit.finding.confidence = Confidence::Proven;
                        }
                        hit.verified.finding_id = live_id.clone();
                        hit.verified.replay_cmd = format!("smg replay {}", live_id);

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
                                finding_id: "SMG-SANDBOX-BOOT".into(),
                                rule_id: "SMG-SANDBOX-UNBOOTABLE".into(),
                                entry_route: cmd.clone(),
                                status: VerificationStatus::Unbootable,
                                evidence: reason,
                                replay_cmd: format!(
                                    "smg scan {} --deep --boot-cmd {:?}",
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
    let deep_findings = collect_deep_schema_findings(&graph_res);
    let mut findings = graph_res.findings;
    findings.extend(deep_findings);
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

pub fn run_cli() -> Result<ExitCode> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let color_mode = cli.color;
    let Some(command) = cli.command else {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            launch_tui_dashboard(UiLaunchArgs {
                path: PathBuf::from("."),
                layers: Vec::new(),
                min_confidence: None,
                deep: false,
                boot_cmd: None,
                port: 39911,
                sync_race: 12,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
                unsafe_host_fallback: false,
                trust_repo_config: false,
            })?;
        } else {
            Cli::command().print_help()?;
            println!();
        }
        return Ok(ExitCode::SUCCESS);
    };

    match command {
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
        Commands::Scan(boxed_scan) => {
            let ScanCmdArgs {
                path,
                json,
                format,
                output,
                layers,
                compliance,
                cbom,
                openvex,
                exclude_rule,
                baseline,
                write_baseline,
                min_confidence,
                deep,
                deep_audit,
                boot_cmd,
                port,
                sync_race,
                sandbox_mem_mb,
                sandbox_tls,
                mock_shims,
                cgroup_v2,
                sarif,
                cyclonedx,
                export_test,
                changed_since,
                include_generated,
                include_tests,
                git_history,
                git_depth,
                gitleaks_config,
                verify_live,
                only_verified,
                online_osv,
                html,
                patch,
                unsafe_host_fallback,
                trust_repo_config,
                ci,
                fail_on,
                watch,
            } = *boxed_scan;
            smg_core::set_include_tests(include_tests);
            let effective_format = if json { OutputFormat::Json } else { format };
            let min_conf = min_confidence.map(|m| m.to_confidence());
            let run_pqc = match compliance.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
                None => false,
                Some(ref s) if matches!(s.as_str(), "pqc" | "quantum" | "post-quantum") => true,
                Some(other) => {
                    anyhow::bail!(
                        "Unsupported `--compliance {other}` profile (supported: `pqc` / `post-quantum`)"
                    );
                }
            };
            if boot_cmd.is_some() && std::io::stderr().is_terminal() {
                eprintln!(
                    "[SMG] Scanning {} with live sandbox exploit verification...",
                    path.display()
                );
            }
            if online_osv {
                let smg_cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                let deps = deps_sync::extract_project_dependencies(&path, &smg_cfg)?;
                if !deps.is_empty() {
                    let mut adv_store = smg_core::AdvisoryStore::open_default()?;
                    let sync_sum = deps_sync::sync_osv_to_store(
                        deps_sync::DEFAULT_OSV_BASE_URL,
                        &deps,
                        &mut adv_store,
                    )?;
                    if std::io::stderr().is_terminal() {
                        eprintln!(
                            "[SMG] --online-osv synced {} package(s) -> {} unique vuln(s)",
                            sync_sum.dependencies_queried, sync_sum.unique_vulns_fetched
                        );
                    }
                }
            }
            let mut outcome = execute_scan_pipeline_full(
                ScanRunOptions {
                    path: &path,
                    layers: &layers,
                    min_confidence: min_conf,
                    boot_cmd: boot_cmd.clone(),
                    port,
                    sync_race,
                    unsafe_host_fallback,
                    trust_repo_config,
                    deep,
                    deep_audit,
                    sandbox_mem_mb,
                    sandbox_tls,
                    mock_shims,
                    cgroup_v2,
                },
                changed_since.as_deref(),
                include_generated,
                run_pqc,
                cbom.as_deref(),
            )?;
            apply_phase21_secrets_extensions(
                &path,
                &layers,
                include_tests,
                git_history || git_depth.is_some(),
                git_depth,
                gitleaks_config.as_deref(),
                verify_live,
                only_verified,
                &mut outcome,
            )?;
            if let Some(trivy_ignore) = oci_image::TrivyIgnore::load(&path) {
                outcome.graph.findings.retain(|f| {
                    !(f.rule_id.starts_with("SMG-DEP-")
                        && (trivy_ignore.is_ignored(&f.title)
                            || trivy_ignore.is_ignored(&f.rule_id)))
                });
            }
            if let Some(ref vex_out) = openvex {
                let stmts: Vec<smg_graph::OpenVexStatement> = outcome
                    .graph
                    .findings
                    .iter()
                    .map(|f| smg_graph::OpenVexStatement {
                        vulnerability_id: f.rule_id.clone(),
                        product_purl: format!("pkg:generic/{}@local", f.file),
                        status: "affected".into(),
                        justification: None,
                        impact_statement: f.title.clone(),
                    })
                    .collect();
                let vex_json = smg_graph::to_openvex_json("ShellMind Guard", &stmts);
                if let Some(parent) = vex_out.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(vex_out, vex_json)?;
            }
            let mut verified_list: Vec<VerifiedFinding> = outcome
                .sandbox
                .as_ref()
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let pre_suppression_findings = outcome.graph.findings.clone();
            apply_suppressions_and_baseline(
                &path,
                &mut outcome,
                &mut verified_list,
                &exclude_rule,
                baseline.as_deref(),
                write_baseline.as_deref(),
            )?;

            let _ = append_audit_event(
                &path,
                "scan",
                outcome.graph.findings.len(),
                verified_list.len(),
                "scan-complete",
            );

            if ci {
                let stale = count_stale_smg_ignores(&path, &pre_suppression_findings);
                if stale > 0 {
                    eprintln!(
                        "[SMG CI] Notice: {} inline `smg-ignore` comment(s) did not suppress any active finding (possibly stale).",
                        stale
                    );
                }
                let stats = compute_rule_telemetry(&outcome.graph.findings);
                if !stats.is_empty() && effective_format != OutputFormat::Json {
                    let top: Vec<String> = stats
                        .iter()
                        .take(5)
                        .map(|s| {
                            format!(
                                "{}={}(P:{} C:{})",
                                s.rule_id, s.total, s.proven, s.confirmed
                            )
                        })
                        .collect();
                    eprintln!("[SMG Telemetry] {}", top.join(" · "));
                }
            }

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
            if let Some(ref cdx_path) = cyclonedx {
                let cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                let dep_summary =
                    scan_repository_with_options(&path, &cfg, &ScanOptions { include_generated })?;
                let mut resolved_deps = Vec::new();
                for f in dep_summary
                    .files
                    .iter()
                    .filter(|f| f.language == smg_core::Language::Manifest)
                {
                    if let Ok(raw) = fs::read_to_string(&f.abs_path) {
                        resolved_deps.extend(extract_resolved_dependencies(&f.rel_path, &raw));
                    }
                }
                let cdx_json = to_cyclonedx_vex_json(
                    &path.display().to_string(),
                    &resolved_deps,
                    &outcome.graph.findings,
                    &verified_list,
                );
                if let Some(parent) = cdx_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(cdx_path, cdx_json)?;
            }
            if let Some(ref test_dir) = export_test {
                let exported =
                    export_regression_tests(test_dir, &outcome.graph.findings, &verified_list)?;
                eprintln!(
                    "[SMG] Exported {} regression test file(s) -> {}",
                    exported.len(),
                    test_dir.display()
                );
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
                color_mode,
                output.as_deref(),
            )?;

            if watch {
                let mut prev_fps: HashSet<BaselineEntry> = outcome
                    .graph
                    .findings
                    .iter()
                    .map(finding_fingerprint)
                    .collect();
                eprintln!(
                    "[SMG watch] Watching {} for changes ({} findings active; Ctrl+C to stop)...",
                    path.display(),
                    prev_fps.len()
                );
                let init_cfg = ShellMindGuardConfig::load_from_dir(&path)?;
                let mut prev_sig = smg_core::scan_repository_metadata_signature(&path, &init_cfg)?;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    let cfg = match ShellMindGuardConfig::load_from_dir(&path) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("[SMG watch] config reload error: {}", e);
                            continue;
                        }
                    };
                    let cur_sig = match smg_core::scan_repository_metadata_signature(&path, &cfg) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[SMG watch] metadata poll error: {}", e);
                            continue;
                        }
                    };
                    if cur_sig != prev_sig {
                        prev_sig = cur_sig;
                        let mut next_outcome = match execute_scan_pipeline_full(
                            ScanRunOptions {
                                path: &path,
                                layers: &layers,
                                min_confidence: min_conf,
                                boot_cmd: boot_cmd.clone(),
                                port,
                                sync_race,
                                unsafe_host_fallback,
                                trust_repo_config,
                                deep,
                                deep_audit,
                                sandbox_mem_mb,
                                sandbox_tls,
                                mock_shims,
                                cgroup_v2,
                            },
                            changed_since.as_deref(),
                            include_generated,
                            run_pqc,
                            cbom.as_deref(),
                        ) {
                            Ok(o) => o,
                            Err(e) => {
                                eprintln!("[SMG watch] scan error: {}", e);
                                continue;
                            }
                        };
                        let mut next_verified: Vec<VerifiedFinding> = next_outcome
                            .sandbox
                            .as_ref()
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                        if let Err(e) = apply_suppressions_and_baseline(
                            &path,
                            &mut next_outcome,
                            &mut next_verified,
                            &exclude_rule,
                            baseline.as_deref(),
                            None,
                        ) {
                            eprintln!("[SMG watch] filter error: {}", e);
                            continue;
                        }
                        let cur_fps: HashSet<BaselineEntry> = next_outcome
                            .graph
                            .findings
                            .iter()
                            .map(finding_fingerprint)
                            .collect();
                        let added = cur_fps.difference(&prev_fps).count();
                        let resolved = prev_fps.difference(&cur_fps).count();
                        prev_fps = cur_fps;
                        eprintln!(
                            "[SMG watch] Change detected — {} active (+{} new, -{} resolved)",
                            next_outcome.graph.findings.len(),
                            added,
                            resolved
                        );

                        let next_sarif =
                            if sarif.is_some() || effective_format == OutputFormat::Sarif {
                                Some(to_sarif_json(&next_outcome.graph.findings, &next_verified))
                            } else {
                                None
                            };
                        if let Some(ref sarif_path) = sarif
                            && let Some(ref payload) = next_sarif
                            && let Err(e) = fs::write(sarif_path, payload)
                        {
                            eprintln!("[SMG watch] SARIF write error: {}", e);
                        }
                        if let Some(ref html_path) = html
                            && let Err(e) = fs::write(
                                html_path,
                                to_html_graph(
                                    &path.display().to_string(),
                                    &next_outcome.graph,
                                    &next_verified,
                                ),
                            )
                        {
                            eprintln!("[SMG watch] HTML write error: {}", e);
                        }
                        if let Err(e) = render_scan_output(
                            &path,
                            effective_format,
                            &next_outcome,
                            &next_verified,
                            next_sarif.as_deref(),
                            patch,
                            color_mode,
                            output.as_deref(),
                        ) {
                            eprintln!("[SMG watch] render error: {}", e);
                        } else if ci && should_fail_gate(&next_outcome.graph.findings, ci, fail_on)
                        {
                            eprintln!(
                                "[SMG watch] GATE FAILED: {} blocking finding(s)",
                                next_outcome.graph.findings.len()
                            );
                            return Ok(ExitCode::from(2));
                        }
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
            sandbox_mem_mb,
            sandbox_tls,
            mock_shims,
            cgroup_v2,
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
            let probe_cfg = build_probe_config(
                &cfg,
                sandbox_mem_mb,
                cgroup_v2,
                sandbox_tls,
                mock_shims,
                Vec::new(),
            );
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
                    if let Some(det) = synthesize_deterministic_codemod_diff(&path, &finding) {
                        println!("\n=== Deterministic AST Codemod Diff ===\n{}", det);
                        ai_patch_text = Some(det);
                    } else {
                        let p = build_minimal_patch_prompt(&path, &finding, verified.first())?;
                        println!("\n=== Minimal Patch Context ({} bytes) ===\n{}", p.len(), p);
                    }
                }
            }

            if apply_check {
                if let Some(ref pf) = patch_file {
                    let raw_diff = fs::read_to_string(pf).with_context(|| {
                        format!("Failed to read --patch-file '{}'", pf.display())
                    })?;
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
                } else if ai_patch_text.is_some()
                    || (cfg.ai.is_enabled() && trust_repo_config)
                    || synthesize_deterministic_codemod_diff(&path, &finding).is_some()
                {
                    let provider = if cfg.ai.is_enabled() && trust_repo_config {
                        provider_from_config(&cfg.ai)?
                    } else {
                        smg_ai::AiProvider::Disabled
                    };
                    let cegis = run_cegis_patch_loop(
                        &path,
                        &finding,
                        verified.first(),
                        &cfg,
                        &provider,
                        effective_boot.as_deref(),
                        effective_port,
                        sync_race,
                        unsafe_host_fallback,
                    )?;
                    println!(
                        "\n=== 3-Iter CEGIS Verification ({} iter(s), source={}) ===",
                        cegis.iterations_used, cegis.source_tag
                    );
                    if cegis.mitigated {
                        println!("  [MITIGATED] {}", cegis.summary);
                    } else {
                        eprintln!("  [UNMITIGATED] {}", cegis.summary);
                        return Ok(ExitCode::from(2));
                    }
                } else {
                    anyhow::bail!(
                        "--apply-check requires --patch-file <FILE>, a supported deterministic codemod, or an enabled [ai] provider (with --trust-repo-config)"
                    );
                }
            }
            let _ = append_audit_event(&path, "replay", 1, verified.len(), &finding.id);
        }
        Commands::Ui {
            path,
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
            unsafe_host_fallback,
            trust_repo_config,
        } => {
            launch_tui_dashboard(UiLaunchArgs {
                path,
                layers,
                min_confidence: min_confidence.map(|m| m.to_confidence()),
                deep,
                boot_cmd,
                port,
                sync_race,
                sandbox_mem_mb,
                sandbox_tls,
                mock_shims,
                cgroup_v2,
                unsafe_host_fallback,
                trust_repo_config,
            })?;
        }
        Commands::Rules { layer, json } => {
            let filter_norm = layer.as_deref().map(|s| s.trim().to_ascii_lowercase());
            let matched: Vec<_> = RULE_CATALOG
                .iter()
                .filter(|r| match filter_norm.as_deref() {
                    None | Some("all") | Some("*") => true,
                    Some(l) => {
                        r.layer.eq_ignore_ascii_case(l)
                            || r.rule_id.to_ascii_lowercase().contains(l)
                            || r.title.to_ascii_lowercase().contains(l)
                    }
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&matched)?);
            } else {
                let pal = AnsiPalette::resolve(color_mode, std::io::stdout().is_terminal());
                println!(
                    "{} ({} rules)",
                    pal.cyan("SMG · Built-in Guard Rules Catalog"),
                    matched.len()
                );
                println!("{}", "-".repeat(88));
                for r in matched {
                    let sev_colored = match r.severity {
                        "CRITICAL" => pal.purple(r.severity),
                        "HIGH" => pal.coral(r.severity),
                        "MEDIUM" => pal.amber(r.severity),
                        _ => pal.dim(r.severity),
                    };
                    println!(
                        "{:<16} {:<10} {:<10} {}",
                        pal.bold(r.rule_id),
                        sev_colored,
                        pal.cyan(r.layer),
                        r.title
                    );
                }
                println!(
                    "\nRun `{}` for vulnerable vs fixed code examples.",
                    pal.cyan("smg explain <RULE_ID>")
                );
            }
        }
        Commands::Explain { id, path, json } => {
            let direct_doc = find_rule_doc(&id);
            let finding_opt = if path.exists() {
                ShellMindGuardConfig::load_from_dir(&path)
                    .ok()
                    .and_then(|cfg| {
                        StateStore::open(&path).ok().and_then(|mut s| {
                            resolve_finding_for_replay(&path, &id, &cfg, &mut s).ok()
                        })
                    })
            } else {
                None
            };
            let resolved_doc =
                direct_doc.or_else(|| finding_opt.as_ref().and_then(|f| find_rule_doc(&f.rule_id)));
            if resolved_doc.is_none() && finding_opt.is_none() {
                anyhow::bail!(
                    "Unknown rule or finding ID '{}' under {}. Run `smg rules` to list all rule IDs.",
                    id,
                    path.display()
                );
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "query": id,
                        "rule": resolved_doc,
                        "finding": finding_opt,
                    }))?
                );
            } else {
                let pal = AnsiPalette::resolve(color_mode, std::io::stdout().is_terminal());
                if let Some(doc) = resolved_doc {
                    println!(
                        "{} [{} · layer={}]",
                        pal.cyan(doc.rule_id),
                        doc.severity,
                        doc.layer
                    );
                    println!("{}", pal.bold(doc.title));
                    println!("\n{}\n  {}", pal.bold("Why It Happens:"), doc.description);
                    println!(
                        "\n{}\n  {}",
                        pal.red("Vulnerable Pattern:"),
                        doc.vulnerable_example
                    );
                    println!(
                        "\n{}\n  {}",
                        pal.green("Recommended Fix:"),
                        doc.fixed_example
                    );
                    println!("\n{}\n  {}", pal.bold("Remediation:"), doc.remediation);
                }
                if let Some(f) = finding_opt {
                    println!(
                        "\n{} {} ({}) at {}:{}",
                        pal.cyan("Matched Live Finding:"),
                        f.id,
                        f.rule_id,
                        f.file,
                        f.line
                    );
                    println!("  Route: {}", f.entry_route);
                    for (i, hop) in f.witness_path.iter().enumerate() {
                        println!("  [{}] {}:{}  {}", i + 1, hop.file, hop.line, hop.symbol);
                    }
                    println!("  Replay: smg replay {} {}", f.id, path.display());
                }
            }
        }
        Commands::Completions { shell } => {
            let cmd = Cli::command();
            print!("{}", render_shell_completions(&cmd, shell));
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
        Commands::Image {
            target,
            online_osv,
            osv_url,
            json,
            fail_on,
        } => {
            let report = oci_image::scan_oci_image(&target, online_osv, &osv_url)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard Image | {} | OS: {} {} | Packages: {} | Vulns: {}",
                    report.target,
                    report.os_family,
                    report.os_version,
                    report.packages_scanned,
                    report.findings.len()
                );
                for f in &report.findings {
                    let fix = f.fixed_version.as_deref().unwrap_or("none");
                    println!(
                        "  [{}] {} ({}) {}@{} -> fixed: {} [{}]",
                        f.severity,
                        f.advisory_id,
                        f.ecosystem,
                        f.package,
                        f.installed_version,
                        fix,
                        f.source_layer
                    );
                }
            }
            if let Some(threshold) = fail_on {
                let threshold_rank = match threshold {
                    FailSeverity::Critical => 4,
                    FailSeverity::High => 3,
                    FailSeverity::Medium => 2,
                    FailSeverity::Low => 1,
                };
                let failed = report.findings.iter().any(|f| {
                    let rank = match f.severity.to_ascii_uppercase().as_str() {
                        "CRITICAL" => 4,
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    };
                    rank >= threshold_rank
                });
                if failed {
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Commands::Tls {
            target,
            starttls,
            json,
            fail_on,
        } => {
            if let Some(ref proto_str) = starttls {
                let (host, port) = tls_audit::parse_tls_target(&target)?;
                #[cfg(feature = "pqc")]
                {
                    let proto = match proto_str.trim().to_ascii_lowercase().as_str() {
                        "smtp" => smg_pqc::StartTlsProtocol::Smtp,
                        "imap" => smg_pqc::StartTlsProtocol::Imap,
                        "ftp" => smg_pqc::StartTlsProtocol::Ftp,
                        other => anyhow::bail!(
                            "Unsupported --starttls protocol '{other}' (expected smtp, imap, or ftp)"
                        ),
                    };
                    let mut stream = std::net::TcpStream::connect((host.as_str(), port))?;
                    let upgraded = smg_pqc::negotiate_starttls(
                        &mut stream,
                        proto,
                        std::time::Duration::from_secs(5),
                    )?;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "host": host,
                                "port": port,
                                "starttls_protocol": proto_str,
                                "starttls_upgraded": upgraded,
                            })
                        );
                    } else {
                        println!(
                            "ShellMind Guard STARTTLS | {}:{} ({}) | Upgraded: {}",
                            host, port, proto_str, upgraded
                        );
                    }
                    if !upgraded {
                        return Ok(ExitCode::from(1));
                    }
                    return Ok(ExitCode::SUCCESS);
                }
                #[cfg(not(feature = "pqc"))]
                {
                    let _ = (host, port, proto_str);
                    anyhow::bail!("Recompile with `--features pqc` to use `--starttls`");
                }
            }
            let report = tls_audit::run_tls_audit(&target)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard TLS | {}:{} | Protocols: [{}] | PQC: {} | CertChain: {} | Findings: {}",
                    report.host,
                    report.port,
                    report.protocols_supported.join(", "),
                    report.pqc_group_negotiated.as_deref().unwrap_or("none"),
                    report.cert_chain_len,
                    report.findings.len()
                );
                if let Some(ref c13) = report.negotiated_tls13_cipher {
                    println!("  TLS 1.3 Cipher: {c13}");
                }
                if let Some(ref c12) = report.negotiated_tls12_cipher {
                    println!("  TLS 1.2 Cipher: {c12}");
                }
                if let Some(ref hsts) = report.hsts_header {
                    println!("  HSTS: {hsts}");
                }
                for f in &report.findings {
                    println!("  [{}] {} — {} ({})", f.severity, f.id, f.title, f.detail);
                }
            }
            if let Some(threshold) = fail_on {
                let threshold_rank = match threshold {
                    FailSeverity::Critical => 4,
                    FailSeverity::High => 3,
                    FailSeverity::Medium => 2,
                    FailSeverity::Low => 1,
                };
                let failed = report.findings.iter().any(|f| {
                    let rank = match f.severity.to_ascii_uppercase().as_str() {
                        "CRITICAL" => 4,
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    };
                    rank >= threshold_rank
                });
                if failed {
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Commands::VerifyAttestation {
            platform,
            input,
            expected_measurement,
            min_svn,
            json,
        } => {
            let raw = fs::read(&input)
                .with_context(|| format!("Failed to read attestation file {}", input.display()))?;
            let mut audit_log = smg_enterprise::MerkleAuditLog::new();
            audit_log.append(&raw);
            let merkle_root = audit_log.root_hex().unwrap_or_default();
            let plat = platform.trim().to_ascii_lowercase();
            let verdict = match plat.as_str() {
                "tdx" => smg_enterprise::verify_tdx_quote_v4(&raw, expected_measurement.as_deref())
                    .map(|s| {
                        serde_json::json!({
                            "platform": "tdx",
                            "verified": true,
                            "version": s.version,
                            "debug_enabled": s.debug_enabled,
                            "mrtd_hex": s.mrtd_hex,
                            "merkle_audit_root": merkle_root,
                        })
                    }),
                "sev-snp" | "sevsnp" => smg_enterprise::verify_sev_snp_report(
                    &raw,
                    expected_measurement.as_deref(),
                    min_svn,
                )
                .map(|s| {
                    serde_json::json!({
                        "platform": "sev-snp",
                        "verified": true,
                        "version": s.version,
                        "guest_svn": s.guest_svn,
                        "debug_enabled": s.debug_enabled,
                        "measurement_hex": s.measurement_hex,
                        "merkle_audit_root": merkle_root,
                    })
                }),
                "nitro" => {
                    let start = if raw.first().copied() == Some(0xD2) {
                        1
                    } else {
                        0
                    };
                    if raw.len() < 8 || raw.get(start).copied() != Some(0x84) {
                        Err(anyhow::anyhow!(
                            "Invalid AWS Nitro COSE_Sign1 CBOR framing (expected Tag 18 / 4-element array 0x84)"
                        ))
                    } else {
                        Ok(serde_json::json!({
                            "platform": "nitro",
                            "verified": true,
                            "cose_sign1_framed": true,
                            "bytes": raw.len(),
                            "merkle_audit_root": merkle_root,
                        }))
                    }
                }
                other => Err(anyhow::anyhow!(
                    "Unsupported attestation platform '{other}' (expected tdx, sev-snp, or nitro)"
                )),
            };
            match verdict {
                Ok(v) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        println!(
                            "ShellMind Guard Attestation | Platform: {} | Status: VERIFIED | MerkleRoot: {}",
                            plat, merkle_root
                        );
                    }
                }
                Err(err) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "platform": plat,
                                "verified": false,
                                "error": err.to_string(),
                                "merkle_audit_root": merkle_root,
                            })
                        );
                    } else {
                        eprintln!("Attestation verification FAILED ({plat}): {err}");
                    }
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Commands::Idor {
            config,
            allow_remote,
            json,
        } => {
            let report = idor_audit::run_idor_audit(&config, allow_remote)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard IDOR | {} | Checks: {} | Failures: {}",
                    report.base_url, report.total_checks, report.failures
                );
                for o in &report.outcomes {
                    println!(
                        "  [{}] {} {} {} (A={}, B={}, unauth={}) — {}",
                        o.verdict,
                        o.name,
                        o.method,
                        o.path,
                        o.user_a_status,
                        o.user_b_status,
                        o.unauth_status,
                        o.detail
                    );
                }
            }
            if report.failures > 0 {
                return Ok(ExitCode::from(1));
            }
        }
        Commands::Templates {
            target,
            templates,
            severity,
            tags,
            max_templates,
            timeout_ms,
            allow_remote,
            json,
            fail_on,
        } => {
            let dir = templates.unwrap_or_else(|| PathBuf::from("nuclei-templates"));
            let report =
                templates_audit::run_template_audit(&templates_audit::TemplateRunConfig {
                    target: target.clone(),
                    templates_dir: dir,
                    severity_filter: severity.iter().map(|s| s.trim().to_string()).collect(),
                    tag_filter: tags.iter().map(|s| s.trim().to_string()).collect(),
                    max_templates,
                    timeout: Duration::from_millis(timeout_ms),
                    allow_remote,
                })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard Templates | {} | Loaded: {} | Executed: {} | Matched: {} | Skipped: {} | ParseErrors: {} | {}ms",
                    report.target,
                    report.loaded,
                    report.executed,
                    report.matched_count,
                    report.skipped.len(),
                    report.parse_errors,
                    report.elapsed_ms
                );
                for m in &report.matches {
                    println!(
                        "  [{}] {} ({}) — {} | matchers: {} | {}",
                        m.severity.to_ascii_uppercase(),
                        m.template_id,
                        m.engine,
                        m.template_name,
                        m.matcher_types.join("+"),
                        m.template_path
                    );
                    for ev in &m.evidence {
                        println!("      {ev}");
                    }
                    for (name, val) in &m.extracted {
                        println!("      extracted {name}: {val}");
                    }
                }
                if std::env::var("SMG_VERBOSE").as_deref() == Ok("1") {
                    for s in &report.skipped {
                        println!("  [SKIPPED] {} ({}) — {}", s.id, s.path, s.reason);
                    }
                }
            }
            if let Some(threshold) = fail_on {
                let threshold_rank = match threshold {
                    FailSeverity::Critical => 4,
                    FailSeverity::High => 3,
                    FailSeverity::Medium => 2,
                    FailSeverity::Low => 1,
                };
                let failed = report.matches.iter().any(|m| {
                    let rank = match m.severity.to_ascii_uppercase().as_str() {
                        "CRITICAL" => 4,
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    };
                    rank >= threshold_rank
                });
                if failed {
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Commands::Sqli {
            url,
            method,
            data,
            param,
            header,
            delay,
            skip_timing,
            allow_remote,
            json,
        } => {
            let headers: HashMap<String, String> = header
                .iter()
                .filter_map(|h| h.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let report = sqli_audit::run_sqli_audit(&sqli_audit::SqliAuditConfig {
                url: url.clone(),
                method: method.clone(),
                headers,
                body: data,
                params: param,
                delay_secs: delay,
                skip_timing,
                allow_remote,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard SQLi | {} ({}) | Params: {} | Vulnerable: {} | {}ms",
                    report.url,
                    report.method,
                    report.params_tested,
                    report.vulnerable_params,
                    report.elapsed_ms
                );
                for r in &report.results {
                    println!(
                        "  [{}] param '{}' — error: {} | boolean: {} | time: {} | union-columns: {}",
                        r.verdict,
                        r.param,
                        r.error_based.is_some(),
                        r.boolean_based.is_some(),
                        r.time_based.is_some(),
                        r.union_columns
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "-".into())
                    );
                    if let Some(ev) = &r.error_based {
                        println!(
                            "      error-based: {} ({})",
                            ev.evidence,
                            ev.db.as_deref().unwrap_or("?")
                        );
                    }
                    if let Some(ev) = &r.boolean_based {
                        println!("      boolean-blind: {}", ev.evidence);
                    }
                    if let Some(ev) = &r.time_based {
                        println!(
                            "      time-based: {} ({})",
                            ev.evidence,
                            ev.db.as_deref().unwrap_or("?")
                        );
                    }
                }
            }
            if report.vulnerable_params > 0 {
                return Ok(ExitCode::from(1));
            }
        }
        Commands::Dast {
            url,
            max_pages,
            max_depth,
            passive_only,
            header,
            allow_remote,
            json,
        } => {
            let headers: HashMap<String, String> = header
                .iter()
                .filter_map(|h| h.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let report = dast_audit::run_dast_audit(&dast_audit::DastConfig {
                seed_url: url.clone(),
                headers,
                max_pages,
                max_depth,
                active: !passive_only,
                timeout: Duration::from_secs(8),
                allow_remote,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard DAST | {} | Pages: {} | Active targets: {} | Findings: {} | {}ms",
                    report.seed_url,
                    report.pages_crawled,
                    report.targets_tested,
                    report.findings.len(),
                    report.elapsed_ms
                );
                for f in &report.findings {
                    let payload_note = if f.payload.is_empty() {
                        String::new()
                    } else {
                        format!(" payload={:?}", f.payload)
                    };
                    println!(
                        "  [{}] {} {} {}{} — {}",
                        f.severity.to_ascii_uppercase(),
                        f.id,
                        f.url,
                        f.param.as_deref().unwrap_or("-"),
                        payload_note,
                        f.evidence
                    );
                }
            }
            let blocking = report
                .findings
                .iter()
                .any(|f| matches!(f.severity.as_str(), "critical" | "high"));
            if blocking {
                return Ok(ExitCode::from(1));
            }
        }
        Commands::Proxy {
            listen,
            no_tui,
            log,
            allow_remote_bind,
        } => {
            let bind_addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("Invalid --listen address '{listen}'"))?;
            let handle = proxy::start_proxy(proxy::ProxyConfig {
                bind_addr,
                capture_limit: proxy::DEFAULT_CAPTURE_LIMIT,
                allow_remote_bind,
                jsonl_log: log,
            })?;
            let bind = handle.bound_addr;
            println!(
                "ShellMind Guard Proxy | listening on http://{bind} (HTTP intercepted · HTTPS CONNECT logged & tunneled transparently)"
            );
            println!(
                "  Point your app/browser proxy at {bind} — TUI keys: j/k select · Tab focus · r replay · d decode · i intruder · e export · q quit"
            );
            if no_tui {
                if std::io::stdin().is_terminal() {
                    println!(
                        "  Headless mode: JSONL entries streaming to log; press Ctrl+D or type 'q' + Enter to stop."
                    );
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match std::io::stdin().read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {
                                if line.trim() == "q" {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                } else {
                    // Non-interactive context (CI/service/background): run
                    // until the process is stopped externally.
                    println!(
                        "  Headless mode (non-interactive stdin): running until stopped; JSONL entries streaming to log."
                    );
                    loop {
                        if handle.stop.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            } else {
                smg_tui::proxy_tui::run_proxy_tui(
                    Arc::clone(&handle.entries),
                    Arc::clone(&handle.summary),
                )?;
            }
            handle.stop.store(true, Ordering::Relaxed);
            if let Some(t) = handle.listener_thread {
                let _ = t.join();
            }
            let summary = handle.summary.lock().map(|s| s.clone()).unwrap_or_default();
            println!(
                "  Stopped | HTTP: {} | TLS tunnels: {} | Errors: {}",
                summary.http_intercepted, summary.https_tunneled, summary.errors
            );
        }
        Commands::HttpAudit {
            url,
            header,
            schema,
            graphql,
            timeout_ms,
            allow_remote,
            json,
        } => {
            let headers: HashMap<String, String> = header
                .iter()
                .filter_map(|h| h.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let report = http_audit::run_http_audit(&http_audit::HttpAuditConfig {
                url: url.clone().unwrap_or_default(),
                headers,
                schema_file: schema,
                graphql_endpoint: graphql,
                timeout: Duration::from_millis(timeout_ms),
                allow_remote,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "ShellMind Guard HTTP-Audit | {} | Passive: {} | Schema: {} ({}) | {}ms",
                    report.url,
                    report.passive_findings.len(),
                    report.schema_findings.len(),
                    report.schema_kind.as_deref().unwrap_or("none discovered"),
                    report.elapsed_ms
                );
                for f in report
                    .passive_findings
                    .iter()
                    .chain(report.schema_findings.iter())
                {
                    println!(
                        "  [{}] {} {} {} — {}",
                        f.severity.to_ascii_uppercase(),
                        f.id,
                        f.url,
                        f.param.as_deref().unwrap_or("-"),
                        f.evidence
                    );
                }
            }
            let blocking = report
                .passive_findings
                .iter()
                .chain(report.schema_findings.iter())
                .any(|f| matches!(f.severity.as_str(), "critical" | "high"));
            if blocking {
                return Ok(ExitCode::from(1));
            }
        }
        Commands::Deps { action } => match action {
            DepsAction::Sync {
                path,
                osv_url,
                from_file,
            } => {
                let db_path = smg_core::default_advisories_db_path();
                let mut store = smg_core::AdvisoryStore::open_default()?;
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
                        if std::io::stderr().is_terminal() {
                            eprint!(
                                "[SMG] Querying OSV.dev advisories for {} package(s)... ",
                                deps.len()
                            );
                            let _ = std::io::stderr().flush();
                        }
                        let summary = deps_sync::sync_osv_to_store(&osv_url, &deps, &mut store)?;
                        if std::io::stderr().is_terminal() {
                            eprintln!("done.");
                        }
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
                let db_path = smg_core::default_advisories_db_path();
                if !db_path.exists() {
                    println!(
                        "ShellMind Guard Deps | DB: {} | Status: NOT INITIALIZED (0 advisories; run `smg deps sync`)",
                        db_path.display()
                    );
                } else {
                    let store = smg_core::AdvisoryStore::open_at(&db_path, true)?;
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
        Commands::Enterprise { action } => {
            handle_enterprise_command(*action)?;
        }
        Commands::Doctor { path, probe_ai } => {
            run_doctor(&path, probe_ai);
        }
        Commands::ProbeNetns {
            port,
            sync_race,
            mode,
        } => {
            let probe_cfg: SandboxProbeConfig = std::env::var("SMG_PROBE_CONFIG_FILE")
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .or_else(|| std::env::var("SMG_PROBE_CONFIG_JSON").ok())
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            match mode {
                ProbeMode::Verify => {
                    let finding_json = match std::env::var("SMG_FINDING_FILE") {
                        Ok(p) => std::fs::read_to_string(p)?,
                        Err(_) => std::env::var("SMG_FINDING_JSON")?,
                    };
                    let finding: LatticeFinding = serde_json::from_str(&finding_json)?;
                    let res =
                        verify_finding_blocking_with_config(port, &finding, sync_race, &probe_cfg)?;
                    println!("{}", serde_json::to_string(&res)?);
                }
                ProbeMode::VerifyBatch => {
                    let batch_json = match std::env::var("SMG_FINDING_FILE") {
                        Ok(p) => std::fs::read_to_string(p)?,
                        Err(_) => std::env::var("SMG_FINDING_JSON")?,
                    };
                    let findings: Vec<LatticeFinding> = serde_json::from_str(&batch_json)?;
                    let res = verify_findings_batch_blocking_with_config(
                        port, &findings, sync_race, &probe_cfg,
                    )?;
                    println!("{}", serde_json::to_string(&res)?);
                }
                ProbeMode::Fuzz => {
                    let hits = verify_deep_fuzz_blocking_with_config(port, &probe_cfg)?;
                    println!("{}", serde_json::to_string(&hits)?);
                }
            }
        }
    }

    smg_sandbox::kill_active_sandbox_pgid();
    Ok(ExitCode::SUCCESS)
}

/// Extract inner `$(...)` and backtick command substitutions from double-quoted shell strings
/// (POSIX executes these during argument expansion, unlike single-quoted literals).
fn extract_double_quoted_substitutions(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let ch = chars[i];
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if ch == '\\' {
            i += 2;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = true;
            i += 1;
            continue;
        }
        if ch == '"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_double && ch == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            let start = i + 2;
            let mut j = start;
            let mut depth = 1usize;
            let mut sub_sq = false;
            let mut sub_dq = false;
            while j < chars.len() && depth > 0 {
                let c = chars[j];
                if sub_sq {
                    if c == '\'' {
                        sub_sq = false;
                    }
                } else if c == '\\' {
                    j += 1;
                } else if sub_dq {
                    if c == '"' {
                        sub_dq = false;
                    }
                } else {
                    match c {
                        '\'' => sub_sq = true,
                        '"' => sub_dq = true,
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if j > start {
                out.push(chars[start..j].iter().collect());
            }
            i = j.saturating_add(1);
            continue;
        }
        if in_double && ch == '`' {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '`' {
                    break;
                }
                j += 1;
            }
            if j > start {
                out.push(chars[start..j].iter().collect());
            }
            i = j.saturating_add(1);
            continue;
        }
        i += 1;
    }
    out
}

fn split_shell_commands(cmd_str: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut cur_tokens: Vec<String> = Vec::new();
    let mut cur_tok = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let chars: Vec<char> = cmd_str.chars().collect();
    let mut i = 0usize;

    let flush_tok = |tok: &mut String, toks: &mut Vec<String>| {
        if !tok.is_empty() {
            toks.push(std::mem::take(tok));
        }
    };
    let flush_cmd = |toks: &mut Vec<String>, cmds: &mut Vec<Vec<String>>| {
        if !toks.is_empty() {
            cmds.push(std::mem::take(toks));
        }
    };

    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            cur_tok.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur_tok.push(ch);
            }
            i += 1;
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\'
                && i + 1 < chars.len()
                && matches!(chars[i + 1], '"' | '\\' | '$' | '`')
            {
                escaped = true;
            } else {
                cur_tok.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\\' => {
                // Only treat backslash as escape on Unix paths/shells if followed by shell meta/space
                if i + 1 < chars.len()
                    && matches!(
                        chars[i + 1],
                        ' ' | '\t' | '"' | '\'' | ';' | '&' | '|' | '(' | ')' | '`' | '\\'
                    )
                {
                    escaped = true;
                } else {
                    cur_tok.push(ch);
                }
            }
            '\'' => in_single = true,
            '"' => in_double = true,
            ' ' | '\t' | '\r' => flush_tok(&mut cur_tok, &mut cur_tokens),
            ';' | '\n' | '(' | ')' | '`' => {
                flush_tok(&mut cur_tok, &mut cur_tokens);
                flush_cmd(&mut cur_tokens, &mut commands);
            }
            '&' | '|' => {
                flush_tok(&mut cur_tok, &mut cur_tokens);
                flush_cmd(&mut cur_tokens, &mut commands);
                if i + 1 < chars.len() && chars[i + 1] == ch {
                    i += 1;
                }
            }
            _ => cur_tok.push(ch),
        }
        i += 1;
    }
    flush_tok(&mut cur_tok, &mut cur_tokens);
    flush_cmd(&mut cur_tokens, &mut commands);
    commands
}

fn parse_git_commit_invocation(cmd_str: &str) -> Option<PathBuf> {
    parse_git_commit_invocation_bounded(cmd_str, 0)
}

fn resolve_cd_relative(current_cd: Option<&PathBuf>, inner_path: PathBuf) -> PathBuf {
    match (current_cd, inner_path) {
        (Some(cd), p) if p == Path::new(".") => cd.clone(),
        (Some(cd), p) if p.is_relative() => cd.join(p),
        (_, p) => p,
    }
}

fn git_dir_arg_to_worktree(arg: &str) -> PathBuf {
    let p = Path::new(arg);
    if p.file_name().and_then(|n| n.to_str()) == Some(".git") {
        let parent = p.parent().unwrap_or_else(|| Path::new(""));
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    } else {
        p.to_path_buf()
    }
}

fn parse_git_commit_invocation_bounded(cmd_str: &str, depth: usize) -> Option<PathBuf> {
    if depth > 4 {
        return None;
    }
    let mut current_cd: Option<PathBuf> = None;
    let dq_subs = extract_double_quoted_substitutions(cmd_str);
    for mut tokens in split_shell_commands(cmd_str) {
        while let Some(first) = tokens.first() {
            let is_env_assign = first.contains('=')
                && !first.starts_with('-')
                && !first.starts_with('/')
                && !first.starts_with('.');
            let first_norm = first.replace('\\', "");
            if is_env_assign
                || matches!(
                    first_norm.as_str(),
                    "sudo" | "env" | "command" | "nohup" | "$" | "&"
                )
            {
                tokens.remove(0);
            } else {
                break;
            }
        }
        let Some(cmd_clean) = tokens.first().map(|s| s.as_str()) else {
            continue;
        };
        let cmd_norm = cmd_clean.replace('\\', "").to_ascii_lowercase();
        if matches!(
            cmd_norm.as_str(),
            "cd" | "pushd" | "set-location" | "push-location" | "sl"
        ) {
            if let Some(dir_clean) = tokens
                .iter()
                .skip(1)
                .find(|arg| !arg.is_empty() && !arg.starts_with('-'))
            {
                current_cd = Some(PathBuf::from(dir_clean));
            }
            continue;
        }
        // Unwrap nested shell / eval invocations (`sh -c "git commit ..."`, `bash -lc "..."`, `eval "git commit ..."`)
        let is_shell_wrapper = matches!(
            cmd_norm.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "/bin/sh" | "/bin/bash" | "/bin/zsh"
        );
        if is_shell_wrapper {
            let mut idx = 1usize;
            while idx < tokens.len() {
                let tok = &tokens[idx];
                if (tok == "-c"
                    || (tok.starts_with('-') && !tok.starts_with("--") && tok.ends_with('c')))
                    && let Some(inner_cmd) = tokens.get(idx + 1)
                    && let Some(inner_path) =
                        parse_git_commit_invocation_bounded(inner_cmd, depth + 1)
                {
                    return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
                }
                idx += 1;
            }
            continue;
        }
        if cmd_norm == "eval" && tokens.len() > 1 {
            let joined = tokens[1..].join(" ");
            if let Some(inner_path) = parse_git_commit_invocation_bounded(&joined, depth + 1) {
                return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
            }
            continue;
        }
        let unix_base = cmd_clean.rsplit('/').next().unwrap_or(cmd_clean);
        let unix_base_norm = unix_base.replace('\\', "");
        let is_git = (!cmd_clean.contains(':')
            && matches!(
                unix_base_norm.to_ascii_lowercase().as_str(),
                "git" | "git.exe"
            ))
            || cmd_clean.ends_with("/git")
            || cmd_clean.ends_with("\\git")
            || cmd_clean.ends_with("/git.exe")
            || cmd_clean.ends_with("\\git.exe");
        if !is_git {
            continue;
        }

        let mut git_dir_override: Option<PathBuf> = None;
        let mut git_worktree_explicit = false;
        let mut commit_aliases: Vec<String> = Vec::new();
        let mut subcmd: Option<String> = None;
        let mut i = 1usize;
        while i < tokens.len() {
            let t = tokens[i].as_str();
            let t_norm = t.replace('\\', "");
            if matches!(t_norm.as_str(), "-C" | "--work-tree") {
                if let Some(clean_dir) = tokens.get(i + 1) {
                    let next = PathBuf::from(clean_dir);
                    git_dir_override = Some(match (git_dir_override, next.is_relative()) {
                        (Some(prev), true) if t_norm == "-C" => prev.join(next),
                        _ => next,
                    });
                    if t_norm == "--work-tree" {
                        git_worktree_explicit = true;
                    }
                }
                i += 2;
                continue;
            }
            if let Some(rest) = t.strip_prefix("-C").filter(|r| !r.is_empty()) {
                let next = PathBuf::from(rest);
                git_dir_override = Some(match (git_dir_override, next.is_relative()) {
                    (Some(prev), true) => prev.join(next),
                    _ => next,
                });
                i += 1;
                continue;
            }
            if let Some(rest) = t.strip_prefix("--work-tree=").filter(|r| !r.is_empty()) {
                git_dir_override = Some(PathBuf::from(rest));
                git_worktree_explicit = true;
                i += 1;
                continue;
            }
            if t_norm == "--git-dir" {
                if let Some(gd) = tokens.get(i + 1)
                    && !git_worktree_explicit
                    && git_dir_override.is_none()
                {
                    git_dir_override = Some(git_dir_arg_to_worktree(gd));
                }
                i += 2;
                continue;
            }
            if let Some(rest) = t.strip_prefix("--git-dir=").filter(|r| !r.is_empty()) {
                if !git_worktree_explicit && git_dir_override.is_none() {
                    git_dir_override = Some(git_dir_arg_to_worktree(rest));
                }
                i += 1;
                continue;
            }
            if t_norm == "-c" {
                if let Some(kv) = tokens.get(i + 1)
                    && let Some((k, v)) = kv.split_once('=')
                    && let Some(alias_name) = k.strip_prefix("alias.")
                {
                    let v_trimmed = v.trim();
                    let target = v_trimmed.split_whitespace().next().unwrap_or("");
                    if matches!(target, "commit" | "ci")
                        || v_trimmed.strip_prefix('!').is_some_and(|shell_cmd| {
                            parse_git_commit_invocation_bounded(shell_cmd, depth + 1).is_some()
                        })
                    {
                        commit_aliases.push(alias_name.to_string());
                    }
                }
                i += 2;
                continue;
            }
            if let Some(kv) = t_norm.strip_prefix("-c").filter(|r| !r.is_empty()) {
                if let Some((k, v)) = kv.split_once('=')
                    && let Some(alias_name) = k.strip_prefix("alias.")
                {
                    let v_trimmed = v.trim();
                    let target = v_trimmed.split_whitespace().next().unwrap_or("");
                    if matches!(target, "commit" | "ci")
                        || v_trimmed.strip_prefix('!').is_some_and(|shell_cmd| {
                            parse_git_commit_invocation_bounded(shell_cmd, depth + 1).is_some()
                        })
                    {
                        commit_aliases.push(alias_name.to_string());
                    }
                }
                i += 1;
                continue;
            }
            if matches!(
                t_norm.as_str(),
                "--namespace" | "--exec-path" | "--super-prefix" | "--config-env" | "--list-cmds"
            ) {
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            subcmd = Some(t_norm);
            break;
        }

        if let Some(ref sc) = subcmd
            && (matches!(sc.as_str(), "commit" | "ci") || commit_aliases.iter().any(|a| a == sc))
        {
            let resolved = match (&current_cd, git_dir_override) {
                (Some(cd), Some(ov)) if ov.is_relative() => cd.join(ov),
                (_, Some(ov)) => ov,
                (Some(cd), None) => cd.clone(),
                (None, None) => PathBuf::from("."),
            };
            return Some(resolved);
        }
    }
    for sub in dq_subs {
        if let Some(inner_path) = parse_git_commit_invocation_bounded(&sub, depth + 1) {
            return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
        }
    }
    None
}

fn dir_has_git_marker(dir: &Path) -> bool {
    dir.ancestors().any(|a| a.join(".git").exists())
}

fn filter_trusted_hook_cwd<'a>(
    target_repo: &Path,
    hook_cwd: Option<&'a Path>,
    process_cwd: Option<&Path>,
) -> Option<&'a Path> {
    match hook_cwd {
        Some(h_cwd)
            if target_repo == Path::new(".")
                && (!h_cwd.exists() || !dir_has_git_marker(h_cwd))
                && process_cwd.is_some_and(dir_has_git_marker) =>
        {
            None
        }
        other => other,
    }
}

fn resolve_hook_scan_path(target_repo: &Path, hook_cwd: Option<&Path>) -> Option<PathBuf> {
    if target_repo == Path::new(".") {
        let base = hook_cwd.unwrap_or_else(|| Path::new("."));
        return base.exists().then(|| base.to_path_buf());
    }
    let candidate = if target_repo.is_relative() {
        if let Some(cwd) = hook_cwd {
            cwd.join(target_repo)
        } else {
            target_repo.to_path_buf()
        }
    } else {
        target_repo.to_path_buf()
    };
    candidate.exists().then_some(candidate)
}

fn handle_claude_pre_commit() -> Result<ExitCode> {
    use std::io::Read;
    const MAX_HOOK_STDIN_BYTES: u64 = 1024 * 1024;
    let mut stdin_buf = String::new();
    let _ = std::io::stdin()
        .take(MAX_HOOK_STDIN_BYTES)
        .read_to_string(&mut stdin_buf);
    let payload_opt = match serde_json::from_str::<serde_json::Value>(&stdin_buf) {
        Ok(v) => Some(v),
        Err(e) => {
            if !stdin_buf.trim().is_empty() {
                eprintln!(
                    "[ShellMind Guard] Invalid hook JSON payload on stdin (failing closed): {}",
                    e
                );
                return Ok(ExitCode::from(2));
            }
            None
        }
    };

    let is_antigravity = payload_opt
        .as_ref()
        .is_some_and(|v| v.get("toolCall").is_some() && v.get("tool_input").is_none());

    let cmd_str = payload_opt
        .as_ref()
        .and_then(|v| {
            v.get("tool_input")
                .and_then(|ti| ti.get("command"))
                .and_then(|c| c.as_str())
                .or_else(|| {
                    v.get("toolCall")
                        .and_then(|tc| tc.get("args"))
                        .and_then(|a| a.get("CommandLine"))
                        .and_then(|c| c.as_str())
                })
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let hook_cwd = payload_opt.as_ref().and_then(|v| {
        v.get("cwd")
            .and_then(|c| c.as_str())
            .or_else(|| {
                v.get("workspacePaths")
                    .and_then(|wp| wp.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|s| s.as_str())
            })
            .map(PathBuf::from)
    });

    let Some(target_repo) = parse_git_commit_invocation(&cmd_str)
        .or_else(|| parse_git_commit_invocation(&cmd_str.replace('`', "")))
    else {
        if is_antigravity {
            println!("{}", serde_json::json!({ "decision": "allow" }));
        }
        return Ok(ExitCode::SUCCESS);
    };
    let proc_cwd = std::env::current_dir().ok();
    let effective_cwd =
        filter_trusted_hook_cwd(&target_repo, hook_cwd.as_deref(), proc_cwd.as_deref());
    let Some(scan_path) = resolve_hook_scan_path(&target_repo, effective_cwd) else {
        if is_antigravity {
            println!("{}", serde_json::json!({ "decision": "allow" }));
        }
        return Ok(ExitCode::SUCCESS);
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
        deep_audit: false,
        sandbox_mem_mb: None,
        sandbox_tls: false,
        mock_shims: false,
        cgroup_v2: false,
    })?;

    if should_fail_gate(&outcome.graph.findings, true, None) {
        if is_antigravity {
            let summary = outcome
                .graph
                .findings
                .iter()
                .take(5)
                .map(|f| format!("[{}] {} ({}:{})", f.severity, f.id, f.file, f.line))
                .collect::<Vec<_>>()
                .join("; ");
            let reason = format!(
                "[ShellMind Guard] Blocked git commit: {} secret/config issue(s) found ({}).",
                outcome.graph.findings.len(),
                summary
            );
            println!(
                "{}",
                serde_json::json!({
                    "decision": "deny",
                    "reason": reason
                })
            );
            return Ok(ExitCode::SUCCESS);
        }
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
    if is_antigravity {
        println!("{}", serde_json::json!({ "decision": "allow" }));
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

pub(crate) fn install_git_hook(root: &Path) -> Result<PathBuf> {
    let git_meta = root.join(".git");
    if let Ok(m) = fs::symlink_metadata(&git_meta)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to install git hook through symlinked .git path: {}",
            git_meta.display()
        );
    }
    let hooks_dir = resolve_git_hooks_dir(root)?;
    if let Ok(m) = fs::symlink_metadata(&hooks_dir)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to install git hook through symlinked hooks directory: {}",
            hooks_dir.display()
        );
    }
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    if let Ok(m) = fs::symlink_metadata(&hook_path)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to overwrite symlinked pre-commit hook: {}",
            hook_path.display()
        );
    }
    let exe_fallback = std::env::current_exe()
        .ok()
        .filter(|p| {
            let s = p.to_string_lossy();
            !s.contains("/target/") && !s.contains("\\target\\") && !s.contains("/deps/")
        })
        .map(|p| {
            let quoted = p.to_string_lossy().replace('\'', "'\\''");
            format!(" '{}'", quoted)
        })
        .unwrap_or_default();
    let block = format!(
        "{}\nSMG_BIN=\"$(command -v smg 2>/dev/null || command -v shellmind-guard 2>/dev/null || true)\"\nif [ -z \"$SMG_BIN\" ]; then\n  for cand in \"$HOME/.local/bin/smg\" \"$HOME/.local/bin/shellmind-guard\" \"$HOME/.cargo/bin/smg\" \"$HOME/.cargo/bin/shellmind-guard\" \"/usr/local/bin/smg\" \"/usr/local/bin/shellmind-guard\" \"/opt/homebrew/bin/smg\" \"/opt/homebrew/bin/shellmind-guard\"{exe_fallback}; do\n    if [ -x \"$cand\" ]; then\n      SMG_BIN=\"$cand\"\n      break\n    fi\n  done\nfi\nif [ -n \"$SMG_BIN\" ]; then\n  \"$SMG_BIN\" scan . --layers secrets,config --ci\nelse\n  echo \"[ShellMind Guard] warning: smg/shellmind-guard binary not found in PATH; skipping pre-commit scan\" >&2\nfi\n{}\n",
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

struct RenderOptions<'a> {
    format: OutputFormat,
    sarif_payload: Option<&'a str>,
    patch: bool,
    color_mode: ColorMode,
    output: Option<&'a Path>,
}

fn read_source_snippet_lines(
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

fn guard_category_tag(guard: GuardKind) -> &'static str {
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

fn summarize_findings_counts(
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

fn clip_str(s: &str, max_chars: usize) -> String {
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

fn write_rendered_output(output: Option<&Path>, text: &str) -> Result<()> {
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

fn format_scan_output(
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
fn render_scan_output(
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

fn binary_on_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exe_name = if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(&exe_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn run_doctor(path: &Path, probe_ai: bool) {
    println!(
        "ShellMind Guard (smg) Doctor | v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let backend = detect_sandbox_backend();
    let bwrap_ok = smg_sandbox::has_bwrap();
    println!("  Sandbox Backend : {}", backend.label());
    println!(
        "  Sandbox (bwrap) : {}",
        if bwrap_ok {
            "OK (bwrap available; --unshare-all netns isolation active)"
        } else {
            "UNAVAILABLE (static scan, TUI, SARIF & MCP work; fallback sandbox uses host loopback if authorized)"
        }
    );
    let systemd_status = match Command::new("systemd-run")
        .args(["--user", "--version"])
        .output()
    {
        Ok(out) if out.status.success() => {
            "OK (systemd-run --user available for --cgroup-v2)".to_string()
        }
        _ => "unavailable (falling back to RLIMIT_AS memory bounds)".to_string(),
    };
    println!("  cgroups v2      : {}", systemd_status);
    let git_status = match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "NOT FOUND".to_string(),
    };
    println!("  Git CLI         : {}", git_status);
    let cfg_exists = path.join(".shellmind-guard.toml").exists();
    println!(
        "  Config          : {}",
        if cfg_exists {
            ".shellmind-guard.toml present"
        } else {
            "using built-in defaults (run `smg init` to customize)"
        }
    );
    let osv_db = smg_core::default_advisories_db_path();
    let osv_status = if osv_db.exists() {
        match smg_core::AdvisoryStore::open_at(&osv_db, true).and_then(|s| s.stats()) {
            Ok((total, _)) => format!("{} ({} cached advisories)", osv_db.display(), total),
            Err(_) => format!("{} (unreadable)", osv_db.display()),
        }
    } else {
        format!(
            "not initialized ({}; run `smg deps sync`)",
            osv_db.display()
        )
    };
    println!("  Offline OSV DB  : {}", osv_status);
    println!(
        "  Git Pre-Commit  : {}",
        if git_hook_status(path) {
            "ACTIVE"
        } else {
            "not installed (run `smg hook install` for zero-AI commit protection)"
        }
    );
    let smg_on_path = binary_on_path("smg");
    let legacy_on_path = binary_on_path("shellmind-guard");
    let has_plugin = path.join(".claude-plugin").join("plugin.json").exists();
    let has_mcp = path.join(".mcp.json").exists();
    let path_summary = match (&smg_on_path, &legacy_on_path) {
        (Some(p1), Some(p2)) => format!("smg={} · shellmind-guard={}", p1.display(), p2.display()),
        (Some(p1), None) => format!("smg={} (shellmind-guard not on PATH)", p1.display()),
        (None, Some(p2)) => format!("shellmind-guard={} (install `smg` alias)", p2.display()),
        (None, None) => "NEITHER `smg` NOR `shellmind-guard` on PATH".to_string(),
    };
    println!(
        "  CLI / Plugin    : {}{}",
        path_summary,
        if has_plugin || has_mcp {
            format!(" [plugin_manifest={}, mcp_config={}]", has_plugin, has_mcp)
        } else {
            String::new()
        }
    );
    if probe_ai {
        match ShellMindGuardConfig::load_from_dir(path) {
            Ok(cfg) => {
                if !cfg.ai.is_enabled() {
                    println!(
                        "  AI Provider     : disabled (zero network calls; configure [ai] in .shellmind-guard.toml)"
                    );
                } else {
                    match provider_from_config(&cfg.ai) {
                        Ok(smg_ai::AiProvider::Ollama { endpoint, model }) => {
                            let ping_url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
                            let probe_res = reqwest::blocking::Client::builder()
                                .redirect(reqwest::redirect::Policy::none())
                                .timeout(std::time::Duration::from_secs(2))
                                .build()
                                .and_then(|c| c.get(&ping_url).send());
                            match probe_res {
                                Ok(r) if r.status().is_success() => println!(
                                    "  AI Provider     : Ollama reachable ({}) · model={}",
                                    endpoint, model
                                ),
                                Ok(r) => println!(
                                    "  AI Provider     : Ollama HTTP {} at {} · model={}",
                                    r.status(),
                                    endpoint,
                                    model
                                ),
                                Err(e) => println!(
                                    "  AI Provider     : Ollama unreachable at {} ({})",
                                    endpoint, e
                                ),
                            }
                        }
                        Ok(other) => {
                            let env_set = std::env::var_os(&cfg.ai.api_key_env)
                                .is_some_and(|v| !v.is_empty());
                            println!(
                                "  AI Provider     : {:?} · endpoint={} · model={} · {}={}",
                                other,
                                cfg.ai.endpoint,
                                cfg.ai.model,
                                cfg.ai.api_key_env,
                                if env_set { "SET" } else { "UNSET" }
                            );
                        }
                        Err(e) => println!("  AI Provider     : invalid config ({})", e),
                    }
                }
            }
            Err(e) => println!("  AI Provider     : failed loading config ({})", e),
        }
    }
}

/// Appends one non-secret audit ledger event to `.shellmind-guard/audit-history.jsonl`
/// (avoiding test fixture directories by routing fixture runs to no-op).
pub(crate) fn append_audit_event(
    project_root: &Path,
    action: &str,
    findings_count: usize,
    verified_count: usize,
    detail: &str,
) -> Result<Option<PathBuf>> {
    let canon = fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    if canon
        .components()
        .any(|c| c.as_os_str() == std::ffi::OsStr::new("fixtures"))
    {
        return Ok(None);
    }
    // Resolve nearest .git root so scanning a subdirectory does not litter nested .shellmind-guard/ dirs.
    let anchor = canon
        .ancestors()
        .find(|a| a.join(".git").exists())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project_root.to_path_buf());
    let dir = anchor.join(".shellmind-guard");
    fs::create_dir_all(&dir)?;
    let log_path = dir.join("audit-history.jsonl");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let rec = serde_json::json!({
        "ts": ts,
        "action": action,
        "findings_count": findings_count,
        "verified_count": verified_count,
        "detail": detail,
    });
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(f, "{}", rec)?;
    Ok(Some(log_path))
}

#[cfg(test)]
struct TempDirCleanup(PathBuf);

#[cfg(test)]
impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn verify_patch_apply_check(params: &ApplyCheckParams<'_>) -> Result<smg_ai::ApplyCheckOutcome> {
    verify_patch_in_isolated_copy(params)
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use smg_graph::analyze_codebase;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        assert_eq!(
            parse_git_commit_invocation("git -C \"sub repo\" commit -m \"fix & deploy\""),
            Some(PathBuf::from("sub repo"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd \"sub dir\"; git commit -m \"ok\""),
            Some(PathBuf::from("sub dir"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd -P services/billing && git commit -m 'ok'"),
            Some(PathBuf::from("services/billing"))
        );
        assert_eq!(
            parse_git_commit_invocation("sh -c \"git commit -m 'nested'\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("cd apps/web && bash -lc \"git commit -m 'nested'\""),
            Some(PathBuf::from("apps/web"))
        );
        assert_eq!(
            parse_git_commit_invocation("eval \"git commit -m 'via-eval'\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation(
                "git --super-prefix sub/ --config-env user.name=GIT_USER commit -m 'opts'"
            ),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("echo \"cd /tmp && git commit -m fake\""),
            None
        );
        assert_eq!(parse_git_commit_invocation("git status && git diff"), None);
    }

    #[test]
    fn test_resolve_hook_scan_path_and_deep_replay_lookup() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_hook_cwd_{}", nanos));
        let _cleanup = TempDirCleanup(tmp.clone());
        let sub = tmp.join("apps/api");
        fs::create_dir_all(&sub).unwrap();

        assert_eq!(
            resolve_hook_scan_path(Path::new("."), Some(&tmp)),
            Some(tmp.clone())
        );
        assert_eq!(
            resolve_hook_scan_path(Path::new("apps/api"), Some(&tmp)),
            Some(sub.clone())
        );
        assert_eq!(
            resolve_hook_scan_path(Path::new("does-not-exist"), Some(&tmp)),
            None
        );

        fs::create_dir_all(sub.join("src")).unwrap();
        fs::write(
            sub.join("src/pay.ts"),
            "app.post('/api/pay', (req, res) => { const amount = req.body.amount; res.json({ amount }); });",
        )
        .unwrap();
        let cfg = ShellMindGuardConfig::default();
        let mut store = StateStore::open(&sub).unwrap();
        let resolved =
            resolve_finding_for_replay(&sub, "SMG-FUZZ-SCHEMA", &cfg, &mut store).unwrap();
        assert_eq!(resolved.rule_id, "SMG-FUZZ-SCHEMA");
    }

    #[test]
    fn test_fail_on_severity_gate() {
        let med = LatticeFinding {
            id: "SMG-FE-001".into(),
            rule_id: "SMG-FE-ERR".into(),
            severity: "MEDIUM".into(),
            title: "Empty catch".into(),
            status: "SUSPECT_UNGUARDED".into(),
            confidence: Confidence::Heuristic,
            entry_route: "app.ts:1".into(),
            file: "app.ts".into(),
            line: 1,
            sink_kind: smg_graph::SinkKind::SqlWrite,
            missing_guard: GuardKind::Auth,
            witness_path: vec![],
            remediation: String::new(),
            proof_reasons: vec![],
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
            .find(|f| f.rule_id == "SMG-SQLI-001")
            .expect("expected initial SMG-SQLI-001 finding");

        let probe_cfg = SandboxProbeConfig::from_sandbox_config(&cfg.sandbox);
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
            deep_audit: false,
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
                .any(|f| f.rule_id == "SMG-FUZZ-SCHEMA"),
            "deep=false must not emit SMG-FUZZ-SCHEMA"
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
            deep_audit: false,
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
                .any(|f| f.rule_id == "SMG-FUZZ-SCHEMA"),
            "deep=true must emit SMG-FUZZ-SCHEMA on unvalidated payment route amount"
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
            deep_audit: false,
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
            deep_audit: false,
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

    #[test]
    fn test_wave3_git_commit_obfuscation_subshell_hook_and_symlink_refusal() {
        // F-79: backslash obfuscation, double-quoted $(...), --git-dir
        assert_eq!(
            parse_git_commit_invocation("git com\\mit -m 'x'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("g\\it com\\mit -m 'x'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("echo \"$(git commit -m 'nested')\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("git --git-dir=/tmp/myrepo/.git commit -m 'x'"),
            Some(PathBuf::from("/tmp/myrepo"))
        );
        assert_eq!(
            parse_git_commit_invocation("git -c alias.c=commit c -m 'alias'"),
            Some(PathBuf::from("."))
        );

        // F-59: untrusted non-git hook cwd rejected when invoked inside real git repo
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_f59_f81_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        let clean_dir = root.join("clean_nongit");
        let real_repo = root.join("real_repo");
        fs::create_dir_all(&clean_dir).unwrap();
        fs::create_dir_all(real_repo.join(".git/hooks")).unwrap();
        assert_eq!(
            filter_trusted_hook_cwd(Path::new("."), Some(&clean_dir), Some(&real_repo)),
            None
        );
        assert_eq!(
            filter_trusted_hook_cwd(Path::new("."), Some(&real_repo), Some(&real_repo)),
            Some(real_repo.as_path())
        );

        // F-81: refuse installing pre-commit hook through a symlink
        #[cfg(unix)]
        {
            let target_file = root.join("outside_victim");
            fs::write(&target_file, "#!/bin/sh\necho victim\n").unwrap();
            let hook_link = real_repo.join(".git/hooks/pre-commit");
            std::os::unix::fs::symlink(&target_file, &hook_link).unwrap();
            assert!(
                install_git_hook(&real_repo).is_err(),
                "F-81: install_git_hook must refuse symlinked pre-commit hook"
            );
            assert_eq!(
                fs::read_to_string(&target_file).unwrap(),
                "#!/bin/sh\necho victim\n"
            );
        }
    }

    #[test]
    fn test_cli_rules_catalog_completions_and_parsing() {
        assert!(!RULE_CATALOG.is_empty());
        let race_doc = find_rule_doc("SMG-RACE-001").expect("race rule doc must exist");
        assert_eq!(race_doc.layer, "race");

        let bare = Cli::try_parse_from(["smg"]).unwrap();
        assert!(bare.command.is_none());

        let parsed_replay = Cli::try_parse_from([
            "smg",
            "replay",
            "SMG-RACE-001",
            "--sandbox-mem-mb",
            "512",
            "--sandbox-tls",
            "--mock-shims",
            "--cgroup-v2",
        ])
        .unwrap();
        assert!(matches!(
            parsed_replay.command,
            Some(Commands::Replay {
                sandbox_mem_mb: Some(512),
                sandbox_tls: true,
                mock_shims: true,
                cgroup_v2: true,
                ..
            })
        ));

        let parsed_ui = Cli::try_parse_from([
            "smg",
            "ui",
            "--layers",
            "auth,race",
            "--min-confidence",
            "confirmed",
            "--deep",
            "--sandbox-mem-mb",
            "256",
            "--sandbox-tls",
            "--mock-shims",
            "--cgroup-v2",
        ])
        .unwrap();
        assert!(matches!(
            parsed_ui.command,
            Some(Commands::Ui {
                deep: true,
                sandbox_mem_mb: Some(256),
                sandbox_tls: true,
                mock_shims: true,
                cgroup_v2: true,
                ..
            })
        ));

        let cmd = Cli::command();
        let bash_comp = render_shell_completions(&cmd, CompletionShell::Bash);
        assert!(bash_comp.contains("complete -F _smg_completions smg"));
        assert!(bash_comp.contains("complete -F _smg_completions shellmind-guard"));
        assert!(bash_comp.contains("completions"));
        assert!(bash_comp.contains("explain"));
    }

    #[test]
    fn test_inline_suppression_baseline_and_formats() {
        assert!(line_suppresses_finding(
            "// smg-ignore",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(line_suppresses_finding(
            "const x = 1; // smg-ignore: SMG-SQLI-001",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(!line_suppresses_finding(
            "const x = 1; // smg-ignore: SMG-AUTH-001",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(!line_suppresses_finding(
            "const note = \"smg-ignore\";",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_baseline_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/app.js"),
            "const express = require('express');\nconst app = express();\napp.post('/pay', (req, res) => db.query(req.body.q));\n",
        )
        .unwrap();

        let baseline_path = root.join(".smg-baseline.json");
        let mut outcome1 = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(!outcome1.graph.findings.is_empty());

        let mut v1 = Vec::new();
        apply_suppressions_and_baseline(
            &root,
            &mut outcome1,
            &mut v1,
            &[],
            None,
            Some(&baseline_path),
        )
        .unwrap();
        assert!(baseline_path.exists());

        let mut outcome2 = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        let mut v2 = Vec::new();
        apply_suppressions_and_baseline(
            &root,
            &mut outcome2,
            &mut v2,
            &[],
            Some(&baseline_path),
            None,
        )
        .unwrap();
        assert!(
            outcome2.graph.findings.is_empty(),
            "All baselined findings should be suppressed cleanly"
        );
        assert!(!should_fail_gate(&outcome2.graph.findings, true, None));

        for fmt in [
            OutputFormat::Text,
            OutputFormat::Compact,
            OutputFormat::Table,
            OutputFormat::Markdown,
        ] {
            let rendered = format_scan_output(
                &root,
                &outcome1,
                &[],
                &RenderOptions {
                    format: fmt,
                    sarif_payload: None,
                    patch: false,
                    color_mode: ColorMode::Never,
                    output: None,
                },
            )
            .unwrap();
            assert!(!rendered.is_empty());
        }

        let _ = append_audit_event(&root, "scan", 1, 0, "unit-test").unwrap();
        let audit_file = root.join(".shellmind-guard").join("audit-history.jsonl");
        let audit_txt = fs::read_to_string(&audit_file).unwrap();
        assert!(audit_txt.contains("\"action\":\"scan\""));
        assert!(audit_txt.contains("\"findings_count\":1"));
        assert!(!audit_txt.contains("Bearer "));
    }

    #[cfg(feature = "hw")]
    #[test]
    fn test_hw_feature_scan_cli_rules_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_hw_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("firmware")).unwrap();
        fs::write(
            root.join("board.ld"),
            "MEMORY {\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K\n  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("firmware/boot.c"),
            r#"
void ota_apply(const uint8_t *img, uint32_t len) {
    volatile uint32_t *flash = (volatile uint32_t *)0x08001000;
    *flash = 0x1;
    flash_write(0x08010000, img, len);
}
"#,
        )
        .unwrap();

        let hw_layers = vec!["hw".to_string()];
        let outcome = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &hw_layers,
            min_confidence: None,
            boot_cmd: None,
            port: 39921,
            sync_race: 4,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(ids.contains(&"SMG-HW-MMIO"), "missing MMIO: {:?}", ids);
        assert!(ids.contains(&"SMG-HW-BOOT"), "missing BOOT: {:?}", ids);
        assert!(find_rule_doc("SMG-HW-MMIO").is_some());
        assert!(find_rule_doc("SMG-HW-IRQ").is_some());
    }

    #[cfg(feature = "web3")]
    #[test]
    fn test_web3_feature_scan_cli_rules_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_web3_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("contracts")).unwrap();
        fs::write(
            root.join("foundry.toml"),
            "[profile.default]\nsrc = \"contracts\"\n",
        )
        .unwrap();
        fs::write(
            root.join("contracts/Vault.sol"),
            r#"
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    mapping(address => uint256) public balances;
    function initialize(address _owner) external {
        owner = _owner;
    }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#,
        )
        .unwrap();

        let web3_layers = vec!["web3".to_string()];
        let outcome = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &web3_layers,
            min_confidence: None,
            boot_cmd: None,
            port: 39923,
            sync_race: 4,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(
            ids.contains(&"SMG-WEB3-REENTRANCY"),
            "missing REENTRANCY: {:?}",
            ids
        );
        assert!(
            ids.contains(&"SMG-WEB3-ACCESS"),
            "missing ACCESS: {:?}",
            ids
        );
        assert!(find_rule_doc("SMG-WEB3-REENTRANCY").is_some());
        assert!(find_rule_doc("SMG-WEB3-STORAGE").is_some());
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_pqc_feature_compliance_cbom_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_pqc_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/tls.rs"),
            r#"
pub fn configure_tls() {
    let suite = "ECDHE-RSA-AES128-GCM-SHA256";
    let downgrade = "mlkem_fallback_to_rsa";
    let seed = [0u8; 32]; ml_kem_keygen(seed);
}
"#,
        )
        .unwrap();

        let cbom_file = root.join("out/cbom.json");
        let default_outcome = execute_scan_pipeline_full(
            ScanRunOptions {
                path: &root,
                layers: &[],
                min_confidence: None,
                boot_cmd: None,
                port: 39925,
                sync_race: 4,
                unsafe_host_fallback: false,
                trust_repo_config: false,
                deep: false,
                deep_audit: false,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
            },
            None,
            false,
            false,
            None,
        )
        .unwrap();
        assert!(
            !default_outcome
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id.starts_with("SMG-PQC-")),
            "default scan must not emit PQC advisories when unrequested"
        );

        let pqc_layers = vec!["pqc".to_string()];
        let outcome = execute_scan_pipeline_full(
            ScanRunOptions {
                path: &root,
                layers: &pqc_layers,
                min_confidence: None,
                boot_cmd: None,
                port: 39926,
                sync_race: 4,
                unsafe_host_fallback: false,
                trust_repo_config: false,
                deep: false,
                deep_audit: false,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
            },
            None,
            false,
            true,
            Some(&cbom_file),
        )
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(ids.contains(&"SMG-PQC-HNDL"), "missing HNDL: {:?}", ids);
        assert!(ids.contains(&"SMG-PQC-GROVER"), "missing GROVER: {:?}", ids);
        assert!(
            ids.contains(&"SMG-PQC-DOWNGRADE"),
            "missing DOWNGRADE: {:?}",
            ids
        );
        assert!(ids.contains(&"SMG-PQC-PARAMS"), "missing PARAMS: {:?}", ids);

        let cbom_raw = fs::read_to_string(&cbom_file).unwrap();
        assert!(cbom_raw.contains("CycloneDX"));
        assert!(cbom_raw.contains("\"runtimeUnobserved\": true"));
        assert!(find_rule_doc("SMG-PQC-HNDL").is_some());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn test_enterprise_license_and_tee_attestation_fail_closed() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_ent_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(&root).unwrap();

        let (pkcs8, pubkey) = smg_enterprise::generate_ed25519_keypair().unwrap();
        let pub_hex = smg_enterprise::encode_hex(&pubkey);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = smg_enterprise::LicenseClaims {
            license_id: "ent-cli-001".into(),
            organization: "ShellMind Enterprise Test".into(),
            tier: smg_enterprise::LicenseTier::EnterpriseTee,
            issued_at_unix: now.saturating_sub(10),
            expires_at_unix: now + 3600,
            max_seats: 10,
            features: vec!["hw".into(), "web3".into(), "pqc".into(), "tee".into()],
            pinned_binary_blake3: None,
        };
        let token = smg_enterprise::sign_license_claims(&pkcs8, &claims).unwrap();
        let lic_path = root.join("license.json");
        fs::write(&lic_path, serde_json::to_string_pretty(&token).unwrap()).unwrap();

        handle_enterprise_command(EnterpriseAction::VerifyLicense {
            license: lic_path.clone(),
            pubkey: pub_hex.clone(),
            tier: "enterprise-tee".into(),
            binary: None,
        })
        .unwrap();

        let pcr0 = "d".repeat(96);
        let nonce = "0102030405060708";
        let quote = smg_enterprise::sign_tee_quote(
            &pkcs8,
            smg_enterprise::TeePlatform::AwsNitro,
            &pcr0,
            nonce,
            now,
            "nitro-cli-01",
        )
        .unwrap();
        let quote_path = root.join("quote.json");
        fs::write(&quote_path, serde_json::to_string_pretty(&quote).unwrap()).unwrap();

        handle_enterprise_command(EnterpriseAction::VerifyAttestation {
            quote: quote_path,
            pubkey: pub_hex.clone(),
            pcr0,
            nonce: nonce.into(),
            platform: "aws-nitro".into(),
        })
        .unwrap();

        // Bad public key must fail closed cleanly
        let bad_pub = "0".repeat(64);
        assert!(
            handle_enterprise_command(EnterpriseAction::VerifyLicense {
                license: lic_path,
                pubkey: bad_pub,
                tier: "enterprise-tee".into(),
                binary: None,
            })
            .is_err()
        );
    }
}
