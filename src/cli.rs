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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Compact,
    Table,
    Markdown,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AnsiPalette {
    pub(crate) enabled: bool,
}

impl AnsiPalette {
    pub(crate) fn resolve(mode: ColorMode, stream_is_tty: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let enabled = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => !no_color && stream_is_tty,
        };
        Self { enabled }
    }

    pub(crate) fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub(crate) fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }

    pub(crate) fn dim(&self, text: &str) -> String {
        self.wrap("2;37", text)
    }

    pub(crate) fn red(&self, text: &str) -> String {
        self.wrap("1;31", text)
    }

    pub(crate) fn amber(&self, text: &str) -> String {
        self.wrap("1;33", text)
    }

    pub(crate) fn green(&self, text: &str) -> String {
        self.wrap("1;32", text)
    }

    pub(crate) fn cyan(&self, text: &str) -> String {
        self.wrap("1;36", text)
    }

    pub(crate) fn purple(&self, text: &str) -> String {
        self.wrap("1;35", text)
    }

    pub(crate) fn coral(&self, text: &str) -> String {
        self.wrap("38;5;209", text)
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum ProbeMode {
    #[default]
    Verify,
    #[value(name = "verify-batch")]
    VerifyBatch,
    Fuzz,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MinConfidenceArg {
    Proven,
    Confirmed,
    Heuristic,
}

impl MinConfidenceArg {
    pub(crate) fn to_confidence(self) -> Confidence {
        match self {
            MinConfidenceArg::Proven => Confidence::Proven,
            MinConfidenceArg::Confirmed => Confidence::Confirmed,
            MinConfidenceArg::Heuristic => Confidence::Heuristic,
        }
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum ProxyAction {
    /// Print (or copy) the local MITM CA certificate for browser/system trust import
    ExportCa {
        #[arg(
            long,
            value_name = "FILE",
            help = "Write the CA certificate PEM to this file instead of stdout"
        )]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum OobAction {
    /// Start the self-hosted OOB callback listener (TCP HTTP catch-all + UDP datagrams)
    Serve {
        #[arg(
            long,
            default_value = crate::oob_server::DEFAULT_OOB_LISTEN,
            value_name = "ADDR",
            help = "Loopback address for both the TCP and UDP callback listeners"
        )]
        listen: String,
        #[arg(
            long,
            value_name = "FILE",
            help = "Append every callback hit as JSONL to this file"
        )]
        log: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum HookAction {
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
pub(crate) enum DepsAction {
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
pub(crate) enum EnterpriseAction {
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

#[derive(Parser, Debug)]
#[command(
    name = "smg",
    version,
    about = "ShellMind Guard (smg) — Zero-false-positive multi-file business-logic & security verifier"
)]
pub(crate) struct Cli {
    /// Control colored terminal output (auto, always, never)
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub(crate) color: ColorMode,
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ScanCmdArgs {
    #[arg(default_value = ".")]
    pub(crate) path: PathBuf,
    #[arg(long, help = "Shorthand for --format json")]
    pub(crate) json: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write formatted scan output to FILE instead of stdout (disables ANSI colors)"
    )]
    pub(crate) output: Option<PathBuf>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Filter active layers (auth,race,concurrency,taint,sqli,cmdi,path,ssrf,xss,csrf,idor,secrets,config,deps,frontend,cicd,k8s,dos,zip,crypto,queue,api,ai,oauth,smuggle,state,engine,memory,mobile,hw,web3,pqc,deep)"
    )]
    pub(crate) layers: Vec<String>,
    #[arg(
        long,
        value_name = "POLICY",
        help = "Enable opt-in compliance analyzers (e.g. `pqc` for NIST PQC bit reduction & Mosca HNDL urgency)"
    )]
    pub(crate) compliance: Option<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write CycloneDX 1.5 Static Source & Config Cryptography Inventory (CBOM JSON) to FILE"
    )]
    pub(crate) cbom: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write OpenVEX v0.2.0 vulnerability exploitability JSON document to FILE"
    )]
    pub(crate) openvex: Option<PathBuf>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Suppress findings matching specific rule IDs (e.g. SMG-CFG-CORS,SMG-MOB-TLS)"
    )]
    pub(crate) exclude_rule: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Suppress findings already recorded in a baseline JSON snapshot"
    )]
    pub(crate) baseline: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write current unmitigated findings snapshot JSON to FILE as baseline"
    )]
    pub(crate) write_baseline: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        help = "Hide findings below this confidence tier (proven, confirmed, heuristic)"
    )]
    pub(crate) min_confidence: Option<MinConfidenceArg>,
    #[arg(
        long,
        help = "Enable Phase 10 deep schema validation (SMG-FUZZ-SCHEMA) & targeted route payload fuzzing"
    )]
    pub(crate) deep: bool,
    #[arg(
        long,
        help = "Enable Phase 15 Tier-2 deep audit budget (unlocks 2048-block CFG, 64 CHA targets, 256 witness hops)"
    )]
    pub(crate) deep_audit: bool,
    #[arg(
        long,
        help = "Print per-phase wall-clock timing telemetry to stderr (or set SMG_PROFILE_PHASES=1)"
    )]
    pub(crate) profile_phases: bool,
    #[arg(long)]
    pub(crate) boot_cmd: Option<String>,
    #[arg(long, default_value_t = 39911)]
    pub(crate) port: u16,
    #[arg(long, default_value_t = 12)]
    pub(crate) sync_race: usize,
    #[arg(
        long,
        value_name = "MB",
        help = "Optional RLIMIT_AS / cgroups v2 memory limit (MiB) inside sandbox"
    )]
    pub(crate) sandbox_mem_mb: Option<u64>,
    #[arg(
        long,
        help = "Probe sandbox target over local loopback TLS using rustls"
    )]
    pub(crate) sandbox_tls: bool,
    #[arg(
        long,
        help = "Start deterministic loopback mock shims (/v1/charges, /oauth/token, /webhooks) inside sandbox"
    )]
    pub(crate) mock_shims: bool,
    #[arg(
        long,
        help = "Enforce systemd-run user cgroups v2 memory/task limits when available"
    )]
    pub(crate) cgroup_v2: bool,
    #[arg(long)]
    pub(crate) sarif: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write CycloneDX 1.5 SBOM + VEX report (with BLAKE3 attestation digest) to FILE"
    )]
    pub(crate) cyclonedx: Option<PathBuf>,
    #[arg(
        long,
        value_name = "DIR",
        help = "Generate self-contained regression test suite into DIR for active findings"
    )]
    pub(crate) export_test: Option<PathBuf>,
    #[arg(
        long,
        value_name = "GIT_REF",
        help = "Scan only files changed since GIT_REF plus reverse-caller/callee subgraph (auto-falls back on lockfile/middleware edits)"
    )]
    pub(crate) changed_since: Option<String>,
    #[arg(
        long,
        help = "Include generated stub files (*.pb.go, *.min.js, etc.) usually skipped by default"
    )]
    pub(crate) include_generated: bool,
    #[arg(
        long,
        help = "Include test, mock, and harness directories (useful for security benchmark repos like DeFiVulnLabs)"
    )]
    pub(crate) include_tests: bool,
    #[arg(
        long,
        help = "Scan full git commit history for deleted or historical leaked secrets (Gitleaks git parity)"
    )]
    pub(crate) git_history: bool,
    #[arg(
        long,
        value_name = "N",
        help = "Limit --git-history scan to the latest N commits (0 = full history)"
    )]
    pub(crate) git_depth: Option<usize>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Explicit path to a .gitleaks.toml allowlist/rules policy file (auto-detected at repo root if omitted)"
    )]
    pub(crate) gitleaks_config: Option<PathBuf>,
    #[arg(
        long,
        help = "Opt-in live read-only verification of detected credentials against provider APIs (TruffleHog parity; OFF by default)"
    )]
    pub(crate) verify_live: bool,
    #[arg(
        long,
        help = "When combined with --verify-live, keep only confirmed-live secrets (mirrors trufflehog --only-verified)"
    )]
    pub(crate) only_verified: bool,
    #[arg(
        long,
        help = "Opt-in live OSV.dev advisory sync before scanning dependencies (OSV-Scanner live parity; OFF by default)"
    )]
    pub(crate) online_osv: bool,
    #[arg(long)]
    pub(crate) html: Option<PathBuf>,
    #[arg(long)]
    pub(crate) patch: bool,
    /// Allow unsafe host execution if `/usr/bin/bwrap` is unavailable
    #[arg(long)]
    pub(crate) unsafe_host_fallback: bool,
    /// Trust `sandbox.boot_cmd` defined in the scanned repo's `.shellmind-guard.toml`
    #[arg(long)]
    pub(crate) trust_repo_config: bool,
    #[arg(long)]
    pub(crate) ci: bool,
    #[arg(
        long,
        value_enum,
        help = "Exit non-zero if any unmitigated finding meets this severity"
    )]
    pub(crate) fail_on: Option<FailSeverity>,
    #[arg(
        long,
        help = "Continuously watch repository and re-scan on file changes"
    )]
    pub(crate) watch: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
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
            help = "Filter rules by layer (auth, race, idor, sqli, cmdi, path, ssrf, xss, csrf, secrets, config, deps, frontend, engine, memory, mobile, deep, cicd, k8s, dos, zip, crypto, queue, api, ai, oauth, smuggle, state, hw, web3, pqc, dast)"
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
    /// Start stdio JSON-RPC 2.0 MCP server (Read-Only by default; pass --allow-write for init or --print-config <client>)
    Mcp {
        /// Explicitly allow write tool (`shellmind_guard_init`) over MCP (default: strictly read-only)
        #[arg(long, default_value_t = false)]
        allow_write: bool,
        /// Print copy-paste read-only MCP config snippet for a client (`claude`, `cursor`, `windsurf`, `antigravity`)
        #[arg(long, value_name = "CLIENT")]
        print_config: Option<String>,
    },
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
        #[arg(
            long,
            help = "Allow POST/PUT/PATCH/DELETE IDOR/BOLA regression checks (strictly restricted to localhost/loopback)"
        )]
        allow_mutations: bool,
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
            value_name = "HOST:PORT",
            help = "Self-hosted OOB callback listener (see `smg oob serve`): enables interactsh-style templates with per-run tokens"
        )]
        oob_server: Option<String>,
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
            value_delimiter = ',',
            value_name = "NAMES",
            help = "Also test request headers as injection surfaces ('auto' = User-Agent,X-Forwarded-For,Referer)"
        )]
        test_headers: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            value_name = "NAMES",
            help = "Also test cookie names (from the Cookie header) as injection surfaces"
        )]
        test_cookies: Vec<String>,
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
            value_name = "COOKIES",
            help = "Cookie header for authenticated crawling, e.g. 'session=abc; csrf=xyz'"
        )]
        cookie: Option<String>,
        #[arg(
            long,
            value_name = "VALUE",
            help = "Authorization header value for authenticated crawling, e.g. 'Bearer <token>'"
        )]
        auth_header: Option<String>,
        #[arg(
            long,
            help = "Render pages in headless Chrome (SPA crawl): client-side routes, XHR/Fetch endpoints, DOM source-to-sink flows"
        )]
        spa: bool,
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
        #[arg(
            long,
            help = "Terminate TLS on CONNECT tunnels with an on-the-fly local CA (~/.config/smg/ca-cert.pem); decrypted HTTPS traffic becomes captured/replayable like HTTP"
        )]
        mitm_ca: bool,
        #[command(subcommand)]
        action: Option<ProxyAction>,
    },
    /// Self-hosted OOB callback listener for interactsh-style templates
    Oob {
        #[command(subcommand)]
        action: OobAction,
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
        #[arg(
            long,
            help = "Render the target in headless Chrome: DOM source-to-sink flows + XHR/Fetch endpoints"
        )]
        spa: bool,
        #[arg(
            long,
            help = "Perform strictly a single passive GET without OpenAPI/GraphQL discovery probes"
        )]
        passive_only: bool,
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
