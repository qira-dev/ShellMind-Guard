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

pub(crate) fn build_probe_config(
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

pub(crate) fn probe_config_from_opts(
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

pub(crate) fn apply_verification_statuses(
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

pub(crate) fn resolve_sandbox_port(cli_port: u16, cfg: &ShellMindGuardConfig) -> Result<u16> {
    if cli_port != 39911 {
        Ok(cli_port)
    } else {
        Ok(cfg.sandbox.loopback_port()?.unwrap_or(cli_port))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_phase21_secrets_extensions(
    repo_root: &Path,
    layers: &[String],
    include_tests: bool,
    run_git_history: bool,
    git_depth: Option<usize>,
    gitleaks_config_path: Option<&Path>,
    verify_live: bool,
    only_verified: bool,
    trust_repo_config: bool,
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

    // 1. Honor `.gitleaks.toml` allowlists on working-tree secret findings ONLY when trusted
    if secrets_layer_active {
        if !trust_repo_config
            && gitleaks_cfg
                .as_ref()
                .is_some_and(|c| !c.allowlists.is_empty() || !c.ignored_fingerprints.is_empty())
        {
            eprintln!(
                "[!] Ignoring repo `.gitleaks.toml` allowlists / `.gitleaksignore` waivers without --trust-repo-config."
            );
        }
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
            if trust_repo_config && let Some(cfg) = gitleaks_cfg.as_ref() {
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
            let smg_cfg =
                ShellMindGuardConfig::load_trusted_from_dir(repo_root, trust_repo_config)?;
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

pub(crate) static PROFILE_PHASES_FLAG: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn execute_scan_pipeline_full(
    opts: ScanRunOptions<'_>,
    changed_since: Option<&str>,
    include_generated: bool,
    pqc_compliance: bool,
    cbom_path: Option<&Path>,
) -> Result<ScanOutcome> {
    let profile_phases = PROFILE_PHASES_FLAG.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var_os("SMG_PROFILE_PHASES").is_some();
    let t0 = Instant::now();
    let mut cfg = ShellMindGuardConfig::load_trusted_from_dir(opts.path, opts.trust_repo_config)?;
    if opts.deep_audit {
        cfg.scan.deep_audit = true;
    }
    let t_walk = Instant::now();
    let summary =
        scan_repository_with_options(opts.path, &cfg, &ScanOptions { include_generated })?;
    let walk_ms = t_walk.elapsed().as_millis();

    let t_sync = Instant::now();
    let mut store = StateStore::open(opts.path)?;
    let (delta, _) = store.sync_files(&summary.files)?;
    let sync_ms = t_sync.elapsed().as_millis();

    let t_graph = Instant::now();
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
    let graph_ms = t_graph.elapsed().as_millis();

    if opts.deep {
        graph_res
            .findings
            .extend(collect_deep_schema_findings(&graph_res));
    }
    #[cfg(feature = "hw")]
    let hw_ms: u128 = {
        let t_hw = Instant::now();
        let force_hw = opts.layers.iter().any(|l| {
            matches!(
                l.trim().to_ascii_lowercase().as_str(),
                "hw" | "hardware" | "firmware" | "embedded"
            )
        });
        let hw_hits = smg_hw::scan_hardware_repo_with_threads(
            opts.path,
            &summary.files,
            force_hw,
            cfg.scan.max_threads.max(1),
        );
        smg_graph::append_local_static_findings(&mut graph_res.findings, &hw_hits);
        t_hw.elapsed().as_millis()
    };
    #[cfg(not(feature = "hw"))]
    let hw_ms: u128 = 0;
    let t_ai_art = Instant::now();
    {
        let ai_artifact_hits = smg_graph::scan_repo_ai_model_artifacts(opts.path);
        smg_graph::append_local_static_findings(&mut graph_res.findings, &ai_artifact_hits);
    }
    let ai_art_ms = t_ai_art.elapsed().as_millis();
    if let Some(gl_cfg) = smg_graph::GitleaksConfig::load(opts.path, None) {
        if !gl_cfg.custom_rules.is_empty() {
            let mut custom_hits = Vec::new();
            for f in &summary.files {
                if f.size_bytes > 2 * 1024 * 1024 {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&f.abs_path) {
                    for (idx, line) in content.lines().enumerate() {
                        for (hit, _) in
                            gl_cfg.scan_custom_rules_line(&f.rel_path, idx + 1, line, None)
                        {
                            custom_hits.push(hit);
                        }
                    }
                    custom_hits.extend(gl_cfg.scan_multiline_custom_rules(&f.rel_path, &content));
                }
            }
            smg_graph::append_local_static_findings(&mut graph_res.findings, &custom_hits);
        }
        // Honor `.gitleaks.toml` allowlists and `.gitleaksignore` fingerprints on working-tree
        // findings ONLY when `--trust-repo-config` is explicitly enabled.
        if opts.trust_repo_config {
            let mut line_cache: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            graph_res.findings.retain(|f| {
                if !f.rule_id.starts_with("SMG-SEC-") && !f.rule_id.starts_with("SMG-GITLEAKS-") {
                    return true;
                }
                if gl_cfg.is_fingerprint_ignored(None, &f.file, &f.rule_id, f.line) {
                    return false;
                }
                let lines = line_cache.entry(f.file.clone()).or_insert_with(|| {
                    fs::read_to_string(opts.path.join(&f.file))
                        .map(|s| s.lines().map(String::from).collect())
                        .unwrap_or_default()
                });
                let line_txt = f
                    .line
                    .checked_sub(1)
                    .and_then(|i| lines.get(i))
                    .map(String::as_str)
                    .unwrap_or("");
                !gl_cfg.is_allowed(&f.file, None, line_txt, &f.title)
            });
        }
    }
    #[cfg(feature = "web3")]
    let web3_ms: u128 = {
        let t_web3 = Instant::now();
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
        t_web3.elapsed().as_millis()
    };
    #[cfg(not(feature = "web3"))]
    let web3_ms: u128 = 0;
    #[cfg(feature = "pqc")]
    let pqc_ms: u128 = {
        let t_pqc = Instant::now();
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
        t_pqc.elapsed().as_millis()
    };
    #[cfg(not(feature = "pqc"))]
    let pqc_ms: u128 = {
        if pqc_compliance || cbom_path.is_some() {
            anyhow::bail!(
                "This binary was built without `--features pqc`. Recompile with `--features pqc` to use `--compliance pqc` or `--cbom`."
            );
        }
        0
    };
    if profile_phases {
        eprintln!(
            "[SMG-PROFILE] walk={}ms sync={}ms graph={}ms hw={}ms web3={}ms pqc={}ms ai_art={}ms total={}ms",
            walk_ms,
            sync_ms,
            graph_ms,
            hw_ms,
            web3_ms,
            pqc_ms,
            ai_art_ms,
            t0.elapsed().as_millis()
        );
    }
    smg_graph::canonical_sort_findings(&mut graph_res.findings);
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
    let has_dynamic_targets = graph_res
        .findings
        .iter()
        .any(smg_sandbox::is_dynamic_probe_target);

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

pub(crate) fn persist_scan_findings(
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

pub(crate) fn resolve_finding_for_replay(
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

pub(crate) fn verify_patch_apply_check(
    params: &ApplyCheckParams<'_>,
) -> Result<smg_ai::ApplyCheckOutcome> {
    let mut outcome = verify_patch_in_isolated_copy(params)?;
    let rule = params.finding.rule_id.as_str();
    let is_frontier_rule = rule.starts_with("SMG-WEB3-")
        || rule.starts_with("SMG-SOL-")
        || rule.starts_with("SMG-MOVE-")
        || rule.starts_with("SMG-HW-")
        || rule.starts_with("SMG-PQC-")
        || rule.starts_with("SMG-AI-");
    if outcome.mitigated && is_frontier_rule {
        // Re-verify frontier findings via the full multi-domain pipeline (smg-web3, smg-hw,
        // smg-pqc, AI model artifacts) so `--apply-check` never claims MITIGATED merely because
        // core `analyze_codebase` alone does not emit frontier rules.
        struct FrontierCopyGuard(PathBuf);
        impl Drop for FrontierCopyGuard {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let tmp_copy = std::env::temp_dir().join(format!(
            "smg-apply-frontier-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _guard = FrontierCopyGuard(tmp_copy.clone());
        fs::create_dir_all(&tmp_copy)?;
        let summary = scan_repository(params.project_root, params.cfg)?;
        for f in &summary.files {
            let dst = tmp_copy.join(&f.rel_path);
            if let Some(p) = dst.parent() {
                fs::create_dir_all(p)?;
            }
            let _ = fs::copy(&f.abs_path, &dst);
        }
        let _ = smg_ai::apply_unified_diff_safely(&tmp_copy, params.raw_diff)?;
        let full_res = execute_scan_pipeline_full(
            ScanRunOptions {
                path: &tmp_copy,
                layers: &[],
                min_confidence: None,
                boot_cmd: None,
                port: params.port,
                sync_race: params.sync_race,
                unsafe_host_fallback: params.unsafe_host_fallback,
                trust_repo_config: false,
                deep: false,
                deep_audit: params.cfg.scan.deep_audit,
                sandbox_mem_mb: params.probe_cfg.memory_limit_mb,
                sandbox_tls: params.probe_cfg.use_tls,
                mock_shims: params.probe_cfg.mock_shims,
                cgroup_v2: params.probe_cfg.use_cgroup_v2,
            },
            None,
            false,
            rule.starts_with("SMG-PQC-"),
            None,
        )?;
        let still_present = full_res
            .graph
            .findings
            .iter()
            .any(|f| f.rule_id == params.finding.rule_id && f.file == params.finding.file);
        if still_present {
            outcome.mitigated = false;
            outcome.summary = format!(
                "Frontier pipeline still detected `{}` in `{}` after applying candidate patch",
                params.finding.rule_id, params.finding.file
            );
        }
    }
    Ok(outcome)
}
