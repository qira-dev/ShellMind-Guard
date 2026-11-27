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

#[cfg(feature = "enterprise")]
pub(crate) fn handle_enterprise_command(action: EnterpriseAction) -> Result<()> {
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
            let cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, false)?;
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
pub(crate) fn handle_enterprise_command(action: EnterpriseAction) -> Result<()> {
    let _ = action;
    anyhow::bail!(
        "This binary was built without `--features enterprise`. Recompile with `--features enterprise`."
    );
}

pub(crate) struct UiLaunchArgs {
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

pub(crate) fn launch_tui_dashboard(args: UiLaunchArgs) -> Result<()> {
    let t0 = Instant::now();
    let cfg = ShellMindGuardConfig::load_trusted_from_dir(&args.path, args.trust_repo_config)?;
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
    let hook_layers = args.layers.clone();
    let hook_min_conf = args.min_confidence;
    let hook_port = effective_port;
    let hook_sync_race = args.sync_race;
    let hook_unsafe_host = args.unsafe_host_fallback;
    let hook_trust = args.trust_repo_config;
    let hook_deep = args.deep;
    let hook_mem = args.sandbox_mem_mb;
    let hook_tls = args.sandbox_tls;
    let hook_shims = args.mock_shims;
    let hook_cg = args.cgroup_v2;
    let rescan_hook: smg_tui::TuiRescanHook = std::sync::Arc::new(move |root: &Path| {
        execute_scan_pipeline(ScanRunOptions {
            path: root,
            layers: &hook_layers,
            min_confidence: hook_min_conf,
            boot_cmd: None,
            port: hook_port,
            sync_race: hook_sync_race,
            unsafe_host_fallback: hook_unsafe_host,
            trust_repo_config: hook_trust,
            deep: hook_deep,
            deep_audit: false,
            sandbox_mem_mb: hook_mem,
            sandbox_tls: hook_tls,
            mock_shims: hook_shims,
            cgroup_v2: hook_cg,
        })
        .map(|o| o.graph)
    });
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
            rescan_hook: Some(rescan_hook),
        },
    )
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
            let cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, false)?;
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
                profile_phases,
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
            PROFILE_PHASES_FLAG.store(profile_phases, std::sync::atomic::Ordering::Relaxed);
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
                let smg_cfg =
                    ShellMindGuardConfig::load_trusted_from_dir(&path, trust_repo_config)?;
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
                trust_repo_config,
                &mut outcome,
            )?;
            if let Some(trivy_ignore) = oci_image::TrivyIgnore::load(&path) {
                if trust_repo_config {
                    outcome.graph.findings.retain(|f| {
                        !(f.rule_id.starts_with("SMG-DEP-")
                            && (trivy_ignore.is_ignored(&f.title)
                                || trivy_ignore.is_ignored(&f.rule_id)))
                    });
                } else if !trivy_ignore.ignored_ids.is_empty() {
                    eprintln!(
                        "[!] Ignoring {} repo `.trivyignore` waiver(s) without --trust-repo-config.",
                        trivy_ignore.ignored_ids.len()
                    );
                }
            }
            if let Some(ref vex_out) = openvex {
                let vex_cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, trust_repo_config)
                    .unwrap_or_default();
                let vex_summaries: Vec<smg_graph::FileAstSummary> =
                    scan_repository(&path, &vex_cfg)
                        .map(|s| {
                            s.files
                                .iter()
                                .filter_map(|f| smg_graph::parse_file_ast(f, &vex_cfg))
                                .collect()
                        })
                        .unwrap_or_default();
                let pkg_index = smg_graph::deps::build_package_import_index(&vex_summaries);
                let auto_vex = smg_graph::AutoVexSymbolIndex::default();
                let route_reachable: std::collections::HashSet<String> = vex_summaries
                    .iter()
                    .flat_map(|s| s.symbols.iter())
                    .filter(|sym| sym.kind == smg_graph::ast::SymbolKind::Route)
                    .map(|sym| sym.id.clone())
                    .collect();

                let stmts: Vec<smg_graph::OpenVexStatement> =
                    outcome
                        .graph
                        .findings
                        .iter()
                        .map(|f| {
                            if let (_, Some(stmt)) =
                                smg_graph::assess_dependency_vex_tier_with_auto_vex(
                                    f,
                                    &pkg_index,
                                    &route_reachable,
                                    Some(&auto_vex),
                                )
                            {
                                return stmt;
                            }
                            let (status, justification) =
                                if f.proof_reasons.iter().any(|r| r == "DeclaredUnusedVEX") {
                                    ("not_affected", Some("component_not_present".to_string()))
                                } else if f
                                    .proof_reasons
                                    .iter()
                                    .any(|r| r == "ImportedSafeApiOnlyVEX")
                                {
                                    (
                                        "not_affected",
                                        Some("vulnerable_code_not_in_execute_path".to_string()),
                                    )
                                } else {
                                    ("affected", None)
                                };
                            smg_graph::OpenVexStatement {
                                vulnerability_id: f.rule_id.clone(),
                                product_purl: format!("pkg:generic/{}@local", f.file),
                                status: status.into(),
                                justification,
                                impact_statement: f.title.clone(),
                            }
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
                let cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, false)?;
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
                let init_cfg =
                    ShellMindGuardConfig::load_trusted_from_dir(&path, trust_repo_config)?;
                let mut prev_sig = smg_core::scan_repository_metadata_signature(&path, &init_cfg)?;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    let cfg =
                        match ShellMindGuardConfig::load_trusted_from_dir(&path, trust_repo_config)
                        {
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
            let cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, trust_repo_config)?;
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
                ShellMindGuardConfig::load_trusted_from_dir(&path, false)
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
        Commands::Mcp {
            allow_write,
            print_config,
        } => {
            if let Some(client) = print_config {
                println!("{}", mcp::render_mcp_client_config(&client)?);
            } else {
                mcp::run_stdio_server_with_options(allow_write)?;
            }
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
                    if !upgraded {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "host": host,
                                    "port": port,
                                    "starttls_protocol": proto_str,
                                    "starttls_upgraded": false,
                                })
                            );
                        } else {
                            println!(
                                "ShellMind Guard STARTTLS | {}:{} ({}) | Upgraded: false",
                                host, port, proto_str
                            );
                        }
                        return Ok(ExitCode::from(1));
                    }
                    let report =
                        tls_audit::audit_upgraded_starttls_stream(&target, &host, port, stream)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "host": host,
                                "port": port,
                                "starttls_protocol": proto_str,
                                "starttls_upgraded": true,
                                "tls_report": report,
                            })
                        );
                    } else {
                        println!(
                            "ShellMind Guard STARTTLS | {}:{} ({}) | Upgraded: true | Protocols: [{}] | CertChain: {} | Findings: {}",
                            host,
                            port,
                            proto_str,
                            report.protocols_supported.join(", "),
                            report.cert_chain_len,
                            report.findings.len()
                        );
                        if let Some(ref c13) = report.negotiated_tls13_cipher {
                            println!("  TLS 1.3 Cipher: {c13}");
                        }
                        if let Some(ref c12) = report.negotiated_tls12_cipher {
                            println!("  TLS 1.2 Cipher: {c12}");
                        }
                        for f in &report.findings {
                            println!("  [{}] {} — {}", f.severity, f.id, f.title);
                        }
                    }
                    return Ok(if report.findings.is_empty() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    });
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
        #[cfg(not(feature = "enterprise"))]
        Commands::VerifyAttestation { .. } => {
            anyhow::bail!(
                "Attestation verification requires the `enterprise` feature (rebuild with `--features enterprise`)"
            );
        }
        #[cfg(feature = "enterprise")]
        Commands::VerifyAttestation {
            platform,
            input,
            expected_measurement,
            min_svn,
            json,
        } => {
            let raw = {
                use std::io::Read;
                let f = fs::File::open(&input).with_context(|| {
                    format!("Failed to read attestation file {}", input.display())
                })?;
                let mut buf = Vec::new();
                f.take(2 * 1024 * 1024).read_to_end(&mut buf)?;
                buf
            };
            let mut audit_log = smg_enterprise::MerkleAuditLog::new();
            audit_log.append(&raw);
            let merkle_root = audit_log.root_hex().unwrap_or_default();
            let plat = platform.trim().to_ascii_lowercase();
            let verdict = match plat.as_str() {
                "tdx" => smg_enterprise::verify_tdx_quote_v4(&raw, expected_measurement.as_deref())
                    .map(|s| {
                        serde_json::json!({
                            "platform": "tdx",
                            "verified": false,
                            "cryptographically_verified": s.cryptographically_verified,
                            "structural_valid": true,
                            "reason": "Structural TDX v4 header/MRTD check passed; Intel DCAP PCK signature/TCB verification is not yet enabled (fail-closed)",
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
                        "verified": false,
                        "cryptographically_verified": s.cryptographically_verified,
                        "structural_valid": true,
                        "reason": "Structural SEV-SNP header/policy check passed; AMD VCEK signature verification is not yet enabled (fail-closed)",
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
                            "verified": false,
                            "cryptographically_verified": false,
                            "structural_valid": true,
                            "expected_measurement_checked": false,
                            "reason": "Structural CBOR COSE_Sign1 framing only; AWS Nitro Root CA / PCR cryptographic verification is not yet enabled (fail-closed)",
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
                    let crypto_ok = v
                        .get("cryptographically_verified")
                        .and_then(|b| b.as_bool())
                        .unwrap_or(false);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        let status_label = if crypto_ok {
                            "VERIFIED"
                        } else {
                            "UNVERIFIED (STRUCTURAL ONLY — FAIL-CLOSED)"
                        };
                        println!(
                            "ShellMind Guard Attestation | Platform: {} | Status: {} | MerkleRoot: {}",
                            plat, status_label, merkle_root
                        );
                    }
                    if !crypto_ok {
                        return Ok(ExitCode::from(1));
                    }
                }
                Err(err) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "platform": plat,
                                "verified": false,
                                "cryptographically_verified": false,
                                "structural_valid": false,
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
            allow_mutations,
            json,
        } => {
            let report =
                idor_audit::run_idor_audit_with_options(&config, allow_remote, allow_mutations)?;
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
            oob_server,
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
                    oob_server,
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
            test_headers,
            test_cookies,
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
                test_headers,
                test_cookies,
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
            cookie,
            auth_header,
            spa,
            allow_remote,
            json,
        } => {
            let mut headers: HashMap<String, String> = header
                .iter()
                .filter_map(|h| h.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            if let Some(c) = cookie
                && !c.trim().is_empty()
            {
                headers.insert("Cookie".into(), c.trim().to_string());
            }
            if let Some(a) = auth_header
                && !a.trim().is_empty()
            {
                headers.insert("Authorization".into(), a.trim().to_string());
            }
            let report = dast_audit::run_dast_audit(&dast_audit::DastConfig {
                seed_url: url.clone(),
                headers,
                max_pages,
                max_depth,
                active: !passive_only,
                spa,
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
            mitm_ca,
            action,
        } => {
            // `smg proxy export-ca` never starts the listener.
            if let Some(ProxyAction::ExportCa { out }) = action {
                proxy_mitm::export_ca(out.as_deref())?;
                return Ok(ExitCode::SUCCESS);
            }
            let bind_addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("Invalid --listen address '{listen}'"))?;
            let mitm = if mitm_ca {
                let ca_dir = proxy_mitm::default_ca_dir()?;
                let ca = proxy_mitm::MitmCa::load_or_create(&ca_dir)?;
                println!(
                    "  MITM CA: {} (import into your browser via `smg proxy export-ca` to avoid TLS warnings)",
                    ca.cert_pem_path.display()
                );
                Some(Arc::new(ca))
            } else {
                None
            };
            let handle = proxy::start_proxy(proxy::ProxyConfig {
                bind_addr,
                capture_limit: proxy::DEFAULT_CAPTURE_LIMIT,
                allow_remote_bind,
                jsonl_log: log,
                mitm,
            })?;
            let bind = handle.bound_addr;
            if mitm_ca {
                println!(
                    "ShellMind Guard Proxy | listening on http://{bind} (HTTP intercepted · HTTPS CONNECT decrypted via local CA)"
                );
            } else {
                println!(
                    "ShellMind Guard Proxy | listening on http://{bind} (HTTP intercepted · HTTPS CONNECT logged & tunneled transparently)"
                );
            }
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
        Commands::Oob { action } => match action {
            OobAction::Serve { listen, log } => {
                let addr: SocketAddr = listen
                    .parse()
                    .with_context(|| format!("Invalid --listen address '{listen}'"))?;
                let handle = oob_server::start_oob_server(addr, log)?;
                println!(
                    "ShellMind Guard OOB | TCP {} + UDP {} (HTTP catch-all + raw datagrams; hit store capped at 100k)",
                    handle.bound_addr, handle.udp_addr
                );
                println!(
                    "  Point templates at it: smg templates <target> --templates DIR --oob-server {}",
                    handle.bound_addr
                );
                println!("  Ctrl+C (SIGINT) stops the listener.");
                handle.wait_for_stop();
                println!("  Stopped.");
            }
        },
        Commands::HttpAudit {
            url,
            header,
            schema,
            graphql,
            spa,
            passive_only,
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
                spa,
                discover_schemas: !passive_only,
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
                    let cfg = ShellMindGuardConfig::load_trusted_from_dir(&path, false)?;
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
