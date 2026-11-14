use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use vf_ai::build_minimal_patch_prompt;
use vf_core::{StateStore, VeriForgeConfig, scan_repository};
use vf_graph::{LatticeFinding, analyze_codebase_cached};
use vf_report::{to_html_graph, to_sarif_json};
use vf_sandbox::{
    VerificationStatus, VerifiedFinding, verify_finding_blocking, verify_findings_in_sandbox,
};
use vf_tui::{TuiLaunchConfig, run_tui};

#[derive(Parser, Debug)]
#[command(
    name = "veriforge",
    version,
    about = "Zero-false-positive multi-file business-logic & AI-code security verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Index a repository using parallel ignore walker, BLAKE3 hashing, and SQLite WAL delta cache
    Index {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Scan a repository using Two-Phase AST cache & Guard-Set Lattice (with optional sandbox, SARIF, HTML, patch & CI gate)
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        boot_cmd: Option<String>,
        #[arg(long, default_value_t = 39911)]
        port: u16,
        #[arg(long, default_value_t = 10)]
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
        #[arg(long, default_value_t = 10)]
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
        #[arg(long, default_value_t = 10)]
        sync_race: usize,
        #[arg(long)]
        unsafe_host_fallback: bool,
    },
    /// Internal probe executed inside `--unshare-net` Bubblewrap namespace
    #[command(name = "__probe-netns", hide = true)]
    ProbeNetns {
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 10)]
        sync_race: usize,
    },
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
            .unwrap_or_else(|| format!("veriforge replay {}", f.id));
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
    cfg: &VeriForgeConfig,
    store: &mut StateStore,
) -> Result<LatticeFinding> {
    // B20: Always re-evaluate against current repository files so renamed/patched routes are never stale!
    let summary = scan_repository(path, cfg)?;
    let _ = store.sync_files(&summary.files)?;
    let graph_res = analyze_codebase_cached(&summary.files, cfg, store)?;
    graph_res
        .findings
        .into_iter()
        .find(|f| f.id.eq_ignore_ascii_case(finding_id))
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
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Index { path, json } => {
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
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
                    "VeriForge Index | {} source files ({} total entries) | {}ms | delta: +{} modified / {} cached / {} removed",
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
            boot_cmd,
            port,
            sync_race,
            sarif,
            html,
            patch,
            unsafe_host_fallback,
            ci,
        } => {
            let t0 = Instant::now();
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _) = store.sync_files(&summary.files)?;
            let graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;

            let effective_boot = boot_cmd.or_else(|| cfg.sandbox.boot_cmd.clone());
            let sandbox_res = if let Some(cmd) = effective_boot {
                if !graph_res.findings.is_empty() {
                    Some(verify_findings_in_sandbox(
                        &path,
                        &cmd,
                        port,
                        &graph_res.findings,
                        sync_race,
                        unsafe_host_fallback,
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

            persist_scan_findings(
                &mut store,
                delta.scan_id,
                &graph_res.findings,
                &verified_list,
            )?;

            if let Some(sarif_path) = sarif {
                if let Some(parent) = sarif_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(
                    &sarif_path,
                    to_sarif_json(&graph_res.findings, &verified_list),
                )?;
            }
            if let Some(html_path) = html {
                if let Some(parent) = html_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(
                    &html_path,
                    to_html_graph(&path.display().to_string(), &graph_res, &verified_list),
                )?;
            }

            let total_ms = t0.elapsed().as_millis();

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "elapsed_ms": total_ms,
                        "delta": delta,
                        "graph": graph_res,
                        "sandbox_verification": sandbox_res.as_ref().map(|(bwrap, res)| serde_json::json!({
                            "bwrap_isolated": bwrap,
                            "results": res,
                        })),
                    }))?
                );
            } else {
                println!(
                    "VeriForge Scan | {} files ({} symbols, {} edges, {} routes) | {}ms (delta: +{} / {} cached)",
                    graph_res.parsed_files,
                    graph_res.symbol_count,
                    graph_res.edge_count,
                    graph_res.route_entries,
                    total_ms,
                    delta.added_or_modified,
                    delta.unchanged_cached
                );
                if graph_res.findings.is_empty() {
                    println!("  [OK] No unguarded entry-to-sink paths detected.");
                } else {
                    println!(
                        "  [!] {} unguarded multi-file flow(s) detected:",
                        graph_res.findings.len()
                    );
                    for f in &graph_res.findings {
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
                    }
                }

                if let Some((bwrap, verified)) = &sandbox_res {
                    println!(
                        "\nVeriForge Sandbox Proof (bwrap={}):",
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
                    for f in &graph_res.findings {
                        let v_opt = verified_list.iter().find(|v| v.finding_id == f.id);
                        if let Ok(p) = build_minimal_patch_prompt(&path, f, v_opt) {
                            println!("\n=== Minimal Patch Context ({} bytes) ===", p.len());
                            println!("{}", p);
                        }
                    }
                }
            }

            if ci
                && verified_list
                    .iter()
                    .any(|v| v.status == VerificationStatus::Proven)
            {
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
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
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
                "VeriForge Replay | {} ({}) | bwrap={}",
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
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
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
        Commands::ProbeNetns { port, sync_race } => {
            let finding_json = std::env::var("VF_FINDING_JSON")?;
            let finding: LatticeFinding = serde_json::from_str(&finding_json)?;
            let res = verify_finding_blocking(port, &finding, sync_race)?;
            println!("{}", serde_json::to_string(&res)?);
        }
    }

    Ok(ExitCode::SUCCESS)
}
