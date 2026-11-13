use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use vf_core::{StateStore, VeriForgeConfig, scan_repository};
use vf_graph::analyze_codebase;
use vf_report::{to_html_graph, to_sarif_json};
use vf_sandbox::{VerificationStatus, VerifiedFinding, verify_findings_in_sandbox};
use vf_tui::run_tui;

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
    /// Scan a repository using Tree-sitter AST & Guard-Set Lattice (with optional sandbox, SARIF, HTML & CI gate)
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
        ci: bool,
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
    },
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
            ci,
        } => {
            let t0 = Instant::now();
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _) = store.sync_files(&summary.files)?;
            let graph_res = analyze_codebase(&summary.files, &cfg)?;

            let effective_boot = boot_cmd.or_else(|| cfg.sandbox.boot_cmd.clone());
            let sandbox_res = if let Some(cmd) = effective_boot {
                if !graph_res.findings.is_empty() {
                    Some(verify_findings_in_sandbox(
                        &path,
                        &cmd,
                        port,
                        &graph_res.findings,
                        sync_race,
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

            if let Some(sarif_path) = sarif {
                if let Some(parent) = sarif_path.parent()
                    && !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                fs::write(&sarif_path, to_sarif_json(&graph_res.findings, &verified_list))?;
            }
            if let Some(html_path) = html {
                if let Some(parent) = html_path.parent()
                    && !parent.as_os_str().is_empty() {
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
                    "VeriForge Scan | {} files ({} symbols, {} edges, {} routes) | {}ms",
                    graph_res.parsed_files,
                    graph_res.symbol_count,
                    graph_res.edge_count,
                    graph_res.route_entries,
                    total_ms
                );
                if graph_res.findings.is_empty() {
                    println!("  [OK] No unguarded entry-to-sink paths detected.");
                } else {
                    println!(
                        "  [!] {} unguarded multi-file flow(s) detected:",
                        graph_res.findings.len()
                    );
                    for f in &graph_res.findings {
                        println!("\n  [{}] {} ({}) -> {}", f.severity, f.id, f.rule_id, f.title);
                        println!("      Entry: {}", f.entry_route);
                        for (i, hop) in f.witness_path.iter().enumerate() {
                            println!("      [{}] {}:{}  {}", i + 1, hop.file, hop.line, hop.symbol);
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
                        println!("  [{}] {} ({}) -> {}", tag, v.finding_id, v.rule_id, v.evidence);
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
        Commands::Ui {
            path,
            boot_cmd,
            port,
            sync_race,
        } => {
            let t0 = Instant::now();
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let _ = store.sync_files(&summary.files)?;
            let graph_res = analyze_codebase(&summary.files, &cfg)?;
            let effective_boot = boot_cmd.or_else(|| cfg.sandbox.boot_cmd.clone());
            let verified_list = if let Some(cmd) = effective_boot {
                if !graph_res.findings.is_empty() {
                    verify_findings_in_sandbox(&path, &cmd, port, &graph_res.findings, sync_race)?.1
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            let total_ms = t0.elapsed().as_millis();
            run_tui(&path, &graph_res, &verified_list, total_ms)?;
        }
    }

    Ok(ExitCode::SUCCESS)
}
