use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vf_core::{StateStore, VeriForgeConfig, scan_repository};

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
    /// Scan a repository for multi-file business-logic & security flaws (Phase 1+2)
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
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
        Commands::Scan { path, json } => {
            let cfg = VeriForgeConfig::load_from_dir(&path)?;
            let summary = scan_repository(&path, &cfg)?;
            let mut store = StateStore::open(&path)?;
            let (delta, _) = store.sync_files(&summary.files)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "phase": "phase-0-core-indexed",
                        "source_files": summary.source_files_hashed,
                        "elapsed_ms": summary.elapsed_ms,
                        "delta": delta,
                        "modules": [
                            vf_graph::graph_engine_ready(),
                            vf_sandbox::sandbox_engine_ready(),
                            vf_tui::tui_ready(),
                            vf_report::report_ready(),
                            vf_ai::ai_patcher_ready(),
                        ]
                    }))?
                );
            } else {
                println!(
                    "Indexed {} source files in {}ms (+{} modified, {} cached).",
                    summary.source_files_hashed,
                    summary.elapsed_ms,
                    delta.added_or_modified,
                    delta.unchanged_cached
                );
                println!("Next: Phase 1 (vf-graph Tree-sitter + Guard-Set Lattice) will attach to this index.");
            }
        }
    }

    Ok(())
}
