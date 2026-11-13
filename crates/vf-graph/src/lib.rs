pub mod ast;
pub mod lattice;

use anyhow::Result;
use rayon::prelude::*;
use vf_core::{IndexedFile, VeriForgeConfig};

pub use ast::{FileAstSummary, GuardKind, SinkKind, parse_file_ast};
pub use lattice::{GraphAnalysisResult, LatticeFinding, TraceHop, solve_guard_lattice};

pub fn analyze_codebase(files: &[IndexedFile], cfg: &VeriForgeConfig) -> Result<GraphAnalysisResult> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.scan.max_threads)
        .build()?;

    let summaries: Vec<FileAstSummary> = pool.install(|| {
        files
            .par_iter()
            .filter_map(|f| parse_file_ast(f, cfg))
            .collect()
    });

    Ok(solve_guard_lattice(&summaries))
}
