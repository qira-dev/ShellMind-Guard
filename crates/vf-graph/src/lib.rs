pub mod ast;
pub mod deps;
pub mod lattice;
pub mod secrets_config;
pub mod taint;

use anyhow::Result;
use rayon::prelude::*;
use vf_core::{IndexedFile, StateStore, VeriForgeConfig};

pub use ast::{
    FileAstSummary, FrontendApiCall, GuardKind, LocalStaticFinding, SinkKind, parse_file_ast,
    parse_file_ast_with_hash,
};
pub use lattice::{
    GraphAnalysisResult, LatticeFinding, TraceHop, solve_guard_lattice,
    solve_guard_lattice_with_public,
};

pub fn analyze_codebase(
    files: &[IndexedFile],
    cfg: &VeriForgeConfig,
) -> Result<GraphAnalysisResult> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.scan.max_threads)
        .build()?;

    let summaries: Vec<FileAstSummary> = pool.install(|| {
        files
            .par_iter()
            .filter_map(|f| parse_file_ast(f, cfg))
            .collect()
    });

    Ok(solve_guard_lattice_with_public(
        &summaries,
        &cfg.guards.public_routes,
    ))
}

/// Two-Phase Incremental AST Cache + Global Guard-Set Lattice Linker:
/// 1. Unchanged files load their `FileAstSummary` directly from SQLite (`ast_cache`) in <15ms.
/// 2. Only new or modified files run `Tree-sitter` in parallel via Rayon and update `ast_cache`.
/// 3. Global cross-file edges and the O(V+E) Guard-Set Lattice ALWAYS run across all files in RAM.
pub fn analyze_codebase_cached(
    files: &[IndexedFile],
    cfg: &VeriForgeConfig,
    store: &mut StateStore,
) -> Result<GraphAnalysisResult> {
    let cfg_json = serde_json::to_string(&cfg.guards).unwrap_or_default();
    let versioned_cfg = format!("v3-6layer|{}", cfg_json);
    let cfg_hash = blake3::hash(versioned_cfg.as_bytes()).to_hex().to_string();

    let cached_map = store.load_ast_cache(&cfg_hash)?;
    let mut all_summaries: Vec<FileAstSummary> = Vec::with_capacity(files.len());
    let mut to_parse: Vec<&IndexedFile> = Vec::new();

    for f in files {
        if let Some((old_hash, json_str)) = cached_map.get(&f.rel_path)
            && old_hash == &f.blake3_hash
            && let Ok(parsed) = serde_json::from_str::<FileAstSummary>(json_str)
        {
            all_summaries.push(parsed);
            continue;
        }
        to_parse.push(f);
    }

    if !to_parse.is_empty() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(cfg.scan.max_threads)
            .build()?;

        let newly_parsed: Vec<(String, String, FileAstSummary)> = pool.install(|| {
            to_parse
                .par_iter()
                .filter_map(|f| {
                    let (actual_hash, s) = parse_file_ast_with_hash(f, cfg)?;
                    Some((f.rel_path.clone(), actual_hash, s))
                })
                .collect()
        });

        let mut cache_rows: Vec<(String, String, String)> = Vec::with_capacity(newly_parsed.len());
        for (rel_path, hash, summary) in newly_parsed {
            if let Ok(js) = serde_json::to_string(&summary) {
                cache_rows.push((rel_path, hash, js));
            }
            all_summaries.push(summary);
        }
        store.save_ast_cache(&cfg_hash, &cache_rows)?;
    }

    Ok(solve_guard_lattice_with_public(
        &all_summaries,
        &cfg.guards.public_routes,
    ))
}
