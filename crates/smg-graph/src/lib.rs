pub mod ai_mcp_model;
pub mod arena;
pub mod ast;
pub mod call_hierarchy;
pub mod cfa_ssa;
pub mod cfg;
pub mod deep_stack;
pub mod deps;
pub mod git_history;
pub mod gitleaks_config;
pub mod iac_policy;
pub mod infra_dos;
pub mod langs;
pub mod lattice;
pub mod phase10;
pub mod phase9;
pub mod protocols_ai;
pub mod rule_pack;
pub mod rules;
pub mod scope;
pub mod secrets_config;
pub mod smt;
pub mod smt_advanced;
pub mod subgraph;
pub mod taint;
pub mod vex_osv;

use anyhow::Result;
use rayon::prelude::*;
use smg_core::{IndexedFile, ShellMindGuardConfig, StateStore};
use std::collections::HashSet;

pub use ai_mcp_model::{
    analyze_indirect_prompt_injection, analyze_mcp_tool_poisoning,
    analyze_model_deserialization_and_ssti, inspect_chat_template_ssti, inspect_pickle_bytes,
    scan_repo_ai_model_artifacts,
};
pub use ast::{
    CallSite, Confidence, FileAstSummary, FrontendApiCall, GuardKind, LocalStaticFinding, SinkKind,
    TypeImplSummary, check_source_syntax, parse_file_ast, parse_file_ast_with_hash,
};
pub use cfa_ssa::{
    AllocSite, CallString2, ContextKey, FieldSensitivePointsTo, KCfaContextTable, PointsToStmt,
    SsaDefUseGraph, SsaOp, SsaVar,
};
pub use deps::{ReachableVulnStatus, assess_dependency_reachability, compute_reachable_packages};
pub use git_history::{
    GitHistoryScanResult, SecretCandidate, extract_aws_secret_near, extract_tokens_from_line,
    scan_git_history,
};
pub use gitleaks_config::{GitleaksConfig, has_inline_allow_marker};
pub use lattice::{
    GraphAnalysisResult, LatticeFinding, RuleHitStat, TraceHop, append_local_static_findings,
    compute_rule_telemetry, finding_matches_layer, solve_guard_lattice,
    solve_guard_lattice_with_options, solve_guard_lattice_with_public,
    solve_guard_lattice_with_slice_mode,
};
pub use phase10::{ParamTypeHint, RouteParamSpec, RouteSchema, collect_deep_schema_findings};
pub use rules::{RULE_CATALOG, RuleDoc, find_rule_doc};
pub use smt::{
    CmpOp, PathConstraint, SmtVerdict, emit_smtlib2, extract_path_constraints_to_line,
    is_line_reachable, is_z3_available, parse_condition_expr, solve_path_constraints,
};
pub use smt_advanced::{
    ArrayConstraint, BvBitState, BvConstraint, LinearIneq, check_interprocedural_feasibility,
    solve_array_constraints, solve_bv_constraints, solve_lia_constraints,
};
pub use subgraph::{
    collect_git_changed_files, should_force_full_scan_on_diff, slice_summaries_for_changed_files,
};
pub use vex_osv::{AutoVexSymbolIndex, OpenVexStatement, to_openvex_json};

fn load_or_parse_summaries_cached(
    files: &[IndexedFile],
    cfg: &ShellMindGuardConfig,
    store: &mut StateStore,
) -> Result<Vec<FileAstSummary>> {
    let cfg_json = serde_json::to_string(&cfg.guards).unwrap_or_default();
    let adv_stamp = smg_core::advisories_db_stamp();
    let versioned_cfg = format!(
        "v33-phase29-web3-ai-mcp-{}|{}|{}|{}",
        env!("CARGO_PKG_VERSION"),
        adv_stamp,
        cfg.scan.deep_audit,
        cfg_json
    );
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
            .stack_size(8 * 1024 * 1024)
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

    Ok(all_summaries)
}

pub fn analyze_codebase(
    files: &[IndexedFile],
    cfg: &ShellMindGuardConfig,
) -> Result<GraphAnalysisResult> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.scan.max_threads)
        .stack_size(8 * 1024 * 1024)
        .build()?;

    let summaries: Vec<FileAstSummary> = pool.install(|| {
        files
            .par_iter()
            .filter_map(|f| parse_file_ast(f, cfg))
            .collect()
    });

    Ok(solve_guard_lattice_with_options(
        &summaries,
        &cfg.guards.public_routes,
        cfg.scan.deep_audit,
    ))
}

/// Two-Phase Incremental AST Cache + Global Guard-Set Lattice Linker.
pub fn analyze_codebase_cached(
    files: &[IndexedFile],
    cfg: &ShellMindGuardConfig,
    store: &mut StateStore,
) -> Result<GraphAnalysisResult> {
    let all_summaries = load_or_parse_summaries_cached(files, cfg, store)?;
    Ok(solve_guard_lattice_with_options(
        &all_summaries,
        &cfg.guards.public_routes,
        cfg.scan.deep_audit,
    ))
}

/// `--changed-since <git-ref>` affected-subgraph analyzer: solves ONLY touched files +
/// reverse callers/callees unless global config/lockfile/middleware changed (auto-fallback).
pub fn analyze_codebase_cached_changed_since(
    files: &[IndexedFile],
    cfg: &ShellMindGuardConfig,
    store: &mut StateStore,
    changed: &HashSet<String>,
) -> Result<(bool, GraphAnalysisResult)> {
    let all_summaries = load_or_parse_summaries_cached(files, cfg, store)?;
    let (full_fallback, sliced) = slice_summaries_for_changed_files(&all_summaries, changed);
    if sliced.is_empty() {
        return Ok((
            full_fallback,
            GraphAnalysisResult {
                parsed_files: 0,
                symbol_count: 0,
                edge_count: 0,
                route_entries: 0,
                active_domains: Vec::new(),
                findings: Vec::new(),
                route_schemas: Vec::new(),
            },
        ));
    }
    let owned_slice: Vec<FileAstSummary> = sliced.into_iter().cloned().collect();
    Ok((
        full_fallback,
        solve_guard_lattice_with_slice_mode(
            &owned_slice,
            &cfg.guards.public_routes,
            cfg.scan.deep_audit,
            !full_fallback,
        ),
    ))
}
