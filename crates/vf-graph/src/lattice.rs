use crate::ast::{
    Confidence, FileAstSummary, GuardKind, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    resolve_import_target,
};
use crate::taint::{TAINT_ALL, TAINT_CMD, TAINT_PATH, TAINT_SQL, TAINT_SSRF, TAINT_XSS};
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub file: String,
    pub symbol: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatticeFinding {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: usize,
    pub status: String,
    #[serde(default)]
    pub confidence: Confidence,
    pub entry_route: String,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    pub witness_path: Vec<TraceHop>,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnalysisResult {
    pub parsed_files: usize,
    pub symbol_count: usize,
    pub edge_count: usize,
    pub route_entries: usize,
    pub findings: Vec<LatticeFinding>,
}

pub fn solve_guard_lattice(summaries: &[FileAstSummary]) -> GraphAnalysisResult {
    solve_guard_lattice_with_public(summaries, &[])
}

fn is_public_route(entry_route: &str, public_routes: &[String]) -> bool {
    let path_part = entry_route.split_whitespace().nth(1).unwrap_or(entry_route);
    let low = path_part.to_ascii_lowercase();
    public_routes.iter().any(|p| {
        let pl = p.to_ascii_lowercase();
        low == pl || low.starts_with(&format!("{}/", pl.trim_end_matches('/')))
    })
}

fn is_admin_route(entry_route: &str) -> bool {
    let path_part = entry_route.split_whitespace().nth(1).unwrap_or(entry_route);
    path_part
        .split('/')
        .any(|seg| seg.eq_ignore_ascii_case("admin"))
}

fn go_parent_dir(rel_path: &str) -> String {
    match rel_path.rfind('/') {
        Some(idx) => rel_path[..idx].to_string(),
        None => String::new(),
    }
}

#[allow(clippy::type_complexity)]
fn resolve_symbol_in_file(
    target_file: &str,
    symbol_name: &str,
    file_symbols_map: &HashMap<(String, String), Vec<NodeIndex>>,
    file_imports: &HashMap<String, Vec<(String, String, String)>>,
    depth: usize,
) -> Vec<NodeIndex> {
    if let Some(indices) = file_symbols_map.get(&(target_file.to_string(), symbol_name.to_string()))
        && !indices.is_empty()
    {
        return indices.clone();
    }
    if depth >= 3 {
        return Vec::new();
    }
    let Some(imps) = file_imports.get(target_file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (local_name, next_file, remote_name) in imps {
        if local_name == symbol_name {
            let resolved = resolve_symbol_in_file(
                next_file,
                remote_name,
                file_symbols_map,
                file_imports,
                depth + 1,
            );
            for idx in resolved {
                if !out.contains(&idx) {
                    out.push(idx);
                }
            }
        } else if local_name == "*" {
            let resolved = resolve_symbol_in_file(
                next_file,
                symbol_name,
                file_symbols_map,
                file_imports,
                depth + 1,
            );
            for idx in resolved {
                if !out.contains(&idx) {
                    out.push(idx);
                }
            }
        }
    }
    out
}

fn remediation_for_guard(g: GuardKind) -> &'static str {
    match g {
        GuardKind::Auth => {
            "Add authentication middleware (e.g. JWT/session check like `requireAuth`) before invoking this handler."
        }
        GuardKind::TxLock => {
            "Wrap balance/payment operations in an ACID transaction with `SELECT ... FOR UPDATE` or enforce an atomic idempotency key."
        }
        GuardKind::SqlSanitizer => {
            "Replace dynamic SQL string interpolation with parameterized queries / prepared statements (`$1`, `?`)."
        }
        GuardKind::CmdSanitizer => {
            "Eliminate shell command concatenation (`exec`/`shell=True`); pass an explicit argument array to `execFile`/`Command::new`."
        }
        GuardKind::PathSanitizer => {
            "Canonicalize user-supplied paths with `path.basename` / `filepath.Clean` and verify `resolved.startsWith(baseDir)`."
        }
        GuardKind::SsrfSanitizer => {
            "Enforce an explicit domain/host allowlist and block private/loopback/metadata IP ranges (127.0.0.0/8, 169.254.0.0/16)."
        }
        GuardKind::XssSanitizer => {
            "Encode or sanitize untrusted HTML with `DOMPurify.sanitize` or strict context-aware template auto-escaping instead of raw HTML sinks."
        }
        GuardKind::CsrfProtection => {
            "Enforce anti-CSRF token validation (`csurf`, Django `CsrfViewMiddleware`, SameSite=Strict/Lax cookies) or switch to stateless `Authorization: Bearer` headers."
        }
        GuardKind::OwnershipCheck => {
            "Enforce object-level authorization by filtering the DB query with the authenticated actor (`WHERE id = $1 AND user_id = req.user.id`)."
        }
        GuardKind::SecretPolicy => {
            "Revoke and rotate the exposed credential immediately, move it to a runtime secret manager, and keep `.env` out of git."
        }
        GuardKind::ConfigPolicy => {
            "Harden the configuration baseline (explicit origins, TLS verification enabled, `httpOnly`/`secure` cookies, AEAD/SHA-256+, debug disabled)."
        }
        GuardKind::DependencyPolicy => {
            "Upgrade to a patched dependency version, pin exact/caret semver ranges instead of `*`/`latest`, and use HTTPS/lockfile registries."
        }
        GuardKind::FrontendContract => {
            "Align frontend request paths/methods with registered backend endpoints and handle errors/empty callbacks cleanly."
        }
    }
}

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

fn prefix_for_guard(g: GuardKind) -> &'static str {
    match g {
        GuardKind::Auth => "VF-AUTH",
        GuardKind::TxLock => "VF-RACE",
        GuardKind::SqlSanitizer => "VF-SQLI",
        GuardKind::CmdSanitizer => "VF-CMDI",
        GuardKind::PathSanitizer => "VF-PATH",
        GuardKind::SsrfSanitizer => "VF-SSRF",
        GuardKind::XssSanitizer => "VF-XSS",
        GuardKind::CsrfProtection => "VF-CSRF",
        GuardKind::OwnershipCheck => "VF-IDOR",
        GuardKind::SecretPolicy => "VF-SEC",
        GuardKind::ConfigPolicy => "VF-CFG",
        GuardKind::DependencyPolicy => "VF-DEP",
        GuardKind::FrontendContract => "VF-FE",
    }
}

fn sink_bit_for_guard(g: GuardKind) -> u8 {
    match g {
        GuardKind::SqlSanitizer => TAINT_SQL,
        GuardKind::CmdSanitizer => TAINT_CMD,
        GuardKind::PathSanitizer => TAINT_PATH,
        GuardKind::SsrfSanitizer => TAINT_SSRF,
        GuardKind::XssSanitizer => TAINT_XSS,
        _ => TAINT_ALL,
    }
}

fn push_taint_edges(
    resolved_callee_map: &HashMap<(usize, String), Vec<NodeIndex>>,
    src_node: NodeIndex,
    callee: &str,
    out_mask: u8,
    taint_parents: &mut [Option<NodeIndex>],
    taint_mask: &mut [u8],
    taint_q: &mut VecDeque<NodeIndex>,
) {
    if out_mask == 0 {
        return;
    }
    if let Some(vs) = resolved_callee_map.get(&(src_node.index(), callee.to_string())) {
        for &v in vs {
            let vi = v.index();
            if taint_parents[vi].is_none() {
                taint_parents[vi] = Some(src_node);
            }
            let next = taint_mask[vi] | out_mask;
            if next != taint_mask[vi] {
                taint_mask[vi] = next;
                taint_q.push_back(v);
            }
        }
    }
}

/// Global Cross-File Call Graph + True O(V + E) Guard-Set Lattice, Taint & 6-Layer Witness Solver
pub fn solve_guard_lattice_with_public(
    summaries: &[FileAstSummary],
    public_routes: &[String],
) -> GraphAnalysisResult {
    let mut graph = DiGraph::<SymbolInfo, ()>::new();
    let mut id_to_idx: HashMap<String, NodeIndex> = HashMap::new();
    let mut file_symbols_map: HashMap<(String, String), Vec<NodeIndex>> = HashMap::new();
    let mut go_dir_map: HashMap<(String, String), Vec<NodeIndex>> = HashMap::new();
    let mut go_exported_map: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    let mut known_files: HashSet<String> = HashSet::new();

    for f in summaries {
        known_files.insert(f.rel_path.clone());
        let is_go = f.rel_path.ends_with(".go");
        let go_dir = if is_go {
            go_parent_dir(&f.rel_path)
        } else {
            String::new()
        };
        for sym in &f.symbols {
            let idx = graph.add_node(sym.clone());
            id_to_idx.insert(sym.id.clone(), idx);
            file_symbols_map
                .entry((f.rel_path.clone(), sym.name.clone()))
                .or_default()
                .push(idx);
            if is_go {
                go_dir_map
                    .entry((go_dir.clone(), sym.name.clone()))
                    .or_default()
                    .push(idx);
                if sym.name.chars().next().is_some_and(|c| c.is_uppercase()) {
                    go_exported_map
                        .entry(sym.name.clone())
                        .or_default()
                        .push(idx);
                }
            }
        }
    }

    let mut file_imports: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    for f in summaries {
        let mut imps = Vec::new();
        for imp in &f.imports {
            if let Some(target_file) =
                resolve_import_target(&f.rel_path, &imp.from_specifier, &known_files)
            {
                let remote = imp
                    .remote_name
                    .as_deref()
                    .unwrap_or(&imp.symbol_name)
                    .to_string();
                imps.push((imp.symbol_name.clone(), target_file, remote));
            }
        }
        if !imps.is_empty() {
            file_imports.insert(f.rel_path.clone(), imps);
        }
    }

    // B11: O(1) edge deduplication via HashSet<(usize, usize)> instead of petgraph::update_edge O(deg)
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut resolved_callee_map: HashMap<(usize, String), Vec<NodeIndex>> = HashMap::new();

    for f in summaries {
        let is_go = f.rel_path.ends_with(".go");
        let go_dir = if is_go {
            go_parent_dir(&f.rel_path)
        } else {
            String::new()
        };
        for sym in &f.symbols {
            let Some(&src_idx) = id_to_idx.get(&sym.id) else {
                continue;
            };
            for callee in sym
                .calls
                .iter()
                .chain(sym.tainted_calls.iter())
                .chain(sym.param_forwarding_calls.iter())
            {
                let mut dst_indices: Vec<NodeIndex> = Vec::new();
                if let Some(same_file_idxs) =
                    file_symbols_map.get(&(f.rel_path.clone(), callee.clone()))
                {
                    dst_indices.extend(same_file_idxs.iter().copied());
                }
                if dst_indices.is_empty()
                    && let Some(imps) = file_imports.get(&f.rel_path)
                {
                    for (local_name, target_file, remote_name) in imps {
                        if local_name == callee {
                            let resolved = resolve_symbol_in_file(
                                target_file,
                                remote_name,
                                &file_symbols_map,
                                &file_imports,
                                0,
                            );
                            for idx in resolved {
                                if !dst_indices.contains(&idx) {
                                    dst_indices.push(idx);
                                }
                            }
                        } else if local_name == "*" {
                            let resolved = resolve_symbol_in_file(
                                target_file,
                                callee,
                                &file_symbols_map,
                                &file_imports,
                                0,
                            );
                            for idx in resolved {
                                if !dst_indices.contains(&idx) {
                                    dst_indices.push(idx);
                                }
                            }
                        }
                    }
                }
                if dst_indices.is_empty() && is_go {
                    if let Some(same_pkg_idxs) = go_dir_map.get(&(go_dir.clone(), callee.clone())) {
                        dst_indices.extend(same_pkg_idxs.iter().copied());
                    }
                    if dst_indices.is_empty()
                        && let Some(exp_idxs) = go_exported_map.get(callee)
                    {
                        dst_indices.extend(exp_idxs.iter().copied());
                    }
                }

                for dst_idx in dst_indices {
                    if src_idx != dst_idx {
                        let entry = resolved_callee_map
                            .entry((src_idx.index(), callee.clone()))
                            .or_default();
                        if !entry.contains(&dst_idx) {
                            entry.push(dst_idx);
                        }
                        if seen_edges.insert((src_idx.index(), dst_idx.index())) {
                            graph.add_edge(src_idx, dst_idx, ());
                        }
                    }
                }
            }
        }
    }

    // O(V + E) Worklist Fixed-Point Guard-Set Lattice:
    // G(v) = Intersection_{p in Pred(v)} ( G(p) ) U NodeGuards(v)
    let node_count = graph.node_count();
    let mut reachable = vec![false; node_count];
    let mut guard_in: Vec<Option<HashSet<GuardKind>>> = vec![None; node_count];
    let mut guard_out: Vec<HashSet<GuardKind>> = vec![HashSet::new(); node_count];
    let mut queue = VecDeque::new();
    let mut route_entries = 0usize;

    for idx in graph.node_indices() {
        let sym = &graph[idx];
        if sym.kind == SymbolKind::Route {
            route_entries += 1;
            reachable[idx.index()] = true;
            guard_in[idx.index()] = Some(HashSet::new());
            guard_out[idx.index()] = sym.guards.clone();
            queue.push_back(idx);
        }
    }

    while let Some(u) = queue.pop_front() {
        let u_out = guard_out[u.index()].clone();
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            let changed = if !reachable[vi] {
                reachable[vi] = true;
                guard_in[vi] = Some(u_out.clone());
                let mut next_out = u_out.clone();
                next_out.extend(graph[v].guards.iter().copied());
                guard_out[vi] = next_out;
                true
            } else {
                let prev_in = guard_in[vi].as_ref().unwrap();
                let intersected: HashSet<GuardKind> =
                    prev_in.intersection(&u_out).copied().collect();
                if intersected.len() < prev_in.len() {
                    guard_in[vi] = Some(intersected.clone());
                    let mut next_out = intersected;
                    next_out.extend(graph[v].guards.iter().copied());
                    if next_out != guard_out[vi] {
                        guard_out[vi] = next_out;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if changed {
                queue.push_back(v);
            }
        }
    }

    // B11: Precompute ONE single forward multi-source BFS tree per GuardKind -> O(V + E) total!
    let auth_parents = build_unguarded_bfs_tree(&graph, GuardKind::Auth);
    let lock_parents = build_unguarded_bfs_tree(&graph, GuardKind::TxLock);
    let route_parents = build_any_route_bfs_tree(&graph);

    // O(V + E) Sink-Typed Bitmask Join-Semilattice Taint Propagation (`tainted_call_masks` + `param_forwarding_calls`)
    let mut taint_parents: Vec<Option<NodeIndex>> = vec![None; node_count];
    let mut taint_mask: Vec<u8> = vec![0; node_count];
    let mut taint_q = VecDeque::new();

    for u in graph.node_indices() {
        let is_route_entry = graph[u].kind == SymbolKind::Route;
        let seed_delegated_route_calls = is_route_entry
            && graph[u].tainted_calls.is_empty()
            && graph[u].param_forwarding_calls.is_empty()
            && !graph[u].has_taint_source
            && graph[u].has_resource_id;
        let seed_iter = graph[u]
            .tainted_calls
            .iter()
            .chain(if is_route_entry {
                graph[u].param_forwarding_calls.as_slice()
            } else {
                &[]
            })
            .chain(if seed_delegated_route_calls {
                graph[u].calls.as_slice()
            } else {
                &[]
            });
        for callee in seed_iter {
            let edge_mask = graph[u]
                .tainted_call_masks
                .get(callee)
                .copied()
                .unwrap_or(TAINT_ALL);
            push_taint_edges(
                &resolved_callee_map,
                u,
                callee,
                edge_mask,
                &mut taint_parents,
                &mut taint_mask,
                &mut taint_q,
            );
        }
    }
    while let Some(w) = taint_q.pop_front() {
        let w_mask = taint_mask[w.index()];
        for callee in &graph[w].tainted_calls {
            let edge_mask = graph[w]
                .tainted_call_masks
                .get(callee)
                .copied()
                .unwrap_or(TAINT_ALL);
            push_taint_edges(
                &resolved_callee_map,
                w,
                callee,
                edge_mask,
                &mut taint_parents,
                &mut taint_mask,
                &mut taint_q,
            );
        }
        for callee in &graph[w].param_forwarding_calls {
            let edge_mask = graph[w]
                .tainted_call_masks
                .get(callee)
                .copied()
                .unwrap_or(TAINT_ALL);
            push_taint_edges(
                &resolved_callee_map,
                w,
                callee,
                w_mask & edge_mask,
                &mut taint_parents,
                &mut taint_mask,
                &mut taint_q,
            );
        }
    }

    // O(V + E) IDOR Resource-ID Reachability BFS (from any Route/node holding a resource ID parameter)
    let mut res_id_reaches = vec![false; node_count];
    let mut res_q = VecDeque::new();
    for idx in graph.node_indices() {
        if reachable[idx.index()] && graph[idx].has_resource_id {
            res_id_reaches[idx.index()] = true;
            res_q.push_back(idx);
        }
    }
    while let Some(u) = res_q.pop_front() {
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if reachable[vi] && !res_id_reaches[vi] {
                res_id_reaches[vi] = true;
                res_q.push_back(v);
            }
        }
    }

    let mut repo_has_cookie_session = false;
    let mut repo_has_bearer_auth = false;
    let mut repo_has_global_csrf = false;
    for f in summaries {
        repo_has_cookie_session |= f.has_cookie_session_setup;
        repo_has_bearer_auth |= f.has_bearer_auth_setup;
        repo_has_global_csrf |= f.has_global_csrf_guard;
    }
    let repo_bearer_only = repo_has_bearer_auth && !repo_has_cookie_session;

    // Deduplicate on the fly by (entry_route, rule_id)
    let mut best_by_key: HashMap<(String, String), LatticeFinding> = HashMap::new();

    for idx in graph.node_indices() {
        let vi = idx.index();
        let sym = &graph[idx];
        let active_guards = &guard_out[vi];

        // Layer 1 & Layer 2 (Auth & Concurrency/TxLock) — requires reachable Route + SinkKind
        if reachable[vi]
            && let Some(sink_kind) = sym.sink_kind
        {
            if !active_guards.contains(&GuardKind::Auth)
                && can_improve_witness(&best_by_key, &graph, &auth_parents, idx, "VF-AUTH-001")
                && let Some((entry_name, witness)) = reconstruct_witness(&graph, &auth_parents, idx)
                && !is_public_route(&entry_name, public_routes)
            {
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "VF-AUTH-001".into(),
                        severity: "HIGH".into(),
                        title: format!("Unauthenticated path to {:?} in `{}`", sink_kind, sym.name),
                        file: String::new(),
                        line: 0,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Confirmed,
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::Auth,
                        witness_path: witness,
                        remediation: remediation_for_guard(GuardKind::Auth).into(),
                    },
                );
            }

            if matches!(
                sink_kind,
                SinkKind::PaymentMutation | SinkKind::BalanceUpdate
            ) && !active_guards.contains(&GuardKind::TxLock)
                && can_improve_witness(&best_by_key, &graph, &lock_parents, idx, "VF-RACE-001")
                && let Some((entry_name, witness)) = reconstruct_witness(&graph, &lock_parents, idx)
            {
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "VF-RACE-001".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "Missing transaction/lock guard before `{}` (Double-Spend Risk)",
                            sym.name
                        ),
                        file: String::new(),
                        line: 0,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Confirmed,
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::TxLock,
                        witness_path: witness,
                        remediation: remediation_for_guard(GuardKind::TxLock).into(),
                    },
                );
            }
        }

        // Layer 2a: Intra-procedural Injection / Path / SSRF / XSS hits (`Source -> Sink` inside node)
        for hit in &sym.local_taint_hits {
            if reachable[vi] && active_guards.contains(&hit.missing_guard) {
                continue;
            }
            let (entry_route, mut witness) =
                if let Some((er, w)) = reconstruct_witness(&graph, &route_parents, idx) {
                    (er, w)
                } else {
                    (
                        format!("{}:{}", hit.rel_path, hit.line),
                        vec![TraceHop {
                            file: hit.rel_path.clone(),
                            symbol: hit.symbol.clone(),
                            line: hit.line,
                        }],
                    )
                };
            if let Some(last) = witness.last_mut() {
                last.line = hit.line;
            }
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: hit.rule_id.clone(),
                    severity: hit.severity.clone(),
                    title: hit.title.clone(),
                    file: hit.rel_path.clone(),
                    line: hit.line,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: hit.confidence,
                    entry_route,
                    sink_kind: hit.sink_kind,
                    missing_guard: hit.missing_guard,
                    witness_path: witness,
                    remediation: hit.remediation.clone(),
                },
            );
        }

        // Layer 2b: Cross-file / Inter-procedural Taint (`Source -> param_forwarding -> ParamSink`)
        if taint_parents[vi].is_some() && taint_mask[vi] != 0 {
            for hit in &sym.param_sinks {
                if (taint_mask[vi] & sink_bit_for_guard(hit.missing_guard)) == 0 {
                    continue;
                }
                if reachable[vi] && active_guards.contains(&hit.missing_guard) {
                    continue;
                }
                if let Some((entry_route, mut witness)) =
                    reconstruct_taint_witness(&graph, &taint_parents, &route_parents, idx)
                {
                    if let Some(last) = witness.last_mut() {
                        last.line = hit.line;
                    }
                    insert_shorter(
                        &mut best_by_key,
                        LatticeFinding {
                            id: String::new(),
                            rule_id: hit.rule_id.clone(),
                            severity: hit.severity.clone(),
                            title: hit.title.clone(),
                            file: hit.rel_path.clone(),
                            line: hit.line,
                            status: "SUSPECT_UNGUARDED".into(),
                            confidence: hit.confidence,
                            entry_route,
                            sink_kind: hit.sink_kind,
                            missing_guard: hit.missing_guard,
                            witness_path: witness,
                            remediation: hit.remediation.clone(),
                        },
                    );
                }
            }
        }

        // Layer 2c: IDOR (`Auth` route + `resource_id` + DB CRUD read/update/delete without ownership filter)
        if reachable[vi]
            && sym.has_db_crud_sink
            && active_guards.contains(&GuardKind::Auth)
            && res_id_reaches[vi]
            && !active_guards.contains(&GuardKind::OwnershipCheck)
            && can_improve_witness(&best_by_key, &graph, &route_parents, idx, "VF-IDOR-001")
            && let Some((entry_name, mut witness)) =
                reconstruct_witness(&graph, &route_parents, idx)
            && !is_public_route(&entry_name, public_routes)
            && !is_admin_route(&entry_name)
        {
            if let Some(last) = witness.last_mut()
                && let Some(ln) = sym.db_crud_line
            {
                last.line = ln;
            }
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: "VF-IDOR-001".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Potential IDOR: authenticated resource query in `{}` lacks ownership filter",
                        sym.name
                    ),
                    file: String::new(),
                    line: 0,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: Confidence::Confirmed,
                    entry_route: entry_name,
                    sink_kind: SinkKind::IdorDbAccess,
                    missing_guard: GuardKind::OwnershipCheck,
                    witness_path: witness,
                    remediation: remediation_for_guard(GuardKind::OwnershipCheck).into(),
                },
            );
        }

        // Layer 2e: CSRF (`VF-CSRF-001`) on `@csrf_exempt` views or unguarded state-changing cookie/session routes
        let lower_sym_name = sym.name.to_ascii_lowercase();
        let is_webhook_or_health = lower_sym_name.contains("webhook")
            || lower_sym_name.contains("/health")
            || lower_sym_name.contains("/metrics");
        if sym.csrf_exempt && !is_webhook_or_health && !sym.has_bearer_header_auth {
            let (entry_name, witness) =
                if let Some((er, w)) = reconstruct_witness(&graph, &route_parents, idx) {
                    (er, w)
                } else {
                    (
                        sym.name.clone(),
                        vec![TraceHop {
                            file: sym.rel_path.clone(),
                            symbol: sym.name.clone(),
                            line: sym.line_start,
                        }],
                    )
                };
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: "VF-CSRF-001".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "CSRF protection explicitly disabled (`@csrf_exempt`) on `{}`",
                        sym.name
                    ),
                    file: sym.rel_path.clone(),
                    line: sym.line_start,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: Confidence::Confirmed,
                    entry_route: entry_name,
                    sink_kind: SinkKind::Csrf,
                    missing_guard: GuardKind::CsrfProtection,
                    witness_path: witness,
                    remediation: remediation_for_guard(GuardKind::CsrfProtection).into(),
                },
            );
        } else if sym.kind == SymbolKind::Route
            && !is_webhook_or_health
            && !active_guards.contains(&GuardKind::CsrfProtection)
            && !repo_has_global_csrf
            && !sym.has_bearer_header_auth
        {
            let method = sym.name.split_whitespace().next().unwrap_or("");
            let is_state_changing = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
            let cookie_session_route = sym.has_cookie_session_auth
                || (active_guards.contains(&GuardKind::Auth)
                    && repo_has_cookie_session
                    && !repo_bearer_only);
            if is_state_changing
                && cookie_session_route
                && !is_public_route(&sym.name, public_routes)
            {
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "VF-CSRF-001".into(),
                        severity: "HIGH".into(),
                        title: format!(
                            "State-changing cookie/session endpoint `{}` lacks CSRF protection",
                            sym.name
                        ),
                        file: sym.rel_path.clone(),
                        line: sym.line_start,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Confirmed,
                        entry_route: sym.name.clone(),
                        sink_kind: SinkKind::Csrf,
                        missing_guard: GuardKind::CsrfProtection,
                        witness_path: vec![TraceHop {
                            file: sym.rel_path.clone(),
                            symbol: sym.name.clone(),
                            line: sym.line_start,
                        }],
                        remediation: remediation_for_guard(GuardKind::CsrfProtection).into(),
                    },
                );
            }
        }
    }

    // Layer 2d: Frontend <-> Backend API Contract Check (`VF-FE-404`)
    if route_entries > 0 {
        let mut all_prefixes: Vec<String> = Vec::new();
        for f in summaries {
            for p in &f.route_prefixes {
                if !p.starts_with("__AUTH_PREFIX__:") && !all_prefixes.iter().any(|x| x == p) {
                    all_prefixes.push(p.clone());
                }
            }
        }

        let mut routes_by_seg_len: HashMap<usize, Vec<(String, Vec<String>)>> = HashMap::new();
        for idx in graph.node_indices() {
            let sym = &graph[idx];
            if sym.kind == SymbolKind::Route
                && let Some(ref rp) = sym.route_path
            {
                let method = sym
                    .name
                    .split_whitespace()
                    .next()
                    .unwrap_or("ANY")
                    .to_ascii_uppercase();
                let norm = crate::taint::normalize_api_path(rp);
                let segs: Vec<String> = norm
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                routes_by_seg_len
                    .entry(segs.len())
                    .or_default()
                    .push((method.clone(), segs));

                for pref in &all_prefixes {
                    if !rp.starts_with(pref) {
                        let combined = format!(
                            "{}/{}",
                            pref.trim_end_matches('/'),
                            rp.trim_start_matches('/')
                        );
                        let pnorm = crate::taint::normalize_api_path(&combined);
                        let psegs: Vec<String> = pnorm
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        routes_by_seg_len
                            .entry(psegs.len())
                            .or_default()
                            .push((method.clone(), psegs));
                    }
                }
            }
        }

        for f in summaries {
            for call in &f.frontend_calls {
                let csegs: Vec<&str> = call
                    .normalized_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                let matched = routes_by_seg_len.get(&csegs.len()).is_some_and(|cands| {
                    cands.iter().any(|(rmethod, rsegs)| {
                        let method_ok = rmethod == &call.method
                            || matches!(rmethod.as_str(), "HTTP" | "DJANGO" | "ANY");
                        method_ok
                            && rsegs
                                .iter()
                                .zip(csegs.iter())
                                .all(|(b, fseg)| b == *fseg || b == "*" || *fseg == "*")
                    })
                });
                if !matched {
                    let key = (
                        format!("{}:{}", call.rel_path, call.line),
                        "VF-FE-404".to_string(),
                    );
                    best_by_key.entry(key).or_insert_with(|| LatticeFinding {
                        id: String::new(),
                        rule_id: "VF-FE-404".into(),
                        severity: "MEDIUM".into(),
                        title: format!(
                            "Frontend `{}` call to `{}` has no matching backend route handler",
                            call.method, call.raw_path
                        ),
                        file: call.rel_path.clone(),
                        line: call.line,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Heuristic,
                        entry_route: format!("{} {}", call.method, call.raw_path),
                        sink_kind: SinkKind::FrontendContract,
                        missing_guard: GuardKind::FrontendContract,
                        witness_path: vec![TraceHop {
                            file: call.rel_path.clone(),
                            symbol: call.symbol.clone(),
                            line: call.line,
                        }],
                        remediation: "Verify the backend route path, HTTP method, and router prefix match the frontend API call.".into(),
                    });
                }
            }
        }
    }

    // Layer 1 (Secrets), Layer 3 (Deps), Layer 4 (Misconfigs), & Layer 2 UI Bugs (`VF-FE-ERR`)
    let mut sensitive_files: Vec<&str> = Vec::new();
    let mut gitignore_files: Vec<(&str, &[String])> = Vec::new();
    for f in summaries {
        if f.is_sensitive_env_or_pem {
            sensitive_files.push(&f.rel_path);
        }
        if let Some(ref lines) = f.gitignore_lines {
            gitignore_files.push((&f.rel_path, lines.as_slice()));
        }
        for sf in &f.static_findings {
            insert_static_finding(&mut best_by_key, sf);
        }
    }
    for env_hit in
        crate::secrets_config::check_gitignore_exposure(&sensitive_files, &gitignore_files)
    {
        insert_static_finding(&mut best_by_key, &env_hit);
    }

    let mut deduped: Vec<LatticeFinding> = best_by_key.into_values().collect();
    deduped.sort_by(|a, b| {
        let ta = if matches!(a.missing_guard, GuardKind::Auth | GuardKind::TxLock) {
            0u8
        } else {
            1u8
        };
        let tb = if matches!(b.missing_guard, GuardKind::Auth | GuardKind::TxLock) {
            0u8
        } else {
            1u8
        };
        ta.cmp(&tb).then_with(|| {
            if ta == 0 {
                a.entry_route
                    .cmp(&b.entry_route)
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
            } else {
                severity_rank(&a.severity)
                    .cmp(&severity_rank(&b.severity))
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
                    .then_with(|| a.entry_route.cmp(&b.entry_route))
                    .then_with(|| {
                        let al = a.witness_path.first().map(|h| h.line).unwrap_or(0);
                        let bl = b.witness_path.first().map(|h| h.line).unwrap_or(0);
                        al.cmp(&bl)
                    })
            }
        })
    });

    let mut prefix_counts: HashMap<&'static str, usize> = HashMap::new();
    for item in deduped.iter_mut() {
        if let Some(primary) = item
            .witness_path
            .last()
            .or_else(|| item.witness_path.first())
        {
            if item.file.is_empty() {
                item.file = primary.file.clone();
            }
            if item.line == 0 {
                item.line = primary.line;
            }
        }
        let prefix = prefix_for_guard(item.missing_guard);
        let c = prefix_counts.entry(prefix).or_insert(0);
        *c += 1;
        item.id = format!("{}-{:03}", prefix, *c);
    }

    GraphAnalysisResult {
        parsed_files: summaries.len(),
        symbol_count: graph.node_count(),
        edge_count: graph.edge_count(),
        route_entries,
        findings: deduped,
    }
}

fn insert_shorter(best: &mut HashMap<(String, String), LatticeFinding>, cand: LatticeFinding) {
    let key = (cand.entry_route.clone(), cand.rule_id.clone());
    let replace = match best.get(&key) {
        Some(prev) => cand.witness_path.len() < prev.witness_path.len(),
        None => true,
    };
    if replace {
        best.insert(key, cand);
    }
}

fn insert_static_finding(
    best: &mut HashMap<(String, String), LatticeFinding>,
    sf: &LocalStaticFinding,
) {
    let entry_route = format!("{}:{}", sf.rel_path, sf.line);
    let key = (entry_route.clone(), sf.rule_id.clone());
    best.entry(key).or_insert_with(|| LatticeFinding {
        id: String::new(),
        rule_id: sf.rule_id.clone(),
        severity: sf.severity.clone(),
        title: sf.title.clone(),
        file: sf.rel_path.clone(),
        line: sf.line,
        status: "SUSPECT_UNGUARDED".into(),
        confidence: sf.confidence,
        entry_route,
        sink_kind: sf.sink_kind,
        missing_guard: sf.missing_guard,
        witness_path: vec![TraceHop {
            file: sf.rel_path.clone(),
            symbol: sf.symbol.clone(),
            line: sf.line,
        }],
        remediation: sf.remediation.clone(),
    });
}

struct BfsTree {
    parent: Vec<Option<NodeIndex>>,
    root: Vec<Option<NodeIndex>>,
    depth: Vec<usize>,
}

fn can_improve_witness(
    best: &HashMap<(String, String), LatticeFinding>,
    graph: &DiGraph<SymbolInfo, ()>,
    tree: &BfsTree,
    sink: NodeIndex,
    rule_id: &str,
) -> bool {
    let si = sink.index();
    let Some(root_idx) = tree.root[si] else {
        return false;
    };
    let entry_name = &graph[root_idx].name;
    let cand_len = tree.depth[si].min(graph.node_count().min(64));
    match best.get(&(entry_name.clone(), rule_id.to_string())) {
        Some(prev) => cand_len < prev.witness_path.len(),
        None => true,
    }
}

/// Single O(V + E) multi-source forward BFS from ALL `Route` entries (unblocked by guards).
fn build_any_route_bfs_tree(graph: &DiGraph<SymbolInfo, ()>) -> BfsTree {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut root = vec![None; n];
    let mut depth = vec![0usize; n];
    let mut q = VecDeque::new();
    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route {
            let i = idx.index();
            parent[i] = Some(idx);
            root[i] = Some(idx);
            depth[i] = 1;
            q.push_back(idx);
        }
    }
    while let Some(u) = q.pop_front() {
        let ui = u.index();
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() {
                parent[vi] = Some(u);
                root[vi] = root[ui];
                depth[vi] = depth[ui] + 1;
                q.push_back(v);
            }
        }
    }
    BfsTree {
        parent,
        root,
        depth,
    }
}

fn reconstruct_taint_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    taint_parents: &[Option<NodeIndex>],
    route_parents: &BfsTree,
    sink: NodeIndex,
) -> Option<(String, Vec<TraceHop>)> {
    let mut rev_taint = Vec::new();
    let mut cur = sink;
    let mut seen: HashSet<usize> = HashSet::new();
    let source_node = loop {
        if !seen.insert(cur.index()) || rev_taint.len() >= 32 {
            break cur;
        }
        let s = &graph[cur];
        rev_taint.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        match taint_parents[cur.index()] {
            Some(p) if p != cur => cur = p,
            _ => break cur,
        }
    };
    rev_taint.reverse();

    if let Some((entry_name, mut prefix_hops)) =
        reconstruct_witness(graph, route_parents, source_node)
    {
        if !rev_taint.is_empty() {
            // Avoid duplicating `source_node` which appears at the end of `prefix_hops` and start of `rev_taint`
            prefix_hops.extend(rev_taint.into_iter().skip(1));
        }
        Some((entry_name, prefix_hops))
    } else {
        let entry = rev_taint
            .first()
            .map(|h| format!("{}:{}", h.file, h.line))
            .unwrap_or_else(|| graph[sink].rel_path.clone());
        Some((entry, rev_taint))
    }
}

/// Single O(V + E) multi-source forward BFS from all unguarded `Route` entries.
/// Returns `BfsTree` with `parent[node]`, `root[node]`, and `depth[node]` in O(1) per node.
fn build_unguarded_bfs_tree(graph: &DiGraph<SymbolInfo, ()>, guard: GuardKind) -> BfsTree {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut root = vec![None; n];
    let mut depth = vec![0usize; n];
    let mut q = VecDeque::new();

    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route && !graph[idx].guards.contains(&guard) {
            let i = idx.index();
            parent[i] = Some(idx);
            root[i] = Some(idx);
            depth[i] = 1;
            q.push_back(idx);
        }
    }

    while let Some(u) = q.pop_front() {
        let ui = u.index();
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() && !graph[v].guards.contains(&guard) {
                parent[vi] = Some(u);
                root[vi] = root[ui];
                depth[vi] = depth[ui] + 1;
                q.push_back(v);
            }
        }
    }
    BfsTree {
        parent,
        root,
        depth,
    }
}

fn reconstruct_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    tree: &BfsTree,
    sink: NodeIndex,
) -> Option<(String, Vec<TraceHop>)> {
    let root_idx = tree.root[sink.index()]?;
    let entry_name = graph[root_idx].name.clone();
    let mut rev_hops = Vec::new();
    let mut cur = sink;
    let mut steps = 0usize;
    let max_steps = graph.node_count().min(64);

    loop {
        let s = &graph[cur];
        rev_hops.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        let p = tree.parent[cur.index()]?;
        if p == cur {
            break;
        }
        steps += 1;
        if steps >= max_steps {
            break;
        }
        cur = p;
    }

    rev_hops.reverse();
    Some((entry_name, rev_hops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{FrontendApiCall, parse_file_ast};
    use std::time::Instant;
    use vf_core::{IndexedFile, Language, ShellMindGuardConfig};

    #[test]
    fn test_b11_2000_node_all_sink_chain_is_linear() {
        let mut symbols = Vec::with_capacity(2001);
        symbols.push(SymbolInfo {
            id: "a.ts::route:1".into(),
            rel_path: "a.ts".into(),
            name: "POST /api/chain".into(),
            kind: SymbolKind::Route,
            sink_kind: None,
            line_start: 1,
            line_end: 1,
            guards: HashSet::new(),
            calls: vec!["sink_0".into()],
            route_path: Some("/api/chain".into()),
            ..Default::default()
        });
        for i in 0..2000 {
            let next_call = if i + 1 < 2000 {
                vec![format!("sink_{}", i + 1)]
            } else {
                Vec::new()
            };
            symbols.push(SymbolInfo {
                id: format!("a.ts::sink_{}", i),
                rel_path: "a.ts".into(),
                name: format!("sink_{}", i),
                kind: SymbolKind::Sink,
                sink_kind: Some(SinkKind::BalanceUpdate),
                line_start: i + 2,
                line_end: i + 2,
                guards: HashSet::new(),
                calls: next_call,
                route_path: None,
                ..Default::default()
            });
        }
        let summaries = vec![FileAstSummary {
            rel_path: "a.ts".into(),
            imports: Vec::new(),
            symbols,
            ..Default::default()
        }];

        let t0 = Instant::now();
        let res = solve_guard_lattice(&summaries);
        let elapsed_ms = t0.elapsed().as_millis();
        assert!(!res.findings.is_empty());
        assert!(
            elapsed_ms < 500,
            "2000-node all-sink chain took {}ms (must be linear!)",
            elapsed_ms
        );
    }

    #[test]
    fn test_cross_file_sqli_idor_and_frontend_contract() {
        let dir = std::env::temp_dir().join("vf_lattice_6layer_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("routes")).unwrap();
        std::fs::create_dir_all(dir.join("db")).unwrap();
        std::fs::create_dir_all(dir.join("web")).unwrap();

        let route_src = r#"
import { runUserQuery } from '../db/queries';
export function requireAuth(req: any, res: any, next: any) { next(); }
app.use('/api/v1', requireAuth);
app.get('/users/:id', async (req, res) => {
    const uid = req.params.id;
    return await runUserQuery(uid);
});
"#;
        let query_src = r#"
export async function runUserQuery(userId: string) {
    return await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}
"#;
        let fe_src = r#"
export async function syncData() {
    await fetch('/api/v1/users/42');
    await fetch('/api/v1/nonexistent/endpoint', { method: 'POST' });
}
"#;
        std::fs::write(dir.join("routes/users.ts"), route_src).unwrap();
        std::fs::write(dir.join("db/queries.ts"), query_src).unwrap();
        std::fs::write(dir.join("web/app.ts"), fe_src).unwrap();

        let cfg = ShellMindGuardConfig::default();
        let f1 = IndexedFile {
            abs_path: dir.join("routes/users.ts"),
            rel_path: "routes/users.ts".into(),
            language: Language::TypeScript,
            size_bytes: route_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(route_src.as_bytes().to_vec()),
        };
        let f2 = IndexedFile {
            abs_path: dir.join("db/queries.ts"),
            rel_path: "db/queries.ts".into(),
            language: Language::TypeScript,
            size_bytes: query_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(query_src.as_bytes().to_vec()),
        };
        let f3 = IndexedFile {
            abs_path: dir.join("web/app.ts"),
            rel_path: "web/app.ts".into(),
            language: Language::TypeScript,
            size_bytes: fe_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(fe_src.as_bytes().to_vec()),
        };

        let s1 = parse_file_ast(&f1, &cfg).unwrap();
        let s2 = parse_file_ast(&f2, &cfg).unwrap();
        let s3 = parse_file_ast(&f3, &cfg).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let res = solve_guard_lattice(&[s1, s2, s3]);
        let sqli = res
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-SQLI-001")
            .expect("Cross-file SQLi must be detected");
        assert!(
            sqli.witness_path.len() >= 2,
            "Cross-file witness must trace Route -> sink: {:?}",
            sqli.witness_path
        );

        assert!(
            res.findings.iter().any(|f| f.rule_id == "VF-IDOR-001"),
            "Authenticated /users/:id DB read without user_id filter must trigger VF-IDOR-001"
        );

        let fe404: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "VF-FE-404")
            .collect();
        assert_eq!(
            fe404.len(),
            1,
            "Mounted /api/v1/users/42 must match, only /nonexistent/endpoint must trigger VF-FE-404: {:?}",
            fe404
        );
        // Ensure FrontendApiCall import stays used cleanly
        let _dummy = std::mem::size_of::<FrontendApiCall>();
    }

    #[test]
    fn test_fastapi_route_param_injection_taint_propagation() {
        let py_src = r#"
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: str):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"#;
        let cfg = ShellMindGuardConfig::default();
        let file = IndexedFile {
            abs_path: "api.py".into(),
            rel_path: "api.py".into(),
            language: Language::Python,
            size_bytes: py_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(py_src.as_bytes().to_vec()),
        };
        let summary = parse_file_ast(&file, &cfg).unwrap();
        let res = solve_guard_lattice(&[summary]);
        assert!(
            res.findings.iter().any(|f| f.rule_id == "VF-SQLI-001"),
            "FastAPI route handler parameter user_id must propagate taint to SQL sink: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_aliased_barrel_imports_idor_masking_and_subpath_auth() {
        let cfg = ShellMindGuardConfig::default();

        let route_src = r#"
import { executeUnsafeSql as runSql } from './barrel';

app.use('/admin', requireAuth);

app.post('/billing/charge', async (req, res) => {
    const uid = req.body.userId;
    await runSql(uid);
});

app.get('/orders/:id', requireAuth, async (req, res) => {
    const order = await prisma.order.findFirst({
        where: { id: req.params.id, user_id: req.query.user_id }
    });
    return res.json(order);
});

app.get('/admin/orders/:id', requireAuth, async (req, res) => {
    const order = await prisma.order.findUnique({
        where: { id: req.params.id }
    });
    return res.json(order);
});
"#;
        let barrel_src = r#"
export * from './db';
"#;
        let db_src = r#"
export async function executeUnsafeSql(targetId: string) {
    let q = "UPDATE balances SET amount = 0 WHERE user_id = '";
    q += targetId;
    return await db.query(q);
}
"#;
        let f_route = IndexedFile {
            abs_path: "src/routes.ts".into(),
            rel_path: "src/routes.ts".into(),
            language: Language::TypeScript,
            size_bytes: route_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(route_src.as_bytes().to_vec()),
        };
        let f_barrel = IndexedFile {
            abs_path: "src/barrel.ts".into(),
            rel_path: "src/barrel.ts".into(),
            language: Language::TypeScript,
            size_bytes: barrel_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(barrel_src.as_bytes().to_vec()),
        };
        let f_db = IndexedFile {
            abs_path: "src/db.ts".into(),
            rel_path: "src/db.ts".into(),
            language: Language::TypeScript,
            size_bytes: db_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(db_src.as_bytes().to_vec()),
        };

        let s1 = parse_file_ast(&f_route, &cfg).unwrap();
        let s2 = parse_file_ast(&f_barrel, &cfg).unwrap();
        let s3 = parse_file_ast(&f_db, &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2, s3]);

        // 1. Sub-path middleware `/admin` must NOT protect `/billing/charge`, and aliased + barrel import must resolve
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "VF-AUTH-001" && f.entry_route == "POST /billing/charge"),
            "Sub-path /admin middleware must not protect POST /billing/charge: {:?}",
            res.findings
        );
        // 2. Multi-statement SQL concatenation via aliased barrel import must trigger VF-SQLI-001
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "VF-SQLI-001" && f.entry_route == "POST /billing/charge"),
            "Aliased barrel import + multi-statement += SQLi must be detected: {:?}",
            res.findings
        );
        // 3. `user_id: req.query.user_id` must NOT satisfy ownership check (must trigger VF-IDOR-001 on /orders/:id)
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "VF-IDOR-001" && f.entry_route == "GET /orders/:id"),
            "Tainted user_id: req.query.user_id must still trigger VF-IDOR-001: {:?}",
            res.findings
        );
        // 4. Admin route `/admin/orders/:id` must NOT trigger VF-IDOR-001
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "VF-IDOR-001" && f.entry_route == "GET /admin/orders/:id"),
            "Admin route GET /admin/orders/:id must not trigger VF-IDOR-001: {:?}",
            res.findings
        );
    }

    fn make_indexed(rel: &str, lang: Language, code: &str) -> IndexedFile {
        IndexedFile {
            abs_path: rel.into(),
            rel_path: rel.into(),
            language: lang,
            size_bytes: code.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(code.as_bytes().to_vec()),
        }
    }

    #[test]
    fn test_sprint2_bitmask_taint_precision_and_early_return_narrowing() {
        let cfg = ShellMindGuardConfig::default();
        let route_src = r#"
import { writeNote, queryUser } from './helpers';

app.get('/report', async (req, res) => {
    if (!req.query.id) {
        return res.status(400).send("missing req.query.id parameter");
    }
    const safeName = path.basename(req.query.name);
    await writeNote(safeName);
    await queryUser(safeName);

    const targetUrl = req.query.url;
    if (!isAllowedHost(targetUrl)) {
        return res.status(400).send("blocked");
    }
    await fetch(targetUrl);
    return res.json({ ok: true });
});
"#;
        let helpers_src = r#"
import * as fs from 'fs';
export async function writeNote(fileName: string) {
    return fs.readFileSync('/var/notes/' + fileName, 'utf8');
}
export async function queryUser(userKey: string) {
    return await db.query(`SELECT * FROM notes WHERE key = '${userKey}'`);
}
"#;
        let s1 = parse_file_ast(
            &make_indexed("src/route.ts", Language::TypeScript, route_src),
            &cfg,
        )
        .unwrap();
        let s2 = parse_file_ast(
            &make_indexed("src/helpers.ts", Language::TypeScript, helpers_src),
            &cfg,
        )
        .unwrap();
        let res = solve_guard_lattice(&[s1, s2]);

        assert!(
            !res.findings.iter().any(|f| f.rule_id == "VF-PATH-001"),
            "path.basename clears TAINT_PATH across call boundaries: {:?}",
            res.findings
        );
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "VF-SSRF-001"),
            "Early-return !isAllowedHost guard must narrow SSRF taint: {:?}",
            res.findings
        );
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "VF-XSS-001"),
            "Static string literal error messages and JSON responses must not trigger VF-XSS-001: {:?}",
            res.findings
        );
        let sqli = res.findings.iter().find(|f| f.rule_id == "VF-SQLI-001");
        assert!(
            sqli.is_some(),
            "path.basename must NOT clear TAINT_SQL on SQL sink: {:?}",
            res.findings
        );
        assert_eq!(sqli.unwrap().confidence, Confidence::Confirmed);
    }

    #[test]
    fn test_sprint2_xss_partial_sanitization_and_multilang() {
        let cfg = ShellMindGuardConfig::default();
        let ts_src = r#"
app.get('/profile', (req, res) => {
    const clean = DOMPurify.sanitize(req.query.clean);
    el1.innerHTML = clean;
    const partial = DOMPurify.sanitize(req.query.a) + req.query.raw;
    el2.innerHTML = partial;
});
app.get('/banner', (req, res) => {
    res.send(`<div>${req.query.msg}</div>`);
});
"#;
        let py_src = r#"
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.get("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<h1>" + name + "</h1>")
"#;
        let go_src = r#"
package main
import ("html/template"; "net/http")

func Register(r *http.ServeMux) {
    r.HandleFunc("/card", func(w http.ResponseWriter, req *http.Request) {
        bio := req.URL.Query().Get("bio")
        _ = template.HTML(bio)
    })
}
"#;
        let s1 = parse_file_ast(
            &make_indexed("web/xss.tsx", Language::TypeScript, ts_src),
            &cfg,
        )
        .unwrap();
        let s2 =
            parse_file_ast(&make_indexed("api/app.py", Language::Python, py_src), &cfg).unwrap();
        let s3 = parse_file_ast(&make_indexed("srv/card.go", Language::Go, go_src), &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2, s3]);

        let xss_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "VF-XSS-001")
            .collect();
        assert!(
            xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 6),
            "Partial sanitization DOMPurify + raw must still trigger VF-XSS-001 on line 6: {:?}",
            xss_hits
        );
        assert!(
            !xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 4),
            "Full DOMPurify.sanitize must NOT trigger VF-XSS-001 on line 4: {:?}",
            xss_hits
        );
        assert!(
            xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 9),
            "HTML template response res.send(`<div>${{...}}</div>`) must trigger VF-XSS-001: {:?}",
            xss_hits
        );
        assert!(
            xss_hits.iter().any(|f| f.file == "api/app.py"),
            "Flask render_template_string with request.args must trigger VF-XSS-001: {:?}",
            xss_hits
        );
        assert!(
            xss_hits.iter().any(|f| f.file == "srv/card.go"),
            "Go template.HTML with tainted query input must trigger VF-XSS-001: {:?}",
            xss_hits
        );
    }

    #[test]
    fn test_sprint2_csrf_precision_cookie_vs_bearer_and_exempt() {
        let cfg = ShellMindGuardConfig::default();
        let cookie_app = r#"
app.use(session({ secret: process.env.SESSION_SECRET }));
app.get('/me', requireAuth, (req, res) => res.json({ user: req.session.uid }));
app.post('/transfer', requireAuth, (req, res) => {
    const u = req.session.uid;
    return res.json({ transferred: u });
});
app.post('/webhooks/stripe', (req, res) => res.sendStatus(200));
"#;
        let bearer_api = r#"
function bearerAuth(req: any, res: any, next: any) {
    const hdr = req.headers.authorization;
    if (!hdr) return res.status(401).end();
    next();
}
app.post('/api/v1/orders', bearerAuth, (req, res) => res.json({ ok: true }));
"#;
        let dj_views = r#"
@csrf_exempt
def update_email(request):
    return HttpResponse("ok")
"#;
        let rust_detector_helper = r##"
fn inspect_helper(sym: &mut Sym) {
    let s = "csrf_exempt";
    let doc = r#"@csrf_exempt"#;
    sym.csrf_exempt = false;
}
"##;
        let s_cookie = parse_file_ast(
            &make_indexed("cookie_app.ts", Language::TypeScript, cookie_app),
            &cfg,
        )
        .unwrap();
        let s_dj =
            parse_file_ast(&make_indexed("views.py", Language::Python, dj_views), &cfg).unwrap();
        let s_rust = parse_file_ast(
            &make_indexed("detector.rs", Language::Rust, rust_detector_helper),
            &cfg,
        )
        .unwrap();
        let res_vuln = solve_guard_lattice(&[s_cookie, s_dj, s_rust]);
        assert!(
            !res_vuln
                .findings
                .iter()
                .any(|f| f.file == "detector.rs" && f.rule_id == "VF-CSRF-001"),
            "Rust helper referencing sym.csrf_exempt or quoted literals must NOT trigger VF-CSRF-001: {:?}",
            res_vuln.findings
        );
        let csrf_routes: Vec<&str> = res_vuln
            .findings
            .iter()
            .filter(|f| f.rule_id == "VF-CSRF-001")
            .map(|f| f.entry_route.as_str())
            .collect();
        assert!(
            csrf_routes.contains(&"POST /transfer"),
            "State-changing cookie/session POST /transfer must trigger VF-CSRF-001: {:?}",
            csrf_routes
        );
        assert!(
            csrf_routes.contains(&"update_email"),
            "Django @csrf_exempt view must trigger VF-CSRF-001: {:?}",
            csrf_routes
        );
        assert!(
            !csrf_routes.contains(&"GET /me") && !csrf_routes.contains(&"POST /webhooks/stripe"),
            "GET and webhook endpoints must NOT trigger VF-CSRF-001: {:?}",
            csrf_routes
        );

        let s_bearer = parse_file_ast(
            &make_indexed("bearer_api.ts", Language::TypeScript, bearer_api),
            &cfg,
        )
        .unwrap();
        let res_bearer = solve_guard_lattice(&[s_bearer]);
        assert!(
            !res_bearer
                .findings
                .iter()
                .any(|f| f.rule_id == "VF-CSRF-001"),
            "Stateless Authorization: Bearer API must NOT trigger VF-CSRF-001: {:?}",
            res_bearer.findings
        );
    }

    #[test]
    fn test_sprint2_jwt_logic_flaws() {
        let cfg = ShellMindGuardConfig::default();
        let bad_ts = r#"
export function decodeUnsafe(token: string, key: string) {
    return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}
export function safeVerify(token: string, pubKey: string) {
    return jwt.verify(token, pubKey, { algorithms: ['RS256'] });
}
"#;
        let bad_py = r#"
import jwt
def parse_tok(tok: str):
    return jwt.decode(tok, options={"verify_signature": False})
"#;
        let s1 = parse_file_ast(
            &make_indexed("auth_jwt.ts", Language::TypeScript, bad_ts),
            &cfg,
        )
        .unwrap();
        let s2 =
            parse_file_ast(&make_indexed("auth_jwt.py", Language::Python, bad_py), &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2]);
        let jwt_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "VF-CFG-JWT-LOGIC")
            .collect();
        assert_eq!(
            jwt_hits.len(),
            2,
            "Both alg:none and verify_signature=False must trigger VF-CFG-JWT-LOGIC while safe RS256 does not: {:?}",
            jwt_hits
        );
        assert!(
            jwt_hits
                .iter()
                .all(|f| f.confidence == Confidence::Confirmed)
        );
    }
}
