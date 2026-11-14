use crate::ast::{
    FileAstSummary, GuardKind, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    resolve_import_target,
};
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
        GuardKind::OwnershipCheck => "VF-IDOR",
        GuardKind::SecretPolicy => "VF-SEC",
        GuardKind::ConfigPolicy => "VF-CFG",
        GuardKind::DependencyPolicy => "VF-DEP",
        GuardKind::FrontendContract => "VF-FE",
    }
}

/// Global Cross-File Call Graph + True O(V + E) Guard-Set Lattice, Taint & 6-Layer Witness Solver
pub fn solve_guard_lattice_with_public(
    summaries: &[FileAstSummary],
    public_routes: &[String],
) -> GraphAnalysisResult {
    let mut graph = DiGraph::<SymbolInfo, ()>::new();
    let mut id_to_idx: HashMap<String, NodeIndex> = HashMap::new();
    let mut file_symbol_map: HashMap<(String, String), NodeIndex> = HashMap::new();
    let mut go_exported_map: HashMap<String, NodeIndex> = HashMap::new();
    let mut known_files: HashSet<String> = HashSet::new();

    for f in summaries {
        known_files.insert(f.rel_path.clone());
        let is_go = f.rel_path.ends_with(".go");
        for sym in &f.symbols {
            let idx = graph.add_node(sym.clone());
            id_to_idx.insert(sym.id.clone(), idx);
            file_symbol_map.insert((f.rel_path.clone(), sym.name.clone()), idx);
            if is_go && sym.name.chars().next().is_some_and(|c| c.is_uppercase()) {
                go_exported_map.entry(sym.name.clone()).or_insert(idx);
            }
        }
    }

    // B11: O(1) edge deduplication via HashSet<(usize, usize)> instead of petgraph::update_edge O(deg)
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut resolved_callee_map: HashMap<(usize, String), NodeIndex> = HashMap::new();

    for f in summaries {
        let mut imported_targets: HashMap<String, String> = HashMap::new();
        for imp in &f.imports {
            if let Some(target_file) =
                resolve_import_target(&f.rel_path, &imp.from_specifier, &known_files)
            {
                imported_targets.insert(imp.symbol_name.clone(), target_file);
            }
        }

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
                let dst_opt = file_symbol_map
                    .get(&(f.rel_path.clone(), callee.clone()))
                    .copied()
                    .or_else(|| {
                        imported_targets
                            .get(callee)
                            .and_then(|tf| file_symbol_map.get(&(tf.clone(), callee.clone())))
                            .copied()
                    })
                    .or_else(|| {
                        if f.rel_path.ends_with(".go") {
                            go_exported_map.get(callee).copied()
                        } else {
                            None
                        }
                    });
                if let Some(dst_idx) = dst_opt
                    && src_idx != dst_idx
                {
                    resolved_callee_map.insert((src_idx.index(), callee.clone()), dst_idx);
                    if seen_edges.insert((src_idx.index(), dst_idx.index())) {
                        graph.add_edge(src_idx, dst_idx, ());
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

    // O(V + E) Taint Propagation across function boundaries (`tainted_calls` -> `param_forwarding_calls`)
    let mut taint_parents: Vec<Option<NodeIndex>> = vec![None; node_count];
    let mut taint_q = VecDeque::new();
    for u in graph.node_indices() {
        for callee in &graph[u].tainted_calls {
            if let Some(&v) = resolved_callee_map.get(&(u.index(), callee.clone()))
                && taint_parents[v.index()].is_none()
            {
                taint_parents[v.index()] = Some(u);
                taint_q.push_back(v);
            }
        }
    }
    while let Some(w) = taint_q.pop_front() {
        for callee in graph[w]
            .tainted_calls
            .iter()
            .chain(graph[w].param_forwarding_calls.iter())
        {
            if let Some(&next_v) = resolved_callee_map.get(&(w.index(), callee.clone()))
                && taint_parents[next_v.index()].is_none()
            {
                taint_parents[next_v.index()] = Some(w);
                taint_q.push_back(next_v);
            }
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
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::TxLock,
                        witness_path: witness,
                        remediation: remediation_for_guard(GuardKind::TxLock).into(),
                    },
                );
            }
        }

        // Layer 2a: Intra-procedural Injection / Path / SSRF hits (`Source -> Sink` inside node)
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
                    entry_route,
                    sink_kind: hit.sink_kind,
                    missing_guard: hit.missing_guard,
                    witness_path: witness,
                    remediation: hit.remediation.clone(),
                },
            );
        }

        // Layer 2b: Cross-file / Inter-procedural Taint (`Source -> param_forwarding -> ParamSink`)
        if taint_parents[vi].is_some() {
            for hit in &sym.param_sinks {
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
            && let Some((entry_name, mut witness)) =
                reconstruct_witness(&graph, &route_parents, idx)
            && !is_public_route(&entry_name, public_routes)
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
                    entry_route: entry_name,
                    sink_kind: SinkKind::IdorDbAccess,
                    missing_guard: GuardKind::OwnershipCheck,
                    witness_path: witness,
                    remediation: remediation_for_guard(GuardKind::OwnershipCheck).into(),
                },
            );
        }
    }

    // Layer 2d: Frontend <-> Backend API Contract Check (`VF-FE-404`)
    if route_entries > 0 {
        let mut all_prefixes: Vec<String> = Vec::new();
        for f in summaries {
            for p in &f.route_prefixes {
                if !all_prefixes.iter().any(|x| x == p) {
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

    let mut tier1_counts: HashMap<&'static str, usize> = HashMap::new();
    for (i, item) in deduped.iter_mut().enumerate() {
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
        if matches!(item.missing_guard, GuardKind::Auth | GuardKind::TxLock) {
            item.id = format!("{}-{:03}", prefix, i + 1);
        } else {
            let c = tier1_counts.entry(prefix).or_insert(0);
            *c += 1;
            item.id = format!("{}-{:03}", prefix, *c);
        }
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

/// Single O(V + E) multi-source forward BFS from ALL `Route` entries (unblocked by guards).
fn build_any_route_bfs_tree(graph: &DiGraph<SymbolInfo, ()>) -> Vec<Option<NodeIndex>> {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut q = VecDeque::new();
    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route {
            parent[idx.index()] = Some(idx);
            q.push_back(idx);
        }
    }
    while let Some(u) = q.pop_front() {
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() {
                parent[vi] = Some(u);
                q.push_back(v);
            }
        }
    }
    parent
}

fn reconstruct_taint_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    taint_parents: &[Option<NodeIndex>],
    route_parents: &[Option<NodeIndex>],
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
/// Returns `parent[node] = Some(prev_node)` (with `Some(node)` for root Routes).
fn build_unguarded_bfs_tree(
    graph: &DiGraph<SymbolInfo, ()>,
    guard: GuardKind,
) -> Vec<Option<NodeIndex>> {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut q = VecDeque::new();

    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route && !graph[idx].guards.contains(&guard) {
            parent[idx.index()] = Some(idx);
            q.push_back(idx);
        }
    }

    while let Some(u) = q.pop_front() {
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() && !graph[v].guards.contains(&guard) {
                parent[vi] = Some(u);
                q.push_back(v);
            }
        }
    }
    parent
}

fn reconstruct_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    parent: &[Option<NodeIndex>],
    sink: NodeIndex,
) -> Option<(String, Vec<TraceHop>)> {
    parent[sink.index()]?;
    let mut rev_hops = Vec::new();
    let mut cur = sink;
    let mut steps = 0usize;
    let max_steps = graph.node_count().min(64);
    let entry_name;

    loop {
        let s = &graph[cur];
        rev_hops.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        let p = parent[cur.index()]?;
        if p == cur {
            entry_name = s.name.clone();
            break;
        }
        steps += 1;
        if steps >= max_steps {
            // Walk directly to root entry name without blowing memory on huge chains
            let mut root_cur = p;
            while let Some(np) = parent[root_cur.index()] {
                if np == root_cur {
                    break;
                }
                root_cur = np;
            }
            entry_name = graph[root_cur].name.clone();
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
    use vf_core::{IndexedFile, Language, VeriForgeConfig};

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

        let cfg = VeriForgeConfig::default();
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
}
