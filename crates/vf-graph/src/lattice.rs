use crate::ast::{
    FileAstSummary, GuardKind, SinkKind, SymbolInfo, SymbolKind, resolve_import_target,
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
    pub status: String,
    pub entry_route: String,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    pub witness_path: Vec<TraceHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnalysisResult {
    pub parsed_files: usize,
    pub symbol_count: usize,
    pub edge_count: usize,
    pub route_entries: usize,
    pub findings: Vec<LatticeFinding>,
}

/// Global Cross-File Call Graph + O(V + E) Guard-Set Lattice Fixed-Point Solver
pub fn solve_guard_lattice(summaries: &[FileAstSummary]) -> GraphAnalysisResult {
    let mut graph = DiGraph::<SymbolInfo, ()>::new();
    let mut id_to_idx: HashMap<String, NodeIndex> = HashMap::new();
    let mut file_symbol_map: HashMap<(String, String), NodeIndex> = HashMap::new();
    let mut global_name_map: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    let mut known_files: HashSet<String> = HashSet::new();

    for f in summaries {
        known_files.insert(f.rel_path.clone());
        for sym in &f.symbols {
            let idx = graph.add_node(sym.clone());
            id_to_idx.insert(sym.id.clone(), idx);
            file_symbol_map.insert((f.rel_path.clone(), sym.name.clone()), idx);
            global_name_map
                .entry(sym.name.clone())
                .or_default()
                .push(idx);
        }
    }

    // Link cross-file edges via resolved imports + intra-file calls
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
            for callee in &sym.calls {
                if let Some(&dst_idx) = file_symbol_map.get(&(f.rel_path.clone(), callee.clone())) {
                    if src_idx != dst_idx {
                        graph.update_edge(src_idx, dst_idx, ());
                    }
                } else if let Some(target_file) = imported_targets.get(callee)
                    && let Some(&dst_idx) =
                        file_symbol_map.get(&(target_file.clone(), callee.clone()))
                {
                    graph.update_edge(src_idx, dst_idx, ());
                }
            }
        }
    }

    // O(V + E) Worklist Fixed-Point Guard-Set Lattice:
    // G(v) = Intersection_{p in Pred(v)} ( G(p) ) U NodeGuards(v)
    // A node is ONLY guaranteed guarded if EVERY reachable route path passes through the guard!
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

    let mut findings = Vec::new();
    let mut seq = 1usize;

    for idx in graph.node_indices() {
        let vi = idx.index();
        if !reachable[vi] {
            continue;
        }
        let sym = &graph[idx];
        let Some(sink_kind) = sym.sink_kind else {
            continue;
        };
        let active_guards = &guard_out[vi];

        // Check Auth Guard requirement
        if !active_guards.contains(&GuardKind::Auth)
            && let Some((entry_name, witness)) =
                extract_unguarded_witness(&graph, idx, GuardKind::Auth)
        {
            findings.push(LatticeFinding {
                id: format!("VF-AUTH-{:03}", seq),
                rule_id: "VF-AUTH-001".into(),
                severity: "HIGH".into(),
                title: format!("Unauthenticated path to {:?} in `{}`", sink_kind, sym.name),
                status: "SUSPECT_UNGUARDED".into(),
                entry_route: entry_name,
                sink_kind,
                missing_guard: GuardKind::Auth,
                witness_path: witness,
            });
            seq += 1;
        }

        // Check Transaction/Lock Guard requirement on Payment & Balance sinks
        if matches!(
            sink_kind,
            SinkKind::PaymentMutation | SinkKind::BalanceUpdate
        ) && !active_guards.contains(&GuardKind::TxLock)
            && let Some((entry_name, witness)) =
                extract_unguarded_witness(&graph, idx, GuardKind::TxLock)
        {
            findings.push(LatticeFinding {
                id: format!("VF-RACE-{:03}", seq),
                rule_id: "VF-RACE-001".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Missing transaction/lock guard before `{}` (Double-Spend Risk)",
                    sym.name
                ),
                status: "SUSPECT_UNGUARDED".into(),
                entry_route: entry_name,
                sink_kind,
                missing_guard: GuardKind::TxLock,
                witness_path: witness,
            });
            seq += 1;
        }
    }

    // Deduplicate findings on the same (entry_route, rule_id), keeping the deepest witness chain,
    // and assign 100% deterministic sequential IDs sorted by (entry_route, rule_id).
    let mut best_by_key: HashMap<(String, String), LatticeFinding> = HashMap::new();
    for f in findings {
        let key = (f.entry_route.clone(), f.rule_id.clone());
        match best_by_key.get(&key) {
            Some(prev) if prev.witness_path.len() >= f.witness_path.len() => {}
            _ => {
                best_by_key.insert(key, f);
            }
        }
    }
    let mut deduped: Vec<LatticeFinding> = best_by_key.into_values().collect();
    deduped.sort_by(|a, b| {
        a.entry_route
            .cmp(&b.entry_route)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    for (i, item) in deduped.iter_mut().enumerate() {
        let prefix = match item.missing_guard {
            GuardKind::Auth => "VF-AUTH",
            GuardKind::TxLock => "VF-RACE",
        };
        item.id = format!("{}-{:03}", prefix, i + 1);
    }

    GraphAnalysisResult {
        parsed_files: summaries.len(),
        symbol_count: graph.node_count(),
        edge_count: graph.edge_count(),
        route_entries,
        findings: deduped,
    }
}

fn extract_unguarded_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    sink: NodeIndex,
    missing_guard: GuardKind,
) -> Option<(String, Vec<TraceHop>)> {
    // Reverse BFS from sink to any Route entry avoiding nodes that contain `missing_guard`
    let mut visited = HashSet::new();
    let mut parent_map: HashMap<NodeIndex, NodeIndex> = HashMap::new();
    let mut q = VecDeque::new();

    if graph[sink].guards.contains(&missing_guard) {
        return None;
    }
    visited.insert(sink);
    q.push_back(sink);

    let mut found_entry = None;
    while let Some(curr) = q.pop_front() {
        if graph[curr].kind == SymbolKind::Route {
            found_entry = Some(curr);
            break;
        }
        for pred in graph.neighbors_directed(curr, Direction::Incoming) {
            if !visited.contains(&pred) && !graph[pred].guards.contains(&missing_guard) {
                visited.insert(pred);
                parent_map.insert(pred, curr);
                q.push_back(pred);
            }
        }
    }

    let entry = found_entry?;
    let entry_name = graph[entry].name.clone();
    let mut hops = Vec::new();
    let mut cur = Some(entry);
    while let Some(n) = cur {
        let s = &graph[n];
        hops.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        cur = parent_map.get(&n).copied();
    }
    Some((entry_name, hops))
}
