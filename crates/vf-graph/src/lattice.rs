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

/// Global Cross-File Call Graph + True O(V + E) Guard-Set Lattice & Witness Solver
pub fn solve_guard_lattice(summaries: &[FileAstSummary]) -> GraphAnalysisResult {
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
                    && seen_edges.insert((src_idx.index(), dst_idx.index()))
                {
                    graph.add_edge(src_idx, dst_idx, ());
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

    // Deduplicate on the fly by (entry_route, rule_id) to avoid quadratic temporary Vec allocation
    let mut best_by_key: HashMap<(String, String), LatticeFinding> = HashMap::new();

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

        if !active_guards.contains(&GuardKind::Auth)
            && let Some((entry_name, witness)) = reconstruct_witness(&graph, &auth_parents, idx)
        {
            let key = (entry_name.clone(), "VF-AUTH-001".to_string());
            let replace = match best_by_key.get(&key) {
                Some(prev) => witness.len() < prev.witness_path.len(),
                None => true,
            };
            if replace {
                best_by_key.insert(
                    key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "VF-AUTH-001".into(),
                        severity: "HIGH".into(),
                        title: format!("Unauthenticated path to {:?} in `{}`", sink_kind, sym.name),
                        status: "SUSPECT_UNGUARDED".into(),
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::Auth,
                        witness_path: witness,
                    },
                );
            }
        }

        if matches!(
            sink_kind,
            SinkKind::PaymentMutation | SinkKind::BalanceUpdate
        ) && !active_guards.contains(&GuardKind::TxLock)
            && let Some((entry_name, witness)) = reconstruct_witness(&graph, &lock_parents, idx)
        {
            let key = (entry_name.clone(), "VF-RACE-001".to_string());
            let replace = match best_by_key.get(&key) {
                Some(prev) => witness.len() < prev.witness_path.len(),
                None => true,
            };
            if replace {
                best_by_key.insert(
                    key,
                    LatticeFinding {
                        id: String::new(),
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
                    },
                );
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
    use std::time::Instant;

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
            });
        }
        let summaries = vec![FileAstSummary {
            rel_path: "a.ts".into(),
            imports: Vec::new(),
            symbols,
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
}
