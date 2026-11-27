//! Unified formal verification core shared across `smg-graph`, `phase9`, `smg-hw`, and `smg-web3`
//! (`Phase 3 / Q71, Q73, Q137`).
//!
//! Consolidates:
//! - `domains`: `Tnum`, `WrappedInterval`, `SparseOctagon`
//! - `PointerAliasUnionFind`: Steensgaard $O(n \alpha(n))$ pointer equivalence classes
//! - `CdclSolver`: Compact pure-Rust DPLL/CDCL SAT core for disjunctive boolean feasibility
//! - `smt` / `smt_advanced`: `PathConstraint`, `BvBitState`, `LinearIneq`, `ArrayConstraint`

pub mod domains;

pub use crate::smt::{
    CmpOp, PathConstraint, SmtVerdict, emit_smtlib2, extract_path_constraints_to_line,
    is_line_reachable, is_z3_available, parse_condition_expr, solve_path_constraints,
};
pub use crate::smt_advanced::{
    ArrayConstraint, BvBitState, BvConstraint, LinearIneq, check_interprocedural_feasibility,
    solve_array_constraints, solve_bv_constraints, solve_lia_constraints,
};
pub use domains::{SparseOctagon, Tnum, WrappedInterval};

use std::collections::HashMap;

/// Disjoint-set pointer equivalence classes (Steensgaard O(n * alpha(n)) pass) shared by
/// `smg-hw` (DMA/__user aliases) and `smg-graph::phase9::mem_typestate` (C/C++/Rust UAF aliasing).
#[derive(Debug, Default, Clone)]
pub struct PointerAliasUnionFind {
    parent: Vec<usize>,
    names: HashMap<String, usize>,
}

impl PointerAliasUnionFind {
    pub fn intern(&mut self, name: &str) -> usize {
        if let Some(&id) = self.names.get(name) {
            return id;
        }
        let id = self.parent.len();
        self.parent.push(id);
        self.names.insert(name.to_string(), id);
        id
    }

    pub fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    pub fn union_names(&mut self, a: &str, b: &str) {
        let ia = self.intern(a);
        let ib = self.intern(b);
        let ra = self.find(ia);
        let rb = self.find(ib);
        if ra != rb {
            self.parent[rb] = ra;
        }
    }

    pub fn same_alias(&mut self, a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        if let (Some(&ia), Some(&ib)) = (self.names.get(a), self.names.get(b)) {
            return self.find(ia) == self.find(ib);
        }
        false
    }
}

/// Compact pure-Rust DPLL/CDCL SAT core with unit propagation and bounded search budget
/// (`Phase 3 / Q73`) for disjunctive path-feasibility queries without external Z3 dependency.
#[derive(Debug, Default, Clone)]
pub struct CdclSolver {
    num_vars: usize,
    clauses: Vec<Vec<i32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatStatus {
    Sat,
    Unsat,
    BudgetExceeded,
}

impl CdclSolver {
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            clauses: Vec::new(),
        }
    }

    /// Adds a CNF clause of signed 1-based literals (`+v` = true, `-v` = false).
    pub fn add_clause(&mut self, clause: Vec<i32>) {
        self.clauses.push(clause);
    }

    pub fn solve_bounded(&self, max_steps: usize) -> SatStatus {
        let mut assignment = vec![None; self.num_vars + 1];
        let mut steps = 0usize;
        self.dpll(&mut assignment, &mut steps, max_steps)
    }

    fn dpll(&self, assign: &mut [Option<bool>], steps: &mut usize, max_steps: usize) -> SatStatus {
        *steps = steps.saturating_add(1);
        if *steps > max_steps {
            return SatStatus::BudgetExceeded;
        }

        // Unit propagation loop
        let mut trail: Vec<usize> = Vec::new();
        loop {
            let mut propagated = false;
            for clause in &self.clauses {
                let mut sat = false;
                let mut unassigned_lit: Option<i32> = None;
                let mut unassigned_count = 0usize;

                for &lit in clause {
                    let var = lit.unsigned_abs() as usize;
                    if var == 0 || var >= assign.len() {
                        continue;
                    }
                    match assign[var] {
                        Some(val) if val == (lit > 0) => {
                            sat = true;
                            break;
                        }
                        Some(_) => {}
                        None => {
                            unassigned_lit = Some(lit);
                            unassigned_count += 1;
                        }
                    }
                }
                if sat {
                    continue;
                }
                if unassigned_count == 0 {
                    for v in trail {
                        assign[v] = None;
                    }
                    return SatStatus::Unsat;
                }
                if unassigned_count == 1
                    && let Some(lit) = unassigned_lit
                {
                    let var = lit.unsigned_abs() as usize;
                    assign[var] = Some(lit > 0);
                    trail.push(var);
                    propagated = true;
                }
            }
            if !propagated {
                break;
            }
        }

        // Pick first unassigned variable
        let next_var = (1..assign.len()).find(|&v| assign[v].is_none());
        let Some(var) = next_var else {
            return SatStatus::Sat;
        };

        for branch in [true, false] {
            assign[var] = Some(branch);
            let res = self.dpll(assign, steps, max_steps);
            if res != SatStatus::Unsat {
                return res;
            }
        }

        assign[var] = None;
        for v in trail {
            assign[v] = None;
        }
        SatStatus::Unsat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdcl_proves_unsat_and_sat_cnf() {
        // (x1 OR x2) AND (!x1 OR x2) AND (!x2) -> UNSAT
        let mut unsat = CdclSolver::new(2);
        unsat.add_clause(vec![1, 2]);
        unsat.add_clause(vec![-1, 2]);
        unsat.add_clause(vec![-2]);
        assert_eq!(unsat.solve_bounded(1000), SatStatus::Unsat);

        // (x1 OR x2) AND (!x1 OR x3) AND (!x2) -> SAT (x1=T, x2=F, x3=T)
        let mut sat = CdclSolver::new(3);
        sat.add_clause(vec![1, 2]);
        sat.add_clause(vec![-1, 3]);
        sat.add_clause(vec![-2]);
        assert_eq!(sat.solve_bounded(1000), SatStatus::Sat);
    }

    #[test]
    fn shared_pointer_alias_union_find_merges_transitively() {
        let mut uf = PointerAliasUnionFind::default();
        uf.union_names("p", "q");
        uf.union_names("q", "r");
        assert!(uf.same_alias("p", "r"));
        assert!(!uf.same_alias("p", "other"));
    }
}
