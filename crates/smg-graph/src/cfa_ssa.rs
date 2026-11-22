//! Phase 27B: Context-Sensitive k-CFA (k=2) + Field-Sensitive Andersen Points-To + SSA Phi-Node Def-Use.
//!
//! Eliminates three classic classes of static-analysis false positives & false negatives:
//! 1. **k-CFA (k=2) Call-String Context Sensitivity:** Prevents taint/guard leakage between
//!    unrelated callers sharing a common helper/wrapper function.
//! 2. **Andersen Field-Sensitive Points-To Graph:** Isolates `obj.safe_field` from `obj.tainted_field`
//!    even across multi-hop object aliases (`let b = a; b.tainted = req.q; sink(a.safe)` -> CLEAN!).
//! 3. **SSA Phi-Node Def-Use Versioning:** Tracks exact branch merges (`x_3 = phi(x_1, x_2)`) and
//!    post-sanitization reassignments (`x_2 = req.body`) with zero-hallucination precision.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// ============================================================================
// 1. Context-Sensitive Call-String (k-CFA, k=2)
// ============================================================================

/// Bounded length-2 call-string context `[immediate_caller, grand_caller]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CallString2 {
    pub caller: Option<u32>,
    pub grand_caller: Option<u32>,
}

impl CallString2 {
    pub fn push(self, new_caller: u32) -> Self {
        Self {
            caller: Some(new_caller),
            grand_caller: self.caller,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextKey {
    pub func_id: u32,
    pub ctx: CallString2,
}

/// Context-sensitive guard & taint summary table indexed by `(func_id, CallString2)`.
#[derive(Debug, Default, Clone)]
pub struct KCfaContextTable {
    /// `ContextKey -> (guard_bitset, param_taint_mask)`
    pub states: HashMap<ContextKey, (u32, u32)>,
}

impl KCfaContextTable {
    /// Propagates `(caller_guards, arg_taint_mask)` into `callee` under `ctx.push(caller)`.
    /// Returns `true` if the context-sensitive state changed (for worklist fixpoint).
    pub fn propagate_call(
        &mut self,
        caller: u32,
        caller_ctx: CallString2,
        callee: u32,
        caller_guards: u32,
        arg_taint_mask: u32,
    ) -> (ContextKey, bool) {
        let key = ContextKey {
            func_id: callee,
            ctx: caller_ctx.push(caller),
        };
        match self.states.get_mut(&key) {
            None => {
                self.states.insert(key, (caller_guards, arg_taint_mask));
                (key, true)
            }
            Some((g, t)) => {
                let new_g = *g & caller_guards; // must-guard intersection
                let new_t = *t | arg_taint_mask; // may-taint union
                if new_g != *g || new_t != *t {
                    *g = new_g;
                    *t = new_t;
                    (key, true)
                } else {
                    (key, false)
                }
            }
        }
    }

    pub fn get(&self, key: &ContextKey) -> Option<(u32, u32)> {
        self.states.get(key).copied()
    }
}

// ============================================================================
// 2. Field-Sensitive Andersen Points-To & Alias Graph
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllocSite(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointsToStmt {
    /// `var = new Object()` at `site`
    Alloc { var: String, site: AllocSite },
    /// `dst = src` (pointer alias copy)
    Copy { dst: String, src: String },
    /// `base.field = taint_bits` (field store; strong update if singleton points-to!)
    StoreFieldTaint {
        base: String,
        field: String,
        taint_bits: u32,
    },
    /// `dst = base.field` (field load into scalar taint)
    LoadFieldTaint {
        dst: String,
        base: String,
        field: String,
    },
    /// `base.field = sanitize(base.field, clear_bits)`
    SanitizeField {
        base: String,
        field: String,
        clear_bits: u32,
    },
}

#[derive(Debug, Default, Clone)]
pub struct FieldSensitivePointsTo {
    /// `var -> set of allocation sites`
    pub pts: HashMap<String, BTreeSet<AllocSite>>,
    /// `(alloc_site, field_name) -> taint bitmask`
    pub field_taint: HashMap<(AllocSite, String), u32>,
    /// `scalar_var -> taint bitmask`
    pub scalar_taint: HashMap<String, u32>,
}

impl FieldSensitivePointsTo {
    /// Solves Andersen inclusion constraints (`pts(src) ⊆ pts(dst)`) to fixpoint,
    /// then propagates field-sensitive taint with singleton strong-update precision.
    pub fn solve(stmts: &[PointsToStmt]) -> Self {
        let mut state = Self::default();

        // Phase 1: Andersen points-to fixpoint
        for st in stmts {
            if let PointsToStmt::Alloc { var, site } = st {
                state.pts.entry(var.clone()).or_default().insert(*site);
            }
        }
        loop {
            let mut changed = false;
            for st in stmts {
                if let PointsToStmt::Copy { dst, src } = st
                    && let Some(src_set) = state.pts.get(src).cloned()
                {
                    let dst_set = state.pts.entry(dst.clone()).or_default();
                    for site in src_set {
                        if dst_set.insert(site) {
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Phase 2: Flow-ordered field-sensitive taint & singleton strong-update sanitization
        for st in stmts {
            match st {
                PointsToStmt::StoreFieldTaint {
                    base,
                    field,
                    taint_bits,
                } => {
                    if let Some(sites) = state.pts.get(base) {
                        let is_singleton = sites.len() == 1;
                        for &site in sites {
                            let entry = state.field_taint.entry((site, field.clone())).or_insert(0);
                            if is_singleton {
                                *entry = *taint_bits; // strong update
                            } else {
                                *entry |= *taint_bits; // sound weak update
                            }
                        }
                    }
                }
                PointsToStmt::SanitizeField {
                    base,
                    field,
                    clear_bits,
                } => {
                    if let Some(sites) = state.pts.get(base)
                        && sites.len() == 1
                        && let Some(&site) = sites.iter().next()
                        && let Some(entry) = state.field_taint.get_mut(&(site, field.clone()))
                    {
                        *entry &= !*clear_bits;
                    }
                }
                PointsToStmt::LoadFieldTaint { dst, base, field } => {
                    let mut acc = 0u32;
                    if let Some(sites) = state.pts.get(base) {
                        for &site in sites {
                            acc |= state
                                .field_taint
                                .get(&(site, field.clone()))
                                .copied()
                                .unwrap_or(0);
                        }
                    }
                    state.scalar_taint.insert(dst.clone(), acc);
                }
                PointsToStmt::Alloc { .. } | PointsToStmt::Copy { .. } => {}
            }
        }

        state
    }

    pub fn query_field_taint(&self, var: &str, field: &str) -> u32 {
        self.pts
            .get(var)
            .map(|sites| {
                sites.iter().fold(0u32, |acc, &site| {
                    acc | self
                        .field_taint
                        .get(&(site, field.to_string()))
                        .copied()
                        .unwrap_or(0)
                })
            })
            .unwrap_or(0)
    }
}

// ============================================================================
// 3. SSA Phi-Node Def-Use Versioning & Sanitizer Revocation
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaOp {
    /// Direct taint assignment (`v_k = source_taint`)
    AssignTaint(u32),
    /// Copy from another SSA version (`v_k = src`)
    Copy(SsaVar),
    /// Sanitize an SSA version (`v_k = src & !clear_bits`)
    Sanitize { src: SsaVar, clear_bits: u32 },
    /// Control-flow merge Phi-node (`v_k = phi(v_a, v_b, ...)`)
    Phi(Vec<SsaVar>),
}

#[derive(Debug, Default, Clone)]
pub struct SsaDefUseGraph {
    next_ver: HashMap<String, u32>,
    pub defs: BTreeMap<(String, u32), SsaOp>,
}

impl SsaDefUseGraph {
    pub fn define(&mut self, name: &str, op: SsaOp) -> SsaVar {
        let v = self.next_ver.entry(name.to_string()).or_insert(0);
        let ver = *v;
        *v += 1;
        self.defs.insert((name.to_string(), ver), op);
        SsaVar {
            name: name.to_string(),
            version: ver,
        }
    }

    /// Evaluates exact taint bitmask for every SSA version to fixpoint (handles cyclic loop phis!).
    pub fn solve_taint(&self) -> HashMap<SsaVar, u32> {
        let mut taint: HashMap<SsaVar, u32> = HashMap::new();
        for (name, ver) in self.defs.keys() {
            taint.insert(
                SsaVar {
                    name: name.clone(),
                    version: *ver,
                },
                0,
            );
        }

        let max_iters = self.defs.len().saturating_mul(2).max(4);
        for _ in 0..max_iters {
            let mut changed = false;
            for ((name, ver), op) in &self.defs {
                let key = SsaVar {
                    name: name.clone(),
                    version: *ver,
                };
                let val = match op {
                    SsaOp::AssignTaint(bits) => *bits,
                    SsaOp::Copy(src) => taint.get(src).copied().unwrap_or(0),
                    SsaOp::Sanitize { src, clear_bits } => {
                        taint.get(src).copied().unwrap_or(0) & !*clear_bits
                    }
                    SsaOp::Phi(inputs) => inputs
                        .iter()
                        .fold(0u32, |acc, inp| acc | taint.get(inp).copied().unwrap_or(0)),
                };
                let cur = taint.get(&key).copied().unwrap_or(0);
                if val != cur {
                    taint.insert(key, val);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        taint
    }

    /// Detects whether a variable was sanitized at an earlier SSA version and later
    /// had taint re-introduced via reassignment (SSA sanitizer revocation).
    pub fn has_sanitizer_revocation(&self, var_name: &str) -> bool {
        let taint = self.solve_taint();
        let mut versions: Vec<u32> = self
            .defs
            .keys()
            .filter(|(n, _)| n == var_name)
            .map(|(_, v)| *v)
            .collect();
        versions.sort_unstable();
        let mut saw_sanitized_clean = false;
        let mut seen_versions: HashSet<u32> = HashSet::new();
        for v in versions {
            if !seen_versions.insert(v) {
                continue;
            }
            let key = SsaVar {
                name: var_name.to_string(),
                version: v,
            };
            let t = taint.get(&key).copied().unwrap_or(0);
            if matches!(
                self.defs.get(&(var_name.to_string(), v)),
                Some(SsaOp::Sanitize { .. })
            ) && t == 0
            {
                saw_sanitized_clean = true;
            } else if saw_sanitized_clean && t != 0 {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_cfa_isolates_unrelated_callers_of_shared_helper() {
        let mut tbl = KCfaContextTable::default();
        const AUTH_GUARD: u32 = 0b0001;
        const SQL_TAINT: u32 = 0b0010;
        let root_ctx = CallString2::default();

        // Caller 1 (safe_route): has AUTH_GUARD, clean args -> calls helper (id=10)
        let (k_safe, _) = tbl.propagate_call(1, root_ctx, 10, AUTH_GUARD, 0);
        // Caller 2 (vuln_route): NO auth guard, SQL_TAINT arg -> calls helper (id=10)
        let (k_vuln, _) = tbl.propagate_call(2, root_ctx, 10, 0, SQL_TAINT);

        assert_ne!(k_safe, k_vuln);
        assert_eq!(tbl.get(&k_safe), Some((AUTH_GUARD, 0)));
        assert_eq!(tbl.get(&k_vuln), Some((0, SQL_TAINT)));
    }

    #[test]
    fn field_sensitive_points_to_isolates_fields_across_aliases() {
        const SQL_TAINT: u32 = 0b0001;
        let stmts = vec![
            PointsToStmt::Alloc {
                var: "req".into(),
                site: AllocSite(1),
            },
            PointsToStmt::Copy {
                dst: "alias".into(),
                src: "req".into(),
            },
            PointsToStmt::StoreFieldTaint {
                base: "alias".into(),
                field: "username".into(),
                taint_bits: SQL_TAINT,
            },
            PointsToStmt::StoreFieldTaint {
                base: "alias".into(),
                field: "role_id".into(),
                taint_bits: 0,
            },
            PointsToStmt::LoadFieldTaint {
                dst: "out_name".into(),
                base: "req".into(),
                field: "username".into(),
            },
            PointsToStmt::LoadFieldTaint {
                dst: "out_safe".into(),
                base: "req".into(),
                field: "role_id".into(),
            },
        ];

        let res = FieldSensitivePointsTo::solve(&stmts);
        // Taint propagates through alias -> req.username
        assert_eq!(res.query_field_taint("req", "username"), SQL_TAINT);
        assert_eq!(res.scalar_taint.get("out_name"), Some(&SQL_TAINT));
        // Unrelated field `role_id` stays 100% CLEAN (zero field pollution!)
        assert_eq!(res.query_field_taint("req", "role_id"), 0);
        assert_eq!(res.scalar_taint.get("out_safe"), Some(&0));
    }

    #[test]
    fn ssa_phi_node_handles_partial_vs_full_sanitization_and_revocation() {
        const XSS: u32 = 0b0100;
        let mut g = SsaDefUseGraph::default();
        let x0 = g.define("x", SsaOp::AssignTaint(XSS));
        let x1 = g.define(
            "x",
            SsaOp::Sanitize {
                src: x0.clone(),
                clear_bits: XSS,
            },
        );
        // Partial merge: only 1 branch sanitized -> still tainted!
        let x_partial = g.define("x_m", SsaOp::Phi(vec![x1.clone(), x0.clone()]));
        // Full merge: both branches sanitized -> clean!
        let x2 = g.define(
            "x",
            SsaOp::Sanitize {
                src: x0,
                clear_bits: XSS,
            },
        );
        let x_full = g.define("x_clean", SsaOp::Phi(vec![x1, x2]));
        // Later reassignment revokes sanitization
        let _x3 = g.define("x", SsaOp::AssignTaint(XSS));

        let taint = g.solve_taint();
        assert_eq!(taint[&x_partial], XSS);
        assert_eq!(taint[&x_full], 0);
        assert!(g.has_sanitizer_revocation("x"));
    }
}
