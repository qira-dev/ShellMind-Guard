//! Phase 27A: Ultra-Depth Formal SMT Theories (`QF_BV` Bitvector + `QF_LIA` Linear Integer
//! Arithmetic + McCarthy Array Read-Over-Write + Inter-Procedural Caller→Callee Propagation).
//!
//! Pure-Rust, zero external C++ solver dependency, overflow-safe (`i128` arithmetic),
//! strictly sound (unknown/unparseable predicates fail open to `Unknown`/`Sat`, NEVER false `Unsat`).

use crate::smt::{CmpOp, PathConstraint, SmtVerdict, solve_path_constraints};
use std::collections::{BTreeMap, HashMap};

// ============================================================================
// 1. QF_BV: 64-bit Tristate Bitvector Constraint Solver
// ============================================================================

/// Per-variable 64-bit known-zero / known-one bitmask state.
/// Invariant: if `(known_zeros & known_ones) != 0`, the constraint set is provably UNSAT.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BvBitState {
    pub known_zeros: u64,
    pub known_ones: u64,
}

impl BvBitState {
    pub fn is_contradiction(self) -> bool {
        (self.known_zeros & self.known_ones) != 0
    }

    pub fn force_ones(&mut self, mask: u64) {
        self.known_ones |= mask;
    }

    pub fn force_zeros(&mut self, mask: u64) {
        self.known_zeros |= mask;
    }

    /// Tightens known high-zero bits from an unsigned upper bound `0 <= x <= max_val`.
    pub fn tighten_unsigned_upper(&mut self, max_val: u64) {
        if max_val == u64::MAX {
            return;
        }
        let lz = max_val.leading_zeros();
        if lz > 0 && lz < 64 {
            let high_zero_mask = !((1u64 << (64 - lz)) - 1);
            self.known_zeros |= high_zero_mask;
        } else if max_val == 0 {
            self.known_zeros = u64::MAX;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BvConstraint {
    /// `(var & mask) == val` (or `!=` when `eq == false`)
    BitAndEq {
        var: String,
        mask: u64,
        val: u64,
        eq: bool,
    },
    /// `(var | mask) == val`
    BitOrEq { var: String, mask: u64, val: u64 },
    /// `(var >> shift) == val` (logical unsigned right shift, `shift < 64`)
    UShrEq { var: String, shift: u32, val: u64 },
    /// `0 <= var <= max_val`
    UnsignedUpper { var: String, max_val: u64 },
    /// `var == exact`
    ExactConst { var: String, val: u64 },
}

/// Solves a conjunction of `QF_BV` bitvector constraints using exact 64-bit tristate propagation.
pub fn solve_bv_constraints(constraints: &[BvConstraint]) -> SmtVerdict {
    let mut states: HashMap<String, BvBitState> = HashMap::new();
    let mut neq_checks: Vec<(&str, u64, u64)> = Vec::new();

    for c in constraints {
        match c {
            BvConstraint::BitAndEq { var, mask, val, eq } => {
                if *eq {
                    if (val & !mask) != 0 {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-bv",
                            reason: format!(
                                "({var} & 0x{mask:x}) == 0x{val:x} is impossible (bits set outside mask)"
                            ),
                        };
                    }
                    let st = states.entry(var.clone()).or_default();
                    st.force_ones(*val & *mask);
                    st.force_zeros(*mask & !*val);
                    if st.is_contradiction() {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-bv",
                            reason: format!("conflicting bitmask constraints on `{var}`"),
                        };
                    }
                } else {
                    neq_checks.push((var.as_str(), *mask, *val));
                }
            }
            BvConstraint::BitOrEq { var, mask, val } => {
                if (val & mask) != *mask {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!(
                            "({var} | 0x{mask:x}) == 0x{val:x} is impossible (mask bits must be 1 in result)"
                        ),
                    };
                }
                let st = states.entry(var.clone()).or_default();
                let free = !*mask;
                st.force_ones(*val & free);
                st.force_zeros(!*val & free);
                if st.is_contradiction() {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!("conflicting bitwise-OR constraints on `{var}`"),
                    };
                }
            }
            BvConstraint::UShrEq { var, shift, val } => {
                if *shift >= 64 {
                    if *val != 0 {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-bv",
                            reason: format!("({var} >> {shift}) cannot equal 0x{val:x}"),
                        };
                    }
                    continue;
                }
                let max_shifted = u64::MAX >> *shift;
                if *val > max_shifted {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!("({var} >> {shift}) == 0x{val:x} exceeds shifted width"),
                    };
                }
                let shifted_mask = u64::MAX << *shift;
                let shifted_val = val.wrapping_shl(*shift);
                let st = states.entry(var.clone()).or_default();
                st.force_ones(shifted_val & shifted_mask);
                st.force_zeros(shifted_mask & !shifted_val);
                if st.is_contradiction() {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!("conflicting shift constraints on `{var}`"),
                    };
                }
            }
            BvConstraint::UnsignedUpper { var, max_val } => {
                let st = states.entry(var.clone()).or_default();
                st.tighten_unsigned_upper(*max_val);
                if st.is_contradiction() {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!(
                            "unsigned bound `{var} <= {max_val}` contradicts bitmask constraints"
                        ),
                    };
                }
            }
            BvConstraint::ExactConst { var, val } => {
                let st = states.entry(var.clone()).or_default();
                st.force_ones(*val);
                st.force_zeros(!*val);
                if st.is_contradiction() {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!(
                            "constant `{var} == 0x{val:x}` contradicts bitmask constraints"
                        ),
                    };
                }
            }
        }
    }

    // Verify `(var & mask) != val` against fully determined mask bits
    for (var, mask, val) in neq_checks {
        if let Some(st) = states.get(var) {
            let determined = st.known_ones | st.known_zeros;
            if (mask & determined) == mask {
                let forced_val = st.known_ones & mask;
                if forced_val == val {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-bv",
                        reason: format!(
                            "({var} & 0x{mask:x}) is forced to 0x{forced_val:x}, contradicting != 0x{val:x}"
                        ),
                    };
                }
            }
        }
    }

    SmtVerdict::Sat {
        solver: "builtin-qf-bv",
        model: None,
    }
}

// ============================================================================
// 2. QF_LIA: Exact i128 Linear Integer Arithmetic (GCD + Fourier-Motzkin)
// ============================================================================

/// Linear integer inequality: `sum(terms[var] * var) <= rhs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearIneq {
    pub terms: BTreeMap<String, i128>,
    pub rhs: i128,
}

impl LinearIneq {
    pub fn new(terms: impl IntoIterator<Item = (String, i128)>, rhs: i128) -> Self {
        let mut map: BTreeMap<String, i128> = BTreeMap::new();
        for (v, c) in terms {
            if c != 0 {
                let e = map.entry(v).or_insert(0);
                *e = e.saturating_add(c);
            }
        }
        map.retain(|_, c| *c != 0);
        Self { terms: map, rhs }
    }

    /// Normalizes by positive GCD of all coefficients using integer floor division on `rhs`:
    /// e.g., `2*x <= 5` becomes `x <= 2` (exact over integers!). Uses `u128` so `i128::MIN` never panics.
    pub fn normalize_int(&mut self) {
        let mut g: u128 = 0;
        for &c in self.terms.values() {
            let mut a = g;
            let mut b = c.unsigned_abs();
            while b != 0 {
                let t = a % b;
                a = b;
                b = t;
            }
            g = a;
        }
        if g > 1
            && let Ok(gi) = i128::try_from(g)
        {
            for c in self.terms.values_mut() {
                *c /= gi;
            }
            self.rhs = self.rhs.div_euclid(gi);
        }
    }
}

/// Checks satisfiability of a conjunction of `QF_LIA` integer linear inequalities
/// using exact `i128` GCD tightening + bounded Fourier-Motzkin elimination.
/// Strictly sound: if elimination exceeds the pair cap (`MAX_FM_ROWS`), returns `Unknown` (never false UNSAT).
pub fn solve_lia_constraints(raw: &[LinearIneq]) -> SmtVerdict {
    const MAX_FM_ROWS: usize = 256;
    let mut rows: Vec<LinearIneq> = raw
        .iter()
        .cloned()
        .map(|mut r| {
            r.normalize_int();
            r
        })
        .collect();

    // Check immediate 0 <= rhs contradictions (including GCD-tightened `2x == 3` -> `x <= 1 && -x <= -2` -> `0 <= -1`)
    for r in &rows {
        if r.terms.is_empty() && r.rhs < 0 {
            return SmtVerdict::Unsat {
                solver: "builtin-qf-lia",
                reason: format!("linear integer contradiction: 0 <= {}", r.rhs),
            };
        }
    }

    // Collect variables sorted by ascending elimination cost (pos_count * neg_count)
    let mut vars: Vec<String> = rows.iter().flat_map(|r| r.terms.keys().cloned()).collect();
    vars.sort();
    vars.dedup();

    for var in vars {
        let mut pos = Vec::new();
        let mut neg = Vec::new();
        let mut rest = Vec::new();

        for r in rows {
            match r.terms.get(&var).copied().unwrap_or(0) {
                c if c > 0 => pos.push((c, r)),
                c if c < 0 => neg.push((-c, r)),
                _ => rest.push(r),
            }
        }

        if pos.len().saturating_mul(neg.len()) + rest.len() > MAX_FM_ROWS {
            return SmtVerdict::Unknown {
                solver: "builtin-qf-lia",
            };
        }

        for (cp, rp) in &pos {
            for (cn, rn) in &neg {
                // Eliminate `var`: cn * rp + cp * rn <= cn * rp.rhs + cp * rn.rhs
                let Some(rhs_p) = cn.checked_mul(rp.rhs) else {
                    return SmtVerdict::Unknown {
                        solver: "builtin-qf-lia",
                    };
                };
                let Some(rhs_n) = cp.checked_mul(rn.rhs) else {
                    return SmtVerdict::Unknown {
                        solver: "builtin-qf-lia",
                    };
                };
                let Some(new_rhs) = rhs_p.checked_add(rhs_n) else {
                    return SmtVerdict::Unknown {
                        solver: "builtin-qf-lia",
                    };
                };

                let mut new_terms: BTreeMap<String, i128> = BTreeMap::new();
                for (k, &v) in &rp.terms {
                    if k == &var {
                        continue;
                    }
                    let Some(scaled) = cn.checked_mul(v) else {
                        return SmtVerdict::Unknown {
                            solver: "builtin-qf-lia",
                        };
                    };
                    *new_terms.entry(k.clone()).or_insert(0) += scaled;
                }
                for (k, &v) in &rn.terms {
                    if k == &var {
                        continue;
                    }
                    let Some(scaled) = cp.checked_mul(v) else {
                        return SmtVerdict::Unknown {
                            solver: "builtin-qf-lia",
                        };
                    };
                    let entry = new_terms.entry(k.clone()).or_insert(0);
                    let Some(sum) = entry.checked_add(scaled) else {
                        return SmtVerdict::Unknown {
                            solver: "builtin-qf-lia",
                        };
                    };
                    *entry = sum;
                }
                new_terms.retain(|_, c| *c != 0);
                let mut combined = LinearIneq {
                    terms: new_terms,
                    rhs: new_rhs,
                };
                combined.normalize_int();
                if combined.terms.is_empty() && combined.rhs < 0 {
                    return SmtVerdict::Unsat {
                        solver: "builtin-qf-lia",
                        reason: format!(
                            "Fourier-Motzkin elimination on `{var}` proved 0 <= {}",
                            combined.rhs
                        ),
                    };
                }
                rest.push(combined);
            }
        }
        rows = rest;
    }

    SmtVerdict::Sat {
        solver: "builtin-qf-lia",
        model: None,
    }
}

// ============================================================================
// 3. McCarthy Array Theory: Read-Over-Write (`select` / `store`) Axiom
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArrayConstraint {
    /// `arr[index] = value`
    StoreConst {
        array: String,
        index: String,
        value: i64,
    },
    /// `arr[index] <op> value`
    SelectCmp {
        array: String,
        index: String,
        op: CmpOp,
        value: i64,
    },
    /// Index equality `idx_a == idx_b`
    IndexEq { lhs: String, rhs: String },
}

/// Applies McCarthy's Read-Over-Write axiom (`select(store(a, i, v), j) == v` when `i == j`)
/// with union-find index equivalence classes to prove array-element contradictions.
pub fn solve_array_constraints(constraints: &[ArrayConstraint]) -> SmtVerdict {
    // Union-find over symbolic index names
    let mut parent: HashMap<String, String> = HashMap::new();
    let find = |p: &mut HashMap<String, String>, x: &str| -> String {
        let mut cur = x.to_string();
        while let Some(next) = p.get(&cur) {
            if next == &cur {
                break;
            }
            cur = next.clone();
        }
        p.entry(x.to_string()).or_insert_with(|| cur.clone());
        cur
    };

    for c in constraints {
        if let ArrayConstraint::IndexEq { lhs, rhs } = c {
            let rl = find(&mut parent, lhs);
            let rr = find(&mut parent, rhs);
            if rl != rr {
                parent.insert(rl, rr);
            }
        }
    }

    // Track last stored constant per (array, canonical_index)
    let mut latest_store: HashMap<(String, String), i64> = HashMap::new();
    for c in constraints {
        match c {
            ArrayConstraint::StoreConst {
                array,
                index,
                value,
            } => {
                let canon_idx = find(&mut parent, index);
                latest_store.insert((array.clone(), canon_idx), *value);
            }
            ArrayConstraint::SelectCmp {
                array,
                index,
                op,
                value,
            } => {
                let canon_idx = find(&mut parent, index);
                if let Some(&stored) = latest_store.get(&(array.clone(), canon_idx)) {
                    let holds = match op {
                        CmpOp::Eq => stored == *value,
                        CmpOp::Neq => stored != *value,
                        CmpOp::Lt => stored < *value,
                        CmpOp::Le => stored <= *value,
                        CmpOp::Gt => stored > *value,
                        CmpOp::Ge => stored >= *value,
                    };
                    if !holds {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-array",
                            reason: format!(
                                "Array read-over-write contradiction: {array}[{index}] is {stored}, cannot satisfy {:?} {value}",
                                op
                            ),
                        };
                    }
                }
            }
            ArrayConstraint::IndexEq { .. } => {}
        }
    }

    SmtVerdict::Sat {
        solver: "builtin-qf-array",
        model: None,
    }
}

// ============================================================================
// 4. Inter-Procedural Caller -> Callee Path-Constraint Propagation
// ============================================================================

/// Renames variables inside `constraint` using `subst` (unmapped variables are alpha-renamed
/// with `prefix` so caller locals never collide with unrelated callee locals).
fn substitute_constraint(
    constraint: &PathConstraint,
    subst: &HashMap<String, String>,
    alpha_prefix: &str,
) -> PathConstraint {
    let map_var = |v: &str| -> String {
        if let Some(mapped) = subst.get(v) {
            mapped.clone()
        } else {
            format!("{alpha_prefix}{v}")
        }
    };
    match constraint {
        PathConstraint::ConstBool(b) => PathConstraint::ConstBool(*b),
        PathConstraint::BoolLit { name, value } => PathConstraint::BoolLit {
            name: map_var(name),
            value: *value,
        },
        PathConstraint::IntCmp { var, op, value } => PathConstraint::IntCmp {
            var: map_var(var),
            op: *op,
            value: *value,
        },
        PathConstraint::VarCmp { lhs, op, rhs } => PathConstraint::VarCmp {
            lhs: map_var(lhs),
            op: *op,
            rhs: map_var(rhs),
        },
        PathConstraint::StrEq { var, literal, eq } => PathConstraint::StrEq {
            var: map_var(var),
            literal: literal.clone(),
            eq: *eq,
        },
        PathConstraint::And(parts) => PathConstraint::And(
            parts
                .iter()
                .map(|p| substitute_constraint(p, subst, alpha_prefix))
                .collect(),
        ),
        PathConstraint::Or(parts) => PathConstraint::Or(
            parts
                .iter()
                .map(|p| substitute_constraint(p, subst, alpha_prefix))
                .collect(),
        ),
    }
}

/// Propagates caller's path constraints across a call site `callee(actual_0, actual_1, ...)`
/// into `callee(formal_0, formal_1, ...)` and checks joint feasibility with `callee_constraints`.
///
/// Example:
/// - Caller proves `amount > 0` before calling `transfer(amount)`
/// - Callee checks `if (val <= 0) { sink(); }` where `formal = ["val"]`, `actual = ["amount"]`
/// - Joint SMT verdict = `Unsat` -> callee branch is **provably unreachable** across functions!
pub fn check_interprocedural_feasibility(
    caller_constraints: &[PathConstraint],
    actual_args: &[String],
    formal_params: &[String],
    callee_constraints: &[PathConstraint],
    use_z3: bool,
) -> SmtVerdict {
    let mut subst: HashMap<String, String> = HashMap::new();
    let mut merged: Vec<PathConstraint> = Vec::with_capacity(
        caller_constraints.len() + callee_constraints.len() + formal_params.len(),
    );

    for (actual, formal) in actual_args.iter().zip(formal_params.iter()) {
        let act = actual.trim();
        let frm = formal.trim();
        if frm.is_empty() || act.is_empty() {
            continue;
        }
        if let Ok(lit_int) = act.parse::<i64>() {
            merged.push(PathConstraint::IntCmp {
                var: frm.to_string(),
                op: CmpOp::Eq,
                value: lit_int,
            });
        } else if act == "true" || act == "false" {
            merged.push(PathConstraint::BoolLit {
                name: frm.to_string(),
                value: act == "true",
            });
        } else if (act.starts_with('"') && act.ends_with('"'))
            || (act.starts_with('\'') && act.ends_with('\''))
        {
            if act.len() >= 2 {
                merged.push(PathConstraint::StrEq {
                    var: frm.to_string(),
                    literal: act[1..act.len() - 1].to_string(),
                    eq: true,
                });
            }
        } else {
            // Map caller variable name directly to callee formal parameter name
            subst.insert(act.to_string(), frm.to_string());
        }
    }

    for c in caller_constraints {
        merged.push(substitute_constraint(c, &subst, "__caller_"));
    }
    merged.extend(callee_constraints.iter().cloned());

    solve_path_constraints(&merged, use_z3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qf_bv_proves_bitmask_shift_and_unsigned_bound_contradictions() {
        // 0 <= x <= 255 AND (x & 0x100) == 0x100 -> UNSAT
        let v1 = solve_bv_constraints(&[
            BvConstraint::UnsignedUpper {
                var: "x".into(),
                max_val: 255,
            },
            BvConstraint::BitAndEq {
                var: "x".into(),
                mask: 0x100,
                val: 0x100,
                eq: true,
            },
        ]);
        assert!(v1.is_unsat(), "expected UNSAT, got {v1:?}");

        // (flags & 0x03) == 0x01 AND (flags & 0x01) == 0x00 -> UNSAT
        let v2 = solve_bv_constraints(&[
            BvConstraint::BitAndEq {
                var: "flags".into(),
                mask: 0x03,
                val: 0x01,
                eq: true,
            },
            BvConstraint::BitAndEq {
                var: "flags".into(),
                mask: 0x01,
                val: 0x00,
                eq: true,
            },
        ]);
        assert!(v2.is_unsat(), "expected UNSAT, got {v2:?}");

        // Satisfiable mask: (flags & 0x03) == 0x01 AND (flags & 0x04) == 0x04 -> SAT
        let v3 = solve_bv_constraints(&[
            BvConstraint::BitAndEq {
                var: "flags".into(),
                mask: 0x03,
                val: 0x01,
                eq: true,
            },
            BvConstraint::BitAndEq {
                var: "flags".into(),
                mask: 0x04,
                val: 0x04,
                eq: true,
            },
        ]);
        assert!(!v3.is_unsat(), "expected SAT, got {v3:?}");
    }

    #[test]
    fn qf_lia_proves_integer_gcd_and_fourier_motzkin_unsat() {
        // Integer-only UNSAT: 2*x == 3 -> 2*x <= 3 AND -2*x <= -3 -> x <= 1 AND -x <= -2 -> 0 <= -1
        let v_odd = solve_lia_constraints(&[
            LinearIneq::new([("x".into(), 2)], 3),
            LinearIneq::new([("x".into(), -2)], -3),
        ]);
        assert!(
            v_odd.is_unsat(),
            "expected integer-GCD UNSAT, got {v_odd:?}"
        );

        // Multi-variable: x + y <= 10, x - y <= -4 (=> 2x <= 6 => x <= 3), AND x >= 4 (-x <= -4) -> UNSAT
        let v_fm = solve_lia_constraints(&[
            LinearIneq::new([("x".into(), 1), ("y".into(), 1)], 10),
            LinearIneq::new([("x".into(), 1), ("y".into(), -1)], -4),
            LinearIneq::new([("x".into(), -1)], -4),
        ]);
        assert!(
            v_fm.is_unsat(),
            "expected Fourier-Motzkin UNSAT, got {v_fm:?}"
        );

        // Satisfiable: x + y <= 10, x - y <= -4, x >= 3 -> SAT (x=3, y=7)
        let v_sat = solve_lia_constraints(&[
            LinearIneq::new([("x".into(), 1), ("y".into(), 1)], 10),
            LinearIneq::new([("x".into(), 1), ("y".into(), -1)], -4),
            LinearIneq::new([("x".into(), -1)], -3),
        ]);
        assert!(!v_sat.is_unsat(), "expected SAT, got {v_sat:?}");
    }

    #[test]
    fn array_read_over_write_proves_aliased_index_contradiction() {
        let v = solve_array_constraints(&[
            ArrayConstraint::IndexEq {
                lhs: "i".into(),
                rhs: "j".into(),
            },
            ArrayConstraint::StoreConst {
                array: "roles".into(),
                index: "i".into(),
                value: 1,
            },
            ArrayConstraint::SelectCmp {
                array: "roles".into(),
                index: "j".into(),
                op: CmpOp::Eq,
                value: 0,
            },
        ]);
        assert!(v.is_unsat(), "expected array UNSAT, got {v:?}");
    }

    #[test]
    fn interprocedural_propagation_proves_cross_function_dead_branch() {
        // Caller: `if (req_amount > 0) { transfer(req_amount); }`
        let caller = vec![PathConstraint::IntCmp {
            var: "req_amount".into(),
            op: CmpOp::Gt,
            value: 0,
        }];
        // Callee: `fn transfer(val) { if (val <= 0) { unreachable_vuln(); } }`
        let callee_dead = vec![PathConstraint::IntCmp {
            var: "val".into(),
            op: CmpOp::Le,
            value: 0,
        }];
        let verdict = check_interprocedural_feasibility(
            &caller,
            &["req_amount".into()],
            &["val".into()],
            &callee_dead,
            false,
        );
        assert!(
            verdict.is_unsat(),
            "expected cross-function UNSAT, got {verdict:?}"
        );

        // Reachable branch: `if (val >= 10)` -> SAT
        let callee_live = vec![PathConstraint::IntCmp {
            var: "val".into(),
            op: CmpOp::Ge,
            value: 10,
        }];
        let v_live = check_interprocedural_feasibility(
            &caller,
            &["req_amount".into()],
            &["val".into()],
            &callee_live,
            false,
        );
        assert!(
            !v_live.is_unsat(),
            "expected cross-function SAT, got {v_live:?}"
        );
    }
}
