//! Phase 15C: Path-Feasibility SMT Engine (`SMT-LIB2` + `z3` Subprocess Oracle + Built-In `QF_IDL` Solver).
//!
//! Extracts branch path conditions (including `if`/`else`, early-return guards, `assert`/`require`,
//! and local constant bindings) from Tree-sitter ASTs along the path to a target line, then proves
//! whether that path is satisfiable (`Sat`) or mathematically unreachable (`Unsat`).
//!
//! Two-tier architecture with zero C++ `z3-sys` compile bloat:
//! - Tier 1 (always on, `< 0.1ms`): Pure-Rust Boolean + String-Equality + Integer Interval +
//!   `QF_IDL` Difference-Logic (Bellman-Ford negative cycle) feasibility solver.
//! - Tier 2 (auto-enabled under `--deep-audit` when `z3` is installed on `PATH`): Emits standard
//!   `SMT-LIB2` (`(check-sat)` + `(get-model)`) to `z3 -smt2 -T:1 -memory:512 -in`.

use crate::ast::{node_text, strip_comments};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    pub fn negate(self) -> Self {
        match self {
            CmpOp::Eq => CmpOp::Neq,
            CmpOp::Neq => CmpOp::Eq,
            CmpOp::Lt => CmpOp::Ge,
            CmpOp::Le => CmpOp::Gt,
            CmpOp::Gt => CmpOp::Le,
            CmpOp::Ge => CmpOp::Lt,
        }
    }

    pub fn flip(self) -> Self {
        match self {
            CmpOp::Eq => CmpOp::Eq,
            CmpOp::Neq => CmpOp::Neq,
            CmpOp::Lt => CmpOp::Gt,
            CmpOp::Le => CmpOp::Ge,
            CmpOp::Gt => CmpOp::Lt,
            CmpOp::Ge => CmpOp::Le,
        }
    }

    fn smt2_op(self) -> &'static str {
        match self {
            CmpOp::Eq => "=",
            CmpOp::Neq => "distinct",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathConstraint {
    ConstBool(bool),
    BoolLit {
        name: String,
        value: bool,
    },
    IntCmp {
        var: String,
        op: CmpOp,
        value: i64,
    },
    VarCmp {
        lhs: String,
        op: CmpOp,
        rhs: String,
    },
    StrEq {
        var: String,
        literal: String,
        eq: bool,
    },
    And(Vec<PathConstraint>),
    Or(Vec<PathConstraint>),
}

impl PathConstraint {
    /// Sound logical negation via De Morgan's laws and comparison inversion.
    pub fn negate(&self) -> Self {
        match self {
            PathConstraint::ConstBool(b) => PathConstraint::ConstBool(!b),
            PathConstraint::BoolLit { name, value } => PathConstraint::BoolLit {
                name: name.clone(),
                value: !value,
            },
            PathConstraint::IntCmp { var, op, value } => PathConstraint::IntCmp {
                var: var.clone(),
                op: op.negate(),
                value: *value,
            },
            PathConstraint::VarCmp { lhs, op, rhs } => PathConstraint::VarCmp {
                lhs: lhs.clone(),
                op: op.negate(),
                rhs: rhs.clone(),
            },
            PathConstraint::StrEq { var, literal, eq } => PathConstraint::StrEq {
                var: var.clone(),
                literal: literal.clone(),
                eq: !eq,
            },
            PathConstraint::And(parts) => {
                PathConstraint::Or(parts.iter().map(PathConstraint::negate).collect())
            }
            PathConstraint::Or(parts) => {
                PathConstraint::And(parts.iter().map(PathConstraint::negate).collect())
            }
        }
    }

    /// Flattens nested conjunctions into a flat list of conjuncts.
    pub fn flatten_conjuncts(&self, out: &mut Vec<PathConstraint>) {
        match self {
            PathConstraint::And(parts) => {
                for p in parts {
                    p.flatten_conjuncts(out);
                }
            }
            other => out.push(other.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtVerdict {
    Sat {
        solver: &'static str,
        model: Option<String>,
    },
    Unsat {
        solver: &'static str,
        reason: String,
    },
    Unknown {
        solver: &'static str,
    },
}

impl SmtVerdict {
    pub fn is_unsat(&self) -> bool {
        matches!(self, SmtVerdict::Unsat { .. })
    }
}

/// Checks once per process whether `z3` is installed and executable on `PATH`.
pub fn is_z3_available() -> bool {
    static Z3_OK: OnceLock<bool> = OnceLock::new();
    *Z3_OK.get_or_init(|| {
        Command::new("z3")
            .arg("-version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Parses a boolean/comparison condition string (from JS/TS, Python, Go, Rust, Java, C/C++, Solidity)
/// into a `PathConstraint`. Returns `None` for unrecognized/opaque expressions (fail-open).
pub fn parse_condition_expr(raw: &str) -> Option<PathConstraint> {
    let cleaned = strip_comments(raw);
    let s = strip_outer_parens(cleaned.trim());
    if s.is_empty() {
        return None;
    }

    // 1. Top-level logical OR (`||`, ` or `)
    if let Some(parts) =
        split_top_level_logical(s, "||").or_else(|| split_top_level_word_op(s, "or"))
    {
        let parsed: Option<Vec<PathConstraint>> =
            parts.into_iter().map(parse_condition_expr).collect();
        return parsed.map(PathConstraint::Or);
    }

    // 2. Top-level logical AND (`&&`, ` and `)
    // Require ALL conjuncts to parse so negating `A && opaque` never collapses to `!A` (False UNSAT).
    if let Some(parts) =
        split_top_level_logical(s, "&&").or_else(|| split_top_level_word_op(s, "and"))
    {
        let parsed: Option<Vec<PathConstraint>> =
            parts.into_iter().map(parse_condition_expr).collect();
        let conjuncts = parsed?;
        return match conjuncts.len() {
            0 => None,
            1 => conjuncts.into_iter().next(),
            _ => Some(PathConstraint::And(conjuncts)),
        };
    }

    // 3. Unary logical negation (`!expr`, `not expr`)
    if let Some(rest) = s.strip_prefix('!')
        && !rest.starts_with('=')
    {
        return parse_condition_expr(rest).map(|c| c.negate());
    }
    if let Some(rest) = s.strip_prefix("not ") {
        return parse_condition_expr(rest).map(|c| c.negate());
    }

    // 4. Boolean constants
    let low = s.to_ascii_lowercase();
    if matches!(low.as_str(), "false" | "0") {
        return Some(PathConstraint::ConstBool(false));
    }
    if matches!(low.as_str(), "true" | "1") {
        return Some(PathConstraint::ConstBool(true));
    }

    // 5. Binary comparison (`===`, `!==`, `==`, `!=`, `<=`, `>=`, `<`, `>`)
    if let Some((lhs_raw, op, rhs_raw)) = split_top_level_cmp(s) {
        let lhs = strip_outer_parens(lhs_raw.trim());
        let rhs = strip_outer_parens(rhs_raw.trim());

        // Boolean literal comparison (`isAdmin === true`, `ok == false`)
        if is_valid_var_expr(lhs) && matches!(rhs.to_ascii_lowercase().as_str(), "true" | "false") {
            let b = rhs.eq_ignore_ascii_case("true");
            return match op {
                CmpOp::Eq => Some(PathConstraint::BoolLit {
                    name: lhs.to_string(),
                    value: b,
                }),
                CmpOp::Neq => Some(PathConstraint::BoolLit {
                    name: lhs.to_string(),
                    value: !b,
                }),
                _ => None,
            };
        }

        // String literal equality (`role === "admin"`, `env != 'prod'`)
        if matches!(op, CmpOp::Eq | CmpOp::Neq) {
            if is_valid_var_expr(lhs)
                && let Some(lit) = parse_string_literal(rhs)
            {
                return Some(PathConstraint::StrEq {
                    var: lhs.to_string(),
                    literal: lit,
                    eq: op == CmpOp::Eq,
                });
            }
            if is_valid_var_expr(rhs)
                && let Some(lit) = parse_string_literal(lhs)
            {
                return Some(PathConstraint::StrEq {
                    var: rhs.to_string(),
                    literal: lit,
                    eq: op == CmpOp::Eq,
                });
            }
        }

        // Integer literal comparison (`x > 10`, `0 <= amount`)
        if is_valid_var_expr(lhs)
            && let Some(val) = parse_int_literal(rhs)
        {
            return Some(PathConstraint::IntCmp {
                var: lhs.to_string(),
                op,
                value: val,
            });
        }
        if is_valid_var_expr(rhs)
            && let Some(val) = parse_int_literal(lhs)
        {
            return Some(PathConstraint::IntCmp {
                var: rhs.to_string(),
                op: op.flip(),
                value: val,
            });
        }

        // Two-variable comparison (`idx >= len`, `a < b`)
        if is_valid_var_expr(lhs) && is_valid_var_expr(rhs) {
            return Some(PathConstraint::VarCmp {
                lhs: lhs.to_string(),
                op,
                rhs: rhs.to_string(),
            });
        }
        return None;
    }

    // 6. Bare boolean identifier (`if (isAdmin)`)
    if is_valid_var_expr(s) {
        return Some(PathConstraint::BoolLit {
            name: s.to_string(),
            value: true,
        });
    }

    None
}

/// Extracts all dominating path constraints from the entry of `fn_node` to `target_line` (1-based).
pub fn extract_path_constraints_to_line(
    fn_node: Node,
    src: &[u8],
    target_line: usize,
) -> Vec<PathConstraint> {
    let mut constraints = Vec::new();
    let Some(body) = fn_node.child_by_field_name("body") else {
        return constraints;
    };
    collect_constraints_in_block(body, src, target_line, &mut constraints, 0);
    constraints
}

fn collect_constraints_in_block(
    block: Node,
    src: &[u8],
    target_line: usize,
    out: &mut Vec<PathConstraint>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    let mut cursor = block.walk();
    for stmt in block.children(&mut cursor) {
        let start_line = stmt.start_position().row + 1;
        let end_line = stmt.end_position().row + 1;
        if start_line > target_line {
            break;
        }

        let sk = stmt.kind();
        if matches!(sk, "if_statement" | "if_expression" | "elif_clause") {
            let cond_opt = stmt
                .child_by_field_name("condition")
                .and_then(|c| parse_condition_expr(node_text(c, src)));
            let cons = stmt
                .child_by_field_name("consequence")
                .or_else(|| stmt.child_by_field_name("body"));
            let alt = stmt.child_by_field_name("alternative");

            if target_line >= start_line && target_line <= end_line {
                // Target is inside this `if`/`else` tree
                if let Some(c_node) = cons {
                    let c_start = c_node.start_position().row + 1;
                    let c_end = c_node.end_position().row + 1;
                    if target_line >= c_start && target_line <= c_end {
                        if let Some(cond) = cond_opt {
                            out.push(cond);
                        }
                        collect_constraints_in_block(c_node, src, target_line, out, depth + 1);
                        return;
                    }
                }
                if let Some(a_node) = alt {
                    let a_start = a_node.start_position().row + 1;
                    let a_end = a_node.end_position().row + 1;
                    if target_line >= a_start && target_line <= a_end {
                        if let Some(cond) = cond_opt {
                            out.push(cond.negate());
                        }
                        collect_constraints_in_block(a_node, src, target_line, out, depth + 1);
                        return;
                    }
                }
                return;
            } else if end_line < target_line {
                // Invalidate any prior constraints on variables mutated inside this `if`/`else` subtree
                let mut mutated = HashSet::new();
                collect_mutated_vars_in_subtree(stmt, src, &mut mutated, 0);
                if !mutated.is_empty() {
                    out.retain(|c| !mutated.iter().any(|v| constraint_mentions_var(c, v)));
                }
                // Target is strictly AFTER this `if` statement: check early-return guard dominance
                if let Some(cond) = cond_opt {
                    let cons_exits = cons.is_some_and(|n| block_always_exits(n, src));
                    let alt_exits = alt.is_some_and(|n| block_always_exits(n, src));
                    if cons_exits && !alt_exits {
                        out.push(cond.negate());
                    } else if alt_exits && !cons_exits {
                        out.push(cond);
                    }
                }
            }
            continue;
        }

        if matches!(
            sk,
            "else_clause" | "statement_block" | "statement_list" | "block" | "compound_statement"
        ) && target_line >= start_line
            && target_line <= end_line
        {
            collect_constraints_in_block(stmt, src, target_line, out, depth + 1);
            return;
        }

        // Track simple constant bindings & `assert`/`require` strictly before `target_line`
        if end_line < target_line {
            let mut mutated = HashSet::new();
            collect_mutated_vars_in_subtree(stmt, src, &mut mutated, 0);
            if !mutated.is_empty() {
                out.retain(|c| !mutated.iter().any(|v| constraint_mentions_var(c, v)));
            }
            let txt = strip_comments(node_text(stmt, src));
            let trimmed = txt.trim().trim_end_matches(';').trim();
            if let Some(inner) = extract_assert_like_arg(trimmed)
                && let Some(c) = parse_condition_expr(inner)
            {
                out.push(c);
            } else if let Some((var, rhs)) = extract_simple_const_binding(trimmed) {
                // Invalidate any earlier constraints on reassigned variable
                out.retain(|c| !constraint_mentions_var(c, &var));
                if let Some(v) = parse_int_literal(rhs) {
                    out.push(PathConstraint::IntCmp {
                        var,
                        op: CmpOp::Eq,
                        value: v,
                    });
                } else if matches!(rhs.to_ascii_lowercase().as_str(), "true" | "false") {
                    out.push(PathConstraint::BoolLit {
                        name: var,
                        value: rhs.eq_ignore_ascii_case("true"),
                    });
                } else if let Some(lit) = parse_string_literal(rhs) {
                    out.push(PathConstraint::StrEq {
                        var,
                        literal: lit,
                        eq: true,
                    });
                }
            }
        }
    }
}

/// Evaluates whether a conjunction of path constraints is satisfiable (`Sat`) or contradictory (`Unsat`).
/// Uses the built-in pure-Rust `QF_IDL` + Boolean + String solver first; if `use_z3` is enabled and
/// `z3` is available on `PATH`, upgrades inconclusive/disjunctive queries to `z3 -smt2 -in`.
pub fn solve_path_constraints(constraints: &[PathConstraint], use_z3: bool) -> SmtVerdict {
    if constraints.is_empty() {
        return SmtVerdict::Sat {
            solver: "builtin-qf-idl",
            model: None,
        };
    }

    let mut flat = Vec::new();
    for c in constraints {
        c.flatten_conjuncts(&mut flat);
    }

    let builtin = solve_builtin_conjunction(&flat);
    if builtin.is_unsat() {
        return builtin;
    }

    // Phase 27/32: Refine non-strict bounds with pure-Rust QF_LIA i128 GCD + Fourier-Motzkin solver.
    // Strict inequalities (`<`, `>`) are NOT tightened by +/- 1 here so untyped float intervals like
    // `0 < rate < 1` are never falsely pruned as integer UNSAT (dense difference-logic handles strictness).
    let mut lia_ineqs = Vec::new();
    for c in &flat {
        if let PathConstraint::IntCmp { var, op, value } = c {
            let mut terms = std::collections::BTreeMap::new();
            match op {
                CmpOp::Le => {
                    terms.insert(var.clone(), 1i128);
                    lia_ineqs.push(crate::smt_advanced::LinearIneq {
                        terms,
                        rhs: *value as i128,
                    });
                }
                CmpOp::Ge => {
                    terms.insert(var.clone(), -1i128);
                    lia_ineqs.push(crate::smt_advanced::LinearIneq {
                        terms,
                        rhs: -(*value as i128),
                    });
                }
                CmpOp::Eq => {
                    terms.insert(var.clone(), 1i128);
                    lia_ineqs.push(crate::smt_advanced::LinearIneq {
                        terms: terms.clone(),
                        rhs: *value as i128,
                    });
                    let mut neg = std::collections::BTreeMap::new();
                    neg.insert(var.clone(), -1i128);
                    lia_ineqs.push(crate::smt_advanced::LinearIneq {
                        terms: neg,
                        rhs: -(*value as i128),
                    });
                }
                CmpOp::Lt | CmpOp::Gt | CmpOp::Neq => {}
            }
        }
    }
    if !lia_ineqs.is_empty() {
        let lia_verdict = crate::smt_advanced::solve_lia_constraints(&lia_ineqs);
        if lia_verdict.is_unsat() {
            return lia_verdict;
        }
    }

    if use_z3 && is_z3_available() {
        let script = emit_smtlib2(&flat);
        if let Some(z3_res) = run_z3_smtlib2(&script) {
            return z3_res;
        }
    }

    builtin
}

/// Convenience helper: returns `true` if `target_line` inside `fn_node` is reachable (not proven UNSAT).
pub fn is_line_reachable(fn_node: Node, src: &[u8], target_line: usize, use_z3: bool) -> bool {
    let constraints = extract_path_constraints_to_line(fn_node, src, target_line);
    if constraints.is_empty() {
        return true;
    }
    !solve_path_constraints(&constraints, use_z3).is_unsat()
}

/// Built-in pure-Rust feasibility solver:
/// - Boolean literal contradictions (`a && !a`, `false`)
/// - String equality/disequality contradictions (`role == "admin" && role == "guest"`)
/// - Integer interval tightening + forbidden values (`x > 5 && x < 5`, `x == 3 && x != 3`)
/// - `QF_IDL` Difference-Logic negative-cycle detection via Bellman-Ford (`x < y && y < z && z <= x`)
/// - Bounded DNF splitting for small `Or` clauses (up to 4 disjuncts)
fn solve_builtin_conjunction(flat: &[PathConstraint]) -> SmtVerdict {
    let mut split_budget = 64usize;
    solve_builtin_conjunction_budgeted(flat, &mut split_budget)
}

fn solve_builtin_conjunction_budgeted(
    flat: &[PathConstraint],
    split_budget: &mut usize,
) -> SmtVerdict {
    // Handle a single small `Or` by checking if ALL disjuncts are UNSAT (bounded split budget)
    if *split_budget > 0
        && let Some((or_idx, PathConstraint::Or(branches))) = flat
            .iter()
            .enumerate()
            .find(|(_, c)| matches!(c, PathConstraint::Or(b) if b.len() <= 4))
    {
        if branches.is_empty() {
            return SmtVerdict::Unsat {
                solver: "builtin-qf-idl",
                reason: "empty disjunction".into(),
            };
        }
        let mut all_unsat = true;
        let mut last_reason = String::new();
        for br in branches {
            if *split_budget == 0 {
                return SmtVerdict::Unknown {
                    solver: "builtin-qf-idl",
                };
            }
            *split_budget -= 1;
            let mut sub = Vec::with_capacity(flat.len());
            for (i, item) in flat.iter().enumerate() {
                if i == or_idx {
                    br.flatten_conjuncts(&mut sub);
                } else {
                    sub.push(item.clone());
                }
            }
            match solve_builtin_conjunction_budgeted(&sub, split_budget) {
                SmtVerdict::Unsat { reason, .. } => last_reason = reason,
                _ => {
                    all_unsat = false;
                    break;
                }
            }
        }
        if all_unsat {
            return SmtVerdict::Unsat {
                solver: "builtin-qf-idl",
                reason: format!("all disjunction branches unsat ({last_reason})"),
            };
        }
    }

    let mut bool_vals: HashMap<&str, bool> = HashMap::new();
    let mut str_eq: HashMap<&str, &str> = HashMap::new();
    let mut str_neq: HashMap<&str, HashSet<&str>> = HashMap::new();

    // Difference-logic graph: node 0 is constant ZERO (`0`), vars are nodes `1..=N`.
    // Edge `(u, v, w)` encodes `val(v) - val(u) <= w`.
    let mut owned_var_ids: HashMap<String, usize> = HashMap::new();
    let mut next_id = 1usize;
    let mut edges: Vec<(usize, usize, (i128, i128))> = Vec::new();
    let mut int_neqs: Vec<(usize, usize, i128)> = Vec::new(); // `val(lhs) - val(rhs) != c`

    let id_of = |name: &str, var_ids: &mut HashMap<String, usize>, next_id: &mut usize| {
        if let Some(&id) = var_ids.get(name) {
            id
        } else {
            let id = *next_id;
            *next_id += 1;
            var_ids.insert(name.to_string(), id);
            id
        }
    };

    for c in flat {
        match c {
            PathConstraint::ConstBool(false) => {
                return SmtVerdict::Unsat {
                    solver: "builtin-qf-idl",
                    reason: "constant false branch".into(),
                };
            }
            PathConstraint::ConstBool(true) | PathConstraint::Or(_) | PathConstraint::And(_) => {}
            PathConstraint::BoolLit { name, value } => {
                if let Some(&prev) = bool_vals.get(name.as_str()) {
                    if prev != *value {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-idl",
                            reason: format!("boolean contradiction on `{name}`"),
                        };
                    }
                } else {
                    bool_vals.insert(name.as_str(), *value);
                }
            }
            PathConstraint::StrEq { var, literal, eq } => {
                if *eq {
                    if let Some(&prev) = str_eq.get(var.as_str())
                        && prev != literal.as_str()
                    {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-idl",
                            reason: format!(
                                "string contradiction: `{var} == \"{prev}\"` and `{var} == \"{literal}\"`"
                            ),
                        };
                    }
                    if str_neq
                        .get(var.as_str())
                        .is_some_and(|s| s.contains(literal.as_str()))
                    {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-idl",
                            reason: format!(
                                "string contradiction: `{var} == \"{literal}\"` and `{var} != \"{literal}\"`"
                            ),
                        };
                    }
                    str_eq.insert(var.as_str(), literal.as_str());
                } else {
                    if str_eq.get(var.as_str()) == Some(&literal.as_str()) {
                        return SmtVerdict::Unsat {
                            solver: "builtin-qf-idl",
                            reason: format!(
                                "string contradiction: `{var} == \"{literal}\"` and `{var} != \"{literal}\"`"
                            ),
                        };
                    }
                    str_neq
                        .entry(var.as_str())
                        .or_default()
                        .insert(literal.as_str());
                }
            }
            PathConstraint::IntCmp { var, op, value } => {
                let v = id_of(var, &mut owned_var_ids, &mut next_id);
                let k = *value as i128;
                // Dense difference-logic weights `(w, eps)` represent `w + eps * ε` (sound over both R and Z):
                // val(v) - val(0) <= k       <==>  edge (0, v, (k, 0))
                // val(v) - val(0) < k        <==>  edge (0, v, (k, -1))
                // val(0) - val(v) <= -k      <==>  edge (v, 0, (-k, 0))
                // val(0) - val(v) < -k       <==>  edge (v, 0, (-k, -1))
                match op {
                    CmpOp::Eq => {
                        edges.push((0, v, (k, 0)));
                        edges.push((v, 0, (-k, 0)));
                    }
                    CmpOp::Le => edges.push((0, v, (k, 0))),
                    CmpOp::Lt => edges.push((0, v, (k, -1))),
                    CmpOp::Ge => edges.push((v, 0, (-k, 0))),
                    CmpOp::Gt => edges.push((v, 0, (-k, -1))),
                    CmpOp::Neq => int_neqs.push((v, 0, k)),
                }
            }
            PathConstraint::VarCmp { lhs, op, rhs } => {
                let l = id_of(lhs, &mut owned_var_ids, &mut next_id);
                let r = id_of(rhs, &mut owned_var_ids, &mut next_id);
                // val(l) - val(r) <= (w, eps) <==> edge (r, l, (w, eps))
                match op {
                    CmpOp::Eq => {
                        edges.push((r, l, (0, 0)));
                        edges.push((l, r, (0, 0)));
                    }
                    CmpOp::Le => edges.push((r, l, (0, 0))),
                    CmpOp::Lt => edges.push((r, l, (0, -1))),
                    CmpOp::Ge => edges.push((l, r, (0, 0))),
                    CmpOp::Gt => edges.push((l, r, (0, -1))),
                    CmpOp::Neq => {
                        if l == r {
                            return SmtVerdict::Unsat {
                                solver: "builtin-qf-idl",
                                reason: format!("irreflexive contradiction `{lhs} != {rhs}`"),
                            };
                        }
                        int_neqs.push((l, r, 0));
                    }
                }
            }
        }
    }

    if !edges.is_empty() {
        let n = next_id;
        // Bellman-Ford from virtual super-source over dense `(w, eps)` weights
        let mut dist = vec![(0i128, 0i128); n];
        for _ in 0..n {
            let mut changed = false;
            for &(u, v, (w, e)) in &edges {
                let cand = (dist[u].0.saturating_add(w), dist[u].1.saturating_add(e));
                if cand < dist[v] {
                    dist[v] = cand;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        // One more pass: any relaxation means a negative cycle => mathematically UNSAT
        for &(u, v, (w, e)) in &edges {
            let cand = (dist[u].0.saturating_add(w), dist[u].1.saturating_add(e));
            if cand < dist[v] {
                return SmtVerdict::Unsat {
                    solver: "builtin-qf-idl",
                    reason: "difference-logic negative cycle (unsatisfiable bounds)".into(),
                };
            }
        }

        // Check if any `lhs - rhs != c` is violated when `lhs - rhs == c` is forced
        for &(l, r, c) in &int_neqs {
            // Forced `val(l) - val(r) == c` iff both `val(l) - val(r) < c` and `val(r) - val(l) < -c` create negative cycles
            let lt_unsat = has_negative_cycle(n, &edges, (r, l, (c, -1)));
            let gt_unsat = has_negative_cycle(n, &edges, (l, r, (-c, -1)));
            if lt_unsat && gt_unsat {
                return SmtVerdict::Unsat {
                    solver: "builtin-qf-idl",
                    reason: "inequality contradicts forced equality".into(),
                };
            }
        }
    }

    SmtVerdict::Sat {
        solver: "builtin-qf-idl",
        model: None,
    }
}

fn has_negative_cycle(
    n: usize,
    base_edges: &[(usize, usize, (i128, i128))],
    extra: (usize, usize, (i128, i128)),
) -> bool {
    let mut dist = vec![(0i128, 0i128); n];
    for _ in 0..n {
        let mut changed = false;
        for &(u, v, (w, e)) in base_edges.iter().chain(std::iter::once(&extra)) {
            let cand = (dist[u].0.saturating_add(w), dist[u].1.saturating_add(e));
            if cand < dist[v] {
                dist[v] = cand;
                changed = true;
            }
        }
        if !changed {
            return false;
        }
    }
    for &(u, v, (w, e)) in base_edges.iter().chain(std::iter::once(&extra)) {
        let cand = (dist[u].0.saturating_add(w), dist[u].1.saturating_add(e));
        if cand < dist[v] {
            return true;
        }
    }
    false
}

/// Emits a self-contained `SMT-LIB2` script for a conjunction of path constraints.
pub fn emit_smtlib2(constraints: &[PathConstraint]) -> String {
    let mut bool_vars: HashSet<String> = HashSet::new();
    let mut int_vars: HashSet<String> = HashSet::new();
    let mut str_vars: HashSet<String> = HashSet::new();
    for c in constraints {
        collect_smt_vars(c, &mut bool_vars, &mut int_vars, &mut str_vars);
    }

    // Build collision-free, sort-disambiguated SMT-LIB2 identifiers keyed by (sort_tag, var_name)
    // so a variable used in multiple sorts (e.g. Int and Bool/String) never emits duplicate
    // `(declare-const x ...)` statements.
    const SORT_INT: u8 = 0;
    const SORT_BOOL: u8 = 1;
    const SORT_STR: u8 = 2;

    let mut ident_map: HashMap<(u8, String), String> = HashMap::new();
    let mut declared: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut alloc_ident = |sort: u8, name: &str| -> String {
        let base = sanitize_smt_ident(name);
        let preferred = if !declared.contains(&base) {
            base.clone()
        } else if sort == SORT_INT {
            let mut idx = 2usize;
            loop {
                let cand = format!("{base}_{idx}");
                if !declared.contains(&cand) {
                    break cand;
                }
                idx += 1;
            }
        } else {
            let suffix = match sort {
                SORT_BOOL => "__bool",
                SORT_STR => "__str",
                _ => "__int",
            };
            let tagged = format!("{base}{suffix}");
            if !declared.contains(&tagged) {
                tagged
            } else {
                let mut idx = 2usize;
                loop {
                    let cand = format!("{base}{suffix}_{idx}");
                    if !declared.contains(&cand) {
                        break cand;
                    }
                    idx += 1;
                }
            }
        };
        declared.insert(preferred.clone());
        preferred
    };

    let mut out = String::from("(set-logic ALL)\n");
    let mut i_sorted: Vec<_> = int_vars.into_iter().collect();
    i_sorted.sort();
    for v in &i_sorted {
        let id = alloc_ident(SORT_INT, v);
        ident_map.insert((SORT_INT, v.clone()), id.clone());
        out.push_str(&format!("(declare-const {id} Int)\n"));
    }
    let mut b_sorted: Vec<_> = bool_vars.into_iter().collect();
    b_sorted.sort();
    for v in &b_sorted {
        let id = alloc_ident(SORT_BOOL, v);
        ident_map.insert((SORT_BOOL, v.clone()), id.clone());
        out.push_str(&format!("(declare-const {id} Bool)\n"));
    }
    let mut s_sorted: Vec<_> = str_vars.into_iter().collect();
    s_sorted.sort();
    for v in &s_sorted {
        let id = alloc_ident(SORT_STR, v);
        ident_map.insert((SORT_STR, v.clone()), id.clone());
        out.push_str(&format!("(declare-const {id} String)\n"));
    }

    for c in constraints {
        out.push_str(&format!("(assert {})\n", constraint_to_smt2(c, &ident_map)));
    }
    out.push_str("(check-sat)\n(get-model)\n");
    out
}

fn collect_smt_vars(
    c: &PathConstraint,
    bools: &mut HashSet<String>,
    ints: &mut HashSet<String>,
    strs: &mut HashSet<String>,
) {
    match c {
        PathConstraint::ConstBool(_) => {}
        PathConstraint::BoolLit { name, .. } => {
            bools.insert(name.clone());
        }
        PathConstraint::IntCmp { var, .. } => {
            ints.insert(var.clone());
        }
        PathConstraint::VarCmp { lhs, rhs, .. } => {
            ints.insert(lhs.clone());
            ints.insert(rhs.clone());
        }
        PathConstraint::StrEq { var, .. } => {
            strs.insert(var.clone());
        }
        PathConstraint::And(parts) | PathConstraint::Or(parts) => {
            for p in parts {
                collect_smt_vars(p, bools, ints, strs);
            }
        }
    }
}

fn sanitize_smt_ident(raw: &str) -> String {
    let mut s = String::from("v_");
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            s.push(ch);
        } else {
            s.push('_');
        }
    }
    s
}

fn escape_smt_string(raw: &str) -> String {
    raw.replace('"', "\"\"")
}

fn lookup_smt_ident(sort: u8, raw: &str, ident_map: &HashMap<(u8, String), String>) -> String {
    ident_map
        .get(&(sort, raw.to_string()))
        .cloned()
        .unwrap_or_else(|| sanitize_smt_ident(raw))
}

fn constraint_to_smt2(c: &PathConstraint, ident_map: &HashMap<(u8, String), String>) -> String {
    const SORT_INT: u8 = 0;
    const SORT_BOOL: u8 = 1;
    const SORT_STR: u8 = 2;
    match c {
        PathConstraint::ConstBool(b) => if *b { "true" } else { "false" }.to_string(),
        PathConstraint::BoolLit { name, value } => {
            let id = lookup_smt_ident(SORT_BOOL, name, ident_map);
            if *value { id } else { format!("(not {id})") }
        }
        PathConstraint::IntCmp { var, op, value } => {
            let id = lookup_smt_ident(SORT_INT, var, ident_map);
            let lit = if *value < 0 {
                format!("(- {})", value.unsigned_abs())
            } else {
                value.to_string()
            };
            format!("({} {id} {lit})", op.smt2_op())
        }
        PathConstraint::VarCmp { lhs, op, rhs } => {
            format!(
                "({} {} {})",
                op.smt2_op(),
                lookup_smt_ident(SORT_INT, lhs, ident_map),
                lookup_smt_ident(SORT_INT, rhs, ident_map)
            )
        }
        PathConstraint::StrEq { var, literal, eq } => {
            let id = lookup_smt_ident(SORT_STR, var, ident_map);
            let esc = escape_smt_string(literal);
            if *eq {
                format!("(= {id} \"{esc}\")")
            } else {
                format!("(distinct {id} \"{esc}\")")
            }
        }
        PathConstraint::And(parts) => {
            if parts.is_empty() {
                "true".to_string()
            } else {
                let inner: Vec<String> = parts
                    .iter()
                    .map(|p| constraint_to_smt2(p, ident_map))
                    .collect();
                format!("(and {})", inner.join(" "))
            }
        }
        PathConstraint::Or(parts) => {
            if parts.is_empty() {
                "false".to_string()
            } else {
                let inner: Vec<String> = parts
                    .iter()
                    .map(|p| constraint_to_smt2(p, ident_map))
                    .collect();
                format!("(or {})", inner.join(" "))
            }
        }
    }
}

/// Runs `z3 -smt2 -T:1 -memory:512 -in` on an SMT-LIB2 script with an external hard deadline
/// and deterministic child reaping.
pub fn run_z3_smtlib2(script: &str) -> Option<SmtVerdict> {
    let mut child = Command::new("z3")
        .args(["-smt2", "-T:1", "-memory:512", "-in"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = script.as_bytes().to_vec();
        let _ = std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(SmtVerdict::Unknown { solver: "z3" });
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut buf = Vec::new();
    if let Some(stdout_pipe) = child.stdout.take() {
        let _ =
            std::io::Read::read_to_end(&mut std::io::Read::take(stdout_pipe, 256 * 1024), &mut buf);
    }
    let stdout = String::from_utf8_lossy(&buf);
    let mut lines = stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines.next()?;
    match first {
        "unsat" => Some(SmtVerdict::Unsat {
            solver: "z3",
            reason: "z3 proved path constraints unsatisfiable".into(),
        }),
        "sat" => {
            let rest: Vec<&str> = lines.take(12).collect();
            let model = (!rest.is_empty()).then(|| rest.join(" "));
            Some(SmtVerdict::Sat {
                solver: "z3",
                model,
            })
        }
        _ => Some(SmtVerdict::Unknown { solver: "z3" }),
    }
}

// ---------------------------------------------------------------------------
// Lexer / AST helpers
// ---------------------------------------------------------------------------

fn strip_outer_parens(mut s: &str) -> &str {
    loop {
        let t = s.trim();
        if t.starts_with('(') && t.ends_with(')') && matching_outer_parens(t) {
            s = &t[1..t.len() - 1];
        } else {
            return t;
        }
    }
}

fn matching_outer_parens(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let bytes = s.as_bytes();
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q && (i == 0 || bytes[i - 1] != b'\\') {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => in_str = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i + 1 < s.len() {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn split_top_level_logical<'a>(s: &'a str, op: &str) -> Option<Vec<&'a str>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if let Some(q) = in_str {
            if ch == q && (i == 0 || bytes[i - 1] != b'\\') {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_str = Some(ch);
                i += 1;
            }
            '(' | '[' | '{' => {
                depth += 1;
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                i += 1;
            }
            _ if depth == 0 && bytes[i..].starts_with(op_bytes) => {
                parts.push(s[start..i].trim());
                i += op_bytes.len();
                start = i;
            }
            _ => i += 1,
        }
    }
    if parts.is_empty() {
        None
    } else {
        parts.push(s[start..].trim());
        Some(parts)
    }
}

fn split_top_level_word_op<'a>(s: &'a str, word: &str) -> Option<Vec<&'a str>> {
    let pat = format!(" {word} ");
    split_top_level_logical(s, &pat)
}

fn split_top_level_cmp(s: &str) -> Option<(&str, CmpOp, &str)> {
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == q && (i == 0 || bytes[i - 1] != b'\\') {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_str = Some(b);
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
            }
            _ if depth == 0 && s.is_char_boundary(i) => {
                let rem = &bytes[i..];
                let matched = if rem.starts_with(b"===") {
                    Some((CmpOp::Eq, 3))
                } else if rem.starts_with(b"!==") {
                    Some((CmpOp::Neq, 3))
                } else if rem.starts_with(b"==") {
                    Some((CmpOp::Eq, 2))
                } else if rem.starts_with(b"!=") {
                    Some((CmpOp::Neq, 2))
                } else if rem.starts_with(b"<=") {
                    Some((CmpOp::Le, 2))
                } else if rem.starts_with(b">=") {
                    Some((CmpOp::Ge, 2))
                } else if rem.starts_with(b"<") && !rem.starts_with(b"<<") {
                    Some((CmpOp::Lt, 1))
                } else if rem.starts_with(b">")
                    && !rem.starts_with(b">>")
                    && (i == 0 || bytes[i - 1] != b'-')
                {
                    Some((CmpOp::Gt, 1))
                } else {
                    None
                };
                if let Some((op, len)) = matched {
                    return Some((&s[..i], op, &s[i + len..]));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn is_valid_var_expr(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || matches!(s, "true" | "false" | "null" | "None") {
        return false;
    }
    let first = s.chars().next().unwrap_or(' ');
    if !(first.is_ascii_alphabetic() || first == '_' || first == '\x24') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '\x24'))
}

fn parse_int_literal(s: &str) -> Option<i64> {
    let t = s.trim().replace('_', "");
    t.parse::<i64>().ok()
}

fn parse_string_literal(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        Some(t[1..t.len() - 1].to_string())
    } else {
        None
    }
}

fn collect_mutated_vars_in_subtree(
    node: Node,
    src: &[u8],
    out: &mut HashSet<String>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    if matches!(
        k,
        "assignment_expression"
            | "augmented_assignment_expression"
            | "compound_assignment_expr"
            | "assignment"
            | "assignment_statement"
            | "short_var_declaration"
    ) {
        if let Some(lhs) = node.child_by_field_name("left") {
            let name = node_text(lhs, src)
                .trim()
                .trim_start_matches('*')
                .trim()
                .to_string();
            if is_valid_var_expr(&name) {
                out.insert(name);
            }
        }
    } else if matches!(k, "update_expression" | "inc_statement" | "dec_statement") {
        let raw = node_text(node, src).trim();
        let cleaned = raw
            .trim_start_matches(['+', '-'])
            .trim_end_matches(['+', '-'])
            .trim()
            .to_string();
        if is_valid_var_expr(&cleaned) {
            out.insert(cleaned);
        }
    } else if matches!(
        k,
        "reference_expression" | "unary_expression" | "pointer_expression"
    ) {
        // Invalidate variables passed by mutable/pointer reference (`&mut x`, `&x`)
        let raw = node_text(node, src).trim();
        if let Some(after_amp) = raw.strip_prefix('&') {
            let cleaned = after_amp
                .trim()
                .strip_prefix("mut")
                .map(str::trim)
                .unwrap_or_else(|| after_amp.trim())
                .trim_start_matches('*')
                .trim();
            if is_valid_var_expr(cleaned) {
                out.insert(cleaned.to_string());
                out.insert(format!("{cleaned}_len"));
            }
        }
    } else if matches!(k, "call_expression" | "method_invocation") {
        // Invalidate receiver `obj` and length aliases on mutating container methods
        let raw = node_text(node, src).trim();
        const MUTATING_METHODS: &[&str] = &[
            ".push(", ".pop(", ".clear(", ".resize(", ".append(", ".insert(", ".remove(",
        ];
        for pat in MUTATING_METHODS {
            if let Some(pos) = raw.find(pat) {
                let recv = raw[..pos].trim().trim_start_matches('*').trim();
                if is_valid_var_expr(recv) {
                    out.insert(recv.to_string());
                    out.insert(format!("{recv}_len"));
                    out.insert(format!("{recv}.len()"));
                    out.insert(format!("{recv}.length"));
                }
            }
        }
    }
    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        collect_mutated_vars_in_subtree(ch, src, out, depth + 1);
    }
}

fn block_always_exits(node: Node, src: &[u8]) -> bool {
    block_always_exits_ctx(node, src, 0, false)
}

fn block_always_exits_ctx(
    node: Node,
    src: &[u8],
    depth: usize,
    in_inner_loop_or_switch: bool,
) -> bool {
    if depth >= 32 {
        return false;
    }
    let k = node.kind();
    // Never treat a nested closure/function body's `return` as exiting the outer block
    if matches!(
        k,
        "arrow_function"
            | "function_expression"
            | "function_declaration"
            | "function_definition"
            | "function_item"
            | "closure_expression"
            | "lambda"
    ) {
        return false;
    }
    if matches!(
        k,
        "return_statement" | "return_expression" | "throw_statement" | "raise_statement"
    ) {
        return true;
    }
    if matches!(
        k,
        "break_statement" | "break_expression" | "continue_statement" | "continue_expression"
    ) {
        return !in_inner_loop_or_switch;
    }
    if matches!(k, "expression_statement" | "macro_invocation") {
        let low = strip_comments(node_text(node, src))
            .trim()
            .to_ascii_lowercase();
        if low.starts_with("panic!(")
            || low.starts_with("unreachable!(")
            || low.starts_with("revert(")
            || low.starts_with("return ")
            || low == "return;"
            || low == "return"
        {
            return true;
        }
        return false;
    }
    if matches!(k, "if_statement" | "if_expression") {
        let cons = node.child_by_field_name("consequence");
        let alt = node.child_by_field_name("alternative");
        return cons
            .is_some_and(|n| block_always_exits_ctx(n, src, depth + 1, in_inner_loop_or_switch))
            && alt.is_some_and(|n| {
                block_always_exits_ctx(n, src, depth + 1, in_inner_loop_or_switch)
            });
    }
    if k == "try_statement" {
        let body = node.child_by_field_name("body");
        let mut handlers = Vec::new();
        let mut finalizer = None;
        let mut cursor = node.walk();
        for ch in node.named_children(&mut cursor) {
            let ck = ch.kind();
            if ck.contains("finally") {
                finalizer = Some(ch);
            } else if ck.contains("catch") || ck.contains("except") {
                handlers.push(ch);
            }
        }
        if let Some(fin) = finalizer
            && block_always_exits_ctx(fin, src, depth + 1, in_inner_loop_or_switch)
        {
            return true;
        }
        let body_exits = body
            .is_some_and(|b| block_always_exits_ctx(b, src, depth + 1, in_inner_loop_or_switch));
        if !body_exits {
            return false;
        }
        if handlers.is_empty() {
            return true;
        }
        return handlers
            .into_iter()
            .all(|h| block_always_exits_ctx(h, src, depth + 1, in_inner_loop_or_switch));
    }
    // Conditional or unconditional loops: sound default is `false` (may execute 0 iterations or break)
    if matches!(
        k,
        "while_statement"
            | "for_statement"
            | "for_in_statement"
            | "for_range_loop"
            | "while_expression"
            | "for_expression"
            | "loop_expression"
            | "do_statement"
    ) {
        return false;
    }
    // Only recurse through sequential statement containers
    if matches!(
        k,
        "statement_block"
            | "block"
            | "compound_statement"
            | "else_clause"
            | "catch_clause"
            | "except_clause"
            | "finally_clause"
            | "parenthesized_expression"
            | "statement_list"
    ) {
        let mut cursor = node.walk();
        for ch in node.named_children(&mut cursor) {
            if block_always_exits_ctx(ch, src, depth + 1, in_inner_loop_or_switch) {
                return true;
            }
        }
    }
    false
}

fn extract_assert_like_arg(trimmed: &str) -> Option<&str> {
    for prefix in ["assert(", "assert!(", "require("] {
        if let Some(rest) = trimmed.strip_prefix(prefix)
            && let Some(inner) = rest.strip_suffix(')')
        {
            return Some(inner.split(',').next().unwrap_or(inner).trim());
        }
    }
    None
}

fn extract_simple_const_binding(trimmed: &str) -> Option<(String, &str)> {
    let body = trimmed
        .strip_prefix("const ")
        .or_else(|| trimmed.strip_prefix("let mut "))
        .or_else(|| trimmed.strip_prefix("let "))
        .or_else(|| trimmed.strip_prefix("var "))
        .unwrap_or(trimmed);
    let (lhs_raw, rhs_raw) = body.split_once('=')?;
    if rhs_raw.starts_with('=') || lhs_raw.ends_with(['!', '<', '>', '+', '-', '*', '/']) {
        return None;
    }
    let lhs = lhs_raw.split(':').next().unwrap_or(lhs_raw).trim();
    if is_valid_var_expr(lhs) {
        Some((lhs.to_string(), rhs_raw.trim()))
    } else {
        None
    }
}

fn constraint_mentions_var(c: &PathConstraint, var: &str) -> bool {
    match c {
        PathConstraint::ConstBool(_) => false,
        PathConstraint::BoolLit { name, .. } => name == var,
        PathConstraint::IntCmp { var: v, .. } | PathConstraint::StrEq { var: v, .. } => v == var,
        PathConstraint::VarCmp { lhs, rhs, .. } => lhs == var || rhs == var,
        PathConstraint::And(parts) | PathConstraint::Or(parts) => {
            parts.iter().any(|p| constraint_mentions_var(p, var))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase15c_builtin_qf_idl_and_boolean_string_contradictions() {
        // 1. Direct integer interval contradiction: x > 10 && x <= 5
        let c1 = vec![
            parse_condition_expr("x > 10").unwrap(),
            parse_condition_expr("x <= 5").unwrap(),
        ];
        assert!(solve_path_constraints(&c1, false).is_unsat());

        // 2. Transitive 3-variable difference-logic negative cycle: a < b && b < c && c <= a
        let c2 = vec![
            parse_condition_expr("a < b").unwrap(),
            parse_condition_expr("b < c").unwrap(),
            parse_condition_expr("c <= a").unwrap(),
        ];
        assert!(solve_path_constraints(&c2, false).is_unsat());

        // 3. Satisfiable bounds: a < b && b < c && a >= 0
        let c3 = vec![
            parse_condition_expr("a < b").unwrap(),
            parse_condition_expr("b < c").unwrap(),
            parse_condition_expr("a >= 0").unwrap(),
        ];
        assert!(!solve_path_constraints(&c3, false).is_unsat());

        // 4. String & boolean contradictions
        let c4 = vec![
            parse_condition_expr("role === 'admin'").unwrap(),
            parse_condition_expr("role !== 'admin'").unwrap(),
        ];
        assert!(solve_path_constraints(&c4, false).is_unsat());

        let c5 = vec![
            parse_condition_expr("isAdmin").unwrap(),
            parse_condition_expr("!isAdmin").unwrap(),
        ];
        assert!(solve_path_constraints(&c5, false).is_unsat());
    }

    #[test]
    fn test_phase15c_smtlib2_emission_format() {
        let constraints = vec![
            parse_condition_expr("amount > 0").unwrap(),
            parse_condition_expr("amount <= limit").unwrap(),
            parse_condition_expr("role === 'admin'").unwrap(),
            parse_condition_expr("!is_disabled").unwrap(),
        ];
        let smt2 = emit_smtlib2(&constraints);
        assert!(smt2.contains("(declare-const v_amount Int)"));
        assert!(smt2.contains("(declare-const v_limit Int)"));
        assert!(smt2.contains("(declare-const v_role String)"));
        assert!(smt2.contains("(declare-const v_is_disabled Bool)"));
        assert!(smt2.contains("(assert (> v_amount 0))"));
        assert!(smt2.contains("(assert (<= v_amount v_limit))"));
        assert!(smt2.contains("(assert (= v_role \"admin\"))"));
        assert!(smt2.contains("(assert (not v_is_disabled))"));
        assert!(smt2.contains("(check-sat)"));

        // Unicode identifiers must not panic in split_top_level_cmp (P0 regression)
        let _ = parse_condition_expr("用户名 === \"admin\"");
        let _ = parse_condition_expr("café > 10");

        // Collision-free SMT-LIB2 ident bijection (`user.id` vs `user_id`)
        let col_constraints = vec![
            parse_condition_expr("user.id > 0").unwrap(),
            parse_condition_expr("user_id < 0").unwrap(),
        ];
        let col_smt2 = emit_smtlib2(&col_constraints);
        assert!(col_smt2.contains("(declare-const v_user_id Int)"));
        assert!(col_smt2.contains("(declare-const v_user_id_2 Int)"));
    }

    #[test]
    fn test_phase15c_end_to_end_dead_branch_pruning_vs_reachable_sink() {
        use crate::ast::parse_file_ast;
        use crate::lattice::solve_guard_lattice;
        use smg_core::{IndexedFile, Language, ShellMindGuardConfig};
        use std::path::PathBuf;

        let run_js = |code: &str| {
            let cfg = ShellMindGuardConfig::default();
            let indexed = IndexedFile {
                rel_path: "src/routes.js".to_string(),
                abs_path: PathBuf::from("src/routes.js"),
                language: Language::JavaScript,
                blake3_hash: String::new(),
                mtime_ns: 0,
                size_bytes: code.len() as u64,
                cached_bytes: Some(code.as_bytes().to_vec()),
            };
            let ast = parse_file_ast(&indexed, &cfg).expect("parse js");
            solve_guard_lattice(&[ast])
        };

        // 1. Dead branch (x > 10 && x < 5 is UNSAT) -> MUST be pruned (0 CMDI findings)
        let dead_interval = run_js(
            r#"
function handler(req, res) {
    const x = req.query.n;
    if (x > 10) {
        if (x < 5) {
            child_process.execSync(req.query.cmd);
        }
    }
}
"#,
        );
        assert!(
            !dead_interval
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001"),
            "UNSAT dead interval branch must be pruned, got: {:#?}",
            dead_interval.findings
        );

        // 2. Early-return string contradiction (`role !== "admin"` returns, then `if (role === "guest")` is UNSAT)
        let dead_early_return = run_js(
            r#"
function adminHandler(req, res) {
    const role = req.user.role;
    if (role !== "admin") {
        return res.status(403).end();
    }
    if (role === "guest") {
        child_process.execSync(req.query.cmd);
    }
}
"#,
        );
        assert!(
            !dead_early_return
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001"),
            "UNSAT early-return string branch must be pruned, got: {:#?}",
            dead_early_return.findings
        );

        // 3. Satisfiable branch (`x > 10 && x < 20` is SAT) -> MUST still report SMG-CMDI-001!
        let live_sat = run_js(
            r#"
function liveHandler(req, res) {
    const x = req.query.n;
    if (x > 10) {
        if (x < 20) {
            child_process.execSync(req.query.cmd);
        }
    }
}
"#,
        );
        assert!(
            live_sat
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001"),
            "SAT reachable branch must still detect SMG-CMDI-001, got: {:#?}",
            live_sat.findings
        );

        // [NEW-01] try/catch with fallthrough catch and loop with break must NOT prune downstream sink
        let try_catch_fallthrough = run_js(
            r#"
function handleTry(req, x) {
    if (x >= 0) {
        try {
            doWork();
            return;
        } catch (e) {
            console.log(e);
        }
    }
    if (x > 10) {
        child_process.execSync(req.query.cmd);
    }
}
"#,
        );
        assert!(
            try_catch_fallthrough
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001"),
            "Fallthrough catch block must not mark if-branch as always exiting: {:#?}",
            try_catch_fallthrough.findings
        );

        let loop_break_fallthrough = run_js(
            r#"
function handleLoop(req, x, n) {
    if (x >= 0) {
        for (let i = 0; i < n; i++) {
            break;
        }
    }
    if (x > 10) {
        child_process.execSync(req.query.cmd);
    }
}
"#,
        );
        assert!(
            loop_break_fallthrough
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001"),
            "Inner loop break must not mark outer if-branch as always exiting: {:#?}",
            loop_break_fallthrough.findings
        );
    }
}
