use crate::arena::GuardBitset;
use crate::ast::{
    GuardKind, classify_guards, collect_call_names_shallow, is_auth_guard_ident,
    is_lock_guard_ident, node_text, stmt_has_sink_or_mutation,
};
use smg_core::ShellMindGuardConfig;
use std::collections::HashSet;
use tree_sitter::Node;

const MAX_CFG_BLOCKS: usize = 256;
const MAX_AST_BLOCK_DEPTH: usize = 32;

/// Single Basic Block inside a selective per-function CFG built for candidate routes & sinks.
#[derive(Debug, Clone)]
pub struct CfgBlock {
    pub preds: Vec<usize>,
    pub succs: Vec<usize>,
    /// Guards proven at the entry/body of this block prior to its first sink (if any).
    pub pre_sink_guards: GuardBitset,
    /// Guards granted anywhere in this block (only propagates out if not terminated early).
    pub post_guards: GuardBitset,
    pub has_sink: bool,
    pub is_exit: bool,
    pub is_abort_exit: bool,
}

/// Evaluates whether guards strictly dominate every reachable sink (or exit block if sinkless
/// wrapper) in `fn_node` across linear, early-return, conditional diamond, and post-sink paths.
pub fn compute_cfg_guard_dominance(
    fn_node: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
) -> HashSet<GuardKind> {
    let entry_guards = extract_param_signature_guards(fn_node, src, cfg);
    let Some(body) = fn_node.child_by_field_name("body") else {
        return entry_guards.to_set();
    };

    let mut builder = CfgBuilder::new(src, cfg, entry_guards);
    let exit_bb = builder.lower_block(body, 0, 0);
    if builder.blocks.len() > MAX_CFG_BLOCKS {
        return entry_guards.to_set();
    }

    // Mark normal reachable exit if body didn't already terminate early.
    if let Some(eb) = exit_bb
        && let Some(b) = builder.blocks.get_mut(eb)
        && !b.is_exit
    {
        b.is_exit = b.succs.is_empty();
    }

    let n = builder.blocks.len();
    let mut in_bits = vec![GuardBitset::EMPTY; n];
    let mut out_bits = vec![GuardBitset::EMPTY; n];
    out_bits[0] = builder.blocks[0].post_guards;

    // Iterative forward dataflow meet (intersection over predecessors):
    // G_in(b)  = Intersection_{p in Pred(b)} G_out(p)
    // G_out(b) = G_in(b) U block_post_guards(b)
    let mut changed = true;
    let mut iters = 0usize;
    while changed && iters < n * 4 + 8 {
        changed = false;
        iters += 1;
        for b_idx in 1..n {
            let preds = &builder.blocks[b_idx].preds;
            if preds.is_empty() {
                continue;
            }
            let mut meet = GuardBitset(u32::MAX);
            let mut any_pred_reachable = false;
            for &p in preds {
                if p == 0 || !builder.blocks[p].preds.is_empty() {
                    any_pred_reachable = true;
                    meet = meet.intersect(out_bits[p]);
                }
            }
            if !any_pred_reachable {
                continue;
            }
            let next_out = meet.union(builder.blocks[b_idx].post_guards);
            if in_bits[b_idx] != meet || out_bits[b_idx] != next_out {
                in_bits[b_idx] = meet;
                out_bits[b_idx] = next_out;
                changed = true;
            }
        }
    }

    // If the function itself has direct sinks/mutations, require dominating guards before EVERY sink.
    // Otherwise (middleware/handler wrapper calling downstream helpers), require dominance at exits.
    let sink_indices: Vec<usize> = builder
        .blocks
        .iter()
        .enumerate()
        .filter(|&(i, b)| b.has_sink && (i == 0 || !b.preds.is_empty()))
        .map(|(i, _)| i)
        .collect();

    let mut proven = GuardBitset(u32::MAX);
    let mut inspected = false;
    if !sink_indices.is_empty() {
        for si in sink_indices {
            inspected = true;
            let at_sink = in_bits[si].union(builder.blocks[si].pre_sink_guards);
            proven = proven.intersect(at_sink);
        }
    } else {
        let has_normal_exit = builder.blocks.iter().enumerate().any(|(i, b)| {
            !b.is_abort_exit && b.succs.is_empty() && (i == 0 || !b.preds.is_empty())
        });
        for (i, b) in builder.blocks.iter().enumerate() {
            if b.succs.is_empty()
                && (i == 0 || !b.preds.is_empty())
                && (!has_normal_exit || !b.is_abort_exit)
            {
                inspected = true;
                proven = proven.intersect(out_bits[i]);
            }
        }
    }

    if inspected {
        proven.to_set()
    } else {
        entry_guards.to_set()
    }
}

/// Extracts DI / signature security extractors (`Depends(require_auth)`, `Security(...)`,
/// Rust `AuthUser`/`Claims` extractors) from a function's parameter list.
pub(crate) fn extract_param_signature_guards(
    fn_node: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
) -> GuardBitset {
    let mut bits = GuardBitset::EMPTY;
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return bits;
    };
    let mut calls = Vec::new();
    collect_call_names_shallow(params, src, &mut calls);
    for c in &calls {
        if is_auth_guard_ident(c, cfg) || c.eq_ignore_ascii_case("Security") {
            bits.insert(GuardKind::Auth);
        }
        if is_lock_guard_ident(c, cfg) {
            bits.insert(GuardKind::TxLock);
        }
    }
    let params_txt = node_text(params, src);
    // Match snake_case or camelCase dependency references inside `Depends(...)` / `Security(...)`
    // and typed Rust/TS extractors (`AuthUser`, `Claims`, `@CurrentUser`).
    for g in classify_guards(params_txt, cfg) {
        bits.insert(g);
    }
    let params_low = params_txt.to_ascii_lowercase();
    if params_low.contains("depends(") {
        let compact = params_low.replace('_', "");
        if cfg
            .guards
            .auth_guards
            .iter()
            .any(|pat| compact.contains(&pat.to_ascii_lowercase().replace('_', "")))
        {
            bits.insert(GuardKind::Auth);
        }
    }
    bits
}

struct CfgBuilder<'a> {
    src: &'a [u8],
    cfg: &'a ShellMindGuardConfig,
    blocks: Vec<CfgBlock>,
}

impl<'a> CfgBuilder<'a> {
    fn new(src: &'a [u8], cfg: &'a ShellMindGuardConfig, entry_guards: GuardBitset) -> Self {
        Self {
            src,
            cfg,
            blocks: vec![CfgBlock {
                preds: Vec::new(),
                succs: Vec::new(),
                pre_sink_guards: entry_guards,
                post_guards: entry_guards,
                has_sink: false,
                is_exit: false,
                is_abort_exit: false,
            }],
        }
    }

    fn new_block(&mut self) -> Option<usize> {
        if self.blocks.len() >= MAX_CFG_BLOCKS {
            return None;
        }
        let id = self.blocks.len();
        self.blocks.push(CfgBlock {
            preds: Vec::new(),
            succs: Vec::new(),
            pre_sink_guards: GuardBitset::EMPTY,
            post_guards: GuardBitset::EMPTY,
            has_sink: false,
            is_exit: false,
            is_abort_exit: false,
        });
        Some(id)
    }

    fn link(&mut self, from: usize, to: usize) {
        if from < self.blocks.len() && to < self.blocks.len() {
            if !self.blocks[from].succs.contains(&to) {
                self.blocks[from].succs.push(to);
            }
            if !self.blocks[to].preds.contains(&from) {
                self.blocks[to].preds.push(from);
            }
        }
    }

    /// Lowers a block/statement list returning `Some(fallthrough_bb)` or `None` if all paths terminated.
    fn lower_block(&mut self, node: Node, mut cur_bb: usize, depth: usize) -> Option<usize> {
        if depth >= MAX_AST_BLOCK_DEPTH || self.blocks.len() >= MAX_CFG_BLOCKS {
            return Some(cur_bb);
        }
        let mut cursor = node.walk();
        for stmt in node.children(&mut cursor) {
            let sk = stmt.kind();
            if matches!(
                sk,
                "{" | "}" | "comment" | "line_comment" | "block_comment" | ":"
            ) {
                continue;
            }
            // Skip Python docstrings
            if sk == "expression_statement" {
                let mut sc = stmt.walk();
                let children: Vec<Node> = stmt.named_children(&mut sc).collect();
                if children.len() == 1 && matches!(children[0].kind(), "string" | "string_literal")
                {
                    continue;
                }
            }
            // Ignore nested inner function declarations (analyzed as their own symbols)
            if matches!(
                sk,
                "function_declaration" | "function_item" | "function_definition"
            ) {
                continue;
            }

            if matches!(sk, "if_statement" | "if_expression" | "elif_clause") {
                cur_bb = self.lower_if(stmt, cur_bb, depth + 1)?;
                continue;
            }
            if matches!(
                sk,
                "else_clause"
                    | "statement_block"
                    | "statement_list"
                    | "block"
                    | "compound_statement"
            ) {
                cur_bb = self.lower_block(stmt, cur_bb, depth + 1)?;
                continue;
            }

            // Record sequential statement guards & sink order inside `cur_bb`.
            let stmt_guards = self.stmt_direct_guards(stmt);
            let is_sink = stmt_has_sink_or_mutation(stmt, self.src);
            if let Some(bb) = self.blocks.get_mut(cur_bb) {
                if is_sink {
                    // Guards on a wrapping expression like `db.transaction(async () => { ... })`
                    // execute before the nested sink mutation; statements strictly after do not.
                    if !bb.has_sink {
                        bb.pre_sink_guards = bb.post_guards.union(stmt_guards);
                        bb.has_sink = true;
                    }
                    bb.post_guards = bb.post_guards.union(stmt_guards);
                } else {
                    bb.post_guards = bb.post_guards.union(stmt_guards);
                    if !bb.has_sink {
                        bb.pre_sink_guards = bb.post_guards;
                    }
                }
            }

            if stmt_unconditionally_exits(stmt, self.src) {
                if let Some(bb) = self.blocks.get_mut(cur_bb) {
                    bb.is_exit = true;
                }
                return None;
            }
        }
        Some(cur_bb)
    }

    fn lower_if(&mut self, if_node: Node, pre_bb: usize, depth: usize) -> Option<usize> {
        let cond_guards = if_node
            .child_by_field_name("condition")
            .map(|c| {
                self.stmt_direct_guards(c)
                    .union(self.early_cond_text_guards(if_node))
            })
            .unwrap_or_else(|| self.early_cond_text_guards(if_node));

        let consequence = if_node
            .child_by_field_name("consequence")
            .or_else(|| if_node.child_by_field_name("body"));
        let alternative = if_node.child_by_field_name("alternative");

        let then_start = self.new_block()?;
        self.link(pre_bb, then_start);
        let then_end = if let Some(cons) = consequence {
            self.lower_block(cons, then_start, depth)
        } else {
            Some(then_start)
        };

        let then_terminated = then_end.is_none();

        let else_end = if let Some(alt) = alternative {
            let else_start = self.new_block()?;
            self.link(pre_bb, else_start);
            self.lower_block(alt, else_start, depth)
        } else {
            // Fallthrough edge (condition false / early-return guard passed).
            if then_terminated && !cond_guards.is_empty() {
                for b in &mut self.blocks[then_start..] {
                    if b.succs.is_empty() {
                        b.is_abort_exit = true;
                    }
                }
            }
            let fall_bb = self.new_block()?;
            self.link(pre_bb, fall_bb);
            if then_terminated && let Some(b) = self.blocks.get_mut(fall_bb) {
                // Passing a terminating auth/lock guard condition grants that guard along the surviving path.
                b.pre_sink_guards = cond_guards;
                b.post_guards = cond_guards;
            }
            Some(fall_bb)
        };

        // Also propagate guard on `if (ok) { ... } else { return 401; }` pattern!
        if !then_terminated
            && else_end.is_none()
            && let Some(tb) = self.blocks.get_mut(then_start)
        {
            tb.pre_sink_guards = tb.pre_sink_guards.union(cond_guards);
            tb.post_guards = tb.post_guards.union(cond_guards);
        }

        match (then_end, else_end) {
            (Some(t), Some(e)) => {
                let join = self.new_block()?;
                self.link(t, join);
                self.link(e, join);
                Some(join)
            }
            (Some(surviving), None) | (None, Some(surviving)) => Some(surviving),
            (None, None) => None,
        }
    }

    fn early_cond_text_guards(&self, if_node: Node) -> GuardBitset {
        let if_txt = crate::ast::strip_comments(node_text(if_node, self.src)).to_ascii_lowercase();
        let mut bits = GuardBitset::EMPTY;
        if let Some(cond_head) = if_txt.lines().next() {
            let mut calls = Vec::new();
            collect_call_names_shallow(if_node, self.src, &mut calls);
            for c in &calls {
                if is_auth_guard_ident(c, self.cfg) {
                    bits.insert(GuardKind::Auth);
                }
                if is_lock_guard_ident(c, self.cfg) {
                    bits.insert(GuardKind::TxLock);
                }
            }
            let is_user_forbidden = (cond_head.contains("req.user")
                || cond_head.contains("session.user")
                || cond_head.contains("current_user"))
                && (if_txt.contains("401")
                    || if_txt.contains("403")
                    || if_txt.contains("unauthoriz"));
            let is_unauth_early_exit = (if_txt.contains("401")
                || if_txt.contains("statusunauthorized")
                || if_txt.contains("errunauthorized"))
                && (cond_head.contains("req.")
                    || cond_head.contains("session")
                    || cond_head.contains("sess")
                    || cond_head.contains("user")
                    || cond_head.contains("auth")
                    || cond_head.contains("token")
                    || cond_head.contains("claims")
                    || cond_head.contains("err != nil")
                    || cond_head.contains("!ok")
                    || cond_head.contains("== nil")
                    || cond_head.contains("== \"\""));
            if is_user_forbidden || is_unauth_early_exit {
                bits.insert(GuardKind::Auth);
            }
        }
        bits
    }

    fn stmt_direct_guards(&self, stmt: Node) -> GuardBitset {
        let mut bits = GuardBitset::EMPTY;
        let mut calls = Vec::new();
        collect_call_names_shallow(stmt, self.src, &mut calls);
        for c in &calls {
            if is_auth_guard_ident(c, self.cfg) {
                bits.insert(GuardKind::Auth);
            }
            if is_lock_guard_ident(c, self.cfg) {
                bits.insert(GuardKind::TxLock);
            }
        }

        let stmt_code = crate::ast::strip_comments(node_text(stmt, self.src)).to_ascii_lowercase();
        if (stmt_code.contains("select ") && stmt_code.contains("for update"))
            || (stmt.kind() == "with_statement"
                && self
                    .cfg
                    .guards
                    .lock_guards
                    .iter()
                    .any(|pat| stmt_code.contains(&pat.to_ascii_lowercase())))
        {
            bits.insert(GuardKind::TxLock);
        }
        bits
    }
}

fn stmt_unconditionally_exits(stmt: Node, src: &[u8]) -> bool {
    let k = stmt.kind();
    if matches!(
        k,
        "return_statement" | "throw_statement" | "raise_statement"
    ) {
        return true;
    }
    let code = crate::ast::strip_comments(node_text(stmt, src)).to_ascii_lowercase();
    code.starts_with("return ")
        || code == "return;"
        || code.starts_with("throw ")
        || code.starts_with("raise ")
        || code.contains("bail!(")
        || code.contains("abort(")
        || code.contains("abortwithstatus")
        || code.contains("http.error(")
        || code.contains("return res.status(")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn eval_ts_fn_guards(code: &str) -> HashSet<GuardKind> {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = p.parse(code, None).unwrap();
        let root = tree.root_node();
        let mut c = root.walk();
        let fn_node = root
            .children(&mut c)
            .find(|n| n.kind() == "function_declaration")
            .unwrap();
        compute_cfg_guard_dominance(fn_node, code.as_bytes(), &ShellMindGuardConfig::default())
    }

    #[test]
    fn test_cfg_dominator_allows_early_return_and_diamond_blocks_side_branch_and_late() {
        let early = eval_ts_fn_guards(
            r#"function pay(req: any) {
                if (!verifyJwt(req)) { return res.status(401).end(); }
                balance -= req.body.amount;
            }"#,
        );
        assert!(early.contains(&GuardKind::Auth));

        let side_branch = eval_ts_fn_guards(
            r#"function pay(req: any) {
                if (req.query.strict === '1') { requireAuth(req); }
                balance -= req.body.amount;
            }"#,
        );
        assert!(!side_branch.contains(&GuardKind::Auth));

        let late = eval_ts_fn_guards(
            r#"function pay(req: any) {
                balance -= req.body.amount;
                requireAuth(req);
            }"#,
        );
        assert!(!late.contains(&GuardKind::Auth));

        let diamond = eval_ts_fn_guards(
            r#"function pay(req: any) {
                if (req.headers.x) { requireAuth(req); } else { verifyJwt(req); }
                balance -= req.body.amount;
            }"#,
        );
        assert!(diamond.contains(&GuardKind::Auth));

        let go_code = r#"
package main
func customGate(w http.ResponseWriter, r *http.Request) {
    sess, ok := getSession(r)
    if !ok || sess == nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    chargeAccount()
}
"#;
        let mut gp = Parser::new();
        gp.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap();
        let gtree = gp.parse(go_code, None).unwrap();
        let groot = gtree.root_node();
        let mut gc = groot.walk();
        let gfn = groot
            .children(&mut gc)
            .find(|n| n.kind() == "function_declaration")
            .unwrap();
        let go_guards =
            compute_cfg_guard_dominance(gfn, go_code.as_bytes(), &ShellMindGuardConfig::default());
        assert!(go_guards.contains(&GuardKind::Auth));
    }
}
