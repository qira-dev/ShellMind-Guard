use crate::arena::GuardBitset;
use crate::ast::{
    GuardKind, classify_guards, collect_call_names_shallow, is_auth_guard_ident,
    is_lock_guard_ident, node_text, stmt_has_sink_or_mutation,
};
use smg_core::ShellMindGuardConfig;
use std::collections::HashSet;
use tree_sitter::Node;

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

/// Fast $O(N)$ AST text pre-filter: returns `false` for pure helper functions that contain
/// no control-flow branching, guard calls, sanitizers, locks, or state-mutating sinks,
/// avoiding unnecessary CFG/dominator allocations on trivial functions.
fn has_cfg_candidate_signal(body: Node, src: &[u8]) -> bool {
    let raw = node_text(body, src);
    if raw.len() > 64 {
        return true;
    }
    let low = raw.to_ascii_lowercase();
    low.contains('(')
        || low.contains("if")
        || low.contains("match")
        || low.contains("switch")
        || low.contains("try")
        || low.contains("for")
        || low.contains("while")
        || low.contains("auth")
        || low.contains("lock")
        || low.contains("select ")
        || low.contains("update ")
        || low.contains("insert ")
        || low.contains("delete ")
        || low.contains("balance")
        || low.contains("debit")
        || low.contains("withdraw")
}

/// Returns `true` when `stmt` is a variable declaration or assignment whose RHS is an uninvoked
/// closure/function definition (`const f = () => { ... };`), so its body does not pollute outer CFG.
fn is_uninvoked_closure_binding(stmt: Node) -> bool {
    if is_nested_fn_or_closure_kind(stmt.kind()) {
        return true;
    }
    if matches!(
        stmt.kind(),
        "lexical_declaration"
            | "variable_declaration"
            | "short_var_declaration"
            | "assignment_expression"
            | "assignment"
            | "let_declaration"
    ) {
        let mut c = stmt.walk();
        for ch in stmt.named_children(&mut c) {
            if is_nested_fn_or_closure_kind(ch.kind()) {
                return true;
            }
            if matches!(ch.kind(), "variable_declarator" | "init_declarator")
                && let Some(val) = ch.child_by_field_name("value")
                && is_nested_fn_or_closure_kind(val.kind())
            {
                return true;
            }
        }
    }
    false
}
/// Returns `true` if `kind` is an inner function or closure boundary whose control flow
/// (`return`, `throw`, inner statements) must not leak into the enclosing function's CFG.
#[inline]
pub(crate) fn is_nested_fn_or_closure_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_item"
            | "function_definition"
            | "method_declaration"
            | "method_definition"
            | "arrow_function"
            | "closure_expression"
            | "func_literal"
            | "function_expression"
            | "lambda"
            | "anonymous_function"
    )
}

/// Evaluates whether guards strictly dominate every reachable sink (or exit block if sinkless
/// wrapper) in `fn_node` across linear, early-return, conditional diamond, switch/match,
/// try/catch/finally, loop, and post-sink paths.
pub fn compute_cfg_guard_dominance(
    fn_node: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
) -> HashSet<GuardKind> {
    let entry_guards = extract_param_signature_guards(fn_node, src, cfg);
    let Some(body) = fn_node.child_by_field_name("body") else {
        return entry_guards.to_set();
    };
    if !has_cfg_candidate_signal(body, src) {
        return entry_guards.to_set();
    }

    let mut builder = CfgBuilder::new(src, cfg, entry_guards);
    let exit_bb = builder.lower_block(body, 0, 0);
    if builder.blocks.len() > cfg.scan.max_cfg_blocks() {
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
        if self.blocks.len() >= self.cfg.scan.max_cfg_blocks() {
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
        if depth >= self.cfg.scan.max_ast_block_depth()
            || self.blocks.len() >= self.cfg.scan.max_cfg_blocks()
        {
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
            // Ignore nested inner function/closure declarations (analyzed as their own symbols)
            if is_uninvoked_closure_binding(stmt) {
                continue;
            }

            if matches!(sk, "if_statement" | "if_expression" | "elif_clause") {
                cur_bb = self.lower_if(stmt, cur_bb, depth + 1)?;
                continue;
            }
            if matches!(
                sk,
                "switch_statement"
                    | "expression_switch_statement"
                    | "type_switch_statement"
                    | "match_expression"
            ) {
                cur_bb = self.lower_switch_or_match(stmt, cur_bb, depth + 1)?;
                continue;
            }
            if sk == "try_statement" {
                cur_bb = self.lower_try(stmt, cur_bb, depth + 1)?;
                continue;
            }
            if matches!(
                sk,
                "for_statement"
                    | "for_in_statement"
                    | "while_statement"
                    | "for_expression"
                    | "while_expression"
                    | "loop_expression"
            ) {
                cur_bb = self.lower_loop(stmt, cur_bb, depth + 1)?;
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
        let cond_node = if_node.child_by_field_name("condition");
        let (cond_guards, cond_is_negated) = cond_node
            .map(|c| {
                let g = self
                    .stmt_direct_guards(c)
                    .union(self.early_cond_text_guards(if_node));
                let c_txt = crate::ast::strip_comments(node_text(c, self.src));
                let t = c_txt.trim_start().trim_start_matches('(').trim_start();
                let neg = t.starts_with('!')
                    || t.starts_with("not ")
                    || t.contains("!= nil")
                    || t.contains("== nil")
                    || t.contains("== null")
                    || t.contains("== false")
                    || t.contains("=== false");
                (g, neg)
            })
            .unwrap_or_else(|| (self.early_cond_text_guards(if_node), false));

        let consequence = if_node
            .child_by_field_name("consequence")
            .or_else(|| if_node.child_by_field_name("body"));
        let alternative = if_node.child_by_field_name("alternative");

        let then_start = self.new_block()?;
        self.link(pre_bb, then_start);
        // Positive branch condition (`if (verifyJwt(req)) { sink(); }`, `if (idx < cap) { ... }`)
        // grants condition guards inside `then_start` even when `else` does not abort.
        if !cond_is_negated
            && !cond_guards.is_empty()
            && let Some(tb) = self.blocks.get_mut(then_start)
        {
            tb.pre_sink_guards = tb.pre_sink_guards.union(cond_guards);
            tb.post_guards = tb.post_guards.union(cond_guards);
        }
        let then_end = if let Some(cons) = consequence {
            self.lower_block(cons, then_start, depth)
        } else {
            Some(then_start)
        };

        let then_terminated = then_end.is_none();
        if then_terminated {
            for b in &mut self.blocks[then_start..] {
                if b.succs.is_empty() {
                    b.is_abort_exit = true;
                }
            }
        }

        let mut else_start_idx: Option<usize> = None;
        let else_end = if let Some(alt) = alternative {
            let else_start = self.new_block()?;
            else_start_idx = Some(else_start);
            self.link(pre_bb, else_start);
            // Negated condition (`if (!verifyJwt(req)) { ... } else { sink(); }`) grants guard on `else_start`.
            if cond_is_negated
                && !cond_guards.is_empty()
                && let Some(eb) = self.blocks.get_mut(else_start)
            {
                eb.pre_sink_guards = eb.pre_sink_guards.union(cond_guards);
                eb.post_guards = eb.post_guards.union(cond_guards);
            }
            self.lower_block(alt, else_start, depth)
        } else {
            let fall_bb = self.new_block()?;
            self.link(pre_bb, fall_bb);
            if then_terminated && let Some(b) = self.blocks.get_mut(fall_bb) {
                // Passing a terminating auth/lock/bounds guard condition grants that guard along the surviving path.
                b.pre_sink_guards = b.pre_sink_guards.union(cond_guards);
                b.post_guards = b.post_guards.union(cond_guards);
            }
            Some(fall_bb)
        };

        // Mark abort exits on `if (ok) { ... } else { return 401; }` and propagate guard onto `then_start`.
        if else_end.is_none() {
            if let Some(es) = else_start_idx {
                for b in &mut self.blocks[es..] {
                    if b.succs.is_empty() {
                        b.is_abort_exit = true;
                    }
                }
            }
            if !then_terminated && let Some(tb) = self.blocks.get_mut(then_start) {
                tb.pre_sink_guards = tb.pre_sink_guards.union(cond_guards);
                tb.post_guards = tb.post_guards.union(cond_guards);
            }
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

    fn lower_switch_or_match(
        &mut self,
        sw_node: Node,
        pre_bb: usize,
        depth: usize,
    ) -> Option<usize> {
        let mut arm_nodes = Vec::new();
        let mut has_default_arm = false;
        let mut c = sw_node.walk();
        for ch in sw_node.children(&mut c) {
            let ck = ch.kind();
            if matches!(
                ck,
                "switch_case" | "switch_default" | "expression_case" | "default_case" | "match_arm"
            ) {
                if ck == "switch_default"
                    || ck == "default_case"
                    || (ck == "match_arm" && node_text(ch, self.src).trim_start().starts_with('_'))
                {
                    has_default_arm = true;
                }
                arm_nodes.push(ch);
            } else if matches!(ck, "switch_body" | "match_block") {
                let mut sc = ch.walk();
                for sub in ch.children(&mut sc) {
                    let sk = sub.kind();
                    if matches!(
                        sk,
                        "switch_case"
                            | "switch_default"
                            | "expression_case"
                            | "default_case"
                            | "match_arm"
                    ) {
                        if sk == "switch_default"
                            || sk == "default_case"
                            || (sk == "match_arm"
                                && node_text(sub, self.src).trim_start().starts_with('_'))
                        {
                            has_default_arm = true;
                        }
                        arm_nodes.push(sub);
                    }
                }
            }
        }
        if arm_nodes.is_empty() {
            return Some(pre_bb);
        }

        let mut surviving_ends = Vec::new();
        for arm in arm_nodes {
            let arm_start = self.new_block()?;
            self.link(pre_bb, arm_start);
            if let Some(end_bb) = self.lower_block(arm, arm_start, depth + 1) {
                surviving_ends.push(end_bb);
            } else {
                for b in &mut self.blocks[arm_start..] {
                    if b.succs.is_empty() {
                        b.is_abort_exit = true;
                    }
                }
            }
        }
        // If switch/match has no default/wildcard arm, an unmatched value bypasses all cases.
        if !has_default_arm {
            let bypass_bb = self.new_block()?;
            self.link(pre_bb, bypass_bb);
            surviving_ends.push(bypass_bb);
        }
        if surviving_ends.is_empty() {
            return None;
        }
        let join = self.new_block()?;
        for end_bb in surviving_ends {
            self.link(end_bb, join);
        }
        Some(join)
    }

    fn lower_try(&mut self, try_node: Node, pre_bb: usize, depth: usize) -> Option<usize> {
        let mut try_body: Option<Node> = try_node.child_by_field_name("body");
        let mut catch_nodes = Vec::new();
        let mut finally_node: Option<Node> = None;

        let mut c = try_node.walk();
        for ch in try_node.children(&mut c) {
            match ch.kind() {
                "statement_block" | "block" | "compound_statement" if try_body.is_none() => {
                    try_body = Some(ch);
                }
                "catch_clause" | "except_clause" => catch_nodes.push(ch),
                "finally_clause" => finally_node = Some(ch),
                _ => {}
            }
        }

        let try_start = self.new_block()?;
        self.link(pre_bb, try_start);
        let try_end = if let Some(tb) = try_body {
            self.lower_block(tb, try_start, depth + 1)
        } else {
            Some(try_start)
        };
        if try_end.is_none() {
            for b in &mut self.blocks[try_start..] {
                if b.succs.is_empty() {
                    b.is_abort_exit = true;
                }
            }
        }

        let mut surviving = Vec::new();
        if let Some(te) = try_end {
            surviving.push(te);
        }
        for cn in catch_nodes {
            let catch_start = self.new_block()?;
            // Exception may occur before try-block guards complete, so link from `pre_bb`.
            self.link(pre_bb, catch_start);
            if let Some(ce) = self.lower_block(cn, catch_start, depth + 1) {
                surviving.push(ce);
            } else {
                for b in &mut self.blocks[catch_start..] {
                    if b.succs.is_empty() {
                        b.is_abort_exit = true;
                    }
                }
            }
        }

        if surviving.is_empty() {
            return None;
        }
        let join = self.new_block()?;
        for s in surviving {
            self.link(s, join);
        }
        if let Some(fin) = finally_node {
            self.lower_block(fin, join, depth + 1)
        } else {
            Some(join)
        }
    }

    fn lower_loop(&mut self, loop_node: Node, pre_bb: usize, depth: usize) -> Option<usize> {
        let is_unconditional_loop = loop_node.kind() == "loop_expression";
        let body_start = self.new_block()?;
        self.link(pre_bb, body_start);
        let body_end = self.lower_block(loop_node, body_start, depth + 1);
        let join = self.new_block()?;
        if let Some(be) = body_end {
            self.link(be, join);
        }
        // Conditional `for`/`while` loops may execute 0 iterations, so guards inside the loop
        // body do not dominate statements after the loop unless verified before the loop.
        if !is_unconditional_loop {
            self.link(pre_bb, join);
        } else if body_end.is_none() {
            return None;
        }
        Some(join)
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
            // Relational / ownership / bounds / path / SSRF / CSRF guard predicates in conditions
            if (cond_head.contains("owner_id")
                || cond_head.contains("ownerid")
                || cond_head.contains("user_id")
                || cond_head.contains("userid")
                || cond_head.contains("tenant_id")
                || cond_head.contains("org_id"))
                && (cond_head.contains("==")
                    || cond_head.contains("===")
                    || cond_head.contains("!=")
                    || cond_head.contains("!=="))
            {
                bits.insert(GuardKind::OwnershipCheck);
            }
            if cond_head.contains("csrf") {
                bits.insert(GuardKind::CsrfProtection);
            }
            if cond_head.contains("startswith(")
                || cond_head.contains("starts_with(")
                || cond_head.contains("hasprefix(")
                || cond_head.contains("isallowedpath")
            {
                bits.insert(GuardKind::PathSanitizer);
            }
            if cond_head.contains("allowed_hosts")
                || cond_head.contains("allowedhosts")
                || cond_head.contains("is_private")
                || cond_head.contains("is_loopback")
            {
                bits.insert(GuardKind::SsrfSanitizer);
            }
            if cond_head.contains("< sizeof(")
                || cond_head.contains("<= sizeof(")
                || cond_head.contains(".len()")
                || cond_head.contains(".length")
                || cond_head.contains("checked_add")
                || cond_head.contains("checked_mul")
            {
                bits.insert(GuardKind::MemoryBounds);
            }
        }
        bits
    }

    fn stmt_direct_guards(&self, stmt: Node) -> GuardBitset {
        let mut bits = GuardBitset::EMPTY;
        if is_uninvoked_closure_binding(stmt) {
            return bits;
        }
        let mut calls = Vec::new();
        collect_call_names_shallow(stmt, self.src, &mut calls);
        for c in &calls {
            if is_auth_guard_ident(c, self.cfg) {
                bits.insert(GuardKind::Auth);
            }
            if is_lock_guard_ident(c, self.cfg) {
                bits.insert(GuardKind::TxLock);
            }
            let c_low = c.to_ascii_lowercase();
            if c_low.contains(" verifycsrf")
                || c_low == "verifycsrf"
                || c_low == "verify_csrf"
                || c_low == "csurf"
            {
                bits.insert(GuardKind::CsrfProtection);
            }
            if c_low.contains("checkownership")
                || c_low.contains("check_ownership")
                || c_low.contains("verifyowner")
                || c_low.contains("verify_owner")
            {
                bits.insert(GuardKind::OwnershipCheck);
            }
        }

        let stmt_raw = crate::ast::strip_comments(node_text(stmt, self.src));
        let stmt_code = stmt_raw.to_ascii_lowercase();
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
        if crate::taint::has_csrf_guard_expr(&stmt_raw) {
            bits.insert(GuardKind::CsrfProtection);
        }
        if stmt_code.contains(".parse(")
            || stmt_code.contains(".safeparse(")
            || stmt_code.contains("validate(")
        {
            bits.insert(GuardKind::InputValidation);
        }
        bits
    }
}

fn stmt_unconditionally_exits(stmt: Node, src: &[u8]) -> bool {
    let k = stmt.kind();
    if is_uninvoked_closure_binding(stmt) {
        return false;
    }
    if matches!(
        k,
        "return_statement" | "throw_statement" | "raise_statement" | "return_expression"
    ) {
        return true;
    }
    if matches!(
        k,
        "statement_block" | "block" | "compound_statement" | "else_clause"
    ) {
        let mut c = stmt.walk();
        return stmt
            .children(&mut c)
            .any(|ch| stmt_unconditionally_exits(ch, src));
    }
    let code = crate::ast::strip_comments(node_text(stmt, src)).to_ascii_lowercase();
    code.starts_with("return ")
        || code == "return;"
        || code == "return"
        || code.starts_with("throw ")
        || code.starts_with("raise ")
        || code.contains("bail!(")
        || code.contains("panic!(")
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

    #[test]
    fn test_sprint1_else_abort_closure_isolation_switch_try_and_loops() {
        // 1. Inverted `if (ok) { ... } else { return 401; }` wrapper (no direct sink) must keep Auth
        let inverted_wrapper = eval_ts_fn_guards(
            r#"function authMiddleware(req: any, res: any) {
                if (verifyJwt(req)) {
                    doNext();
                } else {
                    return res.status(401).end();
                }
            }"#,
        );
        assert!(
            inverted_wrapper.contains(&GuardKind::Auth),
            "Inverted if/else abort must preserve Auth dominance on normal exit"
        );

        // 2. Uninvoked closure binding must NOT leak Auth or early return to enclosing handler
        let uninvoked_closure = eval_ts_fn_guards(
            r#"function pay(req: any, res: any) {
                const helper = () => {
                    requireAuth(req);
                    return res.status(401).end();
                };
                balance -= req.body.amount;
            }"#,
        );
        assert!(
            !uninvoked_closure.contains(&GuardKind::Auth),
            "Uninvoked closure must not grant Auth to enclosing function"
        );

        // 3. Exhaustive switch where all surviving arms have Auth vs non-exhaustive switch
        let sw_exhaustive = eval_ts_fn_guards(
            r#"function pay(req: any, res: any) {
                switch (req.mode) {
                    case 'a':
                        requireAuth(req);
                        break;
                    default:
                        return res.status(401).end();
                }
                balance -= req.body.amount;
            }"#,
        );
        assert!(sw_exhaustive.contains(&GuardKind::Auth));

        let sw_non_exhaustive = eval_ts_fn_guards(
            r#"function pay(req: any) {
                switch (req.mode) {
                    case 'a':
                        requireAuth(req);
                        break;
                }
                balance -= req.body.amount;
            }"#,
        );
        assert!(
            !sw_non_exhaustive.contains(&GuardKind::Auth),
            "Non-exhaustive switch without default must not dominate post-switch sink"
        );

        // 4. try/catch: non-aborting catch prevents dominance; aborting catch preserves dominance
        let try_swallowed = eval_ts_fn_guards(
            r#"function pay(req: any) {
                try {
                    requireAuth(req);
                } catch (e) {
                    logErr(e);
                }
                balance -= req.body.amount;
            }"#,
        );
        assert!(!try_swallowed.contains(&GuardKind::Auth));

        let try_abort_catch = eval_ts_fn_guards(
            r#"function pay(req: any, res: any) {
                try {
                    requireAuth(req);
                } catch (e) {
                    return res.status(401).end();
                }
                balance -= req.body.amount;
            }"#,
        );
        assert!(try_abort_catch.contains(&GuardKind::Auth));
    }
}
