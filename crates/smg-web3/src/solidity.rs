use crate::context::{
    EvmSlotEntry, StateVarSpec, Web3Context, abi_selector, pack_storage_vars_with_defs,
};
use crate::evm_oracle::{
    check_amm_spot_skew_bps, probe_compiled_reentrancy_in_revm, probe_compiled_selector_unauth,
    solve_erc4626_inflation_witness,
};
use revm::primitives::U256;
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Contract,
    AbstractContract,
    Interface,
    Library,
}

#[derive(Debug, Clone)]
pub enum EffectOp {
    ReadState {
        var: String,
        line: usize,
        byte_offset: usize,
        branch_path: Vec<(usize, u8)>,
    },
    WriteState {
        var: String,
        is_accounting: bool,
        is_rhs_nominal_amount: bool,
        line: usize,
        byte_offset: usize,
        branch_path: Vec<(usize, u8)>,
    },
    ExternalCall {
        has_callback_risk: bool,
        kind: String,
        line: usize,
        byte_offset: usize,
        branch_path: Vec<(usize, u8)>,
        in_returning_branch: bool,
    },
    InternalCall {
        callee: String,
        line: usize,
        byte_offset: usize,
        branch_path: Vec<(usize, u8)>,
    },
}

#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub start_line: usize,
    pub visibility: String,
    pub mutability: String,
    pub modifiers: Vec<String>,
    pub params_text: String,
    pub body_text: String,
    pub is_constructor: bool,
    pub ops: Vec<EffectOp>,
    pub div_before_mul_lines: Vec<usize>,
    pub tx_origin_auth_lines: Vec<usize>,
    pub unsafe_delegatecall_lines: Vec<(usize, String)>,
}

#[derive(Debug, Clone)]
pub struct ParsedContract {
    pub name: String,
    pub kind: ContractKind,
    pub start_line: usize,
    pub is_proxy_like: bool,
    pub bases: Vec<String>,
    pub state_vars: Vec<StateVarSpec>,
    pub packed_slots: Vec<EvmSlotEntry>,
    pub custom_auth_modifiers: HashSet<String>,
    pub custom_lock_modifiers: HashSet<String>,
    pub functions: Vec<ParsedFunction>,
    pub has_erc7201_namespace: bool,
}

fn node_txt<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn is_accounting_state_var(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    [
        "balance",
        "balances",
        "share",
        "shares",
        "supply",
        "totalsupply",
        "totalassets",
        "asset",
        "assets",
        "debt",
        "reward",
        "rewards",
        "claimed",
        "deposit",
        "deposits",
        "stake",
        "staked",
        "nonce",
        "nonces",
        "withdrawn",
        "reserve",
        "reserves",
        "credit",
        "collateral",
        "useramount",
    ]
    .iter()
    .any(|kw| low.contains(kw))
}

fn collect_identifiers(
    node: Node,
    src: &[u8],
    state_names: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    if node.kind() == "identifier" {
        let txt = node_txt(node, src);
        if state_names.contains(txt) {
            out.insert(txt.to_string());
        }
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_identifiers(ch, src, state_names, out);
    }
}

fn lhs_root_identifier(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(node_txt(node, src).to_string()),
        "array_access" | "index_expression" => node
            .child(0)
            .and_then(|base| lhs_root_identifier(base, src)),
        "member_expression" => node.child(0).and_then(|obj| lhs_root_identifier(obj, src)),
        _ => {
            let txt = node_txt(node, src);
            let head = txt.split(['[', '.', '(']).next()?.trim();
            (!head.is_empty()).then(|| head.to_string())
        }
    }
}

fn classify_external_call(call_node: Node, src: &[u8]) -> Option<(bool, String)> {
    let fn_node = call_node.child_by_field_name("function")?;
    let raw_fn = node_txt(fn_node, src).trim();
    let full = node_txt(call_node, src);

    if raw_fn.contains("delegatecall") {
        return Some((true, "delegatecall".into()));
    }
    if full.contains(".call{") || raw_fn.ends_with(".call") || full.contains(".call(") {
        return Some((true, "low_level_call".into()));
    }
    // 2300-gas Solidity `.transfer()` / `.send()` cannot reenter; only flag callback-capable token/ETH helpers
    if full.contains("sendValue(") || raw_fn.ends_with(".send") {
        return Some((true, "eth_send_callback_risk".into()));
    }
    if raw_fn.contains("safeTransferFrom")
        || raw_fn.contains("safeBatchTransferFrom")
        || raw_fn.contains("safeMint")
        || raw_fn.contains("safeTransferETH")
        || raw_fn.contains("onERC721Received")
        || raw_fn.contains("onERC1155Received")
        || raw_fn.contains("operatorSend")
        || raw_fn.contains("uniswapV3SwapCallback")
        || raw_fn.contains("flashLoan")
        || raw_fn.contains("swap(")
    {
        return Some((true, raw_fn.to_string()));
    }
    if raw_fn.contains('.')
        && !raw_fn.starts_with("abi.")
        && !raw_fn.starts_with("Math.")
        && !raw_fn.starts_with("ECDSA.")
        && !raw_fn.starts_with("SignatureChecker.")
        && !raw_fn.starts_with("Strings.")
        && !raw_fn.starts_with("SafeCast.")
        && !raw_fn.starts_with("super.")
    {
        return Some((false, raw_fn.to_string()));
    }
    None
}

fn extract_tx_origin_check(node: Node, src: &[u8]) -> Option<usize> {
    if node.kind() == "binary_expression" {
        let txt = node_txt(node, src);
        if txt.contains("tx.origin")
            && (txt.contains("==") || txt.contains("!="))
            && !txt.contains("msg.sender")
        {
            return Some(node.start_position().row + 1);
        }
    }
    None
}

fn is_div_before_mul(node: Node, src: &[u8]) -> bool {
    if node.kind() != "binary_expression" {
        return false;
    }
    let full = node_txt(node, src);
    let mut op_is_mul = false;
    let mut has_div_child = false;
    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        let k = ch.kind();
        if k == "*" {
            op_is_mul = true;
        } else if contains_immediate_div_expr(ch, src) {
            has_div_child = true;
        }
    }
    if !op_is_mul || !has_div_child {
        return false;
    }
    let low = full.to_ascii_lowercase();
    !(low.contains("days")
        || low.contains("hours")
        || low.contains("minutes")
        || low.contains("step"))
}

fn contains_immediate_div_expr(node: Node, src: &[u8]) -> bool {
    let target = match node.kind() {
        "parenthesized_expression" => {
            let mut c = node.walk();
            node.named_children(&mut c).next()
        }
        _ => Some(node),
    };
    let Some(inner) = target else {
        return false;
    };
    if inner.kind() != "binary_expression" {
        return false;
    }
    let mut c = inner.walk();
    for ch in inner.children(&mut c) {
        if ch.kind() == "/" {
            let txt = node_txt(inner, src);
            if !txt.contains("http") {
                return true;
            }
        }
    }
    false
}

fn block_ends_with_return_or_revert(node: Node, src: &[u8]) -> bool {
    let txt = smg_graph::taint::strip_comments_simple(node_txt(node, src));
    let trimmed = txt.trim().trim_end_matches('}').trim();
    if let Some(last_stmt) = trimmed.rsplit(';').nth(1).or(Some(trimmed)) {
        let low = last_stmt.trim().to_ascii_lowercase();
        if low.starts_with("return")
            || low.contains(" return")
            || low.starts_with("revert")
            || low.contains(" revert")
        {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn walk_fn_body(
    node: Node,
    src: &[u8],
    state_names: &HashSet<String>,
    ops: &mut Vec<EffectOp>,
    div_mul: &mut Vec<usize>,
    tx_origin: &mut Vec<usize>,
    unsafe_dcall: &mut Vec<(usize, String)>,
    has_auth_guard_in_fn: bool,
    branch_path: &[(usize, u8)],
    in_returning_branch: bool,
) {
    let line = node.start_position().row + 1;
    let byte_offset = node.start_byte();

    if node.kind() == "if_statement" {
        let if_id = node.start_byte();
        // Walk condition
        if let Some(cond) = node.child_by_field_name("condition") {
            walk_fn_body(
                cond,
                src,
                state_names,
                ops,
                div_mul,
                tx_origin,
                unsafe_dcall,
                has_auth_guard_in_fn,
                branch_path,
                in_returning_branch,
            );
        }
        // Walk consequence (then-branch = 0) and alternative (else-branch = 1)
        let mut c = node.walk();
        let mut branch_idx = 0u8;
        for ch in node.named_children(&mut c) {
            if Some(ch.id()) == node.child_by_field_name("condition").map(|n| n.id()) {
                continue;
            }
            let mut next_path = branch_path.to_vec();
            next_path.push((if_id, branch_idx));
            let branch_rets = in_returning_branch || block_ends_with_return_or_revert(ch, src);
            walk_fn_body(
                ch,
                src,
                state_names,
                ops,
                div_mul,
                tx_origin,
                unsafe_dcall,
                has_auth_guard_in_fn,
                &next_path,
                branch_rets,
            );
            branch_idx = branch_idx.saturating_add(1);
        }
        return;
    }

    match node.kind() {
        "assignment_expression" | "augmented_assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left")
                && let Some(root) = lhs_root_identifier(left, src)
                && state_names.contains(&root)
                && let Some(right) = node.child_by_field_name("right")
            {
                // Recurse into RHS first so nested calls / division-before-multiplication on RHS are captured
                walk_fn_body(
                    right,
                    src,
                    state_names,
                    ops,
                    div_mul,
                    tx_origin,
                    unsafe_dcall,
                    has_auth_guard_in_fn,
                    branch_path,
                    in_returning_branch,
                );
                let mut reads = HashSet::new();
                collect_identifiers(right, src, state_names, &mut reads);
                for r in reads {
                    ops.push(EffectOp::ReadState {
                        var: r,
                        line,
                        byte_offset,
                        branch_path: branch_path.to_vec(),
                    });
                }
                let rhs_txt = node_txt(right, src);
                let rhs_nom = node_txt(node, src).contains("+=")
                    || rhs_txt.to_ascii_lowercase().contains("amount");
                ops.push(EffectOp::WriteState {
                    is_accounting: is_accounting_state_var(&root),
                    is_rhs_nominal_amount: rhs_nom,
                    var: root,
                    line,
                    byte_offset,
                    branch_path: branch_path.to_vec(),
                });
                return;
            }
        }
        "call_expression" => {
            if let Some((callback_risk, kind)) = classify_external_call(node, src) {
                if kind == "delegatecall" {
                    let full = node_txt(node, src);
                    if !has_auth_guard_in_fn {
                        unsafe_dcall.push((line, full.to_string()));
                    }
                }
                ops.push(EffectOp::ExternalCall {
                    has_callback_risk: callback_risk,
                    kind,
                    line,
                    byte_offset,
                    branch_path: branch_path.to_vec(),
                    in_returning_branch,
                });
            } else if let Some(fn_node) = node.child_by_field_name("function") {
                let raw_fn = node_txt(fn_node, src).trim();
                if !raw_fn.is_empty()
                    && !raw_fn.contains('.')
                    && !matches!(
                        raw_fn,
                        "require" | "assert" | "revert" | "keccak256" | "ecrecover"
                    )
                {
                    ops.push(EffectOp::InternalCall {
                        callee: raw_fn.to_string(),
                        line,
                        byte_offset,
                        branch_path: branch_path.to_vec(),
                    });
                }
            }
            let mut c = node.walk();
            for ch in node.named_children(&mut c) {
                walk_fn_body(
                    ch,
                    src,
                    state_names,
                    ops,
                    div_mul,
                    tx_origin,
                    unsafe_dcall,
                    has_auth_guard_in_fn,
                    branch_path,
                    in_returning_branch,
                );
            }
            return;
        }
        "binary_expression" => {
            if is_div_before_mul(node, src) {
                div_mul.push(line);
            }
            if let Some(ln) = extract_tx_origin_check(node, src) {
                tx_origin.push(ln);
            }
        }
        "identifier" => {
            let txt = node_txt(node, src);
            if state_names.contains(txt) {
                ops.push(EffectOp::ReadState {
                    var: txt.to_string(),
                    line,
                    byte_offset,
                    branch_path: branch_path.to_vec(),
                });
            }
            return;
        }
        _ => {}
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_fn_body(
            ch,
            src,
            state_names,
            ops,
            div_mul,
            tx_origin,
            unsafe_dcall,
            has_auth_guard_in_fn,
            branch_path,
            in_returning_branch,
        );
    }
}

fn branches_are_mutually_exclusive(a: &[(usize, u8)], b: &[(usize, u8)]) -> bool {
    for &(if_a, br_a) in a {
        for &(if_b, br_b) in b {
            if if_a == if_b && br_a != br_b {
                return true;
            }
        }
    }
    false
}

fn has_caller_auth_tokens(text: &str) -> bool {
    let stripped = smg_graph::taint::strip_comments_simple(text);
    let low = stripped.to_ascii_lowercase();
    if low.contains("_checkowner")
        || low.contains("_checkrole")
        || low.contains("hasrole(")
        || low.contains("onlyowner")
        || low.contains("onlyrole")
        || low.contains("isauthorized(")
    {
        return true;
    }
    for stmt in low.split(';') {
        let s = stmt.trim();
        let has_sender = s.contains("msg.sender") || s.contains("_msgsender()");
        if !has_sender {
            continue;
        }
        // Require `msg.sender` to participate in a condition, comparison, or access mapping check
        if s.contains("==")
            || s.contains("!=")
            || s.contains("require(")
            || s.contains("require ")
            || s.contains("if (")
            || s.contains("if(")
            || s.contains("revert")
            || s.contains("assert(")
            || s.contains("wards[")
            || s.contains("admins[")
            || s.contains("authorized[")
            || s.contains("operators[")
            || s.contains("whitelist[")
        {
            return true;
        }
    }
    false
}

fn modifier_is_auth_name(name: &str, custom_auth: &HashSet<String>) -> bool {
    if custom_auth.contains(name) {
        return true;
    }
    let low = name.to_ascii_lowercase();
    low.contains("only")
        || low.contains("auth")
        || low.contains("owner")
        || low.contains("admin")
        || low.contains("role")
        || low.contains("governance")
        || low.contains("guardian")
        || low.contains("restricted")
        || low.contains("minter")
        || low.contains("operator")
        || low.contains("initializer")
        || low.contains("reinitializer")
}

fn modifier_is_lock_name(name: &str, custom_locks: &HashSet<String>) -> bool {
    if custom_locks.contains(name) {
        return true;
    }
    let low = name.to_ascii_lowercase();
    low.contains("nonreentrant")
        || low == "lock"
        || low == "locked"
        || low.contains("reentrancy")
        || low == "mutex"
        || low == "noreenter"
}

/// Parses a Solidity file into contract metadata, linearized packed storage layout, and function effect summaries.
pub fn parse_solidity_file(rel_path: &str, source: &str) -> Vec<ParsedContract> {
    parse_solidity_file_with_bases(rel_path, source, None)
}

pub fn parse_solidity_file_with_bases(
    rel_path: &str,
    source: &str,
    workspace_bases: Option<&HashMap<String, ParsedContract>>,
) -> Vec<ParsedContract> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_solidity::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let src = source.as_bytes();
    let mut contracts = Vec::new();
    let mut file_enums: HashSet<String> = HashSet::new();
    let mut file_contract_types: HashSet<String> = HashSet::new();

    let mut cur0 = root.walk();
    for ch in root.named_children(&mut cur0) {
        match ch.kind() {
            "enum_declaration" => {
                if let Some(n) = ch.child_by_field_name("name") {
                    file_enums.insert(node_txt(n, src).to_string());
                }
            }
            "contract_declaration" | "interface_declaration" => {
                if let Some(n) = ch.child_by_field_name("name") {
                    file_contract_types.insert(node_txt(n, src).to_string());
                }
            }
            _ => {}
        }
    }

    let mut contract_nodes = Vec::new();
    let mut cur = root.walk();
    for ch in root.named_children(&mut cur) {
        let kind = match ch.kind() {
            "contract_declaration" => {
                let hdr = node_txt(ch, src);
                if hdr.trim_start().starts_with("abstract ") {
                    ContractKind::AbstractContract
                } else {
                    ContractKind::Contract
                }
            }
            "interface_declaration" => ContractKind::Interface,
            "library_declaration" => ContractKind::Library,
            _ => continue,
        };
        contract_nodes.push(ch);
        contracts.push(extract_contract(
            ch,
            src,
            rel_path,
            kind,
            &file_enums,
            &file_contract_types,
            None,
        ));
    }

    // Linearize inherited base contracts' state variables, auth modifiers, and lock modifiers
    // (merging both same-file bases and cross-file workspace bases via bounded transitive walk).
    let mut by_name: HashMap<String, ParsedContract> = workspace_bases.cloned().unwrap_or_default();
    for c in &contracts {
        by_name.insert(c.name.clone(), c.clone());
    }

    for (idx, c) in contracts.iter_mut().enumerate() {
        if c.bases.is_empty() {
            continue;
        }
        // Bounded C3-style transitive base order (depth <= 8)
        let mut ordered_bases: Vec<String> = Vec::new();
        let mut queue: std::collections::VecDeque<(String, usize)> =
            c.bases.iter().cloned().map(|b| (b, 0)).collect();
        while let Some((bname, depth)) = queue.pop_front() {
            if depth >= 8 || ordered_bases.contains(&bname) {
                continue;
            }
            ordered_bases.push(bname.clone());
            if let Some(bc) = by_name.get(&bname) {
                for parent in &bc.bases {
                    if !ordered_bases.contains(parent) {
                        queue.push_back((parent.clone(), depth + 1));
                    }
                }
            }
        }
        let mut linearized_vars = Vec::new();
        for base_name in &ordered_bases {
            if let Some(base_c) = by_name.get(base_name) {
                for sv in &base_c.state_vars {
                    if !linearized_vars
                        .iter()
                        .any(|v: &StateVarSpec| v.name == sv.name)
                    {
                        linearized_vars.push(sv.clone());
                    }
                }
                c.custom_auth_modifiers
                    .extend(base_c.custom_auth_modifiers.iter().cloned());
                c.custom_lock_modifiers
                    .extend(base_c.custom_lock_modifiers.iter().cloned());
            }
        }
        for sv in &c.state_vars {
            if !linearized_vars.iter().any(|v| v.name == sv.name) {
                linearized_vars.push(sv.clone());
            }
        }
        let inherited_state_names: HashSet<String> =
            linearized_vars.iter().map(|v| v.name.clone()).collect();
        c.state_vars = linearized_vars;
        c.packed_slots = pack_storage_vars_with_defs(
            &c.name,
            rel_path,
            &c.state_vars,
            0,
            &file_enums,
            &file_contract_types,
        );
        // Re-extract child functions with inherited base state_vars so CEI/view reentrancy catches inherited storage writes
        let updated = extract_contract(
            contract_nodes[idx],
            src,
            rel_path,
            c.kind,
            &file_enums,
            &file_contract_types,
            Some(&inherited_state_names),
        );
        c.functions = updated.functions;
    }

    contracts
}

fn extract_contract(
    node: Node,
    src: &[u8],
    rel_path: &str,
    kind: ContractKind,
    file_enums: &HashSet<String>,
    file_contract_types: &HashSet<String>,
    override_state_names: Option<&HashSet<String>>,
) -> ParsedContract {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "Contract".into());
    let start_line = node.start_position().row + 1;
    let full_txt = node_txt(node, src);
    let stripped_contract = smg_graph::taint::strip_comments_simple(full_txt);

    let mut bases = Vec::new();
    let mut c0 = node.walk();
    for ch in node.named_children(&mut c0) {
        if ch.kind() == "inheritance_specifier" {
            let btxt = node_txt(ch, src)
                .split(['(', ' '])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !btxt.is_empty() {
                bases.push(btxt);
            }
        }
    }

    let mut local_enums = file_enums.clone();
    let mut state_vars = Vec::new();
    let mut custom_auth_modifiers = HashSet::new();
    let mut custom_lock_modifiers = HashSet::new();
    let mut fn_nodes = Vec::new();
    let mut has_erc7201_struct = false;

    if let Some(body) = node.child_by_field_name("body") {
        let mut bc = body.walk();
        for item in body.named_children(&mut bc) {
            match item.kind() {
                "enum_declaration" => {
                    if let Some(en) = item.child_by_field_name("name") {
                        local_enums.insert(node_txt(en, src).to_string());
                    }
                }
                "struct_declaration" => {
                    // Check preceding NatSpec comment for `@custom:storage-location erc7201:`
                    let item_start = item.start_byte();
                    let lookback_start = item_start.saturating_sub(240);
                    let preceding =
                        std::str::from_utf8(&src[lookback_start..item_start]).unwrap_or("");
                    if preceding.contains("@custom:storage-location")
                        && preceding.contains("erc7201:")
                    {
                        has_erc7201_struct = true;
                    }
                }
                "state_variable_declaration" => {
                    let raw = smg_graph::taint::strip_comments_simple(node_txt(item, src));
                    let is_const = raw.contains(" constant ") || raw.contains(" immutable ");
                    if let (Some(ty_n), Some(nm_n)) = (
                        item.child_by_field_name("type"),
                        item.child_by_field_name("name"),
                    ) {
                        state_vars.push(StateVarSpec {
                            name: node_txt(nm_n, src).to_string(),
                            var_type: node_txt(ty_n, src).to_string(),
                            is_constant_or_immutable: is_const,
                            line: item.start_position().row + 1,
                        });
                    }
                }
                "modifier_definition" => {
                    let mod_name = item
                        .child_by_field_name("name")
                        .map(|n| node_txt(n, src).to_string())
                        .unwrap_or_default();
                    let mod_txt = smg_graph::taint::strip_comments_simple(node_txt(item, src));
                    if has_caller_auth_tokens(&mod_txt) {
                        custom_auth_modifiers.insert(mod_name.clone());
                    }
                    let mod_low = mod_txt.to_ascii_lowercase();
                    if (mod_low.contains("locked")
                        || mod_low.contains("entered")
                        || mod_low.contains("reentr"))
                        && (mod_low.contains("require")
                            || mod_low.contains("revert")
                            || mod_low.contains("if"))
                    {
                        custom_lock_modifiers.insert(mod_name);
                    }
                }
                "function_definition"
                | "constructor_definition"
                | "fallback_receive_definition" => {
                    fn_nodes.push(item);
                }
                _ => {}
            }
        }
    }

    let mut state_names: HashSet<String> = state_vars.iter().map(|v| v.name.clone()).collect();
    if let Some(ov) = override_state_names {
        state_names.extend(ov.iter().cloned());
    }
    let packed_slots = pack_storage_vars_with_defs(
        &name,
        rel_path,
        &state_vars,
        0,
        &local_enums,
        file_contract_types,
    );

    let mut functions = Vec::new();
    for fnode in fn_nodes {
        let is_constructor = fnode.kind() == "constructor_definition";
        let fn_name = if is_constructor {
            "constructor".to_string()
        } else if fnode.kind() == "fallback_receive_definition" {
            "fallback".to_string()
        } else {
            fnode
                .child_by_field_name("name")
                .map(|n| node_txt(n, src).to_string())
                .unwrap_or_else(|| "fallback".into())
        };

        let mut visibility = "public".to_string();
        let mut mutability = "nonpayable".to_string();
        let mut modifiers = Vec::new();
        let mut params_parts = Vec::new();

        let mut fc = fnode.walk();
        for ch in fnode.named_children(&mut fc) {
            match ch.kind() {
                "visibility" => visibility = node_txt(ch, src).trim().to_string(),
                "state_mutability" => mutability = node_txt(ch, src).trim().to_string(),
                "modifier_invocation" => {
                    if let Some(id_n) = ch.named_child(0) {
                        modifiers.push(node_txt(id_n, src).to_string());
                    }
                }
                "parameter" => params_parts.push(node_txt(ch, src).to_string()),
                _ => {}
            }
        }

        let body_node = fnode.child_by_field_name("body");
        let raw_body = body_node
            .map(|b| node_txt(b, src).to_string())
            .unwrap_or_default();
        let body_text = smg_graph::taint::strip_comments_simple(&raw_body);
        let has_auth_guard = modifiers
            .iter()
            .any(|m| modifier_is_auth_name(m, &custom_auth_modifiers))
            || has_caller_auth_tokens(&body_text);

        let mut ops = Vec::new();
        let mut div_mul = Vec::new();
        let mut tx_origin = Vec::new();
        let mut unsafe_dcall = Vec::new();
        if let Some(b) = body_node {
            walk_fn_body(
                b,
                src,
                &state_names,
                &mut ops,
                &mut div_mul,
                &mut tx_origin,
                &mut unsafe_dcall,
                has_auth_guard,
                &[],
                false,
            );
        }

        functions.push(ParsedFunction {
            name: fn_name,
            start_line: fnode.start_position().row + 1,
            visibility,
            mutability,
            modifiers,
            params_text: params_parts.join(", "),
            body_text,
            is_constructor,
            ops,
            div_before_mul_lines: div_mul,
            tx_origin_auth_lines: tx_origin,
            unsafe_delegatecall_lines: unsafe_dcall,
        });
    }

    // 1-hop intra-contract internal/private helper call EffectOp expansion
    let helper_ops: HashMap<String, Vec<EffectOp>> = functions
        .iter()
        .map(|f| (f.name.clone(), f.ops.clone()))
        .collect();
    for f in &mut functions {
        let mut expanded = Vec::with_capacity(f.ops.len());
        for op in &f.ops {
            if let EffectOp::InternalCall {
                callee,
                line,
                byte_offset,
                branch_path,
            } = op
            {
                if callee != &f.name
                    && let Some(callee_ops) = helper_ops.get(callee)
                {
                    for (idx, cop) in callee_ops.iter().enumerate() {
                        match cop {
                            EffectOp::ReadState { var, .. } => {
                                expanded.push(EffectOp::ReadState {
                                    var: var.clone(),
                                    line: *line,
                                    byte_offset: byte_offset.saturating_add(idx),
                                    branch_path: branch_path.clone(),
                                });
                            }
                            EffectOp::WriteState {
                                var,
                                is_accounting,
                                is_rhs_nominal_amount,
                                ..
                            } => {
                                expanded.push(EffectOp::WriteState {
                                    var: var.clone(),
                                    is_accounting: *is_accounting,
                                    is_rhs_nominal_amount: *is_rhs_nominal_amount,
                                    line: *line,
                                    byte_offset: byte_offset.saturating_add(idx),
                                    branch_path: branch_path.clone(),
                                });
                            }
                            EffectOp::ExternalCall {
                                has_callback_risk,
                                kind,
                                in_returning_branch,
                                ..
                            } => {
                                expanded.push(EffectOp::ExternalCall {
                                    has_callback_risk: *has_callback_risk,
                                    kind: kind.clone(),
                                    line: *line,
                                    byte_offset: byte_offset.saturating_add(idx),
                                    branch_path: branch_path.clone(),
                                    in_returning_branch: *in_returning_branch,
                                });
                            }
                            EffectOp::InternalCall { .. } => {}
                        }
                    }
                }
            } else {
                expanded.push(op.clone());
            }
        }
        f.ops = expanded;
    }

    let is_proxy_like = (stripped_contract.contains("delegatecall")
        && kind == ContractKind::Contract)
        || name.contains("Proxy")
        || bases.iter().any(|b| b.contains("Proxy"));

    // Only treat the contract as fully ERC-7201 namespaced if it declares an ERC-7201 struct and is not a raw slot-0 proxy
    let has_erc7201_namespace = has_erc7201_struct && !is_proxy_like;

    ParsedContract {
        name,
        kind,
        start_line,
        is_proxy_like,
        bases,
        state_vars,
        packed_slots,
        custom_auth_modifiers,
        custom_lock_modifiers,
        functions,
        has_erc7201_namespace,
    }
}

fn has_inline_reentrancy_mutex(body: &str) -> bool {
    let low = smg_graph::taint::strip_comments_simple(body).to_ascii_lowercase();
    (low.contains("_locked =") || low.contains("locked =") || low.contains("_entered ="))
        && (low.contains("require(") || low.contains("revert"))
}

fn view_fn_checks_reentrancy_lock(body: &str) -> bool {
    let low = smg_graph::taint::strip_comments_simple(body).to_ascii_lowercase();
    low.contains("_reentrancyguardentered")
        || low.contains("_locked")
        || low.contains("require(!locked")
}

fn build_withdraw_probe_calldata(
    fn_name: &str,
    params_text: &str,
    art: &crate::context::CompiledContractArtifact,
) -> Vec<u8> {
    let zero_arg_sig = format!("{fn_name}()");
    if art.abi_functions.iter().any(|s| s == &zero_arg_sig) || params_text.trim().is_empty() {
        return abi_selector(&zero_arg_sig).to_vec();
    }
    let one_eth_bytes = U256::from(1_000_000_000_000_000_000u128).to_be_bytes::<32>();
    if let Some(sig) = art
        .abi_functions
        .iter()
        .find(|s| s.starts_with(&format!("{fn_name}(")))
    {
        let mut cd = abi_selector(sig).to_vec();
        if sig.contains("uint") {
            cd.extend_from_slice(&one_eth_bytes);
        }
        return cd;
    }
    let mut cd = abi_selector(&format!("{fn_name}(uint256)")).to_vec();
    cd.extend_from_slice(&one_eth_bytes);
    cd
}

/// Runs all EVM/Solidity security passes on a parsed file and attaches `revm` witness proofs when available.
pub fn analyze_solidity_file(
    rel_path: &str,
    source: &str,
    ctx: &Web3Context,
) -> (Vec<ParsedContract>, Vec<LocalStaticFinding>) {
    analyze_solidity_file_with_bases(rel_path, source, ctx, None)
}

/// Runs EVM/Solidity security passes with workspace-wide multi-file C3 inheritance bases
/// (`Ownable`, `ReentrancyGuard`, abstract storage bases) and ERC-7201 slot-0 collision checks.
pub fn analyze_solidity_file_with_bases(
    rel_path: &str,
    source: &str,
    ctx: &Web3Context,
    workspace_bases: Option<&HashMap<String, ParsedContract>>,
) -> (Vec<ParsedContract>, Vec<LocalStaticFinding>) {
    let contracts = parse_solidity_file_with_bases(rel_path, source, workspace_bases);
    let mut findings = Vec::new();
    let is_test = smg_core::is_test_source_path(rel_path);
    if is_test {
        return (contracts, findings);
    }

    let stripped_source = smg_graph::taint::strip_comments_simple(source);
    let source_lines: Vec<&str> = stripped_source.lines().collect();

    for c in &contracts {
        if matches!(c.kind, ContractKind::Interface) {
            continue;
        }
        // ERC-7201 slot-0 check: proxy using `@custom:storage-location erc7201:...` with raw slot-0 vars
        if c.has_erc7201_namespace
            && c.is_proxy_like
            && !c.packed_slots.is_empty()
            && matches!(c.kind, ContractKind::Contract)
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-STORAGE".into(),
                severity: "HIGH".into(),
                title: format!(
                    "ERC-7201 namespaced contract `{}` also declares {} raw slot-0 storage variable(s) (`{}`)",
                    c.name,
                    c.packed_slots.len(),
                    c.packed_slots[0].var_name
                ),
                rel_path: rel_path.into(),
                line: c.packed_slots[0].line,
                symbol: c.name.clone(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Move all mutable state variables into the ERC-7201 namespaced struct (`@custom:storage-location erc7201:...`) so slot 0 remains untouched across upgrades.".into(),
            });
        }
        let mut stale_vars_exposed_after_call: HashMap<String, (usize, String, String)> =
            HashMap::new();
        let artifact = ctx.lookup_artifact(rel_path, &c.name);

        for f in &c.functions {
            if f.is_constructor || matches!(f.visibility.as_str(), "internal" | "private") {
                check_math_and_oracle_inside_fn(c, f, &source_lines, rel_path, &mut findings);
                continue;
            }

            let is_view_or_pure = matches!(f.mutability.as_str(), "view" | "pure");
            let has_lock = f
                .modifiers
                .iter()
                .any(|m| modifier_is_lock_name(m, &c.custom_lock_modifiers))
                || has_inline_reentrancy_mutex(&f.body_text);
            let has_auth = f
                .modifiers
                .iter()
                .any(|m| modifier_is_auth_name(m, &c.custom_auth_modifiers))
                || has_caller_auth_tokens(&f.body_text);

            // 1. CEI / Reentrancy Effect Graph Sigma(f)
            if !is_view_or_pure && !has_lock {
                struct ActiveCallSite {
                    line: usize,
                    byte_offset: usize,
                    branch_path: Vec<(usize, u8)>,
                    in_returning_branch: bool,
                }
                let mut active_calls: Vec<ActiveCallSite> = Vec::new();
                let mut reported_reentrancy = false;
                for op in &f.ops {
                    if reported_reentrancy {
                        break;
                    }
                    match op {
                        EffectOp::ExternalCall {
                            has_callback_risk: true,
                            line,
                            byte_offset,
                            branch_path,
                            in_returning_branch,
                            ..
                        } => {
                            active_calls.push(ActiveCallSite {
                                line: *line,
                                byte_offset: *byte_offset,
                                branch_path: branch_path.clone(),
                                in_returning_branch: *in_returning_branch,
                            });
                        }
                        EffectOp::WriteState {
                            var,
                            is_accounting: true,
                            line,
                            byte_offset,
                            branch_path,
                            ..
                        } => {
                            if let Some(call_site) = active_calls.iter().find(|cs| {
                                *byte_offset > cs.byte_offset
                                    && !branches_are_mutually_exclusive(
                                        &cs.branch_path,
                                        branch_path,
                                    )
                                    && (!cs.in_returning_branch
                                        || &cs.branch_path == branch_path
                                        || *line == cs.line)
                            }) {
                                let call_line = call_site.line;
                                stale_vars_exposed_after_call
                                    .entry(var.clone())
                                    .or_insert_with(|| {
                                        (call_line, f.name.clone(), f.params_text.clone())
                                    });
                                let mut conf = Confidence::Confirmed;
                                let mut proof_note = String::new();
                                if let Some(art) = artifact
                                    && !art.deployed_bytecode.is_empty()
                                {
                                    let w_cd =
                                        build_withdraw_probe_calldata(&f.name, &f.params_text, art);
                                    let d_sel = art
                                        .abi_functions
                                        .iter()
                                        .find(|s| s.starts_with("deposit"))
                                        .map(|s| abi_selector(s));
                                    let wres = probe_compiled_reentrancy_in_revm(
                                        &art.deployed_bytecode,
                                        d_sel,
                                        &w_cd,
                                    );
                                    if wres.proven {
                                        conf = Confidence::Proven;
                                        proof_note = format!(" [{}]", wres.summary);
                                    }
                                }
                                findings.push(LocalStaticFinding {
                                    rule_id: "SMG-WEB3-REENTRANCY".into(),
                                    severity: "CRITICAL".into(),
                                    title: format!(
                                        "CEI reentrancy in `{}.{}`: external call at line {} precedes state update `{}` at line {}{}",
                                        c.name, f.name, call_line, var, line, proof_note
                                    ),
                                    rel_path: rel_path.into(),
                                    line: call_line,
                                    symbol: format!("{}.{}", c.name, f.name),
                                    sink_kind: SinkKind::BalanceUpdate,
                                    missing_guard: GuardKind::TxLock,
                                    confidence: conf,
                                    remediation: "Update accounting state before external calls (Checks-Effects-Interactions) and add `nonReentrant` guard.".into(),
                                });
                                reported_reentrancy = true;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // 2. Access Control, Init, Delegatecall, `tx.origin`
            if c.kind != ContractKind::Library {
                for ln in &f.tx_origin_auth_lines {
                    findings.push(LocalStaticFinding {
                        rule_id: "SMG-WEB3-ACCESS".into(),
                        severity: "HIGH".into(),
                        title: format!(
                            "`tx.origin` authorization phishing risk in `{}.{}`",
                            c.name, f.name
                        ),
                        rel_path: rel_path.into(),
                        line: *ln,
                        symbol: format!("{}.{}", c.name, f.name),
                        sink_kind: SinkKind::AuthMutation,
                        missing_guard: GuardKind::Auth,
                        confidence: Confidence::Confirmed,
                        remediation: "Replace `tx.origin` authentication checks with `msg.sender`."
                            .into(),
                    });
                }

                for (ln, expr) in &f.unsafe_delegatecall_lines {
                    if !has_auth {
                        findings.push(LocalStaticFinding {
                            rule_id: "SMG-WEB3-ACCESS".into(),
                            severity: "CRITICAL".into(),
                            title: format!(
                                "Unprotected `delegatecall` `{}` without caller authorization in `{}.{}`",
                                expr, c.name, f.name
                            ),
                            rel_path: rel_path.into(),
                            line: *ln,
                            symbol: format!("{}.{}", c.name, f.name),
                            sink_kind: SinkKind::AuthMutation,
                            missing_guard: GuardKind::Auth,
                            confidence: Confidence::Confirmed,
                            remediation: "Restrict proxy/delegatecall upgrades strictly to owner/governance and trusted implementation slots.".into(),
                        });
                    }
                }

                check_initializer_and_admin_access(
                    c,
                    f,
                    is_view_or_pure,
                    has_auth,
                    artifact,
                    rel_path,
                    &mut findings,
                );
            }

            // 3. Replay & Signature Validation
            check_signature_replay(c, f, rel_path, &mut findings);

            // 4. Rounding Math & Oracle Feeds
            check_math_and_oracle_inside_fn(c, f, &source_lines, rel_path, &mut findings);
        }

        // 5. Read-Only View Reentrancy across Sigma(view_fn) reading stale accounting state
        if !stale_vars_exposed_after_call.is_empty() {
            for vf in &c.functions {
                if vf.mutability != "view" {
                    continue;
                }
                let vf_low = vf.name.to_ascii_lowercase();
                let is_pricing_view = vf_low.contains("price")
                    || vf_low.contains("share")
                    || vf_low.contains("rate")
                    || vf_low.contains("convert")
                    || vf_low.contains("totalassets");
                if !is_pricing_view || view_fn_checks_reentrancy_lock(&vf.body_text) {
                    continue;
                }
                for op in &vf.ops {
                    if let EffectOp::ReadState { var, .. } = op
                        && let Some((_, mut_name, mut_params)) =
                            stale_vars_exposed_after_call.get(var)
                    {
                        let mut conf = Confidence::Confirmed;
                        let mut proof_note = String::new();
                        if let Some(art) = artifact
                            && !art.deployed_bytecode.is_empty()
                        {
                            let mut_cd = build_withdraw_probe_calldata(mut_name, mut_params, art);
                            let view_cd =
                                build_withdraw_probe_calldata(&vf.name, &vf.params_text, art);
                            let vres = crate::evm_oracle::probe_view_reentrancy_in_revm(
                                &art.deployed_bytecode,
                                &mut_cd,
                                &view_cd,
                            );
                            if vres.proven {
                                conf = Confidence::Proven;
                                proof_note = format!(" [{}]", vres.summary);
                            }
                        }
                        findings.push(LocalStaticFinding {
                            rule_id: "SMG-WEB3-REENTRANCY".into(),
                            severity: "HIGH".into(),
                            title: format!(
                                "Read-only reentrancy exposure: view `{}.{}` reads `{}` without lock check while mutator leaves state stale across callback{}",
                                c.name, vf.name, var, proof_note
                            ),
                            rel_path: rel_path.into(),
                            line: vf.start_line,
                            symbol: format!("{}.{}", c.name, vf.name),
                            sink_kind: SinkKind::BalanceUpdate,
                            missing_guard: GuardKind::TxLock,
                            confidence: conf,
                            remediation: "Protect dependent pricing views with a non-reentrant lock check (e.g. `_reentrancyGuardEntered()` revert) and enforce CEI.".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    (contracts, findings)
}

fn check_initializer_and_admin_access(
    c: &ParsedContract,
    f: &ParsedFunction,
    is_view_or_pure: bool,
    has_auth: bool,
    artifact: Option<&crate::context::CompiledContractArtifact>,
    rel_path: &str,
    findings: &mut Vec<LocalStaticFinding>,
) {
    if is_view_or_pure {
        return;
    }
    let low = f.name.to_ascii_lowercase();
    let is_initializer = low == "initialize" || low == "init" || low.starts_with("initialize_");
    if is_initializer {
        let guarded = has_auth
            || f.body_text.contains("initialized")
            || f.body_text.contains("_initializing")
            || f.body_text.contains("_disableInitializers")
            || (f.body_text.contains("require(") && f.body_text.contains("== 0"));
        if !guarded {
            let mut conf = Confidence::Confirmed;
            let mut note = String::new();
            if let Some(art) = artifact
                && !art.deployed_bytecode.is_empty()
            {
                let sig = art
                    .abi_functions
                    .iter()
                    .find(|s| s.starts_with(&format!("{}(", f.name)))
                    .cloned()
                    .unwrap_or_else(|| {
                        if f.params_text.trim().is_empty() {
                            format!("{}()", f.name)
                        } else {
                            format!("{}(address)", f.name)
                        }
                    });
                let sel = abi_selector(&sig);
                let arg = (!sig.ends_with("()")).then_some([0xBB; 32]);
                if let Ok((ok, writes, gas)) =
                    probe_compiled_selector_unauth(&art.deployed_bytecode, sel, arg)
                    && ok
                    && writes > 0
                {
                    conf = Confidence::Proven;
                    note =
                        format!(" [revm PROVEN unauth call mutated {writes} slot(s), gas={gas}]");
                }
            }
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ACCESS".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Unprotected initializer `{}.{}` missing `initializer` modifier or initialization guard{}",
                    c.name, f.name, note
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: conf,
                remediation: "Apply OpenZeppelin `initializer` / `reinitializer` modifier and set initialization state before transferring ownership.".into(),
            });
            return;
        }
    }

    let is_amm_lp_mint = low == "mint"
        && (f.body_text.to_ascii_lowercase().contains("mintcallback")
            || c.name.to_ascii_lowercase().contains("pool")
            || c.name.to_ascii_lowercase().contains("pair"));
    let is_privileged_name = (matches!(
        low.as_str(),
        "setowner"
            | "transferownership"
            | "upgradeto"
            | "upgradetoandcall"
            | "setimplementation"
            | "pause"
            | "unpause"
            | "emergencywithdraw"
            | "sweep"
            | "withdrawfees"
            | "setfee"
            | "setoracle"
            | "setadmin"
    ) || (low == "mint" && f.mutability != "payable" && !is_amm_lp_mint));
    if is_privileged_name && !has_auth {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-ACCESS".into(),
            severity: "CRITICAL".into(),
            title: format!(
                "Unprotected privileged entrypoint `{}.{}` missing caller authorization guard",
                c.name, f.name
            ),
            rel_path: rel_path.into(),
            line: f.start_line,
            symbol: format!("{}.{}", c.name, f.name),
            sink_kind: SinkKind::AuthMutation,
            missing_guard: GuardKind::Auth,
            confidence: Confidence::Confirmed,
            remediation: "Enforce caller authorization (`onlyOwner` / `onlyRole` / explicit `msg.sender` verification) on privileged state transitions.".into(),
        });
    }

    let body_low = f.body_text.to_ascii_lowercase();
    let has_loop =
        body_low.contains("for (") || body_low.contains("for(") || body_low.contains("while (");
    if has_loop {
        if body_low.contains("msg.value") {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ACCESS".into(),
                severity: "HIGH".into(),
                title: format!(
                    "`msg.value` reused inside loop in `{}.{}` (double-counting value vulnerability)",
                    c.name, f.name
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Never accumulate or check `msg.value` inside a loop; decrement remaining value or track explicit per-iteration accounting.".into(),
            });
        } else if let Some(helper) = c.functions.iter().find(|callee| {
            callee.name != f.name
                && f.body_text.contains(&format!("{}(", callee.name))
                && callee.body_text.to_ascii_lowercase().contains("msg.value")
        }) {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ACCESS".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "`msg.value` reused across loop iterations in `{}.{}` via `{}` (double-counting value vulnerability)",
                    c.name, f.name, helper.name
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Track cumulative payment across loop iterations instead of comparing `msg.value` inside an internal helper called from a loop.".into(),
            });
        }
    }

    // Caller-controlled arbitrary external call (`target.functionCall(data)` / `target.call(data)` without auth)
    if !has_auth
        && (body_low.contains(".functioncall(")
            || body_low.contains(".functioncallwithvalue(")
            || body_low.contains(".call("))
    {
        let mut addr_params: Vec<&str> = Vec::new();
        let mut bytes_params: Vec<&str> = Vec::new();
        for p in f.params_text.split(',') {
            let toks: Vec<&str> = p.split_whitespace().collect();
            if toks.len() >= 2 {
                let ptype = toks[0].to_ascii_lowercase();
                let pname = toks.last().copied().unwrap_or("");
                if ptype == "address" && !pname.is_empty() {
                    addr_params.push(pname);
                } else if ptype == "bytes" && !pname.is_empty() {
                    bytes_params.push(pname);
                }
            }
        }
        let has_arbitrary_call = addr_params.iter().any(|ap| {
            let ap_low = ap.to_ascii_lowercase();
            bytes_params.iter().any(|bp| {
                let bp_low = bp.to_ascii_lowercase();
                body_low.contains(&format!("{ap_low}.functioncall({bp_low}"))
                    || body_low.contains(&format!("{ap_low}.functioncallwithvalue({bp_low}"))
                    || body_low.contains(&format!("{ap_low}.call({bp_low}"))
            })
        });
        if has_arbitrary_call {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ACCESS".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Unauthenticated arbitrary external call in `{}.{}`: caller controls both target address and calldata",
                    c.name, f.name
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: Confidence::Confirmed,
                remediation: "Restrict external call targets to an allowlist or fixed callback interface (`IERC3156FlashBorrower`) instead of executing arbitrary caller-supplied calldata.".into(),
            });
        }
    }
    if f.mutability == "payable" && body_low.contains("delegatecall(") && low.contains("multicall")
    {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-ACCESS".into(),
            severity: "CRITICAL".into(),
            title: format!("Payable `multicall` with `delegatecall` in `{}.{}` enables `msg.value` reuse drain", c.name, f.name),
            rel_path: rel_path.into(),
            line: f.start_line,
            symbol: format!("{}.{}", c.name, f.name),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::InputValidation,
            confidence: Confidence::Confirmed,
            remediation: "Make `multicall` non-payable or disallow subcalls that inspect `msg.value` inside batch delegatecall loops.".into(),
        });
    }
    if body_low.contains(".transferfrom(") && !has_auth {
        for call_part in f.body_text.split(".transferFrom(").skip(1) {
            let first_arg = call_part.split(',').next().unwrap_or("").trim();
            if !first_arg.is_empty()
                && !first_arg.contains("msg.sender")
                && !first_arg.contains("_msgSender()")
                && !first_arg.contains("address(this)")
                && f.params_text
                    .split(',')
                    .any(|p| p.split_whitespace().last() == Some(first_arg))
            {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-WEB3-ACCESS".into(),
                    severity: "HIGH".into(),
                    title: format!("Arbitrary `transferFrom({}, ...)` uses caller-supplied `from` address in `{}.{}`", first_arg, c.name, f.name),
                    rel_path: rel_path.into(),
                    line: f.start_line,
                    symbol: format!("{}.{}", c.name, f.name),
                    sink_kind: SinkKind::AuthMutation,
                    missing_guard: GuardKind::Auth,
                    confidence: Confidence::Heuristic,
                    remediation: "Pass `msg.sender` (never arbitrary user-controlled `from`) into `safeTransferFrom` unless validating allowance authorization.".into(),
                });
                break;
            }
        }
    }
}

fn check_signature_replay(
    c: &ParsedContract,
    f: &ParsedFunction,
    rel_path: &str,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let body = &f.body_text;
    let uses_raw_ecrecover = body.contains("ecrecover(");
    let uses_oz_ecdsa = body.contains("ECDSA.recover(") || body.contains("SignatureChecker.");
    if !uses_raw_ecrecover && !uses_oz_ecdsa {
        return;
    }

    let mut gaps = Vec::new();
    if uses_raw_ecrecover && !body.contains("address(0)") {
        gaps.push("missing `signer != address(0)` check");
    }
    if uses_raw_ecrecover
        && !body.to_ascii_lowercase().contains("0x7fffffff")
        && !body.contains("ECDSA.")
    {
        gaps.push("missing ECDSA `s`-malleability upper-half check (`s <= secp256k1n/2`)");
    }
    let low = body.to_ascii_lowercase();
    if !low.contains("nonce")
        && !low.contains("used[")
        && !low.contains("usedsignatures")
        && !low.contains("nullifier")
        && !low.contains("consumed")
        && !low.contains("claimed[")
        && !low.contains("executed[")
    {
        gaps.push("missing nonce/hash invalidation");
    }
    if !low.contains("domain_separator")
        && !low.contains("domainseparator")
        && !low.contains("_hashtypeddatav4")
        && !low.contains("block.chainid")
        && !low.contains("chainid")
    {
        gaps.push("missing EIP-712 chainId/verifyingContract domain binding");
    }
    if f.name.to_ascii_lowercase().contains("permit") && !low.contains("deadline") {
        gaps.push("permit() missing `block.timestamp <= deadline` expiry check");
    }

    if !gaps.is_empty() {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-REPLAY".into(),
            severity: "HIGH".into(),
            title: format!(
                "Signature verification flaw in `{}.{}` ({})",
                c.name,
                f.name,
                gaps.join(", ")
            ),
            rel_path: rel_path.into(),
            line: f.start_line,
            symbol: format!("{}.{}", c.name, f.name),
            sink_kind: SinkKind::AuthMutation,
            missing_guard: GuardKind::Auth,
            confidence: Confidence::Confirmed,
            remediation: "Use OpenZeppelin `ECDSA.recover` with EIP-712 domain (`chainId` + `verifyingContract`) and single-use `nonces[signer]++` before external effects.".into(),
        });
    }
}

fn check_math_and_oracle_inside_fn(
    c: &ParsedContract,
    f: &ParsedFunction,
    source_lines: &[&str],
    rel_path: &str,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let body = &f.body_text;
    let low = body.to_ascii_lowercase();
    let fn_low = f.name.to_ascii_lowercase();

    // A. First-depositor ERC-4626 share inflation witness
    if (fn_low.contains("deposit")
        || fn_low.contains("mint")
        || fn_low.contains("converttoshares")
        || fn_low.contains("previewdeposit"))
        && low.contains("totalsupply")
        && (low.contains("totalassets") || low.contains("balanceof(address(this))"))
        && body.contains('/')
    {
        let hardened = low.contains("_decimalsoffset")
            || low.contains("minimum_liquidity")
            || low.contains("virtual")
            || body.contains("totalSupply + 1")
            || body.contains("totalSupply() + 1")
            || body.contains("totalAssets + 1")
            || body.contains("totalAssets() + 1");
        if !hardened
            && let Some(donation_witness) = solve_erc4626_inflation_witness(100_000_000_000_000_000)
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ROUNDING".into(),
                severity: "HIGH".into(),
                title: format!(
                    "ERC-4626 first-depositor inflation in `{}.{}`: 1-wei supply + {donation_witness} wei donation rounds 0.1 ETH deposit to 0 shares",
                    c.name, f.name
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::IntegerOverflow,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Add ERC-4626 virtual shares/assets offset (`_decimalsOffset()`) or burn `MINIMUM_LIQUIDITY` dead shares on initial mint.".into(),
            });
        }
    }

    // B. AST Division before Multiplication precision loss (checked per line rather than whole-function suppression)
    for ln in &f.div_before_mul_lines {
        let line_txt = source_lines
            .get(ln.saturating_sub(1))
            .copied()
            .unwrap_or("");
        if !line_txt.contains("mulDiv") {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ROUNDING".into(),
                severity: "MEDIUM".into(),
                title: format!(
                    "Division-before-multiplication precision truncation in `{}.{}`",
                    c.name, f.name
                ),
                rel_path: rel_path.into(),
                line: *ln,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::IntegerOverflow,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Perform multiplication before division or use fixed-point `Math.mulDiv` to avoid compounding floor-division truncation loss.".into(),
            });
            break;
        }
    }

    // C. Fee-on-Transfer raw `amount` credit without balance delta
    if low.contains("transferfrom(")
        && !low.contains("balanceof(address(this))")
        && !low.contains("ownerof(")
        && low.contains("amount")
        && !body.contains("+= 1;")
        && f.ops.iter().any(|op| {
            matches!(
                op,
                EffectOp::WriteState {
                    is_accounting: true,
                    is_rhs_nominal_amount: true,
                    ..
                }
            )
        })
    {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-ROUNDING".into(),
            severity: "HIGH".into(),
            title: format!(
                "Fee-on-transfer accounting mismatch in `{}.{}`: credits nominal input amount instead of actual post-transfer balance delta",
                c.name, f.name
            ),
            rel_path: rel_path.into(),
            line: f.start_line,
            symbol: format!("{}.{}", c.name, f.name),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::InputValidation,
            confidence: Confidence::Confirmed,
            remediation: "Measure `uint256 received = token.balanceOf(address(this)) - balBefore` around `safeTransferFrom` and credit `received`.".into(),
        });
    }

    // D. Oracle Staleness & Flash-loan Manipulable Spot Reserves
    if body.contains("latestRoundData(") {
        let has_updated = low.contains("updatedat") || low.contains("timestamp");
        let has_pos_price = low.contains("> 0") || low.contains("<= 0") || low.contains("!= 0");
        let round_id_bound = low.contains("uint80 roundid") || low.contains("(roundid,");
        let missing_answered_in_round = round_id_bound && !low.contains("answeredinround");
        if !has_updated || !has_pos_price || missing_answered_in_round {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ORACLE".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Chainlink `latestRoundData()` missing staleness/`answeredInRound`/positive-price validation in `{}.{}`",
                    c.name, f.name
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::SchemaTampering,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Validate `price > 0`, `answeredInRound >= roundId`, and `block.timestamp - updatedAt <= MAX_HEARTBEAT`.".into(),
            });
        }
    }

    let c_low = c.name.to_ascii_lowercase();
    let contract_has_lending_fn = c.functions.iter().any(|ff| {
        let n = ff.name.to_ascii_lowercase();
        n.contains("borrow") || n.contains("liquidat") || n.contains("collateral")
    });
    let is_amm_pair_contract = (c_low.contains("pair")
        || c_low.contains("router")
        || (c_low.contains("pool") && !contract_has_lending_fn))
        && !(fn_low.contains("borrow")
            || fn_low.contains("liquidat")
            || fn_low.contains("collateral")
            || fn_low.contains("oracle"));
    let is_valuation_fn = fn_low.contains("price")
        || fn_low.contains("oracle")
        || fn_low.contains("borrow")
        || fn_low.contains("liquidat")
        || fn_low.contains("collateral")
        || fn_low.contains("depositrequired")
        || fn_low.contains("value");
    let has_pricing_math = body.contains('*') || body.contains('/');
    let lacks_twap_or_feed = !low.contains("twap")
        && !low.contains("observe(")
        && !low.contains("consult(")
        && !low.contains("latestrounddata");
    if !is_amm_pair_contract && is_valuation_fn && has_pricing_math && lacks_twap_or_feed {
        if low.contains("getreserves(") {
            let r_18dec = 1_000_000_000_000_000_000_000_000u128;
            let skew = check_amm_spot_skew_bps(r_18dec, r_18dec, r_18dec / 2);
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ORACLE".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Flash-loan manipulable AMM `getReserves()` spot pricing in `{}.{}` (2-tx 50% swap skews price by {} bps)",
                    c.name, f.name, skew
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::SchemaTampering,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Use manipulation-resistant TWAP (`observe`/`consult`) or Chainlink feeds for collateral and liquidation valuation.".into(),
            });
        } else if body.contains('/')
            && low.contains(".balance")
            && low.contains("balanceof(")
            && !low.contains("totalsupply")
        {
            let r_18dec = 1_000_000_000_000_000_000_000_000u128;
            let skew = check_amm_spot_skew_bps(r_18dec, r_18dec, r_18dec / 2);
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ORACLE".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Flash-loan manipulable spot balance-ratio AMM oracle in `{}.{}` (2-tx 50% swap skews price by {} bps)",
                    c.name, f.name, skew
                ),
                rel_path: rel_path.into(),
                line: f.start_line,
                symbol: format!("{}.{}", c.name, f.name),
                sink_kind: SinkKind::SchemaTampering,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Replace instantaneous pair balance ratios (`pair.balance / token.balanceOf(pair)`) with manipulation-resistant TWAP or Chainlink price feeds.".into(),
            });
        }
    }
}

#[cfg(test)]
mod phase15b_tests {
    use super::*;

    #[test]
    fn test_phase15b_truster_puppet_freerider_defi_exploits() {
        let ctx = Web3Context::default();
        let truster = r#"
pragma solidity ^0.8.0;
contract TrusterLenderPool {
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external returns (bool) {
        target.functionCall(data);
        return true;
    }
}
"#;
        let (_, truster_hits) = analyze_solidity_file("src/TrusterLenderPool.sol", truster, &ctx);
        assert!(
            truster_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-ACCESS" && h.severity == "CRITICAL"),
            "expected CRITICAL SMG-WEB3-ACCESS on Truster arbitrary functionCall, got: {:#?}",
            truster_hits
        );

        let puppet = r#"
pragma solidity ^0.8.0;
contract PuppetPool {
    address public uniswapPair;
    function borrow(uint256 amount) external payable {}
    function _computeOraclePrice() private view returns (uint256) {
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
}
"#;
        let (_, puppet_hits) = analyze_solidity_file("src/PuppetPool.sol", puppet, &ctx);
        assert!(
            puppet_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-ORACLE" && h.severity == "CRITICAL"),
            "expected CRITICAL SMG-WEB3-ORACLE on Puppet balance-ratio spot oracle, got: {:#?}",
            puppet_hits
        );

        let freerider = r#"
pragma solidity ^0.8.0;
contract FreeRiderNFTMarketplace {
    function buyMany(uint256[] calldata tokenIds) external payable {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            _buyOne(tokenIds[i]);
        }
    }
    function _buyOne(uint256 tokenId) private {
        uint256 priceToPay = offers[tokenId];
        require(msg.value >= priceToPay, "not enough");
    }
}
"#;
        let (_, freerider_hits) =
            analyze_solidity_file("src/FreeRiderNFTMarketplace.sol", freerider, &ctx);
        assert!(
            freerider_hits
                .iter()
                .any(|h| h.rule_id == "SMG-WEB3-ACCESS" && h.severity == "CRITICAL"),
            "expected CRITICAL SMG-WEB3-ACCESS on FreeRider inter-procedural msg.value loop, got: {:#?}",
            freerider_hits
        );

        // Phase 16C: ERC721 self-call `transferFrom(from, to, tokenId)` must NOT false-positive
        let erc721_self = r#"
pragma solidity ^0.8.20;
contract ERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        transferFrom(from, to, tokenId);
    }
}
"#;
        let (_, erc721_hits) =
            analyze_solidity_file("contracts/token/ERC721/ERC721.sol", erc721_self, &ctx);
        assert!(
            !erc721_hits
                .iter()
                .any(|h| h.title.contains("Arbitrary `transferFrom")),
            "ERC721 internal self-call transferFrom must not false-positive, got: {:#?}",
            erc721_hits
        );

        // Phase 17B: UniswapV3Pool initialize (`require(slot0.sqrtPriceX96 == 0)`) and AMM LP mint must NOT FP
        let uniswap_v3 = r#"
pragma solidity =0.7.6;
contract UniswapV3Pool {
    function initialize(uint160 sqrtPriceX96) external {
        require(slot0.sqrtPriceX96 == 0, 'AI');
        slot0.sqrtPriceX96 = sqrtPriceX96;
    }
    function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount, bytes calldata data) external returns (uint256, uint256) {
        IUniswapV3MintCallback(msg.sender).uniswapV3MintCallback(amount, 0, data);
        return (amount, 0);
    }
}
"#;
        let (_, uni_hits) = analyze_solidity_file("contracts/UniswapV3Pool.sol", uniswap_v3, &ctx);
        assert!(
            uni_hits.is_empty(),
            "UniswapV3Pool initialize/mint must have 0 FPs, got: {:#?}",
            uni_hits
        );
    }
}
