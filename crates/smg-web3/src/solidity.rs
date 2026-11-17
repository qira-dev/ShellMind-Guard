use crate::context::{EvmSlotEntry, StateVarSpec, Web3Context, abi_selector, pack_storage_vars};
use crate::evm_oracle::{
    check_amm_spot_skew_bps, probe_compiled_reentrancy_in_revm, probe_compiled_selector_unauth,
    solve_erc4626_inflation_witness,
};
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
    },
    WriteState {
        var: String,
        is_accounting: bool,
        is_rhs_nominal_amount: bool,
        line: usize,
    },
    ExternalCall {
        has_callback_risk: bool,
        kind: String,
        line: usize,
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
    if raw_fn.ends_with(".send") || raw_fn.ends_with(".transfer") || full.contains("sendValue(") {
        return Some((true, "eth_transfer_or_token".into()));
    }
    if raw_fn.contains("safeTransferFrom")
        || raw_fn.contains("safeMint")
        || raw_fn.contains("safeTransferETH")
        || raw_fn.contains("onERC721Received")
        || raw_fn.contains("flashLoan")
        || raw_fn.contains("swap(")
    {
        return Some((true, raw_fn.to_string()));
    }
    // Generic external contract method call on an address/interface parameter or state contract handle
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
    // Look strictly at `*` operator where one child is a `/` binary expression (including parens)
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
    // Ignore explicit safe time rounding like `(block.timestamp / 1 days) * 1 days`
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
) {
    let line = node.start_position().row + 1;
    match node.kind() {
        "assignment_expression" | "augmented_assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left")
                && let Some(root) = lhs_root_identifier(left, src)
                && state_names.contains(&root)
                && let Some(right) = node.child_by_field_name("right")
            {
                let mut reads = HashSet::new();
                collect_identifiers(right, src, state_names, &mut reads);
                for r in reads {
                    ops.push(EffectOp::ReadState { var: r, line });
                }
                let rhs_txt = node_txt(right, src);
                let rhs_nom = node_txt(node, src).contains("+=")
                    || rhs_txt.to_ascii_lowercase().contains("amount");
                ops.push(EffectOp::WriteState {
                    is_accounting: is_accounting_state_var(&root),
                    is_rhs_nominal_amount: rhs_nom,
                    var: root,
                    line,
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
                });
            }
            // Also scan arguments for nested reads
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
        );
    }
}

fn has_caller_auth_tokens(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    low.contains("msg.sender")
        || low.contains("_msgsender()")
        || low.contains("_checkowner")
        || low.contains("_checkrole")
        || low.contains("hasrole(")
        || low.contains("owner == ")
        || low.contains("== owner")
        || low.contains("admin == ")
        || low.contains("== admin")
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

/// Parses a Solidity file into contract metadata, packed storage layout, and function effect summaries.
pub fn parse_solidity_file(rel_path: &str, source: &str) -> Vec<ParsedContract> {
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
        contracts.push(extract_contract(ch, src, rel_path, kind));
    }
    contracts
}

fn extract_contract(node: Node, src: &[u8], rel_path: &str, kind: ContractKind) -> ParsedContract {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "Contract".into());
    let start_line = node.start_position().row + 1;
    let full_txt = node_txt(node, src);
    let has_erc7201_namespace = full_txt.contains("erc7201:");

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

    let mut state_vars = Vec::new();
    let mut custom_auth_modifiers = HashSet::new();
    let mut custom_lock_modifiers = HashSet::new();
    let mut fn_nodes = Vec::new();

    if let Some(body) = node.child_by_field_name("body") {
        let mut bc = body.walk();
        for item in body.named_children(&mut bc) {
            match item.kind() {
                "state_variable_declaration" => {
                    let raw = node_txt(item, src);
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
                    let mod_txt = node_txt(item, src);
                    if has_caller_auth_tokens(mod_txt) {
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

    let state_names: HashSet<String> = state_vars.iter().map(|v| v.name.clone()).collect();
    let packed_slots = pack_storage_vars(&name, rel_path, &state_vars, 0);

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
        let body_text = body_node
            .map(|b| node_txt(b, src).to_string())
            .unwrap_or_default();
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

    let is_proxy_like = (full_txt.contains("delegatecall") && kind == ContractKind::Contract)
        || name.contains("Proxy")
        || bases.iter().any(|b| b.contains("Proxy"));

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
    let low = body.to_ascii_lowercase();
    (low.contains("_locked =") || low.contains("locked =") || low.contains("_entered ="))
        && (low.contains("require(") || low.contains("revert"))
}

fn view_fn_checks_reentrancy_lock(body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    low.contains("_reentrancyguardentered")
        || low.contains("_locked")
        || low.contains("require(!locked")
}

/// Runs all EVM/Solidity security passes on a parsed file and attaches `revm` witness proofs when available.
pub fn analyze_solidity_file(
    rel_path: &str,
    source: &str,
    ctx: &Web3Context,
) -> (Vec<ParsedContract>, Vec<LocalStaticFinding>) {
    let contracts = parse_solidity_file(rel_path, source);
    let mut findings = Vec::new();
    let is_test = smg_core::is_test_source_path(rel_path);
    if is_test {
        return (contracts, findings);
    }

    for c in &contracts {
        if matches!(c.kind, ContractKind::Interface) {
            continue;
        }
        let mut stale_vars_exposed_after_call: HashMap<String, usize> = HashMap::new();
        let artifact = ctx.artifacts.get(&c.name);

        for f in &c.functions {
            if f.is_constructor || matches!(f.visibility.as_str(), "internal" | "private") {
                check_math_and_oracle_inside_fn(c, f, rel_path, &mut findings);
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
                let mut first_callback_line: Option<usize> = None;
                for op in &f.ops {
                    match op {
                        EffectOp::ExternalCall {
                            has_callback_risk: true,
                            line,
                            ..
                        } => {
                            if first_callback_line.is_none() {
                                first_callback_line = Some(*line);
                            }
                        }
                        EffectOp::WriteState {
                            var,
                            is_accounting: true,
                            line,
                            ..
                        } => {
                            if let Some(call_line) = first_callback_line
                                && *line > call_line
                            {
                                stale_vars_exposed_after_call
                                    .entry(var.clone())
                                    .or_insert(call_line);
                                let mut conf = Confidence::Confirmed;
                                let mut proof_note = String::new();
                                if let Some(art) = artifact
                                    && !art.deployed_bytecode.is_empty()
                                {
                                    let w_sel = abi_selector(&format!("{}()", f.name));
                                    let d_sel = art
                                        .abi_functions
                                        .iter()
                                        .find(|s| s.starts_with("deposit"))
                                        .map(|s| abi_selector(s));
                                    let wres = probe_compiled_reentrancy_in_revm(
                                        &art.deployed_bytecode,
                                        d_sel,
                                        &w_sel,
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
                                break;
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
            check_math_and_oracle_inside_fn(c, f, rel_path, &mut findings);
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
                        && stale_vars_exposed_after_call.contains_key(var)
                    {
                        findings.push(LocalStaticFinding {
                            rule_id: "SMG-WEB3-REENTRANCY".into(),
                            severity: "HIGH".into(),
                            title: format!(
                                "Read-only reentrancy exposure: view `{}.{}` reads `{}` without lock check while mutator leaves state stale across callback",
                                c.name, vf.name, var
                            ),
                            rel_path: rel_path.into(),
                            line: vf.start_line,
                            symbol: format!("{}.{}", c.name, vf.name),
                            sink_kind: SinkKind::BalanceUpdate,
                            missing_guard: GuardKind::TxLock,
                            confidence: Confidence::Confirmed,
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
            || f.body_text.contains("_disableInitializers");
        if !guarded {
            let mut conf = Confidence::Confirmed;
            let mut note = String::new();
            if let Some(art) = artifact
                && !art.deployed_bytecode.is_empty()
            {
                let sig = format!("{}(address)", f.name);
                let sel = abi_selector(&sig);
                if let Ok((ok, writes, gas)) =
                    probe_compiled_selector_unauth(&art.deployed_bytecode, sel, Some([0xBB; 32]))
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

    let is_privileged_name = matches!(
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
            | "mint"
    );
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
    let low = body.to_ascii_lowercase();
    if !low.contains("nonce")
        && !low.contains("used[")
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

    // B. AST Division before Multiplication precision loss
    for ln in &f.div_before_mul_lines {
        if !body.contains("mulDiv") {
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
        if !has_updated || !has_pos_price {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-ORACLE".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Chainlink `latestRoundData()` missing staleness/positive-price validation in `{}.{}`",
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

    let is_valuation_fn = fn_low.contains("price")
        || fn_low.contains("borrow")
        || fn_low.contains("liquidat")
        || fn_low.contains("collateral")
        || fn_low.contains("value");
    if is_valuation_fn
        && low.contains("getreserves(")
        && !low.contains("twap")
        && !low.contains("observe(")
        && !low.contains("consult(")
        && !low.contains("latestrounddata")
    {
        let skew = check_amm_spot_skew_bps(1_000_000, 1_000_000, 500_000);
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
    }
}
