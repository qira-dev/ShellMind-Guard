use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::HashSet;
use tree_sitter::{Node, Parser};

fn node_txt<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn has_test_attr(node: Node, src: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let txt = node_txt(p, src);
            if txt.contains("cfg(test)") || txt.contains("#[test]") || txt.contains("::test") {
                return true;
            }
            prev = p.prev_sibling();
        } else if matches!(p.kind(), "line_comment" | "block_comment") {
            prev = p.prev_sibling();
        } else {
            break;
        }
    }
    false
}

/// Checks if a Rust file belongs to Solana / Anchor smart contracts.
pub fn is_solana_rust_source(source: &str) -> bool {
    source.contains("anchor_lang")
        || source.contains("solana_program")
        || source.contains("#[program]")
        || source.contains("#[derive(Accounts)]")
        || source.contains("ProgramResult")
}

/// Analyzes Solana Anchor & native Rust SVM programs via Tree-sitter Rust AST.
pub fn analyze_solana_rust_file(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) || !is_solana_rust_source(source) {
        return Vec::new();
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let src = source.as_bytes();
    let mut findings = Vec::new();

    // Collect instruction-wide `is_signer` and `owner ==` checks per file/function
    let mut fn_is_signer_checks: HashSet<String> = HashSet::new();
    let mut fn_owner_checks: HashSet<String> = HashSet::new();
    collect_native_svm_checks(
        tree.root_node(),
        src,
        &mut fn_is_signer_checks,
        &mut fn_owner_checks,
    );

    walk_rust_solana(
        tree.root_node(),
        src,
        rel_path,
        &fn_is_signer_checks,
        &fn_owner_checks,
        &mut findings,
    );
    findings
}

fn collect_native_svm_checks(
    node: Node,
    src: &[u8],
    signers: &mut HashSet<String>,
    owners: &mut HashSet<String>,
) {
    if node.kind() == "function_item" && !has_test_attr(node, src) {
        let body = node_txt(node, src);
        for line in body.lines() {
            let low = line.to_ascii_lowercase();
            if low.contains(".is_signer")
                && let Some(ident) = line.split(".is_signer").next()
                && let Some(word) = ident
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next_back()
                && !word.is_empty()
            {
                signers.insert(word.to_string());
            }
            if low.contains(".owner")
                && (low.contains("==") || low.contains("!="))
                && let Some(ident) = line.split(".owner").next()
                && let Some(word) = ident
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next_back()
                && !word.is_empty()
            {
                owners.insert(word.to_string());
            }
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_native_svm_checks(ch, src, signers, owners);
    }
}

fn has_derive_accounts_attr(node: Node, src: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let txt = node_txt(p, src);
            if txt.contains("Accounts") {
                return true;
            }
            prev = p.prev_sibling();
        } else if matches!(p.kind(), "line_comment" | "block_comment") {
            prev = p.prev_sibling();
        } else {
            break;
        }
    }
    false
}

fn walk_rust_solana(
    node: Node,
    src: &[u8],
    rel_path: &str,
    fn_signers: &HashSet<String>,
    fn_owners: &HashSet<String>,
    findings: &mut Vec<LocalStaticFinding>,
) {
    if has_test_attr(node, src) {
        return;
    }
    match node.kind() {
        "struct_item" if has_derive_accounts_attr(node, src) => {
            inspect_anchor_accounts_struct(node, src, rel_path, fn_signers, fn_owners, findings);
            return;
        }
        "function_item" => {
            inspect_solana_instruction_fn(node, src, rel_path, findings);
        }
        _ => {}
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_solana(ch, src, rel_path, fn_signers, fn_owners, findings);
    }
}

fn inspect_anchor_accounts_struct(
    struct_node: Node,
    src: &[u8],
    rel_path: &str,
    fn_signers: &HashSet<String>,
    fn_owners: &HashSet<String>,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let struct_name = struct_node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "Accounts".into());
    let Some(body) = struct_node.child_by_field_name("body") else {
        return;
    };

    let mut pending_attrs = String::new();
    let mut bc = body.walk();
    for item in body.named_children(&mut bc) {
        if item.kind() == "attribute_item" {
            pending_attrs.push_str(node_txt(item, src));
            pending_attrs.push('\n');
            continue;
        }
        if item.kind() != "field_declaration" {
            continue;
        }
        let field_name = item
            .child_by_field_name("name")
            .map(|n| node_txt(n, src).to_string())
            .unwrap_or_default();
        let field_ty = item
            .child_by_field_name("type")
            .map(|n| node_txt(n, src).to_string())
            .unwrap_or_default();
        let line = item.start_position().row + 1;
        let attrs_low = pending_attrs.to_ascii_lowercase();
        let fname_low = field_name.to_ascii_lowercase();
        pending_attrs.clear();

        let is_raw_account_info =
            field_ty.contains("AccountInfo") || field_ty.contains("UncheckedAccount");
        if !is_raw_account_info {
            continue;
        }

        let is_authority_name = [
            "authority",
            "admin",
            "owner",
            "signer",
            "payer",
            "governance",
            "sender",
        ]
        .iter()
        .any(|kw| fname_low.contains(kw));
        let is_state_or_program_name = ["vault", "state", "config", "pool", "escrow", "program"]
            .iter()
            .any(|kw| fname_low.contains(kw));

        let attr_checks_signer = attrs_low.contains("signer") || fn_signers.contains(&field_name);
        let attr_checks_owner = attrs_low.contains("owner =")
            || attrs_low.contains("address =")
            || attrs_low.contains("constraint =")
            || attrs_low.contains("has_one =")
            || attrs_low.contains("seeds =")
            || fn_owners.contains(&field_name);

        if is_authority_name && !attr_checks_signer {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-SOLANA".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Missing Solana Signer constraint on authority `{struct_name}.{field_name}: {field_ty}`"
                ),
                rel_path: rel_path.into(),
                line,
                symbol: format!("{struct_name}.{field_name}"),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: Confidence::Confirmed,
                remediation: "Replace raw `AccountInfo`/`UncheckedAccount` authority with typed Anchor `Signer<'info>` or validate `is_signer`.".into(),
            });
        } else if is_state_or_program_name && !attr_checks_owner {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-SOLANA".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Missing Anchor owner/program validation on `{struct_name}.{field_name}: {field_ty}`"
                ),
                rel_path: rel_path.into(),
                line,
                symbol: format!("{struct_name}.{field_name}"),
                sink_kind: SinkKind::IdorDbAccess,
                missing_guard: GuardKind::OwnershipCheck,
                confidence: Confidence::Confirmed,
                remediation: "Use typed `Account<'info, T>` / `Program<'info, ...>` or enforce `owner == program_id` and `has_one`/`seeds` constraints.".into(),
            });
        }
    }
}

fn inspect_solana_instruction_fn(
    fn_node: Node,
    src: &[u8],
    rel_path: &str,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let fn_name = fn_node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "instruction".into());
    let body = node_txt(fn_node, src);
    let base_line = fn_node.start_position().row + 1;

    for (idx, line) in body.lines().enumerate() {
        let ln = base_line + idx;
        if line.contains("create_program_address(")
            && !body.contains("find_program_address(")
            && !body.contains("bump")
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-SOLANA".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Non-canonical PDA derivation via `create_program_address` in `{fn_name}` without `find_program_address`"
                ),
                rel_path: rel_path.into(),
                line: ln,
                symbol: fn_name.clone(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Use `Pubkey::find_program_address` or Anchor canonical `bump` seed constraint to prevent non-canonical bump spoofing.".into(),
            });
        }
        if (line.contains("invoke(") || line.contains("invoke_signed("))
            && !body.contains("Program<'info")
            && !body.contains("check_program_account")
            && !body.contains("::ID")
            && !body.contains("::id()")
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-SOLANA".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Arbitrary CPI target in `{fn_name}`: `invoke`/`invoke_signed` without validated program ID or `Program<'info, T>`"
                ),
                rel_path: rel_path.into(),
                line: ln,
                symbol: fn_name.clone(),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: Confidence::Confirmed,
                remediation: "Validate target CPI program account against canonical `Program<'info, ...>` or explicit `key() == expected::ID` check.".into(),
            });
            break;
        }
    }
}

/// Analyzes Sui / Aptos Move source modules cleanly above VM linear resource guarantees.
pub fn analyze_move_file(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0usize;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_test_fn = i > 0 && lines[i - 1].contains("#[test");
        if is_test_fn {
            i += 1;
            continue;
        }

        let is_public_fn = (trimmed.starts_with("public ") || trimmed.starts_with("entry "))
            && trimmed.contains(" fun ");
        if !is_public_fn {
            i += 1;
            continue;
        }

        // Collect signature + balanced body
        let start_line = i + 1;
        let mut sig = String::new();
        let mut j = i;
        while j < lines.len() {
            sig.push_str(lines[j]);
            sig.push(' ');
            if lines[j].contains('{') {
                break;
            }
            j += 1;
        }
        let Some(fun_pos) = sig.find(" fun ") else {
            i += 1;
            continue;
        };
        let after_fun = sig[fun_pos + 5..].trim_start();
        let fn_name = after_fun
            .split(['(', '<', ' '])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let params = after_fun
            .split_once('(')
            .and_then(|(_, r)| r.split_once(')'))
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();

        // Collect balanced function body
        let mut depth: i32 = 0;
        let mut body = String::new();
        let mut k = i;
        let mut started = false;
        while k < lines.len() {
            for ch in lines[k].chars() {
                if ch == '{' {
                    depth += 1;
                    started = true;
                } else if ch == '}' {
                    depth -= 1;
                }
            }
            body.push_str(lines[k]);
            body.push('\n');
            if started && depth <= 0 {
                break;
            }
            k += 1;
        }

        let fn_low = fn_name.to_ascii_lowercase();
        let params_low = params.to_ascii_lowercase();
        let body_low = body.to_ascii_lowercase();

        // 1. Public `init` exposure
        if fn_low == "init" {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-MOVE".into(),
                severity: "CRITICAL".into(),
                title: "Sui Move module exposes `public` initializer `init` — anyone can re-invoke genesis allocation".into(),
                rel_path: rel_path.into(),
                line: start_line,
                symbol: fn_name.clone(),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: Confidence::Confirmed,
                remediation: "Keep module initializer private (`fun init(ctx: &mut TxContext)`) so Sui VM invokes it strictly once on publish.".into(),
            });
        }

        // 2. Missing `&AdminCap` / signer check on privileged Move entrypoints
        let is_privileged = fn_low.starts_with("admin_")
            || fn_low.starts_with("set_")
            || matches!(
                fn_low.as_str(),
                "mint" | "burn" | "withdraw" | "emergency_withdraw" | "pause" | "upgrade"
            );
        let has_cap_or_sender_auth = params_low.contains("cap")
            || body_low.contains("tx_context::sender")
            || body_low.contains("signer::address_of")
            || params_low.contains("treasury_cap");
        if is_privileged && !has_cap_or_sender_auth {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-MOVE".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Unprotected Move privileged function `{fn_name}` missing `&AdminCap` capability or sender authorization"
                ),
                rel_path: rel_path.into(),
                line: start_line,
                symbol: fn_name.clone(),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::Auth,
                confidence: Confidence::Confirmed,
                remediation: "Require `_cap: &AdminCap` (or verify `tx_context::sender(ctx)` / `signer::address_of`) on admin Move entrypoints.".into(),
            });
        }

        // 3. Unchecked zero-value coin/balance split
        if (body_low.contains("coin::split(") || body_low.contains("balance::split("))
            && !body_low.contains("> 0")
            && !body_low.contains("!= 0")
            && !body_low.contains("== 0")
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-MOVE".into(),
                severity: "MEDIUM".into(),
                title: format!(
                    "Unchecked zero-amount coin/balance split in Move `{fn_name}` enables empty object spam or accounting bypass"
                ),
                rel_path: rel_path.into(),
                line: start_line,
                symbol: fn_name,
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Confirmed,
                remediation: "Assert `assert!(amount > 0, E_ZERO_AMOUNT)` before splitting or transferring coins/balances.".into(),
            });
        }

        i = k.saturating_add(1).max(i + 1);
    }

    findings
}
