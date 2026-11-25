use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
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

fn extract_ctx_struct_name(text: &str) -> Option<String> {
    let idx = text.find("Context")?;
    let rest = text[idx + "Context".len()..].trim_start();
    let inner = rest.strip_prefix('<')?.split_once('>')?.0;
    let struct_tok = inner.rsplit(',').next()?.trim();
    let ident: String = struct_tok
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!ident.is_empty()).then_some(ident)
}

fn has_anchor_owner_attr(attrs_low: &str) -> bool {
    let no_ws: String = attrs_low.chars().filter(|c| !c.is_whitespace()).collect();
    no_ws.contains("owner=")
        || no_ws.contains("address=")
        || no_ws.contains("constraint=")
        || no_ws.contains("has_one=")
        || no_ws.contains("seeds=")
}

/// Checks if a Rust file belongs to Solana / Anchor smart contracts.
pub fn is_solana_rust_source(source: &str) -> bool {
    source.contains("anchor_lang")
        || source.contains("solana_program")
        || source.contains("#[program]")
        || source.contains("#[derive(Accounts)]")
        || source.contains("ProgramResult")
}

#[derive(Default, Clone)]
pub struct SolanaFileContext {
    /// Per `Context<StructName>` fields verified with `.is_signer` inside instructions using that `StructName`
    pub(crate) struct_signers: HashMap<String, HashSet<String>>,
    /// Per `Context<StructName>` fields verified with `.owner ==` inside instructions using that `StructName`
    pub(crate) struct_owners: HashMap<String, HashSet<String>>,
    /// Per `#[derive(Accounts)]` struct, the exact field identifiers validated via `Program<'info, ...>`,
    /// `Interface<'info, ...>`, or `#[account(..., address = ...)]`.
    pub(crate) validated_program_fields: HashMap<String, HashSet<String>>,
}

/// Workspace-wide Solana/Anchor context hoisted across split instruction & account files (`Phase 13B P13-04`).
pub type SolanaWorkspaceContext = SolanaFileContext;

/// Collects `#[derive(Accounts)]` and instruction signer/owner validations across all Solana Rust files in a workspace.
pub fn collect_solana_workspace_context(sources: &[(String, String)]) -> SolanaWorkspaceContext {
    let mut sctx = SolanaWorkspaceContext::default();
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return sctx;
    }
    for (rel_path, source) in sources {
        if smg_core::is_test_source_path(rel_path) || !is_solana_rust_source(source) {
            continue;
        }
        let stripped = smg_graph::taint::strip_comments_simple(source);
        if let Some(tree) = parser.parse(&stripped, None) {
            collect_solana_file_context(tree.root_node(), stripped.as_bytes(), &mut sctx, 0);
        }
    }
    sctx
}

/// Analyzes Solana Anchor & native Rust SVM programs via Tree-sitter Rust AST.
pub fn analyze_solana_rust_file(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    analyze_solana_rust_file_with_ctx(rel_path, source, None)
}

/// Analyzes a Solana Anchor/native Rust file with an optional workspace-wide `SolanaWorkspaceContext`
/// so split `instructions/*.rs` and `state/*.rs` handlers share `#[derive(Accounts)]` and signer proofs.
pub fn analyze_solana_rust_file_with_ctx(
    rel_path: &str,
    source: &str,
    workspace_ctx: Option<&SolanaWorkspaceContext>,
) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) || !is_solana_rust_source(source) {
        return Vec::new();
    }
    let stripped = smg_graph::taint::strip_comments_simple(source);
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&stripped, None) else {
        return Vec::new();
    };
    let src = stripped.as_bytes();
    let mut findings = Vec::new();

    let mut sctx = workspace_ctx.cloned().unwrap_or_default();
    collect_solana_file_context(tree.root_node(), src, &mut sctx, 0);

    walk_rust_solana(tree.root_node(), src, rel_path, &sctx, &mut findings, 0);
    findings
}

/// Extracts field names inside an Anchor `#[derive(Accounts)]` struct that are validated
/// program accounts (`Program<'info, ...>`, `Interface<'info, ...>`, or `#[account(..., address = ...)]`).
pub(crate) fn extract_validated_program_fields_from_struct(struct_src: &str) -> HashSet<String> {
    let mut fields = HashSet::new();
    let mut pending_address_attr = false;
    for line in struct_src.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if trimmed.starts_with("#[") {
            if low.contains("address =") || low.contains("address=") {
                pending_address_attr = true;
            }
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once(':') {
            let field_name = lhs
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
            let is_validated_ty =
                rhs.contains("Program<") || rhs.contains("Interface<") || pending_address_attr;
            if !field_name.is_empty() && is_validated_ty {
                fields.insert(field_name.to_string());
            }
            pending_address_attr = false;
        } else if trimmed == "}" {
            pending_address_attr = false;
        }
    }
    fields
}

/// Checks whether a CPI invocation snippet (`invoke`/`invoke_signed`/`CpiContext::new`)
/// targets a validated program field (from `validated_fields`) rather than an unvalidated `AccountInfo`.
pub(crate) fn cpi_targets_validated_program_field(
    window: &str,
    validated_fields: &HashSet<String>,
) -> bool {
    if validated_fields.is_empty() {
        return false;
    }
    // Extract all `<prefix>.<field>` references like `ctx.accounts.target_prog` or `self.token_program`
    let mut mentioned_account_fields: Vec<&str> = Vec::new();
    for marker in ["ctx.accounts.", "accounts.", "self."] {
        let mut rest = window;
        while let Some(pos) = rest.find(marker) {
            let after = &rest[pos + marker.len()..];
            let field = after
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("");
            if !field.is_empty() {
                mentioned_account_fields.push(field);
            }
            rest = after;
        }
    }
    if mentioned_account_fields.is_empty() {
        return false;
    }
    // If an explicit program-like field is referenced (e.g. `target_prog`, `program`, `cpi_program`,
    // `token_program`, `dex_program`), require THAT field to be validated. Otherwise, require at
    // least one referenced field in the CPI call to be validated AND no unvalidated `*prog*`/`*program*` field.
    let prog_like: Vec<&str> = mentioned_account_fields
        .iter()
        .copied()
        .filter(|f| {
            let fl = f.to_ascii_lowercase();
            fl.contains("prog") || fl.contains("cpi") || fl.contains("callee")
        })
        .collect();
    if !prog_like.is_empty() {
        prog_like.iter().all(|f| validated_fields.contains(*f))
    } else {
        mentioned_account_fields
            .iter()
            .any(|f| validated_fields.contains(*f))
    }
}

fn collect_solana_file_context(node: Node, src: &[u8], sctx: &mut SolanaFileContext, depth: usize) {
    if depth >= 128 || has_test_attr(node, src) {
        return;
    }
    if node.kind() == "struct_item" && has_derive_accounts_attr(node, src) {
        let struct_name = node
            .child_by_field_name("name")
            .map(|n| node_txt(n, src).to_string())
            .unwrap_or_default();
        let body_txt = node_txt(node, src);
        let validated = extract_validated_program_fields_from_struct(body_txt);
        if !validated.is_empty() {
            sctx.validated_program_fields
                .entry(struct_name)
                .or_default()
                .extend(validated);
        }
        return;
    }
    if node.kind() == "function_item" {
        let fn_txt = node_txt(node, src);
        let ctx_struct =
            extract_ctx_struct_name(fn_txt).unwrap_or_else(|| "__native__".to_string());
        for line in fn_txt.lines() {
            let trimmed = line.trim();
            let low = trimmed.to_ascii_lowercase();
            // Require `.is_signer` inside an actual guard/check statement (never a bare `msg!` log or `let _ =`)
            let is_guard_stmt = (low.starts_with("if ")
                || low.contains("require!")
                || low.contains("assert!")
                || low.contains("assert_eq!")
                || low.contains("ensure!")
                || low.contains("if !")
                || low.contains("if ("))
                && !low.starts_with("msg!(")
                && !low.starts_with("let _ =");
            if is_guard_stmt
                && low.contains(".is_signer")
                && let Some(ident) = line.split(".is_signer").next()
                && let Some(word) = ident
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next_back()
                && !word.is_empty()
            {
                sctx.struct_signers
                    .entry(ctx_struct.clone())
                    .or_default()
                    .insert(word.to_string());
            }
            if (low.contains(".owner") || low.contains(".key()"))
                && (low.contains("==") || low.contains("!="))
                && let Some(ident) = line
                    .split(".owner")
                    .next()
                    .and_then(|s| s.split(".key()").next())
                && let Some(word) = ident
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next_back()
                && !word.is_empty()
            {
                sctx.struct_owners
                    .entry(ctx_struct.clone())
                    .or_default()
                    .insert(word.to_string());
            }
            if low.contains("assert_keys_eq!")
                && let Some(inner) = low.split("assert_keys_eq!(").nth(1)
            {
                for tok in inner.split([',', ')']).take(2) {
                    if let Some(word) = tok
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next_back()
                        && !word.is_empty()
                    {
                        sctx.struct_owners
                            .entry(ctx_struct.clone())
                            .or_default()
                            .insert(word.to_string());
                    }
                }
            }
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_solana_file_context(ch, src, sctx, depth + 1);
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
    sctx: &SolanaFileContext,
    findings: &mut Vec<LocalStaticFinding>,
    depth: usize,
) {
    if depth >= 128 || has_test_attr(node, src) {
        return;
    }
    match node.kind() {
        "struct_item" if has_derive_accounts_attr(node, src) => {
            inspect_anchor_accounts_struct(node, src, rel_path, sctx, findings);
            return;
        }
        "function_item" => {
            inspect_solana_instruction_fn(node, src, rel_path, sctx, findings);
        }
        _ => {}
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_solana(ch, src, rel_path, sctx, findings, depth + 1);
    }
}

fn inspect_anchor_accounts_struct(
    struct_node: Node,
    src: &[u8],
    rel_path: &str,
    sctx: &SolanaFileContext,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let struct_name = struct_node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "Accounts".into());
    let Some(body) = struct_node.child_by_field_name("body") else {
        return;
    };

    let fn_signers = sctx.struct_signers.get(&struct_name);
    let fn_owners = sctx.struct_owners.get(&struct_name);

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

        let is_non_signing_dest = fname_low.starts_with("new_")
            || fname_low.starts_with("recipient")
            || fname_low.starts_with("dest")
            || fname_low.starts_with("old_")
            || fname_low.starts_with("previous_")
            || fname_low.ends_with("_ata");
        let is_authority_name = !is_non_signing_dest
            && [
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
            .any(|kw| fname_low.contains(kw))
            && fname_low != "program_data";

        let attr_checks_signer =
            attrs_low.contains("signer") || fn_signers.is_some_and(|s| s.contains(&field_name));
        let attr_checks_owner =
            has_anchor_owner_attr(&attrs_low) || fn_owners.is_some_and(|s| s.contains(&field_name));

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
    sctx: &SolanaFileContext,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let fn_name = fn_node
        .child_by_field_name("name")
        .map(|n| node_txt(n, src).to_string())
        .unwrap_or_else(|| "instruction".into());
    let body = node_txt(fn_node, src);
    let base_line = fn_node.start_position().row + 1;
    let mut active_validated_fields: HashSet<String> = HashSet::new();
    if body.contains("&self") {
        let mut cur = fn_node.parent();
        while let Some(p) = cur {
            if p.kind() == "impl_item" {
                let impl_txt = node_txt(p, src);
                for (st, fields) in &sctx.validated_program_fields {
                    if impl_txt.contains(st) {
                        active_validated_fields.extend(fields.iter().cloned());
                    }
                }
                break;
            }
            cur = p.parent();
        }
    }
    if let Some(st) = extract_ctx_struct_name(body)
        && let Some(fields) = sctx.validated_program_fields.get(&st)
    {
        active_validated_fields.extend(fields.iter().cloned());
    }

    let body_low = body.to_ascii_lowercase();
    // Distinguish actual lamport assignment (`= 0`) from equality check (`== 0`, `!= 0`, `<= 0`, `>= 0`)
    let has_zero_assign = body_low.lines().any(|l| {
        let bytes = l.as_bytes();
        for (i, w) in bytes.windows(3).enumerate() {
            if w == b"= 0"
                && (i == 0 || !matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>'))
                && !bytes.get(i + 3).is_some_and(|b| b.is_ascii_digit())
            {
                return true;
            }
        }
        l.contains("=0;")
            && !l.contains("==0")
            && !l.contains("!=0")
            && !l.contains("<=0")
            && !l.contains(">=0")
    });
    let has_lamport_zero = body_low.contains("try_borrow_mut_lamports") && has_zero_assign;
    if has_lamport_zero
        && !body_low.contains(".fill(0)")
        && !body_low.contains("closed_account_discriminator")
    {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-SOLANA".into(),
            severity: "HIGH".into(),
            title: format!("Solana account close zeroes lamports without clearing data/discriminator in `{fn_name}` (account resurrection risk)"),
            rel_path: rel_path.into(),
            line: base_line,
            symbol: fn_name.clone(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::InputValidation,
            confidence: Confidence::Confirmed,
            remediation: "Use Anchor `#[account(mut, close = recipient)]` or zero account data and write `CLOSED_ACCOUNT_DISCRIMINATOR`.".into(),
        });
    }
    if (body_low.contains("token::transfer(")
        || body_low.contains("invoke(")
        || body_low.contains("invoke_signed("))
        && body_low.contains("remaining_accounts")
        && !body_low.contains(".owner ==")
        && !body_low.contains("try_deserialize")
    {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-WEB3-SOLANA".into(),
            severity: "HIGH".into(),
            title: format!("Unvalidated `ctx.remaining_accounts` used near CPI/account access in `{fn_name}`"),
            rel_path: rel_path.into(),
            line: base_line,
            symbol: fn_name.clone(),
            sink_kind: SinkKind::IdorDbAccess,
            missing_guard: GuardKind::OwnershipCheck,
            confidence: Confidence::Heuristic,
            remediation: "Validate `acc.owner == program_id`, expected keys, and account discriminators for every entry in `remaining_accounts`.".into(),
        });
    }

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
        if (line.contains("invoke(")
            || line.contains("invoke_signed(")
            || line.contains("CpiContext::new("))
            && !smg_graph::taint::is_pattern_matcher_or_doc_line(line)
            && !line.contains("\"invoke(\"")
            && !line.contains("\"invoke_signed(\"")
            && !line.contains("\"CpiContext::new(\"")
        {
            let body_lines: Vec<&str> = body.lines().collect();
            let w_start = idx.saturating_sub(8);
            let w_end = (idx + 6).min(body_lines.len());
            let cpi_window = body_lines[w_start..w_end].join("\n");
            let field_validated =
                cpi_targets_validated_program_field(&cpi_window, &active_validated_fields);
            if !field_validated
                && !cpi_window.contains("Program<'info")
                && !cpi_window.contains("check_program_account")
                && !cpi_window.contains("::ID")
                && !cpi_window.contains("::id()")
                && !cpi_window.contains("program_id ==")
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
}

fn has_move_capability_param(params: &str) -> bool {
    for part in params.split(',') {
        let Some((_, raw_ty)) = part.split_once(':') else {
            continue;
        };
        let ty = raw_ty.trim();
        let ty_low = ty.to_ascii_lowercase();
        if ty_low.contains("signer")
            || ty_low.contains("capability")
            || ty_low.contains("treasury_cap")
            || ty_low.contains("admin_cap")
            || ty.ends_with("Cap")
            || ty.contains("Cap<")
        {
            return true;
        }
    }
    false
}

/// Updates brace depth across a single Move line while ignoring string literals (`"..."`, `b"..."`).
pub(crate) fn update_move_brace_depth(line: &str, depth: &mut i32, started: &mut bool) {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if esc {
            esc = false;
            i += 1;
            continue;
        }
        if b == b'\\' && in_str {
            esc = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = !in_str;
            i += 1;
            continue;
        }
        if !in_str {
            if b == b'{' {
                *depth += 1;
                *started = true;
            } else if b == b'}' {
                *depth -= 1;
            }
        }
        i += 1;
    }
}

/// Returns true only when `#[test_only]` annotates the entire `module` declaration itself.
pub(crate) fn is_test_only_move_module(lines: &[&str]) -> bool {
    let mut saw_test_only = false;
    for raw in lines {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("#[test_only]") {
            saw_test_only = true;
            continue;
        }
        if t.starts_with("#[") {
            continue;
        }
        return saw_test_only && t.starts_with("module ");
    }
    false
}

/// Analyzes Sui / Aptos Move source modules cleanly above VM linear resource guarantees.
pub fn analyze_move_file(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) {
        return Vec::new();
    }
    let stripped = smg_graph::taint::strip_comments_simple(source);
    let lines: Vec<&str> = stripped.lines().collect();
    if is_test_only_move_module(&lines) {
        return Vec::new();
    }
    let mut findings = Vec::new();

    // Phase 13B (`P13-04`): Parse Move `struct <Name> has <abilities>` for hot-potato & capability invariants
    // (skipping individual `#[test_only]` items without skipping the rest of the module)
    let mut skip_next_test_item = false;
    let mut skip_item_depth: i32 = 0;
    let mut skip_item_started = false;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if skip_next_test_item {
            update_move_brace_depth(trimmed, &mut skip_item_depth, &mut skip_item_started);
            if (skip_item_started && skip_item_depth <= 0)
                || (!skip_item_started && !trimmed.starts_with("#[") && trimmed.ends_with(';'))
            {
                skip_next_test_item = false;
                skip_item_depth = 0;
                skip_item_started = false;
            }
            continue;
        }
        if trimmed.starts_with("#[test_only]") || trimmed.starts_with("#[test") {
            skip_next_test_item = true;
            skip_item_depth = 0;
            skip_item_started = false;
            continue;
        }
        let after_struct = trimmed
            .strip_prefix("public struct ")
            .or_else(|| trimmed.strip_prefix("struct "));
        if let Some(rest) = after_struct
            && let Some((name_part, ab_part)) = rest.split_once(" has ")
        {
            let sname = name_part.split(['<', ' ']).next().unwrap_or("").trim();
            let abilities_raw = ab_part.split(['{', ';']).next().unwrap_or(ab_part);
            let abilities: Vec<&str> = abilities_raw
                .split([',', ' '])
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .collect();
            let sname_low = sname.to_ascii_lowercase();

            // 1. Hot-potato struct (`*Receipt`, `*FlashLoan`, `*Promise`, `*HotPotato`) must NOT have `drop` or `copy`
            let is_hot_potato = sname_low.contains("receipt")
                || sname_low.contains("flashloan")
                || sname_low.contains("flash_loan")
                || sname_low.contains("hotpotato")
                || sname_low.contains("hot_potato")
                || sname_low.contains("promise");
            if is_hot_potato && (abilities.contains(&"drop") || abilities.contains(&"copy")) {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-WEB3-MOVE".into(),
                    severity: "CRITICAL".into(),
                    title: format!(
                        "Move hot-potato struct `{sname}` declares `drop`/`copy` ability — callers can discard flash-loan repayment obligation"
                    ),
                    rel_path: rel_path.into(),
                    line: idx + 1,
                    symbol: sname.to_string(),
                    sink_kind: SinkKind::AuthMutation,
                    missing_guard: GuardKind::InputValidation,
                    confidence: Confidence::Confirmed,
                    remediation: "Remove `drop` and `copy` abilities from hot-potato receipts so Move's linear type system forces repayment inside the same transaction.".into(),
                });
            }

            // 2. Capability struct (`*Cap`, `*AdminCap`, `*OwnerCap`) must NOT have `copy` or unrestricted `store`
            let is_cap = sname.ends_with("Cap") || sname_low.ends_with("_cap");
            if is_cap && (abilities.contains(&"copy") || abilities.contains(&"store")) {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-WEB3-MOVE".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Move capability struct `{sname}` declares `copy`/`store` ability — privilege object can be duplicated or freely transferred via `public_transfer`"
                    ),
                    rel_path: rel_path.into(),
                    line: idx + 1,
                    symbol: sname.to_string(),
                    sink_kind: SinkKind::AuthMutation,
                    missing_guard: GuardKind::Auth,
                    confidence: Confidence::Confirmed,
                    remediation: "Restrict admin/treasury capabilities to `has key` only (omit `copy` and `store`) and gate transfers through explicit module-owned rotation functions.".into(),
                });
            }
        }
    }

    let mut i = 0usize;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_test_fn = (i > 0
            && (lines[i - 1].contains("#[test") || lines[i - 1].contains("#[test_only]")))
            || (i > 1
                && (lines[i - 2].contains("#[test") || lines[i - 2].contains("#[test_only]")))
            || trimmed.starts_with("#[test");
        if is_test_fn {
            // Skip the entire annotated test/test_only item body
            let mut td: i32 = 0;
            let mut t_started = false;
            let mut m = i;
            while m < lines.len() {
                let lt = lines[m].trim();
                update_move_brace_depth(lt, &mut td, &mut t_started);
                if (t_started && td <= 0)
                    || (!t_started && !lt.starts_with("#[") && lt.ends_with(';'))
                {
                    break;
                }
                m += 1;
            }
            i = m.saturating_add(1).max(i + 1);
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
            update_move_brace_depth(lines[k], &mut depth, &mut started);
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

        // 1. Public Sui `init(ctx: &mut TxContext)` exposure
        if fn_low == "init" && params_low.contains("txcontext") {
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

        // 2. Missing `&AdminCap` / signer check on privileged Move entrypoints (exempt benign user self-setters)
        let is_user_self_setter = matches!(
            fn_low.as_str(),
            "set_profile"
                | "set_referrer"
                | "set_username"
                | "set_avatar"
                | "set_bio"
                | "set_nickname"
        );
        let is_privileged = !is_user_self_setter
            && (fn_low.starts_with("admin_")
                || fn_low.starts_with("set_")
                || matches!(
                    fn_low.as_str(),
                    "mint" | "burn" | "withdraw" | "emergency_withdraw" | "pause" | "upgrade"
                ));
        let has_cap_or_sender_auth = has_move_capability_param(&params)
            || body_low.contains("tx_context::sender")
            || body_low.contains("signer::address_of");
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

        // 2b. Unconstrained generic `Coin<T>` / `Balance<T>` missing `type_name::get<T>()` check
        if (params.contains("Coin<T>") || params.contains("Balance<T>"))
            && (body_low.contains("deposit")
                || body_low.contains("repay")
                || body_low.contains("mint"))
            && !body_low.contains("type_name::get")
            && !body_low.contains("type_of<")
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-WEB3-MOVE".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Move generic `Coin<T>`/`Balance<T>` entrypoint `{fn_name}` omits runtime `type_name::get<T>()` verification"
                ),
                rel_path: rel_path.into(),
                line: start_line,
                symbol: fn_name.clone(),
                sink_kind: SinkKind::AuthMutation,
                missing_guard: GuardKind::InputValidation,
                confidence: Confidence::Heuristic,
                remediation: "Validate generic coin type `T` against pool type witness via `type_name::get<T>() == pool.coin_type`.".into(),
            });
        }

        // 3. Unchecked zero-value coin/balance split (also honor `>= MIN_` / `> MIN_` assertions)
        let has_non_zero_bound = body_low.contains("> 0")
            || body_low.contains("!= 0")
            || body_low.contains("== 0")
            || body_low.contains(">= 1")
            || body_low.contains(">= 2")
            || body_low.contains(">= min")
            || body_low.contains("> min")
            || body_low.contains("< 1")
            || body_low.contains("assert!(amount >")
            || body_low.contains("assert!(amount >=");
        if (body_low.contains("coin::split(") || body_low.contains("balance::split("))
            && !has_non_zero_bound
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
