use crate::ast::{ImportRef, node_text};
use crate::taint::{MAX_AST_WALK_DEPTH, TAINT_XSS, has_taint_source_expr, is_call_sanitizer_for};
use smg_core::Language;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Per-file generic AST scope, receiver provenance, and sanitizer-binding table.
/// Prevents unscoped name collisions (`LocalMetricsRunner.query` vs SQL DB clients) and
/// flow-insensitively/flow-sensitively tracks variable sanitizer assignments across statements.
#[derive(Debug, Clone, Default)]
pub struct FileScopeTable {
    /// Class/struct declarations defined locally in this file (used to disambiguate benign helpers).
    pub local_classes: HashSet<String>,
    /// Variable -> inferred class/constructor/callee type name (`runner -> LocalMetricsRunner`).
    pub var_receivers: HashMap<String, String>,
    /// Import alias -> source module specifier (`runSql -> ./barrel`).
    pub import_aliases: HashMap<String, String>,
    /// Variables proven to hold XSS-sanitized HTML values (`clean = DOMPurify.sanitize(...)`),
    /// revoked automatically if reassigned or shadowed by an unsanitized parameter/assignment anywhere in the file.
    pub xss_sanitized_vars: HashSet<String>,
    /// Variables that have at least one unsanitized assignment or parameter binding in the file,
    /// preventing cross-function sanitizer leakage when two functions share a variable name.
    pub unsanitized_or_shadowed_vars: HashSet<String>,
}

/// Extracts per-file scope bindings and sanitizer provenance in a single bounded AST walk.
pub fn extract_file_scope(
    root: Node,
    src: &[u8],
    lang: Language,
    imports: &[ImportRef],
) -> FileScopeTable {
    let mut table = FileScopeTable::default();
    for imp in imports {
        if !imp.symbol_name.is_empty() && imp.symbol_name != "*" {
            table
                .import_aliases
                .insert(imp.symbol_name.clone(), imp.from_specifier.clone());
        }
    }
    walk_scope(root, src, lang, &mut table, 0);
    table
}

fn walk_scope(node: Node, src: &[u8], lang: Language, table: &mut FileScopeTable, depth: usize) {
    if depth >= MAX_AST_WALK_DEPTH {
        return;
    }
    let kind = node.kind();

    if matches!(
        kind,
        "class_declaration" | "class_definition" | "struct_item" | "type_declaration"
    ) && let Some(name_n) = node.child_by_field_name("name")
    {
        let cname = node_text(name_n, src).trim().to_string();
        if !cname.is_empty() {
            table.local_classes.insert(cname);
        }
    }

    // Track function parameter names so a parameter `html` in function B is never treated as
    // sanitized just because function A had `const html = DOMPurify.sanitize(...)`.
    if matches!(
        kind,
        "formal_parameters" | "parameters" | "parameter_list" | "function_parameters"
    ) {
        record_param_shadowing(node, src, table);
    }

    if matches!(
        kind,
        "variable_declarator" | "assignment_expression" | "assignment" | "short_var_declaration"
    ) {
        let lhs_node = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("left"));
        let rhs_node = node
            .child_by_field_name("value")
            .or_else(|| node.child_by_field_name("right"));

        if let (Some(lhs), Some(rhs)) = (lhs_node, rhs_node) {
            let var_name = node_text(lhs, src)
                .trim()
                .trim_start_matches('$')
                .split([':', ' '])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !var_name.is_empty() {
                update_binding_from_rhs(&var_name, rhs, src, lang, table);
            }
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_scope(ch, src, lang, table, depth + 1);
    }
}

fn record_param_shadowing(node: Node, src: &[u8], table: &mut FileScopeTable) {
    record_param_shadowing_depth(node, src, table, 0);
}

fn record_param_shadowing_depth(node: Node, src: &[u8], table: &mut FileScopeTable, depth: usize) {
    if depth >= MAX_AST_WALK_DEPTH {
        return;
    }
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        let name = node_text(node, src).trim();
        if !name.is_empty() && name != "_" {
            table.unsanitized_or_shadowed_vars.insert(name.to_string());
            table.xss_sanitized_vars.remove(name);
        }
        return;
    }
    if matches!(
        node.kind(),
        "type_annotation" | "generic_type" | "pointer_type" | "qualified_type" | "type"
    ) {
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        record_param_shadowing_depth(ch, src, table, depth + 1);
    }
}

fn update_binding_from_rhs(
    var_name: &str,
    rhs: Node,
    src: &[u8],
    _lang: Language,
    table: &mut FileScopeTable,
) {
    let rhs_txt = node_text(rhs, src).trim();
    if rhs.kind() == "new_expression"
        && let Some(ctor) = rhs.child_by_field_name("constructor")
    {
        let cname = node_text(ctor, src).trim().to_string();
        if !cname.is_empty() {
            table.var_receivers.insert(var_name.to_string(), cname);
        }
    } else if matches!(
        rhs.kind(),
        "call_expression" | "call" | "composite_literal" | "struct_expression" | "unary_expression"
    ) {
        // Also recognize Rust `ClassName::new()`, Go `&ClassName{}` / `NewClassName()`, and Python `ClassName()`
        let candidate = rhs_txt
            .trim_start_matches('&')
            .split(['(', '{', ':'])
            .next()
            .unwrap_or("")
            .trim();
        if !candidate.is_empty() && table.local_classes.contains(candidate) {
            table
                .var_receivers
                .insert(var_name.to_string(), candidate.to_string());
        }
    }

    let is_direct_xss_san = contains_xss_sanitizer_call(rhs, src)
        || (table.xss_sanitized_vars.contains(rhs_txt) && !has_taint_source_expr(rhs_txt));
    if is_direct_xss_san
        && !has_direct_tainted_unsanitized_wrap(rhs_txt)
        && !table.unsanitized_or_shadowed_vars.contains(var_name)
    {
        table.xss_sanitized_vars.insert(var_name.to_string());
    } else if rhs_txt.is_empty() || !table.xss_sanitized_vars.contains(rhs_txt) {
        table
            .unsanitized_or_shadowed_vars
            .insert(var_name.to_string());
        table.xss_sanitized_vars.remove(var_name);
    }
}

fn has_non_negated_xss_sanitizer(low: &str) -> bool {
    for needle in [
        "dompurify.sanitize(",
        "sanitizehtml(",
        "sanitize_html(",
        "escapehtml(",
    ] {
        for (pos, _) in low.match_indices(needle) {
            let prev = &low[..pos];
            if prev.ends_with("un") || prev.ends_with("de") || prev.ends_with("re") {
                continue;
            }
            if let Some(ch) = prev.chars().next_back()
                && (ch.is_ascii_alphanumeric() || ch == '_')
            {
                continue;
            }
            return true;
        }
    }
    false
}

fn contains_xss_sanitizer_call(node: Node, src: &[u8]) -> bool {
    let k = node.kind();
    if matches!(k, "call_expression" | "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let full = node_text(node, src).trim();
        if is_call_sanitizer_for(ftxt, full, TAINT_XSS)
            || ftxt.to_ascii_lowercase().contains("dompurify")
        {
            return true;
        }
    }
    let low = node_text(node, src).to_ascii_lowercase();
    has_non_negated_xss_sanitizer(&low)
}

fn has_direct_tainted_unsanitized_wrap(rhs_txt: &str) -> bool {
    let low = rhs_txt.to_ascii_lowercase();
    // E.g. `` `${DOMPurify.sanitize(a)}${req.query.b}` `` concatenates raw untrusted tail
    (low.contains("${") || rhs_txt.contains('+')) && has_taint_source_expr(rhs_txt)
}

/// Checks if a React `dangerouslySetInnerHTML={{ __html: expr }}` attribute passes
/// either an inline sanitizer call or a variable tracked as sanitized in [`FileScopeTable`].
pub fn is_safe_jsx_html_attribute(attr_text: &str, scope: &FileScopeTable) -> bool {
    let low = attr_text.to_ascii_lowercase();
    if low.contains("dompurify")
        || low.contains("sanitizehtml")
        || low.contains("sanitize_html")
        || low.contains("escapehtml")
    {
        return true;
    }
    if let Some(idx) = attr_text.find("__html") {
        let after = attr_text[idx + 6..]
            .trim_start()
            .trim_start_matches(':')
            .trim();
        let expr = after.trim_end_matches('}').trim();
        // Match plain identifier (`__html: clean`) backed by prior sanitizer assignment.
        if !expr.is_empty()
            && expr
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
            && scope.xss_sanitized_vars.contains(expr)
        {
            return true;
        }
    }
    false
}

/// Returns true when a `MethodCall` like `runner.query(...)` resolves strictly to a benign local
/// user class rather than SQL/DB libraries (`db`, `tx`, `prisma`, `knex`, `pool`, etc.).
pub fn is_benign_local_receiver(call_expr: &str, scope: &FileScopeTable) -> bool {
    let Some((recv, _)) = call_expr.trim().split_once('.') else {
        return false;
    };
    let r = recv.trim();
    if let Some(ty) = scope.var_receivers.get(r)
        && scope.local_classes.contains(ty)
    {
        let ty_low = ty.to_ascii_lowercase();
        let looks_like_db = ty_low.contains("db")
            || ty_low.contains("sql")
            || ty_low.contains("repo")
            || ty_low.contains("dao")
            || ty_low.contains("client")
            || ty_low.contains("prisma")
            || ty_low.contains("knex");
        return !looks_like_db;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_ts_scope(code: &str) -> FileScopeTable {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = p.parse(code, None).unwrap();
        extract_file_scope(tree.root_node(), code.as_bytes(), Language::TypeScript, &[])
    }

    #[test]
    fn test_scope_tracks_xss_sanitizer_and_revocation() {
        let code = r#"
import DOMPurify from 'dompurify';
function renderBio(req: any) {
    const clean = DOMPurify.sanitize(String(req.query.bio || ''));
    let mutable = DOMPurify.sanitize(String(req.query.alt || ''));
    mutable = req.query.raw;
    return [clean, mutable];
}
"#;
        let scope = parse_ts_scope(code);
        assert!(scope.xss_sanitized_vars.contains("clean"));
        assert!(!scope.xss_sanitized_vars.contains("mutable"));
        assert!(is_safe_jsx_html_attribute(
            "dangerouslySetInnerHTML={{ __html: clean }}",
            &scope
        ));
        assert!(!is_safe_jsx_html_attribute(
            "dangerouslySetInnerHTML={{ __html: mutable }}",
            &scope
        ));
    }

    #[test]
    fn test_scope_disambiguates_benign_local_class_receiver() {
        let code = r#"
export class LocalMetricsRunner {
    query(metricName: string): number { return metricName.length; }
}
const runner = new LocalMetricsRunner();
runner.query('cpu');
"#;
        let scope = parse_ts_scope(code);
        assert!(scope.local_classes.contains("LocalMetricsRunner"));
        assert!(is_benign_local_receiver("runner.query", &scope));
    }

    #[test]
    fn test_scope_prevents_cross_function_parameter_shadowing_leak() {
        let code = r#"
import DOMPurify from 'dompurify';
function safeView(raw: string) {
    const html = DOMPurify.sanitize(raw);
    return html;
}
function unsafeView(html: string) {
    return html;
}
"#;
        let scope = parse_ts_scope(code);
        assert!(
            !scope.xss_sanitized_vars.contains("html"),
            "Parameter `html` in unsafeView must revoke file-global xss_sanitized_vars entry"
        );
    }
}
