pub mod bash;
pub mod c_cpp;
pub mod csharp;
pub mod dart;
pub mod hcl;
pub mod java;
pub mod kotlin;
pub mod php;
pub mod ruby;
pub mod swift;

use crate::ast::{
    Confidence, GuardKind, ImportRef, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    classify_guards, classify_sink, contains_guard_pattern, is_auth_guard_ident,
    is_lock_guard_ident, node_text, strip_comments,
};
use crate::taint::{
    TAINT_ALL, TAINT_CMD, TAINT_PATH, TAINT_SQL, TAINT_SSRF, TAINT_XSS, has_bearer_header_expr,
    has_cookie_session_expr, has_csrf_exempt_expr, has_csrf_guard_expr, has_ownership_filter,
    has_resource_id_expr,
};
use regex::Regex;
use smg_core::{Language, ShellMindGuardConfig};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tree_sitter::Node;

/// Declarative per-ecosystem pattern profile shared by all Phase 8 Tree-sitter extractors.
pub(crate) struct LangProfile {
    pub id_prefix: &'static str,
    pub taint_sources: &'static [&'static str],
    pub tainted_param_markers: &'static [&'static str],
    pub sql_sinks: &'static [&'static str],
    pub sql_sanitizers: &'static [&'static str],
    pub cmd_sinks: &'static [&'static str],
    pub cmd_sanitizers: &'static [&'static str],
    pub path_sinks: &'static [&'static str],
    pub path_sanitizers: &'static [&'static str],
    pub ssrf_sinks: &'static [&'static str],
    pub ssrf_sanitizers: &'static [&'static str],
    pub xss_sinks: &'static [&'static str],
    pub xss_sanitizers: &'static [&'static str],
    pub ownership_markers: &'static [&'static str],
    pub db_write_sinks: &'static [&'static str],
    pub db_crud_markers: &'static [&'static str],
    pub extra_auth_guards: &'static [&'static str],
    pub extra_lock_guards: &'static [&'static str],
}

/// Returns the Tree-sitter grammar for any Phase 8 language.
pub fn ts_language_for(lang: Language) -> Option<tree_sitter::Language> {
    match lang {
        Language::Php => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        Language::Java => Some(tree_sitter_java::LANGUAGE.into()),
        Language::CSharp => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        Language::Kotlin => Some(tree_sitter_kotlin_ng::LANGUAGE.into()),
        Language::Swift => Some(tree_sitter_swift::LANGUAGE.into()),
        Language::Dart => Some(tree_sitter_dart::LANGUAGE.into()),
        Language::C => Some(tree_sitter_c::LANGUAGE.into()),
        Language::Cpp => Some(tree_sitter_cpp::LANGUAGE.into()),
        Language::Ruby => Some(tree_sitter_ruby::LANGUAGE.into()),
        Language::Bash => Some(tree_sitter_bash::LANGUAGE.into()),
        Language::Hcl => Some(tree_sitter_hcl::LANGUAGE.into()),
        Language::TypeScript
        | Language::JavaScript
        | Language::Rust
        | Language::Python
        | Language::Go
        | Language::Sql
        | Language::Config
        | Language::Manifest => None,
    }
}

/// Dispatches AST extraction for Phase 8 modular language extractors.
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract_extension_language(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    cfg: &ShellMindGuardConfig,
    file_middleware_guards: &mut HashSet<GuardKind>,
    imports: &mut Vec<ImportRef>,
    symbols: &mut Vec<SymbolInfo>,
    route_prefixes: &mut Vec<String>,
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    let mut ctx = ExtractContext {
        src,
        rel_path,
        cfg,
        file_middleware_guards,
        imports,
        symbols,
        route_prefixes,
        static_findings,
    };
    match lang {
        Language::Php => php::extract(root, &mut ctx),
        Language::Java => java::extract(root, &mut ctx),
        Language::CSharp => csharp::extract(root, &mut ctx),
        Language::Kotlin => kotlin::extract(root, &mut ctx),
        Language::Swift => swift::extract(root, &mut ctx),
        Language::Dart => dart::extract(root, &mut ctx),
        Language::C | Language::Cpp => c_cpp::extract(root, &mut ctx),
        Language::Ruby => ruby::extract(root, &mut ctx),
        Language::Bash => bash::extract(root, &mut ctx),
        Language::Hcl => hcl::extract(root, &mut ctx),
        Language::TypeScript
        | Language::JavaScript
        | Language::Rust
        | Language::Python
        | Language::Go
        | Language::Sql
        | Language::Config
        | Language::Manifest => {}
    }
}

pub(crate) struct ExtractContext<'a> {
    pub src: &'a [u8],
    pub rel_path: &'a str,
    pub cfg: &'a ShellMindGuardConfig,
    pub file_middleware_guards: &'a mut HashSet<GuardKind>,
    pub imports: &'a mut Vec<ImportRef>,
    pub symbols: &'a mut Vec<SymbolInfo>,
    pub route_prefixes: &'a mut Vec<String>,
    pub static_findings: &'a mut Vec<LocalStaticFinding>,
}

fn ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").expect("valid ident regex"))
}

fn php_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").expect("valid php var regex"))
}

fn sql_verb_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?is)\b(?:SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM)\b",
        )
        .expect("valid sql verb regex")
    })
}

pub(crate) fn strip_quotes(s: &str) -> String {
    s.trim()
        .trim_matches(|ch| ch == '"' || ch == '\'' || ch == '`')
        .to_string()
}

pub(crate) fn join_route_prefix(prefix: &str, sub: &str) -> String {
    let p = prefix.trim();
    let s = sub.trim();
    if p.is_empty() || p == "/" {
        if s.starts_with('/') {
            return s.to_string();
        }
        return if s.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", s)
        };
    }
    let clean_p = format!("/{}", p.trim_matches('/'));
    let clean_s = s.trim_matches('/');
    if clean_s.is_empty() {
        clean_p
    } else {
        format!("{}/{}", clean_p, clean_s)
    }
}

pub(crate) fn find_first_string_literal(node: Node, src: &[u8]) -> Option<String> {
    let k = node.kind();
    if k.contains("string") && !k.contains("interpolated") && !k.contains("template") {
        let raw = node_text(node, src).trim();
        let unq = strip_quotes(raw);
        if !unq.is_empty() {
            return Some(unq);
        }
    }
    if k == "string_literal" || k == "line_string_literal" {
        let raw = node_text(node, src).trim();
        let unq = strip_quotes(raw);
        if !unq.is_empty() {
            return Some(unq);
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(found) = find_first_string_literal(ch, src) {
            return Some(found);
        }
    }
    None
}

/// Collects call identifiers across all Phase 8 Tree-sitter grammar call node variants.
pub(crate) fn collect_calls_generic(node: Node, src: &[u8], out: &mut Vec<String>) {
    collect_calls_generic_depth(node, src, out, 0);
}

fn collect_calls_generic_depth(node: Node, src: &[u8], out: &mut Vec<String>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    let callee_raw: Option<&str> = match k {
        "call_expression" | "function_call_expression" | "invocation_expression" => {
            if let Some(f) = node.child_by_field_name("function") {
                Some(node_text(f, src))
            } else {
                // Kotlin / Swift `call_expression` has callee as first named child
                let mut c = node.walk();
                node.named_children(&mut c)
                    .next()
                    .map(|n| node_text(n, src))
            }
        }
        "method_invocation" => node.child_by_field_name("name").map(|n| node_text(n, src)),
        "member_call_expression" | "scoped_call_expression" => {
            node.child_by_field_name("name").map(|n| node_text(n, src))
        }
        "call" => node
            .child_by_field_name("method")
            .map(|n| node_text(n, src)),
        "object_creation_expression" => node.child_by_field_name("type").map(|n| node_text(n, src)),
        _ => None,
    };

    if let Some(raw) = callee_raw {
        let cleaned = raw.trim();
        let short = cleaned
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(cleaned)
            .rsplit("->")
            .next()
            .unwrap_or(cleaned)
            .trim();
        if !short.is_empty()
            && short.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !out.iter().any(|existing| existing == short)
        {
            out.push(short.to_string());
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_calls_generic_depth(ch, src, out, depth + 1);
    }
}

pub(crate) fn has_auth_opt_out_annotation(text: &str) -> bool {
    let low = crate::taint::strip_comments_and_non_attr_strings(text).to_ascii_lowercase();
    low.contains("[allowanonymous]")
        || low.contains("@permitall")
        || low.contains("@allowanonymous")
}

pub(crate) fn is_non_route_receiver(ftxt: &str) -> bool {
    let recv = ftxt
        .rsplit_once('.')
        .or_else(|| ftxt.rsplit_once("->"))
        .map(|(r, _)| r.rsplit(['.', ':', '>', ' ']).next().unwrap_or(r).trim())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        recv.as_str(),
        "map"
            | "hashmap"
            | "config"
            | "cfg"
            | "settings"
            | "dict"
            | "cache"
            | "env"
            | "prefs"
            | "preferences"
            | "headers"
            | "query"
            | "params"
            | "json"
            | "bundle"
            | "attributes"
            | "session"
            | "store"
    )
}

pub(crate) fn detect_text_guards(
    text: &str,
    cfg: &ShellMindGuardConfig,
    profile: &LangProfile,
) -> HashSet<GuardKind> {
    let mut guards = classify_guards(text, cfg);
    let code_only = crate::taint::strip_comments_and_non_attr_strings(text);
    let low = code_only.to_ascii_lowercase();

    // Respect explicit opt-outs like AllowAnonymous / PermitAll
    if has_auth_opt_out_annotation(text) {
        guards.remove(&GuardKind::Auth);
        return guards;
    }

    for marker in profile.extra_auth_guards {
        if contains_guard_pattern(&low, &marker.to_ascii_lowercase()) {
            guards.insert(GuardKind::Auth);
        }
    }
    for marker in profile.extra_lock_guards {
        if low.contains(&marker.to_ascii_lowercase()) {
            guards.insert(GuardKind::TxLock);
        }
    }

    // Standard call/ident guard matching
    for m in ident_re().find_iter(&code_only) {
        let ident = m.as_str();
        if is_auth_guard_ident(ident, cfg) {
            guards.insert(GuardKind::Auth);
        }
        if is_lock_guard_ident(ident, cfg) {
            guards.insert(GuardKind::TxLock);
        }
    }

    if has_csrf_guard_expr(&code_only) {
        guards.insert(GuardKind::CsrfProtection);
    }
    guards
}

pub(crate) fn classify_sink_with_profile(
    name: &str,
    body: &str,
    profile: &LangProfile,
) -> Option<SinkKind> {
    if let Some(base) = classify_sink(name, body) {
        return Some(base);
    }
    let low_name = name.to_ascii_lowercase();
    let low_body = strip_comments(body).to_ascii_lowercase();

    if (low_name.contains("charge") || low_name.contains("payment") || low_name.contains("refund"))
        && (low_body.contains("amount") || low_body.contains("currency"))
    {
        return Some(SinkKind::PaymentMutation);
    }
    if (low_name.contains("withdraw")
        || low_name.contains("debit")
        || low_name.contains("transfer"))
        && (low_body.contains("balance")
            || low_body.contains("save")
            || low_body.contains("update"))
    {
        return Some(SinkKind::BalanceUpdate);
    }
    if profile
        .db_write_sinks
        .iter()
        .any(|pat| low_body.contains(&pat.to_ascii_lowercase()))
    {
        return Some(SinkKind::SqlWrite);
    }
    None
}

fn contains_any_ci(haystack_low: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|n| haystack_low.contains(&n.to_ascii_lowercase()))
}

fn contains_word_call(haystack_low: &str, call_marker: &str) -> bool {
    let bytes = haystack_low.as_bytes();
    let mut off = 0usize;
    while let Some(rel) = haystack_low[off..].find(call_marker) {
        let pos = off + rel;
        let prev_ok =
            pos == 0 || (!bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_');
        if prev_ok {
            return true;
        }
        off = pos + 1;
    }
    false
}

fn stmt_sanitizer_mask(stmt_code: &str, profile: &LangProfile) -> u8 {
    let low = stmt_code.to_ascii_lowercase();
    let mut mask = 0u8;

    // Universal scalar casts neutralize injection/path/SSRF/XSS completely (word-bounded so `POINT(` never matches `int(`)
    let filter_var_strict = low.contains("filter_var(")
        && (low.contains("filter_validate_int")
            || low.contains("filter_validate_float")
            || low.contains("filter_validate_boolean"));
    if low.contains("intval(")
        || low.contains("integer.parseint(")
        || low.contains("long.parselong(")
        || low.contains("uuid.fromstring(")
        || low.contains("int.parse(")
        || low.contains("int.tryparse(")
        || low.contains("guid.parse(")
        || low.contains(".tointornull(")
        || low.contains(".toint(")
        || contains_word_call(&low, "int(")
        || contains_word_call(&low, "atoi(")
        || contains_word_call(&low, "strtol(")
        || contains_word_call(&low, "ctype_digit(")
        || filter_var_strict
    {
        return TAINT_ALL;
    }

    if contains_any_ci(&low, profile.sql_sanitizers) {
        mask |= TAINT_SQL;
    }
    if contains_any_ci(&low, profile.cmd_sanitizers) {
        mask |= TAINT_CMD;
    }
    if contains_any_ci(&low, profile.path_sanitizers) {
        mask |= TAINT_PATH;
    }
    if contains_any_ci(&low, profile.ssrf_sanitizers) {
        mask |= TAINT_SSRF;
    }
    if contains_any_ci(&low, profile.xss_sanitizers) {
        mask |= TAINT_XSS;
    }
    mask
}

fn expr_var_taint(expr: &str, tainted_vars: &HashMap<String, u8>) -> u8 {
    let mut mask = 0u8;
    for cap in php_var_re().captures_iter(expr) {
        if let Some(m) = tainted_vars.get(&cap[1]) {
            mask |= *m;
        }
    }
    for m in ident_re().find_iter(expr) {
        if let Some(tm) = tainted_vars.get(m.as_str()) {
            mask |= *tm;
        }
    }
    mask
}

fn expr_direct_source_mask(expr: &str, profile: &LangProfile, extra_sources: &[&str]) -> u8 {
    let low = expr.to_ascii_lowercase();
    let is_source =
        contains_any_ci(&low, profile.taint_sources) || contains_any_ci(&low, extra_sources);
    if is_source {
        TAINT_ALL & !stmt_sanitizer_mask(expr, profile)
    } else {
        0
    }
}

fn has_quoted_dollar_interp(stmt: &str) -> bool {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut prev = '\0';
    let mut prev2 = '\0';
    for ch in stmt.chars() {
        if escaped {
            escaped = false;
            prev2 = prev;
            prev = ch;
            continue;
        }
        if ch == '\\' && in_quote.is_some() {
            escaped = true;
            prev2 = prev;
            prev = ch;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            } else if ch == '$' && (q == '"' || q == '\'') {
                return true;
            }
        } else if ch == '"' || ch == '\'' {
            if prev == '$' || (prev2 == '$' && prev == '@') {
                return true;
            }
            in_quote = Some(ch);
        }
        prev2 = prev;
        prev = ch;
    }
    false
}

fn is_dynamic_sql_stmt(stmt: &str, has_sql_var_taint: bool) -> bool {
    let has_concat_or_interp = stmt.contains('+')
        || stmt.contains(" . ")
        || stmt.contains(".$")
        || stmt.contains("\\(")
        || stmt.contains("#{")
        || stmt.contains("sprintf")
        || stmt.contains("snprintf")
        || stmt.contains("string.format")
        || stmt.contains("fmt::format")
        || has_quoted_dollar_interp(stmt);
    let has_param_placeholder = stmt.contains("?")
        || stmt.contains("@p0")
        || stmt.contains("@id")
        || stmt.contains(":id")
        || stmt.contains("$1");
    if has_param_placeholder && !has_concat_or_interp {
        return false;
    }
    (sql_verb_re().is_match(stmt) || has_sql_var_taint) && has_concat_or_interp
}

fn is_static_string_only_call(stmt: &str) -> bool {
    // Reject calls whose arguments are purely static literals (e.g. `system("ls -la")`, `exec("git status")`)
    let trimmed_stmt = stmt.trim();
    if trimmed_stmt.starts_with("echo ") || trimmed_stmt.starts_with("print ") {
        return false;
    }
    let Some(open) = stmt.find('(') else {
        return false;
    };
    let before = stmt[..open].trim();
    if before.contains(char::is_whitespace) || before.contains('$') || before.contains('[') {
        return false;
    }
    let args = &stmt[open + 1..];
    let trimmed = args
        .trim()
        .trim_end_matches(';')
        .trim_end_matches(')')
        .trim();
    if trimmed.is_empty() {
        return true;
    }
    let has_interp = trimmed.contains('$')
        || trimmed.contains('{')
        || trimmed.contains("\\(")
        || trimmed.contains('+');
    if trimmed.starts_with('"') && trimmed.ends_with('"') && !has_interp {
        return true;
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && !has_interp && !trimmed.contains('.')
    {
        return true;
    }
    false
}

/// Evaluates an extracted function/method/handler body across guards, sinks, IDOR, CSRF, and taint.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_analyzed_symbol(
    ctx: &ExtractContext<'_>,
    profile: &LangProfile,
    sym_id: String,
    name: String,
    kind: SymbolKind,
    line_start: usize,
    line_end: usize,
    attr_text: &str,
    params_text: &str,
    body_node: Option<Node>,
    full_node: Node,
    route_path: Option<String>,
    param_names: &[String],
) -> SymbolInfo {
    let fn_code = strip_comments(node_text(full_node, ctx.src));
    let body_code = body_node
        .map(|b| strip_comments(node_text(b, ctx.src)))
        .unwrap_or_else(|| fn_code.clone());
    let combined_guard_text = format!("{}\n{}", attr_text, body_code);

    let mut guards = detect_text_guards(&combined_guard_text, ctx.cfg, profile);
    // Attribute-only guards should always grant Auth/TxLock if declared on controller/method
    guards.extend(detect_text_guards(attr_text, ctx.cfg, profile));
    if kind == SymbolKind::Route {
        guards.extend(ctx.file_middleware_guards.iter().copied());
    }

    // Ownership filter check for IDOR (active non-literal principals + scoped query filter)
    let body_active_low =
        crate::taint::strip_comments_and_non_attr_strings(&body_code).to_ascii_lowercase();
    let body_low = body_code.to_ascii_lowercase();
    if has_ownership_filter(&body_code)
        || contains_any_ci(&body_active_low, profile.ownership_markers)
    {
        guards.insert(GuardKind::OwnershipCheck);
    }

    let mut calls = Vec::new();
    collect_calls_generic(full_node, ctx.src, &mut calls);

    let sink_kind = classify_sink_with_profile(&name, &body_code, profile);
    let mut sym = SymbolInfo::base(
        sym_id,
        ctx.rel_path,
        name.clone(),
        kind,
        sink_kind,
        line_start,
        line_end,
        guards,
        calls.clone(),
        route_path.clone(),
    );

    sym.has_cookie_session_auth = has_cookie_session_expr(&fn_code);
    sym.has_bearer_header_auth = has_bearer_header_expr(&fn_code);
    sym.csrf_exempt = has_csrf_exempt_expr(&combined_guard_text);
    if has_resource_id_expr(&fn_code, route_path.as_deref())
        || params_text.contains("@PathVariable")
        || params_text.contains("[FromRoute]")
    {
        sym.has_resource_id = true;
    }
    if contains_any_ci(&body_low, profile.db_crud_markers) || sink_kind == Some(SinkKind::SqlWrite)
    {
        sym.has_db_crud_sink = true;
        sym.db_crud_line = Some(line_start);
    }

    // Intra-procedural line-by-line taint & sanitizer propagation
    let mut tainted_vars: HashMap<String, u8> = HashMap::new();
    let mut param_vars: HashSet<String> = param_names.iter().cloned().collect();

    // Seed parameters annotated with explicit HTTP input attributes/extractors
    let params_low = params_text.to_ascii_lowercase();
    for p in param_names {
        let p_low = p.to_ascii_lowercase();
        let explicit_tainted = profile.tainted_param_markers.iter().any(|mk| {
            let mkl = mk.to_ascii_lowercase();
            params_low.contains(&format!("{} {}", mkl, p_low))
                || params_low.contains(&format!("{}\n{}", mkl, p_low))
                || params_low.contains(&mkl) && route_path.is_some()
        });
        if explicit_tainted
            || p_low == "argv"
            || (route_path.is_some()
                && matches!(
                    p_low.as_str(),
                    "id" | "cmd" | "url" | "path" | "file" | "query" | "input" | "name" | "payload"
                ))
        {
            tainted_vars.insert(p.clone(), TAINT_ALL);
            sym.has_taint_source = true;
        } else {
            param_vars.insert(p.clone());
        }
    }

    if contains_any_ci(&fn_code.to_ascii_lowercase(), profile.taint_sources) {
        sym.has_taint_source = true;
    }

    let lines: Vec<&str> = body_code.lines().collect();
    for (idx, raw_line) in lines.iter().enumerate() {
        let stmt = raw_line.trim();
        if stmt.is_empty() {
            continue;
        }
        let abs_line = body_node
            .map(|b| b.start_position().row + 1 + idx)
            .unwrap_or(line_start + idx);
        let stmt_low = stmt.to_ascii_lowercase();

        // 1. Evaluate assignment RHS -> LHS variable taint mask / caller param flow
        if let Some((lhs_raw, rhs, is_compound)) = split_assignment(stmt)
            && let Some(lhs_var) = extract_assigned_ident(lhs_raw)
        {
            let mut rhs_mask = expr_direct_source_mask(rhs, profile, &[]);
            rhs_mask |= expr_var_taint(rhs, &tainted_vars);
            let rhs_san = stmt_sanitizer_mask(rhs, profile);
            let net = rhs_mask & !rhs_san;
            if is_compound {
                if net != 0 {
                    *tainted_vars.entry(lhs_var).or_insert(0) |= net;
                } else {
                    let rhs_uses_param = param_vars
                        .iter()
                        .any(|p| ident_re().find_iter(rhs).any(|m| m.as_str() == p));
                    if rhs_uses_param && rhs_san == 0 {
                        param_vars.insert(lhs_var);
                    }
                }
            } else if net != 0 {
                tainted_vars.insert(lhs_var, net);
            } else {
                tainted_vars.remove(&lhs_var);
                let rhs_uses_param = param_vars
                    .iter()
                    .any(|p| ident_re().find_iter(rhs).any(|m| m.as_str() == p));
                if rhs_uses_param && rhs_san == 0 {
                    param_vars.insert(lhs_var);
                } else {
                    param_vars.remove(&lhs_var);
                }
            }
        }

        let stmt_san = stmt_sanitizer_mask(stmt, profile);
        let direct_src = expr_direct_source_mask(stmt, profile, &[]);
        let var_taint = expr_var_taint(stmt, &tainted_vars);
        let active_taint = (direct_src | var_taint) & !stmt_san;

        let param_in_stmt = param_vars
            .iter()
            .any(|p| ident_re().find_iter(stmt).any(|m| m.as_str() == p));

        // 2. Check each of the 5 taint sink classes (with strict sanitizer & literal disproof)
        type TaintSinkSpec<'s> = (
            u8,
            &'s [&'s str],
            &'static str,
            &'static str,
            SinkKind,
            GuardKind,
            &'static str,
        );
        let checks: &[TaintSinkSpec<'_>] = &[
            (
                TAINT_SQL,
                profile.sql_sinks,
                "SMG-SQLI-001",
                "CRITICAL",
                SinkKind::SqlInjection,
                GuardKind::SqlSanitizer,
                "Use parameterized queries or prepared statements instead of interpolating/concatenating untrusted input into SQL.",
            ),
            (
                TAINT_CMD,
                profile.cmd_sinks,
                "SMG-CMDI-001",
                "CRITICAL",
                SinkKind::CommandInjection,
                GuardKind::CmdSanitizer,
                "Avoid shell execution with dynamic strings; pass fixed commands with an argument array or strict allowlist.",
            ),
            (
                TAINT_PATH,
                profile.path_sinks,
                "SMG-PATH-001",
                "HIGH",
                SinkKind::PathTraversal,
                GuardKind::PathSanitizer,
                "Canonicalize paths, extract basename, and enforce a strict base-directory prefix check before file I/O.",
            ),
            (
                TAINT_SSRF,
                profile.ssrf_sinks,
                "SMG-SSRF-001",
                "HIGH",
                SinkKind::Ssrf,
                GuardKind::SsrfSanitizer,
                "Validate outbound URLs against an explicit scheme/hostname allowlist and block private/loopback IP ranges.",
            ),
            (
                TAINT_XSS,
                profile.xss_sinks,
                "SMG-XSS-001",
                "HIGH",
                SinkKind::Xss,
                GuardKind::XssSanitizer,
                "HTML-escape untrusted values before writing raw markup into responses.",
            ),
        ];

        for &(bit, sinks, rule_id, sev, skind, mguard, rem) in checks {
            if !contains_any_ci(&stmt_low, sinks) {
                continue;
            }
            if (stmt_san & bit) != 0 {
                continue;
            }
            if is_static_string_only_call(stmt) {
                continue;
            }
            if bit == TAINT_SQL && !is_dynamic_sql_stmt(stmt, (active_taint & TAINT_SQL) != 0) {
                continue;
            }
            if (active_taint & bit) != 0 {
                sym.local_taint_hits.push(LocalStaticFinding {
                    rule_id: rule_id.to_string(),
                    severity: sev.to_string(),
                    title: format!(
                        "{} ({}) via untrusted input in `{}`",
                        rule_id, profile.id_prefix, name
                    ),
                    rel_path: ctx.rel_path.to_string(),
                    line: abs_line,
                    symbol: name.clone(),
                    sink_kind: skind,
                    missing_guard: mguard,
                    confidence: Confidence::Confirmed,
                    remediation: rem.to_string(),
                });
            } else if param_in_stmt {
                sym.param_sinks.push(LocalStaticFinding {
                    rule_id: rule_id.to_string(),
                    severity: sev.to_string(),
                    title: format!(
                        "{} ({}) via caller-supplied parameter in `{}`",
                        rule_id, profile.id_prefix, name
                    ),
                    rel_path: ctx.rel_path.to_string(),
                    line: abs_line,
                    symbol: name.clone(),
                    sink_kind: skind,
                    missing_guard: mguard,
                    confidence: Confidence::Heuristic,
                    remediation: rem.to_string(),
                });
            }
        }

        // 3. Record cross-file tainted callee forwarding when a call receives a tainted arg/source
        for c in &calls {
            if c == &name {
                continue;
            }
            if let Some(after) = find_call_args_slice(stmt, c) {
                let call_taint = (expr_direct_source_mask(after, profile, &[])
                    | expr_var_taint(after, &tainted_vars))
                    & !stmt_san;
                if call_taint != 0 {
                    if !sym.tainted_calls.iter().any(|x| x == c) {
                        sym.tainted_calls.push(c.clone());
                    }
                    *sym.tainted_call_masks.entry(c.clone()).or_insert(0) |= call_taint;
                } else if param_vars
                    .iter()
                    .any(|p| ident_re().find_iter(after).any(|m| m.as_str() == p))
                    && !sym.param_forwarding_calls.iter().any(|x| x == c)
                {
                    sym.param_forwarding_calls.push(c.clone());
                }
            }
        }
    }

    sym
}

fn find_call_args_slice<'a>(stmt: &'a str, callee: &str) -> Option<&'a str> {
    let call_pat = format!("{}(", callee);
    if let Some(pos) = stmt.find(&call_pat) {
        return Some(&stmt[pos + call_pat.len()..]);
    }
    let space_pat = format!("{} ", callee);
    let bytes = stmt.as_bytes();
    let mut offset = 0usize;
    while let Some(rel) = stmt[offset..].find(&space_pat) {
        let pos = offset + rel;
        let prev_ok = pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_';
        if prev_ok {
            return Some(&stmt[pos + space_pat.len()..]);
        }
        offset = pos + callee.len();
    }
    None
}

fn split_assignment(stmt: &str) -> Option<(&str, &str, bool)> {
    // Avoid `==`, `!=`, `<=`, `>=`, `=>`; detect compound `+=`, `.=`, `|=`
    let bytes = stmt.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { 0 };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            if matches!(prev, b'=' | b'!' | b'<' | b'>') || matches!(next, b'=' | b'>') {
                continue;
            }
            let is_compound = matches!(prev, b'+' | b'.' | b'|');
            let lhs_end = if is_compound { i - 1 } else { i };
            return Some((&stmt[..lhs_end], &stmt[i + 1..], is_compound));
        }
    }
    None
}

fn extract_assigned_ident(lhs: &str) -> Option<String> {
    let trimmed = lhs.trim().trim_end_matches(':');
    let last_tok = trimmed
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
        .rfind(|s| !s.is_empty())?;
    let cleaned = last_tok.trim_start_matches('$');
    if cleaned.is_empty() || cleaned.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        None
    } else {
        Some(cleaned.to_string())
    }
}

pub(crate) fn extract_param_idents(params_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let inner = params_text
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    for part in inner.split(',') {
        let before_eq = part.split('=').next().unwrap_or(part).trim();
        // Support both `Type name` (C#/Java/C++) and `name: Type` (Kotlin/Swift/TypeScript)
        let seg = if !before_eq.contains("::") && before_eq.contains(':') {
            before_eq.split(':').next().unwrap_or(before_eq).trim()
        } else {
            before_eq
        };
        if let Some(last) = seg
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
            .rfind(|s| !s.is_empty())
        {
            let name = last.trim_start_matches('$');
            if !name.is_empty()
                && !matches!(
                    name,
                    "int"
                        | "string"
                        | "String"
                        | "Int"
                        | "bool"
                        | "Bool"
                        | "void"
                        | "Request"
                        | "Response"
                        | "CancellationToken"
                )
                && !out.iter().any(|x| x == name)
            {
                out.push(name.to_string());
            }
        }
    }
    out
}

pub(crate) fn http_verb_from_ident(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "get" | "httpget" | "getmapping" | "mapget" => Some("GET"),
        "post" | "httppost" | "postmapping" | "mappost" => Some("POST"),
        "put" | "httpput" | "putmapping" | "mapput" => Some("PUT"),
        "delete" | "httpdelete" | "deletemapping" | "mapdelete" => Some("DELETE"),
        "patch" | "httppatch" | "patchmapping" | "mappatch" => Some("PATCH"),
        "request" | "requestmapping" | "any" => Some("ANY"),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
