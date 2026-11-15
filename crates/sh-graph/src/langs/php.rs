use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix, strip_quotes,
};
use crate::ast::{GuardKind, ImportRef, SymbolInfo, SymbolKind, node_text, strip_comments};
use std::collections::HashSet;
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "php",
    taint_sources: &[
        "$_get",
        "$_post",
        "$_request",
        "$_cookie",
        "$_server",
        "$request->input(",
        "$request->query(",
        "$request->post(",
        "$request->get(",
        "$request->all(",
        "php://input",
    ],
    tainted_param_markers: &["Request "],
    sql_sinks: &[
        "->query(",
        "mysqli_query(",
        "db::select(",
        "db::statement(",
        "->whereraw(",
        "->selectraw(",
        "pg_query(",
    ],
    sql_sanitizers: &[
        "->prepare(",
        "mysqli_prepare(",
        "prepare(",
        "bindparam(",
        "bindvalue(",
        "escape_string(",
    ],
    cmd_sinks: &[
        "exec(",
        "shell_exec(",
        "system(",
        "passthru(",
        "proc_open(",
        "popen(",
    ],
    cmd_sanitizers: &["escapeshellarg(", "escapeshellcmd("],
    path_sinks: &[
        "file_get_contents(",
        "fopen(",
        "readfile(",
        "unlink(",
        "include(",
        "require(",
    ],
    path_sanitizers: &["basename(", "realpath("],
    ssrf_sinks: &[
        "curl_exec(",
        "curl_init(",
        "http::get(",
        "http::post(",
        "getasync(",
    ],
    ssrf_sanitizers: &["validateurl", "allowedhosts", "filter_var("],
    xss_sinks: &["echo ", "print "],
    xss_sanitizers: &["htmlspecialchars(", "htmlentities(", "strip_tags(", " e("],
    ownership_markers: &[
        "auth::id(",
        "$request->user(",
        "user_id",
        "owner_id",
        "tenant_id",
    ],
    db_write_sinks: &[
        "db::insert(",
        "db::update(",
        "db::delete(",
        "->save(",
        "->decrement(",
        "->increment(",
        "->exec(",
    ],
    db_crud_markers: &[
        "db::",
        "$pdo->",
        "->find(",
        "->findorfail(",
        "->where(",
        "->update(",
        "->delete(",
    ],
    extra_auth_guards: &[
        "middleware('auth",
        "middleware(\"auth",
        "#[isgranted",
        "gate::authorize",
        "$this->authorize",
        "auth::user",
    ],
    extra_lock_guards: &["db::transaction", "lockforupdate", "begintransaction"],
};

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    walk_node(root, ctx, "", &HashSet::new());
}

fn walk_node(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    route_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) {
    let k = node.kind();

    // 1. `use App\Services\LedgerService;`
    if k == "namespace_use_declaration" {
        let txt = node_text(node, ctx.src);
        for seg in txt
            .trim()
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .split(',')
        {
            let clean = seg.split(" as ").next().unwrap_or(seg).trim();
            if !clean.is_empty() {
                ctx.imports.push(ImportRef {
                    symbol_name: "*".to_string(),
                    from_specifier: format!(
                        "php::{}",
                        clean.trim_start_matches('\\').replace('\\', "/")
                    ),
                    remote_name: None,
                });
            }
        }
        return;
    }

    // 2. `require 'path.php';` / `include 'path.php';`
    if matches!(
        k,
        "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression"
    ) {
        if let Some(path_lit) = find_first_string_literal(node, ctx.src) {
            ctx.imports.push(ImportRef {
                symbol_name: "*".to_string(),
                from_specifier: path_lit,
                remote_name: None,
            });
        }
        return;
    }

    // 3. `class FooController { ... }`
    if k == "class_declaration" {
        let class_name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.src).trim().to_string())
            .unwrap_or_else(|| "AnonymousClass".to_string());
        if class_name.ends_with("Test") {
            return;
        }
        let attr_txt = node
            .child_by_field_name("attributes")
            .map(|a| node_text(a, ctx.src))
            .unwrap_or("");
        let mut class_guards = scope_guards.clone();
        class_guards.extend(super::detect_text_guards(attr_txt, ctx.cfg, &PROFILE));

        let class_prefix = parse_symfony_route_attr(attr_txt)
            .map(|(_, p)| join_route_prefix(route_prefix, &p))
            .unwrap_or_else(|| route_prefix.to_string());

        if let Some(body) = node.child_by_field_name("body") {
            let class_body_txt = strip_comments(node_text(body, ctx.src));
            // Detect constructor `$this->middleware('auth')` in class body
            if class_body_txt.contains("$this->middleware(")
                && class_body_txt.to_ascii_lowercase().contains("auth")
            {
                class_guards.insert(GuardKind::Auth);
            }
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                if ch.kind() == "method_declaration" {
                    extract_method_or_fn(ch, ctx, Some(&class_name), &class_prefix, &class_guards);
                }
            }
        }
        return;
    }

    // 4. Top-level function `function debitBalance(...) { ... }`
    if k == "function_definition" {
        extract_method_or_fn(node, ctx, None, route_prefix, scope_guards);
        return;
    }

    // 5. Laravel `Route::get('/pay', ...)` / `Route::middleware('auth')->group(...)`
    if k == "scoped_call_expression" || k == "member_call_expression" {
        let txt = strip_comments(node_text(node, ctx.src));
        if (txt.contains("Route::") || txt.starts_with("$router->"))
            && handle_laravel_route_expr(node, ctx, route_prefix, scope_guards)
        {
            return;
        }
    }

    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        walk_node(ch, ctx, route_prefix, scope_guards);
    }
}

fn extract_method_or_fn(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    class_name: Option<&str>,
    class_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) {
    let fn_name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "anonymous".to_string());
    if fn_name.starts_with("test") && class_name.is_some_and(|c| c.ends_with("Test")) {
        return;
    }

    let attr_txt = node
        .child_by_field_name("attributes")
        .map(|a| node_text(a, ctx.src))
        .unwrap_or("");
    let params_txt = node
        .child_by_field_name("parameters")
        .map(|p| node_text(p, ctx.src))
        .unwrap_or("");
    let param_names = extract_param_idents(params_txt);
    let body = node.child_by_field_name("body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_route = parse_symfony_route_attr(attr_txt).map(|(verb, path)| {
        let full_p = join_route_prefix(class_prefix, &path);
        format!("{} {}", verb, full_p)
    });

    let mut guards = scope_guards.clone();
    guards.extend(super::detect_text_guards(attr_txt, ctx.cfg, &PROFILE));

    let kind = if sym_route.is_some() {
        SymbolKind::Route
    } else {
        SymbolKind::Function
    };
    let sym_id = format!("php:{}:{}:{}", ctx.rel_path, fn_name, line_start);
    let mut sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        fn_name,
        kind,
        line_start,
        line_end,
        attr_txt,
        params_txt,
        body,
        node,
        sym_route,
        &param_names,
    );
    sym.guards.extend(guards);
    ctx.symbols.push(sym);
}

fn handle_laravel_route_expr(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    route_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) -> bool {
    let full_txt = strip_comments(node_text(node, ctx.src));
    let mut next_guards = scope_guards.clone();
    next_guards.extend(super::detect_text_guards(&full_txt, ctx.cfg, &PROFILE));

    // Check group wrapper `Route::prefix('/api')->middleware('auth')->group(function () { ... })`
    let name_str = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim())
        .unwrap_or("");

    if name_str == "group" {
        let new_prefix = if let Some(pos) = full_txt.find("prefix(") {
            let after = &full_txt[pos + 7..];
            let sub = after
                .split(')')
                .next()
                .map(strip_quotes)
                .unwrap_or_default();
            join_route_prefix(route_prefix, &sub)
        } else {
            route_prefix.to_string()
        };
        if let Some(args) = node.child_by_field_name("arguments") {
            walk_node(args, ctx, &new_prefix, &next_guards);
        }
        if let Some(obj) = node.child_by_field_name("object") {
            let _ = obj;
        }
        return true;
    }

    // Look for innermost HTTP verb call on `Route::get('/pay', ...)` or `$router->post(...)`
    let Some(verb) = find_route_verb_in_chain(node, ctx.src) else {
        return false;
    };
    let Some(route_sub) = find_route_path_in_chain(node, ctx.src) else {
        return false;
    };
    let full_path = join_route_prefix(route_prefix, &route_sub);
    let route_label = format!("{} {}", verb, full_path);
    if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
        ctx.route_prefixes.push(full_path.clone());
    }

    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;
    let sym_id = format!("php:route:{}:{}", ctx.rel_path, line_start);

    // Check if an inline closure `function (...) { ... }` exists in chain
    let inline_fn = find_closure_node(node);
    if let Some(cl) = inline_fn {
        let params_txt = cl
            .child_by_field_name("parameters")
            .map(|p| node_text(p, ctx.src))
            .unwrap_or("");
        let param_names = extract_param_idents(params_txt);
        let body = cl.child_by_field_name("body");
        let mut sym = build_analyzed_symbol(
            ctx,
            &PROFILE,
            sym_id,
            route_label.clone(),
            SymbolKind::Route,
            line_start,
            line_end,
            &full_txt,
            params_txt,
            body,
            cl,
            Some(route_label),
            &param_names,
        );
        sym.guards.extend(next_guards);
        ctx.symbols.push(sym);
        return true;
    }

    // Otherwise extract controller action `[PaymentController::class, 'withdraw']` -> call `'withdraw'`
    let mut calls = Vec::new();
    if let Some(method_target) = extract_laravel_controller_action(&full_txt) {
        calls.push(method_target);
    }
    let mut sym = SymbolInfo::base(
        sym_id,
        ctx.rel_path,
        route_label.clone(),
        SymbolKind::Route,
        None,
        line_start,
        line_end,
        next_guards,
        calls,
        Some(route_label),
    );
    sym.has_resource_id = full_path.contains('{');
    ctx.symbols.push(sym);
    true
}

fn find_route_verb_in_chain(node: Node, src: &[u8]) -> Option<&'static str> {
    if let Some(n) = node.child_by_field_name("name")
        && let Some(v) = http_verb_from_ident(node_text(n, src))
    {
        return Some(v);
    }
    if let Some(obj) = node.child_by_field_name("object") {
        return find_route_verb_in_chain(obj, src);
    }
    None
}

fn find_route_path_in_chain(node: Node, src: &[u8]) -> Option<String> {
    if let Some(n) = node.child_by_field_name("name")
        && http_verb_from_ident(node_text(n, src)).is_some()
        && let Some(args) = node.child_by_field_name("arguments")
    {
        return find_first_string_literal(args, src);
    }
    if let Some(obj) = node.child_by_field_name("object") {
        return find_route_path_in_chain(obj, src);
    }
    None
}

fn find_closure_node(node: Node) -> Option<Node> {
    if matches!(node.kind(), "anonymous_function" | "arrow_function") {
        return Some(node);
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(found) = find_closure_node(ch) {
            return Some(found);
        }
    }
    None
}

fn extract_laravel_controller_action(txt: &str) -> Option<String> {
    // Pattern: `[Controller::class, 'methodName']`
    if let Some(pos) = txt.find("::class") {
        let after = &txt[pos + 7..];
        for tok in after.split([',', ']']) {
            let clean = strip_quotes(tok);
            if !clean.is_empty() && clean.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(clean);
            }
        }
    }
    None
}

fn parse_symfony_route_attr(attr_txt: &str) -> Option<(&'static str, String)> {
    let pos = attr_txt.find("#[Route(")?;
    let inner = attr_txt[pos + 8..].split(')').next()?;
    let path = inner
        .split(',')
        .next()
        .map(strip_quotes)
        .filter(|p| !p.is_empty())?;
    let low = inner.to_ascii_lowercase();
    let verb = if low.contains("post") {
        "POST"
    } else if low.contains("put") {
        "PUT"
    } else if low.contains("delete") {
        "DELETE"
    } else if low.contains("patch") {
        "PATCH"
    } else {
        "GET"
    };
    Some((verb, path))
}
