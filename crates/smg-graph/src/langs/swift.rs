use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents, http_verb_from_ident,
    join_route_prefix, strip_quotes,
};
use crate::ast::{GuardKind, ImportRef, SymbolInfo, SymbolKind, node_text, strip_comments};
use std::collections::HashSet;
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "swift",
    taint_sources: &[
        "req.query[",
        "req.query.get(",
        "req.parameters.get(",
        "req.content.decode(",
        "req.headers.first(",
        "urlcomponents(",
    ],
    tainted_param_markers: &[],
    sql_sinks: &["sql.raw(", ".raw(", "sqlite3_exec("],
    sql_sanitizers: &["bind:", "binds:", "sqlite3_prepare"],
    cmd_sinks: &["process()", "launchpath", "executableurl"],
    cmd_sanitizers: &["allowedcommands"],
    path_sinks: &["filemanager.default", "data(contentsof:", "contentsof("],
    path_sanitizers: &["standardizedfileurl", "lastpathcomponent"],
    ssrf_sinks: &[
        "urlsession.shared.data(",
        "req.client.get(",
        "req.client.post(",
    ],
    ssrf_sanitizers: &["allowedhosts", "validateurl"],
    xss_sinks: &["response(status: .ok, body:"],
    xss_sanitizers: &["htmlescape", "addingpercentencoding"],
    ownership_markers: &["req.auth.require("],
    db_write_sinks: &[".save(on:", ".update(on:", ".delete(on:", ".create(on:"],
    db_crud_markers: &[".find(", ".query(", ".save(on:", "sql.raw("],
    extra_auth_guards: &[
        "req.auth.require",
        ".authenticator(",
        ".guardmiddleware(",
        "requireauth",
    ],
    extra_lock_guards: &["db.transaction", "withlock", "nslock", "lock()"],
};

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    let mut grouped_auth_vars: HashSet<String> = HashSet::new();
    walk_node(root, ctx, &mut grouped_auth_vars);
}

fn walk_node(node: Node, ctx: &mut ExtractContext<'_>, grouped_auth_vars: &mut HashSet<String>) {
    let k = node.kind();

    if k == "import_declaration" {
        let raw = node_text(node, ctx.src).trim();
        let mod_name = raw
            .split_whitespace()
            .last()
            .unwrap_or("")
            .trim()
            .to_string();
        if !mod_name.is_empty()
            && !matches!(
                mod_name.as_str(),
                "Foundation" | "Vapor" | "SwiftUI" | "UIKit" | "Fluent"
            )
        {
            ctx.imports.push(ImportRef {
                symbol_name: "*".to_string(),
                from_specifier: format!("swift::{}", mod_name),
                remote_name: None,
            });
        }
        return;
    }

    // Track `let protected = app.grouped(User.authenticator(), User.guardMiddleware())`
    if k == "property_declaration" {
        let txt = strip_comments(node_text(node, ctx.src));
        if txt.contains(".grouped(")
            && (txt.contains("authenticator") || txt.contains("guardMiddleware"))
            && let Some(lhs) = txt.split('=').next()
            && let Some(var_name) = lhs.split_whitespace().last()
        {
            grouped_auth_vars.insert(var_name.trim().to_string());
        }
    }

    if k == "class_declaration" {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.src).trim().to_string())
            .unwrap_or_default();
        if name.ends_with("Tests") {
            return;
        }
        if let Some(body) = node.child_by_field_name("body") {
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                walk_node(ch, ctx, grouped_auth_vars);
            }
        }
        return;
    }

    if k == "function_declaration" {
        extract_function(node, ctx, grouped_auth_vars);
        return;
    }

    if k == "call_expression" && handle_vapor_route(node, ctx, grouped_auth_vars) {
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx, grouped_auth_vars);
    }
}

fn extract_function(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    grouped_auth_vars: &mut HashSet<String>,
) {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "func".to_string());
    if name.starts_with("test") && ctx.rel_path.ends_with("Tests.swift") {
        return;
    }
    let fn_txt = node_text(node, ctx.src);
    let params_txt = fn_txt
        .find('(')
        .and_then(|s| fn_txt[s..].find('{').map(|e| &fn_txt[s..s + e]))
        .unwrap_or("");
    let param_names = extract_param_idents(params_txt);
    let body = node.child_by_field_name("body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_id = format!("swift:{}:{}:{}", ctx.rel_path, name, line_start);
    let sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        name,
        SymbolKind::Function,
        line_start,
        line_end,
        "",
        params_txt,
        body,
        node,
        None,
        &param_names,
    );
    ctx.symbols.push(sym);

    if let Some(b) = body {
        let mut c = b.walk();
        for ch in b.children(&mut c) {
            walk_node(ch, ctx, grouped_auth_vars);
        }
    }
}

fn handle_vapor_route(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    grouped_auth_vars: &HashSet<String>,
) -> bool {
    let mut c = node.walk();
    let named: Vec<Node> = node.named_children(&mut c).collect();
    let Some(first) = named.first().copied() else {
        return false;
    };
    let callee_txt = node_text(first, ctx.src).trim();
    let Some((receiver, method)) = callee_txt.rsplit_once('.') else {
        return false;
    };
    if super::is_non_route_receiver(callee_txt) {
        return false;
    }
    let Some(verb) = http_verb_from_ident(method) else {
        return false;
    };
    let full_txt = strip_comments(node_text(node, ctx.src));
    let mut path_segments = Vec::new();
    let suffix = named.iter().find(|n| n.kind() == "call_suffix").copied();
    if let Some(suf) = suffix {
        collect_vapor_path_segments(suf, ctx.src, &mut path_segments);
    }
    if path_segments.is_empty() {
        return false;
    }
    let full_path = join_route_prefix("", &path_segments.join("/"));
    let route_label = format!("{} {}", verb, full_path);
    if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
        ctx.route_prefixes.push(full_path.clone());
    }

    let mut guards = super::detect_text_guards(&full_txt, ctx.cfg, &PROFILE);
    if grouped_auth_vars.contains(receiver.trim()) {
        guards.insert(GuardKind::Auth);
    }

    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;
    let sym_id = format!("swift:route:{}:{}", ctx.rel_path, line_start);

    let lambda = suffix.and_then(|s| find_kind_recursive(s, "lambda_literal"));
    if let Some(lam) = lambda {
        let mut sym = build_analyzed_symbol(
            ctx,
            &PROFILE,
            sym_id,
            route_label.clone(),
            SymbolKind::Route,
            line_start,
            line_end,
            &full_txt,
            "",
            Some(lam),
            lam,
            Some(route_label),
            &[],
        );
        sym.guards.extend(guards);
        ctx.symbols.push(sym);
        return true;
    }

    let mut calls = Vec::new();
    if let Some(pos) = full_txt.find("use:") {
        let target = full_txt[pos + 4..]
            .split([')', ','])
            .next()
            .unwrap_or("")
            .trim();
        if !target.is_empty() {
            calls.push(target.to_string());
        }
    }
    let mut sym = SymbolInfo::base(
        sym_id,
        ctx.rel_path,
        route_label.clone(),
        SymbolKind::Route,
        None,
        line_start,
        line_end,
        guards,
        calls,
        Some(route_label),
    );
    sym.has_resource_id = full_path.contains(':');
    ctx.symbols.push(sym);
    true
}

fn collect_vapor_path_segments(node: Node, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "lambda_literal" {
        return;
    }
    if node.kind() == "line_string_literal" {
        let seg = strip_quotes(node_text(node, src));
        if !seg.is_empty() {
            out.push(seg);
        }
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_vapor_path_segments(ch, src, out);
    }
}

fn find_kind_recursive<'a>(node: Node<'a>, target: &str) -> Option<Node<'a>> {
    if node.kind() == target {
        return Some(node);
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(f) = find_kind_recursive(ch, target) {
            return Some(f);
        }
    }
    None
}
