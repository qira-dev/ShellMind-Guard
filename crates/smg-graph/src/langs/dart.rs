use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix, strip_quotes,
};
use crate::ast::{ImportRef, SymbolInfo, SymbolKind, node_text, strip_comments};
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "dart",
    taint_sources: &[
        "queryparameters",
        "request.url.query",
        "context.request.uri",
        "request.readasstring(",
        "params[",
    ],
    tainted_param_markers: &[],
    sql_sinks: &[
        ".rawquery(",
        ".rawinsert(",
        ".rawupdate(",
        ".rawdelete(",
        ".execute(",
    ],
    sql_sanitizers: &["preparedstatement", "substitutionvalues"],
    cmd_sinks: &["process.run(", "process.start(", "process.runsync("],
    cmd_sanitizers: &["allowedcommands", "commandallowlist"],
    path_sinks: &["new file(", "file(", ".writeasstring("],
    path_sanitizers: &["p.basename(", "path.basename(", ".resolve("],
    ssrf_sinks: &["http.get(", "http.post(", "dio().get(", "dio.get("],
    ssrf_sanitizers: &["allowedhosts", "validateurl"],
    xss_sinks: &["text/html", "contenttype.html"],
    xss_sanitizers: &["htmlEscape", "escape("],
    ownership_markers: &["currentuserid"],
    db_write_sinks: &[".rawinsert(", ".rawupdate(", ".rawdelete("],
    db_crud_markers: &[".rawquery(", ".rawinsert(", ".rawupdate(", ".find("],
    extra_auth_guards: &["requireauth", "checkauth", "authmiddleware"],
    extra_lock_guards: &["db.transaction(", "synchronized("],
};

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    walk_node(root, ctx, 0);
}

fn walk_node(node: Node, ctx: &mut ExtractContext<'_>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();

    if k == "import_or_export" || k == "library_import" {
        if let Some(raw_lit) = find_first_string_literal(node, ctx.src) {
            let unq = strip_quotes(&raw_lit);
            if !unq.starts_with("dart:") && !unq.starts_with("package:flutter/") {
                let spec = if let Some(rest) = unq.strip_prefix("package:") {
                    let tail = rest.split_once('/').map(|(_, t)| t).unwrap_or(rest);
                    format!("dart::{}", tail)
                } else {
                    unq
                };
                ctx.imports.push(ImportRef {
                    symbol_name: "*".to_string(),
                    from_specifier: spec,
                    remote_name: None,
                });
            }
        }
        return;
    }

    if k == "class_declaration" {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.src).trim().to_string())
            .unwrap_or_default();
        if name.ends_with("Test") {
            return;
        }
        if let Some(body) = node.child_by_field_name("body") {
            walk_block_members(body, ctx, depth + 1);
        }
        return;
    }

    // Handle `function_declaration` or top-level paired `function_signature` + `function_body`
    if (k == "function_declaration" || k == "method_declaration")
        && let Some(sig) = node.child_by_field_name("signature")
    {
        let body = node.child_by_field_name("body");
        extract_dart_callable(sig, body, node, ctx, depth + 1);
        return;
    }

    if matches!(k, "program" | "source_file" | "block") {
        walk_block_members(node, ctx, depth + 1);
        return;
    }

    if k == "call_expression" && handle_shelf_route(node, ctx) {
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx, depth + 1);
    }
}

fn walk_block_members(container: Node, ctx: &mut ExtractContext<'_>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let mut cursor = container.walk();
    let children: Vec<Node> = container.children(&mut cursor).collect();
    let mut i = 0;
    while i < children.len() {
        let ch = children[i];
        if (ch.kind() == "function_signature" || ch.kind() == "method_signature")
            && i + 1 < children.len()
            && children[i + 1].kind() == "function_body"
        {
            extract_dart_callable(ch, Some(children[i + 1]), ch, ctx, depth + 1);
            i += 2;
            continue;
        }
        walk_node(ch, ctx, depth + 1);
        i += 1;
    }
}

fn extract_dart_callable(
    sig: Node,
    body: Option<Node>,
    full_node: Node,
    ctx: &mut ExtractContext<'_>,
    depth: usize,
) {
    let fn_sig = if sig.kind() == "method_signature" {
        sig.named_children(&mut sig.walk())
            .find(|n| n.kind() == "function_signature")
            .unwrap_or(sig)
    } else {
        sig
    };
    let name = fn_sig
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "dartFn".to_string());
    let params_txt = fn_sig
        .child_by_field_name("parameters")
        .map(|p| node_text(p, ctx.src))
        .unwrap_or("");
    let param_names = extract_param_idents(params_txt);
    let line_start = full_node.start_position().row + 1;
    let line_end = body
        .map(|b| b.end_position().row + 1)
        .unwrap_or_else(|| full_node.end_position().row + 1);

    // Dart Frog `routes/...` uses `onRequest(RequestContext context)` as HTTP entry
    let sym_route = if name == "onRequest" {
        let route_p = ctx
            .rel_path
            .split("routes/")
            .nth(1)
            .map(|r| {
                let no_ext = r.strip_suffix(".dart").unwrap_or(r);
                join_route_prefix("", no_ext)
            })
            .unwrap_or_else(|| "/".to_string());
        if !ctx.route_prefixes.iter().any(|p| p == &route_p) {
            ctx.route_prefixes.push(route_p.clone());
        }
        Some(format!("ANY {}", route_p))
    } else {
        None
    };

    let kind = if sym_route.is_some() {
        SymbolKind::Route
    } else {
        SymbolKind::Function
    };
    let sym_id = format!("dart:{}:{}:{}", ctx.rel_path, name, line_start);
    let sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        name,
        kind,
        line_start,
        line_end,
        "",
        params_txt,
        body,
        body.unwrap_or(full_node),
        sym_route,
        &param_names,
    );
    ctx.symbols.push(sym);

    if let Some(b) = body {
        walk_node(b, ctx, depth + 1);
    }
}

fn handle_shelf_route(node: Node, ctx: &mut ExtractContext<'_>) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    let ftxt = node_text(func, ctx.src).trim();
    if super::is_non_route_receiver(ftxt) {
        return false;
    }
    let short = ftxt.rsplit('.').next().unwrap_or(ftxt);
    let Some(verb) = http_verb_from_ident(short) else {
        return false;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let Some(sub_path) = find_first_string_literal(args, ctx.src) else {
        return false;
    };
    if !sub_path.starts_with('/') {
        return false;
    }
    let full_path = join_route_prefix("", &sub_path);
    let route_label = format!("{} {}", verb, full_path);
    if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
        ctx.route_prefixes.push(full_path.clone());
    }

    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;
    let full_txt = strip_comments(node_text(node, ctx.src));
    let guards = super::detect_text_guards(&full_txt, ctx.cfg, &PROFILE);
    let sym_id = format!("dart:route:{}:{}", ctx.rel_path, line_start);

    if let Some(fn_expr) = find_function_expression(args) {
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
            Some(fn_expr),
            fn_expr,
            Some(route_label),
            &[],
        );
        sym.guards.extend(guards);
        ctx.symbols.push(sym);
        return true;
    }

    let mut calls = Vec::new();
    // Shelf handler symbol: `router.get('/pay', handlePayment)` -> second argument identifier
    let mut ac = args.walk();
    if let Some(second_arg) = args.named_children(&mut ac).nth(1) {
        let h = node_text(second_arg, ctx.src).trim();
        if !h.is_empty() && h.chars().all(|c| c.is_alphanumeric() || c == '_') {
            calls.push(h.to_string());
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
    sym.has_resource_id = full_path.contains('<');
    ctx.symbols.push(sym);
    true
}

fn find_function_expression(node: Node) -> Option<Node> {
    if node.kind() == "function_expression" {
        return Some(node);
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(f) = find_function_expression(ch) {
            return Some(f);
        }
    }
    None
}
