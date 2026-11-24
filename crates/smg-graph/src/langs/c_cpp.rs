use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix, strip_quotes,
};
use crate::ast::{ImportRef, SymbolInfo, SymbolKind, node_text, strip_comments};
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "cpp",
    taint_sources: &[
        "argv",
        "getenv(",
        "fgets(",
        "scanf(",
        "req.body",
        "req.url_params",
        "req.get_param_value(",
    ],
    tainted_param_markers: &[],
    sql_sinks: &[
        "sqlite3_exec(",
        "mysql_query(",
        "mysql_real_query(",
        "pqexec(",
    ],
    sql_sanitizers: &[
        "sqlite3_prepare",
        "sqlite3_bind_",
        "mysql_stmt_prepare",
        "pqexecparams",
    ],
    cmd_sinks: &["system(", "popen(", "execl(", "execvp(", "shellexecute("],
    cmd_sanitizers: &["allowed_cmds", "commandallowlist"],
    path_sinks: &[
        "fopen(",
        "ifstream(",
        "ofstream(",
        "std::filesystem::copy(",
        "std::filesystem::remove(",
        "std::filesystem::rename(",
    ],
    path_sanitizers: &["realpath(", "canonical(", ".starts_with("],
    ssrf_sinks: &["curl_easy_setopt(", "cpr::get(", "httplib::client("],
    ssrf_sanitizers: &["allowed_hosts", "validate_url"],
    xss_sinks: &["res.set_content(", "mg_http_reply("],
    xss_sanitizers: &["html_escape(", "escape_html("],
    ownership_markers: &["session_user"],
    db_write_sinks: &["sqlite3_exec(", "mysql_query(", "pqexec("],
    db_crud_markers: &["sqlite3_", "mysql_", "pqexec"],
    extra_auth_guards: &["require_auth", "verify_jwt", "check_auth"],
    extra_lock_guards: &[
        "std::lock_guard",
        "std::unique_lock",
        "std::scoped_lock",
        "pthread_mutex_lock",
    ],
};

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    walk_node(root, ctx);
}

fn walk_node(node: Node, ctx: &mut ExtractContext<'_>) {
    let k = node.kind();

    if k == "preproc_include" {
        if let Some(path_node) = node.child_by_field_name("path") {
            let raw = node_text(path_node, ctx.src).trim();
            if raw.starts_with('"') && raw.ends_with('"') {
                let inc = strip_quotes(raw);
                if !inc.is_empty() {
                    ctx.imports.push(ImportRef {
                        symbol_name: "*".to_string(),
                        from_specifier: format!("cpp::{}", inc),
                        remote_name: None,
                    });
                }
            }
        }
        return;
    }

    if k == "function_definition" {
        extract_function(node, ctx);
        return;
    }

    // Handle Crow / cpp-httplib routes (`CROW_ROUTE(app, "/pay")` or `svr.Post("/pay", ...)`)
    if k == "call_expression" && handle_cpp_http_route(node, ctx) {
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx);
    }
}

fn extract_function(node: Node, ctx: &mut ExtractContext<'_>) {
    let decl = node.child_by_field_name("declarator");
    let fn_name = decl
        .and_then(|d| extract_c_declarator_name(d, ctx.src))
        .unwrap_or_else(|| "c_fn".to_string());
    if fn_name.starts_with("test_") || fn_name.starts_with("TEST") {
        return;
    }
    let params_txt = decl
        .and_then(|d| find_param_list_text(d, ctx.src))
        .unwrap_or_default();
    let param_names = extract_param_idents(&params_txt);
    let body = node.child_by_field_name("body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_id = format!("cpp:{}:{}:{}", ctx.rel_path, fn_name, line_start);
    let sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        fn_name,
        SymbolKind::Function,
        line_start,
        line_end,
        "",
        &params_txt,
        body,
        node,
        None,
        &param_names,
    );
    ctx.symbols.push(sym);

    if let Some(b) = body {
        walk_node(b, ctx);
    }
}

fn extract_c_declarator_name(node: Node, src: &[u8]) -> Option<String> {
    let k = node.kind();
    if k == "function_declarator"
        && let Some(inner) = node.child_by_field_name("declarator")
    {
        return extract_c_declarator_name(inner, src);
    }
    if matches!(
        k,
        "pointer_declarator"
            | "reference_declarator"
            | "attributed_declarator"
            | "parenthesized_declarator"
    ) && let Some(inner) = node.child_by_field_name("declarator")
    {
        return extract_c_declarator_name(inner, src);
    }
    if matches!(
        k,
        "identifier" | "field_identifier" | "qualified_identifier"
    ) {
        let txt = node_text(node, src).trim();
        let short = txt.rsplit("::").next().unwrap_or(txt).trim();
        if !short.is_empty() {
            return Some(short.to_string());
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(found) = extract_c_declarator_name(ch, src) {
            return Some(found);
        }
    }
    None
}

fn find_param_list_text(node: Node, src: &[u8]) -> Option<String> {
    if node.kind() == "parameter_list" {
        return Some(node_text(node, src).to_string());
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(found) = find_param_list_text(ch, src) {
            return Some(found);
        }
    }
    None
}

fn handle_cpp_http_route(node: Node, ctx: &mut ExtractContext<'_>) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    let ftxt = node_text(func, ctx.src).trim();
    let short = ftxt.rsplit(['.', '>']).next().unwrap_or(ftxt).trim();

    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };

    // Chained Crow route: `CROW_ROUTE(app, "/debit").methods("POST"_method)(handle_debit)`
    // or `CROW_ROUTE(app, "/debit")(handle_debit)`
    let (verb, path_str, handler_idx) = if ftxt.starts_with("CROW_ROUTE(") {
        let Some(p) = find_first_string_literal(func, ctx.src) else {
            return false;
        };
        let f_up = ftxt.to_ascii_uppercase();
        let v = if f_up.contains("\"POST\"") {
            "POST"
        } else if f_up.contains("\"PUT\"") {
            "PUT"
        } else if f_up.contains("\"DELETE\"") {
            "DELETE"
        } else if f_up.contains("\"PATCH\"") {
            "PATCH"
        } else if f_up.contains("\"GET\"") {
            "GET"
        } else {
            "ANY"
        };
        (v, p, 0usize)
    } else if short == "CROW_ROUTE" {
        let Some(p) = find_first_string_literal(args, ctx.src) else {
            return false;
        };
        ("ANY", p, 1usize)
    } else if (ftxt.contains('.') || ftxt.contains("->")) && !super::is_non_route_receiver(ftxt) {
        let Some(v) = http_verb_from_ident(short) else {
            return false;
        };
        let Some(p) = find_first_string_literal(args, ctx.src) else {
            return false;
        };
        if !p.starts_with('/') {
            return false;
        }
        (v, p, 1usize)
    } else {
        return false;
    };

    let full_path = join_route_prefix("", &path_str);
    let route_label = format!("{} {}", verb, full_path);
    if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
        ctx.route_prefixes.push(full_path.clone());
    }

    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;
    let full_txt = strip_comments(node_text(node, ctx.src));
    let guards = super::detect_text_guards(&full_txt, ctx.cfg, &PROFILE);
    let sym_id = format!("cpp:route:{}:{}", ctx.rel_path, line_start);

    if let Some(lam) = find_lambda_expression(args) {
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
    let mut ac = args.walk();
    if let Some(handler_arg) = args.named_children(&mut ac).nth(handler_idx) {
        let h = node_text(handler_arg, ctx.src).trim();
        let short_h = h.rsplit("::").next().unwrap_or(h).trim_start_matches('&');
        if !short_h.is_empty() && short_h.chars().all(|c| c.is_alphanumeric() || c == '_') {
            calls.push(short_h.to_string());
        }
    }
    let sym = SymbolInfo::base(
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
    ctx.symbols.push(sym);
    true
}

fn find_lambda_expression(node: Node) -> Option<Node> {
    if node.kind() == "lambda_expression" {
        return Some(node);
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(f) = find_lambda_expression(ch) {
            return Some(f);
        }
    }
    None
}
