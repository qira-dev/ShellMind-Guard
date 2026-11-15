use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix, strip_quotes,
};
use crate::ast::{GuardKind, ImportRef, SymbolInfo, SymbolKind, node_text, strip_comments};
use std::collections::HashSet;
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "cs",
    taint_sources: &[
        "request.query",
        "req.query",
        "request.form",
        "request.headers",
        "httpcontext.request",
        "[fromquery]",
        "[fromroute]",
        "[frombody]",
        "[fromform]",
    ],
    tainted_param_markers: &["[FromQuery]", "[FromRoute]", "[FromBody]", "[FromForm]"],
    sql_sinks: &[
        "fromsqlraw(",
        "executesqlraw(",
        "executesqlrawasync(",
        "new sqlcommand(",
        ".commandtext =",
    ],
    sql_sanitizers: &[
        "fromsqlinterpolated(",
        "executesqlinterpolated(",
        "parameters.addwithvalue(",
        "parameters.add(",
    ],
    cmd_sinks: &["process.start(", "new processstartinfo("],
    cmd_sanitizers: &["argumentlist.add(", "commandallowlist"],
    path_sinks: &[
        "file.readalltext(",
        "file.readallbytes(",
        "file.writealltext(",
        "file.open(",
        "path.combine(",
    ],
    path_sanitizers: &["path.getfilename(", "getfullpath(", ".startswith("],
    ssrf_sinks: &[
        "httpclient.getasync(",
        "httpclient.getstringasync(",
        ".getasync(",
        ".sendasync(",
        "webrequest.create(",
    ],
    ssrf_sanitizers: &["allowedhosts", "validateurl", "urihostnametype"],
    xss_sinks: &["response.writeasync(", "html.raw(", "text/html"],
    xss_sanitizers: &[
        "htmlencoder.",
        "httputility.htmlencode(",
        "webutility.htmlencode(",
    ],
    ownership_markers: &[
        "user.identity",
        "claimtypes.nameidentifier",
        "userid",
        "ownerid",
        "tenantid",
    ],
    db_write_sinks: &[
        "savechanges(",
        "savechangesasync(",
        "executesqlraw",
        "executenonquery",
    ],
    db_crud_markers: &[
        "_db.",
        "_context.",
        "dbcontext",
        "firstordefault",
        "findasync",
        "savechanges",
    ],
    extra_auth_guards: &["[authorize", ".requireauthorization("],
    extra_lock_guards: &[
        "begintransaction",
        "isolationlevel.",
        "semaphoreslim",
        "lock (",
    ],
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

    if k == "using_directive" {
        let raw = node_text(node, ctx.src)
            .trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_start_matches("static ")
            .trim_end_matches(';')
            .trim();
        let ns = raw.split('=').next_back().unwrap_or(raw).trim();
        if !ns.is_empty() && !ns.starts_with("System") && !ns.starts_with("Microsoft") {
            ctx.imports.push(ImportRef {
                symbol_name: "*".to_string(),
                from_specifier: format!("cs::{}", ns.replace('.', "/")),
                remote_name: None,
            });
        }
        return;
    }

    if k == "class_declaration" {
        let class_name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.src).trim().to_string())
            .unwrap_or_default();
        if class_name.ends_with("Test") || class_name.ends_with("Tests") {
            return;
        }
        let attrs = collect_attr_lists(node, ctx.src);
        let mut class_guards = scope_guards.clone();
        class_guards.extend(super::detect_text_guards(&attrs, ctx.cfg, &PROFILE));

        let controller_slug = class_name
            .strip_suffix("Controller")
            .unwrap_or(&class_name)
            .to_ascii_lowercase();
        let class_prefix = parse_aspnet_route_attr(&attrs, &controller_slug)
            .map(|p| join_route_prefix(route_prefix, &p))
            .unwrap_or_else(|| route_prefix.to_string());

        if let Some(body) = node.child_by_field_name("body") {
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                if ch.kind() == "method_declaration" {
                    extract_method(ch, ctx, &class_prefix, &class_guards);
                }
            }
        }
        return;
    }

    // Minimal APIs: `app.MapGet("/...", ...)` / `app.MapPost(...).RequireAuthorization()`
    if k == "invocation_expression" {
        let txt = strip_comments(node_text(node, ctx.src));
        if (txt.contains("MapGet(")
            || txt.contains("MapPost(")
            || txt.contains("MapPut(")
            || txt.contains("MapDelete(")
            || txt.contains("MapPatch("))
            && handle_minimal_api(node, ctx, route_prefix, scope_guards)
        {
            return;
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx, route_prefix, scope_guards);
    }
}

fn collect_attr_lists(node: Node, src: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if ch.kind() == "attribute_list" {
            parts.push(node_text(ch, src).to_string());
        }
    }
    parts.join("\n")
}

fn extract_method(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    class_prefix: &str,
    class_guards: &HashSet<GuardKind>,
) {
    let attrs = collect_attr_lists(node, ctx.src);
    if attrs.contains("[Fact") || attrs.contains("[Theory") || attrs.contains("[Test") {
        return;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "Method".to_string());
    let params_txt = node
        .child_by_field_name("parameters")
        .map(|p| node_text(p, ctx.src))
        .unwrap_or("");
    let param_names = extract_param_idents(params_txt);
    let body = node.child_by_field_name("body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_route = parse_aspnet_method_route(&attrs).map(|(verb, sub)| {
        let full = join_route_prefix(class_prefix, &sub);
        if !ctx.route_prefixes.iter().any(|p| p == &full) {
            ctx.route_prefixes.push(full.clone());
        }
        format!("{} {}", verb, full)
    });

    let kind = if sym_route.is_some() {
        SymbolKind::Route
    } else {
        SymbolKind::Function
    };
    let sym_id = format!("cs:{}:{}:{}", ctx.rel_path, name, line_start);
    let mut sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        name,
        kind,
        line_start,
        line_end,
        &attrs,
        params_txt,
        body,
        node,
        sym_route,
        &param_names,
    );
    if !attrs.contains("[AllowAnonymous]") {
        sym.guards.extend(class_guards.iter().copied());
    } else {
        sym.guards.remove(&GuardKind::Auth);
    }
    ctx.symbols.push(sym);
}

fn handle_minimal_api(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    route_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) -> bool {
    let full_txt = strip_comments(node_text(node, ctx.src));
    // Unwrap outer fluent chains like `app.MapPost(...).RequireAuthorization().Produces(200)`
    let mut target = node;
    loop {
        let Some(fnode) = target.child_by_field_name("function") else {
            return false;
        };
        let ftxt = node_text(fnode, ctx.src);
        let mname = ftxt.rsplit('.').next().unwrap_or(ftxt).trim();
        if http_verb_from_ident(mname).is_some() {
            break;
        }
        if fnode.kind() == "member_access_expression"
            && let Some(inner) = fnode.child_by_field_name("expression")
            && inner.kind() == "invocation_expression"
        {
            target = inner;
        } else {
            return false;
        }
    }

    let Some(func_node) = target.child_by_field_name("function") else {
        return false;
    };
    let func_txt = node_text(func_node, ctx.src);
    let method_name = func_txt.rsplit('.').next().unwrap_or(func_txt).trim();
    let Some(verb) = http_verb_from_ident(method_name) else {
        return false;
    };
    let Some(args) = target.child_by_field_name("arguments") else {
        return false;
    };
    let Some(sub_path) = find_first_string_literal(args, ctx.src) else {
        return false;
    };
    let full_path = join_route_prefix(route_prefix, &sub_path);
    let route_label = format!("{} {}", verb, full_path);
    if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
        ctx.route_prefixes.push(full_path.clone());
    }

    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;
    let mut guards = scope_guards.clone();
    if let Some(parent) = node.parent() {
        let ptxt = strip_comments(node_text(parent, ctx.src));
        guards.extend(super::detect_text_guards(&ptxt, ctx.cfg, &PROFILE));
    }
    guards.extend(super::detect_text_guards(&full_txt, ctx.cfg, &PROFILE));
    if full_txt.to_ascii_lowercase().contains(".allowanonymous(") {
        guards.remove(&GuardKind::Auth);
    }

    let sym_id = format!("cs:route:{}:{}", ctx.rel_path, line_start);
    if let Some(lambda) = find_lambda_node(args) {
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
            Some(lambda),
            lambda,
            Some(route_label),
            &[],
        );
        sym.guards.extend(guards);
        ctx.symbols.push(sym);
        return true;
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
        Vec::new(),
        Some(route_label),
    );
    sym.has_resource_id = full_path.contains('{');
    ctx.symbols.push(sym);
    true
}

fn find_lambda_node(node: Node) -> Option<Node> {
    if matches!(
        node.kind(),
        "lambda_expression" | "anonymous_method_expression"
    ) {
        return Some(node);
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(found) = find_lambda_node(ch) {
            return Some(found);
        }
    }
    None
}

fn parse_aspnet_route_attr(attrs: &str, controller_slug: &str) -> Option<String> {
    let pos = attrs.find("[Route(")?;
    let raw = attrs[pos + 7..].split(')').next().map(strip_quotes)?;
    if raw.is_empty() {
        None
    } else {
        Some(raw.replace("[controller]", controller_slug))
    }
}

fn parse_aspnet_method_route(attrs: &str) -> Option<(&'static str, String)> {
    const ATTRS: &[(&str, &str)] = &[
        ("[HttpGet", "GET"),
        ("[HttpPost", "POST"),
        ("[HttpPut", "PUT"),
        ("[HttpDelete", "DELETE"),
        ("[HttpPatch", "PATCH"),
    ];
    for &(pat, verb) in ATTRS {
        if let Some(pos) = attrs.find(pat) {
            let after = &attrs[pos + pat.len()..];
            let sub = if let Some(rest) = after.strip_prefix('(') {
                rest.split(')')
                    .next()
                    .map(strip_quotes)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "/".to_string())
            } else {
                "/".to_string()
            };
            return Some((verb, sub));
        }
    }
    None
}
