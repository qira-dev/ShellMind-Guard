use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix,
};
use crate::ast::{GuardKind, ImportRef, SymbolKind, node_text, strip_comments};
use std::collections::HashSet;
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "kt",
    taint_sources: &[
        "call.parameters",
        "call.receive",
        "request.getparameter(",
        "intent.getstringextra(",
        "intent.data",
        "@requestparam",
        "@pathvariable",
        "@requestbody",
    ],
    tainted_param_markers: &["@RequestParam", "@PathVariable", "@RequestBody"],
    sql_sinks: &[
        ".rawquery(",
        ".execsql(",
        ".executequery(",
        ".executeupdate(",
        "createnativequery(",
        "jdbctemplate.query(",
    ],
    sql_sanitizers: &[
        "preparestatement(",
        ".setparameter(",
        ".setstring(",
        ".setint(",
        "arrayof(",
    ],
    cmd_sinks: &["getruntime().exec(", "processbuilder("],
    cmd_sanitizers: &["commandallowlist", "allowedcommands"],
    path_sinks: &["file(", "files.readstring(", "openfileinput("],
    path_sanitizers: &["canonicalpath.startswith(", ".normalize().startswith("],
    ssrf_sinks: &[
        "newurl(",
        "url(",
        "okhttpclient",
        "httpclient.",
        "resttemplate.",
    ],
    ssrf_sanitizers: &["allowedhosts", "validateurl", "isvalidhost"],
    xss_sinks: &["respondtext(", "loadurl(\"javascript:", "loaddata("],
    xss_sanitizers: &["htmlescape(", "escapehtml("],
    ownership_markers: &[
        "principal?.getname",
        "securitycontextholder",
        "call.principal",
        "userid",
        "ownerid",
        "tenantid",
    ],
    db_write_sinks: &[
        ".save(",
        "jdbctemplate.update(",
        ".executeupdate(",
        ".execsql(",
        "entitymanager.persist(",
    ],
    db_crud_markers: &[
        "repository.",
        "entitymanager.",
        "jdbctemplate.",
        "transaction {",
        "execsql",
    ],
    extra_auth_guards: &[
        "@preauthorize",
        "@secured",
        "@rolesallowed",
        "authenticate(",
        "call.principal",
    ],
    extra_lock_guards: &[
        "@transactional",
        "transaction {",
        "mutex.withlock",
        "synchronized(",
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

    if k == "import" {
        let raw = node_text(node, ctx.src)
            .trim()
            .trim_start_matches("import ")
            .trim();
        let cleaned = raw
            .split(" as ")
            .next()
            .unwrap_or(raw)
            .trim()
            .trim_end_matches(".*");
        if !cleaned.is_empty() && !cleaned.starts_with("kotlin.") && !cleaned.starts_with("java.") {
            ctx.imports.push(ImportRef {
                symbol_name: "*".to_string(),
                from_specifier: format!("kt::{}", cleaned.replace('.', "/")),
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
        let mod_txt = collect_child_text(node, "modifiers", ctx.src);
        let mut class_guards = scope_guards.clone();
        class_guards.extend(super::detect_text_guards(&mod_txt, ctx.cfg, &PROFILE));
        let class_prefix = parse_spring_kt_mapping(&mod_txt)
            .map(|(_, sub)| join_route_prefix(route_prefix, &sub))
            .unwrap_or_else(|| route_prefix.to_string());

        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if matches!(ch.kind(), "class_body" | "enum_class_body") {
                let mut bc = ch.walk();
                for member in ch.children(&mut bc) {
                    walk_node(member, ctx, &class_prefix, &class_guards);
                }
            }
        }
        return;
    }

    if k == "function_declaration" {
        extract_function(node, ctx, route_prefix, scope_guards);
        return;
    }

    if k == "call_expression" && handle_ktor_dsl_call(node, ctx, route_prefix, scope_guards) {
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx, route_prefix, scope_guards);
    }
}

fn collect_child_text(node: Node, target_kind: &str, src: &[u8]) -> String {
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if ch.kind() == target_kind {
            return node_text(ch, src).to_string();
        }
    }
    String::new()
}

fn find_child_kind<'a>(node: Node<'a>, target_kind: &str) -> Option<Node<'a>> {
    let mut c = node.walk();
    node.children(&mut c).find(|ch| ch.kind() == target_kind)
}

fn extract_function(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    route_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) {
    let mod_txt = collect_child_text(node, "modifiers", ctx.src);
    if mod_txt.contains("@Test") {
        return;
    }
    let name = node
        .child_by_field_name("name")
        .or_else(|| find_child_kind(node, "simple_identifier"))
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "fun".to_string());
    let params_txt = collect_child_text(node, "function_value_parameters", ctx.src);
    let param_names = extract_param_idents(&params_txt);
    let body = find_child_kind(node, "function_body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_route = parse_spring_kt_mapping(&mod_txt).map(|(verb, sub)| {
        let full = join_route_prefix(route_prefix, &sub);
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
    let sym_id = format!("kt:{}:{}:{}", ctx.rel_path, name, line_start);
    let mut sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        name,
        kind,
        line_start,
        line_end,
        &mod_txt,
        &params_txt,
        body,
        node,
        sym_route,
        &param_names,
    );
    sym.guards.extend(scope_guards.iter().copied());
    ctx.symbols.push(sym);

    // Also traverse inside function body so Ktor `routing { ... }` DSL blocks emit routes cleanly
    if let Some(b) = body {
        let mut c = b.walk();
        for ch in b.children(&mut c) {
            walk_node(ch, ctx, route_prefix, scope_guards);
        }
    }
}

fn handle_ktor_dsl_call(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    route_prefix: &str,
    scope_guards: &HashSet<GuardKind>,
) -> bool {
    let mut c = node.walk();
    let named: Vec<Node> = node.named_children(&mut c).collect();
    let Some(first) = named.first().copied() else {
        return false;
    };
    // Kotlin trailing-lambda syntax `post("/withdraw") { ... }` and `authenticate("jwt") { ... }`
    // nests the inner `call_expression` (`post("/withdraw")`) inside an outer `call_expression` with `annotated_lambda`.
    let (callee_node, args) = if first.kind() == "call_expression" {
        let mut ic = first.walk();
        let inner_first = first.named_children(&mut ic).next().unwrap_or(first);
        let inner_args = find_child_kind(first, "value_arguments")
            .or_else(|| find_child_kind(node, "value_arguments"));
        (inner_first, inner_args)
    } else {
        (first, find_child_kind(node, "value_arguments"))
    };
    let callee_txt = node_text(callee_node, ctx.src).trim();
    let callee_short = callee_txt.rsplit('.').next().unwrap_or(callee_txt).trim();
    let lambda = find_child_kind(node, "annotated_lambda");

    if callee_short == "routing" || callee_short == "authenticate" || callee_short == "route" {
        let mut next_guards = scope_guards.clone();
        if callee_short == "authenticate" {
            next_guards.insert(GuardKind::Auth);
        }
        let next_prefix = if callee_short == "route" {
            args.and_then(|a| find_first_string_literal(a, ctx.src))
                .map(|sub| join_route_prefix(route_prefix, &sub))
                .unwrap_or_else(|| route_prefix.to_string())
        } else {
            route_prefix.to_string()
        };
        if let Some(lam) = lambda {
            let mut lc = lam.walk();
            for ch in lam.children(&mut lc) {
                walk_node(ch, ctx, &next_prefix, &next_guards);
            }
            return true;
        }
        return false;
    }

    if let Some(verb) = http_verb_from_ident(callee_short)
        && let Some(a) = args
        && let Some(sub_path) = find_first_string_literal(a, ctx.src)
        && let Some(lam) = lambda
    {
        let full_path = join_route_prefix(route_prefix, &sub_path);
        let route_label = format!("{} {}", verb, full_path);
        if !ctx.route_prefixes.iter().any(|p| p == &full_path) {
            ctx.route_prefixes.push(full_path.clone());
        }
        let line_start = node.start_position().row + 1;
        let line_end = node.end_position().row + 1;
        let sym_id = format!("kt:route:{}:{}", ctx.rel_path, line_start);
        let full_txt = strip_comments(node_text(node, ctx.src));
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
        sym.guards.extend(scope_guards.iter().copied());
        ctx.symbols.push(sym);
        return true;
    }

    false
}

fn parse_spring_kt_mapping(mod_txt: &str) -> Option<(&'static str, String)> {
    const ANNS: &[(&str, &str)] = &[
        ("@GetMapping", "GET"),
        ("@PostMapping", "POST"),
        ("@PutMapping", "PUT"),
        ("@DeleteMapping", "DELETE"),
        ("@PatchMapping", "PATCH"),
        ("@RequestMapping", "ANY"),
    ];
    for &(ann, verb) in ANNS {
        if let Some(pos) = mod_txt.find(ann) {
            let after = &mod_txt[pos + ann.len()..];
            let sub = after
                .split('"')
                .nth(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "/".to_string());
            return Some((verb, sub));
        }
    }
    None
}
