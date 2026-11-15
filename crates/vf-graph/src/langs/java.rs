use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents, join_route_prefix,
    strip_quotes,
};
use crate::ast::{GuardKind, ImportRef, SymbolKind, node_text};
use std::collections::HashSet;
use tree_sitter::Node;

pub(crate) const PROFILE: LangProfile = LangProfile {
    id_prefix: "java",
    taint_sources: &[
        ".getparameter(",
        ".getparametervalues(",
        ".getheader(",
        ".getquerystring(",
        "@requestparam",
        "@pathvariable",
        "@requestbody",
        "@queryparam",
        "@headerparam",
    ],
    tainted_param_markers: &[
        "@RequestParam",
        "@PathVariable",
        "@RequestBody",
        "@QueryParam",
        "@HeaderParam",
    ],
    sql_sinks: &[
        ".executequery(",
        ".executeupdate(",
        ".execute(",
        "createnativequery(",
        "jdbctemplate.query(",
        "jdbctemplate.execute(",
        "createsqlquery(",
    ],
    sql_sanitizers: &[
        "preparedstatement",
        "preparestatement(",
        ".setparameter(",
        ".setstring(",
        ".setlong(",
        ".setint(",
    ],
    cmd_sinks: &["getruntime().exec(", ".exec(", "new processbuilder("],
    cmd_sanitizers: &["commandallowlist", "allowedcommands"],
    path_sinks: &[
        "files.readstring(",
        "files.readallbytes(",
        "files.write(",
        "new file(",
        "new fileinputstream(",
        "paths.get(",
    ],
    path_sanitizers: &[
        ".normalize().startswith(",
        "getcanonicalpath(",
        "filenameutils.getname(",
    ],
    ssrf_sinks: &[
        "openconnection(",
        "openstream(",
        "resttemplate.",
        "webclient.",
        "httpclient.",
        "new url(",
    ],
    ssrf_sanitizers: &["allowedhosts", "validateurl", "isvalidhost"],
    xss_sinks: &["getwriter().print", "getwriter().write("],
    xss_sanitizers: &["htmlescape(", "escapehtml(", "encoder.forhtml("],
    ownership_markers: &[
        "principal.getname",
        "securitycontextholder",
        "getcurrentuserid",
        "ownerid",
        "userid",
        "tenantid",
    ],
    db_write_sinks: &[
        ".save(",
        ".saveandflush(",
        ".executeupdate(",
        "jdbctemplate.update(",
        "entitymanager.persist(",
        "entitymanager.merge(",
    ],
    db_crud_markers: &[
        "repository.",
        "entitymanager.",
        "jdbctemplate.",
        "executequery",
        "executeupdate",
    ],
    extra_auth_guards: &[
        "@preauthorize",
        "@secured",
        "@rolesallowed",
        "@authenticated",
        "securitycontextholder",
    ],
    extra_lock_guards: &[
        "@transactional",
        "pessimistic_write",
        "reentrantlock",
        "synchronized",
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

    if k == "import_declaration" {
        let raw = node_text(node, ctx.src)
            .trim()
            .trim_start_matches("import ")
            .trim_start_matches("static ")
            .trim_end_matches(';')
            .trim();
        if !raw.is_empty() && !raw.starts_with("java.") && !raw.starts_with("javax.") {
            let trimmed = raw.trim_end_matches(".*");
            ctx.imports.push(ImportRef {
                symbol_name: "*".to_string(),
                from_specifier: format!("java::{}", trimmed.replace('.', "/")),
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
        let mod_txt = find_modifiers_text(node, ctx.src);
        let mut class_guards = scope_guards.clone();
        class_guards.extend(super::detect_text_guards(&mod_txt, ctx.cfg, &PROFILE));

        let class_prefix = parse_spring_mapping(&mod_txt)
            .map(|(_, p)| join_route_prefix(route_prefix, &p))
            .unwrap_or_else(|| route_prefix.to_string());

        if let Some(body) = node.child_by_field_name("body") {
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                match ch.kind() {
                    "method_declaration" => {
                        extract_method(ch, ctx, &class_prefix, &class_guards);
                    }
                    "class_declaration" => walk_node(ch, ctx, &class_prefix, &class_guards),
                    _ => {}
                }
            }
        }
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_node(ch, ctx, route_prefix, scope_guards);
    }
}

fn find_modifiers_text(node: Node, src: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if matches!(ch.kind(), "modifiers" | "annotation" | "marker_annotation") {
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
    let mod_txt = find_modifiers_text(node, ctx.src);
    if mod_txt.contains("@Test") || mod_txt.contains("@ParameterizedTest") {
        return;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_else(|| "method".to_string());
    let params_txt = node
        .child_by_field_name("parameters")
        .map(|p| node_text(p, ctx.src))
        .unwrap_or("");
    let param_names = extract_param_idents(params_txt);
    let body = node.child_by_field_name("body");
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let sym_route = parse_spring_mapping(&mod_txt).map(|(verb, sub)| {
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
    let sym_id = format!("java:{}:{}:{}", ctx.rel_path, name, line_start);
    let mut sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        sym_id,
        name,
        kind,
        line_start,
        line_end,
        &mod_txt,
        params_txt,
        body,
        node,
        sym_route,
        &param_names,
    );
    sym.guards.extend(class_guards.iter().copied());
    ctx.symbols.push(sym);
}

fn parse_spring_mapping(mod_txt: &str) -> Option<(&'static str, String)> {
    const MAPPINGS: &[(&str, &str)] = &[
        ("@GetMapping", "GET"),
        ("@PostMapping", "POST"),
        ("@PutMapping", "PUT"),
        ("@DeleteMapping", "DELETE"),
        ("@PatchMapping", "PATCH"),
        ("@RequestMapping", "ANY"),
    ];
    for &(ann, default_verb) in MAPPINGS {
        if let Some(pos) = mod_txt.find(ann) {
            let after = &mod_txt[pos + ann.len()..];
            let sub = if let Some(rest) = after.trim_start().strip_prefix('(') {
                let inside = rest.split(')').next().unwrap_or("");
                if let Some(vpos) = inside.find('"') {
                    inside[vpos..]
                        .split('"')
                        .nth(1)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "/".to_string())
                } else {
                    "/".to_string()
                }
            } else {
                "/".to_string()
            };
            let verb = if default_verb == "ANY" {
                let up = after.to_ascii_uppercase();
                if up.contains("POST") {
                    "POST"
                } else if up.contains("PUT") {
                    "PUT"
                } else if up.contains("DELETE") {
                    "DELETE"
                } else if up.contains("PATCH") {
                    "PATCH"
                } else {
                    "GET"
                }
            } else {
                default_verb
            };
            return Some((verb, sub));
        }
    }
    // JAX-RS `@Path("/orders")` + `@POST` / `@GET`
    if let Some(pos) = mod_txt.find("@Path(") {
        let after = &mod_txt[pos + 6..];
        let path = after
            .split(')')
            .next()
            .map(strip_quotes)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/".to_string());
        let verb = if mod_txt.contains("@POST") {
            "POST"
        } else if mod_txt.contains("@PUT") {
            "PUT"
        } else if mod_txt.contains("@DELETE") {
            "DELETE"
        } else if mod_txt.contains("@PATCH") {
            "PATCH"
        } else {
            "GET"
        };
        return Some((verb, path));
    }
    None
}
