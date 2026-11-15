use crate::ast::{GuardKind, ImportRef, SymbolInfo, SymbolKind, node_text};
use std::collections::HashSet;
use tree_sitter::Node;

use super::{
    ExtractContext, LangProfile, build_analyzed_symbol, extract_param_idents,
    find_first_string_literal, http_verb_from_ident, join_route_prefix, strip_quotes,
};

const PROFILE: LangProfile = LangProfile {
    id_prefix: "rb",
    taint_sources: &[
        "params[",
        "params.",
        "request.params",
        "request.query_parameters",
        "request.request_parameters",
        "request.raw_post",
        "request.body",
        "request.headers",
        "cookies[",
        "env[",
        "argv",
    ],
    tainted_param_markers: &[":params", "params"],
    sql_sinks: &[
        ".execute(",
        ".execute ",
        ".exec_query(",
        ".find_by_sql(",
        ".select_all(",
        ".where(",
        ".order(",
        ".group(",
        ".having(",
        ".joins(",
        ".from(",
        ".exec(",
    ],
    sql_sanitizers: &["sanitize_sql", ".quote(", ".to_i", "integer(", "float("],
    cmd_sinks: &[
        "system(",
        "system ",
        "exec(",
        "exec ",
        "open3.",
        "io.popen",
        "process.spawn",
        "kernel.system",
        "kernel.exec",
    ],
    cmd_sanitizers: &[
        "shellwords.escape",
        "shellwords.shellescape",
        "shellescape",
        ".to_i",
        "integer(",
    ],
    path_sinks: &[
        "file.read",
        "file.open",
        "file.write",
        "file.delete",
        "file.unlink",
        "io.read",
        "io.write",
        "send_file",
        "pathname.new",
    ],
    path_sanitizers: &[
        "file.basename",
        "file.expand_path",
        "cleanpath",
        "sanitize_filename",
    ],
    ssrf_sinks: &[
        "net::http",
        "httparty.",
        "faraday.",
        "restclient.",
        "uri.open",
        "excon.",
        "typhoeus.",
        "curb.",
    ],
    ssrf_sanitizers: &["uri.parse", "allowlist", "allowed_hosts", "valid_url"],
    xss_sinks: &[
        ".html_safe",
        "raw(",
        "erb.new",
        "render inline:",
        "render html:",
    ],
    xss_sanitizers: &[
        "erb::util.html_escape",
        "cgi.escapehtml",
        "sanitize(",
        "html_escape",
        "escape_once",
    ],
    ownership_markers: &[
        "current_user.",
        "@current_user.",
        "authorize ",
        "pundit",
        "cancancan",
    ],
    db_write_sinks: &[
        ".update!(",
        ".update(",
        ".save!",
        ".save",
        ".create!(",
        ".create(",
        ".destroy!",
        ".increment!",
        ".decrement!",
        ".update_columns(",
    ],
    db_crud_markers: &[
        "activerecord",
        ".find(",
        ".find_by",
        ".where(",
        ".update",
        ".save",
        ".create",
        ".destroy",
    ],
    extra_auth_guards: &[
        "authenticate_user!",
        "authenticate_admin!",
        "require_login",
        "authorize_request",
        "verify_jwt",
        "current_user",
    ],
    extra_lock_guards: &[
        "activerecord::base.transaction",
        ".transaction do",
        ".with_lock",
        ".lock(",
        "for update",
    ],
};

#[derive(Default)]
struct ControllerFilters {
    auth_global: bool,
    auth_only: HashSet<String>,
    auth_except: HashSet<String>,
    skip_auth_global: bool,
    skip_auth_only: HashSet<String>,
    csrf_global: bool,
    csrf_exempt_global: bool,
    csrf_exempt_only: HashSet<String>,
}

impl ControllerFilters {
    fn has_auth_for(&self, method_name: &str) -> bool {
        if self.skip_auth_global || self.skip_auth_only.contains(method_name) {
            return false;
        }
        if !self.auth_only.is_empty() {
            return self.auth_only.contains(method_name);
        }
        if !self.auth_except.is_empty() {
            return !self.auth_except.contains(method_name);
        }
        self.auth_global
    }

    fn is_csrf_exempt_for(&self, method_name: &str) -> bool {
        self.csrf_exempt_global || self.csrf_exempt_only.contains(method_name)
    }
}

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    let is_routes_file = ctx
        .rel_path
        .replace('\\', "/")
        .to_ascii_lowercase()
        .ends_with("routes.rb");
    walk_program(root, ctx, is_routes_file, "");
}

fn walk_program(node: Node, ctx: &mut ExtractContext<'_>, is_routes_file: bool, prefix: &str) {
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "module" => {
                if let Some(body) = ch.child_by_field_name("body") {
                    walk_program(body, ctx, is_routes_file, prefix);
                }
            }
            "class" => {
                extract_class(ch, ctx);
            }
            "method" | "singleton_method" => {
                if let Some(sym) = extract_ruby_method(ch, ctx, false, None) {
                    ctx.symbols.push(sym);
                }
            }
            "call" => {
                handle_top_call(ch, ctx, is_routes_file, prefix);
            }
            _ => {
                walk_program(ch, ctx, is_routes_file, prefix);
            }
        }
    }
}

fn find_call_block(node: Node) -> Option<Node> {
    node.child_by_field_name("block").or_else(|| {
        let mut c = node.walk();
        node.children(&mut c)
            .find(|ch| ch.kind() == "do_block" || ch.kind() == "block")
    })
}

fn find_block_body(block: Node) -> Option<Node> {
    block.child_by_field_name("body").or_else(|| {
        let mut c = block.walk();
        block
            .children(&mut c)
            .find(|ch| ch.kind() == "body_statement")
    })
}

fn handle_top_call(node: Node, ctx: &mut ExtractContext<'_>, is_routes_file: bool, prefix: &str) {
    let Some(method_node) = node.child_by_field_name("method") else {
        return;
    };
    let callee = node_text(method_node, ctx.src).trim();
    let line = node.start_position().row + 1;

    // 1. Ruby imports (`require` / `require_relative` / `load`)
    if matches!(callee, "require" | "require_relative" | "load")
        && let Some(args) = node.child_by_field_name("arguments")
        && let Some(raw_spec) = find_first_string_literal(args, ctx.src)
    {
        let clean = raw_spec.trim().trim_end_matches(".rb").to_string();
        let spec = if clean.starts_with('.') {
            clean
        } else {
            format!("rb::{}", clean.trim_start_matches("./"))
        };
        ctx.imports.push(ImportRef {
            symbol_name: "*".to_string(),
            from_specifier: spec,
            remote_name: None,
        });
        return;
    }

    let raw_call = node_text(node, ctx.src);
    let low_call = raw_call.to_ascii_lowercase();

    // 2. File-level protection declarations (e.g. Rack / Sinatra middleware or top-level filter)
    if low_call.contains("before_action") && low_call.contains("authenticate") {
        ctx.file_middleware_guards.insert(GuardKind::Auth);
    }
    if low_call.contains("protect_from_forgery") && !low_call.contains("null_session") {
        ctx.file_middleware_guards.insert(GuardKind::CsrfProtection);
    }

    // 3. Rails `routes.rb` namespace / scope prefixes
    if (is_routes_file || matches!(callee, "namespace" | "scope" | "draw"))
        && let Some(block) = find_call_block(node)
    {
        let mut next_prefix = prefix.to_string();
        if matches!(callee, "namespace" | "scope")
            && let Some(args) = node.child_by_field_name("arguments")
            && let Some(seg) = extract_route_segment(args, ctx.src)
        {
            next_prefix = join_route_prefix(prefix, &seg);
            if !ctx.route_prefixes.contains(&next_prefix) {
                ctx.route_prefixes.push(next_prefix.clone());
            }
        }
        if let Some(body) = find_block_body(block) {
            walk_program(body, ctx, is_routes_file, &next_prefix);
        }
        return;
    }

    // 4. HTTP route DSL (`get '/path' => 'ctrl#act'`, `post '/transfer' do ... end`)
    if let Some(verb) = http_verb_from_ident(callee) {
        let args_text = node
            .child_by_field_name("arguments")
            .map(|a| node_text(a, ctx.src))
            .unwrap_or("");
        let sub_path = node
            .child_by_field_name("arguments")
            .and_then(|a| find_first_string_literal(a, ctx.src))
            .unwrap_or_else(|| "/".to_string());
        let full_path = join_route_prefix(prefix, &sub_path);

        // Rails controller dispatch target (`to: 'orders#transfer'` or `=> 'orders#transfer'`)
        if let Some((ctrl, act)) = extract_controller_action(args_text) {
            let ctrl_stem = ctrl.trim_end_matches("_controller");
            let spec = format!("rb::{}_controller", ctrl_stem);
            ctx.imports.push(ImportRef {
                symbol_name: act.clone(),
                from_specifier: spec,
                remote_name: Some(act.clone()),
            });
            let mut guards = ctx.file_middleware_guards.clone();
            if raw_call.to_ascii_lowercase().contains("authenticate") {
                guards.insert(GuardKind::Auth);
            }
            ctx.symbols.push(SymbolInfo {
                id: format!("rb:{}:{}:route", ctx.rel_path, line),
                rel_path: ctx.rel_path.to_string(),
                name: format!("{} {}", verb, full_path),
                kind: SymbolKind::Route,
                sink_kind: None,
                line_start: line,
                line_end: node.end_position().row + 1,
                guards,
                calls: vec![act],
                route_path: Some(full_path),
                has_resource_id: full_path_has_id(&sub_path),
                ..Default::default()
            });
            return;
        }

        // Sinatra / Grape inline block route handler (`post '/transfer' do ... end`)
        if let Some(block) = find_call_block(node) {
            let body_node = find_block_body(block).or(Some(block));
            let params_text = block
                .child_by_field_name("parameters")
                .map(|p| node_text(p, ctx.src))
                .unwrap_or("");
            let param_names = extract_param_idents(params_text);
            let sym_name = format!("{} {}", verb, full_path);
            let sym = build_analyzed_symbol(
                ctx,
                &PROFILE,
                format!("rb:{}:{}", ctx.rel_path, line),
                sym_name,
                SymbolKind::Route,
                line,
                node.end_position().row + 1,
                "",
                params_text,
                body_node,
                node,
                Some(full_path),
                &param_names,
            );
            ctx.symbols.push(sym);
            return;
        }
    }

    // 5. Rails `resources :orders` standard REST dispatch
    if is_routes_file
        && callee == "resources"
        && let Some(args) = node.child_by_field_name("arguments")
        && let Some(res_name) = extract_route_segment(args, ctx.src)
    {
        let ctrl_name = format!("rb::{}_controller", res_name.trim_start_matches('/'));
        let base_path = join_route_prefix(prefix, &res_name);
        for (verb, act, suffix) in [
            ("GET", "show", "/:id"),
            ("POST", "create", ""),
            ("PATCH", "update", "/:id"),
            ("DELETE", "destroy", "/:id"),
        ] {
            let full_path = format!("{}{}", base_path, suffix);
            ctx.imports.push(ImportRef {
                symbol_name: act.to_string(),
                from_specifier: ctrl_name.clone(),
                remote_name: Some(act.to_string()),
            });
            ctx.symbols.push(SymbolInfo {
                id: format!("rb:{}:{}:{}:route", ctx.rel_path, line, act),
                rel_path: ctx.rel_path.to_string(),
                name: format!("{} {}", verb, full_path),
                kind: SymbolKind::Route,
                sink_kind: None,
                line_start: line,
                line_end: node.end_position().row + 1,
                guards: ctx.file_middleware_guards.clone(),
                calls: vec![act.to_string()],
                route_path: Some(full_path),
                has_resource_id: !suffix.is_empty(),
                ..Default::default()
            });
        }
        return;
    }

    // Recurse into any nested calls/blocks
    if let Some(block) = find_call_block(node)
        && let Some(body) = find_block_body(block)
    {
        walk_program(body, ctx, is_routes_file, prefix);
    }
}

fn extract_class(node: Node, ctx: &mut ExtractContext<'_>) {
    let class_name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_default();
    let superclass = node
        .child_by_field_name("superclass")
        .map(|n| node_text(n, ctx.src).trim().to_string())
        .unwrap_or_default();
    let is_controller = class_name.ends_with("Controller") || superclass.contains("Controller");

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };

    let mut filters = ControllerFilters::default();
    collect_controller_filters(body, ctx.src, &mut filters);
    if filters.csrf_global {
        ctx.file_middleware_guards.insert(GuardKind::CsrfProtection);
    }

    let mut in_private_section = false;
    let mut c = body.walk();
    for ch in body.children(&mut c) {
        let kind = ch.kind();
        if kind == "identifier" {
            let vis = node_text(ch, ctx.src).trim();
            if matches!(vis, "private" | "protected") {
                in_private_section = true;
            } else if vis == "public" {
                in_private_section = false;
            }
            continue;
        }
        match kind {
            "class" => extract_class(ch, ctx),
            "module" => {
                if let Some(sub_body) = ch.child_by_field_name("body") {
                    walk_program(sub_body, ctx, false, "");
                }
            }
            "method" | "singleton_method" => {
                let expose_as_controller_action = is_controller && !in_private_section;
                if let Some(sym) =
                    extract_ruby_method(ch, ctx, expose_as_controller_action, Some(&filters))
                {
                    ctx.symbols.push(sym);
                }
            }
            "call" => handle_top_call(ch, ctx, false, ""),
            _ => {}
        }
    }
}

fn collect_controller_filters(body: Node, src: &[u8], out: &mut ControllerFilters) {
    let mut c = body.walk();
    for ch in body.children(&mut c) {
        if ch.kind() != "call" {
            continue;
        }
        let text = node_text(ch, src).trim();
        let low = text.to_ascii_lowercase();
        let Some(m) = ch.child_by_field_name("method") else {
            continue;
        };
        let callee = node_text(m, src).trim();
        match callee {
            "before_action" | "before_filter" => {
                if low.contains("authenticate")
                    || low.contains("require_login")
                    || low.contains("authorize")
                {
                    let (only, except) = parse_only_except_actions(text);
                    if !only.is_empty() {
                        out.auth_only.extend(only);
                    } else if !except.is_empty() {
                        out.auth_except.extend(except);
                    } else {
                        out.auth_global = true;
                    }
                }
            }
            "skip_before_action" | "skip_before_filter" => {
                if low.contains("verify_authenticity_token") {
                    let (only, _) = parse_only_except_actions(text);
                    if only.is_empty() {
                        out.csrf_exempt_global = true;
                    } else {
                        out.csrf_exempt_only.extend(only);
                    }
                }
                if low.contains("authenticate") || low.contains("require_login") {
                    let (only, _) = parse_only_except_actions(text);
                    if only.is_empty() {
                        out.skip_auth_global = true;
                    } else {
                        out.skip_auth_only.extend(only);
                    }
                }
            }
            "protect_from_forgery" => {
                if low.contains("null_session") {
                    out.csrf_exempt_global = true;
                } else {
                    out.csrf_global = true;
                }
            }
            _ => {}
        }
    }
}

fn parse_only_except_actions(stmt: &str) -> (HashSet<String>, HashSet<String>) {
    let mut only = HashSet::new();
    let mut except = HashSet::new();
    let extract_syms = |slice: &str, dst: &mut HashSet<String>| {
        let bounded = if let Some(rb) = slice.find(']') {
            &slice[..rb]
        } else {
            slice.split(',').next().unwrap_or(slice)
        };
        for part in bounded.split(|c: char| c.is_whitespace() || c == '[' || c == ',' || c == '%') {
            let clean = part.trim().trim_start_matches(':').trim_matches(|c| {
                c == '\'' || c == '"' || c == ']' || c == ')' || c == 'i' || c == '('
            });
            if !clean.is_empty() && clean.chars().all(|c| c.is_alphanumeric() || c == '_') {
                dst.insert(clean.to_string());
            }
        }
    };
    if let Some(pos) = stmt.find("only:") {
        extract_syms(&stmt[pos + 5..], &mut only);
    }
    if let Some(pos) = stmt.find("except:") {
        extract_syms(&stmt[pos + 7..], &mut except);
    }
    (only, except)
}

fn extract_ruby_method(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    _is_controller_action: bool,
    filters: Option<&ControllerFilters>,
) -> Option<SymbolInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.src).trim().to_string())?;
    if name.is_empty() {
        return None;
    }
    let params_text = node
        .child_by_field_name("parameters")
        .map(|n| node_text(n, ctx.src))
        .unwrap_or("");
    let body_node = node.child_by_field_name("body");
    let param_names = extract_param_idents(params_text);
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    let mut sym = build_analyzed_symbol(
        ctx,
        &PROFILE,
        format!("rb:{}:{}:{}", ctx.rel_path, name, line_start),
        name.clone(),
        SymbolKind::Function,
        line_start,
        line_end,
        "",
        params_text,
        body_node,
        node,
        None,
        &param_names,
    );

    if let Some(flt) = filters {
        if flt.has_auth_for(&name) {
            sym.guards.insert(GuardKind::Auth);
        }
        if flt.csrf_global {
            sym.guards.insert(GuardKind::CsrfProtection);
        }
        if flt.is_csrf_exempt_for(&name) {
            sym.csrf_exempt = true;
            sym.guards.remove(&GuardKind::CsrfProtection);
        }
    }

    Some(sym)
}

fn extract_route_segment(args: Node, src: &[u8]) -> Option<String> {
    if let Some(lit) = find_first_string_literal(args, src) {
        return Some(lit);
    }
    let raw = node_text(args, src);
    for tok in raw.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')') {
        let t = tok.trim();
        if let Some(sym) = t.strip_prefix(':') {
            let clean = sym.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

fn extract_controller_action(args_text: &str) -> Option<(String, String)> {
    for part in args_text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')') {
        let cleaned = strip_quotes(part);
        if let Some((ctrl, act)) = cleaned.split_once('#') {
            let c = ctrl.trim().trim_start_matches('/');
            let a = act.trim();
            if !c.is_empty()
                && !a.is_empty()
                && a.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
            {
                return Some((c.to_string(), a.to_string()));
            }
        }
    }
    None
}

fn full_path_has_id(path: &str) -> bool {
    path.contains(":id") || path.contains("_id") || path.contains('{')
}
