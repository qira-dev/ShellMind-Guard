use crate::ast::{FrontendApiCall, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;
use tree_sitter::Node;
use vf_core::Language;

#[derive(Debug, Default)]
pub struct FunctionTaintSummary {
    pub guards: HashSet<GuardKind>,
    pub has_taint_source: bool,
    pub has_resource_id: bool,
    pub has_db_crud_sink: bool,
    pub db_crud_line: Option<usize>,
    pub tainted_calls: Vec<String>,
    pub param_forwarding_calls: Vec<String>,
    pub local_taint_hits: Vec<LocalStaticFinding>,
    pub param_sinks: Vec<LocalStaticFinding>,
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").expect("valid ident regex"))
}

fn params_mask_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:req\.params\.[A-Za-z0-9_]+|c\.Param\s*\([^)]*\)|r\.PathValue\s*\([^)]*\))"#,
        )
        .expect("valid params mask regex")
    })
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

fn strip_comments_simple(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut cut = line;
        if let Some(pos) = cut.find("//")
            && (pos == 0 || cut.as_bytes()[pos - 1] != b':')
        {
            cut = &cut[..pos];
        }
        if let Some(pos) = cut.find('#')
            && !cut[pos..].starts_with("#[")
        {
            cut = &cut[..pos];
        }
        out.push_str(cut);
        out.push('\n');
    }
    out
}

pub fn has_taint_source_expr(text: &str) -> bool {
    const SOURCES: &[&str] = &[
        "req.body",
        "req.query",
        "req.params",
        "req.headers",
        "request.body",
        "request.query",
        "request.params",
        "request.args",
        "request.json",
        "request.form",
        "request.values",
        "request.data",
        "c.Param(",
        "c.Query(",
        "c.DefaultQuery(",
        "c.PostForm(",
        "c.BindJSON(",
        "c.ShouldBindJSON(",
        "r.URL.Query(",
        "r.FormValue(",
        "r.PathValue(",
        "ctx.query",
        "ctx.params",
        "ctx.request.body",
        "c.req.query",
        "c.req.param",
        "c.req.json",
        "searchParams.get",
        "web::Query",
        "web::Path",
        "web::Json",
    ];
    SOURCES.iter().any(|s| text.contains(s))
}

pub fn has_resource_id_expr(text: &str, route_path: Option<&str>) -> bool {
    if let Some(rp) = route_path
        && (rp.contains("/:") || rp.contains("/{") || rp.contains("/[") || rp.contains('<'))
    {
        return true;
    }
    const ID_SOURCES: &[&str] = &[
        "req.params.",
        "req.params[",
        "c.Param(",
        "r.PathValue(",
        "request.view_args",
        "Path<",
        "web::Path",
    ];
    ID_SOURCES.iter().any(|s| text.contains(s))
}

pub fn has_ownership_filter(code: &str) -> bool {
    let cleaned = strip_comments_simple(code);
    let masked = params_mask_re().replace_all(&cleaned, "");
    let low = masked.to_ascii_lowercase();
    const OWNERSHIP_TOKENS: &[&str] = &[
        "req.user",
        "request.user",
        "session.user",
        "current_user",
        "currentuser",
        "auth.uid",
        "claims.",
        "owner_id =",
        "owner_id=",
        "owner_id:",
        "ownerid:",
        "tenant_id =",
        "tenant_id=",
        "tenant_id:",
        "tenantid:",
        "org_id =",
        "org_id=",
        "org_id:",
        "orgid:",
        "created_by =",
        "created_by=",
        "user_id =",
        "user_id=",
        "user_id:",
        "userid:",
        "account_id =",
        "account_id=",
        "account_id:",
        "accountid:",
        "and user_id",
        "and userid",
        "and owner_id",
        "and tenant_id",
    ];
    OWNERSHIP_TOKENS.iter().any(|t| low.contains(t))
}

fn is_universal_sanitizer(expr: &str) -> bool {
    const SANITIZERS: &[&str] = &[
        "strconv.Atoi(",
        "strconv.ParseInt(",
        "strconv.ParseUint(",
        "parseInt(",
        "Number(",
        "z.object(",
        "z.string(",
        "z.number(",
        ".safeParse(",
        ".parse(",
        "Joi.",
        ".validate(",
        "validateOrReject(",
        "Uuid::parse_str(",
        ".parse::<i",
        ".parse::<u",
    ];
    SANITIZERS.iter().any(|s| expr.contains(s))
}

fn expr_has_path_sanitizer(expr: &str) -> bool {
    const PATH_SAN: &[&str] = &[
        "filepath.Clean(",
        "filepath.Base(",
        "path.basename(",
        "os.path.basename(",
        "os.path.realpath(",
        ".startsWith(",
        "strings.HasPrefix(",
        ".starts_with(",
    ];
    PATH_SAN.iter().any(|s| expr.contains(s)) || is_universal_sanitizer(expr)
}

fn expr_has_ssrf_sanitizer(expr: &str) -> bool {
    let low = expr.to_ascii_lowercase();
    low.contains("allowlist")
        || low.contains("whitelist")
        || low.contains("allowed_hosts")
        || low.contains("allowedhosts")
        || low.contains("isallowedhost")
        || low.contains("validateurl")
        || is_universal_sanitizer(expr)
}

fn expr_has_cmd_sanitizer(expr: &str) -> bool {
    expr.contains("shlex.quote(")
        || expr.contains("shellEscape(")
        || expr.to_ascii_lowercase().contains("allowlist")
        || is_universal_sanitizer(expr)
}

fn extract_param_names(fn_node: Node, src: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return out;
    };
    collect_param_idents(params, src, &mut out);
    for fw in [
        "req", "res", "next", "ctx", "c", "w", "r", "self", "request", "response", "err",
    ] {
        out.remove(fw);
    }
    out
}

fn collect_param_idents(node: Node, src: &[u8], out: &mut HashSet<String>) {
    let k = node.kind();
    if matches!(k, "identifier" | "shorthand_property_identifier_pattern") {
        let name = node_text(node, src).trim();
        if !name.is_empty() && name != "_" {
            out.insert(name.to_string());
        }
        return;
    }
    if k == "parameter_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, src).trim();
            if !name.is_empty() && name != "_" {
                out.insert(name.to_string());
            }
        }
        return;
    }
    if matches!(
        k,
        "type_annotation" | "generic_type" | "pointer_type" | "qualified_type"
    ) {
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_param_idents(ch, src, out);
    }
}

fn expr_references_any(expr: &str, vars: &HashSet<String>) -> bool {
    if vars.is_empty() {
        return false;
    }
    for cap in ident_re().captures_iter(expr) {
        if vars.contains(&cap[1]) {
            return true;
        }
    }
    false
}

fn extract_assigned_targets(stmt: Node, src: &[u8]) -> Option<(Vec<String>, String)> {
    let k = stmt.kind();
    match k {
        "lexical_declaration" | "variable_declaration" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                if ch.kind() == "variable_declarator"
                    && let (Some(n), Some(v)) = (
                        ch.child_by_field_name("name"),
                        ch.child_by_field_name("value"),
                    )
                {
                    let mut names = Vec::new();
                    for cap in ident_re().captures_iter(node_text(n, src)) {
                        names.push(cap[1].to_string());
                    }
                    return Some((names, node_text(v, src).to_string()));
                }
            }
            None
        }
        "expression_statement" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                if matches!(ch.kind(), "assignment_expression" | "assignment")
                    && let (Some(l), Some(r)) = (
                        ch.child_by_field_name("left"),
                        ch.child_by_field_name("right"),
                    )
                {
                    let mut names = Vec::new();
                    for cap in ident_re().captures_iter(node_text(l, src)) {
                        names.push(cap[1].to_string());
                    }
                    return Some((names, node_text(r, src).to_string()));
                }
            }
            None
        }
        "short_var_declaration" | "assignment_statement" | "assignment" => {
            let left = stmt.child_by_field_name("left")?;
            let right = stmt.child_by_field_name("right")?;
            let mut names = Vec::new();
            for cap in ident_re().captures_iter(node_text(left, src)) {
                let id = &cap[1];
                if id != "_" && id != "err" {
                    names.push(id.to_string());
                }
            }
            Some((names, node_text(right, src).to_string()))
        }
        "let_declaration" => {
            let pat = stmt.child_by_field_name("pattern")?;
            let val = stmt.child_by_field_name("value")?;
            let mut names = Vec::new();
            for cap in ident_re().captures_iter(node_text(pat, src)) {
                if &cap[1] != "mut" {
                    names.push(cap[1].to_string());
                }
            }
            Some((names, node_text(val, src).to_string()))
        }
        "var_declaration" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                if ch.kind() == "var_spec"
                    && let (Some(n), Some(v)) = (
                        ch.child_by_field_name("name"),
                        ch.child_by_field_name("value"),
                    )
                {
                    let mut names = Vec::new();
                    for cap in ident_re().captures_iter(node_text(n, src)) {
                        names.push(cap[1].to_string());
                    }
                    return Some((names, node_text(v, src).to_string()));
                }
            }
            None
        }
        _ => None,
    }
}

fn is_db_crud_stmt(code: &str) -> bool {
    let low = code.to_ascii_lowercase();
    if low.contains("db.delete(")
        || low.contains("db.update(")
        || low.contains("db.select(")
        || low.contains("db.find(")
        || low.contains("db.get(")
        || low.contains("db.query(")
        || low.contains("db.queryrow(")
        || low.contains("db.exec(")
        || low.contains("tx.exec(")
        || low.contains("pool.query(")
        || low.contains("client.query(")
        || low.contains(".findbyid(")
        || low.contains(".findbyidandupdate(")
        || low.contains(".findbyidanddelete(")
        || low.contains(".findone(")
        || low.contains(".destroy(")
        || low.contains(".filter_by(")
        || low.contains(".objects.get(")
        || low.contains(".objects.filter(")
        || low.contains("cursor.execute(")
        || low.contains("session.query(")
        || (low.contains("prisma.")
            && (low.contains(".findunique(")
                || low.contains(".findfirst(")
                || low.contains(".update(")
                || low.contains(".delete(")))
    {
        return true;
    }
    if (low.contains("select ") && low.contains(" from ") && low.contains(" where "))
        || (low.contains("update ") && low.contains(" set ") && low.contains(" where "))
        || (low.contains("delete from ") && low.contains(" where "))
    {
        return true;
    }
    false
}

#[derive(Clone, Copy)]
enum TaintSourceKind {
    Direct,
    Param,
}

fn stmt_taint_status(
    text: &str,
    tainted_vars: &HashSet<String>,
    param_vars: &HashSet<String>,
) -> Option<TaintSourceKind> {
    if has_taint_source_expr(text) || expr_references_any(text, tainted_vars) {
        Some(TaintSourceKind::Direct)
    } else if expr_references_any(text, param_vars) {
        Some(TaintSourceKind::Param)
    } else {
        None
    }
}

fn has_dynamic_sql_interpolation(node: Node, src: &[u8]) -> bool {
    let k = node.kind();
    let txt = node_text(node, src);
    if !sql_verb_re().is_match(txt) {
        return false;
    }
    if k == "template_string" && txt.contains("${") {
        return true;
    }
    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        if ftxt == "fmt.Sprintf" || ftxt.ends_with(".Sprintf") || ftxt.ends_with(".format") {
            return true;
        }
    }
    if k == "macro_invocation" && txt.starts_with("format!") {
        return true;
    }
    if k == "string" && txt.contains('{') && (txt.starts_with("f\"") || txt.starts_with("f'")) {
        return true;
    }
    if matches!(k, "binary_expression" | "binary_operator")
        && (txt.contains('+') || txt.contains('%'))
    {
        // Confirm at least one child is a string literal with SQL verb
        let mut c = node.walk();
        let mut has_sql_lit = false;
        let mut has_non_lit = false;
        for ch in node.children(&mut c) {
            let ck = ch.kind();
            if matches!(
                ck,
                "string" | "string_literal" | "interpreted_string_literal"
            ) {
                if sql_verb_re().is_match(node_text(ch, src)) {
                    has_sql_lit = true;
                }
            } else if !matches!(ck, "+" | "%") {
                has_non_lit = true;
            }
        }
        if has_sql_lit && has_non_lit {
            return true;
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if has_dynamic_sql_interpolation(ch, src) {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn check_call_taint_sinks(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    tainted_vars: &HashSet<String>,
    param_vars: &HashSet<String>,
    fn_guards: &HashSet<GuardKind>,
    summary: &mut FunctionTaintSummary,
) {
    let k = node.kind();

    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let short = ftxt.rsplit('.').next().unwrap_or(ftxt);
        let short = short.rsplit("::").next().unwrap_or(short);
        let args_txt = node
            .child_by_field_name("arguments")
            .map(|a| node_text(a, src))
            .unwrap_or("");
        let line = node.start_position().row + 1;

        // Track tainted call-arg forwarding to other functions
        if !short.is_empty() {
            if has_taint_source_expr(args_txt) || expr_references_any(args_txt, tainted_vars) {
                if !summary.tainted_calls.iter().any(|c| c == short) {
                    summary.tainted_calls.push(short.to_string());
                }
            } else if expr_references_any(args_txt, param_vars)
                && !summary.param_forwarding_calls.iter().any(|c| c == short)
            {
                summary.param_forwarding_calls.push(short.to_string());
            }
        }

        // 1. Command Injection (VF-CMDI-001)
        let is_shell_exec = matches!(
            ftxt,
            "exec" | "execSync" | "child_process.exec" | "child_process.execSync"
        ) || ftxt.ends_with(".execSync")
            || (ftxt.ends_with(".exec")
                && !ftxt.starts_with("db.")
                && !ftxt.starts_with("tx.")
                && !ftxt.starts_with("stmt.")
                && !ftxt.starts_with("re.")
                && !ftxt.starts_with("regex.")
                && !ftxt.starts_with("pattern."))
            || ((short == "spawn" || short == "spawnSync" || short == "execFile")
                && args_txt.contains("shell")
                && args_txt.contains("true"))
            || ((ftxt == "exec.Command" || ftxt == "exec.CommandContext")
                && (args_txt.contains("\"-c\"") || args_txt.contains("'/c'")))
            || (ftxt.starts_with("subprocess.") && args_txt.contains("shell=True"))
            || matches!(ftxt, "os.system" | "os.popen")
            || (ftxt == "Command::new"
                && (args_txt.contains("\"sh\"") || args_txt.contains("\"bash\"")));

        if is_shell_exec
            && !fn_guards.contains(&GuardKind::CmdSanitizer)
            && !expr_has_cmd_sanitizer(args_txt)
            && let Some(tkind) = stmt_taint_status(args_txt, tainted_vars, param_vars)
        {
            let hit = LocalStaticFinding {
                    rule_id: "VF-CMDI-001".into(),
                    severity: "CRITICAL".into(),
                    title: format!("OS Command Injection via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    remediation: "Avoid invoking a shell; use `execFile`/`spawn` with an argument array (`shell: false`) or strict input allowlisting.".into(),
                };
            match tkind {
                TaintSourceKind::Direct => summary.local_taint_hits.push(hit),
                TaintSourceKind::Param => summary.param_sinks.push(hit),
            }
        }

        // 2. Path Traversal (VF-PATH-001)
        let is_fs_sink = matches!(
            ftxt,
            "fs.readFile"
                | "fs.readFileSync"
                | "fs.promises.readFile"
                | "fs.writeFile"
                | "fs.writeFileSync"
                | "fs.unlink"
                | "fs.unlinkSync"
                | "fs.rm"
                | "res.sendFile"
                | "sendFile"
                | "os.Open"
                | "os.ReadFile"
                | "os.WriteFile"
                | "os.Remove"
                | "ioutil.ReadFile"
                | "http.ServeFile"
                | "fs::read"
                | "fs::read_to_string"
                | "fs::File::open"
                | "fs::remove_file"
                | "send_file"
        ) || (lang == Language::Python && ftxt == "open");

        if is_fs_sink
            && !fn_guards.contains(&GuardKind::PathSanitizer)
            && !expr_has_path_sanitizer(args_txt)
            && let Some(tkind) = stmt_taint_status(args_txt, tainted_vars, param_vars)
        {
            let hit = LocalStaticFinding {
                    rule_id: "VF-PATH-001".into(),
                    severity: "HIGH".into(),
                    title: format!("Arbitrary Path Traversal via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::PathTraversal,
                    missing_guard: GuardKind::PathSanitizer,
                    remediation: "Normalize the path with `path.basename` / `filepath.Base` and verify `resolvedPath.startsWith(baseDir)` before accessing the filesystem.".into(),
                };
            match tkind {
                TaintSourceKind::Direct => summary.local_taint_hits.push(hit),
                TaintSourceKind::Param => summary.param_sinks.push(hit),
            }
        }

        // 3. SSRF (VF-SSRF-001)
        let is_http_sink = matches!(
            ftxt,
            "fetch"
                | "axios"
                | "axios.get"
                | "axios.post"
                | "axios.put"
                | "axios.delete"
                | "axios.request"
                | "got"
                | "http.Get"
                | "http.Post"
                | "http.NewRequest"
                | "requests.get"
                | "requests.post"
                | "requests.request"
                | "httpx.get"
                | "urllib.request.urlopen"
                | "reqwest::get"
        );
        let trimmed_args = args_txt.trim_start_matches('(').trim();
        let is_relative_api_url = trimmed_args.starts_with("\"/")
            || trimmed_args.starts_with("'/")
            || trimmed_args.starts_with("`/");

        if is_http_sink
            && !is_relative_api_url
            && !fn_guards.contains(&GuardKind::SsrfSanitizer)
            && !expr_has_ssrf_sanitizer(args_txt)
            && let Some(tkind) = stmt_taint_status(args_txt, tainted_vars, param_vars)
        {
            let hit = LocalStaticFinding {
                    rule_id: "VF-SSRF-001".into(),
                    severity: "HIGH".into(),
                    title: format!("Server-Side Request Forgery (SSRF) via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::Ssrf,
                    missing_guard: GuardKind::SsrfSanitizer,
                    remediation: "Parse the URL and enforce an explicit hostname allowlist while blocking loopback/private/link-local IP ranges (169.254.0.0/16, 10.0.0.0/8, 127.0.0.1).".into(),
                };
            match tkind {
                TaintSourceKind::Direct => summary.local_taint_hits.push(hit),
                TaintSourceKind::Param => summary.param_sinks.push(hit),
            }
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        check_call_taint_sinks(
            ch,
            src,
            rel_path,
            lang,
            symbol_name,
            tainted_vars,
            param_vars,
            fn_guards,
            summary,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_statement_block(
    block: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    tainted_vars: &mut HashSet<String>,
    param_vars: &mut HashSet<String>,
    summary: &mut FunctionTaintSummary,
) {
    let mut cursor = block.walk();
    for stmt in block.children(&mut cursor) {
        let sk = stmt.kind();
        if matches!(sk, "{" | "}" | "comment" | "line_comment" | "block_comment") {
            continue;
        }
        let stmt_txt = node_text(stmt, src);
        let stmt_code = strip_comments_simple(stmt_txt);

        if has_taint_source_expr(&stmt_code) {
            summary.has_taint_source = true;
        }
        if has_resource_id_expr(&stmt_code, None) {
            summary.has_resource_id = true;
        }
        if has_ownership_filter(&stmt_code) {
            summary.guards.insert(GuardKind::OwnershipCheck);
        }
        if expr_has_path_sanitizer(&stmt_code) {
            summary.guards.insert(GuardKind::PathSanitizer);
        }
        if expr_has_ssrf_sanitizer(&stmt_code) {
            summary.guards.insert(GuardKind::SsrfSanitizer);
        }
        if expr_has_cmd_sanitizer(&stmt_code) {
            summary.guards.insert(GuardKind::CmdSanitizer);
        }
        if is_universal_sanitizer(&stmt_code) {
            summary.guards.insert(GuardKind::SqlSanitizer);
        }
        if is_db_crud_stmt(&stmt_code) {
            summary.has_db_crud_sink = true;
            if summary.db_crud_line.is_none() {
                summary.db_crud_line = Some(stmt.start_position().row + 1);
            }
        }

        // Check SQL injection dynamic construction in statement
        if has_dynamic_sql_interpolation(stmt, src) && !is_universal_sanitizer(&stmt_code) {
            let line = stmt.start_position().row + 1;
            if let Some(tkind) = stmt_taint_status(&stmt_code, tainted_vars, param_vars) {
                let hit = LocalStaticFinding {
                    rule_id: "VF-SQLI-001".into(),
                    severity: "CRITICAL".into(),
                    title: format!("SQL Injection via unsanitized string interpolation in `{}`", symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::SqlInjection,
                    missing_guard: GuardKind::SqlSanitizer,
                    remediation: "Use parameterized queries (`$1`, `?`, or ORM query builders) instead of interpolating untrusted input into SQL strings.".into(),
                };
                match tkind {
                    TaintSourceKind::Direct => summary.local_taint_hits.push(hit),
                    TaintSourceKind::Param => summary.param_sinks.push(hit),
                }
            }
        }

        // Check CMDi, Path Traversal, SSRF, and tainted callee forwarding
        check_call_taint_sinks(
            stmt,
            src,
            rel_path,
            lang,
            symbol_name,
            tainted_vars,
            param_vars,
            &summary.guards.clone(),
            summary,
        );

        // Update local variable taint state after evaluating RHS
        if let Some((lhs_names, rhs_txt)) = extract_assigned_targets(stmt, src) {
            if is_universal_sanitizer(&rhs_txt) {
                for n in &lhs_names {
                    tainted_vars.remove(n);
                    param_vars.remove(n);
                }
            } else if has_taint_source_expr(&rhs_txt) || expr_references_any(&rhs_txt, tainted_vars)
            {
                for n in lhs_names {
                    tainted_vars.insert(n);
                }
            } else if expr_references_any(&rhs_txt, param_vars) {
                for n in lhs_names {
                    param_vars.insert(n);
                }
            }
        }

        // Recurse into control-flow sub-blocks (`if`, `else`, `try`, `for`, etc.)
        if matches!(
            sk,
            "if_statement"
                | "else_clause"
                | "try_statement"
                | "except_clause"
                | "finally_clause"
                | "for_statement"
                | "while_statement"
                | "block"
        ) {
            let mut sub = stmt.walk();
            for ch in stmt.children(&mut sub) {
                if matches!(
                    ch.kind(),
                    "statement_block"
                        | "block"
                        | "if_statement"
                        | "else_clause"
                        | "try_statement"
                        | "catch_clause"
                        | "except_clause"
                        | "finally_clause"
                ) {
                    analyze_statement_block(
                        ch,
                        src,
                        rel_path,
                        lang,
                        symbol_name,
                        tainted_vars,
                        param_vars,
                        summary,
                    );
                }
            }
        }
    }
}

/// Runs intra-procedural taint, sanitizer, ownership, and DB CRUD extraction on a function or inline handler AST node.
pub fn analyze_function_taint(
    fn_node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    route_path: Option<&str>,
) -> FunctionTaintSummary {
    let mut summary = FunctionTaintSummary::default();
    let fn_code = strip_comments_simple(node_text(fn_node, src));

    if has_taint_source_expr(&fn_code) {
        summary.has_taint_source = true;
    }
    if has_resource_id_expr(&fn_code, route_path) {
        summary.has_resource_id = true;
    }
    let body_code = fn_node
        .child_by_field_name("body")
        .map(|b| strip_comments_simple(node_text(b, src)))
        .unwrap_or_default();
    if has_ownership_filter(&body_code) {
        summary.guards.insert(GuardKind::OwnershipCheck);
    }

    let mut tainted_vars = HashSet::new();
    let mut param_vars = extract_param_names(fn_node, src);

    if let Some(body) = fn_node.child_by_field_name("body") {
        if matches!(body.kind(), "statement_block" | "block") {
            analyze_statement_block(
                body,
                src,
                rel_path,
                lang,
                symbol_name,
                &mut tainted_vars,
                &mut param_vars,
                &mut summary,
            );
        } else {
            // Expression-bodied arrow function `(req, res) => execSync(...)`
            analyze_statement_block(
                fn_node,
                src,
                rel_path,
                lang,
                symbol_name,
                &mut tainted_vars,
                &mut param_vars,
                &mut summary,
            );
        }
    }

    summary
}

pub fn normalize_api_path(raw: &str) -> String {
    let without_query = raw.split('?').next().unwrap_or(raw).trim();
    if without_query.is_empty() {
        return "/".to_string();
    }
    let mut segs: Vec<String> = Vec::new();
    for seg in without_query.split('/').filter(|s| !s.is_empty()) {
        if seg.starts_with(':')
            || (seg.starts_with('{') && seg.ends_with('}'))
            || (seg.starts_with('[') && seg.ends_with(']'))
            || seg.contains("${")
            || (seg.starts_with('<') && seg.ends_with('>'))
        {
            segs.push("*".to_string());
        } else {
            segs.push(seg.to_string());
        }
    }
    format!("/{}", segs.join("/"))
}

fn has_ancestor_kind(node: Node, target_kind: &str) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == target_kind {
            return true;
        }
        if matches!(
            p.kind(),
            "function_declaration" | "arrow_function" | "function_expression" | "method_definition"
        ) {
            break;
        }
        cur = p.parent();
    }
    false
}

fn has_dot_catch_chain(node: Node, src: &[u8]) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        let txt = node_text(p, src);
        if txt.contains(".catch(") {
            return true;
        }
        if matches!(
            p.kind(),
            "statement_block"
                | "expression_statement"
                | "lexical_declaration"
                | "function_declaration"
        ) {
            break;
        }
        cur = p.parent();
    }
    false
}

/// Extracts frontend `/api/...` calls (`VF-FE-404` candidates) and UI/async functional bugs (`VF-FE-ERR`).
pub fn extract_frontend_calls_and_bugs(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    calls_out: &mut Vec<FrontendApiCall>,
    bugs_out: &mut Vec<LocalStaticFinding>,
) {
    if !matches!(lang, Language::TypeScript | Language::JavaScript) {
        return;
    }

    let kind = node.kind();

    // 1. Dead/empty `onClick={() => {}}` / `onSubmit={() => {}}`
    if kind == "jsx_attribute" {
        let attr_txt = node_text(node, src);
        if (attr_txt.starts_with("onClick") || attr_txt.starts_with("onSubmit"))
            && let Some(expr_node) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "jsx_expression")
        {
            let mut c = expr_node.walk();
            for ch in expr_node.children(&mut c) {
                if matches!(ch.kind(), "arrow_function" | "function_expression")
                    && let Some(body) = ch.child_by_field_name("body")
                    && body.kind() == "statement_block"
                {
                    let has_stmt = body.children(&mut body.walk()).any(|s| {
                        !matches!(
                            s.kind(),
                            "{" | "}" | "comment" | "line_comment" | "block_comment"
                        )
                    });
                    if !has_stmt {
                        bugs_out.push(LocalStaticFinding {
                            rule_id: "VF-FE-ERR".into(),
                            severity: "MEDIUM".into(),
                            title: "Dead/empty UI event handler (`onClick={() => {}}`)".into(),
                            rel_path: rel_path.to_string(),
                            line: node.start_position().row + 1,
                            symbol: attr_txt.split('=').next().unwrap_or("onClick").trim().to_string(),
                            sink_kind: SinkKind::FrontendContract,
                            missing_guard: GuardKind::FrontendContract,
                            remediation: "Wire the event handler to an actual state update, callback, or remove the dead interactive trigger.".into(),
                        });
                    }
                }
            }
        }
    }

    // 2. Frontend `fetch('/api/...')` / `axios.<method>('/api/...')` contract extraction
    if kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let is_fetch = ftxt == "fetch";
        let is_axios = ftxt == "axios"
            || matches!(
                ftxt,
                "axios.get" | "axios.post" | "axios.put" | "axios.patch" | "axios.delete"
            );
        if (is_fetch || is_axios)
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut c = args.walk();
            let first_arg = args
                .children(&mut c)
                .find(|a| !matches!(a.kind(), "(" | ")" | ","));
            if let Some(arg0) = first_arg {
                let raw_arg = if arg0.kind() == "binary_expression" {
                    arg0.child_by_field_name("left")
                        .map(|l| {
                            let s = node_text(l, src)
                                .trim()
                                .trim_matches(|ch| ch == '\'' || ch == '"' || ch == '`');
                            if s.starts_with("/api/") {
                                format!("{}/*", s.trim_end_matches('/'))
                            } else {
                                String::new()
                            }
                        })
                        .unwrap_or_default()
                } else {
                    node_text(arg0, src)
                        .trim()
                        .trim_matches(|ch| ch == '\'' || ch == '"' || ch == '`')
                        .to_string()
                };
                if raw_arg.starts_with("/api/") || raw_arg == "/api" {
                    let method = if let Some(m) = ftxt.strip_prefix("axios.") {
                        m.to_ascii_uppercase()
                    } else {
                        let args_txt = node_text(args, src).to_ascii_uppercase();
                        if args_txt.contains("POST") {
                            "POST".into()
                        } else if args_txt.contains("PUT") {
                            "PUT".into()
                        } else if args_txt.contains("PATCH") {
                            "PATCH".into()
                        } else if args_txt.contains("DELETE") {
                            "DELETE".into()
                        } else {
                            "GET".into()
                        }
                    };
                    calls_out.push(FrontendApiCall {
                        rel_path: rel_path.to_string(),
                        line: node.start_position().row + 1,
                        method,
                        raw_path: raw_arg.clone(),
                        normalized_path: normalize_api_path(&raw_arg),
                        symbol: ftxt.to_string(),
                    });
                }
            }
        }
    }

    // 3. Unhandled async mutation missing `try/catch` or `.catch(...)`
    if kind == "await_expression" {
        let txt = node_text(node, src);
        let low = txt.to_ascii_lowercase();
        let is_mutation = low.contains("axios.post(")
            || low.contains("axios.put(")
            || low.contains("axios.patch(")
            || low.contains("axios.delete(")
            || low.contains(".mutateasync(")
            || (low.contains("fetch(")
                && (low.contains("post")
                    || low.contains("put")
                    || low.contains("patch")
                    || low.contains("delete")));
        if is_mutation
            && !has_ancestor_kind(node, "try_statement")
            && !has_dot_catch_chain(node, src)
        {
            bugs_out.push(LocalStaticFinding {
                rule_id: "VF-FE-ERR".into(),
                severity: "MEDIUM".into(),
                title: "Unhandled async mutation missing `try/catch` or `.catch()` error handling"
                    .into(),
                rel_path: rel_path.to_string(),
                line: node.start_position().row + 1,
                symbol: "await mutation".into(),
                sink_kind: SinkKind::FrontendContract,
                missing_guard: GuardKind::FrontendContract,
                remediation: "Wrap the `await` mutation in a `try { ... } catch (err) { ... }` block and surface an explicit error state to the UI.".into(),
            });
        }
    }

    // 4. Swallowed or empty `catch (e) {}` / `catch (e) { console.log(e); }` error blocks
    if kind == "catch_clause"
        && let Some(body) = node.child_by_field_name("body")
    {
        let mut c = body.walk();
        let stmts: Vec<Node> = body
            .children(&mut c)
            .filter(|ch| {
                !matches!(
                    ch.kind(),
                    "{" | "}" | "comment" | "line_comment" | "block_comment"
                )
            })
            .collect();
        if stmts.is_empty() {
            bugs_out.push(LocalStaticFinding {
                rule_id: "VF-FE-ERR".into(),
                severity: "MEDIUM".into(),
                title: "Empty `catch` block silently swallows runtime/API errors".into(),
                rel_path: rel_path.to_string(),
                line: node.start_position().row + 1,
                symbol: "catch".into(),
                sink_kind: SinkKind::FrontendContract,
                missing_guard: GuardKind::FrontendContract,
                remediation: "Handle caught errors explicitly (surface UI error feedback, report telemetry, or rethrow).".into(),
            });
        } else if stmts.len() == 1 {
            let only = node_text(stmts[0], src).trim();
            if only.starts_with("console.") {
                bugs_out.push(LocalStaticFinding {
                    rule_id: "VF-FE-ERR".into(),
                    severity: "LOW".into(),
                    title: "`catch` block only logs to `console` without handling or surfacing error".into(),
                    rel_path: rel_path.to_string(),
                    line: node.start_position().row + 1,
                    symbol: "catch (console-only)".into(),
                    sink_kind: SinkKind::FrontendContract,
                    missing_guard: GuardKind::FrontendContract,
                    remediation: "Update error UI state, return an error result, or rethrow instead of only logging to console.".into(),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        extract_frontend_calls_and_bugs(ch, src, rel_path, lang, calls_out, bugs_out);
    }
}
