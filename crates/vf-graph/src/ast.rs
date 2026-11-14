use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Parser};
use vf_core::{IndexedFile, Language, VeriForgeConfig};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Route,
    #[default]
    Function,
    Sink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    PaymentMutation,
    BalanceUpdate,
    SqlWrite,
    AuthMutation,
    SqlInjection,
    CommandInjection,
    PathTraversal,
    Ssrf,
    IdorDbAccess,
    SecretLeak,
    Misconfiguration,
    DependencyRisk,
    FrontendContract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardKind {
    Auth,
    TxLock,
    SqlSanitizer,
    CmdSanitizer,
    PathSanitizer,
    SsrfSanitizer,
    OwnershipCheck,
    SecretPolicy,
    ConfigPolicy,
    DependencyPolicy,
    FrontendContract,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStaticFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub rel_path: String,
    pub line: usize,
    pub symbol: String,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendApiCall {
    pub rel_path: String,
    pub line: usize,
    pub method: String,
    pub raw_path: String,
    pub normalized_path: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRef {
    pub symbol_name: String,
    pub from_specifier: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub id: String,
    pub rel_path: String,
    pub name: String,
    pub kind: SymbolKind,
    pub sink_kind: Option<SinkKind>,
    pub line_start: usize,
    pub line_end: usize,
    pub guards: HashSet<GuardKind>,
    pub calls: Vec<String>,
    pub route_path: Option<String>,
    #[serde(default)]
    pub has_taint_source: bool,
    #[serde(default)]
    pub has_resource_id: bool,
    #[serde(default)]
    pub has_db_crud_sink: bool,
    #[serde(default)]
    pub db_crud_line: Option<usize>,
    #[serde(default)]
    pub tainted_calls: Vec<String>,
    #[serde(default)]
    pub param_forwarding_calls: Vec<String>,
    #[serde(default)]
    pub local_taint_hits: Vec<LocalStaticFinding>,
    #[serde(default)]
    pub param_sinks: Vec<LocalStaticFinding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAstSummary {
    pub rel_path: String,
    pub imports: Vec<ImportRef>,
    pub symbols: Vec<SymbolInfo>,
    #[serde(default)]
    pub static_findings: Vec<LocalStaticFinding>,
    #[serde(default)]
    pub frontend_calls: Vec<FrontendApiCall>,
    #[serde(default)]
    pub route_prefixes: Vec<String>,
    #[serde(default)]
    pub gitignore_lines: Option<Vec<String>>,
    #[serde(default)]
    pub is_sensitive_env_or_pem: bool,
}

impl SymbolInfo {
    #[allow(clippy::too_many_arguments)]
    fn base(
        id: String,
        rel_path: &str,
        name: String,
        kind: SymbolKind,
        sink_kind: Option<SinkKind>,
        line_start: usize,
        line_end: usize,
        guards: HashSet<GuardKind>,
        calls: Vec<String>,
        route_path: Option<String>,
    ) -> Self {
        Self {
            id,
            rel_path: rel_path.to_string(),
            name,
            kind,
            sink_kind,
            line_start,
            line_end,
            guards,
            calls,
            route_path,
            has_taint_source: false,
            has_resource_id: false,
            has_db_crud_sink: false,
            db_crud_line: None,
            tainted_calls: Vec::new(),
            param_forwarding_calls: Vec::new(),
            local_taint_hits: Vec::new(),
            param_sinks: Vec::new(),
        }
    }

    fn apply_taint(&mut self, t: crate::taint::FunctionTaintSummary) {
        self.guards.extend(t.guards);
        self.has_taint_source = self.has_taint_source || t.has_taint_source;
        self.has_resource_id = self.has_resource_id || t.has_resource_id;
        self.has_db_crud_sink = self.has_db_crud_sink || t.has_db_crud_sink;
        if self.db_crud_line.is_none() {
            self.db_crud_line = t.db_crud_line;
        }
        for c in t.tainted_calls {
            if !self.tainted_calls.iter().any(|x| x == &c) {
                self.tainted_calls.push(c);
            }
        }
        for c in t.param_forwarding_calls {
            if !self.param_forwarding_calls.iter().any(|x| x == &c) {
                self.param_forwarding_calls.push(c);
            }
        }
        self.local_taint_hits.extend(t.local_taint_hits);
        self.param_sinks.extend(t.param_sinks);
    }
}

pub fn parse_file_ast_with_hash(
    file: &IndexedFile,
    cfg: &VeriForgeConfig,
) -> Option<(String, FileAstSummary)> {
    let owned_bytes;
    let bytes: &[u8] = if let Some(ref cached) = file.cached_bytes {
        cached.as_slice()
    } else {
        owned_bytes = fs::read(&file.abs_path).ok()?;
        owned_bytes.as_slice()
    };
    let actual_hash = if file.cached_bytes.is_some() && !file.blake3_hash.is_empty() {
        file.blake3_hash.clone()
    } else {
        blake3::hash(bytes).to_hex().to_string()
    };
    let is_sensitive = crate::secrets_config::is_sensitive_env_or_pem(&file.rel_path);
    let source = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            if is_sensitive {
                return Some((
                    actual_hash,
                    FileAstSummary {
                        rel_path: file.rel_path.clone(),
                        is_sensitive_env_or_pem: true,
                        ..Default::default()
                    },
                ));
            }
            return None;
        }
    };

    let gitignore_lines = if Path::new(&file.rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        == Some(".gitignore")
    {
        Some(source.lines().map(|l| l.to_string()).collect())
    } else {
        None
    };

    let mut static_findings =
        crate::secrets_config::scan_secrets_and_config(&file.rel_path, source);
    if matches!(file.language, Language::Manifest) {
        static_findings.extend(crate::deps::scan_dependencies(&file.rel_path, source));
    }

    if matches!(
        file.language,
        Language::Config | Language::Manifest | Language::Sql
    ) {
        return Some((
            actual_hash,
            FileAstSummary {
                rel_path: file.rel_path.clone(),
                static_findings,
                gitignore_lines,
                is_sensitive_env_or_pem: is_sensitive,
                ..Default::default()
            },
        ));
    }

    let mut parser = Parser::new();

    match file.language {
        Language::TypeScript => {
            let is_tsx = file.rel_path.ends_with(".tsx");
            let lang = if is_tsx {
                tree_sitter_typescript::LANGUAGE_TSX.into()
            } else {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            };
            parser.set_language(&lang).ok()?;
        }
        Language::JavaScript => {
            parser
                .set_language(&tree_sitter_javascript::LANGUAGE.into())
                .ok()?;
        }
        Language::Rust => {
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .ok()?;
        }
        Language::Python => {
            parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .ok()?;
        }
        Language::Go => {
            parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
        }
        Language::Sql | Language::Config | Language::Manifest => unreachable!(),
    }

    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    let src_bytes = source.as_bytes();

    let mut imports = Vec::new();
    let mut symbols = Vec::new();
    let mut route_prefixes = Vec::new();

    let mut file_middleware_guards = HashSet::new();
    extract_node(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        cfg,
        &mut file_middleware_guards,
        &mut imports,
        &mut symbols,
        &mut route_prefixes,
    );

    let mut frontend_calls = Vec::new();
    crate::taint::extract_frontend_calls_and_bugs(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        &mut frontend_calls,
        &mut static_findings,
    );

    Some((
        actual_hash,
        FileAstSummary {
            rel_path: file.rel_path.clone(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            gitignore_lines,
            is_sensitive_env_or_pem: is_sensitive,
        },
    ))
}

pub fn parse_file_ast(file: &IndexedFile, cfg: &VeriForgeConfig) -> Option<FileAstSummary> {
    parse_file_ast_with_hash(file, cfg).map(|(_, s)| s)
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn find_line_comment_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'/' && bytes[i + 1] == b'/' {
            if i > 0 && bytes[i - 1] == b':' {
                continue;
            }
            return Some(i);
        }
    }
    None
}

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let trimmed = if let Some(idx) = find_line_comment_start(line) {
            &line[..idx]
        } else {
            line
        };
        let trimmed = if let Some(idx) = trimmed.find('#') {
            if trimmed[idx..].starts_with("#[") {
                trimmed
            } else {
                &trimmed[..idx]
            }
        } else {
            trimmed
        };
        out.push_str(trimmed);
        out.push('\n');
    }
    out
}

fn is_auth_guard_ident(name: &str, cfg: &VeriForgeConfig) -> bool {
    let low = name.to_ascii_lowercase();
    cfg.guards.auth_guards.iter().any(|pat| {
        low == pat.to_ascii_lowercase() || low.ends_with(&format!(".{}", pat.to_ascii_lowercase()))
    })
}

fn is_lock_guard_ident(name: &str, cfg: &VeriForgeConfig) -> bool {
    let low = name.to_ascii_lowercase();
    cfg.guards.lock_guards.iter().any(|pat| {
        low == pat.to_ascii_lowercase() || low.ends_with(&format!(".{}", pat.to_ascii_lowercase()))
    })
}

fn classify_guards(text: &str, cfg: &VeriForgeConfig) -> HashSet<GuardKind> {
    let mut g = HashSet::new();
    let code_only = strip_comments(text);
    let low = code_only.to_ascii_lowercase();
    if cfg
        .guards
        .auth_guards
        .iter()
        .any(|pat| low.contains(&pat.to_ascii_lowercase()))
    {
        g.insert(GuardKind::Auth);
    }
    if cfg
        .guards
        .lock_guards
        .iter()
        .any(|pat| low.contains(&pat.to_ascii_lowercase()))
    {
        g.insert(GuardKind::TxLock);
    }
    g
}

fn collect_call_names_shallow(node: Node, src: &[u8], out: &mut Vec<String>) {
    let k = node.kind();
    if matches!(
        k,
        "if_statement"
            | "switch_statement"
            | "function_declaration"
            | "arrow_function"
            | "function_expression"
    ) {
        return;
    }
    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let txt = node_text(func, src).trim();
        let short = txt.rsplit('.').next().unwrap_or(txt);
        let short = short.rsplit("::").next().unwrap_or(short);
        if !short.is_empty() {
            out.push(short.to_string());
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_call_names_shallow(ch, src, out);
    }
}

fn stmt_has_sink_or_mutation(stmt: Node, src: &[u8]) -> bool {
    let txt = strip_comments(node_text(stmt, src)).to_ascii_lowercase();
    txt.contains("stripe.")
        || txt.contains("charges.create")
        || txt.contains("paymentintent")
        || txt.contains("update ")
        || txt.contains("insert into ")
        || txt.contains("delete from ")
        || txt.contains("debit")
        || txt.contains("withdraw")
        || txt.contains("balance")
}

/// Control-flow & statement-order aware guard extractor (B02):
/// - Ignores guards inside string literals, comments, `if` branches, or uncalled nested functions.
/// - Requires unconditional guard call to execute BEFORE the first mutation/sink statement
///   (or wrap it via `withTransaction(...)`).
fn classify_fn_guards_cfg(fn_node: Node, src: &[u8], cfg: &VeriForgeConfig) -> HashSet<GuardKind> {
    let mut guards = HashSet::new();
    let Some(body) = fn_node.child_by_field_name("body") else {
        return guards;
    };

    let mut seen_mutation = false;
    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        let sk = stmt.kind();
        if matches!(sk, "{" | "}" | "comment" | "line_comment" | "block_comment") {
            continue;
        }
        // Skip conditional branches & uncalled nested functions for unconditional guard proof
        if matches!(
            sk,
            "if_statement"
                | "switch_statement"
                | "for_statement"
                | "while_statement"
                | "function_declaration"
                | "function_item"
                | "function_definition"
        ) {
            if stmt_has_sink_or_mutation(stmt, src) {
                seen_mutation = true;
            }
            continue;
        }

        // Check wrapper transaction like `return withTransaction(async () => { ... })`
        let mut calls = Vec::new();
        collect_call_names_shallow(stmt, src, &mut calls);

        for c in &calls {
            if !seen_mutation && is_auth_guard_ident(c, cfg) {
                guards.insert(GuardKind::Auth);
            }
            if !seen_mutation && is_lock_guard_ident(c, cfg) {
                guards.insert(GuardKind::TxLock);
            }
        }

        // Also allow SQL-level `SELECT ... FOR UPDATE` inside an unconditional top-level statement before mutation
        let stmt_code = strip_comments(node_text(stmt, src)).to_ascii_lowercase();
        if !seen_mutation && stmt_code.contains("select ") && stmt_code.contains("for update") {
            guards.insert(GuardKind::TxLock);
        }

        if stmt_has_sink_or_mutation(stmt, src) {
            seen_mutation = true;
        }
    }

    guards
}

fn classify_sink(name: &str, body: &str) -> Option<SinkKind> {
    let low_name = name.to_ascii_lowercase();
    let low_body = strip_comments(body).to_ascii_lowercase();

    if low_body.contains("stripe.")
        || low_body.contains("charges.create")
        || low_body.contains("paymentintent")
        || low_body.contains("paypal.")
        || low_body.contains("razorpay.")
        || low_body.contains("paddle.")
        || low_body.contains("sslcommerz")
        || low_body.contains("braintree.")
        || (low_name.contains("charge") && low_body.contains("amount"))
    {
        return Some(SinkKind::PaymentMutation);
    }
    if (low_body.contains("balance")
        || low_name.contains("balance")
        || low_name.contains("withdraw")
        || low_name.contains("debit"))
        && (low_body.contains("update")
            || low_body.contains("-=")
            || low_body.contains("+=")
            || low_body.contains("set ")
            || low_body.contains(".save("))
    {
        return Some(SinkKind::BalanceUpdate);
    }
    if (low_body.contains("update ") && low_body.contains("set "))
        || low_body.contains("insert into ")
        || low_body.contains("delete from ")
        || ((low_body.contains("prisma.") || low_body.contains("db."))
            && (low_body.contains(".create(")
                || low_body.contains(".update(")
                || low_body.contains(".upsert(")
                || low_body.contains(".delete(")))
        || low_body.contains("db.insert(")
        || low_body.contains("db.update(")
        || low_body.contains("db.delete(")
        || low_body.contains(".updates(")
        || low_body.contains("db.exec(")
        || low_body.contains("tx.exec(")
        || low_body.contains("session.commit(")
    {
        return Some(SinkKind::SqlWrite);
    }
    if low_name.contains("role") && (low_body.contains("admin") || low_body.contains("update")) {
        return Some(SinkKind::AuthMutation);
    }
    None
}

fn collect_calls(node: Node, src: &[u8], calls: &mut Vec<String>) {
    if (node.kind() == "call_expression" || node.kind() == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let txt = node_text(func, src).trim();
        let short = txt.rsplit('.').next().unwrap_or(txt);
        let short = short.rsplit("::").next().unwrap_or(short);
        if !short.is_empty() && !calls.iter().any(|c| c == short) {
            calls.push(short.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_calls(child, src, calls);
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_node(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    cfg: &VeriForgeConfig,
    file_middleware_guards: &mut HashSet<GuardKind>,
    imports: &mut Vec<ImportRef>,
    symbols: &mut Vec<SymbolInfo>,
    route_prefixes: &mut Vec<String>,
) {
    let kind = node.kind();

    // 1a. Cross-file imports & re-exports (TS/JS: named, default, namespace `* as`)
    if kind == "import_statement" || kind == "export_statement" {
        let txt = node_text(node, src);
        if let Some(spec_node) = node.child_by_field_name("source") {
            let spec = node_text(spec_node, src).trim_matches(|c| c == '\'' || c == '"');
            if let (Some(lbrace), Some(rbrace)) = (txt.find('{'), txt.find('}')) {
                for item in txt[lbrace + 1..rbrace].split(',') {
                    let sym = item.split(" as ").next().unwrap_or(item).trim();
                    if !sym.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: sym.to_string(),
                            from_specifier: spec.to_string(),
                        });
                    }
                }
            }
            // Also extract default import (`import foo from './y'`) or namespace (`import * as ns from './y'`)
            if let Some(clause) = txt
                .strip_prefix("import ")
                .and_then(|s| s.split(" from ").next())
            {
                let before_brace = clause
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(',');
                if let Some((_, ns)) = before_brace.split_once("* as ") {
                    let sym = ns.trim();
                    if !sym.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: sym.to_string(),
                            from_specifier: spec.to_string(),
                        });
                    }
                } else if !before_brace.is_empty() && !before_brace.contains('*') {
                    imports.push(ImportRef {
                        symbol_name: before_brace.to_string(),
                        from_specifier: spec.to_string(),
                    });
                }
            }
        }
    }

    // 1a-cjs. CommonJS `const { a, b } = require('./y')` or `const mod = require('./y')`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "variable_declarator"
        && let (Some(name_node), Some(val_node)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        && val_node.kind() == "call_expression"
        && let Some(fn_node) = val_node.child_by_field_name("function")
        && node_text(fn_node, src).trim() == "require"
        && let Some(args) = val_node.child_by_field_name("arguments")
    {
        let args_txt = node_text(args, src);
        let spec = args_txt.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '\'' || c == '"' || c.is_whitespace()
        });
        if !spec.is_empty() {
            let ntxt = node_text(name_node, src).trim();
            if let (Some(lbrace), Some(rbrace)) = (ntxt.find('{'), ntxt.find('}')) {
                for item in ntxt[lbrace + 1..rbrace].split(',') {
                    let sym = item.split(':').next().unwrap_or(item).trim();
                    if !sym.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: sym.to_string(),
                            from_specifier: spec.to_string(),
                        });
                    }
                }
            } else if !ntxt.is_empty() {
                imports.push(ImportRef {
                    symbol_name: ntxt.to_string(),
                    from_specifier: spec.to_string(),
                });
            }
        }
    }

    // 1b. Rust `use crate::foo::bar;` or `use super::foo::bar;`
    if lang == Language::Rust && kind == "use_declaration" {
        let txt = node_text(node, src)
            .trim_start_matches("pub ")
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .trim();
        if let Some((mod_path, tail)) = txt.rsplit_once("::") {
            let spec = format!("rust::{}", mod_path.replace("::", "/"));
            if tail.starts_with('{') && tail.ends_with('}') {
                for item in tail[1..tail.len() - 1].split(',') {
                    let sym = item.trim();
                    if !sym.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: sym.to_string(),
                            from_specifier: spec.clone(),
                        });
                    }
                }
            } else {
                imports.push(ImportRef {
                    symbol_name: tail.trim().to_string(),
                    from_specifier: spec,
                });
            }
        }
    }

    // 1c. Python `from .services import foo, bar`
    if lang == Language::Python && kind == "import_from_statement" {
        let txt = node_text(node, src);
        if let Some(rest) = txt.strip_prefix("from ")
            && let Some((mod_part, imp_part)) = rest.split_once(" import ")
        {
            let spec = format!("py::{}", mod_part.trim());
            for item in imp_part.split(',') {
                let sym = item.split(" as ").next().unwrap_or(item).trim();
                if !sym.is_empty() {
                    imports.push(ImportRef {
                        symbol_name: sym.to_string(),
                        from_specifier: spec.clone(),
                    });
                }
            }
        }
    }

    // 2a-use. File-level `app.use(requireAuth)` / `router.use(requireAuth)` & prefix capture (B03)
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if ftxt.ends_with(".use")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('\'') || atxt.starts_with('"') {
                    let unq = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    if unq.starts_with('/')
                        && unq.len() > 1
                        && !route_prefixes.iter().any(|p| p == unq)
                    {
                        route_prefixes.push(unq.to_string());
                    }
                }
                if is_auth_guard_ident(atxt, cfg) {
                    file_middleware_guards.insert(GuardKind::Auth);
                }
            }
        }
    }

    // 2a-nest-ctrl. NestJS `@Controller("prefix")` decorator capture
    if (lang == Language::TypeScript || lang == Language::JavaScript) && kind == "decorator" {
        let dtxt = node_text(node, src).trim();
        if dtxt.contains("@Controller(")
            && let Some(raw) = dtxt.split('(').nth(1).and_then(|s| s.split(')').next())
        {
            let cleaned = raw.trim().trim_matches(|ch| ch == '\'' || ch == '"');
            if !cleaned.is_empty() && cleaned != "/" {
                let pref = if cleaned.starts_with('/') {
                    cleaned.to_string()
                } else {
                    format!("/{}", cleaned)
                };
                if !route_prefixes.iter().any(|p| p == &pref) {
                    route_prefixes.push(pref);
                }
            }
        }
    }

    // 2a. Universal TS/JS HTTP Route entries (Express, Fastify, Hono, Koa, custom routers):
    // `<router>.(get|post|put|patch|delete)('/...', ...middlewares, handler)`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        let method = ftxt.rsplit('.').next().unwrap_or("");
        let is_custom = cfg
            .guards
            .custom_routes
            .iter()
            .any(|cr| ftxt == cr || ftxt.ends_with(&format!(".{}", cr)));
        let is_http_method =
            ftxt.contains('.') && matches!(method, "get" | "post" | "put" | "patch" | "delete");
        if (is_http_method || is_custom)
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path: Option<String> = None;
            let mut calls = Vec::new();
            let mut guards = file_middleware_guards.clone();
            let mut seen_handler = false;
            let mut route_taints = Vec::new();
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;

            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let ak = arg.kind();
                if matches!(ak, "(" | ")" | ",") {
                    continue;
                }
                let atxt = node_text(arg, src).trim();
                if (atxt.starts_with('\'') || atxt.starts_with('"')) && route_path.is_none() {
                    let unq = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    if unq.starts_with('/') || is_custom {
                        route_path = Some(unq.to_string());
                    }
                } else if route_path.is_some() {
                    if ak == "identifier" {
                        if !seen_handler && is_auth_guard_ident(atxt, cfg) {
                            guards.insert(GuardKind::Auth);
                        } else if !seen_handler && is_lock_guard_ident(atxt, cfg) {
                            guards.insert(GuardKind::TxLock);
                        } else {
                            seen_handler = true;
                        }
                        calls.push(atxt.to_string());
                    } else if matches!(ak, "arrow_function" | "function_expression") {
                        seen_handler = true;
                        let inline_body = node_text(arg, src);
                        let inline_guards = classify_fn_guards_cfg(arg, src, cfg);
                        guards.extend(inline_guards);
                        collect_calls(arg, src, &mut calls);

                        let handler_label = route_path
                            .as_deref()
                            .map(|rp| format!("{} {}", method.to_ascii_uppercase(), rp))
                            .unwrap_or_else(|| format!("inline_{}", line_start));
                        let t_inline = crate::taint::analyze_function_taint(
                            arg,
                            src,
                            rel_path,
                            lang,
                            &handler_label,
                            route_path.as_deref(),
                        );

                        if let Some(sk) =
                            classify_sink(route_path.as_deref().unwrap_or("inline"), inline_body)
                        {
                            let inline_id = format!("{}::inline_sink:{}", rel_path, line_start);
                            let inline_name = format!("inline_sink_{}", line_start);
                            let mut inline_calls = Vec::new();
                            collect_calls(arg, src, &mut inline_calls);
                            let mut sink_sym = SymbolInfo::base(
                                inline_id,
                                rel_path,
                                inline_name.clone(),
                                SymbolKind::Sink,
                                Some(sk),
                                arg.start_position().row + 1,
                                arg.end_position().row + 1,
                                classify_fn_guards_cfg(arg, src, cfg),
                                inline_calls,
                                None,
                            );
                            sink_sym.has_db_crud_sink = t_inline.has_db_crud_sink;
                            sink_sym.db_crud_line = t_inline.db_crud_line;
                            sink_sym.has_resource_id = t_inline.has_resource_id;
                            sink_sym.has_taint_source = t_inline.has_taint_source;
                            sink_sym.guards.extend(t_inline.guards.iter().copied());
                            symbols.push(sink_sym);
                            calls.push(inline_name);
                        }
                        route_taints.push(t_inline);
                    } else {
                        if !seen_handler && is_auth_guard_ident(atxt, cfg) {
                            guards.insert(GuardKind::Auth);
                        }
                        collect_calls(arg, src, &mut calls);
                    }
                }
            }
            if let Some(rp) = route_path {
                let r_label = format!("{} {}", method.to_ascii_uppercase(), rp);
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    r_label,
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                if has_res_id {
                    route_sym.has_resource_id = true;
                }
                for t in route_taints {
                    route_sym.apply_taint(t);
                }
                symbols.push(route_sym);
                return;
            }
        }
    }

    // 2a-trpc. tRPC `publicProcedure...mutation(...)` / `protectedProcedure...mutation(...)`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if (ftxt.ends_with(".mutation") || ftxt.ends_with(".query"))
            && (ftxt.contains("publicProcedure") || ftxt.contains("protectedProcedure"))
        {
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            let mut guards = file_middleware_guards.clone();
            if ftxt.contains("protectedProcedure") {
                guards.insert(GuardKind::Auth);
            }
            let mut calls = Vec::new();
            let mut inline_body = "";
            let r_label = format!("TRPC {}:{}", rel_path, line_start);
            let trpc_path = format!("/trpc/{}", line_start);
            let mut trpc_taint = None;
            if let Some(args) = node.child_by_field_name("arguments") {
                inline_body = node_text(args, src);
                collect_calls(args, src, &mut calls);
                trpc_taint = Some(crate::taint::analyze_function_taint(
                    args,
                    src,
                    rel_path,
                    lang,
                    &r_label,
                    Some(&trpc_path),
                ));
            }
            if let Some(sk) = classify_sink(&r_label, inline_body) {
                let inline_name = format!("trpc_sink_{}", line_start);
                let mut sink_sym = SymbolInfo::base(
                    format!("{}::{}", rel_path, inline_name),
                    rel_path,
                    inline_name.clone(),
                    SymbolKind::Sink,
                    Some(sk),
                    line_start,
                    line_end,
                    guards.clone(),
                    calls.clone(),
                    None,
                );
                if let Some(ref t) = trpc_taint {
                    sink_sym.has_db_crud_sink = t.has_db_crud_sink;
                    sink_sym.db_crud_line = t.db_crud_line;
                    sink_sym.has_resource_id = t.has_resource_id;
                    sink_sym.has_taint_source = t.has_taint_source;
                    sink_sym.guards.extend(t.guards.iter().copied());
                }
                symbols.push(sink_sym);
                calls.push(inline_name);
            }
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                r_label,
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                guards,
                calls,
                Some(trpc_path),
            );
            if let Some(t) = trpc_taint {
                route_sym.apply_taint(t);
            }
            symbols.push(route_sym);
            return;
        }
    }

    // 2a-nest. NestJS `@Controller` / `@Get` / `@Post` / `@UseGuards` inside `class_declaration`
    if (lang == Language::TypeScript || lang == Language::JavaScript) && kind == "class_declaration"
    {
        let class_txt = node_text(node, src);
        let class_has_auth = class_txt.contains("@UseGuards") && class_txt.contains("Auth");
        if let Some(body) = node.child_by_field_name("body") {
            let mut pending_method: Option<String> = None;
            let mut pending_path: Option<String> = None;
            let mut pending_guards = HashSet::new();
            if class_has_auth {
                pending_guards.insert(GuardKind::Auth);
            }
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                if ch.kind() == "decorator" {
                    let dtxt = node_text(ch, src);
                    for m in ["Get", "Post", "Put", "Patch", "Delete"] {
                        if dtxt.contains(&format!("@{}(", m)) {
                            pending_method = Some(m.to_ascii_uppercase());
                            let rp = dtxt
                                .split('(')
                                .nth(1)
                                .and_then(|s| s.split(')').next())
                                .map(|s| s.trim().trim_matches(|q| q == '\'' || q == '"'))
                                .unwrap_or("/");
                            pending_path = Some(if rp.is_empty() {
                                "/".into()
                            } else {
                                rp.to_string()
                            });
                        }
                    }
                    pending_guards.extend(classify_guards(dtxt, cfg));
                } else if ch.kind() == "method_definition"
                    && let Some(m) = pending_method.take()
                {
                    let rp = pending_path.take().unwrap_or_else(|| "/".into());
                    if let Some(name_node) = ch.child_by_field_name("name") {
                        let mname = node_text(name_node, src).trim().to_string();
                        let line_start = ch.start_position().row + 1;
                        let line_end = ch.end_position().row + 1;
                        let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                        let mut route_sym = SymbolInfo::base(
                            format!("{}::route:{}", rel_path, line_start),
                            rel_path,
                            format!("{} {}", m, rp),
                            SymbolKind::Route,
                            None,
                            line_start,
                            line_end,
                            std::mem::take(&mut pending_guards),
                            vec![mname],
                            Some(rp),
                        );
                        route_sym.has_resource_id = has_res_id;
                        symbols.push(route_sym);
                    }
                    if class_has_auth {
                        pending_guards.insert(GuardKind::Auth);
                    }
                }
            }
        }
    }

    // 2c. Python Flask / FastAPI `@app.post("/api/...")` decorated_definition (B06)
    if lang == Language::Python && kind == "decorated_definition" {
        let mut route_method = None;
        let mut route_path = None;
        let mut dec_guards = HashSet::new();
        let mut fn_node = None;

        let mut cursor = node.walk();
        for ch in node.children(&mut cursor) {
            if ch.kind() == "decorator" {
                let dtxt = node_text(ch, src);
                for m in ["get", "post", "put", "patch", "delete"] {
                    let needle = format!(".{}(", m);
                    if let Some(pos) = dtxt.find(&needle) {
                        route_method = Some(m.to_ascii_uppercase());
                        let rest = &dtxt[pos + needle.len()..];
                        if let Some(q1) = rest.find(['\'', '"']) {
                            let qch = rest.as_bytes()[q1] as char;
                            if let Some(q2) = rest[q1 + 1..].find(qch) {
                                route_path = Some(rest[q1 + 1..q1 + 1 + q2].to_string());
                            }
                        }
                    }
                }
                dec_guards.extend(classify_guards(dtxt, cfg));
            } else if ch.kind() == "function_definition" {
                fn_node = Some(ch);
            }
        }

        if let (Some(method), Some(rp), Some(fnode)) = (route_method, route_path, fn_node)
            && let Some(name_node) = fnode.child_by_field_name("name")
        {
            let fn_name = node_text(name_node, src).trim().to_string();
            let line_start = node.start_position().row + 1;
            let line_end = fnode.end_position().row + 1;
            let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                format!("{} {}", method, rp),
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                dec_guards,
                vec![fn_name],
                Some(rp),
            );
            route_sym.has_resource_id = has_res_id;
            symbols.push(route_sym);
            // Continue into `fnode` to emit the Function / Sink symbol itself
            extract_node(
                fnode,
                src,
                rel_path,
                lang,
                cfg,
                file_middleware_guards,
                imports,
                symbols,
                route_prefixes,
            );
            return;
        }
    }

    // 2b. Rust Axum / Actix `.route("/api/...", post(handler))`
    if lang == Language::Rust
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if ftxt.ends_with(".route")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path = None;
            let mut method = "POST".to_string();
            let mut calls = Vec::new();
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('"') && route_path.is_none() {
                    route_path = Some(atxt.trim_matches('"').to_string());
                } else if arg.kind() == "call_expression" {
                    if let Some(mfn) = arg.child_by_field_name("function") {
                        let mname = node_text(mfn, src).rsplit("::").next().unwrap_or("post");
                        if matches!(mname, "get" | "post" | "put" | "patch" | "delete") {
                            method = mname.to_ascii_uppercase();
                        }
                    }
                    if let Some(margs) = arg.child_by_field_name("arguments") {
                        let mut mc = margs.walk();
                        for marg in margs.children(&mut mc) {
                            if marg.kind() == "identifier" || marg.kind() == "scoped_identifier" {
                                let hname = node_text(marg, src).rsplit("::").next().unwrap_or("");
                                if !hname.is_empty() {
                                    calls.push(hname.to_string());
                                }
                            }
                        }
                    }
                    collect_calls(arg, src, &mut calls);
                }
            }
            if let Some(rp) = route_path {
                let guards = classify_guards(&calls.join(" "), cfg);
                let line_start = args.start_position().row + 1;
                let line_end = args.end_position().row + 1;
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("{} {}", method, rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                symbols.push(route_sym);
            }
        }
    }

    // 2c-django. Python Django `path("api/...", views.my_view)`
    if lang == Language::Python
        && kind == "call"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        if (ftxt == "path" || ftxt == "re_path")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path = None;
            let mut calls = Vec::new();
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if (atxt.starts_with('\'') || atxt.starts_with('"')) && route_path.is_none() {
                    let rp = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    route_path = Some(if rp.starts_with('/') {
                        rp.to_string()
                    } else {
                        format!("/{}", rp)
                    });
                } else if !matches!(arg.kind(), "(" | ")" | "," | "keyword_argument") {
                    let short = atxt.rsplit('.').next().unwrap_or(atxt).trim();
                    if !short.is_empty() {
                        calls.push(short.to_string());
                    }
                }
            }
            if let Some(rp) = route_path
                && !calls.is_empty()
            {
                let line_start = node.start_position().row + 1;
                let line_end = node.end_position().row + 1;
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("DJANGO {}", rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    HashSet::new(),
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                symbols.push(route_sym);
                return;
            }
        }
    }

    // 2d. Go Gin/Echo/Fiber/Chi + `net/http` `HandleFunc` + `r.Group(..., mw...)`
    if lang == Language::Go
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        let method = ftxt.rsplit('.').next().unwrap_or("");
        let method_upper = method.to_ascii_uppercase();
        if (method == "Group" || method == "Use")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('"') || atxt.starts_with('`') {
                    let unq = atxt.trim_matches(|ch| ch == '"' || ch == '`');
                    if unq.starts_with('/')
                        && unq.len() > 1
                        && !route_prefixes.iter().any(|p| p == unq)
                    {
                        route_prefixes.push(unq.to_string());
                    }
                }
            }
        }
        if method == "Group" || method == "Use" {
            let gtxt = node_text(node, src);
            file_middleware_guards.extend(classify_guards(gtxt, cfg));
        }
        let is_go_http = matches!(
            method_upper.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HANDLEFUNC"
        );
        if is_go_http
            && ftxt.contains('.')
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path = None;
            let mut calls = Vec::new();
            let mut guards = file_middleware_guards.clone();
            let mut seen_handler = false;
            let mut route_taints = Vec::new();
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;

            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let ak = arg.kind();
                if matches!(ak, "(" | ")" | ",") {
                    continue;
                }
                let atxt = node_text(arg, src).trim();
                if (atxt.starts_with('"') || atxt.starts_with('`')) && route_path.is_none() {
                    route_path = Some(atxt.trim_matches(|ch| ch == '"' || ch == '`').to_string());
                } else if ak == "func_literal" {
                    seen_handler = true;
                    let inline_body = node_text(arg, src);
                    guards.extend(classify_fn_guards_cfg(arg, src, cfg));
                    collect_calls(arg, src, &mut calls);
                    let handler_label = route_path
                        .as_deref()
                        .map(|rp| format!("{} {}", method_upper, rp))
                        .unwrap_or_else(|| format!("go_inline_{}", line_start));
                    let t_inline = crate::taint::analyze_function_taint(
                        arg,
                        src,
                        rel_path,
                        lang,
                        &handler_label,
                        route_path.as_deref(),
                    );
                    if let Some(sk) =
                        classify_sink(route_path.as_deref().unwrap_or("inline"), inline_body)
                    {
                        let inline_name = format!("inline_sink_{}", line_start);
                        let mut inline_calls = Vec::new();
                        collect_calls(arg, src, &mut inline_calls);
                        let mut sink_sym = SymbolInfo::base(
                            format!("{}::inline_sink:{}", rel_path, line_start),
                            rel_path,
                            inline_name.clone(),
                            SymbolKind::Sink,
                            Some(sk),
                            arg.start_position().row + 1,
                            arg.end_position().row + 1,
                            classify_fn_guards_cfg(arg, src, cfg),
                            inline_calls,
                            None,
                        );
                        sink_sym.has_db_crud_sink = t_inline.has_db_crud_sink;
                        sink_sym.db_crud_line = t_inline.db_crud_line;
                        sink_sym.has_resource_id = t_inline.has_resource_id;
                        sink_sym.has_taint_source = t_inline.has_taint_source;
                        sink_sym.guards.extend(t_inline.guards.iter().copied());
                        symbols.push(sink_sym);
                        calls.push(inline_name);
                    }
                    route_taints.push(t_inline);
                } else {
                    let short = atxt
                        .split('(')
                        .next()
                        .unwrap_or(atxt)
                        .rsplit('.')
                        .next()
                        .unwrap_or(atxt)
                        .trim();
                    if !seen_handler && is_auth_guard_ident(short, cfg) {
                        guards.insert(GuardKind::Auth);
                    } else if !seen_handler && is_lock_guard_ident(short, cfg) {
                        guards.insert(GuardKind::TxLock);
                    } else if !short.is_empty() {
                        seen_handler = true;
                        calls.push(short.to_string());
                    }
                    collect_calls(arg, src, &mut calls);
                }
            }

            if let Some(rp) = route_path {
                let label_method = if method_upper == "HANDLEFUNC" {
                    "HTTP".to_string()
                } else {
                    method_upper
                };
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("{} {}", label_method, rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                for t in route_taints {
                    route_sym.apply_taint(t);
                }
                symbols.push(route_sym);
                return;
            }
        }
    }

    // 2e. Next.js App Router (`app/**/route.ts|js`): exported GET/POST/PUT/PATCH/DELETE
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && (rel_path.ends_with("/route.ts")
            || rel_path.ends_with("/route.tsx")
            || rel_path.ends_with("/route.js")
            || rel_path == "route.ts")
        && kind == "function_declaration"
        && let Some(name_node) = node.child_by_field_name("name")
    {
        let fn_name = node_text(name_node, src).trim().to_string();
        if matches!(
            fn_name.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            let route_p = format!(
                "/{}",
                rel_path
                    .trim_start_matches("src/")
                    .trim_start_matches("app/")
                    .trim_end_matches("/route.ts")
                    .trim_end_matches("/route.tsx")
                    .trim_end_matches("/route.js")
            );
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            let has_res_id = crate::taint::has_resource_id_expr("", Some(&route_p));
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                format!("{} {}", fn_name, route_p),
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                HashSet::new(),
                vec![fn_name],
                Some(route_p),
            );
            route_sym.has_resource_id = has_res_id;
            symbols.push(route_sym);
        }
    }

    // 2f. Rust Actix-web `#[post("/...")]` / `#[get("/...")]` attribute_item + function_item
    if lang == Language::Rust && kind == "attribute_item" {
        let atxt = node_text(node, src);
        for m in ["get", "post", "put", "patch", "delete"] {
            let needle = format!("#[{}(\"", m);
            if let Some(pos) = atxt.find(&needle) {
                let rest = &atxt[pos + needle.len()..];
                if let Some(q2) = rest.find('"') {
                    let rp = rest[..q2].to_string();
                    if let Some(next_fn) = node.next_named_sibling()
                        && next_fn.kind() == "function_item"
                        && let Some(name_node) = next_fn.child_by_field_name("name")
                    {
                        let fn_name = node_text(name_node, src).trim().to_string();
                        let line_start = next_fn.start_position().row + 1;
                        let line_end = next_fn.end_position().row + 1;
                        let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                        let mut route_sym = SymbolInfo::base(
                            format!("{}::route:{}", rel_path, line_start),
                            rel_path,
                            format!("{} {}", m.to_ascii_uppercase(), rp),
                            SymbolKind::Route,
                            None,
                            line_start,
                            line_end,
                            HashSet::new(),
                            vec![fn_name],
                            Some(rp),
                        );
                        route_sym.has_resource_id = has_res_id;
                        symbols.push(route_sym);
                    }
                }
            }
        }
    }

    // 3. Function / Method declarations (TS/JS, Rust, Python, Go)
    if matches!(
        kind,
        "function_declaration"
            | "method_definition"
            | "function_item"
            | "function_definition"
            | "method_declaration"
    ) && let Some(name_node) = node.child_by_field_name("name")
    {
        let name = node_text(name_node, src).trim().to_string();
        let body = node_text(node, src);
        let mut calls = Vec::new();
        collect_calls(node, src, &mut calls);
        let guards = classify_fn_guards_cfg(node, src, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        let mut sym = SymbolInfo::base(
            format!("{}::{}", rel_path, name),
            rel_path,
            name.clone(),
            sym_kind,
            sink_kind,
            node.start_position().row + 1,
            node.end_position().row + 1,
            guards,
            calls,
            None,
        );
        sym.apply_taint(crate::taint::analyze_function_taint(
            node, src, rel_path, lang, &name, None,
        ));
        symbols.push(sym);
    }

    // 4. Arrow functions assigned to const/let: const foo = async (...) => { ... }
    if kind == "variable_declarator"
        && let (Some(name_node), Some(val_node)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        && matches!(val_node.kind(), "arrow_function" | "function_expression")
    {
        let name = node_text(name_node, src).trim().to_string();
        let body = node_text(val_node, src);
        let mut calls = Vec::new();
        collect_calls(val_node, src, &mut calls);
        let guards = classify_fn_guards_cfg(val_node, src, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        let mut sym = SymbolInfo::base(
            format!("{}::{}", rel_path, name),
            rel_path,
            name.clone(),
            sym_kind,
            sink_kind,
            node.start_position().row + 1,
            node.end_position().row + 1,
            guards,
            calls,
            None,
        );
        sym.apply_taint(crate::taint::analyze_function_taint(
            val_node, src, rel_path, lang, &name, None,
        ));
        symbols.push(sym);
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_node(
            child,
            src,
            rel_path,
            lang,
            cfg,
            file_middleware_guards,
            imports,
            symbols,
            route_prefixes,
        );
    }
}

pub fn resolve_import_target(
    from_file: &str,
    spec: &str,
    known_files: &HashSet<String>,
) -> Option<String> {
    // 1. Rust `rust::crate/...` or `rust::super/...`
    if let Some(rs_spec) = spec.strip_prefix("rust::") {
        if let Some(mut rest) = rs_spec.strip_prefix("super") {
            let mut dir = Path::new(from_file).parent()?;
            // If `from_file` is `src/services/account.rs` (not `mod.rs`), `super::` refers to `src/services/`
            if !from_file.ends_with("mod.rs")
                && !from_file.ends_with("lib.rs")
                && !from_file.ends_with("main.rs")
            {
                // `super` in `src/services/account.rs` is `src/services`, and each extra `super/` walks up
                rest = rest.strip_prefix('/').unwrap_or(rest);
            } else if let Some(p) = dir.parent() {
                dir = p;
                rest = rest.strip_prefix('/').unwrap_or(rest);
            }
            while let Some(after) = rest.strip_prefix("super/") {
                if let Some(p) = dir.parent() {
                    dir = p;
                }
                rest = after;
            }
            let base = if rest.is_empty() {
                dir.to_string_lossy().to_string()
            } else {
                dir.join(rest).to_string_lossy().replace('\\', "/")
            };
            for ext in [".rs", "/mod.rs"] {
                let cand = format!("{}{}", base, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
            return None;
        }

        let cleaned = rs_spec.strip_prefix("crate/").unwrap_or(rs_spec);
        for prefix in ["src/", ""] {
            for ext in [".rs", "/mod.rs"] {
                let cand = format!("{}{}{}", prefix, cleaned, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
        }
        return None;
    }

    // 2. Python `py::...` (handles relative `.db`, `..pkg.db` relative to `from_file`)
    if let Some(py_spec) = spec.strip_prefix("py::") {
        let dot_count = py_spec.chars().take_while(|&c| c == '.').count();
        let mod_tail = py_spec[dot_count..].replace('.', "/");
        if dot_count > 0 {
            let mut dir = Path::new(from_file).parent()?;
            for _ in 1..dot_count {
                if let Some(p) = dir.parent() {
                    dir = p;
                }
            }
            let base = if mod_tail.is_empty() {
                dir.to_string_lossy().to_string()
            } else {
                dir.join(&mod_tail).to_string_lossy().replace('\\', "/")
            };
            for ext in [".py", "/__init__.py"] {
                let cand = format!("{}{}", base, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
            return None;
        }
        for prefix in ["src/", "app/", ""] {
            for ext in [".py", "/__init__.py"] {
                let cand = format!("{}{}{}", prefix, mod_tail, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
        }
        return None;
    }

    // 3. TS/JS `@/` or `~/` path aliases
    if let Some(alias_rest) = spec.strip_prefix("@/").or_else(|| spec.strip_prefix("~/")) {
        for prefix in ["src/", ""] {
            for ext in ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"] {
                let cand = format!("{}{}{}", prefix, alias_rest, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
        }
        return None;
    }

    // 4. Relative `./` or `../` imports
    if !spec.starts_with('.') {
        return None;
    }
    let parent = Path::new(from_file).parent()?;
    let joined = parent.join(spec);
    let mut stack: Vec<String> = Vec::new();
    for comp in joined.components() {
        match comp {
            std::path::Component::Normal(s) => stack.push(s.to_string_lossy().to_string()),
            std::path::Component::ParentDir => {
                stack.pop();
            }
            _ => {}
        }
    }
    let base = stack.join("/");
    for ext in ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"] {
        let cand = format!("{}{}", base, ext);
        if known_files.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_comments_preserves_urls_and_strips_for_update_comment() {
        let code = r#"
            const url = "https://api.stripe.com/v1/charges"; // FOR UPDATE
            // requireAuth()
        "#;
        let cleaned = strip_comments(code);
        assert!(cleaned.contains("https://api.stripe.com/v1/charges"));
        assert!(!cleaned.contains("FOR UPDATE"));
        assert!(!cleaned.contains("requireAuth"));
    }

    #[test]
    fn test_resolve_aliases_and_rust_python_relative_modules() {
        let mut known = HashSet::new();
        known.insert("src/services/ledger.ts".to_string());
        known.insert("src/services/helper.rs".to_string());
        known.insert("src/db/queries.rs".to_string());
        known.insert("src/py_pkg/db.py".to_string());
        known.insert("app/db.py".to_string());

        assert_eq!(
            resolve_import_target("src/routes/checkout.ts", "@/services/ledger", &known),
            Some("src/services/ledger.ts".to_string())
        );
        assert_eq!(
            resolve_import_target("src/main.rs", "rust::crate/db/queries", &known),
            Some("src/db/queries.rs".to_string())
        );
        assert_eq!(
            resolve_import_target("src/services/account.rs", "rust::super/helper", &known),
            Some("src/services/helper.rs".to_string())
        );
        assert_eq!(
            resolve_import_target("src/py_pkg/app.py", "py::.db", &known),
            Some("src/py_pkg/db.py".to_string())
        );
    }

    fn parse_inline_ts(code: &str) -> FileAstSummary {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(code, None).unwrap();
        let cfg = VeriForgeConfig::default();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            code.as_bytes(),
            "test.ts",
            Language::TypeScript,
            &cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        let mut frontend_calls = Vec::new();
        let mut static_findings = Vec::new();
        crate::taint::extract_frontend_calls_and_bugs(
            tree.root_node(),
            code.as_bytes(),
            "test.ts",
            Language::TypeScript,
            &mut frontend_calls,
            &mut static_findings,
        );
        FileAstSummary {
            rel_path: "test.ts".into(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            ..Default::default()
        }
    }

    #[test]
    fn test_b02_guard_after_write_and_branch_only_do_not_protect() {
        let code = r#"
            function debitLateAuth(amount: number) {
                balance -= amount;
                requireAuth();
            }
            function debitBranchLock(cond: boolean, amount: number) {
                if (cond) { withTransaction(); }
                balance -= amount;
            }
            function debitStringFake(amount: number) {
                const label = "requireAuth FOR UPDATE";
                balance -= amount;
            }
        "#;
        let ast = parse_inline_ts(code);
        for sym in &ast.symbols {
            assert!(
                !sym.guards.contains(&GuardKind::Auth),
                "{} must NOT have Auth guard",
                sym.name
            );
            assert!(
                !sym.guards.contains(&GuardKind::TxLock),
                "{} must NOT have TxLock guard",
                sym.name
            );
        }
    }

    #[test]
    fn test_b03_middleware_order_and_b07_inline_route_sink() {
        let code = r#"
            app.post('/api/late-mw', handler, requireAuth);
            app.post('/api/inline-pay', async (req, res) => {
                await stripe.charges.create({ amount: req.body.amount });
            });
        "#;
        let ast = parse_inline_ts(code);
        let late = ast
            .symbols
            .iter()
            .find(|s| s.name == "POST /api/late-mw")
            .unwrap();
        assert!(!late.guards.contains(&GuardKind::Auth));

        let inline_sink = ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Sink && s.sink_kind == Some(SinkKind::PaymentMutation))
            .expect("inline route sink must be extracted");
        assert!(!inline_sink.guards.contains(&GuardKind::Auth));
    }

    #[test]
    fn test_b06_python_fastapi_route_discovery() {
        let py_code = r#"
@app.post("/api/v1/py/withdraw")
def withdraw(amount: int):
    balance -= amount
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(py_code, None).unwrap();
        let cfg = VeriForgeConfig::default();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            py_code.as_bytes(),
            "app.py",
            Language::Python,
            &cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/v1/py/withdraw")
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Sink && s.name == "withdraw")
        );
    }

    fn parse_inline_file(rel_path: &str, code: &str, cfg: &VeriForgeConfig) -> FileAstSummary {
        let lang = if rel_path.ends_with(".go") {
            Language::Go
        } else if rel_path.ends_with(".py") {
            Language::Python
        } else if rel_path.ends_with(".rs") {
            Language::Rust
        } else if rel_path.ends_with(".js") {
            Language::JavaScript
        } else {
            Language::TypeScript
        };
        let mut parser = Parser::new();
        let ts_lang: tree_sitter::Language = match lang {
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Sql | Language::Config | Language::Manifest => unreachable!(),
        };
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            code.as_bytes(),
            rel_path,
            lang,
            cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        let mut frontend_calls = Vec::new();
        let mut static_findings = Vec::new();
        crate::taint::extract_frontend_calls_and_bugs(
            tree.root_node(),
            code.as_bytes(),
            rel_path,
            lang,
            &mut frontend_calls,
            &mut static_findings,
        );
        FileAstSummary {
            rel_path: rel_path.into(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            ..Default::default()
        }
    }

    #[test]
    fn test_universal_go_gin_group_and_net_http() {
        let go_code = r#"
package main

func registerRoutes(r *gin.Engine) {
    api := r.Group("/api/v1")
    api.Use(AuthMiddleware())
    api.POST("/charge", handleCharge)
    http.HandleFunc("/webhook/stripe", handleWebhook)
}

func handleCharge(c *gin.Context) {
    razorpay.Orders.Create(100)
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
    tx.Exec("UPDATE balances SET amt = amt - 1")
}
"#;
        let ast = parse_inline_file("main.go", go_code, &VeriForgeConfig::default());
        let charge_route = ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Route && s.name == "POST /charge")
            .expect("Go Gin Group route must be extracted");
        assert!(
            charge_route.guards.contains(&GuardKind::Auth),
            "Go Gin Group.Use(AuthMiddleware) must propagate Auth guard"
        );
        assert!(
            ast.symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "HTTP /webhook/stripe"),
            "net/http HandleFunc route must be extracted"
        );
        assert!(
            ast.symbols.iter().any(|s| s.kind == SymbolKind::Sink
                && s.name == "handleCharge"
                && s.sink_kind == Some(SinkKind::PaymentMutation)),
            "Razorpay sink must be detected"
        );
        assert!(
            ast.symbols.iter().any(|s| s.kind == SymbolKind::Sink
                && s.name == "handleWebhook"
                && s.sink_kind == Some(SinkKind::BalanceUpdate)),
            "tx.Exec sink must be detected"
        );
    }

    #[test]
    fn test_universal_nextjs_nestjs_trpc_django_actix() {
        let cfg = VeriForgeConfig::default();

        // Next.js App Router
        let nextjs_code = r#"
export async function POST(req: Request) {
    await prisma.ledger.update({ data: { balance: 0 } });
}
"#;
        let next_ast = parse_inline_file("app/api/pay/route.ts", nextjs_code, &cfg);
        assert!(
            next_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/pay"),
            "Next.js App Router route must be extracted"
        );
        assert!(
            next_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Sink && s.sink_kind == Some(SinkKind::BalanceUpdate)),
            "Prisma sink must be detected"
        );

        // NestJS
        let nest_code = r#"
@Controller("billing")
export class BillingController {
    @Post("payout")
    @UseGuards(AuthGuard)
    async payout() {
        await stripe.transfers.create({});
    }
}
"#;
        let nest_ast = parse_inline_file("billing.controller.ts", nest_code, &cfg);
        let nest_route = nest_ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Route && s.name.contains("payout"))
            .expect("NestJS @Post route must be extracted");
        assert!(nest_route.guards.contains(&GuardKind::Auth));

        // tRPC
        let trpc_code = r#"
export const payRouter = router({
    openPay: publicProcedure.mutation(async () => {
        await paddle.transactions.create({});
    }),
    safePay: protectedProcedure.mutation(async () => {
        await paddle.transactions.create({});
    }),
});
"#;
        let trpc_ast = parse_inline_file("trpc/pay.ts", trpc_code, &cfg);
        let trpc_routes: Vec<_> = trpc_ast
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Route && s.name.starts_with("TRPC trpc/pay.ts:"))
            .collect();
        assert_eq!(
            trpc_routes.len(),
            2,
            "Both tRPC mutations must be extracted"
        );
        assert!(
            trpc_routes
                .iter()
                .any(|r| !r.guards.contains(&GuardKind::Auth)),
            "tRPC publicProcedure must NOT have Auth guard"
        );
        assert!(
            trpc_routes
                .iter()
                .any(|r| r.guards.contains(&GuardKind::Auth)),
            "tRPC protectedProcedure must have Auth guard"
        );

        // Django
        let django_code = r#"
urlpatterns = [
    path("api/v1/refund/", refund_view),
]
"#;
        let dj_ast = parse_inline_file("urls.py", django_code, &cfg);
        assert!(
            dj_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "DJANGO /api/v1/refund/"),
            "Django path() route must be extracted"
        );

        // Rust Actix-web
        let actix_code = r#"
#[post("/api/v1/transfer")]
async fn transfer_funds() {
    let amount = 10;
    balance -= amount;
}
"#;
        let actix_ast = parse_inline_file("routes.rs", actix_code, &cfg);
        assert!(
            actix_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/v1/transfer"),
            "Actix-web #[post] route must be extracted"
        );
    }

    #[test]
    fn test_public_routes_suppresses_auth_only() {
        let ts_code = r#"
app.post('/api/v1/auth/2fa/confirm', async (req, res) => {
    await stripe.charges.create({ amount: 100 });
});
"#;
        let cfg = VeriForgeConfig::default();
        let ast = parse_inline_file("auth.ts", ts_code, &cfg);
        let res =
            crate::lattice::solve_guard_lattice_with_public(&[ast], &cfg.guards.public_routes);
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "VF-AUTH-001"),
            "public_routes must suppress VF-AUTH-001"
        );
        assert!(
            res.findings.iter().any(|f| f.rule_id == "VF-RACE-001"),
            "public_routes must still report VF-RACE-001 if unlocked"
        );
    }

    #[test]
    fn test_phase2_taint_idor_and_frontend_extraction() {
        let cfg = VeriForgeConfig::default();
        let backend = r#"
app.get('/api/users/:id', requireAuth, async (req, res) => {
    const id = req.params.id;
    return await db.query(`SELECT * FROM users WHERE id = ${id}`);
});
app.post('/api/exec', requireAuth, async (req, res) => {
    const host = req.body.host;
    exec("ping -c 1 " + host);
});
function readSafeFile(req: any) {
    const safe = path.basename(req.query.name);
    return fs.readFileSync('/var/data/' + safe);
}
app.post('/api/proxy', requireAuth, async (req, res) => {
    const u = req.body.url;
    await fetch(u);
});
"#;
        let b_ast = parse_inline_file("routes.ts", backend, &cfg);
        let hits: Vec<_> = b_ast
            .symbols
            .iter()
            .flat_map(|s| s.local_taint_hits.iter())
            .collect();
        assert!(
            hits.iter().any(|h| h.rule_id == "VF-SQLI-001"),
            "Must detect SQLi in interpolated query"
        );
        assert!(
            hits.iter().any(|h| h.rule_id == "VF-CMDI-001"),
            "Must detect CMDi in exec()"
        );
        assert!(
            !hits.iter().any(|h| h.rule_id == "VF-PATH-001"),
            "path.basename sanitizer must clear VF-PATH-001"
        );
        assert!(
            hits.iter().any(|h| h.rule_id == "VF-SSRF-001"),
            "Must detect SSRF in outbound fetch(u)"
        );

        let user_route = b_ast
            .symbols
            .iter()
            .find(|s| s.name == "GET /api/users/:id")
            .unwrap();
        assert!(user_route.has_resource_id);
        assert!(user_route.has_db_crud_sink);

        let fe = r#"
export async function loadProfile(id: string) {
    try {
        await fetch(`/api/profile/${id}`);
    } catch (e) {}
    try {
        await fetch(`/api/users/${id}`);
    } catch (e) {
        console.log(e);
    }
}
"#;
        let fe_ast = parse_inline_file("web/profile.tsx", fe, &cfg);
        assert_eq!(fe_ast.frontend_calls.len(), 2);
        assert!(
            fe_ast
                .static_findings
                .iter()
                .filter(|f| f.rule_id == "VF-FE-ERR")
                .count()
                >= 2,
            "Must flag empty catch and console-only catch as VF-FE-ERR"
        );

        let safe_tagged = r#"
function runSafeTagged(req: any) {
    const id = req.params.id;
    return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}
"#;
        let safe_ast = parse_inline_file("safe.ts", safe_tagged, &cfg);
        assert!(
            safe_ast
                .symbols
                .iter()
                .all(|s| s.local_taint_hits.is_empty()),
            "prisma.$queryRaw tagged template must NOT trigger VF-SQLI-001"
        );
    }
}
