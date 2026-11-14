use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Parser};
use vf_core::{IndexedFile, Language, VeriForgeConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Route,
    Function,
    Sink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    PaymentMutation,
    BalanceUpdate,
    SqlWrite,
    AuthMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardKind {
    Auth,
    TxLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRef {
    pub symbol_name: String,
    pub from_specifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAstSummary {
    pub rel_path: String,
    pub imports: Vec<ImportRef>,
    pub symbols: Vec<SymbolInfo>,
}

pub fn parse_file_ast_with_hash(
    file: &IndexedFile,
    cfg: &VeriForgeConfig,
) -> Option<(String, FileAstSummary)> {
    let bytes = fs::read(&file.abs_path).ok()?;
    let actual_hash = blake3::hash(&bytes).to_hex().to_string();
    let source = String::from_utf8(bytes).ok()?;
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
        Language::Go | Language::Sql => return None,
    }

    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    let src_bytes = source.as_bytes();

    let mut imports = Vec::new();
    let mut symbols = Vec::new();

    extract_node(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        cfg,
        &mut imports,
        &mut symbols,
    );

    Some((
        actual_hash,
        FileAstSummary {
            rel_path: file.rel_path.clone(),
            imports,
            symbols,
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

fn classify_sink(name: &str, body: &str) -> Option<SinkKind> {
    let low_name = name.to_ascii_lowercase();
    let low_body = strip_comments(body).to_ascii_lowercase();

    if low_body.contains("stripe.")
        || low_body.contains("charges.create")
        || low_body.contains("paymentintent")
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
            || low_body.contains("set "))
    {
        return Some(SinkKind::BalanceUpdate);
    }
    if (low_body.contains("update ") && low_body.contains("set "))
        || low_body.contains("insert into ")
        || low_body.contains("delete from ")
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

fn extract_node(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    cfg: &VeriForgeConfig,
    imports: &mut Vec<ImportRef>,
    symbols: &mut Vec<SymbolInfo>,
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

    // 2a. Express / Router HTTP Route entries (TS/JS): app.post('/path', ...handlers)
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        let method = ftxt.rsplit('.').next().unwrap_or("");
        if matches!(method, "get" | "post" | "put" | "patch" | "delete")
            && (ftxt.starts_with("app.") || ftxt.starts_with("router.") || ftxt.contains("Router"))
        {
            let full_txt = node_text(node, src);
            let mut route_path = None;
            let mut calls = Vec::new();
            if let Some(args) = node.child_by_field_name("arguments") {
                let mut c = args.walk();
                for arg in args.children(&mut c) {
                    let atxt = node_text(arg, src).trim();
                    if (atxt.starts_with('\'') || atxt.starts_with('"')) && route_path.is_none() {
                        route_path =
                            Some(atxt.trim_matches(|ch| ch == '\'' || ch == '"').to_string());
                    } else if arg.kind() == "identifier" {
                        calls.push(atxt.to_string());
                    } else {
                        collect_calls(arg, src, &mut calls);
                    }
                }
            }
            let guards = classify_guards(full_txt, cfg);
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            let r_label = format!(
                "{} {}",
                method.to_ascii_uppercase(),
                route_path.clone().unwrap_or_else(|| "/unknown".into())
            );
            symbols.push(SymbolInfo {
                id: format!("{}::route:{}", rel_path, line_start),
                rel_path: rel_path.to_string(),
                name: r_label,
                kind: SymbolKind::Route,
                sink_kind: None,
                line_start,
                line_end,
                guards,
                calls,
                route_path,
            });
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
                symbols.push(SymbolInfo {
                    id: format!("{}::route:{}", rel_path, line_start),
                    rel_path: rel_path.to_string(),
                    name: format!("{} {}", method, rp),
                    kind: SymbolKind::Route,
                    sink_kind: None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    route_path: Some(rp),
                });
            }
        }
    }

    // 3. Function / Method declarations (TS/JS, Rust, Python)
    if matches!(
        kind,
        "function_declaration" | "method_definition" | "function_item" | "function_definition"
    ) && let Some(name_node) = node.child_by_field_name("name")
    {
        let name = node_text(name_node, src).trim().to_string();
        let body = node_text(node, src);
        let mut calls = Vec::new();
        collect_calls(node, src, &mut calls);
        let guards = classify_guards(body, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        symbols.push(SymbolInfo {
            id: format!("{}::{}", rel_path, name),
            rel_path: rel_path.to_string(),
            name,
            kind: sym_kind,
            sink_kind,
            line_start: node.start_position().row + 1,
            line_end: node.end_position().row + 1,
            guards,
            calls,
            route_path: None,
        });
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
        let guards = classify_guards(body, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        symbols.push(SymbolInfo {
            id: format!("{}::{}", rel_path, name),
            rel_path: rel_path.to_string(),
            name,
            kind: sym_kind,
            sink_kind,
            line_start: node.start_position().row + 1,
            line_end: node.end_position().row + 1,
            guards,
            calls,
            route_path: None,
        });
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_node(child, src, rel_path, lang, cfg, imports, symbols);
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
}
