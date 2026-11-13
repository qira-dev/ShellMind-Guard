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

pub fn parse_file_ast(file: &IndexedFile, cfg: &VeriForgeConfig) -> Option<FileAstSummary> {
    let source = fs::read_to_string(&file.abs_path).ok()?;
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
    let bytes = source.as_bytes();

    let mut imports = Vec::new();
    let mut symbols = Vec::new();

    extract_node(
        root,
        bytes,
        &file.rel_path,
        file.language,
        cfg,
        &mut imports,
        &mut symbols,
    );

    Some(FileAstSummary {
        rel_path: file.rel_path.clone(),
        imports,
        symbols,
    })
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn find_line_comment_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Ignore URLs like https:// or http://
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
            // Preserve Rust #[attr] lines, strip Python # comments
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
    let low_body = body.to_ascii_lowercase();

    if low_body.contains("stripe.")
        || low_body.contains("charges.create")
        || low_body.contains("paymentintent")
        || (low_name.contains("charge") && low_body.contains("amount"))
    {
        return Some(SinkKind::PaymentMutation);
    }
    if (low_body.contains("balance") || low_name.contains("balance") || low_name.contains("withdraw") || low_name.contains("debit"))
        && (low_body.contains("update") || low_body.contains("-=") || low_body.contains("+=") || low_body.contains("set "))
    {
        return Some(SinkKind::BalanceUpdate);
    }
    if low_body.contains("update ") && low_body.contains("set ")
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
        && let Some(func) = node.child_by_field_name("function") {
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

    // 1. Cross-file imports (TS/JS)
    if kind == "import_statement" {
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
        }
    }

    // 2. Express / Router HTTP Route entries: app.post('/path', ...handlers)
    if (lang == Language::TypeScript || lang == Language::JavaScript) && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function") {
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
                            route_path = Some(atxt.trim_matches(|ch| ch == '\'' || ch == '"').to_string());
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
                return;
            }
        }

    // 3. Function / Method declarations (TS/JS, Rust, Python)
    if matches!(
        kind,
        "function_declaration" | "method_definition" | "function_item" | "function_definition"
    )
        && let Some(name_node) = node.child_by_field_name("name") {
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
            return;
        }

    // Arrow functions assigned to const/let: const foo = async (...) => { ... }
    if kind == "variable_declarator"
        && let (Some(name_node), Some(val_node)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
            && matches!(val_node.kind(), "arrow_function" | "function_expression") {
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

pub fn resolve_import_target(from_file: &str, spec: &str, known_files: &HashSet<String>) -> Option<String> {
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
}
