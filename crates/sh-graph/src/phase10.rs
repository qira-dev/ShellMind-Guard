use crate::ast::{
    Confidence, FileAstSummary, GuardKind, SinkKind, SymbolInfo, SymbolKind, node_text,
    strip_comments,
};
use crate::lattice::{GraphAnalysisResult, LatticeFinding, TraceHop};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sh_core::Language;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;
use tree_sitter::Node;

/// Inferred parameter data type for targeted `--deep` schema validation & payload fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamTypeHint {
    String,
    Integer,
    Number,
    Boolean,
    Unknown,
}

/// Extracted parameter constraint on an HTTP endpoint route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteParamSpec {
    pub name: String,
    pub location: String,
    pub type_hint: ParamTypeHint,
    #[serde(default)]
    pub is_financial: bool,
    #[serde(default)]
    pub has_positive_bound: bool,
}

/// Normalized API route + parameter contract discovered via AST or OpenAPI/Swagger specs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RouteSchema {
    pub method: String,
    pub path: String,
    pub source_file: String,
    #[serde(default)]
    pub line: usize,
    #[serde(default)]
    pub params: Vec<RouteParamSpec>,
    #[serde(default)]
    pub from_openapi: bool,
}

fn path_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?::([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}|\[([A-Za-z_][A-Za-z0-9_]*)\]|<(?:[A-Za-z_]+:)?([A-Za-z_][A-Za-z0-9_]*)>)"#)
            .expect("valid route path param regex")
    })
}

fn req_field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:req(?:uest)?\.(body|query|params)|ctx\.(?:request\.)?body)\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[["']([A-Za-z_][A-Za-z0-9_]*)["']\])"#,
        )
        .expect("valid request field access regex")
    })
}

fn destructured_req_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\{\s*([A-Za-z0-9_,\s:]+)\}\s*=\s*(?:req(?:uest)?\.(body|query|params))"#)
            .expect("valid destructured req field regex")
    })
}

fn go_py_query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:c\.(Query|PostForm|Param)|r\.(?:FormValue|PathValue)|URL\.Query\(\)\.Get|request\.(?:args|form)\.get)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#)
            .expect("valid go/py query param regex")
    })
}

pub(crate) fn is_financial_param_name(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "amount"
            | "price"
            | "unit_price"
            | "unitprice"
            | "total"
            | "subtotal"
            | "quantity"
            | "qty"
            | "discount"
            | "balance"
            | "fee"
            | "rate"
            | "credits"
            | "delta"
    ) || low.ends_with("_amount")
        || low.ends_with("amount")
        || low.ends_with("_price")
        || low.ends_with("price")
        || low.ends_with("_qty")
        || low.ends_with("quantity")
}

fn infer_param_type(name: &str, schema_type: Option<&str>) -> ParamTypeHint {
    if let Some(st) = schema_type {
        return match st.to_ascii_lowercase().as_str() {
            "integer" | "int" | "i32" | "i64" | "u32" | "u64" => ParamTypeHint::Integer,
            "number" | "float" | "double" | "decimal" | "f64" | "float64" => ParamTypeHint::Number,
            "boolean" | "bool" => ParamTypeHint::Boolean,
            "string" | "str" => ParamTypeHint::String,
            _ => ParamTypeHint::Unknown,
        };
    }
    if is_financial_param_name(name) || name.to_ascii_lowercase().ends_with("count") {
        ParamTypeHint::Number
    } else if name.eq_ignore_ascii_case("id") || name.to_ascii_lowercase().ends_with("id") {
        ParamTypeHint::String
    } else {
        ParamTypeHint::Unknown
    }
}

fn has_positive_bound_for(code_low: &str, param_name: &str) -> bool {
    let p = param_name.to_ascii_lowercase();
    code_low.contains(&format!("{p} > 0"))
        || code_low.contains(&format!("{p} >= 1"))
        || code_low.contains(&format!("{p} <= 0"))
        || code_low.contains(&format!("{p} < 1"))
        || code_low.contains(&format!("{p} < 0"))
        || code_low.contains(&format!("0 < {p}"))
        || code_low.contains(".positive(")
        || code_low.contains("gt=0")
        || code_low.contains("ge=1")
        || code_low.contains("@min(1")
        || code_low.contains("@positive")
        || code_low.contains("nonzero")
        || code_low.contains("isfinite(")
        || code_low.contains("is_finite(")
}

fn add_unique_param(params: &mut Vec<RouteParamSpec>, cand: RouteParamSpec) {
    if let Some(existing) = params
        .iter_mut()
        .find(|p| p.name == cand.name && p.location == cand.location)
    {
        if existing.type_hint == ParamTypeHint::Unknown && cand.type_hint != ParamTypeHint::Unknown
        {
            existing.type_hint = cand.type_hint;
        }
        existing.is_financial |= cand.is_financial;
        existing.has_positive_bound |= cand.has_positive_bound;
        return;
    }
    params.push(cand);
}

fn extract_params_from_route_text(path: &str, code: &str) -> Vec<RouteParamSpec> {
    let mut params = Vec::new();
    let cleaned = strip_comments(code);
    let low = cleaned.to_ascii_lowercase();

    for cap in path_param_re().captures_iter(path) {
        if let Some(name) = cap
            .get(1)
            .or_else(|| cap.get(2))
            .or_else(|| cap.get(3))
            .or_else(|| cap.get(4))
            .map(|m| m.as_str())
        {
            let fin = is_financial_param_name(name);
            add_unique_param(
                &mut params,
                RouteParamSpec {
                    name: name.to_string(),
                    location: "path".into(),
                    type_hint: infer_param_type(name, None),
                    is_financial: fin,
                    has_positive_bound: has_positive_bound_for(&low, name),
                },
            );
        }
    }

    for cap in req_field_re().captures_iter(&cleaned) {
        let loc = cap.get(1).map(|m| m.as_str()).unwrap_or("body");
        if let Some(field) = cap.get(2).or_else(|| cap.get(3)).map(|m| m.as_str()) {
            let fin = is_financial_param_name(field);
            add_unique_param(
                &mut params,
                RouteParamSpec {
                    name: field.to_string(),
                    location: loc.to_string(),
                    type_hint: infer_param_type(field, None),
                    is_financial: fin,
                    has_positive_bound: has_positive_bound_for(&low, field),
                },
            );
        }
    }

    for cap in destructured_req_re().captures_iter(&cleaned) {
        let loc = cap.get(2).map(|m| m.as_str()).unwrap_or("body");
        for raw_field in cap[1].split(',') {
            let name = raw_field
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches("...");
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let fin = is_financial_param_name(name);
                add_unique_param(
                    &mut params,
                    RouteParamSpec {
                        name: name.to_string(),
                        location: loc.to_string(),
                        type_hint: infer_param_type(name, None),
                        is_financial: fin,
                        has_positive_bound: has_positive_bound_for(&low, name),
                    },
                );
            }
        }
    }

    for cap in go_py_query_re().captures_iter(&cleaned) {
        let kind = cap.get(1).map(|m| m.as_str()).unwrap_or("query");
        let loc = if kind.eq_ignore_ascii_case("Param") || kind.eq_ignore_ascii_case("PathValue") {
            "path"
        } else {
            "query"
        };
        if let Some(name) = cap.get(2).map(|m| m.as_str()) {
            let fin = is_financial_param_name(name);
            add_unique_param(
                &mut params,
                RouteParamSpec {
                    name: name.to_string(),
                    location: loc.to_string(),
                    type_hint: infer_param_type(name, None),
                    is_financial: fin,
                    has_positive_bound: has_positive_bound_for(&low, name),
                },
            );
        }
    }

    params
}

fn is_route_registration_call(node: Node, src: &[u8]) -> Option<(String, String)> {
    let txt = node_text(node, src);
    let head = txt.lines().next().unwrap_or("");
    let cap_re = route_str_re();
    let cap = cap_re.captures(head)?;
    let method = cap.get(1)?.as_str().to_ascii_uppercase();
    let path = cap.get(2)?.as_str();
    if !path.starts_with('/') {
        return None;
    }
    Some((method, path.to_string()))
}

fn route_str_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.\s*(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']"#)
            .expect("valid route extraction regex")
    })
}

/// Extracts [`RouteSchema`] entries from source AST symbols + raw route calls, including `server.mjs` style HTTP branches.
pub fn extract_ast_route_schemas(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbols: &[SymbolInfo],
) -> Vec<RouteSchema> {
    let mut schemas = Vec::new();
    let full_text = node_text(root, src);

    for sym in symbols {
        if sym.kind == SymbolKind::Route
            && let Some(ref rp) = sym.route_path
        {
            let method = sym
                .name
                .split_whitespace()
                .next()
                .unwrap_or("POST")
                .to_ascii_uppercase();
            let snippet = slice_lines(full_text, sym.line_start, sym.line_end);
            let params = extract_params_from_route_text(rp, &snippet);
            schemas.push(RouteSchema {
                method,
                path: rp.clone(),
                source_file: rel_path.to_string(),
                line: sym.line_start,
                params,
                from_openapi: false,
            });
        }
    }

    // Also scan JS/TS/Rust/Python AST nodes for inline framework registrations or raw `req.url === '/...'` branches
    collect_inline_http_schemas(root, src, rel_path, lang, &mut schemas);

    schemas
}

fn slice_lines(text: &str, start_line: usize, end_line: usize) -> String {
    if start_line == 0 || end_line < start_line {
        return String::new();
    }
    text.lines()
        .skip(start_line - 1)
        .take(end_line - start_line + 1)
        .collect::<Vec<_>>()
        .join("\n")
}

fn url_eq_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"req\.method\s*===\s*["'](GET|POST|PUT|PATCH|DELETE)["'][^\n]{0,80}req\.url\s*===\s*["']([^"']+)["']"#,
        )
        .expect("valid raw node http route regex")
    })
}

fn collect_inline_http_schemas(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    out: &mut Vec<RouteSchema>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if lang == Language::Rust
            && matches!(kind, "mod_item" | "function_item")
            && crate::ast::is_rust_test_item(node, src)
        {
            continue;
        }

        if matches!(kind, "call_expression" | "call")
            && let Some((method, path)) = is_route_registration_call(node, src)
            && !out.iter().any(|s| s.method == method && s.path == path)
        {
            let params = extract_params_from_route_text(&path, node_text(node, src));
            out.push(RouteSchema {
                method,
                path,
                source_file: rel_path.to_string(),
                line: node.start_position().row + 1,
                params,
                from_openapi: false,
            });
        }

        if kind == "if_statement" {
            let cond_line = node
                .child_by_field_name("condition")
                .map(|c| node_text(c, src))
                .unwrap_or("");
            if let Some(cap) = url_eq_re().captures(cond_line) {
                let method = cap[1].to_ascii_uppercase();
                let path = cap[2].to_string();
                let line = node.start_position().row + 1;
                let body_txt = node_text(node, src);
                let params = extract_params_from_route_text(&path, body_txt);
                if !out.iter().any(|s| s.method == method && s.path == path) {
                    out.push(RouteSchema {
                        method,
                        path,
                        source_file: rel_path.to_string(),
                        line,
                        params,
                        from_openapi: false,
                    });
                }
            }
        }

        let prev_len = stack.len();
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            stack.push(ch);
        }
        stack[prev_len..].reverse();
    }
}

/// Parses OpenAPI 3.x / Swagger 2.0 specs (`openapi.json`, `openapi.yaml`, `swagger.json`, `swagger.yaml`).
pub fn parse_openapi_route_schemas(rel_path: &str, source: &str) -> Vec<RouteSchema> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(
        fname.as_str(),
        "openapi.json"
            | "openapi.yaml"
            | "openapi.yml"
            | "swagger.json"
            | "swagger.yaml"
            | "swagger.yml"
    ) {
        return Vec::new();
    }

    if fname.ends_with(".json") {
        parse_openapi_json(rel_path, source)
    } else {
        parse_openapi_yaml_lite(rel_path, source)
    }
}

fn resolve_json_ref<'a>(root: &'a Value, val: &'a Value) -> &'a Value {
    if let Some(ref_str) = val.get("$ref").and_then(|r| r.as_str())
        && let Some(ptr) = ref_str.strip_prefix('#')
        && let Some(resolved) = root.pointer(ptr)
    {
        return resolved;
    }
    val
}

fn parse_openapi_json(rel_path: &str, source: &str) -> Vec<RouteSchema> {
    let Ok(doc) = serde_json::from_str::<Value>(source) else {
        return Vec::new();
    };
    let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (route_path, path_item) in paths {
        let Some(methods_obj) = path_item.as_object() else {
            continue;
        };
        for (method_raw, op_val) in methods_obj {
            let method = method_raw.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
            ) {
                continue;
            }
            let mut params = Vec::new();
            if let Some(param_arr) = op_val.get("parameters").and_then(|p| p.as_array()) {
                for raw_p in param_arr {
                    let p = resolve_json_ref(&doc, raw_p);
                    let Some(name) = p.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let loc = p.get("in").and_then(|v| v.as_str()).unwrap_or("query");
                    let schema = p.get("schema").map(|s| resolve_json_ref(&doc, s));
                    let ty = schema
                        .and_then(|s| s.get("type"))
                        .or_else(|| p.get("type"))
                        .and_then(|t| t.as_str());
                    let min_pos = schema
                        .and_then(|s| {
                            s.get("minimum")
                                .and_then(|m| m.as_f64())
                                .map(|v| v > 0.0)
                                .or_else(|| s.get("exclusiveMinimum").and_then(|b| b.as_bool()))
                        })
                        .unwrap_or(false);
                    let fin = is_financial_param_name(name);
                    add_unique_param(
                        &mut params,
                        RouteParamSpec {
                            name: name.to_string(),
                            location: loc.to_string(),
                            type_hint: infer_param_type(name, ty),
                            is_financial: fin,
                            has_positive_bound: min_pos,
                        },
                    );
                }
            }
            if let Some(props) = op_val
                .get("requestBody")
                .and_then(|rb| rb.get("content"))
                .and_then(|c| c.get("application/json"))
                .and_then(|j| j.get("schema"))
                .map(|s| resolve_json_ref(&doc, s))
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.as_object())
            {
                for (prop_name, prop_raw) in props {
                    let prop = resolve_json_ref(&doc, prop_raw);
                    let ty = prop.get("type").and_then(|t| t.as_str());
                    let min_pos = prop
                        .get("minimum")
                        .and_then(|m| m.as_f64())
                        .map(|v| v > 0.0)
                        .unwrap_or(false);
                    let fin = is_financial_param_name(prop_name);
                    add_unique_param(
                        &mut params,
                        RouteParamSpec {
                            name: prop_name.clone(),
                            location: "body".into(),
                            type_hint: infer_param_type(prop_name, ty),
                            is_financial: fin,
                            has_positive_bound: min_pos,
                        },
                    );
                }
            }
            out.push(RouteSchema {
                method,
                path: route_path.clone(),
                source_file: rel_path.to_string(),
                line: 1,
                params,
                from_openapi: true,
            });
        }
    }
    out
}

fn parse_openapi_yaml_lite(rel_path: &str, source: &str) -> Vec<RouteSchema> {
    let mut out = Vec::new();
    let mut in_paths = false;
    let mut paths_indent = 0usize;
    let mut cur_path: Option<String> = None;
    let mut path_indent = 0usize;
    let mut cur_method: Option<String> = None;
    let mut cur_line = 1usize;
    let mut cur_params: Vec<RouteParamSpec> = Vec::new();
    let mut cur_prop_name: Option<String> = None;
    let mut in_properties = false;
    let mut props_indent = 0usize;
    let mut seen_param_name: Option<String> = None;
    let mut seen_param_in: Option<String> = None;

    let flush_op = |out: &mut Vec<RouteSchema>,
                    rel: &str,
                    cp: &Option<String>,
                    cm: &mut Option<String>,
                    cl: usize,
                    params: &mut Vec<RouteParamSpec>| {
        if let (Some(p), Some(m)) = (cp.as_ref(), cm.take()) {
            out.push(RouteSchema {
                method: m,
                path: p.clone(),
                source_file: rel.to_string(),
                line: cl,
                params: std::mem::take(params),
                from_openapi: true,
            });
        }
    };

    for (idx, raw) in source.lines().enumerate() {
        let ln = idx + 1;
        let without_comment = raw.split('#').next().unwrap_or("");
        if without_comment.trim().is_empty() {
            continue;
        }
        let indent = without_comment.len() - without_comment.trim_start().len();
        let trimmed = without_comment.trim();

        if trimmed == "paths:" {
            in_paths = true;
            paths_indent = indent;
            continue;
        }
        if !in_paths {
            continue;
        }
        if indent <= paths_indent && trimmed != "paths:" {
            flush_op(
                &mut out,
                rel_path,
                &cur_path,
                &mut cur_method,
                cur_line,
                &mut cur_params,
            );
            in_paths = false;
            continue;
        }

        if let Some(key) = trimmed.strip_suffix(':') {
            let clean_key = key.trim_matches(|c| matches!(c, '"' | '\''));
            if clean_key.starts_with('/') && indent > paths_indent {
                flush_op(
                    &mut out,
                    rel_path,
                    &cur_path,
                    &mut cur_method,
                    cur_line,
                    &mut cur_params,
                );
                cur_path = Some(clean_key.to_string());
                path_indent = indent;
                in_properties = false;
                cur_prop_name = None;
                continue;
            }
            let up = clean_key.to_ascii_uppercase();
            if cur_path.is_some()
                && indent > path_indent
                && matches!(
                    up.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
                )
            {
                flush_op(
                    &mut out,
                    rel_path,
                    &cur_path,
                    &mut cur_method,
                    cur_line,
                    &mut cur_params,
                );
                cur_method = Some(up);
                cur_line = ln;
                in_properties = false;
                cur_prop_name = None;
                seen_param_name = None;
                seen_param_in = None;
                continue;
            }
            if clean_key == "properties" && cur_method.is_some() {
                in_properties = true;
                props_indent = indent;
                cur_prop_name = None;
                continue;
            }
            if in_properties && indent == props_indent + 2 {
                cur_prop_name = Some(clean_key.to_string());
                let fin = is_financial_param_name(clean_key);
                add_unique_param(
                    &mut cur_params,
                    RouteParamSpec {
                        name: clean_key.to_string(),
                        location: "body".into(),
                        type_hint: infer_param_type(clean_key, None),
                        is_financial: fin,
                        has_positive_bound: false,
                    },
                );
                continue;
            }
        }

        if in_properties
            && indent <= props_indent
            && trimmed != "properties:"
            && !trimmed.starts_with('-')
        {
            in_properties = false;
            cur_prop_name = None;
        }

        if cur_method.is_some() {
            let item = trimmed.trim_start_matches('-').trim();
            if let Some((k, v_raw)) = item.split_once(':') {
                let k = k.trim();
                let v = v_raw.trim().trim_matches(|c| matches!(c, '"' | '\''));
                if in_properties
                    && let Some(ref pn) = cur_prop_name
                    && let Some(last) = cur_params
                        .iter_mut()
                        .rev()
                        .find(|p| p.name == *pn && p.location == "body")
                {
                    if k == "type" {
                        last.type_hint = infer_param_type(pn, Some(v));
                    } else if k == "minimum"
                        && let Ok(mv) = v.parse::<f64>()
                        && mv > 0.0
                    {
                        last.has_positive_bound = true;
                    }
                    continue;
                }
                if k == "name" {
                    seen_param_name = Some(v.to_string());
                } else if k == "in" {
                    seen_param_in = Some(v.to_string());
                } else if k == "type"
                    && let Some(ref pn) = seen_param_name
                {
                    let fin = is_financial_param_name(pn);
                    add_unique_param(
                        &mut cur_params,
                        RouteParamSpec {
                            name: pn.clone(),
                            location: seen_param_in.clone().unwrap_or_else(|| "query".into()),
                            type_hint: infer_param_type(pn, Some(v)),
                            is_financial: fin,
                            has_positive_bound: false,
                        },
                    );
                }
                if let (Some(pn), Some(loc)) = (&seen_param_name, &seen_param_in) {
                    let fin = is_financial_param_name(pn);
                    add_unique_param(
                        &mut cur_params,
                        RouteParamSpec {
                            name: pn.clone(),
                            location: loc.clone(),
                            type_hint: infer_param_type(pn, None),
                            is_financial: fin,
                            has_positive_bound: false,
                        },
                    );
                }
            }
        }
    }

    flush_op(
        &mut out,
        rel_path,
        &cur_path,
        &mut cur_method,
        cur_line,
        &mut cur_params,
    );
    out
}

/// Merges per-file AST route schemas and OpenAPI route schemas deterministically.
pub fn merge_repo_route_schemas(summaries: &[FileAstSummary]) -> Vec<RouteSchema> {
    let mut by_key: HashMap<(String, String), RouteSchema> = HashMap::new();
    for f in summaries {
        for s in &f.route_schemas {
            let key = (s.method.clone(), s.path.clone());
            if let Some(existing) = by_key.get_mut(&key) {
                for p in &s.params {
                    add_unique_param(&mut existing.params, p.clone());
                }
                existing.from_openapi |= s.from_openapi;
                if existing.source_file.is_empty() && !s.source_file.is_empty() {
                    existing.source_file = s.source_file.clone();
                    existing.line = s.line;
                }
            } else {
                by_key.insert(key, s.clone());
            }
        }
    }
    let mut merged: Vec<RouteSchema> = by_key.into_values().collect();
    merged.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));
    merged
}

/// In `--deep` static mode, flags state-changing routes accepting financial/numeric parameters
/// (`amount`, `price`, `quantity`, etc.) without positive/finite bounds validation (`VF-FUZZ-SCHEMA`).
pub fn collect_deep_schema_findings(graph: &GraphAnalysisResult) -> Vec<LatticeFinding> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for rs in &graph.route_schemas {
        if !matches!(rs.method.as_str(), "POST" | "PUT" | "PATCH") {
            continue;
        }
        let missing_fin: Vec<&RouteParamSpec> = rs
            .params
            .iter()
            .filter(|p| p.is_financial && !p.has_positive_bound)
            .collect();
        if missing_fin.is_empty() {
            continue;
        }
        let field_names: Vec<&str> = missing_fin.iter().map(|p| p.name.as_str()).collect();
        let entry_route = format!("{} {}", rs.method, rs.path);
        if !seen.insert((entry_route.clone(), "VF-FUZZ-SCHEMA".to_string())) {
            continue;
        }
        out.push(LatticeFinding {
            id: format!("VF-FUZZ-{:03}", out.len() + 1),
            rule_id: "VF-FUZZ-SCHEMA".into(),
            severity: "HIGH".into(),
            title: format!(
                "Unvalidated financial/quantity field(s) ({}) on `{}` (negative/zero/NaN tampering risk)",
                field_names.join(", "),
                entry_route
            ),
            file: rs.source_file.clone(),
            line: rs.line.max(1),
            status: "SUSPECT_UNGUARDED".into(),
            confidence: Confidence::Confirmed,
            entry_route,
            sink_kind: SinkKind::SchemaTampering,
            missing_guard: GuardKind::InputValidation,
            witness_path: vec![TraceHop {
                file: rs.source_file.clone(),
                symbol: format!("{} {}", rs.method, rs.path),
                line: rs.line.max(1),
            }],
            remediation: "Enforce explicit finite & strictly positive schema constraints (e.g., `Number.isFinite(amount) && amount > 0`, Zod `.finite().positive()`, or Pydantic `gt=0`) before applying financial mutations.".into(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_codebase, parse_file_ast};
    use sh_core::{IndexedFile, ShellMindGuardConfig};
    use std::path::PathBuf;

    fn mem_file(rel_path: &str, language: Language, content: &str) -> IndexedFile {
        let bytes = content.as_bytes().to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        IndexedFile {
            rel_path: rel_path.to_string(),
            abs_path: PathBuf::from(rel_path),
            language,
            blake3_hash: hash,
            mtime_ns: 0,
            size_bytes: bytes.len() as u64,
            cached_bytes: Some(bytes),
        }
    }

    #[test]
    fn test_phase10_struct_field_taint_across_files_and_safe_field_suppression() {
        let cfg = ShellMindGuardConfig::default();
        let files = vec![
            mem_file(
                "src/routes.ts",
                Language::TypeScript,
                r#"
                import { dangerousHelper, safeHelper } from './helper';
                export function register(app: any) {
                    app.post('/api/v1/run', (req: any, res: any) => {
                        const a = { foo: req.body.cmd, safe: "status" };
                        dangerousHelper(a);
                        safeHelper(a);
                        res.json({ ok: true });
                    });
                }
                "#,
            ),
            mem_file(
                "src/helper.ts",
                Language::TypeScript,
                r#"
                import { execSync } from 'child_process';
                export function dangerousHelper(a: any) {
                    execSync(a.foo);
                }
                export function safeHelper(a: any) {
                    execSync(a.safe);
                }
                "#,
            ),
        ];
        let res = analyze_codebase(&files, &cfg).unwrap();
        let cmdi: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "VF-CMDI-001")
            .collect();
        assert_eq!(
            cmdi.len(),
            1,
            "Only `a.foo` should propagate across files (`a.safe` must be suppressed): {:?}",
            cmdi
        );
        assert!(
            cmdi[0]
                .witness_path
                .iter()
                .any(|h| h.symbol == "dangerousHelper"),
            "Witness should go through dangerousHelper: {:?}",
            cmdi[0].witness_path
        );
    }

    #[test]
    fn test_phase10_callback_closure_and_cross_file_callback_taint() {
        let cfg = ShellMindGuardConfig::default();
        let files = vec![
            mem_file(
                "src/routes.ts",
                Language::TypeScript,
                r#"
                import { dispatchTask } from './dispatcher';
                import { workerSink } from './worker';
                export function setup(app: any) {
                    app.post('/api/v1/job', (req: any, res: any) => {
                        dispatchTask(req.body.cmd, workerSink);
                        res.json({ ok: true });
                    });
                    app.post('/api/v1/inline', (req: any, res: any) => {
                        const items = [req.body.cmd];
                        items.forEach((cmd: string) => {
                            require('child_process').execSync(cmd);
                        });
                        res.json({ ok: true });
                    });
                }
                "#,
            ),
            mem_file(
                "src/dispatcher.ts",
                Language::TypeScript,
                r#"
                export function dispatchTask(payload: string, cb: (x: string) => void) {
                    cb(payload);
                }
                "#,
            ),
            mem_file(
                "src/worker.ts",
                Language::TypeScript,
                r#"
                import { execSync } from 'child_process';
                export function workerSink(cmd: string) {
                    execSync(cmd);
                }
                "#,
            ),
        ];
        let res = analyze_codebase(&files, &cfg).unwrap();
        let job_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-CMDI-001" && f.entry_route.contains("/api/v1/job"));
        assert!(
            job_hit.is_some(),
            "Expected cross-file callback taint from /api/v1/job -> dispatchTask -> workerSink: {:?}",
            res.findings
        );
        let inline_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-CMDI-001" && f.entry_route.contains("/api/v1/inline"));
        assert!(
            inline_hit.is_some(),
            "Expected inline closure taint on /api/v1/inline: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_phase10_cross_file_sanitizer_wrapper_reduces_false_positives() {
        let cfg = ShellMindGuardConfig::default();
        let files = vec![
            mem_file(
                "src/sanitize.ts",
                Language::TypeScript,
                r#"
                export function sanitizePayload(obj: any) {
                    const cleanCmd = shellEscape(obj.cmd);
                    return { cmd: cleanCmd, raw: obj.raw };
                }
                export function wrapPayload(obj: any) {
                    return { cmd: obj.cmd };
                }
                "#,
            ),
            mem_file(
                "src/routes.ts",
                Language::TypeScript,
                r#"
                import { execSync } from 'child_process';
                import { sanitizePayload, wrapPayload } from './sanitize';
                export function registerSafe(app: any) {
                    app.post('/api/v1/safe-wrap', (req: any, res: any) => {
                        const clean = sanitizePayload(req.body);
                        execSync(clean.cmd);
                        res.json({ ok: true });
                    });
                }
                export function registerUnsafe(app: any) {
                    app.post('/api/v1/unsafe-wrap', (req: any, res: any) => {
                        const wrapped = wrapPayload(req.body);
                        execSync(wrapped.cmd);
                        res.json({ ok: true });
                    });
                }
                "#,
            ),
        ];
        let res = analyze_codebase(&files, &cfg).unwrap();
        let safe_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-CMDI-001" && f.entry_route.contains("/api/v1/safe-wrap"));
        assert!(
            safe_hit.is_none(),
            "Sanitizer wrapper on `clean.cmd` should suppress false positive: {:?}",
            safe_hit
        );
        let unsafe_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "VF-CMDI-001" && f.entry_route.contains("/api/v1/unsafe-wrap"));
        assert!(
            unsafe_hit.is_some(),
            "Passthrough wrapper without sanitizer must still trigger VF-CMDI-001: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_phase10_openapi_and_ast_route_schema_fuzz_findings() {
        let cfg = ShellMindGuardConfig::default();
        let openapi_json = r##"{
            "openapi": "3.0.3",
            "paths": {
                "/api/v1/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/OrderReq" }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "OrderReq": {
                        "type": "object",
                        "properties": {
                            "quantity": { "type": "integer" },
                            "unit_price": { "type": "number", "minimum": 1 }
                        }
                    }
                }
            }
        }"##;
        let openapi_yaml = r#"
openapi: 3.0.0
paths:
  /api/v1/refund:
    post:
      parameters:
        - name: amount
          in: query
          type: number
"#;
        let files = vec![
            mem_file("openapi.json", Language::Config, openapi_json),
            mem_file("docs/openapi.yaml", Language::Config, openapi_yaml),
        ];
        let summary = parse_file_ast(&files[0], &cfg).unwrap();
        assert_eq!(summary.route_schemas.len(), 1);
        assert_eq!(summary.route_schemas[0].params.len(), 2);

        let graph = analyze_codebase(&files, &cfg).unwrap();
        let deep = collect_deep_schema_findings(&graph);
        assert_eq!(
            deep.len(),
            2,
            "Expected VF-FUZZ-SCHEMA for unvalidated quantity & amount (unit_price has minimum:1): {:?}",
            deep
        );
    }
}
