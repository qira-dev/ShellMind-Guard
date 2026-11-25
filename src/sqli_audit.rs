//! Defensive non-destructive SQL injection detection/prover (`smg sqli`).
//!
//! Strictly scoped to developer QA & authorized lab verification:
//! - Defaults to loopback / RFC1918 lab hosts; `--allow-remote` opt-in for the
//!   owner's own staging servers (same policy as `smg idor`).
//! - Only GET requests and urlencoded/JSON POST bodies are driven.
//! - Injection surfaces: URL query, urlencoded form body, recursive JSON body
//!   leaves (`$.user.id`, `$.items[0].code`), plus opt-in request headers
//!   (`--test-headers`) and cookies (`--test-cookies`).
//! - Techniques: error-based signature detection, boolean-based differential
//!   response analysis, statistically-verified time-based delay, and ORDER BY
//!   UNION column-count detection.
//! - NEVER does: data extraction/dumping, stacked (multi-statement) queries,
//!   OS-level command execution, or WAF-evasion tamper transformations.

use anyhow::{Context, Result, bail};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const UNION_MAX_COLUMNS: usize = 16;
const TIME_BASELINE_REPS: usize = 2;
const TIME_PAYLOAD_REPS: usize = 2;

// ---------------------------------------------------------------------------
// DB error signatures
// ---------------------------------------------------------------------------

fn mysql_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(you have an error in your sql syntax|warning: mysql|mysqli?_[a-z_]+\(|mariadb server version|check the manual that corresponds to your mysql)")
            .expect("static regex")
    })
}

fn postgres_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(pg::(syntax|invalidtextrepresentation|undefinedfunction|invalidparametervalue)|unterminated quoted (string|identifier) at or near|psycopg2\.|org\.postgresql\.util|ERROR:  syntax error at)")
            .expect("static regex")
    })
}

fn sqlite_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(sqlite3?\.(operational|syntax|programming)error|SQLITE_(ERROR|CONSTRAINT|SYNTAX)|unrecognized token:|sql logic error|Warning: sqlite_)")
            .expect("static regex")
    })
}

fn mssql_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(unclosed quotation mark after|incorrect syntax near|microsoft ole db provider|SQLException:|conversion failed when converting|Warning: mssql_)")
            .expect("static regex")
    })
}

fn oracle_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(ORA-\d{5}|oracle\.jdbc|quoted string not properly terminated|ORA-00936|ORA-01756)")
            .expect("static regex")
    })
}

fn db_hint_for(text: &str) -> Option<&'static str> {
    if mysql_error_re().is_match(text) {
        Some("MySQL/MariaDB")
    } else if postgres_error_re().is_match(text) {
        Some("PostgreSQL")
    } else if sqlite_error_re().is_match(text) {
        Some("SQLite")
    } else if mssql_error_re().is_match(text) {
        Some("MSSQL")
    } else if oracle_error_re().is_match(text) {
        Some("Oracle")
    } else {
        None
    }
}

/// First matched DB error signature (db family + matched snippet, capped).
pub fn scan_error_signatures(text: &str) -> Option<(String, String)> {
    let re_chain = [
        mysql_error_re(),
        postgres_error_re(),
        sqlite_error_re(),
        mssql_error_re(),
        oracle_error_re(),
    ];
    for re in re_chain {
        if let Some(m) = re.find(text) {
            let family = db_hint_for(m.as_str()).unwrap_or("SQL");
            return Some((family.into(), m.as_str().chars().take(80).collect()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config / report model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueEvidence {
    pub technique: String,
    pub payload: String,
    pub evidence: String,
    pub db: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliParamResult {
    pub param: String,
    pub location: String,
    pub error_based: Option<TechniqueEvidence>,
    pub boolean_based: Option<TechniqueEvidence>,
    pub time_based: Option<TechniqueEvidence>,
    pub union_columns: Option<usize>,
    pub verdict: String, // VULNERABLE | CLEAN | INCONCLUSIVE
    pub db_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliAuditReport {
    pub url: String,
    pub method: String,
    pub params_tested: usize,
    pub vulnerable_params: usize,
    pub results: Vec<SqliParamResult>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct SqliAuditConfig {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub params: Vec<String>,
    /// Request-header names to test as injection surfaces ("auto" expands to
    /// User-Agent / X-Forwarded-For / Referer). Opt-in only.
    pub test_headers: Vec<String>,
    /// Cookie names to test as injection surfaces. Opt-in only; the Cookie
    /// header comes from `headers`.
    pub test_cookies: Vec<String>,
    pub delay_secs: u64,
    pub skip_timing: bool,
    pub allow_remote: bool,
}

// ---------------------------------------------------------------------------
// Injection plumbing
// ---------------------------------------------------------------------------

fn percent_encode_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Rebuilds a `k=v&k2=v2` string with `param` set to `value` (percent-encoded).
fn set_param_in_pairs(pairs: &str, param: &str, value: &str) -> Option<String> {
    let mut found = false;
    let rebuilt: Vec<String> = pairs
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if k == param => {
                found = true;
                format!("{k}={}", percent_encode_value(value))
            }
            _ if kv == param => {
                found = true;
                format!("{kv}={}", percent_encode_value(value))
            }
            _ => kv.to_string(),
        })
        .collect();
    if !found {
        return None;
    }
    Some(rebuilt.join("&"))
}

/// Injection surfaces supported by the parameter engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamLocation {
    Query,
    Form,
    Json,
    Multipart,
    Header,
    Cookie,
}

impl ParamLocation {
    fn as_str(self) -> &'static str {
        match self {
            ParamLocation::Query => "query",
            ParamLocation::Form => "form",
            ParamLocation::Json => "json",
            ParamLocation::Multipart => "multipart",
            ParamLocation::Header => "header",
            ParamLocation::Cookie => "cookie",
        }
    }
}

#[derive(Debug, Clone)]
struct ParamRef {
    name: String,
    location: ParamLocation,
}

// ---------------------------------------------------------------------------
// JSON body surface (recursive leaf paths)
// ---------------------------------------------------------------------------

enum JsonPathTok {
    Key(String),
    Idx(usize),
}

/// Parses a JSON path like `$.user.id` or `$.items[0].code` into tokens.
fn parse_json_path(path: &str) -> Option<Vec<JsonPathTok>> {
    let rest = path.strip_prefix('$')?;
    let chars: Vec<char> = rest.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    i += 1;
                }
                let key: String = chars[start..i].iter().collect();
                if key.is_empty() {
                    return None;
                }
                toks.push(JsonPathTok::Key(key));
            }
            '[' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                if i >= chars.len() {
                    return None;
                }
                let idx: String = chars[start..i].iter().collect();
                i += 1;
                toks.push(JsonPathTok::Idx(idx.trim().parse().ok()?));
            }
            _ => return None,
        }
    }
    if toks.is_empty() { None } else { Some(toks) }
}

/// Collects the JSON paths of every scalar leaf (e.g. `$.user.id`, `$.items[0].code`).
fn walk_json_params(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = format!("{prefix}.{k}");
                if v.is_object() || v.is_array() {
                    walk_json_params(v, &path, out);
                } else {
                    out.push(path);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (idx, v) in items.iter().enumerate() {
                let path = format!("{prefix}[{idx}]");
                if v.is_object() || v.is_array() {
                    walk_json_params(v, &path, out);
                } else {
                    out.push(path);
                }
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// Reads the scalar at `path` as a string.
fn get_json_leaf_str(root: &serde_json::Value, path: &str) -> Option<String> {
    let toks = parse_json_path(path)?;
    let mut cur = root;
    for tok in &toks {
        cur = match tok {
            JsonPathTok::Key(k) => cur.get(k)?,
            JsonPathTok::Idx(idx) => cur.get(*idx)?,
        };
    }
    Some(match cur {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    })
}

/// Replaces the scalar at `path` with a string value; returns true when applied.
fn set_json_leaf(root: &mut serde_json::Value, path: &str, value: &str) -> bool {
    let Some(toks) = parse_json_path(path) else {
        return false;
    };
    let mut cur = root;
    for (i, tok) in toks.iter().enumerate() {
        let last = i + 1 == toks.len();
        match tok {
            JsonPathTok::Key(k) => {
                let map = match cur {
                    serde_json::Value::Object(map) => map,
                    _ => return false,
                };
                if last {
                    if !map.contains_key(k.as_str()) {
                        return false;
                    }
                    map.insert(k.clone(), serde_json::Value::String(value.to_string()));
                    return true;
                }
                cur = match map.get_mut(k.as_str()) {
                    Some(v) => v,
                    None => return false,
                };
            }
            JsonPathTok::Idx(idx) => {
                let items = match cur {
                    serde_json::Value::Array(items) => items,
                    _ => return false,
                };
                if *idx >= items.len() {
                    return false;
                }
                if last {
                    items[*idx] = serde_json::Value::String(value.to_string());
                    return true;
                }
                cur = &mut items[*idx];
            }
        }
    }
    false
}

/// Detects a multipart/form-data boundary from the Content-Type header or body prefix.
fn multipart_boundary(cfg: &SqliAuditConfig) -> Option<String> {
    if let Some((_, ct)) = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        let low = ct.to_ascii_lowercase();
        if let Some(pos) = low.find("boundary=") {
            let raw = ct[pos + "boundary=".len()..].trim();
            let b = raw.split(';').next().unwrap_or("").trim().trim_matches('"');
            if !b.is_empty() {
                return Some(b.to_string());
            }
        }
    }
    let body = cfg.body.as_deref()?;
    if body.starts_with("--") && body.contains("Content-Disposition:") {
        let first_line = body.lines().next()?.trim_end_matches('\r');
        let b = first_line.strip_prefix("--")?.trim();
        if !b.is_empty() {
            return Some(b.to_string());
        }
    }
    None
}

fn extract_multipart_name(head: &str) -> Option<String> {
    let low = head.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel_pos) = low[search_from..].find("name=") {
        let pos = search_from + rel_pos;
        let prev_is_ident = pos > 0
            && (low.as_bytes()[pos - 1].is_ascii_alphanumeric()
                || low.as_bytes()[pos - 1] == b'_'
                || low.as_bytes()[pos - 1] == b'-');
        if prev_is_ident {
            search_from = pos + 5;
            continue;
        }
        let rest = head[pos + 5..].trim_start();
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            let name = quoted[..end].trim();
            return (!name.is_empty()).then(|| name.to_string());
        } else {
            let end = rest
                .find([';', '\r', '\n', ' ', '\t'])
                .unwrap_or(rest.len());
            let name = rest[..end].trim();
            return (!name.is_empty()).then(|| name.to_string());
        }
    }
    None
}

/// Extracts non-file text field `(name, value)` pairs from a multipart/form-data body.
fn parse_multipart_fields(body: &str, boundary: &str) -> Vec<(String, String)> {
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    for part in body.split(&delim) {
        let trimmed = part.trim_start_matches("\r\n").trim_start_matches('\n');
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        let (head, val) = if let Some((h, v)) = trimmed.split_once("\r\n\r\n") {
            (h, v.strip_suffix("\r\n").unwrap_or(v))
        } else if let Some((h, v)) = trimmed.split_once("\n\n") {
            (h, v.strip_suffix('\n').unwrap_or(v))
        } else {
            continue;
        };
        if head.to_ascii_lowercase().contains("filename=") {
            continue;
        }
        if let Some(name) = extract_multipart_name(head) {
            out.push((name, val.to_string()));
        }
    }
    out
}

/// Replaces one text field value inside a multipart/form-data body while preserving boundary framing.
fn set_multipart_field(body: &str, boundary: &str, target: &str, value: &str) -> Option<String> {
    let delim = format!("--{boundary}");
    let sep = if body.contains("\r\n") { "\r\n" } else { "\n" };
    let head_sep = if sep == "\r\n" { "\r\n\r\n" } else { "\n\n" };
    let mut found = false;
    let mut rebuilt = String::with_capacity(body.len() + value.len());
    let parts: Vec<&str> = body.split(&delim).collect();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            rebuilt.push_str(&delim);
        }
        let trimmed = part.trim_start_matches("\r\n").trim_start_matches('\n');
        if trimmed.is_empty() || trimmed.starts_with("--") {
            rebuilt.push_str(part);
            continue;
        }
        if let Some((head, _old_val)) = trimmed.split_once(head_sep)
            && !head.to_ascii_lowercase().contains("filename=")
            && extract_multipart_name(head).as_deref() == Some(target)
        {
            found = true;
            rebuilt.push_str(sep);
            rebuilt.push_str(head);
            rebuilt.push_str(head_sep);
            rebuilt.push_str(value);
            rebuilt.push_str(sep);
            continue;
        }
        rebuilt.push_str(part);
    }
    if found { Some(rebuilt) } else { None }
}

/// Detects a JSON request body: explicit Content-Type or a leading `{`/`[`.
fn body_is_json(cfg: &SqliAuditConfig) -> bool {
    if let Some((_, ct)) = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        && ct.to_ascii_lowercase().contains("application/json")
    {
        return true;
    }
    cfg.body
        .as_deref()
        .map(|b| {
            let t = b.trim_start();
            t.starts_with('{') || t.starts_with('[')
        })
        .unwrap_or(false)
}

/// Parses the template `Cookie` header into name/value pairs.
fn cookie_pairs(cfg: &SqliAuditConfig) -> Vec<(String, String)> {
    cfg.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| {
            v.split(';')
                .filter_map(|kv| {
                    kv.trim()
                        .split_once('=')
                        .map(|(k, val)| (k.trim().to_string(), val.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn header_template_value(cfg: &SqliAuditConfig, name: &str) -> Option<String> {
    cfg.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

// ---------------------------------------------------------------------------
// Injectable request template
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Injectable {
    url: String,
    body: Option<String>,
    body_is_json: bool,
    /// Header overrides layered on top of the template headers (lowercase names).
    extra_headers: Vec<(String, String)>,
}

fn base_injectable(cfg: &SqliAuditConfig, url_str: &str) -> Injectable {
    Injectable {
        url: url_str.to_string(),
        body: cfg.body.clone(),
        body_is_json: body_is_json(cfg),
        extra_headers: Vec::new(),
    }
}

fn make_injectable(cfg: &SqliAuditConfig, pref: &ParamRef) -> Result<Injectable> {
    let url = reqwest::Url::parse(cfg.url.trim())
        .with_context(|| format!("Invalid URL '{}'", cfg.url))?;
    let inj = base_injectable(cfg, url.as_str());
    let present = match pref.location {
        ParamLocation::Query => {
            let query = url.query().unwrap_or_default().to_string();
            set_param_in_pairs(&query, &pref.name, "x").is_some()
        }
        ParamLocation::Form => cfg
            .body
            .as_deref()
            .map(|b| set_param_in_pairs(b, &pref.name, "x").is_some())
            .unwrap_or(false),
        ParamLocation::Json => {
            let body = cfg
                .body
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("JSON injection requires a --data body"))?;
            let mut parsed: serde_json::Value =
                serde_json::from_str(body).context("Invalid JSON body")?;
            set_json_leaf(&mut parsed, &pref.name, "x")
        }
        ParamLocation::Multipart => {
            let body = cfg
                .body
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Multipart injection requires a --data body"))?;
            let boundary = multipart_boundary(cfg)
                .ok_or_else(|| anyhow::anyhow!("Multipart body is missing boundary"))?;
            set_multipart_field(body, &boundary, &pref.name, "x").is_some()
        }
        // Header names are opt-in via --test-headers, so presence is assumed:
        // the header may be injected into a request that never carried it
        // (sqlmap-style surface testing).
        ParamLocation::Header => true,
        ParamLocation::Cookie => cookie_pairs(cfg)
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(&pref.name)),
    };
    if !present {
        bail!(
            "Parameter '{}' not found at location '{}' (URL query, form body, JSON body, or Cookie header)",
            pref.name,
            pref.location.as_str()
        );
    }
    Ok(inj)
}

/// Returns a copy of the request template with `pref` set to `value`.
fn inject_value(cfg: &SqliAuditConfig, pref: &ParamRef, url_str: &str, value: &str) -> Injectable {
    let mut inj = base_injectable(cfg, url_str);
    match pref.location {
        ParamLocation::Query => {
            if let Ok(mut u) = reqwest::Url::parse(url_str) {
                let query = u.query().unwrap_or_default().to_string();
                if let Some(nq) = set_param_in_pairs(&query, &pref.name, value) {
                    u.set_query(Some(&nq));
                    inj.url = u.to_string();
                }
            }
        }
        ParamLocation::Form => {
            if let Some(orig) = cfg.body.as_deref()
                && let Some(nb) = set_param_in_pairs(orig, &pref.name, value)
            {
                inj.body = Some(nb);
            }
        }
        ParamLocation::Json => {
            if let Some(orig) = cfg.body.as_deref()
                && let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(orig)
                && set_json_leaf(&mut parsed, &pref.name, value)
            {
                inj.body = Some(parsed.to_string());
            }
        }
        ParamLocation::Multipart => {
            if let Some(orig) = cfg.body.as_deref()
                && let Some(boundary) = multipart_boundary(cfg)
                && let Some(nb) = set_multipart_field(orig, &boundary, &pref.name, value)
            {
                inj.body = Some(nb);
                if !cfg
                    .headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("content-type"))
                {
                    inj.extra_headers.push((
                        "content-type".into(),
                        format!("multipart/form-data; boundary={boundary}"),
                    ));
                }
            }
        }
        ParamLocation::Header => {
            inj.extra_headers
                .push((pref.name.to_ascii_lowercase(), value.to_string()));
        }
        ParamLocation::Cookie => {
            let safe_cookie_val = value.replace(';', "%3B");
            let rebuilt: Vec<String> = cookie_pairs(cfg)
                .iter()
                .map(|(k, v)| {
                    if k.eq_ignore_ascii_case(&pref.name) {
                        format!("{k}={safe_cookie_val}")
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect();
            inj.extra_headers
                .push(("cookie".into(), rebuilt.join("; ")));
        }
    }
    inj
}

struct Response {
    status: u16,
    body: String,
}

fn send_injectable(
    client: &Client,
    inj: &Injectable,
    method: &str,
    headers: &HashMap<String, String>,
) -> Result<Response> {
    let m = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
    let mut req = client.request(m, &inj.url);
    for (k, v) in headers {
        let overridden = inj
            .extra_headers
            .iter()
            .any(|(ek, _)| ek.eq_ignore_ascii_case(k));
        if !overridden {
            req = req.header(k.as_str(), v.as_str());
        }
    }
    for (k, v) in &inj.extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(body) = &inj.body {
        let has_ct = headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
            || inj
                .extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !has_ct {
            let content_type = if inj.body_is_json {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };
            req = req.header("Content-Type", content_type);
        }
        req = req.body(body.clone());
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let mut raw = Vec::new();
    let _ = std::io::Read::read_to_end(&mut std::io::Read::take(resp, 2 * 1024 * 1024), &mut raw);
    let body = String::from_utf8_lossy(&raw).into_owned();
    Ok(Response { status, body })
}

// ---------------------------------------------------------------------------
// Structural response normalization (boolean-diff noise reduction)
// ---------------------------------------------------------------------------

/// JSON fields whose values churn between identical requests (timestamps,
/// request ids, nonces). Their values are replaced before boolean diffing so
/// a changing `timestamp`/`request_id` cannot fake a divergence.
const VARIABLE_JSON_FIELDS: &[&str] = &[
    "timestamp",
    "created_at",
    "updated_at",
    "modified_at",
    "created",
    "updated",
    "modified",
    "date",
    "expires",
    "expires_at",
    "epoch",
    "ts",
    "time",
    "uuid",
    "guid",
    "request_id",
    "requestid",
    "trace_id",
    "traceid",
    "span_id",
    "spanid",
    "nonce",
    "csrf",
    "iat",
    "exp",
    "jti",
];

fn normalize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if VARIABLE_JSON_FIELDS.contains(&k.to_ascii_lowercase().as_str()) {
                    *v = serde_json::Value::String("[SMG-VAR]".into());
                } else {
                    normalize_json_value(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                normalize_json_value(item);
            }
        }
        _ => {}
    }
}

/// Canonical comparison text for a response body: JSON documents get their
/// variable fields replaced with a fixed placeholder and are re-serialized
/// canonically (sorted keys); non-JSON bodies pass through unchanged.
fn normalize_response_body(body: &str) -> String {
    let mut parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    normalize_json_value(&mut parsed);
    serde_json::to_string(&parsed).unwrap_or_else(|_| body.to_string())
}

/// Token-level Jaccard similarity percentage (0..=100) so same-length
/// different-content responses (e.g. `{"user":"alice"}` vs `{"error":"none"}`)
/// are still distinguished cleanly.
fn token_similarity_pct(a: &str, b: &str) -> usize {
    use std::collections::HashSet;
    fn tok(s: &str) -> HashSet<&str> {
        s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|t| !t.is_empty())
            .take(512)
            .collect()
    }
    let sa = tok(a);
    let sb = tok(b);
    let union = sa.union(&sb).count();
    if union == 0 {
        return if a == b { 100 } else { 0 };
    }
    let inter = sa.intersection(&sb).count();
    (inter * 100) / union
}

fn body_close(a: &Response, b: &Response) -> bool {
    if a.status != b.status {
        return false;
    }
    let (na, nb) = (
        normalize_response_body(&a.body),
        normalize_response_body(&b.body),
    );
    if na == nb {
        return true;
    }
    let max = na.len().max(nb.len()).max(1);
    let delta = (na.len() as i64 - nb.len() as i64).unsigned_abs() as usize;
    delta * 100 / max <= 2 && token_similarity_pct(&na, &nb) >= 70
}

fn body_diverges(a: &Response, b: &Response) -> bool {
    if a.status != b.status {
        return true;
    }
    let (na, nb) = (
        normalize_response_body(&a.body),
        normalize_response_body(&b.body),
    );
    if na == nb {
        return false;
    }
    let max = na.len().max(nb.len()).max(1);
    let delta = (na.len() as i64 - nb.len() as i64).unsigned_abs() as usize;
    delta * 100 / max > 5 || token_similarity_pct(&na, &nb) < 60
}

fn median_f64(samples: &mut [f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    samples[samples.len() / 2]
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

const ERROR_PROBES: &[&str] = &["'", "\"", "')", "'))", "\\"];

fn push_param(prefs: &mut Vec<ParamRef>, name: &str, location: ParamLocation) {
    if !prefs
        .iter()
        .any(|p| p.name == name && p.location == location)
    {
        prefs.push(ParamRef {
            name: name.to_string(),
            location,
        });
    }
}

/// The original value at a param location, used to shape boolean payloads
/// (numeric vs quoted-string vs empty).
fn original_value_of(cfg: &SqliAuditConfig, url: &reqwest::Url, pref: &ParamRef) -> String {
    match pref.location {
        ParamLocation::Query => url
            .query_pairs()
            .find(|(k, _)| k == pref.name.as_str())
            .map(|(_, v)| v.to_string())
            .unwrap_or_default(),
        ParamLocation::Form => cfg
            .body
            .as_deref()
            .and_then(|b| {
                b.split('&').find_map(|kv| {
                    kv.split_once('=')
                        .filter(|(k, _)| *k == pref.name)
                        .map(|(_, v)| v.to_string())
                })
            })
            .unwrap_or_default(),
        ParamLocation::Json => cfg
            .body
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| get_json_leaf_str(&v, &pref.name))
            .unwrap_or_default(),
        ParamLocation::Multipart => cfg
            .body
            .as_deref()
            .zip(multipart_boundary(cfg))
            .and_then(|(b, bnd)| {
                parse_multipart_fields(b, &bnd)
                    .into_iter()
                    .find(|(k, _)| k == &pref.name)
                    .map(|(_, v)| v)
            })
            .unwrap_or_default(),
        ParamLocation::Header => header_template_value(cfg, &pref.name).unwrap_or_default(),
        ParamLocation::Cookie => cookie_pairs(cfg)
            .into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&pref.name))
            .map(|(_, v)| v)
            .unwrap_or_default(),
    }
}

pub fn run_sqli_audit(cfg: &SqliAuditConfig) -> Result<SqliAuditReport> {
    let url = crate::idor_audit::validate_live_target_url(&cfg.url, cfg.allow_remote)?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("SQLi verification requires an http:// or https:// target URL");
    }
    let method = cfg.method.to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST") {
        bail!(
            "Only GET and POST urlencoded methods are supported in safe SQLi verification mode (got '{method}')"
        );
    }
    if method == "POST" && cfg.body.is_none() {
        bail!("POST requires a --data body (urlencoded or JSON)");
    }

    crate::idor_audit::ensure_rustls_ring_provider();
    let safe_delay = cfg.delay_secs.clamp(1, 30);
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(
            safe_delay
                .saturating_mul(TIME_PAYLOAD_REPS as u64)
                .saturating_add(20),
        ))
        .redirect(Policy::none())
        .user_agent(concat!("ShellMind-Guard/", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Determine the parameter set across all testable surfaces.
    let mut prefs: Vec<ParamRef> = Vec::new();
    let json_value = if body_is_json(cfg) {
        cfg.body
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    } else {
        None
    };

    // Header/cookie surfaces are strictly opt-in.
    for h in &cfg.test_headers {
        let trimmed = h.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("auto") {
            for name in ["User-Agent", "X-Forwarded-For", "Referer"] {
                push_param(&mut prefs, name, ParamLocation::Header);
            }
        } else {
            push_param(&mut prefs, &trimmed, ParamLocation::Header);
        }
    }
    for c in &cfg.test_cookies {
        let trimmed = c.trim();
        if !trimmed.is_empty() {
            push_param(&mut prefs, trimmed, ParamLocation::Cookie);
        }
    }

    // URL query / form / JSON surfaces: explicit --param names or discovery.
    if !cfg.params.is_empty() {
        for name in &cfg.params {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let in_query = set_param_in_pairs(url.query().unwrap_or_default(), name, "x").is_some();
            let in_form = cfg
                .body
                .as_deref()
                .map(|b| set_param_in_pairs(b, name, "x").is_some())
                .unwrap_or(false);
            let json_path = if name.starts_with('$') {
                name.to_string()
            } else {
                format!("$.{name}")
            };
            let in_json = json_value
                .as_ref()
                .map(|v| get_json_leaf_str(v, &json_path).is_some())
                .unwrap_or(false);
            let in_multipart = cfg
                .body
                .as_deref()
                .zip(multipart_boundary(cfg))
                .map(|(b, bnd)| set_multipart_field(b, &bnd, name, "x").is_some())
                .unwrap_or(false);
            if in_query {
                push_param(&mut prefs, name, ParamLocation::Query);
            } else if in_multipart {
                push_param(&mut prefs, name, ParamLocation::Multipart);
            } else if in_form {
                push_param(&mut prefs, name, ParamLocation::Form);
            } else if in_json {
                push_param(&mut prefs, &json_path, ParamLocation::Json);
            } else {
                bail!(
                    "Parameter '{name}' not found in URL query, form body, multipart body, or JSON body"
                );
            }
        }
    } else {
        for (k, _) in url.query_pairs() {
            push_param(&mut prefs, &k, ParamLocation::Query);
        }
        if let Some(body) = cfg.body.as_deref() {
            if let Some(boundary) = multipart_boundary(cfg) {
                for (name, _) in parse_multipart_fields(body, &boundary) {
                    push_param(&mut prefs, &name, ParamLocation::Multipart);
                }
            } else if body_is_json(cfg) {
                if let Some(v) = &json_value {
                    let mut paths = Vec::new();
                    // GraphQL envelope: scope variable discovery to $.variables so
                    // static query text and operationName are not mutated as user inputs.
                    if v.get("query").is_some_and(|q| q.is_string())
                        && let Some(vars) = v.get("variables")
                        && vars.is_object()
                    {
                        walk_json_params(vars, "\x24.variables", &mut paths);
                    } else {
                        walk_json_params(v, "\x24", &mut paths);
                    }
                    for p in paths {
                        push_param(&mut prefs, &p, ParamLocation::Json);
                    }
                }
            } else {
                for kv in body.split('&').filter(|kv| !kv.is_empty()) {
                    if let Some((k, _)) = kv.split_once('=') {
                        push_param(&mut prefs, k, ParamLocation::Form);
                    }
                }
            }
        }
    }
    if prefs.is_empty() {
        bail!("No testable parameters found; pass --param, --test-headers, or --test-cookies");
    }

    let started = Instant::now();
    let mut results = Vec::new();
    let mut vulnerable = 0usize;

    for pref in &prefs {
        let inj = make_injectable(cfg, pref)?;
        let mut result = SqliParamResult {
            param: pref.name.clone(),
            location: pref.location.as_str().to_string(),
            error_based: None,
            boolean_based: None,
            time_based: None,
            union_columns: None,
            verdict: "INCONCLUSIVE".into(),
            db_hints: Vec::new(),
        };

        let baseline = send_injectable(&client, &inj, &method, &cfg.headers);
        let mut probes_succeeded = 0usize;

        if let Ok(base) = &baseline {
            let orig_value = original_value_of(cfg, &url, pref);
            let send_probe = |payload: &str| -> Result<Response> {
                let probe = inject_value(cfg, pref, cfg.url.as_str(), payload);
                send_injectable(&client, &probe, &method, &cfg.headers)
            };

            // 1. Error-based
            for payload in ERROR_PROBES {
                if let Ok(resp) = send_probe(payload) {
                    probes_succeeded += 1;
                    let haystack = format!("{}\n{}", resp.body, resp.status);
                    if let Some((db, sig)) = scan_error_signatures(&haystack) {
                        result.error_based = Some(TechniqueEvidence {
                            technique: "error-based".into(),
                            payload: payload.to_string(),
                            evidence: sig,
                            db: Some(db.clone()),
                        });
                        if !result.db_hints.contains(&db) {
                            result.db_hints.push(db);
                        }
                        break;
                    }
                }
            }

            // 2. Boolean-based differential (2 consistent reps, zero guessing)
            let numeric = !orig_value.is_empty() && orig_value.chars().all(|c| c.is_ascii_digit());
            let (true_payload, false_payload) = if numeric {
                (
                    format!("{orig_value} AND 1=1"),
                    format!("{orig_value} AND 1=2"),
                )
            } else if !orig_value.is_empty() {
                (
                    format!("{orig_value}' AND '1'='1"),
                    format!("{orig_value}' AND '1'='2"),
                )
            } else {
                ("1 AND 1=1".to_string(), "1 AND 1=2".to_string())
            };
            let t1 = send_probe(&true_payload);
            let f1 = send_probe(&false_payload);
            if let (Ok(t1), Ok(f1)) = (&t1, &f1) {
                probes_succeeded += 2;
                let truthy_matches = body_close(t1, base);
                let falsy_diverges = body_diverges(f1, base) && !body_close(f1, t1);
                if truthy_matches
                    && falsy_diverges
                    && let (Ok(t2), Ok(f2)) =
                        (send_probe(&true_payload), send_probe(&false_payload))
                    && body_close(&t2, base)
                    && body_diverges(&f2, base)
                    && !body_close(&f2, &t2)
                {
                    result.boolean_based = Some(TechniqueEvidence {
                        technique: "boolean-blind".into(),
                        payload: false_payload.clone(),
                        evidence: format!(
                            "truthy≈baseline ({}B, HTTP {}) vs falsy divergent ({}B, HTTP {})",
                            t1.body.len(),
                            t1.status,
                            f1.body.len(),
                            f1.status
                        ),
                        db: None,
                    });
                }
            }

            // 3. Time-based (only when quick checks were inconclusive; bounded, single-statement only)
            if result.error_based.is_none() && result.boolean_based.is_none() && !cfg.skip_timing {
                let delay = safe_delay;
                let baseline_median = {
                    let mut samples = Vec::new();
                    for _ in 0..TIME_BASELINE_REPS {
                        let t0 = Instant::now();
                        let _ = send_injectable(&client, &inj, &method, &cfg.headers);
                        samples.push(t0.elapsed().as_secs_f64());
                    }
                    median_f64(&mut samples)
                };
                // Strictly single-statement timing expressions (never stacked `;` queries).
                let families: Vec<(&str, String)> = if numeric {
                    vec![
                        ("MySQL/MariaDB", format!("{orig_value} AND sleep({delay})")),
                        ("PostgreSQL", format!("{orig_value} AND pg_sleep({delay})")),
                    ]
                } else {
                    vec![
                        (
                            "MySQL/MariaDB",
                            format!("{orig_value}' AND sleep({delay})-- "),
                        ),
                        ("PostgreSQL", format!("{orig_value}'||pg_sleep({delay})||'")),
                    ]
                };
                for (db, payload) in &families {
                    let mut samples = Vec::new();
                    for _ in 0..TIME_PAYLOAD_REPS {
                        let t0 = Instant::now();
                        if send_probe(payload).is_ok() {
                            probes_succeeded += 1;
                            samples.push(t0.elapsed().as_secs_f64());
                        }
                    }
                    if samples.len() < TIME_PAYLOAD_REPS {
                        continue;
                    }
                    let payload_median = median_f64(&mut samples);
                    if payload_median - baseline_median >= (delay as f64) * 0.7 {
                        result.time_based = Some(TechniqueEvidence {
                            technique: "time-based blind".into(),
                            payload: payload.clone(),
                            evidence: format!(
                                "baseline {baseline_median:.2}s vs payload {payload_median:.2}s (delay {delay}s)"
                            ),
                            db: Some(db.to_string()),
                        });
                        if !result.db_hints.iter().any(|h| h == db) {
                            result.db_hints.push(db.to_string());
                        }
                        break;
                    }
                }
            }

            // 4. UNION column-count detection (ORDER BY enumeration, detection-only)
            let mut columns: Option<usize> = None;
            let mut k1_close_to_base = false;
            for k in 1..=UNION_MAX_COLUMNS {
                let payload = if numeric {
                    format!("{orig_value} ORDER BY {k}")
                } else {
                    format!("{orig_value}' ORDER BY {k}-- ")
                };
                match send_probe(&payload) {
                    Ok(resp) => {
                        probes_succeeded += 1;
                        if matches!(resp.status, 429 | 413 | 414 | 503) {
                            break;
                        }
                        if k == 1 {
                            k1_close_to_base =
                                resp.status == base.status && body_close(&resp, base);
                            if !k1_close_to_base {
                                break;
                            }
                        }
                        let broke = scan_error_signatures(&resp.body).is_some()
                            || resp.status != base.status
                            || body_diverges(&resp, base);
                        if broke {
                            if k > 1 && k1_close_to_base {
                                // Confirm break is deterministic rather than transient rate-limit
                                if let Ok(confirm_resp) = send_probe(&payload)
                                    && !matches!(confirm_resp.status, 429 | 503)
                                    && (scan_error_signatures(&confirm_resp.body).is_some()
                                        || confirm_resp.status != base.status
                                        || body_diverges(&confirm_resp, base))
                                {
                                    columns = Some(k - 1);
                                }
                            }
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            result.union_columns = columns;
        }

        result.verdict = if result.error_based.is_some()
            || result.boolean_based.is_some()
            || result.time_based.is_some()
            || result.union_columns.is_some()
        {
            vulnerable += 1;
            "VULNERABLE".into()
        } else if baseline.is_ok() && probes_succeeded > 0 {
            "CLEAN".into()
        } else {
            "INCONCLUSIVE".into()
        };
        results.push(result);
    }

    let url_out = cfg.url.clone();
    let method_out = method.clone();
    Ok(SqliAuditReport {
        url: url_out,
        method: method_out,
        params_tested: results.len(),
        vulnerable_params: vulnerable,
        results,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// Full percent-decoder for the mock (matches the engine's encoder).
    fn test_pct_decode(s: &str) -> String {
        let mut bytes = Vec::with_capacity(s.len());
        let raw = s.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%'
                && i + 2 < raw.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                bytes.push(v);
                i += 3;
                continue;
            }
            bytes.push(raw[i]);
            i += 1;
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Reads a full mock request (headers + Content-Length body).
    fn read_request(stream: &mut TcpStream) -> String {
        let mut data: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..pos]);
                let clen = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let have = data.len() - (pos + 4);
                if have >= clen {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&data).into_owned()
    }

    fn header_value(req: &str, name: &str) -> String {
        req.lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.trim().eq_ignore_ascii_case(name) {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Shared vulnerable-endpoint behaviour for the JSON/header/cookie mock
    /// surfaces. Variable JSON fields (timestamp/request_id) change length per
    /// payload, so raw body comparison would false-diverge — the boolean
    /// differential only passes thanks to the structural normalizer.
    fn vuln_behavior(decoded: &str, delay: u64) -> (u16, String, u64) {
        if decoded.contains('\'') || decoded.contains('"') {
            return (
                500,
                "You have an error in your SQL syntax; check the manual".into(),
                0,
            );
        }
        if let Some(col) = decoded
            .split("ORDER BY")
            .nth(1)
            .and_then(|s| s.trim().trim_end_matches("--").trim().parse::<usize>().ok())
            && col > 3
        {
            return (500, "ERROR:  syntax error at or near".into(), 0);
        }
        if decoded.contains("sleep") {
            return (200, "delayed".into(), delay);
        }
        let falsy = decoded.ends_with("AND '1'='2") || decoded.ends_with("AND 1=2");
        let base_item = decoded.split(" ORDER BY").next().unwrap_or("").trim();
        let ts_len = 80 + (decoded.len() * 7) % 50;
        if falsy {
            let body = format!(
                "{{\"denied\":true,\"blob\":\"{}\",\"timestamp\":\"{}\"}}",
                "x".repeat(30),
                "t".repeat(ts_len)
            );
            (200, body, 0)
        } else {
            let body = format!(
                "{{\"result\":\"item {base_item}\",\"blob\":\"{}\",\"timestamp\":\"{}\",\"request_id\":\"{}\"}}",
                "x".repeat(200),
                "t".repeat(ts_len),
                "r".repeat(100)
            );
            (200, body, 0)
        }
    }

    /// Mock server with per-endpoint SQLi behaviour:
    /// - `/error?id=` → MySQL signature when value contains a quote
    /// - `/bool?q=`   → long page for truthy payloads, short for falsy
    /// - `/time?id=`  → sleeps when the payload contains "sleep"
    /// - `/union?id=` → SQL error when ORDER BY column > 3
    /// - `/json`      → JSON body `{"user":{"id":V}}` drives `vuln_behavior`
    /// - `/hdr`       → `X-Forwarded-For` header drives `vuln_behavior`
    /// - `/cookie`    → `Cookie: session=V` drives `vuln_behavior`
    fn mock_server(delay: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..256 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let req = read_request(&mut stream);
                let path = req.split_whitespace().nth(1).unwrap_or("");
                let mut status = 200u16;
                let mut body = String::new();
                let mut sleep_secs = 0u64;
                if path.starts_with("/json") {
                    let body_text = req.split("\r\n\r\n").nth(1).unwrap_or_default();
                    let id_val = serde_json::from_str::<serde_json::Value>(body_text)
                        .ok()
                        .and_then(|v| {
                            v.get("user").and_then(|u| u.get("id")).map(|x| match x {
                                serde_json::Value::String(s) => s.clone(),
                                other => other.to_string(),
                            })
                        })
                        .unwrap_or_default();
                    (status, body, sleep_secs) = vuln_behavior(&id_val, delay);
                } else if path.starts_with("/hdr") {
                    let v = header_value(&req, "x-forwarded-for");
                    (status, body, sleep_secs) = vuln_behavior(&v, delay);
                } else if path.starts_with("/cookie") {
                    let cookie = header_value(&req, "cookie");
                    let v = cookie
                        .split(';')
                        .find_map(|kv| kv.trim().strip_prefix("session=").map(|s| s.to_string()))
                        .unwrap_or_default();
                    (status, body, sleep_secs) = vuln_behavior(&v, delay);
                } else if let Some((_, q)) = path.split_once('?') {
                    let raw_value = q
                        .split('&')
                        .find_map(|kv| {
                            kv.strip_prefix("id=")
                                .or_else(|| kv.strip_prefix("q="))
                                .map(|v| v.to_string())
                        })
                        .unwrap_or_default();
                    let decoded = test_pct_decode(&raw_value);
                    if path.starts_with("/error?") {
                        if decoded.contains('\'') || decoded.contains('"') {
                            status = 500;
                            body = "You have an error in your SQL syntax; check the manual".into();
                        } else {
                            body = format!("item {decoded}");
                        }
                    } else if path.starts_with("/bool?") {
                        if decoded.ends_with("AND '1'='1") || decoded.ends_with("AND 1=1") {
                            body = "x".repeat(500);
                        } else if decoded.ends_with("AND '1'='2") || decoded.ends_with("AND 1=2") {
                            body = "x".repeat(50);
                        } else {
                            body = "x".repeat(500);
                        }
                    } else if path.starts_with("/time?") {
                        if decoded.contains("sleep") {
                            body = "delayed".into();
                            sleep_secs = delay;
                        } else {
                            body = "quick".into();
                        }
                    } else if path.starts_with("/union?") {
                        // The baseline item is everything before the ORDER BY
                        // marker, so valid ORDER BY probes return the exact
                        // baseline body (no divergence) and only out-of-range
                        // columns break with a SQL error.
                        let base_item = decoded
                            .split(" ORDER BY")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let order_col = decoded.split("ORDER BY").nth(1).and_then(|s| {
                            s.trim().trim_end_matches("--").trim().parse::<usize>().ok()
                        });
                        match order_col {
                            Some(col) if col > 3 => {
                                status = 500;
                                body = "ERROR:  syntax error at or near".into();
                            }
                            _ => body = format!("item {base_item}"),
                        }
                    } else if path.starts_with("/clean?") {
                        // Hardened endpoint: every probe echoes the baseline
                        // item, so no technique can fire.
                        let base_item = decoded
                            .split(" ORDER BY")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        body = format!("item {base_item}");
                    }
                }
                if body.is_empty() {
                    status = 404;
                    body = "not found".into();
                }
                if sleep_secs > 0 {
                    thread::sleep(Duration::from_secs(sleep_secs));
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn cfg_for(url: &str, tweak: impl FnOnce(&mut SqliAuditConfig)) -> SqliAuditConfig {
        let mut cfg = SqliAuditConfig {
            url: url.to_string(),
            method: "GET".into(),
            headers: HashMap::new(),
            body: None,
            params: vec![],
            test_headers: vec![],
            test_cookies: vec![],
            delay_secs: 1,
            skip_timing: false,
            allow_remote: false,
        };
        tweak(&mut cfg);
        cfg
    }

    #[test]
    fn detects_error_based_mysql_signature() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/error?id=42"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert_eq!(
            r.error_based.as_ref().unwrap().db.as_deref(),
            Some("MySQL/MariaDB")
        );
        assert_eq!(r.verdict, "VULNERABLE");
    }

    #[test]
    fn detects_boolean_differential() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/bool?q=abc"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        assert!(report.results[0].boolean_based.is_some());
    }

    #[test]
    fn detects_time_based_delay() {
        let base = mock_server(1);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/time?id=7"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert!(r.time_based.is_some());
        assert!(r.db_hints.iter().any(|h| h.contains("MySQL")));
    }

    #[test]
    fn detects_union_column_count() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/union?id=9"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        assert_eq!(report.results[0].union_columns, Some(3));
    }

    #[test]
    fn clean_param_yields_clean_verdict() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/clean?id=1"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 0);
        assert_eq!(report.results[0].verdict, "CLEAN");
    }

    #[test]
    fn refuses_remote_host_without_explicit_flag() {
        let err = run_sqli_audit(&cfg_for("https://example.com/item?id=1", |_| {}));
        assert!(err.is_err());
    }

    #[test]
    fn refuses_imds_even_with_allow_remote_and_detects_same_length_divergence() {
        let err = run_sqli_audit(&cfg_for("http://169.254.169.254/latest?id=1", |c| {
            c.allow_remote = true;
        }));
        assert!(err.is_err());

        let a = Response {
            status: 200,
            body: r#"{"status":"ok","user":"alice"}"#.into(),
        };
        let b = Response {
            status: 200,
            body: r#"{"error":"denied","role":"none"}"#.into(),
        };
        assert!(!body_close(&a, &b));
        assert!(body_diverges(&a, &b));
    }

    #[test]
    fn refuses_put_method() {
        let base = mock_server(0);
        let err = run_sqli_audit(&cfg_for(&format!("{base}/error?id=1"), |c| {
            c.method = "PUT".into();
        }));
        assert!(err.is_err());
    }

    #[test]
    fn json_walk_and_set_handle_nested_paths() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"user":{"id":1},"items":[{"code":"A"},{"code":"B"}]}"#)
                .unwrap();
        let mut paths = Vec::new();
        walk_json_params(&v, "$", &mut paths);
        assert!(paths.contains(&"$.user.id".to_string()));
        assert!(paths.contains(&"$.items[0].code".to_string()));
        assert!(paths.contains(&"$.items[1].code".to_string()));

        let mut v2 = v.clone();
        assert!(set_json_leaf(&mut v2, "$.items[1].code", "x'"));
        assert_eq!(v2["items"][1]["code"], "x'");
        assert!(!set_json_leaf(&mut v2, "$.missing", "x"));
        assert!(!set_json_leaf(&mut v2, "$.items[9].code", "x"));
    }

    #[test]
    fn json_variable_fields_normalize_to_identical_text() {
        let a = r#"{"result":"item 7","timestamp":"tttttttttt","request_id":"r-1"}"#;
        let b = r#"{"request_id":"zzzzzzzzzzzzz","result":"item 7","timestamp":"u"}"#;
        assert_eq!(normalize_response_body(a), normalize_response_body(b));
        assert_eq!(normalize_response_body("plain text"), "plain text");
    }

    #[test]
    fn detects_json_body_boolean_with_normalized_timestamps() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/json"), |c| {
            c.method = "POST".into();
            c.headers
                .insert("Content-Type".into(), "application/json".into());
            c.body = Some(r#"{"user":{"id":7}}"#.into());
        }))
        .unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert_eq!(r.param, "$.user.id");
        assert_eq!(r.location, "json");
        assert!(r.boolean_based.is_some());
    }

    #[test]
    fn detects_header_surface_injection() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/hdr"), |c| {
            c.headers
                .insert("X-Forwarded-For".into(), "10.0.0.9".into());
            c.test_headers = vec!["X-Forwarded-For".into()];
        }))
        .unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert_eq!(r.param, "X-Forwarded-For");
        assert_eq!(r.location, "header");
        assert!(r.error_based.is_some());
    }

    #[test]
    fn detects_cookie_surface_injection() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/cookie"), |c| {
            c.headers
                .insert("Cookie".into(), "session=abc; theme=dark".into());
            c.test_cookies = vec!["session".into()];
        }))
        .unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert_eq!(r.param, "session");
        assert_eq!(r.location, "cookie");
        assert!(r.error_based.is_some());
    }

    #[test]
    fn multipart_form_data_field_parsing_and_replacement() {
        let body = "--smgBnd\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--smgBnd\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--smgBnd--\r\n";
        let fields = parse_multipart_fields(body, "smgBnd");
        assert_eq!(fields, vec![("user".to_string(), "alice".to_string())]);
        let updated = set_multipart_field(body, "smgBnd", "user", "bob'").unwrap();
        assert!(updated.contains("bob'"));
        assert!(updated.contains("PNGDATA"));
        assert!(set_multipart_field(body, "smgBnd", "avatar", "x").is_none());
    }

    #[test]
    fn graphql_envelope_scopes_variables_only() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"operationName":"GetUser","query":"query GetUser($id:ID!){user(id:$id){name}}","variables":{"id":"42","filter":{"role":"admin"}}}"#,
        )
        .unwrap();
        let mut paths = Vec::new();
        walk_json_params(v.get("variables").unwrap(), "\x24.variables", &mut paths);
        paths.sort();
        assert_eq!(
            paths,
            vec!["\x24.variables.filter.role", "\x24.variables.id"]
        );
    }
}
