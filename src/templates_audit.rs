//! Defensive Nuclei-compatible YAML template runner (`smg templates`).
//!
//! Loads standard `nuclei-templates/` directories and executes **detection-only**
//! HTTP, DNS and raw-network (TCP/TLS) templates against a target with strict
//! lab-scope guardrails:
//! - Defaults to loopback / RFC1918 lab hosts unless `--allow-remote` is passed
//!   (same policy as `smg idor`).
//! - Detection templates only: fuzz/payload (`race`, `pipelines`), headless,
//!   javascript, code, file, ssl, websocket, whois and Interactsh (OOB callback)
//!   engines are explicitly skipped with a reason instead of guessing.
//! - Deterministic substitution: `{{randstr}}` is derived from the template id
//!   via BLAKE3 so every re-run is byte-for-byte reproducible (zero hallucination).

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use md5::{Digest, Md5};
use regex::{Captures, Regex};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const MAX_CAPTURE_BODY: usize = 2 * 1024 * 1024;
const MAX_TEMPLATE_FILES: usize = 5_000;

fn helper_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\{\{\s*(md5|sha1|sha256|base64|base64_encode|base64_decode|url_encode|url_decode|upper|lower|html_escape)\s*\(\s*"([^"]*)"\s*\)\s*\}\}"#,
        )
        .expect("static helper regex")
    })
}

fn unresolved_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}").expect("static var regex")
    })
}

// ---------------------------------------------------------------------------
// Serde model (Nuclei v3 YAML schema subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortVal {
    Num(usize),
    Str(String),
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct TemplateInfo {
    pub name: Option<String>,
    pub author: Option<OneOrMany<String>>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub tags: Option<OneOrMany<String>>,
    pub classification: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: Option<OneOrMany<usize>>,
    pub words: Option<OneOrMany<String>>,
    pub regex: Option<OneOrMany<String>>,
    pub dsl: Option<OneOrMany<String>>,
    pub binary: Option<OneOrMany<String>>,
    pub size: Option<OneOrMany<usize>>,
    pub part: Option<String>,
    pub condition: Option<String>,
    pub negative: bool,
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: Option<String>,
    pub regex: Option<OneOrMany<String>>,
    pub words: Option<OneOrMany<String>>,
    pub kval: Option<OneOrMany<KvalExtractor>>,
    pub internal: bool,
    pub part: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct KvalExtractor {
    pub name: Option<String>,
    pub part: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct HttpBlock {
    pub method: Option<String>,
    pub path: Option<OneOrMany<String>>,
    pub raw: Option<OneOrMany<String>>,
    pub headers: Option<HashMap<String, serde_yaml_ng::Value>>,
    pub body: Option<String>,
    pub redirects: Option<bool>,
    pub max_redirects: Option<usize>,
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Option<String>,
    pub extractors: Vec<Extractor>,
    pub stop_at_first_match: bool,
    pub payloads: Option<serde_yaml_ng::Value>,
    pub race: bool,
    pub threads: Option<usize>,
    pub flow: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct DnsBlock {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub qtype: Option<String>,
    pub class: Option<String>,
    pub retries: usize,
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Option<String>,
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkInput {
    pub data: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkBlock {
    pub host: Option<OneOrMany<String>>,
    pub ports: Option<OneOrMany<PortVal>>,
    pub inputs: Option<Vec<NetworkInput>>,
    pub read_size: Option<usize>,
    pub tls: Option<serde_yaml_ng::Value>,
    pub sni: Option<String>,
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Option<String>,
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NucleiTemplate {
    pub id: Option<String>,
    pub info: TemplateInfo,
    pub http: Vec<HttpBlock>,
    pub dns: Vec<DnsBlock>,
    pub network: Vec<NetworkBlock>,
    pub variables: HashMap<String, String>,
    pub constants: HashMap<String, String>,
    // Engines that are explicitly outside the defensive detection scope.
    pub headless: Option<serde_yaml_ng::Value>,
    pub javascript: Option<serde_yaml_ng::Value>,
    pub code: Option<serde_yaml_ng::Value>,
    pub file: Option<serde_yaml_ng::Value>,
    pub ssl: Option<serde_yaml_ng::Value>,
    pub websocket: Option<serde_yaml_ng::Value>,
    pub whois: Option<serde_yaml_ng::Value>,
    pub flow: Option<serde_yaml_ng::Value>,
    pub lua: Option<serde_yaml_ng::Value>,
    pub interactive: Option<bool>,
}

fn yaml_val_to_string(v: &serde_yaml_ng::Value) -> String {
    match v {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Number(n) => n.to_string(),
        serde_yaml_ng::Value::Bool(b) => b.to_string(),
        other => serde_yaml_ng::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn block_headers(block: &HttpBlock) -> Vec<(String, String)> {
    block
        .headers
        .as_ref()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), yaml_val_to_string(v)))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Variable substitution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Vars {
    pub base_url: String,
    pub root_url: String,
    pub hostname: String,
    pub host: String,
    pub port: String,
    pub scheme: String,
    pub path: String,
    pub file: String,
    pub fqdn: String,
    pub randstr: String,
}

impl Vars {
    /// `{{randstr}}` is deterministic per template id (BLAKE3-derived) so that
    /// repeated runs of the same scan are byte-for-byte reproducible.
    pub fn for_template(base: &Vars, template_id: &str) -> Vars {
        let mut v = base.clone();
        let digest = blake3::hash(template_id.as_bytes()).to_hex();
        v.randstr = digest.as_bytes()[..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        v
    }
}

fn last_path_segment(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string()
}

pub fn parse_target(target: &str) -> Result<Vars> {
    let normalized = if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    let url = reqwest::Url::parse(normalized.trim())
        .with_context(|| format!("Invalid target '{target}'"))?;
    let scheme = url.scheme().to_string();
    if scheme != "http" && scheme != "https" {
        bail!("Only http/https targets are supported (got '{scheme}')");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Target is missing a host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let base_url = match url.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    let path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    Ok(Vars {
        root_url: base_url.clone(),
        hostname: base_url
            .trim_start_matches(&format!("{scheme}://"))
            .to_string(),
        fqdn: host.clone(),
        base_url,
        host,
        port,
        scheme,
        path,
        file: last_path_segment(url.path()),
        randstr: String::new(),
    })
}

pub fn substitute(input: &str, vars: &Vars, extra: &HashMap<String, String>) -> String {
    let mut s = input.to_string();
    for (k, v) in extra {
        s = s.replace(&format!("{{{{{k}}}}}"), v);
    }
    s = s
        .replace("{{BaseURL}}", &vars.base_url)
        .replace("{{RootURL}}", &vars.root_url)
        .replace("{{Hostname}}", &vars.hostname)
        .replace("{{Host}}", &vars.host)
        .replace("{{Port}}", &vars.port)
        .replace("{{Scheme}}", &vars.scheme)
        .replace("{{Path}}", &vars.path)
        .replace("{{File}}", &vars.file)
        .replace("{{FQDN}}", &vars.fqdn)
        .replace("{{randstr}}", &vars.randstr)
        .replace("{{randomstr}}", &vars.randstr);
    replace_helper_calls(&s)
}

fn url_encode_component(s: &str) -> String {
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

fn url_decode_component(s: &str) -> String {
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
        if raw[i] == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(raw[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn replace_helper_calls(input: &str) -> String {
    let re = helper_re();
    re.replace_all(input, |caps: &Captures| {
        let fname = &caps[1];
        let arg = &caps[2];
        match fname {
            "md5" => {
                let mut h = Md5::new();
                h.update(arg.as_bytes());
                hex_encode(&h.finalize())
            }
            "sha1" => {
                let mut h = Sha1::new();
                h.update(arg.as_bytes());
                hex_encode(&h.finalize())
            }
            "sha256" => {
                let mut h = Sha256::new();
                h.update(arg.as_bytes());
                hex_encode(&h.finalize())
            }
            "base64" | "base64_encode" => B64.encode(arg.as_bytes()),
            "base64_decode" => B64
                .decode(arg)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
            "url_encode" => url_encode_component(arg),
            "url_decode" => url_decode_component(arg),
            "upper" => arg.to_uppercase(),
            "lower" => arg.to_lowercase(),
            "html_escape" => arg
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;"),
            _ => caps[0].to_string(),
        }
    })
    .into_owned()
}

fn has_unresolved_vars(s: &str) -> bool {
    unresolved_var_re().is_match(s)
}

// ---------------------------------------------------------------------------
// DSL evaluator (subset, zero-guessing: unknown atoms => fail closed)
// ---------------------------------------------------------------------------

struct DslCtx<'a> {
    status: u16,
    body: &'a str,
    headers: &'a str,
    vars: &'a Vars,
}

fn split_top_level(s: &str, sep: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch == '"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_quote = !in_quote;
            cur.push(ch);
            i += 1;
            continue;
        }
        if !in_quote && s[i..].starts_with(sep) {
            parts.push(cur.trim().to_string());
            cur.clear();
            i += sep.len();
            continue;
        }
        cur.push(ch);
        i += 1;
    }
    parts.push(cur.trim().to_string());
    parts
}

/// Extract a full balanced function call starting at `pos` in `s`.
fn take_fn_call(s: &str, pos: usize) -> Option<(String, Vec<String>, usize)> {
    let bytes = s.as_bytes();
    let mut name = String::new();
    let mut i = pos;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        name.push(bytes[i] as char);
        i += 1;
    }
    if name.is_empty() || i >= bytes.len() || bytes[i] != b'(' {
        return None;
    }
    i += 1;
    let mut depth = 1usize;
    let mut in_quote = false;
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch == '"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_quote = !in_quote;
            cur.push(ch);
            i += 1;
            continue;
        }
        if !in_quote {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
                if depth == 0 {
                    args.push(cur.trim().to_string());
                    return Some((name, args, i + 1));
                }
            } else if ch == ',' && depth == 1 {
                args.push(cur.trim().to_string());
                cur.clear();
                i += 1;
                continue;
            }
        }
        cur.push(ch);
        i += 1;
    }
    None
}

fn eval_arg(raw: &str, ctx: &DslCtx) -> Option<String> {
    let raw = raw.trim();
    if let Some(stripped) = raw.strip_prefix('"') {
        let inner = stripped.strip_suffix('"')?;
        return Some(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if let Some((fname, args, _)) = take_fn_call(raw, 0) {
        return match fname.as_str() {
            "to_lower" => Some(eval_arg(args.first()?, ctx)?.to_lowercase()),
            "to_upper" => Some(eval_arg(args.first()?, ctx)?.to_uppercase()),
            "len" => Some(eval_arg(args.first()?, ctx)?.chars().count().to_string()),
            "concat" => {
                let mut out = String::new();
                for a in &args {
                    out.push_str(&eval_arg(a, ctx)?);
                }
                Some(out)
            }
            "md5" => {
                let mut h = Md5::new();
                h.update(eval_arg(args.first()?, ctx)?.as_bytes());
                Some(hex_encode(&h.finalize()))
            }
            "sha1" => {
                let mut h = Sha1::new();
                h.update(eval_arg(args.first()?, ctx)?.as_bytes());
                Some(hex_encode(&h.finalize()))
            }
            "sha256" => {
                let mut h = Sha256::new();
                h.update(eval_arg(args.first()?, ctx)?.as_bytes());
                Some(hex_encode(&h.finalize()))
            }
            "base64" => Some(B64.encode(eval_arg(args.first()?, ctx)?.as_bytes())),
            _ => None,
        };
    }
    match raw {
        "body" => return Some(ctx.body.to_string()),
        "status_code" => return Some(ctx.status.to_string()),
        "headers" => return Some(ctx.headers.to_string()),
        "host" | "hostname" => return Some(ctx.vars.hostname.clone()),
        "base_url" => return Some(ctx.vars.base_url.clone()),
        _ => {}
    }
    if let Some(rest) = raw.strip_prefix("headers[") {
        let name = rest
            .trim_end_matches(']')
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .trim();
        for line in ctx.headers.lines() {
            if let Some((k, v)) = line.split_once(": ")
                && k.eq_ignore_ascii_case(name)
            {
                return Some(v.trim().to_string());
            }
        }
        return Some(String::new());
    }
    if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some(raw.to_string());
    }
    None
}

fn find_top_level_op(s: &str, op: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quote = !in_quote;
        } else if !in_quote && s[i..].starts_with(op) {
            match op {
                ">" if s[i..].starts_with(">=") => {
                    i += 1;
                }
                "<" if s[i..].starts_with("<=") => {
                    i += 1;
                }
                "!" if !s[i..].starts_with("!=") => {
                    i += 1;
                }
                "=" if s[i..].starts_with("==") => return Some(i),
                _ => return Some(i),
            }
        }
        i += 1;
    }
    None
}

fn compare_values(lhs: &str, op: &str, rhs: &str) -> Option<bool> {
    if let (Ok(a), Ok(b)) = (lhs.parse::<f64>(), rhs.parse::<f64>()) {
        return Some(match op {
            "==" => (a - b).abs() < f64::EPSILON,
            "!=" => (a - b).abs() >= f64::EPSILON,
            ">=" => a >= b,
            "<=" => a <= b,
            ">" => a > b,
            "<" => a < b,
            _ => return None,
        });
    }
    match op {
        "==" => Some(lhs == rhs),
        "!=" => Some(lhs != rhs),
        _ => None,
    }
}

fn eval_dsl_atom(atom: &str, ctx: &DslCtx) -> Option<bool> {
    let atom = atom.trim();
    for op in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some(idx) = find_top_level_op(atom, op) {
            let lhs = eval_arg(&atom[..idx], ctx)?;
            let rhs = eval_arg(&atom[idx + op.len()..], ctx)?;
            return compare_values(&lhs, op, &rhs);
        }
    }
    let (fname, args, _) = take_fn_call(atom, 0)?;
    let src = eval_arg(args.first()?, ctx)?;
    match fname.as_str() {
        "contains" => {
            let mut out = true;
            for a in args.iter().skip(1) {
                out &= src.contains(&eval_arg(a, ctx)?);
            }
            Some(out)
        }
        "contains_any" => {
            let mut out = false;
            for a in args.iter().skip(1) {
                out |= src.contains(&eval_arg(a, ctx)?);
            }
            Some(out)
        }
        "contains_all" => {
            let mut out = true;
            for a in args.iter().skip(1) {
                out &= src.contains(&eval_arg(a, ctx)?);
            }
            Some(out)
        }
        "icontains" => {
            let needle = eval_arg(args.get(1)?, ctx)?.to_lowercase();
            Some(src.to_lowercase().contains(&needle))
        }
        "starts_with" => Some(src.starts_with(&eval_arg(args.get(1)?, ctx)?)),
        "ends_with" => Some(src.ends_with(&eval_arg(args.get(1)?, ctx)?)),
        "regex" => Regex::new(&eval_arg(args.get(1)?, ctx)?)
            .ok()
            .map(|re| re.is_match(&src)),
        _ => None,
    }
}

fn eval_dsl(expr: &str, ctx: &DslCtx) -> Option<bool> {
    let substituted = substitute(expr, ctx.vars, &HashMap::new());
    if substituted.contains("interactsh") {
        return None;
    }
    for group in split_top_level(&substituted, "||") {
        let mut group_true = !group.is_empty();
        for atom in split_top_level(&group, "&&") {
            if atom.is_empty() {
                group_true = false;
                break;
            }
            match eval_dsl_atom(&atom, ctx) {
                Some(true) => {}
                Some(false) => {
                    group_true = false;
                    break;
                }
                None => return None,
            }
        }
        if group_true {
            return Some(true);
        }
    }
    Some(false)
}

// ---------------------------------------------------------------------------
// HTTP execution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: String,
    pub body: String,
}

pub struct HttpRunners {
    no_redirect: Client,
    redirect: Client,
    allow_remote: bool,
}

impl HttpRunners {
    pub fn build_with_scope(timeout: Duration, allow_remote: bool) -> Result<HttpRunners> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let build = |redirects: bool| -> Result<Client> {
            let policy = if redirects {
                Policy::custom(move |attempt| {
                    if attempt.previous().len() >= 10 {
                        return attempt.stop();
                    }
                    if !allow_remote
                        && !crate::idor_audit::is_lab_or_loopback_url(attempt.url().as_str())
                            .unwrap_or(false)
                    {
                        return attempt.stop();
                    }
                    attempt.follow()
                })
            } else {
                Policy::none()
            };
            let client = Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(timeout)
                .redirect(policy)
                .user_agent(concat!(
                    "Mozilla/5.0 (compatible; ShellMind-Guard/",
                    env!("CARGO_PKG_VERSION"),
                    ")"
                ))
                // Lab-only runner: loopback/RFC1918 targets frequently use
                // self-signed certs; remote staging targets verify TLS by default.
                .danger_accept_invalid_certs(!allow_remote) // smg-ignore: SMG-CFG-TLS
                .build()?;
            Ok(client)
        };
        Ok(HttpRunners {
            no_redirect: build(false)?,
            redirect: build(true)?,
            allow_remote,
        })
    }
}

pub fn build_url(base_url: &str, path: &str) -> String {
    let p = path.trim();
    if p.starts_with("http://") || p.starts_with("https://") {
        return p.to_string();
    }
    let base = base_url.trim_end_matches('/');
    if p.starts_with('/') {
        format!("{base}{p}")
    } else {
        format!("{base}/{p}")
    }
}

pub struct RawRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn parse_raw_request(raw: &str) -> Option<RawRequest> {
    let (head, body) = if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], raw[pos + 4..].to_string())
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], raw[pos + 2..].to_string())
    } else {
        (raw, String::new())
    };
    let mut lines = head.lines();
    let first = lines.next()?.trim().to_string();
    let mut tokens = first.split_whitespace();
    let method = tokens.next()?.to_ascii_uppercase();
    let target = tokens.next()?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some(RawRequest {
        method,
        target,
        headers,
        body,
    })
}

pub enum BlockOutcome {
    Response(HttpResponse),
    Skipped(String),
}

fn send_request(
    runners: &HttpRunners,
    method: &reqwest::Method,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    follow_redirects: bool,
) -> Result<HttpResponse> {
    if !runners.allow_remote && !crate::idor_audit::is_lab_or_loopback_url(url)? {
        bail!("refusing off-scope template URL '{url}' without --allow-remote");
    }
    let client = if follow_redirects {
        &runners.redirect
    } else {
        &runners.no_redirect
    };
    let mut req = client.request(method.clone(), url);
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            req = req.header(name, val);
        }
    }
    if !body.is_empty() {
        req = req.body(body.to_string());
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let mut header_str = String::new();
    let hmap: &HeaderMap = resp.headers();
    for (k, v) in hmap.iter() {
        header_str.push_str(&format!(
            "{}: {}\r\n",
            k.as_str(),
            v.to_str().unwrap_or("<binary>")
        ));
    }
    let mut bytes = Vec::new();
    let _ = resp
        .take(MAX_CAPTURE_BODY as u64)
        .read_to_end(&mut bytes);
    let body = String::from_utf8_lossy(&bytes).into_owned();
    Ok(HttpResponse {
        status,
        headers: header_str,
        body,
    })
}

pub fn execute_http_block(runners: &HttpRunners, block: &HttpBlock, vars: &Vars) -> BlockOutcome {
    let extra = HashMap::new();
    if block.race || block.flow.is_some() || block.payloads.is_some() {
        return BlockOutcome::Skipped(
            "fuzz/race/flow blocks are outside the defensive detection scope".into(),
        );
    }
    let follow = block.redirects.unwrap_or(false);

    if let Some(raws) = &block.raw {
        if let Some(raw) = raws.to_vec().into_iter().next() {
            let substituted = substitute(&raw, vars, &extra);
            if has_unresolved_vars(&substituted) {
                return BlockOutcome::Skipped(
                    "raw request has unresolved template variables".into(),
                );
            }
            let Some(parsed) = parse_raw_request(&substituted) else {
                return BlockOutcome::Skipped("raw request could not be parsed".into());
            };
            let Ok(method) = reqwest::Method::from_bytes(parsed.method.as_bytes()) else {
                return BlockOutcome::Skipped(format!("unsupported HTTP method {}", parsed.method));
            };
            let url = build_url(&vars.base_url, &parsed.target);
            let mut headers = parsed.headers;
            if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
                headers.push(("Host".into(), vars.hostname.clone()));
            }
            return match send_request(runners, &method, &url, &headers, &parsed.body, follow) {
                Ok(resp) => BlockOutcome::Response(resp),
                Err(e) => BlockOutcome::Skipped(format!("HTTP request failed: {e}")),
            };
        }
        return BlockOutcome::Skipped("raw block had no requests".into());
    }

    let Some(paths) = &block.path else {
        return BlockOutcome::Skipped("HTTP block has neither path nor raw".into());
    };
    let method_name = block
        .method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_ascii_uppercase();
    let Ok(method) = reqwest::Method::from_bytes(method_name.as_bytes()) else {
        return BlockOutcome::Skipped(format!("unsupported HTTP method {method_name}"));
    };
    if matches!(method, reqwest::Method::CONNECT | reqwest::Method::TRACE) {
        return BlockOutcome::Skipped(format!(
            "method {method_name} not allowed in detection mode"
        ));
    }
    if let Some(path) = paths.to_vec().into_iter().next() {
        let substituted = substitute(&path, vars, &extra);
        if has_unresolved_vars(&substituted) {
            return BlockOutcome::Skipped("path has unresolved template variables".into());
        }
        let url = build_url(&vars.base_url, &substituted);
        let mut headers = block_headers(block);
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            headers.push(("Host".into(), vars.hostname.clone()));
        }
        let body = substitute(block.body.as_deref().unwrap_or_default(), vars, &extra);
        match send_request(runners, &method, &url, &headers, &body, follow) {
            Ok(resp) => return BlockOutcome::Response(resp),
            Err(e) => return BlockOutcome::Skipped(format!("HTTP request failed: {e}")),
        }
    }
    BlockOutcome::Skipped("path block had no requests".into())
}

// ---------------------------------------------------------------------------
// Matcher evaluation
// ---------------------------------------------------------------------------

pub struct MatcherResult {
    pub matched: bool,
    pub evidence: Vec<String>,
}

fn part_text(resp: &HttpResponse, part: Option<&str>) -> String {
    match part.unwrap_or("body").to_ascii_lowercase().as_str() {
        "header" | "headers" => resp.headers.clone(),
        "all" => format!("{}\n{}", resp.headers, resp.body),
        "body" | "" => resp.body.clone(),
        // interactsh parts are filtered out earlier; anything else is unsupported.
        _ => String::new(),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn matcher_on_text(m: &Matcher, text: &str, resp: &HttpResponse, vars: &Vars) -> Option<bool> {
    let out: Option<bool> = match m.kind.as_str() {
        "status" => {
            let statuses = m.status.as_ref()?.to_vec();
            Some(statuses.contains(&(resp.status as usize)))
        }
        "word" => {
            let words = m.words.as_ref()?.to_vec();
            let cond_and = m
                .condition
                .as_deref()
                .unwrap_or("or")
                .eq_ignore_ascii_case("and");
            let mut all = true;
            let mut any = false;
            for w in &words {
                let (hay, needle) = if m.case_insensitive {
                    (text.to_lowercase(), w.to_lowercase())
                } else {
                    (text.to_string(), w.clone())
                };
                all &= hay.contains(&needle);
                any |= hay.contains(&needle);
            }
            Some(if cond_and { all } else { any })
        }
        "regex" => {
            let patterns = m.regex.as_ref()?.to_vec();
            let cond_and = m
                .condition
                .as_deref()
                .unwrap_or("or")
                .eq_ignore_ascii_case("and");
            let mut all = true;
            let mut any = false;
            for p in &patterns {
                let re = match regex::RegexBuilder::new(p)
                    .size_limit(256 * 1024)
                    .dfa_size_limit(256 * 1024)
                    .build()
                {
                    Ok(re) => re,
                    Err(_) => return None,
                };
                let hit = re.is_match(text);
                all &= hit;
                any |= hit;
            }
            Some(if cond_and { all && !patterns.is_empty() } else { any })
        }
        "size" => {
            let sizes = m.size.as_ref()?.to_vec();
            Some(sizes.contains(&text.len()))
        }
        "binary" => {
            let bins = m.binary.as_ref()?.to_vec();
            let mut any = false;
            for b in &bins {
                if let Ok(bytes) = decode_hex(b) {
                    any |= contains_subslice(text.as_bytes(), &bytes);
                }
            }
            Some(any)
        }
        "dsl" => {
            let exprs = m.dsl.as_ref()?.to_vec();
            let cond_and = m
                .condition
                .as_deref()
                .unwrap_or("or")
                .eq_ignore_ascii_case("and");
            let ctx = DslCtx {
                status: resp.status,
                body: &resp.body,
                headers: &resp.headers,
                vars,
            };
            let mut all = true;
            let mut any = false;
            for e in &exprs {
                let v = eval_dsl(e, &ctx)?;
                all &= v;
                any |= v;
            }
            Some(if cond_and { all && !exprs.is_empty() } else { any })
        }
        _ => return None,
    };
    if m.negative { out.map(|v| !v) } else { out }
}

pub fn evaluate_matchers(
    matchers: &[Matcher],
    condition: Option<&str>,
    resp: &HttpResponse,
    vars: &Vars,
) -> MatcherResult {
    let mut evidence = Vec::new();
    if matchers.is_empty() {
        return MatcherResult {
            matched: true,
            evidence: vec!["no matchers (implicit match)".into()],
        };
    }
    let cond_and = condition.unwrap_or("or").eq_ignore_ascii_case("and");
    let mut all_true = true;
    let mut any_true = false;
    for m in matchers {
        let text = part_text(resp, m.part.as_deref());
        match matcher_on_text(m, &text, resp, vars) {
            Some(true) => {
                any_true = true;
                evidence.push(format!("{} matcher matched", m.kind));
                if let Some(w) = m.words.as_ref() {
                    for word in w.to_vec().into_iter().take(2) {
                        if text.contains(&word) {
                            evidence.push(format!("word: {word:?}"));
                        }
                    }
                }
            }
            Some(false) => {
                all_true = false;
            }
            // Unsupported matcher shape: fail-closed => cannot prove a match.
            None => {
                all_true = false;
                evidence.push(format!("{} matcher unsupported (fail-closed)", m.kind));
            }
        }
    }
    let matched = if cond_and {
        all_true && !matchers.is_empty()
    } else {
        any_true
    };
    MatcherResult { matched, evidence }
}

pub fn run_extractors(extractors: &[Extractor], resp: &HttpResponse) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for ex in extractors {
        let name = ex.name.clone().unwrap_or_else(|| ex.kind.clone());
        match ex.kind.as_str() {
            "regex" => {
                for p in ex.regex.as_ref().map(|r| r.to_vec()).unwrap_or_default() {
                    if let Ok(re) = Regex::new(&p)
                        && let Some(cap) = re.captures(&resp.body)
                        && let Some(v) = cap.get(1).or_else(|| cap.get(0))
                    {
                        out.push((name.clone(), v.as_str().to_string()));
                    }
                }
            }
            "word" => {
                for w in ex.words.as_ref().map(|r| r.to_vec()).unwrap_or_default() {
                    if resp.body.contains(&w) {
                        out.push((name.clone(), w));
                    }
                }
            }
            "kval" => {
                for kv in ex.kval.as_ref().map(|r| r.to_vec()).unwrap_or_default() {
                    if let Some(k) = kv.name {
                        for line in resp.headers.lines() {
                            if let Some((hk, hv)) = line.split_once(": ")
                                && hk.eq_ignore_ascii_case(&k)
                            {
                                out.push((name.clone(), hv.trim().to_string()));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// DNS engine (pure-Rust UDP resolver, deterministic query ids)
// ---------------------------------------------------------------------------

pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QTYPE_NS: u16 = 2;
pub const DNS_QTYPE_CNAME: u16 = 5;
pub const DNS_QTYPE_PTR: u16 = 12;
pub const DNS_QTYPE_MX: u16 = 15;
pub const DNS_QTYPE_TXT: u16 = 16;
pub const DNS_QTYPE_AAAA: u16 = 28;

pub fn dns_qtype_from_str(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(DNS_QTYPE_A),
        "NS" => Some(DNS_QTYPE_NS),
        "CNAME" => Some(DNS_QTYPE_CNAME),
        "PTR" => Some(DNS_QTYPE_PTR),
        "MX" => Some(DNS_QTYPE_MX),
        "TXT" => Some(DNS_QTYPE_TXT),
        "AAAA" => Some(DNS_QTYPE_AAAA),
        _ => None,
    }
}

pub fn system_nameservers() -> Vec<String> {
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        let servers: Vec<String> = content
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver "))
            .map(|s| s.trim().to_string())
            .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
            .collect();
        if !servers.is_empty() {
            return servers;
        }
    }
    vec!["127.0.0.53".into(), "127.0.0.1".into()]
}

pub fn build_dns_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD flag
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QDCOUNT=1
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // IN
    out
}

fn read_dns_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;
    let mut hops = 0usize;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = ptr;
            hops += 1;
            if hops > 32 {
                return None;
            }
        } else if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else {
            if pos + 1 + len > buf.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + len]).to_string());
            pos += 1 + len;
        }
    }
    Some((labels.join("."), end_pos))
}

/// Returns `(rcode, records)` for a DNS response, or `None` on malformed data.
pub fn parse_dns_response(buf: &[u8]) -> Option<(u16, Vec<(u16, String)>)> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x0F;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_, next) = read_dns_name(buf, pos)?;
        pos = next + 4;
    }
    let mut records = Vec::new();
    for _ in 0..ancount {
        let (_, mut p) = read_dns_name(buf, pos)?;
        if p + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        p += 10;
        if p + rdlen > buf.len() {
            return None;
        }
        let rdata = &buf[p..p + rdlen];
        let rendered = match rtype {
            DNS_QTYPE_A if rdlen == 4 => {
                format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
            }
            DNS_QTYPE_AAAA if rdlen == 16 => {
                let groups: Vec<String> = (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                    .collect();
                groups.join(":")
            }
            DNS_QTYPE_CNAME | DNS_QTYPE_NS | DNS_QTYPE_PTR => {
                read_dns_name(buf, p).map(|(n, _)| n)?
            }
            DNS_QTYPE_MX if rdlen > 2 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                read_dns_name(buf, p + 2).map(|(n, _)| format!("{pref} {n}"))?
            }
            DNS_QTYPE_TXT => {
                let mut text = String::new();
                let mut i = 0;
                while i < rdlen {
                    let seg_len = rdata[i] as usize;
                    if i + 1 + seg_len > rdlen {
                        break;
                    }
                    text.push_str(&String::from_utf8_lossy(&rdata[i + 1..i + 1 + seg_len]));
                    i += 1 + seg_len;
                }
                text
            }
            _ => String::new(),
        };
        records.push((rtype, rendered));
        pos = p + rdlen;
    }
    Some((rcode, records))
}

pub fn send_dns_query(
    name: &str,
    qtype: u16,
    id: u16,
    timeout: Duration,
) -> Option<Vec<(u16, String)>> {
    let query = build_dns_query(name, qtype, id);
    for server in system_nameservers().into_iter().take(3) {
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.set_read_timeout(Some(timeout)).ok()?;
        sock.set_write_timeout(Some(timeout)).ok()?;
        if sock.send_to(&query, format!("{server}:53")).is_err() {
            continue;
        }
        let mut buf = [0u8; 4096];
        let Ok((n, _)) = sock.recv_from(&mut buf) else {
            continue;
        };
        if n < 12 || buf[0..2] != id.to_be_bytes() {
            continue;
        }
        if let Some((rcode, records)) = parse_dns_response(&buf[..n])
            && rcode == 0
        {
            return Some(records);
        }
    }
    None
}

pub enum DnsOutcome {
    Records(Vec<(u16, String)>),
    Failed(String),
}

pub fn execute_dns_block(
    block: &DnsBlock,
    vars: &Vars,
    timeout: Duration,
    template_id: &str,
) -> DnsOutcome {
    let extra = HashMap::new();
    let name_raw = block.name.clone().unwrap_or_else(|| "{{FQDN}}".into());
    let name = substitute(&name_raw, vars, &extra);
    if has_unresolved_vars(&name) {
        return DnsOutcome::Failed("DNS name has unresolved template variables".into());
    }
    let Some(qtype) = dns_qtype_from_str(block.qtype.as_deref().unwrap_or("A")) else {
        return DnsOutcome::Failed(format!(
            "unsupported DNS qtype {}",
            block.qtype.as_deref().unwrap_or("")
        ));
    };
    let digest = blake3::hash(format!("{template_id}:{name}").as_bytes()).to_hex();
    let id = u16::from_be_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]);
    match send_dns_query(&name, qtype, id, timeout) {
        Some(records) => DnsOutcome::Records(records),
        None => DnsOutcome::Failed("DNS query failed (no reachable resolver)".into()),
    }
}

fn dns_record_text(records: &[(u16, String)]) -> String {
    records
        .iter()
        .map(|(t, r)| {
            let tn = match *t {
                DNS_QTYPE_A => "A",
                DNS_QTYPE_AAAA => "AAAA",
                DNS_QTYPE_CNAME => "CNAME",
                DNS_QTYPE_NS => "NS",
                DNS_QTYPE_PTR => "PTR",
                DNS_QTYPE_MX => "MX",
                DNS_QTYPE_TXT => "TXT",
                _ => "OTHER",
            };
            format!("{tn} {r}")
        })
        .collect::<Vec<_>>()
        .join(" ; ")
}

// ---------------------------------------------------------------------------
// Network (raw TCP/TLS banner) engine
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct InsecureServerVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

enum NetConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl NetConn {
    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            NetConn::Plain(s) => s.write_all(data),
            NetConn::Tls(s) => s.write_all(data),
        }
    }
    fn read_available(&mut self, size: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let n = match self {
            NetConn::Plain(s) => s.read(&mut buf)?,
            NetConn::Tls(s) => s.read(&mut buf)?,
        };
        buf.truncate(n);
        Ok(buf)
    }
}

fn expand_ports(ports: &[PortVal]) -> Vec<u16> {
    let mut out = Vec::new();
    for p in ports {
        let spec = match p {
            PortVal::Num(n) => n.to_string(),
            PortVal::Str(s) => s.clone(),
        };
        if let Some((a, b)) = spec.split_once('-')
            && let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>())
        {
            for port in a..=b.min(a.saturating_add(63)) {
                out.push(port);
            }
            continue;
        }
        if let Ok(port) = spec.trim().parse::<u16>() {
            out.push(port);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn tls_enabled(v: &Option<serde_yaml_ng::Value>) -> bool {
    match v {
        Some(serde_yaml_ng::Value::Bool(true)) => true,
        Some(serde_yaml_ng::Value::String(s)) => matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "secure" | "insecure" | "auto"
        ),
        _ => false,
    }
}

pub fn execute_network_block(
    block: &NetworkBlock,
    vars: &Vars,
    timeout: Duration,
) -> Result<Vec<HttpResponse>> {
    let extra = HashMap::new();
    let hosts = block
        .host
        .as_ref()
        .map(|h| h.to_vec())
        .unwrap_or_else(|| vec!["{{Hostname}}".into()]);
    let port_specs = block.ports.as_ref().map(|p| p.to_vec()).unwrap_or_default();
    let ports = expand_ports(&port_specs);
    let read_size = block.read_size.unwrap_or(1024).min(1 << 20);
    let mut responses = Vec::new();

    for host_raw in hosts {
        let host = substitute(&host_raw, vars, &extra);
        let (host_name, host_port): (String, Option<u16>) = if !host.contains('[')
            && let Some((h, p)) = host.rsplit_once(':')
        {
            (h.to_string(), p.parse().ok())
        } else {
            (host.clone(), None)
        };
        let ip: std::net::IpAddr = host_name.parse().map_err(|_| {
            anyhow::anyhow!(
                "network host '{host_name}' is not an IP (hostname DNS resolution is outside the network engine scope; use {{Host}} of an IP target)"
            )
        })?;
        let port_list: Vec<u16> = if ports.is_empty() {
            vec![host_port.unwrap_or(80)]
        } else {
            ports.clone()
        };
        for port in port_list {
            let addr = std::net::SocketAddr::new(ip, port);
            let sock = TcpStream::connect_timeout(&addr, timeout)?;
            sock.set_read_timeout(Some(timeout))?;
            sock.set_write_timeout(Some(timeout))?;
            let mut conn = if tls_enabled(&block.tls) {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let cfg = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
                    .with_no_client_auth();
                let server_name = block.sni.clone().unwrap_or_else(|| host_name.clone());
                let name = rustls::pki_types::ServerName::try_from(server_name)
                    .map_err(|e| anyhow::anyhow!("invalid SNI/server name: {e}"))?;
                let client = rustls::ClientConnection::new(Arc::new(cfg), name)
                    .map_err(|e| anyhow::anyhow!("TLS client init failed: {e}"))?;
                NetConn::Tls(Box::new(rustls::StreamOwned::new(client, sock)))
            } else {
                NetConn::Plain(sock)
            };
            let mut sent = 0usize;
            for input in block.inputs.iter().flatten() {
                let data = substitute(&input.data, vars, &extra)
                    .replace("\\r", "\r")
                    .replace("\\n", "\n");
                if conn.write_all(data.as_bytes()).is_err() {
                    break;
                }
                sent += 1;
            }
            let mut collected: Vec<u8> = Vec::new();
            let read_iters = if sent > 0 { 4 } else { 1 };
            for _ in 0..read_iters {
                match conn.read_available(read_size) {
                    Ok(chunk) if chunk.is_empty() => break,
                    Ok(chunk) => collected.extend(chunk),
                    Err(_) => break,
                }
            }
            responses.push(HttpResponse {
                status: 0,
                headers: String::new(),
                body: String::from_utf8_lossy(&collected).into_owned(),
            });
        }
    }
    Ok(responses)
}

// ---------------------------------------------------------------------------
// Template loading & run orchestration
// ---------------------------------------------------------------------------

pub struct LoadedTemplate {
    pub path: PathBuf,
    pub template: NucleiTemplate,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkippedTemplate {
    pub id: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TemplateMatch {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub template_path: String,
    pub url: String,
    pub engine: String,
    pub matcher_types: Vec<String>,
    pub evidence: Vec<String>,
    pub extracted: Vec<(String, String)>,
}

#[derive(Debug, serde::Serialize)]
pub struct TemplateRunReport {
    pub target: String,
    pub templates_dir: String,
    pub loaded: usize,
    pub executed: usize,
    pub matched_count: usize,
    pub matches: Vec<TemplateMatch>,
    pub skipped: Vec<SkippedTemplate>,
    pub parse_errors: usize,
    pub elapsed_ms: u128,
}

pub struct TemplateRunConfig {
    pub target: String,
    pub templates_dir: PathBuf,
    pub severity_filter: Vec<String>,
    pub tag_filter: Vec<String>,
    pub max_templates: usize,
    pub timeout: Duration,
    pub allow_remote: bool,
}

fn unsupported_reason(t: &NucleiTemplate, raw_text: &str) -> Option<String> {
    if t.headless.is_some() {
        return Some("headless-browser engine not supported".into());
    }
    if t.javascript.is_some() || t.lua.is_some() {
        return Some("javascript/lua engine not supported".into());
    }
    if t.code.is_some() {
        return Some("code-execution engine not supported".into());
    }
    if t.file.is_some() {
        return Some("file engine not supported".into());
    }
    if t.ssl.is_some() {
        return Some("ssl engine not supported (use `smg tls` for live TLS audits)".into());
    }
    if t.websocket.is_some() {
        return Some("websocket engine not supported".into());
    }
    if t.whois.is_some() {
        return Some("whois engine not supported".into());
    }
    if t.flow.is_some() {
        return Some("flow engine not supported".into());
    }
    if t.interactive == Some(true) {
        return Some("interactive template not supported".into());
    }
    if raw_text.contains("interactsh") || raw_text.contains("oob") {
        return Some("interactsh/OOB callback template not supported".into());
    }
    None
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 12 || out.len() > MAX_TEMPLATE_FILES * 2 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_yaml_files(&p, out, depth + 1);
        } else if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        ) {
            out.push(p);
        }
    }
}

fn load_templates_dir(
    dir: &Path,
    max: usize,
) -> Result<(Vec<LoadedTemplate>, Vec<SkippedTemplate>, usize)> {
    if !dir.is_dir() {
        bail!("Templates directory {} does not exist", dir.display());
    }
    let mut yaml_paths: Vec<PathBuf> = Vec::new();
    collect_yaml_files(dir, &mut yaml_paths, 0);
    yaml_paths.sort();
    let mut loaded = Vec::new();
    let mut skipped = Vec::new();
    let mut parse_errors = 0usize;
    for path in yaml_paths.into_iter().take(max) {
        let Ok(raw) = fs::read_to_string(&path) else {
            parse_errors += 1;
            continue;
        };
        match serde_yaml_ng::from_str::<NucleiTemplate>(&raw) {
            Ok(mut tpl) => {
                let id = match tpl.id.clone() {
                    Some(id) if !id.is_empty() => id,
                    _ => {
                        skipped.push(SkippedTemplate {
                            id: String::new(),
                            path: path.display().to_string(),
                            reason: "missing template id".into(),
                        });
                        continue;
                    }
                };
                if let Some(reason) = unsupported_reason(&tpl, &raw) {
                    skipped.push(SkippedTemplate {
                        id,
                        path: path.display().to_string(),
                        reason,
                    });
                    continue;
                }
                if tpl.http.is_empty() && tpl.dns.is_empty() && tpl.network.is_empty() {
                    skipped.push(SkippedTemplate {
                        id,
                        path: path.display().to_string(),
                        reason: "no http/dns/network request block".into(),
                    });
                    continue;
                }
                if tpl.http.iter().any(|b| b.payloads.is_some() || b.race) {
                    skipped.push(SkippedTemplate {
                        id,
                        path: path.display().to_string(),
                        reason: "fuzz/payload or race engine not supported".into(),
                    });
                    continue;
                }
                tpl.id = Some(id);
                loaded.push(LoadedTemplate {
                    path,
                    template: tpl,
                });
            }
            Err(_) => {
                parse_errors += 1;
            }
        }
    }
    Ok((loaded, skipped, parse_errors))
}

fn template_tags(t: &NucleiTemplate) -> Vec<String> {
    t.info
        .tags
        .as_ref()
        .map(|tm| {
            tm.to_vec()
                .iter()
                .flat_map(|s| s.split(','))
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn template_severity(t: &NucleiTemplate) -> String {
    t.info
        .severity
        .as_deref()
        .unwrap_or("info")
        .trim()
        .to_ascii_lowercase()
}

pub fn run_template_audit(cfg: &TemplateRunConfig) -> Result<TemplateRunReport> {
    if !cfg.allow_remote && !crate::idor_audit::is_lab_or_loopback_url(&cfg.target)? {
        bail!(
            "Refusing remote target '{}' by default (template scans target loopback/private lab hosts unless `--allow-remote` is explicitly passed for your own staging server).",
            cfg.target
        );
    }
    let started = Instant::now();
    let (templates, mut skipped, parse_errors) =
        load_templates_dir(&cfg.templates_dir, cfg.max_templates.max(1))?;
    let base_vars = parse_target(&cfg.target)?;
    let runners = HttpRunners::build_with_scope(cfg.timeout, cfg.allow_remote)?;
    let mut matches = Vec::new();
    let mut executed = 0usize;

    for loaded in &templates {
        let tpl = &loaded.template;
        let id = tpl.id.clone().unwrap_or_default();
        let severity = template_severity(tpl);
        if !cfg.severity_filter.is_empty()
            && !cfg
                .severity_filter
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&severity))
        {
            continue;
        }
        let tags = template_tags(tpl);
        if !cfg.tag_filter.is_empty()
            && !cfg
                .tag_filter
                .iter()
                .any(|t| tags.contains(&t.to_ascii_lowercase()))
        {
            continue;
        }
        let vars = Vars::for_template(&base_vars, &id);
        let mut block_skips: Vec<String> = Vec::new();
        let mut template_matched = false;
        let total_blocks = tpl.http.len() + tpl.dns.len() + tpl.network.len();

        for block in &tpl.http {
            match execute_http_block(&runners, block, &vars) {
                BlockOutcome::Skipped(reason) => block_skips.push(reason),
                BlockOutcome::Response(resp) => {
                    executed += 1;
                    let result = evaluate_matchers(
                        &block.matchers,
                        block.matchers_condition.as_deref(),
                        &resp,
                        &vars,
                    );
                    let extracted = run_extractors(&block.extractors, &resp);
                    if result.matched {
                        template_matched = true;
                        matches.push(TemplateMatch {
                            template_id: id.clone(),
                            template_name: tpl.info.name.clone().unwrap_or_default(),
                            severity: severity.clone(),
                            template_path: loaded.path.display().to_string(),
                            url: vars.base_url.clone(),
                            engine: "http".into(),
                            matcher_types: block.matchers.iter().map(|m| m.kind.clone()).collect(),
                            evidence: result.evidence,
                            extracted,
                        });
                        if block.stop_at_first_match {
                            break;
                        }
                    }
                }
            }
        }

        if template_matched && !tpl.http.iter().any(|b| b.stop_at_first_match) {
            // continue evaluating remaining engines for complete evidence
        }

        for block in &tpl.dns {
            match execute_dns_block(block, &vars, cfg.timeout, &id) {
                DnsOutcome::Failed(reason) => block_skips.push(reason),
                DnsOutcome::Records(records) => {
                    executed += 1;
                    let text = dns_record_text(&records);
                    let resp = HttpResponse {
                        status: 0,
                        headers: String::new(),
                        body: text,
                    };
                    let result = evaluate_matchers(
                        &block.matchers,
                        block.matchers_condition.as_deref(),
                        &resp,
                        &vars,
                    );
                    if result.matched {
                        template_matched = true;
                        matches.push(TemplateMatch {
                            template_id: id.clone(),
                            template_name: tpl.info.name.clone().unwrap_or_default(),
                            severity: severity.clone(),
                            template_path: loaded.path.display().to_string(),
                            url: vars.fqdn.clone(),
                            engine: "dns".into(),
                            matcher_types: block.matchers.iter().map(|m| m.kind.clone()).collect(),
                            evidence: result.evidence,
                            extracted: run_extractors(&block.extractors, &resp),
                        });
                    }
                }
            }
        }

        if !tpl.network.is_empty() {
            match execute_network_block(&tpl.network[0], &vars, cfg.timeout) {
                Err(e) => block_skips.push(format!("network engine: {e}")),
                Ok(responses) => {
                    for resp in responses {
                        executed += 1;
                        let result = evaluate_matchers(
                            &tpl.network[0].matchers,
                            tpl.network[0].matchers_condition.as_deref(),
                            &resp,
                            &vars,
                        );
                        if result.matched {
                            template_matched = true;
                            matches.push(TemplateMatch {
                                template_id: id.clone(),
                                template_name: tpl.info.name.clone().unwrap_or_default(),
                                severity: severity.clone(),
                                template_path: loaded.path.display().to_string(),
                                url: format!("{}:{}", vars.host, vars.port),
                                engine: "network".into(),
                                matcher_types: tpl.network[0]
                                    .matchers
                                    .iter()
                                    .map(|m| m.kind.clone())
                                    .collect(),
                                evidence: result.evidence,
                                extracted: run_extractors(&tpl.network[0].extractors, &resp),
                            });
                        }
                    }
                }
            }
        }

        if !template_matched && !block_skips.is_empty() && block_skips.len() == total_blocks {
            skipped.push(SkippedTemplate {
                id,
                path: loaded.path.display().to_string(),
                reason: block_skips.join("; "),
            });
        }
    }

    let target = cfg.target.clone();
    Ok(TemplateRunReport {
        templates_dir: cfg.templates_dir.display().to_string(),
        target,
        loaded: templates.len(),
        executed,
        matched_count: matches.len(),
        matches,
        skipped,
        parse_errors,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn mock_server(routes: &'static [(&'static str, &'static str, u16, &'static str)]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..64 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let mut response = String::new();
                for (path, body, status, content_type) in routes {
                    if req.starts_with(&format!("GET {path} "))
                        || req.starts_with(&format!("POST {path} "))
                    {
                        let reason = match status {
                            200 => "OK",
                            301 => "Moved Permanently",
                            403 => "Forbidden",
                            _ => "OK",
                        };
                        response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        break;
                    }
                }
                if response.is_empty() {
                    response =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string();
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn temp_templates_dir(entries: &[(&str, &str)]) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("smg-tpl-{}-{}", std::process::id(), entries.len()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for (name, content) in entries {
            fs::write(dir.join(format!("{name}.yaml")), content).unwrap();
        }
        dir
    }

    const GIT_CONFIG_TEMPLATE: &str = r#"
id: git-config-exposure
info:
  name: Git config exposure
  author: smg-test
  severity: high
  tags: exposure,config
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
"#;

    #[test]
    fn http_word_matcher_detects_git_config_exposure() {
        let target = mock_server(&[(
            "/.git/config",
            "[core]\n\trepositoryformatversion = 0\n",
            200,
            "text/plain",
        )]);
        let dir = temp_templates_dir(&[("git", GIT_CONFIG_TEMPLATE)]);
        let report = run_template_audit(&TemplateRunConfig {
            target,
            templates_dir: dir.clone(),
            severity_filter: vec![],
            tag_filter: vec![],
            max_templates: 100,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.matched_count, 1);
        assert_eq!(report.matches[0].template_id, "git-config-exposure");
        assert_eq!(report.matches[0].engine, "http");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dsl_matcher_and_severity_filtering_work() {
        let target = mock_server(&[("/admin", "admin panel: SUPERUSER", 200, "text/plain")]);
        let tpl = r#"
id: admin-panel-detect
info:
  name: Admin panel
  author: smg-test
  severity: critical
  tags: panel
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && contains(body, "SUPERUSER")'
"#;
        let dir = temp_templates_dir(&[("admin", tpl)]);
        let filtered = run_template_audit(&TemplateRunConfig {
            target: target.clone(),
            templates_dir: dir.clone(),
            severity_filter: vec!["low".into()],
            tag_filter: vec![],
            max_templates: 50,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(filtered.matched_count, 0);
        let report = run_template_audit(&TemplateRunConfig {
            target,
            templates_dir: dir.clone(),
            severity_filter: vec![],
            tag_filter: vec![],
            max_templates: 50,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.matched_count, 1);
        assert_eq!(report.matches[0].template_id, "admin-panel-detect");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn interactsh_and_headless_templates_are_skipped_with_reason() {
        let dir = temp_templates_dir(&[
            (
                "oob",
                r#"
id: oob-detect
info:
  name: OOB detection
  author: smg-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["x"]
"#,
            ),
            (
                "headless",
                r#"
id: headless-detect
info:
  name: Headless
  author: smg-test
  severity: info
headless:
  - steps:
      - action: navigate
        url: "{{BaseURL}}"
"#,
            ),
        ]);
        let report = run_template_audit(&TemplateRunConfig {
            target: "http://127.0.0.1:9".into(),
            templates_dir: dir.clone(),
            severity_filter: vec![],
            tag_filter: vec![],
            max_templates: 50,
            timeout: Duration::from_secs(2),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.loaded, 0);
        assert_eq!(report.skipped.len(), 2);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.reason.contains("interactsh"))
        );
        assert!(report.skipped.iter().any(|s| s.reason.contains("headless")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_remote_target_without_allow_remote() {
        let dir = temp_templates_dir(&[("x", GIT_CONFIG_TEMPLATE)]);
        let err = run_template_audit(&TemplateRunConfig {
            target: "https://example.com".into(),
            templates_dir: dir.clone(),
            severity_filter: vec![],
            tag_filter: vec![],
            max_templates: 10,
            timeout: Duration::from_secs(2),
            allow_remote: false,
        });
        assert!(err.is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn helper_substitution_md5_base64_url_encode() {
        let vars = Vars {
            base_url: "http://127.0.0.1:1".into(),
            root_url: "http://127.0.0.1:1".into(),
            hostname: "127.0.0.1:1".into(),
            host: "127.0.0.1".into(),
            port: "1".into(),
            scheme: "http".into(),
            path: "/".into(),
            file: String::new(),
            fqdn: "127.0.0.1".into(),
            randstr: "abcdef123456".into(),
        };
        let out = substitute(
            "{{md5(\"abc\")}} {{base64(\"abc\")}} {{url_encode(\"a b\")}} {{upper(\"hi\")}} {{randstr}}",
            &vars,
            &HashMap::new(),
        );
        assert_eq!(
            out,
            "900150983cd24fb0d6963f7d28e17f72 YWJj a%20b HI abcdef123456"
        );
    }

    #[test]
    fn dns_query_build_and_synthetic_response_parse() {
        let query = build_dns_query("example.com", DNS_QTYPE_A, 0x534D);
        assert_eq!(&query[0..2], &[0x53, 0x4D]);
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        let qname = &query[12..];
        assert_eq!(qname[0], 7);
        assert_eq!(&qname[1..8], b"example");
        assert_eq!(qname[8], 3);
        assert_eq!(&qname[9..12], b"com");
        assert_eq!(qname[12], 0);

        // Synthetic response: header + question + one A answer with pointer compression.
        let mut resp: Vec<u8> = vec![
            0x53, 0x4D, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        resp.extend_from_slice(&query[12..]);
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        let (rcode, records) = parse_dns_response(&resp).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, DNS_QTYPE_A);
        assert_eq!(records[0].1, "93.184.216.34");
    }

    #[test]
    fn raw_request_template_parses_and_matches() {
        let target = mock_server(&[("/legacy", "legacy-app-banner-XYZ", 200, "text/plain")]);
        let tpl = r#"
id: legacy-banner
info:
  name: Legacy banner
  author: smg-test
  severity: low
http:
  - raw:
      - |
        GET /legacy HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        words:
          - "legacy-app-banner-XYZ"
"#;
        let dir = temp_templates_dir(&[("legacy", tpl)]);
        let report = run_template_audit(&TemplateRunConfig {
            target,
            templates_dir: dir.clone(),
            severity_filter: vec![],
            tag_filter: vec![],
            max_templates: 50,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.matched_count, 1);
        let _ = fs::remove_dir_all(dir);
    }
}
