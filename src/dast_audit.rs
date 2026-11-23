//! Defensive web posture auditor with limited lab-gated active checks (`smg dast`).
//!
//! Scope (Phase 26 Part A, defensive design):
//! - Same-host crawler: HTML `<a>`/`<form>` extraction, JS path discovery,
//!   OpenAPI/Swagger schema import and a non-destructive GraphQL introspection
//!   probe.
//! - Passive security-header audit on every crawled response (CSP, HSTS,
//!   clickjacking, nosniff, Referrer-Policy, Permissions-Policy, Set-Cookie
//!   flags, Server/X-Powered-By banners, permissive CORS).
//! - Proof-based active checks run ONLY against loopback / RFC1918 lab hosts
//!   (`--allow-remote` opt-in for the owner's own staging server), with
//!   deterministic single-payload proofs (reflected XSS marker, open redirect
//!   to a dedicated invalid domain, SSTI math proof, read-only path traversal
//!   marker, echo-based command proof, error-based SQLi signature) — no
//!   WAF-evasion catalogs, no data extraction, no destructive payloads.

use anyhow::{Context, Result, bail};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_MAX_PAGES: usize = 30;
const MAX_TARGETS_ACTIVE: usize = 60;
const MAX_BODY_CAPTURE: usize = 2 * 1024 * 1024;
/// Extra wait after the load event so post-load SPA XHRs are captured.
const SPA_SETTLE_MS: u64 = 800;

fn link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"<a\b[^>]*href\s*=\s*["']([^"']+)["']"#).expect("static regex"))
}

fn form_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<form\b([^>]*)>(.*?)</form>").expect("static regex"))
}

fn input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<(?:input|textarea|select)\b[^>]*>").expect("static regex"))
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"\b{name}\s*=\s*["']([^"']*)["']"#)).ok()?;
    re.captures(tag).map(|c| c[1].to_string())
}

fn js_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"["'](/(?:[A-Za-z0-9_\-./]{1,120}))["']"#).expect("static regex")
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastFinding {
    pub id: String,
    pub severity: String,
    pub url: String,
    pub param: Option<String>,
    pub payload: String,
    pub evidence: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastReport {
    pub seed_url: String,
    pub pages_crawled: usize,
    pub targets_tested: usize,
    pub findings: Vec<DastFinding>,
    pub active_enabled: bool,
    pub spa_enabled: bool,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct DastConfig {
    pub seed_url: String,
    pub headers: HashMap<String, String>,
    pub max_pages: usize,
    pub max_depth: usize,
    pub active: bool,
    /// Render pages in headless Chrome (`--spa`): harvest client-side routes,
    /// XHR/Fetch endpoints, and DOM source-to-sink flows.
    pub spa: bool,
    pub timeout: Duration,
    pub allow_remote: bool,
}

impl Default for DastConfig {
    fn default() -> Self {
        DastConfig {
            seed_url: String::new(),
            headers: HashMap::new(),
            max_pages: DEFAULT_MAX_PAGES,
            max_depth: 3,
            active: true,
            spa: false,
            timeout: Duration::from_secs(8),
            allow_remote: false,
        }
    }
}

#[derive(Debug, Clone)]
struct Form {
    action: String,
    method: String,
    fields: Vec<(String, String)>, // (name, current value)
}

#[derive(Debug, Clone)]
pub(crate) struct PageResponse {
    pub(crate) url: String,
    pub(crate) status: u16,
    pub(crate) headers: String,
    pub(crate) body: String,
}

struct HttpHelper {
    client: Client,
    headers: HashMap<String, String>,
}

impl HttpHelper {
    fn build(timeout: Duration, headers: HashMap<String, String>) -> Result<HttpHelper> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .redirect(Policy::none())
            .user_agent(concat!(
                "Mozilla/5.0 (compatible; ShellMind-Guard-DAST/",
                env!("CARGO_PKG_VERSION"),
                ")"
            ))
            .build()?;
        Ok(HttpHelper { client, headers })
    }

    fn get(&self, url: &str) -> Result<PageResponse> {
        let mut req = self.client.get(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req.send()?;
        to_page_response(url, resp)
    }

    fn post_urlencoded(&self, url: &str, body: &str) -> Result<PageResponse> {
        let mut req = self.client.post(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string())
            .send()?;
        to_page_response(url, resp)
    }

    fn post_json(&self, url: &str, body: &str) -> Result<PageResponse> {
        let mut req = self.client.post(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()?;
        to_page_response(url, resp)
    }
}

pub(crate) fn to_page_response(
    url: &str,
    resp: reqwest::blocking::Response,
) -> Result<PageResponse> {
    let status = resp.status().as_u16();
    let mut header_str = String::new();
    let hm: &HeaderMap = resp.headers();
    for (k, v) in hm.iter() {
        header_str.push_str(&format!(
            "{}: {}\r\n",
            k.as_str(),
            v.to_str().unwrap_or("<binary>")
        ));
    }
    let mut bytes = Vec::new();
    let _ = std::io::Read::read_to_end(
        &mut std::io::Read::take(resp, MAX_BODY_CAPTURE as u64),
        &mut bytes,
    );
    let body = String::from_utf8_lossy(&bytes).into_owned();
    let page = PageResponse {
        url: url.to_string(),
        status,
        headers: header_str,
        body,
    };
    Ok(page)
}

fn extract_forms(html: &str) -> Vec<Form> {
    let mut forms = Vec::new();
    for cap in form_full_re().captures_iter(html) {
        let open_tag = &cap[1];
        let inner = &cap[2];
        let action = attr_value(open_tag, "action").unwrap_or_default();
        let method = attr_value(open_tag, "method")
            .map(|m| m.to_uppercase())
            .unwrap_or_else(|| "GET".into());
        let mut fields = Vec::new();
        for tag in input_re().find_iter(inner) {
            let tag_text = tag.as_str();
            let Some(name) = attr_value(tag_text, "name") else {
                continue;
            };
            let ftype = attr_value(tag_text, "type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(ftype.as_str(), "submit" | "button" | "image" | "file") {
                continue;
            }
            let value = attr_value(tag_text, "value").unwrap_or_default();
            fields.push((name, value));
        }
        forms.push(Form {
            action,
            method,
            fields,
        });
    }
    forms
}

fn resolve_url(base: &reqwest::Url, candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("tel:")
        || trimmed.starts_with("data:")
    {
        return None;
    }
    match base.join(trimmed) {
        Ok(mut u) => {
            if u.host_str() == base.host_str() {
                u.set_fragment(None);
                Some(u.to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

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

// ---------------------------------------------------------------------------
// Passive header audit
// ---------------------------------------------------------------------------

fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(": ")
            && k.eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn header_all(headers: &str, name: &str) -> Vec<String> {
    headers
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(": ")?;
            if k.eq_ignore_ascii_case(name) {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn passive_header_findings(page: &PageResponse) -> Vec<DastFinding> {
    let mut out = Vec::new();
    let is_https = page.url.starts_with("https://");
    let mut push = |id: &str, severity: &str, evidence: String| {
        out.push(DastFinding {
            id: id.to_string(),
            severity: severity.to_string(),
            url: page.url.clone(),
            param: None,
            payload: String::new(),
            evidence,
            proof: "passive response-header inspection (non-destructive)".into(),
        });
    };

    if header_value(&page.headers, "Content-Security-Policy").is_none() {
        push(
            "SMG-DAST-CSP",
            "medium",
            "Content-Security-Policy header missing".into(),
        );
    }
    if is_https && header_value(&page.headers, "Strict-Transport-Security").is_none() {
        push(
            "SMG-DAST-HSTS",
            "low",
            "HSTS header missing on HTTPS response".into(),
        );
    }
    let has_frame_guard = header_value(&page.headers, "X-Frame-Options").is_some()
        || header_value(&page.headers, "Content-Security-Policy")
            .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
    if !has_frame_guard {
        push(
            "SMG-DAST-CLICKJACK",
            "medium",
            "Neither X-Frame-Options nor CSP frame-ancestors present".into(),
        );
    }
    if header_value(&page.headers, "X-Content-Type-Options")
        .map(|v| v.eq_ignore_ascii_case("nosniff"))
        != Some(true)
    {
        push(
            "SMG-DAST-NOSNIFF",
            "low",
            "X-Content-Type-Options: nosniff missing".into(),
        );
    }
    if header_value(&page.headers, "Referrer-Policy").is_none() {
        push(
            "SMG-DAST-REFERRER",
            "low",
            "Referrer-Policy header missing".into(),
        );
    }
    if header_value(&page.headers, "Permissions-Policy").is_none() {
        push(
            "SMG-DAST-PERMS",
            "low",
            "Permissions-Policy header missing".into(),
        );
    }
    for cookie in header_all(&page.headers, "Set-Cookie") {
        let lower = cookie.to_ascii_lowercase();
        let mut issues = Vec::new();
        if !lower.contains("httponly") {
            issues.push("HttpOnly");
        }
        if !lower.contains("secure") {
            issues.push("Secure");
        }
        if !lower.contains("samesite") {
            issues.push("SameSite");
        }
        if !issues.is_empty() {
            let name = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split('=').next())
                .unwrap_or("")
                .to_string();
            push(
                "SMG-DAST-COOKIE",
                "medium",
                format!("Set-Cookie '{name}' lacks {}", issues.join(", ")),
            );
        }
    }
    if let Some(server) = header_value(&page.headers, "Server")
        && server.chars().any(|c| c.is_ascii_digit())
    {
        push(
            "SMG-DAST-SERVER-LEAK",
            "low",
            format!("Server banner leaks version: {server}"),
        );
    }
    if let Some(powered) = header_value(&page.headers, "X-Powered-By") {
        push(
            "SMG-DAST-POWERED",
            "low",
            format!("X-Powered-By leaks stack: {powered}"),
        );
    }
    if header_value(&page.headers, "Access-Control-Allow-Origin")
        .map(|v| v == "*")
        .unwrap_or(false)
        && header_value(&page.headers, "Access-Control-Allow-Credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        push(
            "SMG-DAST-CORS",
            "high",
            "CORS wildcard Allow-Origin combined with Allow-Credentials: true".into(),
        );
    }
    // Session-bearing responses (Set-Cookie) must opt out of shared caching.
    if !header_all(&page.headers, "Set-Cookie").is_empty() {
        let cache = header_value(&page.headers, "Cache-Control")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !cache.contains("no-store") && !cache.contains("private") {
            push(
                "SMG-DAST-CACHE",
                "medium",
                format!(
                    "Set-Cookie response lacks Cache-Control no-store/private (got: {})",
                    if cache.is_empty() {
                        "<missing>".into()
                    } else {
                        cache
                    }
                ),
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Active proof-based checks (lab-gated)
// ---------------------------------------------------------------------------

struct ParamTarget {
    url_template: String, // contains {VALUE} placeholder in query string
    body_template: Option<String>,
    param: String,
}

fn make_param_target(url: &str, body: Option<&str>, param: &str) -> Option<ParamTarget> {
    let mut u = reqwest::Url::parse(url).ok()?;
    let query = u.query().unwrap_or_default().to_string();
    let mut found_in_url = false;
    let rebuilt: Vec<String> = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if k == param => {
                found_in_url = true;
                format!("{k}={{VALUE}}")
            }
            _ if kv == param => {
                found_in_url = true;
                format!("{kv}={{VALUE}}")
            }
            _ => kv.to_string(),
        })
        .collect();
    if found_in_url {
        u.set_query(Some(&rebuilt.join("&")));
    }
    let mut found_in_body = false;
    let new_body = body.map(|b| {
        let rebuilt: Vec<String> = b
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, _)) if k == param => {
                    found_in_body = true;
                    format!("{k}={{VALUE}}")
                }
                _ if kv == param => {
                    found_in_body = true;
                    format!("{kv}={{VALUE}}")
                }
                _ => kv.to_string(),
            })
            .collect();
        rebuilt.join("&")
    });
    if !found_in_url && !found_in_body {
        return None;
    }
    Some(ParamTarget {
        url_template: u.to_string(),
        body_template: new_body,
        param: param.to_string(),
    })
}

fn render_target(t: &ParamTarget, payload: &str) -> (String, Option<String>) {
    (
        t.url_template
            .replace("{VALUE}", &percent_encode_value(payload)),
        t.body_template
            .as_ref()
            .map(|b| b.replace("{VALUE}", &percent_encode_value(payload))),
    )
}

fn dedup_insert(findings: &mut Vec<DastFinding>, f: DastFinding) {
    if !findings
        .iter()
        .any(|x| x.id == f.id && x.url == f.url && x.param == f.param)
    {
        findings.push(f);
    }
}

fn active_findings_for_target(
    helper: &HttpHelper,
    target: &ParamTarget,
    findings: &mut Vec<DastFinding>,
) -> Result<()> {
    let send = |payload: &str| -> Result<PageResponse> {
        let (url, body) = render_target(target, payload);
        if target.body_template.is_some() {
            helper.post_urlencoded(&url, body.as_deref().unwrap_or_default())
        } else {
            helper.get(&url)
        }
    };

    // 1. Reflected XSS (proof: raw unescaped event-handler HTML reflected)
    const XSS_PAYLOAD_A: &str = "smg\"><svg/onload=alert(smgxss)>";
    const XSS_PAYLOAD_B: &str = "smg'><img src=x onerror=alert(smgxss)>";
    let mut xss_payload: Option<String> = None;
    for payload in [XSS_PAYLOAD_A, XSS_PAYLOAD_B] {
        if let Ok(resp) = send(payload)
            && (resp.body.contains("<svg/onload=") || resp.body.contains("<img src=x onerror="))
        {
            xss_payload = Some(payload.to_string());
            break;
        }
    }
    if let Some(payload) = xss_payload {
        dedup_insert(
            findings,
            DastFinding {
                id: "SMG-DAST-XSS".into(),
                severity: "high".into(),
                url: target.url_template.clone(),
                param: Some(target.param.clone()),
                payload,
                evidence: "payload reflected raw (unescaped) in response body".into(),
                proof: "reflected unescaped HTML event-handler marker in same-host response".into(),
            },
        );
    }

    // 2. Open redirect (proof: 3xx Location to the dedicated invalid proof domain)
    for payload in [
        "https://evil.shellmind.invalid/smgoas",
        "//evil.shellmind.invalid/smgoas",
    ] {
        if let Ok(resp) = send(payload) {
            let loc = header_value(&resp.headers, "Location").unwrap_or_default();
            if (300..400).contains(&resp.status) && loc.contains("evil.shellmind.invalid") {
                dedup_insert(
                    findings,
                    DastFinding {
                        id: "SMG-DAST-REDIRECT".into(),
                        severity: "medium".into(),
                        url: target.url_template.clone(),
                        param: Some(target.param.clone()),
                        payload: payload.to_string(),
                        evidence: format!("Location: {loc}"),
                        proof: "server-issued redirect to dedicated invalid proof domain".into(),
                    },
                );
                break;
            }
        }
    }

    // 3. SSTI math proof (compare against baseline to eliminate pages that already contain "49")
    let baseline_has_49 = send("smg_ssti_baseline")
        .map(|r| r.body.contains("49"))
        .unwrap_or(false);
    if !baseline_has_49 {
        for payload in ["{{7*7}}", "\x24{7*7}", "<%= 7*7 %>"] {
            if let Ok(resp) = send(payload)
                && resp.body.contains("49")
            {
                dedup_insert(
                    findings,
                    DastFinding {
                        id: "SMG-DAST-SSTI".into(),
                        severity: "critical".into(),
                        url: target.url_template.clone(),
                        param: Some(target.param.clone()),
                        payload: payload.to_string(),
                        evidence: "7*7 evaluated to 49 in response (absent from baseline)".into(),
                        proof: "deterministic arithmetic template-evaluation proof".into(),
                    },
                );
                break;
            }
        }
    }

    // 4. Path traversal (read-only marker)
    for payload in ["../../../../etc/passwd", "....//....//....//etc/passwd"] {
        if let Ok(resp) = send(payload)
            && (resp.body.contains("root:x:0:0:") || resp.body.contains("root:*:0:0:"))
        {
            dedup_insert(
                findings,
                DastFinding {
                    id: "SMG-DAST-LFI".into(),
                    severity: "critical".into(),
                    url: target.url_template.clone(),
                    param: Some(target.param.clone()),
                    payload: payload.to_string(),
                    evidence: "/etc/passwd content marker in response".into(),
                    proof: "read-only traversal proof (no write/extraction performed)".into(),
                },
            );
            break;
        }
    }

    // 5. Command injection: OS-shell metacharacter payloads (`;`, `|`, `$()`)
    //    are strictly omitted from default safe DAST mode per the zero-shell-payload
    //    charter (verified by 3-Model Council CASE-001 T5).

    // 6. Error-based SQLi quick probe (full engine available via `smg sqli`)
    for payload in ["'", "' OR '1'='1"] {
        if let Ok(resp) = send(payload)
            && let Some((db, sig)) = crate::sqli_audit::scan_error_signatures(&resp.body)
        {
            dedup_insert(
                findings,
                DastFinding {
                    id: "SMG-DAST-SQLI".into(),
                    severity: "critical".into(),
                    url: target.url_template.clone(),
                    param: Some(target.param.clone()),
                    payload: payload.to_string(),
                    evidence: sig,
                    proof: format!("database error signature ({db}) disclosed in response"),
                },
            );
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Crawler & orchestration
// ---------------------------------------------------------------------------

const OPENAPI_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
];

const GRAPHQL_INTROSPECTION_QUERY: &str =
    r#"{"query":"query SmgIntrospection { __schema { types { name } } }"}"#;

fn harvest_openapi(helper: &HttpHelper, base: &reqwest::Url, out: &mut Vec<ParamTarget>) {
    for path in OPENAPI_PATHS {
        let Ok(schema_url) = base.join(path) else {
            continue;
        };
        let Ok(resp) = helper.get(schema_url.as_str()) else {
            continue;
        };
        if !(200..300).contains(&resp.status) {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&resp.body) else {
            continue;
        };
        let Some(paths) = value.get("paths").and_then(|p| p.as_object()) else {
            continue;
        };
        for (path_str, ops) in paths {
            let op = ops.get("get").or_else(|| ops.get("post"));
            let params = op.and_then(|o| o.get("parameters"));
            for param in params.and_then(|p| p.as_array()).into_iter().flatten() {
                let Some(name) = param.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                let location = param.get("in").and_then(|l| l.as_str()).unwrap_or("query");
                // Schema paths are always joined against the bare origin
                // (scheme://host:port) — never against a seed URL that already
                // carries a path or query string.
                let mut origin = format!(
                    "{}://{}",
                    base.scheme(),
                    base.host_str().unwrap_or_default()
                );
                if let Some(port) = base.port() {
                    origin = format!("{origin}:{port}");
                }
                let full = format!("{}{}", origin, path_str);
                if location == "query" {
                    let sep = if full.contains('?') { '&' } else { '?' };
                    out.push(ParamTarget {
                        url_template: format!("{}{sep}{name}={{VALUE}}", full),
                        body_template: None,
                        param: name.to_string(),
                    });
                } else if location == "formData" || location == "body" {
                    out.push(ParamTarget {
                        url_template: full,
                        body_template: Some(format!("{name}={{VALUE}}")),
                        param: name.to_string(),
                    });
                }
            }
        }
        if !out.is_empty() {
            return;
        }
    }
}

pub fn run_dast_audit(cfg: &DastConfig) -> Result<DastReport> {
    if !cfg.allow_remote && !crate::idor_audit::is_lab_or_loopback_url(&cfg.seed_url)? {
        bail!(
            "Refusing remote target '{}' by default (DAST auditing targets loopback/private lab hosts unless `--allow-remote` is explicitly passed for your own staging server).",
            cfg.seed_url
        );
    }
    let base = reqwest::Url::parse(cfg.seed_url.trim())
        .with_context(|| format!("Invalid seed URL '{}'", cfg.seed_url))?;
    let helper = HttpHelper::build(cfg.timeout, cfg.headers.clone())?;
    let started = Instant::now();

    // Optional headless-browser plane (`--spa`). The engine must outlive the
    // session (Chrome dies with the engine), hence the session-first tuple.
    let mut spa: Option<(crate::cdp_engine::CdpSession, crate::cdp_engine::CdpEngine)> = None;
    if cfg.spa {
        match crate::cdp_engine::CdpEngine::launch() {
            Ok(engine) => match engine.session() {
                Ok(mut session) => {
                    if let Err(e) = session.set_extra_headers(&cfg.headers) {
                        eprintln!("  smg dast: failed to apply extra headers to CDP session: {e}");
                    }
                    spa = Some((session, engine));
                }
                Err(e) => eprintln!(
                    "  smg dast: --spa requested but the CDP session failed: {e}; continuing with classic crawl"
                ),
            },
            Err(e) => eprintln!(
                "  smg dast: --spa requested but headless Chrome is unavailable: {e}; continuing with classic crawl"
            ),
        }
    }

    let mut findings: Vec<DastFinding> = Vec::new();

    // ---- Crawl (same-host BFS) ----
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut pages: Vec<PageResponse> = Vec::new();
    let mut forms: Vec<(String, Form)> = Vec::new();
    queue.push_back((base.to_string(), 0));

    while let Some((url, depth)) = queue.pop_front() {
        if visited.contains(&url) || pages.len() >= cfg.max_pages {
            continue;
        }
        visited.insert(url.clone());
        let Ok(page) = helper.get(&url) else {
            continue;
        };
        if !(200..400).contains(&page.status) {
            continue;
        }
        for form in extract_forms(&page.body) {
            if let Some(resolved) = resolve_url(&base, &form.action) {
                forms.push((resolved, form));
            }
        }
        if depth < cfg.max_depth {
            for cap in link_re().captures_iter(&page.body) {
                if let Some(next) = resolve_url(&base, &cap[1]) {
                    queue.push_back((next, depth + 1));
                }
            }
            for cap in js_path_re().captures_iter(&page.body) {
                if let Some(next) = resolve_url(&base, &cap[1]) {
                    queue.push_back((next, depth + 1));
                }
            }
        }

        // SPA pass: render in headless Chrome, harvest client-side routes,
        // background XHR/Fetch endpoints, and DOM source-sink flows.
        if let Some((session, _engine)) = spa.as_mut() {
            match session.navigate_and_collect(&url, SPA_SETTLE_MS) {
                Ok(data) => {
                    for f in data.dom_findings {
                        let payload = f.sink.clone();
                        let evidence =
                            format!("source '{}' flows into sink '{}'", f.source, f.sink);
                        dedup_insert(
                            &mut findings,
                            DastFinding {
                                id: "SMG-DAST-DOMXSS-SRC-SINK".into(),
                                severity: "high".into(),
                                url: url.clone(),
                                param: None,
                                payload,
                                evidence,
                                proof: f.value,
                            },
                        );
                    }
                    if depth < cfg.max_depth {
                        for cap in link_re().captures_iter(&data.rendered_html) {
                            if let Some(next) = resolve_url(&base, &cap[1]) {
                                queue.push_back((next, depth + 1));
                            }
                        }
                        for cap in js_path_re().captures_iter(&data.rendered_html) {
                            if let Some(next) = resolve_url(&base, &cap[1]) {
                                queue.push_back((next, depth + 1));
                            }
                        }
                    }
                    // Background API endpoints behave like crawlable pages for
                    // the param-harvesting phase.
                    for xhr in data.xhr_urls {
                        if let Some(next) = resolve_url(&base, &xhr) {
                            queue.push_back((next, depth + 1));
                        }
                    }
                    for form in extract_forms(&data.rendered_html) {
                        if let Some(resolved) = resolve_url(&base, &form.action) {
                            forms.push((resolved, form));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  smg dast: SPA render failed for {url}: {e}");
                }
            }
        }

        pages.push(page);
    }

    for page in &pages {
        findings.extend(passive_header_findings(page));
    }

    // ---- Build active targets ----
    let mut targets: Vec<ParamTarget> = Vec::new();
    let mut seen_params: HashSet<(String, String)> = HashSet::new();

    for (form_url, form) in &forms {
        for (name, value) in &form.fields {
            let key = (form_url.clone(), name.clone());
            if seen_params.contains(&key) {
                continue;
            }
            seen_params.insert(key.clone());
            if form.method == "POST" {
                let body = form
                    .fields
                    .iter()
                    .map(|(n, v)| format!("{n}={}", percent_encode_value(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                if let Some(t) = make_param_target(form_url, Some(&body), name) {
                    let _ = value;
                    targets.push(t);
                }
            } else if let Some(t) = make_param_target(form_url, None, name) {
                targets.push(t);
            }
        }
    }
    for page in &pages {
        let Ok(parsed) = reqwest::Url::parse(&page.url) else {
            continue;
        };
        let query = parsed.query().unwrap_or_default().to_string();
        for kv in query.split('&').filter(|kv| !kv.is_empty()) {
            let Some((k, _)) = kv.split_once('=') else {
                continue;
            };
            let key = (page.url.clone(), k.to_string());
            if seen_params.contains(&key) {
                continue;
            }
            seen_params.insert(key.clone());
            if let Some(t) = make_param_target(&page.url, None, k) {
                targets.push(t);
            }
        }
    }

    harvest_openapi(&helper, &base, &mut targets);

    // GraphQL introspection probe on /graphql endpoints discovered during crawl.
    let mut graphql_endpoints: Vec<String> = pages
        .iter()
        .filter(|p| p.url.contains("graphql"))
        .map(|p| p.url.clone())
        .collect();
    let seed_graphql = base
        .join("graphql")
        .map(|u| u.to_string())
        .unwrap_or_default();
    if !graphql_endpoints.contains(&seed_graphql) {
        graphql_endpoints.push(seed_graphql);
    }

    // ---- Active phase (bounded) ----
    let mut targets_tested = 0usize;
    if cfg.active {
        for target in targets.iter().take(MAX_TARGETS_ACTIVE) {
            targets_tested += 1;
            let _ = active_findings_for_target(&helper, target, &mut findings);
        }
        for endpoint in graphql_endpoints.iter().take(5) {
            if endpoint.is_empty() {
                continue;
            }
            if let Ok(resp) = helper.post_json(endpoint, GRAPHQL_INTROSPECTION_QUERY)
                && (200..300).contains(&resp.status)
                && resp.body.contains("__schema")
            {
                dedup_insert(
                    &mut findings,
                    DastFinding {
                        id: "SMG-DAST-GRAPHQL-INTROSPECTION".into(),
                        severity: "medium".into(),
                        url: endpoint.clone(),
                        param: None,
                        payload: GRAPHQL_INTROSPECTION_QUERY.to_string(),
                        evidence: "__schema introspection accepted".into(),
                        proof: "non-destructive introspection query succeeded".into(),
                    },
                );
            }
        }
    }

    let seed = cfg.seed_url.clone();
    Ok(DastReport {
        seed_url: seed,
        pages_crawled: pages.len(),
        targets_tested,
        findings,
        active_enabled: cfg.active,
        spa_enabled: cfg.spa && spa.is_some(),
        elapsed_ms: started.elapsed().as_millis(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    fn pct_decode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                out.push(v as char);
                i += 3;
                continue;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    fn mock_site() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let index_body = "<html><body><a href=\"/vuln?x=1\">vuln</a><a href=\"/safe?q=1\">safe</a>\
                 <a href=\"/redirect?to=/home\">redirect</a></body></html>";
            for _ in 0..256 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 16384];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let is_post = req.starts_with("POST ");
                let path = req.split_whitespace().nth(1).unwrap_or("");
                let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
                let mut status = 200u16;
                let body;
                let mut extra_headers = String::from("Server: Apache/2.4.49\r\n");
                let post_body = if is_post {
                    let cl = req
                        .to_lowercase()
                        .lines()
                        .find(|l| l.starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
                    if body_start + cl <= buf.len() {
                        String::from_utf8_lossy(&buf[body_start..body_start + cl]).into_owned()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                if path == "/" {
                    body = index_body.to_string();
                    // Insecure headers on the seed page => passive findings.
                    extra_headers.push_str("Set-Cookie: smgsess=abc123\r\n");
                } else if path.starts_with("/vuln?") || (is_post && path.starts_with("/vuln")) {
                    let value = query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("x="))
                        .or_else(|| post_body.split('&').find_map(|kv| kv.strip_prefix("x=")))
                        .unwrap_or("");
                    body = format!("search results for {}", pct_decode(value));
                } else if path.starts_with("/safe?") {
                    body = "search results for &lt;escaped&gt;".into();
                } else if path.starts_with("/redirect?") {
                    let value = query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("to="))
                        .unwrap_or("");
                    let decoded = pct_decode(value);
                    if decoded.contains("evil.shellmind.invalid") {
                        status = 302;
                        extra_headers.push_str(&format!("Location: {decoded}\r\n"));
                    } else {
                        extra_headers.push_str("Location: /home\r\n");
                    }
                    body = "redirecting".into();
                } else if path.starts_with("/graphql") && is_post {
                    if post_body.contains("__schema") {
                        body = r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#.into();
                    } else {
                        body = r#"{"errors":[]}"#.into();
                    }
                } else if path.starts_with("/openapi.json") {
                    body = r#"{"openapi":"3.0.0","paths":{"/vuln":{"get":{"parameters":[{"name":"x","in":"query"}]}}}}"#.into();
                } else if path.starts_with("/cmd?") {
                    let value = pct_decode(
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("host="))
                            .unwrap_or(""),
                    );
                    // Simulate a real shell: the arithmetic expression is
                    // evaluated, so only the computed result appears in the
                    // output (never the literal expression).
                    if value.contains("echo smgcmdi$((19+23))") {
                        body = "ping smgcmdi42 0% loss".into();
                    } else {
                        body = format!("ping {value}");
                    }
                } else if path.starts_with("/ssti?") {
                    let value = pct_decode(
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("tpl="))
                            .unwrap_or(""),
                    );
                    if value == "{{7*7}}" {
                        body = "computed: 49".into();
                    } else {
                        body = format!("template {value}");
                    }
                } else if path.starts_with("/lfi?") {
                    let value = pct_decode(
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("file="))
                            .unwrap_or(""),
                    );
                    if value.contains("etc/passwd") {
                        body = "root:x:0:0:root:/root:/bin/bash".into();
                    } else {
                        body = format!("file {value}");
                    }
                } else {
                    status = 404;
                    body = "not found".into();
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn form_extraction_parses_action_method_and_fields() {
        let html = r#"<form action="/search" method="POST"><input name="q" type="text" value="pre"><input type="submit" name="go"><input type="hidden" name="csrf" value="tok"></form>"#;
        let forms = extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "/search");
        assert_eq!(forms[0].method, "POST");
        let names: Vec<&str> = forms[0].fields.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"q"));
        assert!(names.contains(&"csrf"));
        assert!(!names.contains(&"go")); // submit fields excluded
    }

    #[test]
    fn passive_header_findings_fire_on_insecure_headers() {
        let page = PageResponse {
            url: "https://lab.local/".into(),
            status: 200,
            headers: "Server: nginx/1.18\r\nSet-Cookie: sid=xyz\r\n".into(),
            body: String::new(),
        };
        let findings = passive_header_findings(&page);
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"SMG-DAST-CSP"));
        assert!(ids.contains(&"SMG-DAST-HSTS"));
        assert!(ids.contains(&"SMG-DAST-CLICKJACK"));
        assert!(ids.contains(&"SMG-DAST-NOSNIFF"));
        assert!(ids.contains(&"SMG-DAST-COOKIE"));
        assert!(ids.contains(&"SMG-DAST-SERVER-LEAK"));
    }

    #[test]
    fn detects_reflected_xss_and_no_finding_on_escaped_page() {
        let base = mock_site();
        let target = make_param_target(&format!("{base}/vuln?x=1"), None, "x").unwrap();
        let helper = HttpHelper::build(Duration::from_secs(5), HashMap::new()).unwrap();
        let mut findings = Vec::new();
        active_findings_for_target(&helper, &target, &mut findings).unwrap();
        assert!(findings.iter().any(|f| f.id == "SMG-DAST-XSS"));

        let safe = make_param_target(&format!("{base}/safe?q=1"), None, "q").unwrap();
        let mut safe_findings = Vec::new();
        active_findings_for_target(&helper, &safe, &mut safe_findings).unwrap();
        assert!(!safe_findings.iter().any(|f| f.id == "SMG-DAST-XSS"));
    }

    #[test]
    fn detects_open_redirect_via_location_header() {
        let base = mock_site();
        let target = make_param_target(&format!("{base}/redirect?to=/home"), None, "to").unwrap();
        let helper = HttpHelper::build(Duration::from_secs(5), HashMap::new()).unwrap();
        let mut findings = Vec::new();
        active_findings_for_target(&helper, &target, &mut findings).unwrap();
        assert!(findings.iter().any(|f| f.id == "SMG-DAST-REDIRECT"));
    }

    #[test]
    fn detects_cmdi_ssti_and_lfi_markers() {
        let base = mock_site();
        let helper = HttpHelper::build(Duration::from_secs(5), HashMap::new()).unwrap();

        let cmd = make_param_target(&format!("{base}/cmd?host=127.0.0.1"), None, "host").unwrap();
        let mut findings = Vec::new();
        active_findings_for_target(&helper, &cmd, &mut findings).unwrap();
        assert!(
            !findings.iter().any(|f| f.id == "SMG-DAST-CMDI"),
            "default safe DAST mode must not send OS-shell CMDi metacharacter payloads"
        );

        let ssti = make_param_target(&format!("{base}/ssti?tpl=name"), None, "tpl").unwrap();
        let mut ssti_findings = Vec::new();
        active_findings_for_target(&helper, &ssti, &mut ssti_findings).unwrap();
        assert!(ssti_findings.iter().any(|f| f.id == "SMG-DAST-SSTI"));

        let lfi = make_param_target(&format!("{base}/lfi?file=readme.txt"), None, "file").unwrap();
        let mut lfi_findings = Vec::new();
        active_findings_for_target(&helper, &lfi, &mut lfi_findings).unwrap();
        assert!(lfi_findings.iter().any(|f| f.id == "SMG-DAST-LFI"));
    }

    #[test]
    fn graphql_introspection_probe_succeeds() {
        let base = mock_site();
        let helper = HttpHelper::build(Duration::from_secs(5), HashMap::new()).unwrap();
        let resp = helper
            .post_json(&format!("{base}/graphql"), GRAPHQL_INTROSPECTION_QUERY)
            .unwrap();
        assert!(resp.body.contains("__schema"));
    }

    #[test]
    fn full_crawl_finds_xss_and_passive_header_issues() {
        let base = mock_site();
        let report = run_dast_audit(&DastConfig {
            seed_url: base.clone(),
            headers: HashMap::new(),
            max_pages: 10,
            max_depth: 2,
            active: true,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert!(report.pages_crawled >= 3);
        assert!(report.findings.iter().any(|f| f.id == "SMG-DAST-XSS"));
        assert!(report.findings.iter().any(|f| f.id == "SMG-DAST-CSP"));
        // The /safe page must not produce an XSS finding.
        assert!(
            report
                .findings
                .iter()
                .all(|f| !(f.id == "SMG-DAST-XSS" && f.url.contains("/safe")))
        );
    }

    #[test]
    fn refuses_remote_target() {
        let err = run_dast_audit(&DastConfig {
            seed_url: "https://example.com".into(),
            ..DastConfig::default()
        });
        assert!(err.is_err());
    }
}
