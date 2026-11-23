//! Defensive passive HTTP security-posture auditor + static API schema linter
//! (`smg http-audit`).
//!
//! Phase 26 Part B — strictly non-destructive by construction:
//! - At most ONE GET to the target (passive response-header posture: CSP, HSTS,
//!   clickjacking, nosniff, Referrer-Policy, Permissions-Policy, Set-Cookie
//!   flags, Cache-Control, Server/X-Powered-By, CORS) plus passive OpenAPI
//!   schema discovery.
//! - Static schema security linting (OpenAPI 3 / Swagger 2 JSON, GraphQL SDL)
//!   from a local file or a discovered live schema — every finding quotes the
//!   exact spec source, nothing is inferred.
//! - GraphQL introspection is a read-only `__schema` query (never executes
//!   mutations). No active attack payloads of any kind.
//! - Loopback/RFC1918 default; `--allow-remote` opt-in for the owner's own
//!   staging servers.

use anyhow::{Context, Result, bail};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::dast_audit::{DastFinding, PageResponse, passive_header_findings, to_page_response};

const OPENAPI_PROBE_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
];

const GRAPHQL_INTROSPECTION_QUERY: &str =
    r#"{"query":"query SmgHttpAuditIntrospection { __schema { types { name } } }"}"#;

fn sensitive_field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(password|passwd|secret|token|apikey|api_key|accesskey|ssn|creditcard)\w*\s*:",
        )
        .expect("static regex")
    })
}

fn debug_field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(debug|dump|exec|eval|runshell)\w*\s*:").expect("static regex")
    })
}

#[derive(Debug, Clone)]
pub struct HttpAuditConfig {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub schema_file: Option<PathBuf>,
    pub graphql_endpoint: Option<String>,
    /// Render the target in headless Chrome (`--spa`) and report DOM
    /// source-to-sink flows plus background XHR/Fetch endpoints.
    pub spa: bool,
    pub timeout: Duration,
    pub allow_remote: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuditReport {
    pub url: String,
    pub passive_findings: Vec<DastFinding>,
    pub schema_findings: Vec<DastFinding>,
    pub schema_kind: Option<String>,
    pub schema_source: Option<String>,
    pub spa_xhr_endpoints: Vec<String>,
    pub elapsed_ms: u128,
}

fn client_build(timeout: Duration, headers: &HashMap<String, String>) -> Result<Client> {
    crate::idor_audit::ensure_rustls_ring_provider();
    let builder = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(timeout)
        .redirect(Policy::none())
        .user_agent(concat!(
            "Mozilla/5.0 (compatible; ShellMind-Guard-HTTP-Audit/",
            env!("CARGO_PKG_VERSION"),
            ")"
        ));
    let mut default_headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            default_headers.insert(name, val);
        }
    }
    Ok(builder.default_headers(default_headers).build()?)
}

fn fetch_passive(client: &Client, url: &str) -> Result<PageResponse> {
    let resp = client.get(url).send()?;
    to_page_response(url, resp)
}

fn dedup_insert(findings: &mut Vec<DastFinding>, f: DastFinding) {
    if !findings
        .iter()
        .any(|x| x.id == f.id && x.url == f.url && x.param == f.param)
    {
        findings.push(f);
    }
}

// ---------------------------------------------------------------------------
// OpenAPI / Swagger static lints
// ---------------------------------------------------------------------------

pub(crate) fn lint_openapi(value: &serde_json::Value, url: &str) -> Vec<DastFinding> {
    let mut out = Vec::new();
    let mut push = |id: &str, severity: &str, evidence: String| {
        out.push(DastFinding {
            id: id.to_string(),
            severity: severity.to_string(),
            url: url.to_string(),
            param: None,
            payload: String::new(),
            evidence,
            proof: "static OpenAPI/Swagger schema lint (spec-derived, non-destructive)".into(),
        });
    };

    let is_swagger2 = value.get("swagger").and_then(|s| s.as_str()).is_some();
    let is_openapi3 = value.get("openapi").and_then(|s| s.as_str()).is_some();
    if !is_swagger2 && !is_openapi3 {
        return out;
    }

    // Transport: OpenAPI 3 `servers[].url`, Swagger 2 `schemes[]`.
    if is_openapi3 {
        let mut insecure = 0usize;
        let mut examples = Vec::new();
        if let Some(servers) = value.get("servers").and_then(|s| s.as_array()) {
            for server in servers.iter().take(8) {
                if let Some(u) = server.get("url").and_then(|u| u.as_str())
                    && (u.starts_with("http://") || u.starts_with("//"))
                {
                    insecure += 1;
                    if examples.len() < 3 {
                        examples.push(u.to_string());
                    }
                }
            }
        }
        if insecure > 0 {
            push(
                "SMG-OAPI-INSECURE-SERVER",
                "medium",
                format!(
                    "{insecure} declared server(s) use plaintext http:// (e.g. {})",
                    examples.join(", ")
                ),
            );
        }
    } else if is_swagger2 {
        let schemes: Vec<String> = value
            .get("schemes")
            .and_then(|s| s.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        if !schemes.is_empty() && !schemes.iter().any(|s| s == "https") {
            push(
                "SMG-OAPI-INSECURE-SERVER",
                "medium",
                format!(
                    "Swagger `schemes` declares only plaintext transport: {}",
                    schemes.join(", ")
                ),
            );
        }
    }

    // Auth scheme coverage.
    let schemes_node = if is_swagger2 {
        value.get("securityDefinitions")
    } else {
        value
            .get("components")
            .and_then(|c| c.get("securitySchemes"))
    };
    let has_schemes = schemes_node
        .and_then(|s| s.as_object())
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    let has_global_security = value
        .get("security")
        .and_then(|s| s.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !has_schemes && !has_global_security {
        push(
            "SMG-OAPI-NO-AUTH-SCHEME",
            "medium",
            "No securitySchemes/securityDefinitions and no global security requirement declared"
                .into(),
        );
    }

    // Weak scheme choices (only when schemes are declared).
    if let Some(map) = schemes_node.and_then(|s| s.as_object()) {
        for (name, scheme) in map.iter().take(16) {
            let stype = scheme.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let http_scheme = scheme
                .get("scheme")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if stype == "http" && http_scheme == "basic" {
                push(
                    "SMG-OAPI-BASIC-AUTH",
                    "low",
                    format!(
                        "securityScheme '{name}' uses HTTP Basic (no TLS-layer token rotation)"
                    ),
                );
            }
            if stype == "apiKey" && scheme.get("in").and_then(|i| i.as_str()) == Some("query") {
                push(
                    "SMG-OAPI-APIKEY-QUERY",
                    "low",
                    format!(
                        "securityScheme '{name}' passes an apiKey as a URL query parameter (log/referrer leakage)"
                    ),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GraphQL SDL static lints
// ---------------------------------------------------------------------------

pub(crate) fn lint_graphql_sdl(sdl: &str, url: &str) -> Vec<DastFinding> {
    let mut out = Vec::new();
    let mut push = |id: &str, severity: &str, evidence: String| {
        out.push(DastFinding {
            id: id.to_string(),
            severity: severity.to_string(),
            url: url.to_string(),
            param: None,
            payload: String::new(),
            evidence,
            proof: "static GraphQL SDL lint (schema-derived, non-destructive)".into(),
        });
    };

    if !sdl.contains("type Query") && !sdl.contains("type query") {
        push(
            "SMG-GQL-NO-QUERY-ROOT",
            "low",
            "Schema does not declare a `type Query` root (broken/unreadable schema)".into(),
        );
    }
    let mut sensitive: Vec<String> = Vec::new();
    for cap in sensitive_field_re().find_iter(sdl).take(8) {
        let field = cap.as_str().trim_end_matches(':').trim().to_string();
        if !sensitive.contains(&field) {
            sensitive.push(field);
        }
    }
    if !sensitive.is_empty() {
        push(
            "SMG-GQL-SENSITIVE-FIELD",
            "info",
            format!(
                "Sensitive-looking schema field(s) exposed for review: {}",
                sensitive.join(", ")
            ),
        );
    }
    let mut debug: Vec<String> = Vec::new();
    for cap in debug_field_re().find_iter(sdl).take(8) {
        let field = cap.as_str().trim_end_matches(':').trim().to_string();
        if !debug.contains(&field) {
            debug.push(field);
        }
    }
    if !debug.is_empty() {
        push(
            "SMG-GQL-DEBUG-FIELD",
            "medium",
            format!(
                "Debug/dangerous-looking schema field(s): {}",
                debug.join(", ")
            ),
        );
    }
    out
}

fn detect_schema_kind(content: &str) -> Option<&'static str> {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
            && (value.get("openapi").is_some() || value.get("swagger").is_some())
        {
            return Some("openapi");
        }
        return None;
    }
    if content.contains("type Query") || content.contains("schema {") || content.contains("schema{")
    {
        return Some("graphql");
    }
    None
}

fn probe_graphql_introspection(client: &Client, endpoint: &str, findings: &mut Vec<DastFinding>) {
    if let Ok(resp) = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(GRAPHQL_INTROSPECTION_QUERY)
        .send()
    {
        let status = resp.status().as_u16();
        let mut buf = Vec::new();
        let _ =
            std::io::Read::read_to_end(&mut std::io::Read::take(resp, 2 * 1024 * 1024), &mut buf);
        let body = String::from_utf8_lossy(&buf);
        if (200..300).contains(&status) && body.contains("__schema") {
            dedup_insert(
                findings,
                DastFinding {
                    id: "SMG-GQL-INTROSPECTION".into(),
                    severity: "medium".into(),
                    url: endpoint.to_string(),
                    param: None,
                    payload: GRAPHQL_INTROSPECTION_QUERY.to_string(),
                    evidence: "__schema introspection query accepted".into(),
                    proof: "read-only introspection query succeeded (no mutations sent)".into(),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

pub fn run_http_audit(cfg: &HttpAuditConfig) -> Result<HttpAuditReport> {
    let started = Instant::now();
    let offline_only = cfg.url.is_empty();
    if !offline_only {
        let parsed = crate::idor_audit::validate_live_target_url(&cfg.url, cfg.allow_remote)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("HTTP audit requires an http:// or https:// target URL");
        }
    }

    let client = client_build(cfg.timeout, &cfg.headers)?;
    let mut passive: Vec<DastFinding> = Vec::new();
    let mut schema_findings: Vec<DastFinding> = Vec::new();
    let mut schema_kind: Option<String> = None;
    let mut schema_source: Option<String> = None;
    let mut spa_xhr_endpoints: Vec<String> = Vec::new();
    let target_url = cfg.url.clone();

    if !offline_only {
        // 1. Passive posture: exactly one GET.
        let page = fetch_passive(&client, &target_url)?;
        passive.extend(passive_header_findings(&page));

        // 1b. Optional SPA render (`--spa`): JS-executed DOM source-sink
        // flows + background XHR/Fetch endpoints.
        if cfg.spa {
            match crate::cdp_engine::CdpEngine::launch() {
                Ok(engine) => match engine.session() {
                    Ok(mut session) => match session.navigate_and_collect(&target_url, 800) {
                        Ok(data) => {
                            for f in data.dom_findings {
                                let payload = f.sink.clone();
                                let evidence =
                                    format!("source '{}' flows into sink '{}'", f.source, f.sink);
                                dedup_insert(
                                    &mut passive,
                                    DastFinding {
                                        id: "SMG-DAST-DOMXSS-SRC-SINK".into(),
                                        severity: "high".into(),
                                        url: target_url.clone(),
                                        param: None,
                                        payload,
                                        evidence,
                                        proof: f.value,
                                    },
                                );
                            }
                            spa_xhr_endpoints = data.xhr_urls;
                        }
                        Err(e) => {
                            eprintln!("  smg http-audit: SPA render failed: {e}");
                        }
                    },
                    Err(e) => {
                        eprintln!("  smg http-audit: CDP session failed: {e}");
                    }
                },
                Err(e) => {
                    eprintln!("  smg http-audit: headless Chrome unavailable: {e}");
                }
            }
        }

        // 2. Passive OpenAPI discovery on the origin (plain GETs only).
        let parsed = reqwest::Url::parse(&target_url)?;
        for path in OPENAPI_PROBE_PATHS {
            let Ok(schema_url) = parsed.join(path) else {
                continue;
            };
            if schema_url.scheme() != parsed.scheme()
                || schema_url.host_str() != parsed.host_str()
                || schema_url.port_or_known_default() != parsed.port_or_known_default()
                || crate::idor_audit::validate_live_target_url(
                    schema_url.as_str(),
                    cfg.allow_remote,
                )
                .is_err()
            {
                continue;
            }
            let Ok(resp) = client.get(schema_url.as_str()).send() else {
                continue;
            };
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                continue;
            }
            let mut raw = Vec::new();
            let _ = std::io::Read::read_to_end(
                &mut std::io::Read::take(resp, 2 * 1024 * 1024),
                &mut raw,
            );
            let body = String::from_utf8_lossy(&raw).into_owned();
            if detect_schema_kind(&body) == Some("openapi") {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                    schema_findings.extend(lint_openapi(&value, schema_url.as_str()));
                    schema_kind = Some("openapi".into());
                    schema_source = Some(format!("live:{path}"));
                }
                break;
            }
        }

        // 3. Read-only GraphQL introspection probe on the conventional endpoint.
        let gql = cfg
            .graphql_endpoint
            .clone()
            .or_else(|| parsed.join("graphql").ok().map(|u| u.to_string()));
        if let Some(endpoint) = gql {
            crate::idor_audit::validate_live_target_url(&endpoint, cfg.allow_remote)?;
            probe_graphql_introspection(&client, &endpoint, &mut schema_findings);
        }
    }

    // 4. Static schema file linting (no network at all).
    if let Some(path) = &cfg.schema_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed reading schema file {}", path.display()))?;
        match detect_schema_kind(&content) {
            Some("openapi") => {
                let value: serde_json::Value = serde_json::from_str(&content)
                    .with_context(|| format!("Invalid JSON in {}", path.display()))?;
                schema_findings.extend(lint_openapi(
                    &value,
                    &path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                ));
                schema_kind = Some("openapi".into());
            }
            Some("graphql") => {
                schema_findings.extend(lint_graphql_sdl(
                    &content,
                    &path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                ));
                schema_kind = Some("graphql".into());
            }
            _ => bail!(
                "Schema file {} is neither OpenAPI/Swagger JSON nor GraphQL SDL",
                path.display()
            ),
        }
        schema_source = Some(path.display().to_string());
    }

    let url = if offline_only {
        cfg.schema_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    } else {
        target_url
    };
    Ok(HttpAuditReport {
        url,
        passive_findings: passive,
        schema_findings,
        schema_kind,
        schema_source,
        spa_xhr_endpoints,
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

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("smg-httpaudit-{}-{name}", std::process::id()));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn openapi_static_lints_flag_insecure_servers_and_weak_schemes() {
        let spec = r#"{
            "openapi": "3.0.0",
            "servers": [{"url": "http://api.lab.internal"}],
            "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "query", "name": "key"}}},
            "paths": {}
        }"#;
        let value: serde_json::Value = serde_json::from_str(spec).unwrap();
        let findings = lint_openapi(&value, "spec.json");
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"SMG-OAPI-INSECURE-SERVER"));
        assert!(ids.contains(&"SMG-OAPI-APIKEY-QUERY"));
        assert!(!ids.contains(&"SMG-OAPI-NO-AUTH-SCHEME")); // schemes declared
    }

    #[test]
    fn openapi_without_any_security_flagged() {
        let spec = r#"{"openapi": "3.0.0", "servers": [{"url": "https://api.lab.internal"}], "paths": {}}"#;
        let value: serde_json::Value = serde_json::from_str(spec).unwrap();
        let findings = lint_openapi(&value, "spec.json");
        assert!(findings.iter().any(|f| f.id == "SMG-OAPI-NO-AUTH-SCHEME"));
    }

    #[test]
    fn swagger2_https_only_passes_transport_check() {
        let spec = r#"{"swagger": "2.0", "schemes": ["https"], "paths": {}}"#;
        let value: serde_json::Value = serde_json::from_str(spec).unwrap();
        let findings = lint_openapi(&value, "spec.json");
        assert!(!findings.iter().any(|f| f.id == "SMG-OAPI-INSECURE-SERVER"));
    }

    #[test]
    fn graphql_sdl_lints_sensitive_and_debug_fields() {
        let sdl = "schema { query: Query }\n type Query { user(id: ID): User password: String debugDump: String } type User { name: String secretToken: String }";
        let findings = lint_graphql_sdl(sdl, "schema.graphql");
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"SMG-GQL-SENSITIVE-FIELD"));
        assert!(ids.contains(&"SMG-GQL-DEBUG-FIELD"));
        assert!(!ids.contains(&"SMG-GQL-NO-QUERY-ROOT"));
    }

    #[test]
    fn offline_schema_file_lint_requires_no_network() {
        let openapi = temp_file(
            "spec.json",
            r#"{"openapi":"3.0.0","servers":[{"url":"http://api.lab.internal"}],"paths":{}}"#,
        );
        let report = run_http_audit(&HttpAuditConfig {
            url: String::new(),
            headers: HashMap::new(),
            schema_file: Some(openapi.clone()),
            graphql_endpoint: None,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.schema_kind.as_deref(), Some("openapi"));
        assert!(
            report
                .schema_findings
                .iter()
                .any(|f| f.id == "SMG-OAPI-INSECURE-SERVER")
        );

        let sdl = temp_file(
            "schema.graphql",
            "type Query { token: String debugField: String }",
        );
        let report = run_http_audit(&HttpAuditConfig {
            url: String::new(),
            headers: HashMap::new(),
            schema_file: Some(sdl),
            graphql_endpoint: None,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        assert_eq!(report.schema_kind.as_deref(), Some("graphql"));
        assert!(
            report
                .schema_findings
                .iter()
                .any(|f| f.id == "SMG-GQL-DEBUG-FIELD")
        );
        let _ = fs::remove_file(openapi);
    }

    fn mock_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..64 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let is_post = req.starts_with("POST ");
                let path = req.split_whitespace().nth(1).unwrap_or("");
                let status = 200u16;
                let body: String;
                let extra = "Server: lab/1.0\r\nSet-Cookie: sid=abc\r\n";
                if path.starts_with("/openapi.json") {
                    body = r#"{"openapi":"3.0.0","servers":[{"url":"http://api.lab.internal"}],"paths":{}}"#.into();
                } else if path.starts_with("/graphql") && is_post {
                    if req.contains("__schema") {
                        body = r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#.into();
                    } else {
                        body = r#"{"errors":[]}"#.into();
                    }
                } else {
                    body = "<html>lab index</html>".into();
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn live_passive_posture_plus_schema_discovery_and_introspection() {
        let base = mock_server();
        let report = run_http_audit(&HttpAuditConfig {
            url: base.clone(),
            headers: HashMap::new(),
            schema_file: None,
            graphql_endpoint: None,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        })
        .unwrap();
        // Passive posture (shared with dast) incl. the new Cache-Control check.
        let passive_ids: Vec<&str> = report
            .passive_findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert!(passive_ids.contains(&"SMG-DAST-CSP"));
        assert!(passive_ids.contains(&"SMG-DAST-CACHE"));
        assert!(passive_ids.contains(&"SMG-DAST-COOKIE"));
        // Static OpenAPI lint from the discovered live schema.
        assert_eq!(report.schema_kind.as_deref(), Some("openapi"));
        assert!(
            report
                .schema_findings
                .iter()
                .any(|f| f.id == "SMG-OAPI-INSECURE-SERVER")
        );
        // Read-only introspection probe.
        assert!(
            report
                .schema_findings
                .iter()
                .any(|f| f.id == "SMG-GQL-INTROSPECTION")
        );
    }

    #[test]
    fn refuses_remote_target() {
        let err = run_http_audit(&HttpAuditConfig {
            url: "https://example.com".into(),
            headers: HashMap::new(),
            schema_file: None,
            graphql_endpoint: None,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: false,
        });
        assert!(err.is_err());
    }

    #[test]
    fn refuses_imds_even_with_allow_remote() {
        let err = run_http_audit(&HttpAuditConfig {
            url: "http://169.254.169.254/latest/meta-data/".into(),
            headers: HashMap::new(),
            schema_file: None,
            graphql_endpoint: None,
            spa: false,
            timeout: Duration::from_secs(5),
            allow_remote: true,
        });
        assert!(err.is_err());
    }
}
