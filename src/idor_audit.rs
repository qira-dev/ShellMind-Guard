//! Defensive 2-Test-User Authorization / IDOR / BFLA Regression Verifier (`smg idor`).
//!
//! Designed strictly for developer QA & staging access-control regression testing:
//! - Defaults to loopback / RFC1918 lab hosts (`127.0.0.1`, `localhost`, `10.*`, `192.168.*`, `172.16-31.*`)
//!   unless `--allow-remote` is explicitly specified for the owner's own staging server.
//! - Non-destructive read-only differential authorization checks:
//!   1. Verifies `user_a` can access their own resource (HTTP 2xx)
//!   2. Verifies `user_b` (different test account) is DENIED (`401`/`403`/`404`) on `user_a`'s resource
//!   3. Verifies unauthenticated request is DENIED (`401`/`403`)
//!   4. Supports vertical BFLA checks (`admin_only: true` must deny regular `user_b`)

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct IdorTestConfig {
    pub base_url: String,
    #[serde(default)]
    pub user_a_headers: HashMap<String, String>,
    #[serde(default)]
    pub user_b_headers: HashMap<String, String>,
    pub checks: Vec<IdorEndpointCheck>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdorEndpointCheck {
    pub name: String,
    #[serde(default = "default_get")]
    pub method: String,
    pub path: String,
    /// Optional marker substring expected in `user_a`'s own response (e.g. test record ID).
    #[serde(default)]
    pub owner_marker: Option<String>,
    /// If true, tests vertical privilege escalation (BFLA): `user_b` must be denied even without `owner_marker`.
    #[serde(default)]
    pub admin_only: bool,
}

fn default_get() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorCheckOutcome {
    pub name: String,
    pub method: String,
    pub path: String,
    pub user_a_status: u16,
    pub user_b_status: u16,
    pub unauth_status: u16,
    pub verdict: String, // "PASS" | "FAIL_IDOR" | "FAIL_BFLA" | "FAIL_UNAUTH" | "INCONCLUSIVE"
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorAuditReport {
    pub base_url: String,
    pub total_checks: usize,
    pub failures: usize,
    pub outcomes: Vec<IdorCheckOutcome>,
}

pub fn is_lab_or_loopback_url(base_url: &str) -> Result<bool> {
    let parsed = reqwest::Url::parse(base_url)
        .with_context(|| format!("Invalid base_url '{base_url}'"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("base_url is missing host"))?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return Ok(true);
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback(),
        });
    }
    Ok(false)
}

pub fn run_idor_audit(config_path: &Path, allow_remote: bool) -> Result<IdorAuditReport> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("Failed reading IDOR config {}", config_path.display()))?;
    let cfg: IdorTestConfig = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid JSON in {}", config_path.display()))?;
    run_idor_audit_config(&cfg, allow_remote)
}

pub fn run_idor_audit_config(cfg: &IdorTestConfig, allow_remote: bool) -> Result<IdorAuditReport> {
    if !allow_remote && !is_lab_or_loopback_url(&cfg.base_url)? {
        bail!(
            "Refusing remote target '{}' by default (IDOR regression checks target loopback/private lab hosts unless `--allow-remote` is explicitly passed for your own staging server).",
            cfg.base_url
        );
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .user_agent(concat!("ShellMind-Guard/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let base = cfg.base_url.trim_end_matches('/');
    let mut outcomes = Vec::with_capacity(cfg.checks.len());
    let mut failures = 0usize;

    for chk in &cfg.checks {
        let method = reqwest::Method::from_bytes(chk.method.trim().to_ascii_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        // Strictly restrict to non-destructive read methods in automated regression mode
        if !matches!(method, reqwest::Method::GET | reqwest::Method::HEAD | reqwest::Method::OPTIONS) {
            outcomes.push(IdorCheckOutcome {
                name: chk.name.clone(),
                method: chk.method.clone(),
                path: chk.path.clone(),
                user_a_status: 0,
                user_b_status: 0,
                unauth_status: 0,
                verdict: "INCONCLUSIVE".into(),
                detail: "Skipped non-read HTTP method in safe regression mode (GET/HEAD/OPTIONS only).".into(),
            });
            continue;
        }
        let url = format!("{base}/{}", chk.path.trim_start_matches('/'));

        let (st_a, body_a) = send_with_headers(&client, method.clone(), &url, &cfg.user_a_headers)?;
        let (st_b, body_b) = send_with_headers(&client, method.clone(), &url, &cfg.user_b_headers)?;
        let (st_u, body_u) = send_with_headers(&client, method, &url, &HashMap::new())?;

        let marker_leaked_b = chk
            .owner_marker
            .as_deref()
            .map(|m| !m.is_empty() && body_b.contains(m))
            .unwrap_or(true);
        let marker_leaked_u = chk
            .owner_marker
            .as_deref()
            .map(|m| !m.is_empty() && body_u.contains(m))
            .unwrap_or(true);

        let (verdict, detail) = if (200..300).contains(&st_u) && marker_leaked_u {
            failures += 1;
            (
                "FAIL_UNAUTH".to_string(),
                format!("Unauthenticated request returned HTTP {st_u} instead of 401/403"),
            )
        } else if chk.admin_only && (200..300).contains(&st_b) {
            failures += 1;
            (
                "FAIL_BFLA".to_string(),
                format!("Non-admin user_b received HTTP {st_b} on admin-only endpoint"),
            )
        } else if (200..300).contains(&st_a) && (200..300).contains(&st_b) && marker_leaked_b {
            failures += 1;
            (
                "FAIL_IDOR".to_string(),
                format!(
                    "Cross-account access: user_b received HTTP {st_b} on user_a's object (body_a={}B, body_b={}B)",
                    body_a.len(),
                    body_b.len()
                ),
            )
        } else if !(200..300).contains(&st_a) {
            (
                "INCONCLUSIVE".to_string(),
                format!("Owner user_a baseline returned HTTP {st_a} (expected 2xx)"),
            )
        } else {
            (
                "PASS".to_string(),
                format!("Access control enforced (user_a={st_a}, user_b={st_b}, unauth={st_u})"),
            )
        };

        outcomes.push(IdorCheckOutcome {
            name: chk.name.clone(),
            method: chk.method.clone(),
            path: chk.path.clone(),
            user_a_status: st_a,
            user_b_status: st_b,
            unauth_status: st_u,
            verdict,
            detail,
        });
    }

    Ok(IdorAuditReport {
        base_url: cfg.base_url.clone(),
        total_checks: outcomes.len(),
        failures,
        outcomes,
    })
}

fn send_with_headers(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    headers: &HashMap<String, String>,
) -> Result<(u16, String)> {
    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .send()
        .with_context(|| format!("HTTP request failed for {url}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn detects_idor_and_passes_hardened_endpoint_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Handle 6 requests (2 endpoints x 3 identities: user_a, user_b, unauth)
        thread::spawn(move || {
            for _ in 0..6 {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let is_a = req.contains("Bearer token-a");
                let is_b = req.contains("Bearer token-b");
                let (status, body) = if req.starts_with("GET /vuln/order/101 ") {
                    if is_a || is_b {
                        ("200 OK", r#"{"order_id":"ord-101","owner":"alice"}"#)
                    } else {
                        ("401 Unauthorized", r#"{"error":"auth required"}"#)
                    }
                } else if req.starts_with("GET /safe/order/101 ") {
                    if is_a {
                        ("200 OK", r#"{"order_id":"ord-101","owner":"alice"}"#)
                    } else if is_b {
                        ("403 Forbidden", r#"{"error":"forbidden"}"#)
                    } else {
                        ("401 Unauthorized", r#"{"error":"auth required"}"#)
                    }
                } else {
                    ("404 Not Found", "{}")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let mut ua = HashMap::new();
        ua.insert("Authorization".into(), "Bearer token-a".into());
        let mut ub = HashMap::new();
        ub.insert("Authorization".into(), "Bearer token-b".into());

        let cfg = IdorTestConfig {
            base_url: format!("http://{addr}"),
            user_a_headers: ua,
            user_b_headers: ub,
            checks: vec![
                IdorEndpointCheck {
                    name: "vulnerable-order".into(),
                    method: "GET".into(),
                    path: "/vuln/order/101".into(),
                    owner_marker: Some("ord-101".into()),
                    admin_only: false,
                },
                IdorEndpointCheck {
                    name: "hardened-order".into(),
                    method: "GET".into(),
                    path: "/safe/order/101".into(),
                    owner_marker: Some("ord-101".into()),
                    admin_only: false,
                },
            ],
        };

        let report = run_idor_audit_config(&cfg, false).unwrap();
        assert_eq!(report.total_checks, 2);
        assert_eq!(report.failures, 1);
        assert_eq!(report.outcomes[0].verdict, "FAIL_IDOR");
        assert_eq!(report.outcomes[1].verdict, "PASS");
    }

    #[test]
    fn refuses_remote_host_without_explicit_flag() {
        let cfg = IdorTestConfig {
            base_url: "https://example.com".into(),
            user_a_headers: HashMap::new(),
            user_b_headers: HashMap::new(),
            checks: vec![],
        };
        assert!(run_idor_audit_config(&cfg, false).is_err());
    }
}
