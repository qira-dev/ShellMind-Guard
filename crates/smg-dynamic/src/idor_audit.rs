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
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

static RUSTLS_PROVIDER_INIT: Once = Once::new();

/// Ensures the `rustls` ring `CryptoProvider` is installed once process-wide
/// so isolated tests and live-engine invocations never panic with
/// `No rustls crypto provider is configured`.
pub fn ensure_rustls_ring_provider() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
    /// Optional JSON request body for loopback-only `--allow-mutations` checks.
    #[serde(default)]
    pub body: Option<serde_json::Value>,
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

/// Returns true for IP addresses that MUST be unconditionally denied across all
/// live engines, even when `--allow-remote` is explicitly passed:
/// - IPv4 link-local (`169.254.0.0/16`, incl. cloud IMDS `169.254.169.254`)
/// - IPv4 unspecified (`0.0.0.0`)
/// - IPv6 link-local (`fe80::/10`), unspecified (`::`), AWS IPv6 IMDS (`fd00:ec2::254`),
///   and IPv4-mapped IPv6 encodings of forbidden IPv4 addresses.
pub fn is_forbidden_metadata_or_special_ip(ip: IpAddr) -> bool {
    let is_forbidden_v4 = |v4: std::net::Ipv4Addr| {
        v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_multicast()
            || v4.is_broadcast()
            || v4.octets() == [100, 100, 100, 200]
            || v4.octets() == [192, 0, 0, 192]
    };
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                is_forbidden_v4(mapped)
            } else {
                let segs = v6.segments();
                // RFC 6052 Well-Known Prefix 64:ff9b::/96 NAT64 embedded IPv4
                if segs[0..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                    let embedded = std::net::Ipv4Addr::new(
                        (segs[6] >> 8) as u8,
                        (segs[6] & 0xff) as u8,
                        (segs[7] >> 8) as u8,
                        (segs[7] & 0xff) as u8,
                    );
                    if is_forbidden_v4(embedded) {
                        return true;
                    }
                }
                v6.is_unspecified()
                    || v6.is_multicast()
                    || (segs[0] & 0xffc0) == 0xfe80
                    || segs == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
            }
        }
    }
}

/// Returns true only for loopback or RFC1918 private lab IPs (never link-local/IMDS/unspecified).
pub fn is_lab_ip(ip: IpAddr) -> bool {
    if is_forbidden_metadata_or_special_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                !mapped.is_link_local()
                    && !mapped.is_unspecified()
                    && (mapped.is_loopback() || mapped.is_private())
            } else {
                v6.is_loopback()
            }
        }
    }
}

pub fn is_forbidden_metadata_or_special_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if matches!(
        clean.as_str(),
        "metadata.google.internal"
            | "metadata.goog"
            | "metadata.azure.com"
            | "169.254.169.254"
            | "instance-data"
            | "instance-data.ec2.internal"
            | "metadata.tencentyun.com"
            | "metadata.packet.net"
    ) {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return is_forbidden_metadata_or_special_ip(ip);
    }
    false
}

fn is_local_alias_hostname(host: &str) -> bool {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    clean == "localhost" || clean.ends_with(".local")
}

/// Resolves `host:port` and enforces both unconditional IMDS/link-local denial
/// and lab-scope rules (when `!allow_remote`). Returns the validated socket
/// addresses so raw TCP engines can connect directly without a second DNS lookup.
pub fn resolve_and_validate_live_addrs(
    host: &str,
    port: u16,
    allow_remote: bool,
) -> Result<Vec<SocketAddr>> {
    let clean = host.trim().trim_matches(['[', ']']);
    if clean.is_empty() || clean.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("Invalid or empty target host '{host}'");
    }
    if is_forbidden_metadata_or_special_host(clean) {
        bail!(
            "Refusing cloud metadata / link-local / unspecified host '{clean}' (unconditionally denied even with --allow-remote)"
        );
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if is_forbidden_metadata_or_special_ip(ip) {
            bail!(
                "Refusing cloud metadata / link-local / unspecified IP '{ip}' (unconditionally denied even with --allow-remote)"
            );
        }
        if !allow_remote && !is_lab_ip(ip) {
            bail!(
                "Refusing non-lab remote target '{clean}:{port}' (pass --allow-remote for an explicitly owned staging host)"
            );
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let local_alias = is_local_alias_hostname(clean);
    if !allow_remote && !local_alias {
        bail!(
            "Refusing non-lab remote target '{clean}:{port}' (pass --allow-remote for an explicitly owned staging host)"
        );
    }

    let addrs: Vec<SocketAddr> = (clean, port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve target host '{clean}:{port}'"))?
        .collect();
    if addrs.is_empty() {
        bail!("Target host '{clean}:{port}' resolved to no addresses");
    }
    for addr in &addrs {
        if is_forbidden_metadata_or_special_ip(addr.ip()) {
            bail!(
                "Refusing host '{clean}' resolving to forbidden cloud metadata / link-local / unspecified IP '{}'",
                addr.ip()
            );
        }
        if !allow_remote && !is_lab_ip(addr.ip()) {
            bail!(
                "Refusing local host '{clean}' resolving to non-lab IP '{}'",
                addr.ip()
            );
        }
    }
    Ok(addrs)
}

/// Unified unconditional IMDS / link-local / lab-scope guardrail.
/// Even when `allow_remote == true`, cloud metadata & link-local addresses are ALWAYS denied.
pub fn validate_live_target_url(raw_url: &str, allow_remote: bool) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(raw_url.trim())
        .with_context(|| format!("Invalid target URL '{raw_url}'"))?;
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") {
        bail!("Unsupported URL scheme '{}'", parsed.scheme());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("Refusing URL with embedded credentials");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Target URL is missing host"))?;
    if is_forbidden_metadata_or_special_host(host) {
        bail!(
            "Refusing cloud metadata / link-local / unspecified host '{host}' (unconditionally denied even with --allow-remote)"
        );
    }
    let clean = host.trim_matches(['[', ']']);
    let port = parsed.port_or_known_default().unwrap_or(80);
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if is_forbidden_metadata_or_special_ip(ip) {
            bail!(
                "Refusing cloud metadata / link-local / unspecified IP '{ip}' (unconditionally denied even with --allow-remote)"
            );
        }
        if !allow_remote && !is_lab_ip(ip) {
            bail!(
                "Refusing non-lab remote target '{raw_url}' (pass --allow-remote for an explicitly owned staging host)"
            );
        }
        return Ok(parsed);
    }

    if is_local_alias_hostname(clean) {
        // Fail closed on DNS failure or forbidden/non-lab resolution for localhost / *.local.
        let _ = resolve_and_validate_live_addrs(clean, port, allow_remote)?;
        return Ok(parsed);
    }

    if !allow_remote {
        bail!(
            "Refusing non-lab remote target '{raw_url}' (pass --allow-remote for an explicitly owned staging host)"
        );
    }

    // Even when `allow_remote == true`, if DNS resolves the hostname to any
    // cloud metadata / link-local / unspecified address, unconditionally deny.
    if let Ok(addrs) = (clean, port).to_socket_addrs() {
        for addr in addrs {
            if is_forbidden_metadata_or_special_ip(addr.ip()) {
                bail!(
                    "Refusing host '{clean}' resolving to forbidden cloud metadata / link-local / unspecified IP '{}'",
                    addr.ip()
                );
            }
        }
    }
    Ok(parsed)
}

/// Resolves `raw_url` fail-closed and returns `(parsed_url, clean_dns_host_opt, pinned_addrs)`
/// so live HTTP `reqwest::blocking::Client` builders can pin `.resolve_to_addrs(...)`
/// and completely eliminate DNS-rebinding TOCTOU.
pub fn resolve_and_pin_live_target_url(
    raw_url: &str,
    allow_remote: bool,
) -> Result<(reqwest::Url, Option<String>, Vec<SocketAddr>)> {
    let parsed = validate_live_target_url(raw_url, allow_remote)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Target URL is missing host"))?;
    let clean = host.trim_matches(['[', ']']);
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs = resolve_and_validate_live_addrs(clean, port, allow_remote)?;
    let dns_host = if clean.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(clean.to_string())
    };
    Ok((parsed, dns_host, addrs))
}

fn looks_like_html_or_error_envelope(body: &str) -> bool {
    let t = body.trim();
    if t.is_empty() {
        return true;
    }
    let low = t.to_ascii_lowercase();
    if low.starts_with("<!doctype html") || low.starts_with("<html") {
        return true;
    }
    if t.starts_with('{')
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(t)
        && let Some(obj) = val.as_object()
    {
        if obj.get("ok").and_then(|v| v.as_bool()) == Some(false)
            || obj.get("success").and_then(|v| v.as_bool()) == Some(false)
        {
            return true;
        }
        if obj.len() <= 3
            && (obj.contains_key("error") || obj.contains_key("errors"))
            && !obj.contains_key("data")
            && !obj.contains_key("id")
        {
            return true;
        }
    }
    false
}

pub fn is_strictly_loopback_url(base_url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if is_forbidden_metadata_or_special_host(host) {
        return false;
    }
    let clean = host.trim_matches(['[', ']']);
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    if clean.eq_ignore_ascii_case("localhost") {
        let port = parsed.port_or_known_default().unwrap_or(80);
        let Ok(addrs) = (clean, port).to_socket_addrs() else {
            return false;
        };
        let list: Vec<SocketAddr> = addrs.collect();
        return !list.is_empty() && list.iter().all(|a| a.ip().is_loopback());
    }
    false
}

pub fn run_idor_audit_with_options(
    config_path: &Path,
    allow_remote: bool,
    allow_mutations: bool,
) -> Result<IdorAuditReport> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("Failed reading IDOR config {}", config_path.display()))?;
    let cfg: IdorTestConfig = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid JSON in {}", config_path.display()))?;
    run_idor_audit_config_with_options(&cfg, allow_remote, allow_mutations)
}

#[cfg(test)]
pub fn run_idor_audit_config(cfg: &IdorTestConfig, allow_remote: bool) -> Result<IdorAuditReport> {
    run_idor_audit_config_with_options(cfg, allow_remote, false)
}

pub fn run_idor_audit_config_with_options(
    cfg: &IdorTestConfig,
    allow_remote: bool,
    allow_mutations: bool,
) -> Result<IdorAuditReport> {
    let (base_parsed, pinned_host, pinned_addrs) =
        resolve_and_pin_live_target_url(&cfg.base_url, allow_remote)?;
    if !matches!(base_parsed.scheme(), "http" | "https") {
        bail!("IDOR audit requires http:// or https:// base_url");
    }
    if allow_mutations && !is_strictly_loopback_url(&cfg.base_url) {
        bail!(
            "Refusing `--allow-mutations` against non-loopback target '{}' (mutating IDOR/BOLA checks are strictly restricted to 127.0.0.1 / ::1 / localhost).",
            cfg.base_url
        );
    }
    if !cfg.checks.is_empty()
        && !cfg.user_a_headers.is_empty()
        && cfg.user_a_headers == cfg.user_b_headers
    {
        bail!(
            "IDOR config must define two distinct authenticated test principals (`user_a_headers` and `user_b_headers` are identical)"
        );
    }

    ensure_rustls_ring_provider();
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .user_agent(concat!("ShellMind-Guard/", env!("CARGO_PKG_VERSION")));
    if let Some(ref host_name) = pinned_host {
        builder = builder.resolve_to_addrs(host_name, &pinned_addrs);
    }
    let client = builder.build()?;

    let base = cfg.base_url.trim_end_matches('/');
    let mut outcomes = Vec::with_capacity(cfg.checks.len());
    let mut failures = 0usize;

    for chk in &cfg.checks {
        let method = reqwest::Method::from_bytes(chk.method.trim().to_ascii_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        // Strictly restrict to read methods unless `--allow-mutations` was explicitly passed on loopback
        let is_read = matches!(
            method,
            reqwest::Method::GET | reqwest::Method::HEAD | reqwest::Method::OPTIONS
        );
        let is_allowed_mutation = allow_mutations
            && matches!(
                method,
                reqwest::Method::POST
                    | reqwest::Method::PUT
                    | reqwest::Method::PATCH
                    | reqwest::Method::DELETE
            );
        if !is_read && !is_allowed_mutation {
            outcomes.push(IdorCheckOutcome {
                name: chk.name.clone(),
                method: chk.method.clone(),
                path: chk.path.clone(),
                user_a_status: 0,
                user_b_status: 0,
                unauth_status: 0,
                verdict: "INCONCLUSIVE".into(),
                detail:
                    "Skipped non-read HTTP method in safe regression mode (pass `--allow-mutations` on localhost to test POST/PUT/PATCH/DELETE)."
                        .into(),
            });
            continue;
        }
        let clean_path = chk.path.trim_start_matches('/');
        let url = format!("{base}/{clean_path}");
        let parsed_check = validate_live_target_url(&url, allow_remote)?;
        if parsed_check.scheme() != base_parsed.scheme()
            || parsed_check.host_str() != base_parsed.host_str()
            || parsed_check.port_or_known_default() != base_parsed.port_or_known_default()
        {
            bail!(
                "Refusing IDOR check '{}' whose resolved URL '{}' leaves base_url origin",
                chk.name,
                parsed_check
            );
        }

        let (st_a, body_a) = send_with_headers(
            &client,
            method.clone(),
            &url,
            &cfg.user_a_headers,
            chk.body.as_ref(),
        )?;
        let (st_b, body_b) = send_with_headers(
            &client,
            method.clone(),
            &url,
            &cfg.user_b_headers,
            chk.body.as_ref(),
        )?;
        let (st_u, body_u) =
            send_with_headers(&client, method, &url, &HashMap::new(), chk.body.as_ref())?;

        let configured_marker = chk
            .owner_marker
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty());
        let owner_marker_present_a = configured_marker
            .map(|m| body_a.contains(m))
            .unwrap_or_else(|| !looks_like_html_or_error_envelope(&body_a));
        let marker_leaked_b = configured_marker
            .map(|m| body_b.contains(m))
            .unwrap_or_else(|| !looks_like_html_or_error_envelope(&body_b));
        let marker_leaked_u = configured_marker
            .map(|m| body_u.contains(m))
            .unwrap_or_else(|| !looks_like_html_or_error_envelope(&body_u));

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
        } else if !owner_marker_present_a {
            (
                "INCONCLUSIVE".to_string(),
                "Owner user_a 2xx baseline response did not contain configured owner_marker"
                    .to_string(),
            )
        } else if st_b >= 500 || st_u >= 500 {
            (
                "INCONCLUSIVE".to_string(),
                format!(
                    "Server error during authorization probe (user_b={st_b}, unauth={st_u}); cannot certify PASS"
                ),
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
    body: Option<&serde_json::Value>,
) -> Result<(u16, String)> {
    let mut req = client.request(method, url);
    if let Some(json_body) = body {
        req = req.json(json_body);
    }
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .send()
        .with_context(|| format!("HTTP request failed for {url}"))?;
    let status = resp.status().as_u16();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(resp, 2 * 1024 * 1024), &mut buf)
        .with_context(|| format!("Failed reading HTTP response body from {url}"))?;
    let body = String::from_utf8_lossy(&buf).into_owned();
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
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
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
                    body: None,
                    admin_only: false,
                },
                IdorEndpointCheck {
                    name: "hardened-order".into(),
                    method: "GET".into(),
                    path: "/safe/order/101".into(),
                    owner_marker: Some("ord-101".into()),
                    body: None,
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

    #[test]
    fn unconditionally_denies_imds_and_link_local_even_with_allow_remote() {
        let forbidden = [
            "http://169.254.169.254/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[fe80::1]/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fd00:0ec2:0:0:0:0:0:254]/latest/meta-data/",
            "http://0.0.0.0/",
            "http://[::]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal./computeMetadata/v1/",
            "https://metadata.azure.com/metadata/instance",
            "http://user:pass@127.0.0.1:8080/",
            "file:///etc/passwd",
        ];
        for url in forbidden {
            assert!(
                validate_live_target_url(url, true).is_err(),
                "must deny {url} even with allow_remote=true"
            );
            assert!(
                validate_live_target_url(url, false).is_err(),
                "must deny {url} with allow_remote=false"
            );
        }
        assert!(validate_live_target_url("http://127.0.0.1:8080/api", false).is_ok());
        assert!(validate_live_target_url("http://[::1]:8080/api", false).is_ok());

        // IDOR audit must also deny IMDS even when allow_remote == true
        let cfg = IdorTestConfig {
            base_url: "http://169.254.169.254".into(),
            user_a_headers: HashMap::new(),
            user_b_headers: HashMap::new(),
            checks: vec![],
        };
        assert!(run_idor_audit_config(&cfg, true).is_err());
    }
}
