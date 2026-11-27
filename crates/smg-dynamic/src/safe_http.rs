//! Unified SSRF-safe, DNS-pinned, redirect-revalidating, rate-limited, and bounded HTTP client
//! shared across `smg-dynamic` engines (`Phase 2 / Q92`).

use anyhow::{Context, Result, bail};
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for [`SafeHttpClient`].
#[derive(Debug, Clone)]
pub struct SafeHttpConfig {
    pub allow_remote: bool,
    pub timeout: Duration,
    pub max_body_bytes: usize,
    pub max_redirects: usize,
    pub min_host_interval_ms: u64,
    pub user_agent: String,
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for SafeHttpConfig {
    fn default() -> Self {
        Self {
            allow_remote: false,
            timeout: Duration::from_secs(10),
            max_body_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
            min_host_interval_ms: 0,
            user_agent: format!("ShellMind-Guard/{}", env!("CARGO_PKG_VERSION")),
            cancel: None,
        }
    }
}

/// Captured bounded HTTP response from [`SafeHttpClient`].
#[derive(Debug, Clone)]
pub struct SafeHttpResponse {
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub elapsed_ms: u128,
}

/// Unconditionally denied cloud metadata / link-local / multicast / unspecified addresses
/// (including IPv4-mapped IPv6 `::ffff:169.254.169.254`).
pub fn is_unconditionally_denied_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_denied_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_denied_v4(mapped);
            }
            if let Some(compat) = v6.to_ipv4()
                && !v6.is_loopback()
                && is_denied_v4(compat)
            {
                return true;
            }
            is_denied_v6(v6)
        }
    }
}

fn is_denied_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // 169.254.169.254 (AWS/GCP/Azure IMDS) is already link-local, plus 100.100.100.200 (Alibaba IMDS)
        || (o[0] == 100 && o[1] == 100 && o[2] == 100 && o[3] == 200)
}

fn is_denied_v6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    v6.is_unspecified()
        || v6.is_multicast()
        // Link-local fe80::/10
        || (segs[0] & 0xffc0) == 0xfe80
        // AWS IPv6 IMDS fd00:ec2::254
        || (segs[0] == 0xfd00 && segs[1] == 0x0ec2)
}

/// Returns true for local/private lab targets (loopback, RFC1918, IPv6 ULA/loopback).
pub fn is_private_or_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_private();
            }
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Resolves DNS once, validates EVERY returned IPv4/IPv6 address against the scope policy
/// (unconditionally blocking IMDS, link-local, and IPv4-mapped IPv6 bypasses), and returns
/// the pinned `SocketAddr` list.
pub fn resolve_and_validate_addrs(
    host: &str,
    port: u16,
    allow_remote: bool,
) -> Result<Vec<SocketAddr>> {
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    if clean_host.is_empty() {
        bail!("SafeHttpClient: empty host");
    }
    let addrs: Vec<SocketAddr> = if let Ok(ip) = clean_host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        (clean_host, port)
            .to_socket_addrs()
            .with_context(|| format!("SafeHttpClient: DNS resolution failed for '{clean_host}'"))?
            .collect()
    };
    if addrs.is_empty() {
        bail!("SafeHttpClient: DNS returned no addresses for '{clean_host}'");
    }
    for addr in &addrs {
        let ip = addr.ip();
        if is_unconditionally_denied_ip(ip) {
            bail!(
                "SafeHttpClient blocked denied metadata/link-local address {} for '{}'",
                ip,
                clean_host
            );
        }
        if !allow_remote && !is_private_or_loopback_ip(ip) {
            bail!(
                "SafeHttpClient blocked remote address {} for '{}' (pass --allow-remote to permit external hosts)",
                ip,
                clean_host
            );
        }
    }
    Ok(addrs)
}

/// Unified SSRF-safe HTTP client with DNS pinning, per-hop redirect re-validation,
/// bounded streaming reads, per-host rate limiting, and cooperative cancellation.
pub struct SafeHttpClient {
    cfg: SafeHttpConfig,
    last_hit: Mutex<HashMap<String, Instant>>,
}

impl SafeHttpClient {
    pub fn new(cfg: SafeHttpConfig) -> Self {
        crate::idor_audit::ensure_rustls_ring_provider();
        Self {
            cfg,
            last_hit: Mutex::new(HashMap::new()),
        }
    }

    fn check_cancelled(&self) -> Result<()> {
        if let Some(flag) = &self.cfg.cancel
            && flag.load(Ordering::Relaxed)
        {
            bail!("SafeHttpClient: request cancelled");
        }
        Ok(())
    }

    fn enforce_rate_limit(&self, host_key: &str) {
        if self.cfg.min_host_interval_ms == 0 {
            return;
        }
        let min_gap = Duration::from_millis(self.cfg.min_host_interval_ms);
        let sleep_for = {
            let mut guard = self.last_hit.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if let Some(&prev) = guard.get(host_key) {
                let elapsed = now.saturating_duration_since(prev);
                if elapsed < min_gap {
                    let wait = min_gap - elapsed;
                    guard.insert(host_key.to_string(), now + wait);
                    Some(wait)
                } else {
                    guard.insert(host_key.to_string(), now);
                    None
                }
            } else {
                guard.insert(host_key.to_string(), now);
                None
            }
        };
        if let Some(wait) = sleep_for {
            std::thread::sleep(wait);
        }
    }

    /// Executes an HTTP request with single DNS resolution, IP pinning, per-hop 3xx redirect
    /// re-validation, and bounded streaming body reading.
    pub fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<SafeHttpResponse> {
        let start = Instant::now();
        let mut current_url = reqwest::Url::parse(url)
            .with_context(|| format!("SafeHttpClient: invalid URL '{url}'"))?;
        let mut current_method = method;
        let mut current_body = body.map(|b| b.to_vec());

        for hop in 0..=self.cfg.max_redirects {
            self.check_cancelled()?;
            if !matches!(current_url.scheme(), "http" | "https") {
                bail!(
                    "SafeHttpClient blocked unsupported scheme '{}'",
                    current_url.scheme()
                );
            }
            let host = current_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("SafeHttpClient: URL missing host"))?
                .to_string();
            let port = current_url.port_or_known_default().unwrap_or(80);
            let pinned_addrs = resolve_and_validate_addrs(&host, port, self.cfg.allow_remote)?;
            let pinned = pinned_addrs[0];
            let is_lab = is_private_or_loopback_ip(pinned.ip());

            self.enforce_rate_limit(&format!("{}:{}", host.to_ascii_lowercase(), port));

            let mut builder = Client::builder()
                .timeout(self.cfg.timeout)
                .redirect(Policy::none())
                .user_agent(&self.cfg.user_agent)
                .resolve(&host, pinned);
            if is_lab {
                // smg-ignore: SMG-CFG-TLS (strictly gated on local/loopback lab hosts; remote hosts enforce OS TLS)
                builder = builder.danger_accept_invalid_certs(true);
            }
            let client = builder.build().context("SafeHttpClient: build client")?;

            let mut req = client.request(current_method.clone(), current_url.clone());
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(ref b) = current_body {
                req = req.body(b.clone());
            }

            let mut resp = req
                .send()
                .with_context(|| format!("SafeHttpClient: request to '{}' failed", current_url))?;
            let status = resp.status().as_u16();
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            if matches!(status, 301 | 302 | 303 | 307 | 308)
                && let Some((_, loc)) = resp_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            {
                if hop >= self.cfg.max_redirects {
                    bail!(
                        "SafeHttpClient: exceeded max redirects ({})",
                        self.cfg.max_redirects
                    );
                }
                current_url = current_url.join(loc).with_context(|| {
                    format!("SafeHttpClient: invalid redirect location '{loc}'")
                })?;
                if matches!(status, 301..=303)
                    && !matches!(current_method, Method::GET | Method::HEAD)
                {
                    current_method = Method::GET;
                    current_body = None;
                }
                continue;
            }

            let cap = self.cfg.max_body_bytes;
            let mut buf = Vec::with_capacity(cap.min(64 * 1024));
            let mut limited = (&mut resp).take((cap as u64).saturating_add(1));
            let _ = limited.read_to_end(&mut buf);
            let truncated = buf.len() > cap;
            if truncated {
                buf.truncate(cap);
            }

            return Ok(SafeHttpResponse {
                final_url: current_url.to_string(),
                status,
                headers: resp_headers,
                body: buf,
                truncated,
                elapsed_ms: start.elapsed().as_millis(),
            });
        }

        bail!("SafeHttpClient: redirect loop terminated unexpectedly")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn blocks_imds_and_ipv4_mapped_ipv6_imds() {
        assert!(is_unconditionally_denied_ip(
            "169.254.169.254".parse().unwrap()
        ));
        assert!(is_unconditionally_denied_ip(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(is_unconditionally_denied_ip("fe80::1".parse().unwrap()));
        assert!(is_unconditionally_denied_ip(
            "fd00:ec2::254".parse().unwrap()
        ));
        assert!(resolve_and_validate_addrs("169.254.169.254", 80, true).is_err());
        assert!(resolve_and_validate_addrs("::ffff:169.254.169.254", 80, true).is_err());
    }

    #[test]
    fn blocks_redirect_hop_to_imds_and_bounds_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut req_buf = [0u8; 1024];
                    let n = stream.read(&mut req_buf).unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&req_buf[..n]);
                    if req_str.starts_with("GET /redir") {
                        let _ = stream.write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    } else {
                        let big = "A".repeat(4096);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            big.len(),
                            big
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                }
            }
        });

        let client = SafeHttpClient::new(SafeHttpConfig {
            allow_remote: false,
            max_body_bytes: 256,
            ..Default::default()
        });

        // 1. Redirect to IMDS must be rejected
        let redir_err = client
            .send(Method::GET, &format!("http://{addr}/redir"), &[], None)
            .unwrap_err();
        assert!(
            redir_err.to_string().contains("metadata/link-local"),
            "unexpected error: {redir_err}"
        );

        // 2. Oversized body must be truncated cleanly at max_body_bytes
        let ok = client
            .send(Method::GET, &format!("http://{addr}/big"), &[], None)
            .unwrap();
        assert_eq!(ok.status, 200);
        assert!(ok.truncated);
        assert_eq!(ok.body.len(), 256);

        let _ = handle.join();
    }
}
