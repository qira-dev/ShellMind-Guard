use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Barrier, Notify};
use tokio::task::JoinSet;
use tokio::time::timeout;
use vf_graph::{GuardKind, LatticeFinding};

const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Proven,
    Mitigated,
    SuspectUnverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub entry_route: String,
    pub status: VerificationStatus,
    pub evidence: String,
    pub replay_cmd: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxProbeConfig {
    #[serde(default)]
    pub user_a_header: Option<String>,
    #[serde(default)]
    pub user_b_header: Option<String>,
    #[serde(default)]
    pub probe_body: Option<String>,
}

fn format_optional_header(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    let (name, value) = raw.split_once(':')?;
    let clean_name: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let clean_val: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let clean_val = clean_val.trim();
    if clean_name.is_empty() || clean_val.is_empty() {
        return None;
    }
    Some(format!("{}: {}\r\n", clean_name, clean_val))
}

async fn send_http_probe(
    port: u16,
    method: &str,
    path: &str,
    extra_header: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String, bool)> {
    let hdr_line = format_optional_header(extra_header).unwrap_or_default();
    let req = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr_line}Connection: close\r\n\r\n"
        )
    };
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", port))).await??;
    timeout(IO_TIMEOUT, stream.write_all(req.as_bytes())).await??;
    Ok(read_http_bounded(&mut stream)
        .await
        .unwrap_or((0, String::new(), false)))
}

fn parse_route(entry: &str) -> (&str, &str) {
    let mut parts = entry.split_whitespace();
    let method = parts.next().unwrap_or("POST");
    let path = parts.next().unwrap_or("/");
    (method, path)
}

fn extract_http_status(resp: &str) -> u16 {
    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().ok();
        }
    }
    None
}

fn is_chunked_encoding(headers: &str) -> bool {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            return true;
        }
    }
    false
}

fn decode_chunked_body(raw_body: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(raw_body.len());
    let mut rest = raw_body;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        let size_line = std::str::from_utf8(&rest[..pos]).unwrap_or("");
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        if chunk_len == 0 {
            break;
        }
        let after_size = &rest[pos + 2..];
        if after_size.len() < chunk_len {
            out.extend_from_slice(after_size);
            break;
        }
        out.extend_from_slice(&after_size[..chunk_len]);
        rest = &after_size[chunk_len..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    if out.is_empty() {
        String::from_utf8_lossy(raw_body).to_string()
    } else {
        String::from_utf8_lossy(&out).to_string()
    }
}

/// Reads an HTTP response with strict timeout and 256 KiB cap, decoding `Transfer-Encoding: chunked`
/// and stopping immediately once `Content-Length` or `0\r\n\r\n` arrives.
async fn read_http_bounded(stream: &mut TcpStream) -> Result<(u16, String, bool)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut expected_total: Option<usize> = None;
    let mut chunked = false;

    let res = timeout(IO_TIMEOUT, async {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            let take = n.min(MAX_HTTP_BODY_BYTES.saturating_sub(buf.len()));
            buf.extend_from_slice(&tmp[..take]);
            let s = String::from_utf8_lossy(&buf);
            if expected_total.is_none()
                && !chunked
                && let Some(hdr_end) = s.find("\r\n\r\n")
            {
                let hdrs = &s[..hdr_end];
                chunked = is_chunked_encoding(hdrs);
                if !chunked && let Some(cl) = parse_content_length(hdrs) {
                    expected_total = Some(hdr_end + 4 + cl.min(MAX_HTTP_BODY_BYTES));
                }
            }
            if chunked && let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let body_bytes = &buf[hdr_end + 4..];
                if body_bytes.starts_with(b"0\r\n\r\n")
                    || body_bytes.windows(7).any(|w| w == b"\r\n0\r\n\r\n")
                {
                    break;
                }
            }
            if let Some(tot) = expected_total
                && buf.len() >= tot
            {
                break;
            }
            if buf.len() >= MAX_HTTP_BODY_BYTES {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;

    let hdr_split = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (hdr_bytes, body_bytes) = match hdr_split {
        Some(pos) => (&buf[..pos], &buf[pos + 4..]),
        None => (&buf[..], &[][..]),
    };
    let hdrs = String::from_utf8_lossy(hdr_bytes);
    let status = extract_http_status(&hdrs);
    let is_html = hdrs.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("content-type:")
            && l.to_ascii_lowercase().contains("text/html")
    });
    let decoded = if is_chunked_encoding(&hdrs) {
        decode_chunked_body(body_bytes)
    } else {
        String::from_utf8_lossy(body_bytes).to_string()
    };
    if res.is_err() && status == 0 {
        anyhow::bail!("Timed out reading HTTP response");
    }
    Ok((status, decoded.trim().to_string(), is_html))
}

fn is_failure_envelope(status: u16, body: &str) -> bool {
    if status == 204 || body.is_empty() {
        return true;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
            return true;
        }
        if v.get("success").and_then(|b| b.as_bool()) == Some(false) {
            return true;
        }
        if let Some(code_num) = v
            .get("statusCode")
            .or_else(|| v.get("status_code"))
            .or_else(|| v.get("code"))
            .and_then(|c| c.as_u64())
            && (400..600).contains(&code_num)
        {
            return true;
        }
        if let Some(st) = v.get("status").and_then(|s| s.as_str())
            && matches!(
                st.to_ascii_lowercase().as_str(),
                "error" | "duplicate" | "rejected" | "failed"
            )
        {
            return true;
        }
        if let Some(errs) = v.get("errors").and_then(|e| e.as_array())
            && !errs.is_empty()
        {
            return true;
        }
        if let Some(err) = v.get("error")
            && !err.is_null()
            && v.get("ok").and_then(|b| b.as_bool()) != Some(true)
        {
            return true;
        }
    }
    false
}

fn substitute_route_params(path: &str) -> String {
    let joined = path
        .split('/')
        .map(|seg| {
            if seg.starts_with(':')
                || (seg.starts_with('{') && seg.ends_with('}'))
                || (seg.starts_with('[') && seg.ends_with(']'))
                || (seg.starts_with('<') && seg.ends_with('>'))
                || seg == "*"
            {
                "1"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let sanitized: String = joined
        .chars()
        .filter(|c| !c.is_control() && *c != ' ')
        .collect();
    if sanitized.starts_with('/') {
        sanitized
    } else {
        format!("/{}", sanitized)
    }
}

fn shell_quote_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Checks whether an unauthenticated request to the flagged route is blocked (401/403)
/// or actually executes a non-error payload inside the isolated loopback sandbox.
pub async fn verify_auth_invariant(port: u16, finding: &LatticeFinding) -> Result<VerifiedFinding> {
    verify_auth_invariant_with_config(port, finding, &SandboxProbeConfig::default()).await
}

pub async fn verify_auth_invariant_with_config(
    port: u16,
    finding: &LatticeFinding,
    cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    let (method, raw_path) = parse_route(&finding.entry_route);
    let path = substitute_route_params(raw_path);
    let default_body = r#"{"userId":"test-user-1","amount":10}"#;
    let body = cfg.probe_body.as_deref().unwrap_or(default_body);
    let (status_code, resp_body, is_html) =
        send_http_probe(port, method, &path, None, Some(body)).await?;

    let (status, evidence) = if status_code == 401 || status_code == 403 {
        (
            VerificationStatus::Mitigated,
            format!("Blocked by runtime guard with HTTP {}", status_code),
        )
    } else if (200..300).contains(&status_code)
        && !is_html
        && !is_failure_envelope(status_code, &resp_body)
    {
        (
            VerificationStatus::Proven,
            format!(
                "Unauthenticated request executed with HTTP {} (payload: {})",
                status_code,
                resp_body.chars().take(120).collect::<String>()
            ),
        )
    } else if (200..300).contains(&status_code) {
        (
            VerificationStatus::SuspectUnverified,
            format!(
                "HTTP {} returned empty/HTML/failure envelope ({}); cannot prove mutation",
                status_code,
                resp_body.chars().take(80).collect::<String>()
            ),
        )
    } else {
        (
            VerificationStatus::SuspectUnverified,
            format!("Server returned HTTP {} (inconclusive)", status_code),
        )
    };

    let url = format!("http://127.0.0.1:{}{}", port, path);
    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!(
            "curl -i -X {} {} -H 'Content-Type: application/json' -d {}",
            shell_quote_single(method),
            shell_quote_single(&url),
            shell_quote_single(body)
        ),
    })
}

/// Cancel-safe Last-Byte Sync concurrency test:
/// Buffers N identical requests minus the final byte, aligns them on a `tokio::sync::Barrier`
/// inside a `JoinSet`, and cancels cleanly via `Notify` on any pre-barrier I/O error.
pub async fn verify_concurrency_invariant(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    verify_concurrency_invariant_with_config(
        port,
        finding,
        concurrency,
        &SandboxProbeConfig::default(),
    )
    .await
}

pub async fn verify_concurrency_invariant_with_config(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
    cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    if concurrency == 0 {
        return Ok(VerifiedFinding {
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            entry_route: finding.entry_route.clone(),
            status: VerificationStatus::SuspectUnverified,
            evidence: "Concurrency set to 0; no requests dispatched".into(),
            replay_cmd: format!("shellmind-guard replay {} --sync-race 12", finding.id),
        });
    }

    let (method, raw_path) = parse_route(&finding.entry_route);
    let path = substitute_route_params(raw_path);
    let body = cfg
        .probe_body
        .as_deref()
        .unwrap_or(r#"{"userId":"test-user-1","amount":80}"#);
    let auth_hdr = format_optional_header(cfg.user_a_header.as_deref()).unwrap_or_default();
    let raw_req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let bytes = raw_req.into_bytes();
    let split_at = bytes.len().saturating_sub(1);
    let prefix = Arc::new(bytes[..split_at].to_vec());
    let last_byte = bytes[split_at];

    let barrier = Arc::new(Barrier::new(concurrency));
    let abort = Arc::new(Notify::new());
    let aborted = Arc::new(AtomicBool::new(false));
    let failed_count = Arc::new(AtomicUsize::new(0));
    let mut set = JoinSet::new();

    for _ in 0..concurrency {
        let pfx = Arc::clone(&prefix);
        let bar = Arc::clone(&barrier);
        let abt = Arc::clone(&abort);
        let abtd = Arc::clone(&aborted);
        let failed = Arc::clone(&failed_count);
        set.spawn(async move {
            let conn = timeout(
                Duration::from_secs(2),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await;
            let mut stream = match conn {
                Ok(Ok(s)) => s,
                _ => {
                    failed.fetch_add(1, Ordering::SeqCst);
                    abtd.store(true, Ordering::SeqCst);
                    abt.notify_waiters();
                    return None;
                }
            };
            let _ = stream.set_nodelay(true);
            if timeout(Duration::from_secs(2), stream.write_all(&pfx))
                .await
                .is_err()
                || stream.flush().await.is_err()
            {
                failed.fetch_add(1, Ordering::SeqCst);
                abtd.store(true, Ordering::SeqCst);
                abt.notify_waiters();
                return None;
            }

            let released = tokio::select! {
                _ = bar.wait() => true,
                _ = abt.notified() => false,
                _ = tokio::time::sleep(Duration::from_millis(2500)) => false,
            };
            if !released || abtd.load(Ordering::SeqCst) {
                return None;
            }

            if timeout(Duration::from_secs(2), stream.write_all(&[last_byte]))
                .await
                .is_err()
                || stream.flush().await.is_err()
            {
                return None;
            }

            read_http_bounded(&mut stream).await.ok()
        });
    }

    let mut valid_2xx = 0usize;
    let mut blocked = 0usize;
    let mut first_2xx_code: Option<u16> = None;
    let mut distinct_bodies: HashSet<String> = HashSet::new();

    while let Some(joined) = set.join_next().await {
        if let Ok(Some((code, resp_body, is_html))) = joined {
            if (200..300).contains(&code)
                && !is_html
                && !is_failure_envelope(code, &resp_body)
                && !matches!(code, 409 | 429 | 400)
            {
                valid_2xx += 1;
                if first_2xx_code.is_none() {
                    first_2xx_code = Some(code);
                }
                distinct_bodies.insert(resp_body);
            } else if code > 0 {
                blocked += 1;
            }
        }
    }

    let pre_failed = failed_count.load(Ordering::SeqCst);
    let (status, evidence) = if pre_failed > 0 && valid_2xx == 0 && blocked == 0 {
        (
            VerificationStatus::SuspectUnverified,
            format!(
                "Aborted Last-Byte Sync cleanly: {} pre-barrier worker error(s) without deadlock",
                pre_failed
            ),
        )
    } else if valid_2xx >= 2 {
        (
            VerificationStatus::Proven,
            format!(
                "{}/{} concurrent requests returned HTTP {} (Last-Byte Sync, {} distinct bodies)",
                valid_2xx,
                concurrency,
                first_2xx_code.unwrap_or(200),
                distinct_bodies.len()
            ),
        )
    } else if valid_2xx == 1 && blocked > 0 {
        (
            VerificationStatus::Mitigated,
            format!(
                "Last-Byte Sync ({}x): only 1x succeeded, {}x blocked by lock/idempotency guard",
                concurrency, blocked
            ),
        )
    } else {
        (
            VerificationStatus::SuspectUnverified,
            format!(
                "Last-Byte Sync ({}x): {}x 2xx, {}x non-2xx (inconclusive)",
                concurrency, valid_2xx, blocked
            ),
        )
    };

    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!(
            "shellmind-guard replay {} --sync-race {}",
            finding.id, concurrency
        ),
    })
}

/// Cross-tenant IDOR probe: replays User A's resource route as User B and fails-closed
/// if `[sandbox]` credentials are omitted or baseline User A fails.
pub async fn verify_idor_invariant_with_config(
    port: u16,
    finding: &LatticeFinding,
    cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    let (method, raw_path) = parse_route(&finding.entry_route);
    let path = substitute_route_params(raw_path);
    let url = format!("http://127.0.0.1:{}{}", port, path);

    let (Some(hdr_a), Some(hdr_b)) = (
        cfg.user_a_header
            .as_deref()
            .filter(|s| format_optional_header(Some(s)).is_some()),
        cfg.user_b_header
            .as_deref()
            .filter(|s| format_optional_header(Some(s)).is_some()),
    ) else {
        return Ok(VerifiedFinding {
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            entry_route: finding.entry_route.clone(),
            status: VerificationStatus::SuspectUnverified,
            evidence: "IDOR live probe skipped: configure [sandbox] user_a_header and user_b_header in .shellmind-guard.toml".into(),
            replay_cmd: format!("shellmind-guard replay {}", finding.id),
        });
    };

    let req_body = if matches!(method, "GET" | "HEAD" | "DELETE") {
        cfg.probe_body.as_deref()
    } else {
        Some(
            cfg.probe_body
                .as_deref()
                .unwrap_or(r#"{"status":"updated"}"#),
        )
    };

    let (code_a, body_a, html_a) =
        send_http_probe(port, method, &path, Some(hdr_a), req_body).await?;
    if !(200..300).contains(&code_a) || html_a || is_failure_envelope(code_a, &body_a) {
        return Ok(VerifiedFinding {
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            entry_route: finding.entry_route.clone(),
            status: VerificationStatus::SuspectUnverified,
            evidence: format!(
                "IDOR baseline User A returned HTTP {} ({}); cannot confirm cross-tenant bypass",
                code_a,
                body_a.chars().take(80).collect::<String>()
            ),
            replay_cmd: format!(
                "curl -i -X {} {} -H {}",
                shell_quote_single(method),
                shell_quote_single(&url),
                shell_quote_single(hdr_b.trim())
            ),
        });
    }

    let (code_b, body_b, html_b) =
        send_http_probe(port, method, &path, Some(hdr_b), req_body).await?;
    let (status, evidence) = if matches!(code_b, 401 | 403 | 404)
        || is_failure_envelope(code_b, &body_b)
    {
        (
            VerificationStatus::Mitigated,
            format!(
                "IDOR Mitigated: User A succeeded (HTTP {}) while cross-tenant User B was blocked (HTTP {})",
                code_a, code_b
            ),
        )
    } else if (200..300).contains(&code_b) && !html_b {
        (
            VerificationStatus::Proven,
            format!(
                "Cross-tenant IDOR confirmed: User B read/mutated User A resource at {} with HTTP {} (payload: {})",
                path,
                code_b,
                body_b.chars().take(120).collect::<String>()
            ),
        )
    } else {
        (
            VerificationStatus::SuspectUnverified,
            format!("IDOR User B returned HTTP {} (inconclusive)", code_b),
        )
    };

    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!(
            "curl -i -X {} {} -H {}",
            shell_quote_single(method),
            shell_quote_single(&url),
            shell_quote_single(hdr_b.trim())
        ),
    })
}

pub async fn verify_finding(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    verify_finding_with_config(port, finding, concurrency, &SandboxProbeConfig::default()).await
}

pub async fn verify_finding_with_config(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
    cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    match finding.missing_guard {
        GuardKind::Auth => verify_auth_invariant_with_config(port, finding, cfg).await,
        GuardKind::TxLock => {
            verify_concurrency_invariant_with_config(port, finding, concurrency, cfg).await
        }
        GuardKind::OwnershipCheck => verify_idor_invariant_with_config(port, finding, cfg).await,
        other => Ok(VerifiedFinding {
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            entry_route: finding.entry_route.clone(),
            status: VerificationStatus::SuspectUnverified,
            evidence: format!(
                "Static/AST finding ({:?}); live exploit probe applies to Auth, IDOR, and Race findings",
                other
            ),
            replay_cmd: format!("shellmind-guard replay {}", finding.id),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_keep_open_response_does_not_hang() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut req = [0u8; 512];
                let _ = sock.read(&mut req).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let (code, body, _) = timeout(Duration::from_millis(500), read_http_bounded(&mut stream))
            .await
            .expect("must not hang on keep-open socket")
            .unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn test_chunked_failure_envelope_is_decoded_and_not_false_proven() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut req = [0u8; 512];
                let _ = sock.read(&mut req).await;
                let payload = r#"{"ok":false,"error":"rejected"}"#;
                let chunked = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                    payload.len(),
                    payload
                );
                let _ = sock.write_all(chunked.as_bytes()).await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"POST /test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let (code, body, _) = read_http_bounded(&mut stream).await.unwrap();
        assert_eq!(code, 200);
        assert!(is_failure_envelope(code, &body));
    }

    #[tokio::test]
    async fn test_joinset_barrier_12_concurrent_200_marks_proven() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicUsize::new(0));
        let c_srv = Arc::clone(&counter);
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let c_req = Arc::clone(&c_srv);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let mut total = 0usize;
                        while total < buf.len() {
                            match sock.read(&mut buf[total..]).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    total += n;
                                    let s = String::from_utf8_lossy(&buf[..total]);
                                    if s.ends_with('}') {
                                        break;
                                    }
                                }
                            }
                        }
                        let id = c_req.fetch_add(1, Ordering::SeqCst) + 1;
                        let body = format!(r#"{{"ok":true,"tx":{}}}"#, id);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });

        let finding = LatticeFinding {
            id: "VF-RACE-002".into(),
            rule_id: "VF-RACE-001".into(),
            severity: "CRITICAL".into(),
            title: "Double spend".into(),
            file: "server.mjs".into(),
            line: 14,
            status: "SUSPECT".into(),
            confidence: vf_graph::Confidence::Confirmed,
            entry_route: "POST /api/pay".into(),
            sink_kind: vf_graph::SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: Vec::new(),
            remediation: String::new(),
        };
        let vf = verify_concurrency_invariant(port, &finding, 12)
            .await
            .unwrap();
        assert_eq!(vf.status, VerificationStatus::Proven);
        assert!(vf.evidence.contains("12/12"), "evidence: {}", vf.evidence);
    }

    #[tokio::test]
    async fn test_joinset_barrier_409_rejection_marks_mitigated() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicUsize::new(0));
        let c_srv = Arc::clone(&counter);
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let c_req = Arc::clone(&c_srv);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let mut total = 0usize;
                        while total < buf.len() {
                            match sock.read(&mut buf[total..]).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    total += n;
                                    let s = String::from_utf8_lossy(&buf[..total]);
                                    if s.ends_with('}') {
                                        break;
                                    }
                                }
                            }
                        }
                        let seq = c_req.fetch_add(1, Ordering::SeqCst);
                        let (status_line, body) = if seq == 0 {
                            ("200 OK", r#"{"ok":true}"#)
                        } else {
                            ("409 Conflict", r#"{"error":"idempotency lock active"}"#)
                        };
                        let resp = format!(
                            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            status_line,
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });

        let finding = LatticeFinding {
            id: "VF-RACE-002".into(),
            rule_id: "VF-RACE-001".into(),
            severity: "CRITICAL".into(),
            title: "Double spend".into(),
            file: "server.mjs".into(),
            line: 14,
            status: "SUSPECT".into(),
            confidence: vf_graph::Confidence::Confirmed,
            entry_route: "POST /api/pay".into(),
            sink_kind: vf_graph::SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: Vec::new(),
            remediation: String::new(),
        };
        let vf = verify_concurrency_invariant(port, &finding, 12)
            .await
            .unwrap();
        assert_eq!(vf.status, VerificationStatus::Mitigated);
    }

    #[tokio::test]
    async fn test_idor_probe_proven_mitigated_and_missing_headers() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let (status_line, body) = if req.contains("Bearer tok-a") {
                            ("200 OK", r#"{"id":1,"owner":"user-a","secret":"ok"}"#)
                        } else if req.contains("Bearer tok-b-vuln") {
                            ("200 OK", r#"{"id":1,"owner":"user-a","leaked":true}"#)
                        } else if req.contains("Bearer tok-b-safe") {
                            ("403 Forbidden", r#"{"error":"forbidden"}"#)
                        } else {
                            ("401 Unauthorized", r#"{"error":"unauthorized"}"#)
                        };
                        let resp = format!(
                            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            status_line,
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });

        let finding = LatticeFinding {
            id: "VF-IDOR-001".into(),
            rule_id: "VF-IDOR-001".into(),
            severity: "HIGH".into(),
            title: "Potential IDOR".into(),
            file: "routes.ts".into(),
            line: 10,
            status: "SUSPECT".into(),
            confidence: vf_graph::Confidence::Confirmed,
            entry_route: "GET /orders/:id".into(),
            sink_kind: vf_graph::SinkKind::IdorDbAccess,
            missing_guard: GuardKind::OwnershipCheck,
            witness_path: Vec::new(),
            remediation: String::new(),
        };

        // 1. Missing headers fails closed as SuspectUnverified
        let missing = verify_finding_with_config(port, &finding, 4, &SandboxProbeConfig::default())
            .await
            .unwrap();
        assert_eq!(missing.status, VerificationStatus::SuspectUnverified);

        // 2. User B receives 200 OK -> Proven!
        let proven = verify_finding_with_config(
            port,
            &finding,
            4,
            &SandboxProbeConfig {
                user_a_header: Some("Authorization: Bearer tok-a".into()),
                user_b_header: Some("Authorization: Bearer tok-b-vuln".into()),
                probe_body: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(proven.status, VerificationStatus::Proven);
        assert!(proven.evidence.contains("/orders/1"));

        // 3. User B receives 403 Forbidden -> Mitigated!
        let mitigated = verify_finding_with_config(
            port,
            &finding,
            4,
            &SandboxProbeConfig {
                user_a_header: Some("Authorization: Bearer tok-a".into()),
                user_b_header: Some("Authorization: Bearer tok-b-safe".into()),
                probe_body: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(mitigated.status, VerificationStatus::Mitigated);
    }
}
