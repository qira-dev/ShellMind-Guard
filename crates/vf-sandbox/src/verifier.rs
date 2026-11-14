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

fn split_headers_and_body(raw: &str) -> (&str, &str) {
    if let Some((h, b)) = raw.split_once("\r\n\r\n") {
        (h, b)
    } else if let Some((h, b)) = raw.split_once("\n\n") {
        (h, b)
    } else {
        (raw, "")
    }
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

fn decode_chunked_body(raw_body: &str) -> String {
    let mut out = String::with_capacity(raw_body.len());
    let mut rest = raw_body;
    while let Some((size_line, after_size)) = rest.split_once("\r\n") {
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        if chunk_len == 0 {
            break;
        }
        if after_size.len() < chunk_len {
            out.push_str(after_size);
            break;
        }
        out.push_str(&after_size[..chunk_len]);
        rest = &after_size[chunk_len..];
        rest = rest.strip_prefix("\r\n").unwrap_or(rest);
    }
    if out.is_empty() {
        raw_body.to_string()
    } else {
        out
    }
}

/// Reads an HTTP response with strict timeout and 256 KiB cap, decoding `Transfer-Encoding: chunked`
/// and stopping immediately once `Content-Length` or `0\r\n\r\n` arrives.
async fn read_http_bounded(stream: &mut TcpStream) -> Result<(u16, String)> {
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
            if chunked
                && let Some(hdr_end) = s.find("\r\n\r\n")
                && s[hdr_end + 4..].contains("0\r\n\r\n")
            {
                break;
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

    let raw = String::from_utf8_lossy(&buf).to_string();
    let status = extract_http_status(&raw);
    let (hdrs, body) = split_headers_and_body(&raw);
    let decoded = if is_chunked_encoding(hdrs) {
        decode_chunked_body(body)
    } else {
        body.to_string()
    };
    if res.is_err() && status == 0 {
        anyhow::bail!("Timed out reading HTTP response");
    }
    Ok((status, decoded.trim().to_string()))
}

fn is_failure_envelope(status: u16, body: &str) -> bool {
    if status == 204 || body.is_empty() {
        return true;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
            return true;
        }
        if v.get("error").is_some() && v.get("ok").and_then(|b| b.as_bool()) != Some(true) {
            return true;
        }
    }
    false
}

/// Checks whether an unauthenticated request to the flagged route is blocked (401/403)
/// or actually executes a non-error payload inside the isolated loopback sandbox.
pub async fn verify_auth_invariant(port: u16, finding: &LatticeFinding) -> Result<VerifiedFinding> {
    let (method, path) = parse_route(&finding.entry_route);
    let body = r#"{"userId":"test-user-1","amount":10}"#;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", port))).await??;
    timeout(IO_TIMEOUT, stream.write_all(req.as_bytes())).await??;
    let (status_code, resp_body) = read_http_bounded(&mut stream)
        .await
        .unwrap_or((0, String::new()));

    let (status, evidence) = if status_code == 401 || status_code == 403 {
        (
            VerificationStatus::Mitigated,
            format!("Blocked by runtime guard with HTTP {}", status_code),
        )
    } else if (200..300).contains(&status_code) && !is_failure_envelope(status_code, &resp_body) {
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
                "HTTP {} returned empty/failure envelope ({}); cannot prove mutation",
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

    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!(
            "curl -i -X {} http://127.0.0.1:{}{} -H 'Content-Type: application/json' -d '{}'",
            method, port, path, body
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

    let (method, path) = parse_route(&finding.entry_route);
    let body = r#"{"userId":"test-user-1","amount":80}"#;
    let raw_req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        if let Ok(Some((code, resp_body))) = joined {
            if (200..300).contains(&code)
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
    } else if valid_2xx <= 1 && blocked > 0 {
        (
            VerificationStatus::Mitigated,
            format!(
                "Last-Byte Sync ({}x): only {}x succeeded, {}x blocked by lock/idempotency guard",
                concurrency, valid_2xx, blocked
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

pub async fn verify_finding(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    match finding.missing_guard {
        GuardKind::Auth => verify_auth_invariant(port, finding).await,
        GuardKind::TxLock => verify_concurrency_invariant(port, finding, concurrency).await,
        other => Ok(VerifiedFinding {
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            entry_route: finding.entry_route.clone(),
            status: VerificationStatus::SuspectUnverified,
            evidence: format!(
                "Static/AST finding ({:?}); live exploit probe applies to Auth and Race findings",
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
        let (code, body) = timeout(Duration::from_millis(500), read_http_bounded(&mut stream))
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
        let (code, body) = read_http_bounded(&mut stream).await.unwrap();
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
}
