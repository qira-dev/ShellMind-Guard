use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use vf_graph::{GuardKind, LatticeFinding};

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

/// Checks whether an unauthenticated request to the flagged route is blocked (401/403)
/// or actually executes (2xx) inside the isolated loopback sandbox.
pub async fn verify_auth_invariant(port: u16, finding: &LatticeFinding) -> Result<VerifiedFinding> {
    let (method, path) = parse_route(&finding.entry_route);
    let body = r#"{"userId":"test-user-1","amount":10}"#;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);
    let status_code = extract_http_status(&resp);

    let (status, evidence) = if status_code == 401 || status_code == 403 {
        (
            VerificationStatus::Mitigated,
            format!("Blocked by runtime guard with HTTP {}", status_code),
        )
    } else if (200..300).contains(&status_code) {
        (
            VerificationStatus::Proven,
            format!("Unauthenticated request succeeded with HTTP {}", status_code),
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

/// Barrier-synchronized Last-Byte Sync concurrency test:
/// Buffers N identical requests minus the final byte, waits at a Tokio Barrier(N),
/// and flushes the final byte simultaneously to test idempotency/transaction locking.
pub async fn verify_concurrency_invariant(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
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
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let pfx = Arc::clone(&prefix);
        let b = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
            let _ = stream.set_nodelay(true);
            stream.write_all(&pfx).await.ok()?;
            stream.flush().await.ok()?;

            b.wait().await;

            stream.write_all(&[last_byte]).await.ok()?;
            stream.flush().await.ok()?;

            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            let resp = String::from_utf8_lossy(&buf);
            Some(extract_http_status(&resp))
        }));
    }

    let mut ok_2xx = 0usize;
    let mut blocked = 0usize;
    for h in handles {
        if let Ok(Some(code)) = h.await {
            if (200..300).contains(&code) {
                ok_2xx += 1;
            } else if code > 0 {
                blocked += 1;
            }
        }
    }

    let (status, evidence) = if ok_2xx > 1 {
        (
            VerificationStatus::Proven,
            format!(
                "Last-Byte Sync ({}x concurrent): {}x HTTP 2xx succeeded simultaneously (idempotency/lock missing!)",
                concurrency, ok_2xx
            ),
        )
    } else if ok_2xx <= 1 && blocked > 0 {
        (
            VerificationStatus::Mitigated,
            format!(
                "Last-Byte Sync ({}x concurrent): only {}x succeeded, {}x blocked by lock/guard",
                concurrency, ok_2xx, blocked
            ),
        )
    } else {
        (
            VerificationStatus::SuspectUnverified,
            format!("Last-Byte Sync ({}x): {}x 2xx, {}x non-2xx", concurrency, ok_2xx, blocked),
        )
    };

    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!("veriforge replay {} --sync-race {}", finding.id, concurrency),
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
    }
}
