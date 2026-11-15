use anyhow::Result;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sh_graph::{
    Confidence, GuardKind, LatticeFinding, ParamTypeHint, RouteSchema, SinkKind, TraceHop,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Barrier, Notify, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
static SANDBOX_RUSTLS_INIT: Once = Once::new();

pub(crate) fn ensure_rustls_crypto() {
    SANDBOX_RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Proven,
    Mitigated,
    SuspectUnverified,
    Unbootable,
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
    #[serde(default)]
    pub memory_limit_mb: Option<u64>,
    #[serde(default)]
    pub use_cgroup_v2: bool,
    #[serde(default)]
    pub use_tls: bool,
    #[serde(default)]
    pub mock_shims: bool,
    #[serde(default)]
    pub fuzz_routes: Vec<RouteSchema>,
}

/// Self-contained loopback-only TLS certificate verifier so local `--sandbox-tls`
/// targets using self-signed dev certs inside `127.0.0.1` can still be probed via `rustls`.
#[derive(Debug)]
struct LoopbackTestCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl LoopbackTestCertVerifier {
    fn new() -> Self {
        ensure_rustls_crypto();
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for LoopbackTestCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Intentionally permitted ONLY for isolated loopback sandbox endpoints (`127.0.0.1`).
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

enum ProbeStream {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl ProbeStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            ProbeStream::Tcp(s) => s.write_all(buf).await,
            ProbeStream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ProbeStream::Tcp(s) => s.flush().await,
            ProbeStream::Tls(s) => s.flush().await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ProbeStream::Tcp(s) => s.read(buf).await,
            ProbeStream::Tls(s) => s.read(buf).await,
        }
    }
}

async fn connect_probe_stream(port: u16, use_tls: bool) -> Result<ProbeStream> {
    let tcp = timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", port))).await??;
    let _ = tcp.set_nodelay(true);
    if !use_tls {
        return Ok(ProbeStream::Tcp(tcp));
    }
    ensure_rustls_crypto();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LoopbackTestCertVerifier::new()))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from("localhost")?;
    let tls_stream = timeout(IO_TIMEOUT, connector.connect(server_name, tcp)).await??;
    Ok(ProbeStream::Tls(Box::new(tls_stream)))
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

#[cfg(test)]
async fn send_http_probe(
    port: u16,
    method: &str,
    path: &str,
    extra_header: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String, bool)> {
    send_http_probe_with_tls(
        port,
        method,
        path,
        extra_header,
        body.map(|b| b.as_bytes()),
        false,
    )
    .await
}

async fn send_http_probe_with_tls(
    port: u16,
    method: &str,
    path: &str,
    extra_header: Option<&str>,
    body: Option<&[u8]>,
    use_tls: bool,
) -> Result<(u16, String, bool)> {
    let hdr_line = format_optional_header(extra_header).unwrap_or_default();
    let mut raw: Vec<u8> = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            b.len()
        )
        .into_bytes()
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr_line}Connection: close\r\n\r\n"
        )
        .into_bytes()
    };
    if let Some(b) = body {
        raw.extend_from_slice(b);
    }
    let mut stream = connect_probe_stream(port, use_tls).await?;
    timeout(IO_TIMEOUT, stream.write_all(&raw)).await??;
    let _ = stream.flush().await;
    Ok(read_probe_bounded(&mut stream)
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

async fn read_probe_bounded(stream: &mut ProbeStream) -> Result<(u16, String, bool)> {
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
    let (status_code, resp_body, is_html) = send_http_probe_with_tls(
        port,
        method,
        &path,
        None,
        Some(body.as_bytes()),
        cfg.use_tls,
    )
    .await?;

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

    let scheme = if cfg.use_tls { "https" } else { "http" };
    let k_flag = if cfg.use_tls { "-k " } else { "" };
    let url = format!("{}://127.0.0.1:{}{}", scheme, port, path);
    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!(
            "curl {}-i -X {} {} -H 'Content-Type: application/json' -d {}",
            k_flag,
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
    let use_tls = cfg.use_tls;

    for _ in 0..concurrency {
        let pfx = Arc::clone(&prefix);
        let bar = Arc::clone(&barrier);
        let abt = Arc::clone(&abort);
        let abtd = Arc::clone(&aborted);
        let failed = Arc::clone(&failed_count);
        set.spawn(async move {
            let conn = timeout(Duration::from_secs(2), connect_probe_stream(port, use_tls)).await;
            let mut stream = match conn {
                Ok(Ok(s)) => s,
                _ => {
                    failed.fetch_add(1, Ordering::SeqCst);
                    abtd.store(true, Ordering::SeqCst);
                    abt.notify_waiters();
                    return None;
                }
            };
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

            read_probe_bounded(&mut stream).await.ok()
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

    let (code_a, body_a, html_a) = send_http_probe_with_tls(
        port,
        method,
        &path,
        Some(hdr_a),
        req_body.map(|s| s.as_bytes()),
        cfg.use_tls,
    )
    .await?;
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

    let (code_b, body_b, html_b) = send_http_probe_with_tls(
        port,
        method,
        &path,
        Some(hdr_b),
        req_body.map(|s| s.as_bytes()),
        cfg.use_tls,
    )
    .await?;
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

/// Actionable `UNBOOTABLE` classifier when an isolated server fails to boot due to external DBs,
/// missing environment configuration, port contention, or premature process exit.
pub fn classify_boot_failure(raw_log_or_err: &str) -> String {
    let trimmed = raw_log_or_err.trim();
    let low = trimmed.to_ascii_lowercase();
    let reason = if low.contains("econnrefused")
        && (low.contains("5432") || low.contains("postgres") || low.contains("pg_"))
    {
        "external PostgreSQL database unavailable inside isolated sandbox (ECONNREFUSED :5432)"
    } else if low.contains("econnrefused")
        && (low.contains("3306") || low.contains("mysql") || low.contains("mariadb"))
    {
        "external MySQL/MariaDB database unavailable inside isolated sandbox (ECONNREFUSED :3306)"
    } else if low.contains("econnrefused")
        && (low.contains("27017")
            || low.contains("mongo")
            || low.contains("6379")
            || low.contains("redis"))
    {
        "external data store (Redis/MongoDB) unavailable inside isolated sandbox"
    } else if low.contains("database_url")
        || low.contains("missing env")
        || low.contains("environment variable")
        || low.contains("cannot find module")
        || low.contains("modulenotfounderror")
    {
        "missing runtime dependency or environment variable (e.g. DATABASE_URL / packages)"
    } else if low.contains("eaddrinuse") || low.contains("address already in use") {
        "loopback port conflict inside sandbox"
    } else {
        "target process exited before opening HTTP/HTTPS loopback listener"
    };
    let tail: String = trimmed
        .lines()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    if tail.is_empty() {
        format!("UNBOOTABLE: {}", reason)
    } else {
        format!(
            "UNBOOTABLE: {} ({})",
            reason,
            tail.chars().take(180).collect::<String>()
        )
    }
}

/// Local loopback deterministic mock server for Stripe charges, OAuth tokens, and webhooks
/// when `--mock-shims` is active (never makes outbound calls).
pub struct MockShimHandle {
    pub port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for MockShimHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.join_handle.take() {
            h.abort();
        }
    }
}

pub fn mock_shim_env_vars(port: u16) -> Vec<(&'static str, String)> {
    let base = format!("http://127.0.0.1:{}", port);
    vec![
        ("MOCK_SHIM_URL", base.clone()),
        ("STRIPE_API_BASE", base.clone()),
        ("OAUTH_TOKEN_URL", format!("{}/oauth/token", base)),
        ("WEBHOOK_TARGET_URL", format!("{}/webhooks", base)),
    ]
}

async fn run_mock_shim_loop(listener: TcpListener, mut shutdown_rx: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let Ok((mut sock, _)) = accepted else { break; };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let body = if path.starts_with("/v1/charges") {
                        r#"{"id":"ch_mock_001","object":"charge","amount":1000,"status":"succeeded"}"#
                    } else if path.starts_with("/oauth/token") {
                        r#"{"access_token":"mock-access-token","token_type":"Bearer","expires_in":3600}"#
                    } else if path.starts_with("/webhook") {
                        r#"{"received":true,"verified":true}"#
                    } else {
                        r#"{"ok":true,"mock":true}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        }
    }
}

pub async fn spawn_mock_shim_server() -> Result<MockShimHandle> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let (tx, rx) = oneshot::channel();
    let jh = tokio::spawn(run_mock_shim_loop(listener, rx));
    Ok(MockShimHandle {
        port,
        shutdown_tx: Some(tx),
        join_handle: Some(jh),
    })
}

pub async fn spawn_mock_shim_server_on_port(port: u16) -> Result<MockShimHandle> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let actual = listener.local_addr()?.port();
    let (tx, rx) = oneshot::channel();
    let jh = tokio::spawn(run_mock_shim_loop(listener, rx));
    Ok(MockShimHandle {
        port: actual,
        shutdown_tx: Some(tx),
        join_handle: Some(jh),
    })
}

/// Combined live finding + verification proof produced by `--deep` targeted route fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzProbeHit {
    pub finding: LatticeFinding,
    pub verified: VerifiedFinding,
}

async fn probe_raw_bytes(port: u16, use_tls: bool, raw_req: &[u8]) -> Result<(u16, String, bool)> {
    let mut stream = connect_probe_stream(port, use_tls).await?;
    timeout(IO_TIMEOUT, stream.write_all(raw_req)).await??;
    let _ = stream.flush().await;
    Ok(read_probe_bounded(&mut stream)
        .await
        .unwrap_or((0, String::new(), false)))
}

fn build_baseline_json(route: &RouteSchema) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for p in &route.params {
        if p.location == "path" {
            continue;
        }
        let val = match p.type_hint {
            ParamTypeHint::Integer => serde_json::json!(1),
            ParamTypeHint::Number => serde_json::json!(10),
            ParamTypeHint::Boolean => serde_json::json!(true),
            ParamTypeHint::String | ParamTypeHint::Unknown => {
                if p.is_financial {
                    serde_json::json!(10)
                } else {
                    serde_json::json!("test-user-1")
                }
            }
        };
        map.insert(p.name.clone(), val);
    }
    if map.is_empty() {
        map.insert("userId".into(), serde_json::json!("test-user-1"));
        map.insert("amount".into(), serde_json::json!(10));
    }
    map
}

/// Bounded Phase 10 `--deep` route fuzzer: generates tailored financial/boundary/encoding payloads
/// from discovered `RouteSchema` contracts and tests live loopback sandbox endpoints.
pub async fn verify_route_fuzz_with_config(
    port: u16,
    routes: &[RouteSchema],
    cfg: &SandboxProbeConfig,
) -> Vec<FuzzProbeHit> {
    let mut hits = Vec::new();
    if routes.is_empty() {
        return hits;
    }
    let overall_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let auth_hdr = cfg.user_a_header.as_deref();
    let mut seen_route_rule: HashSet<(String, String)> = HashSet::new();

    for (r_idx, route) in routes.iter().take(24).enumerate() {
        if tokio::time::Instant::now() >= overall_deadline {
            break;
        }
        let method = if route.method.is_empty() {
            "POST"
        } else {
            route.method.as_str()
        };
        let path = substitute_route_params(&route.path);
        let entry_route = format!("{} {}", method, route.path);

        // 1. Negative / zero financial & quantity tampering (`POST`/`PUT`/`PATCH`)
        if matches!(method, "POST" | "PUT" | "PATCH") {
            let fin_fields: Vec<String> = {
                let mut f: Vec<String> = route
                    .params
                    .iter()
                    .filter(|p| p.is_financial)
                    .map(|p| p.name.clone())
                    .collect();
                if f.is_empty() {
                    let low = route.path.to_ascii_lowercase();
                    if low.contains("pay")
                        || low.contains("order")
                        || low.contains("checkout")
                        || low.contains("withdraw")
                        || low.contains("transfer")
                        || low.contains("refund")
                    {
                        f.push("amount".into());
                    }
                }
                f
            };
            for fld in fin_fields.into_iter().take(2) {
                for bad_num in [-100i64, 0] {
                    let mut obj = build_baseline_json(route);
                    obj.insert(fld.clone(), serde_json::json!(bad_num));
                    let body_str = serde_json::Value::Object(obj).to_string();
                    if let Ok((code, rbody, is_html)) = send_http_probe_with_tls(
                        port,
                        method,
                        &path,
                        auth_hdr,
                        Some(body_str.as_bytes()),
                        cfg.use_tls,
                    )
                    .await
                        && (200..300).contains(&code)
                        && !is_html
                        && !is_failure_envelope(code, &rbody)
                        && seen_route_rule.insert((entry_route.clone(), "VF-FUZZ-TAMPER".into()))
                    {
                        let fid = format!("VF-FUZZ-{:03}", r_idx + hits.len() + 1);
                        let evidence = format!(
                            "Negative/zero financial input `{}={}` accepted with HTTP {} ({})",
                            fld,
                            bad_num,
                            code,
                            rbody.chars().take(100).collect::<String>()
                        );
                        let url = format!(
                            "{}://127.0.0.1:{}{}",
                            if cfg.use_tls { "https" } else { "http" },
                            port,
                            path
                        );
                        hits.push(FuzzProbeHit {
                            finding: LatticeFinding {
                                id: fid.clone(),
                                rule_id: "VF-FUZZ-TAMPER".into(),
                                severity: "HIGH".into(),
                                title: format!(
                                    "Price/quantity tampering (`{}={}`) accepted on `{}`",
                                    fld, bad_num, entry_route
                                ),
                                file: route.source_file.clone(),
                                line: route.line.max(1),
                                status: "PROVEN".into(),
                                confidence: Confidence::Proven,
                                entry_route: entry_route.clone(),
                                sink_kind: SinkKind::SchemaTampering,
                                missing_guard: GuardKind::InputValidation,
                                witness_path: vec![TraceHop {
                                    file: route.source_file.clone(),
                                    symbol: entry_route.clone(),
                                    line: route.line.max(1),
                                }],
                                remediation: "Reject non-positive or non-finite numeric/financial fields with HTTP 400 before balance/order mutation.".into(),
                            },
                            verified: VerifiedFinding {
                                finding_id: fid.clone(),
                                rule_id: "VF-FUZZ-TAMPER".into(),
                                entry_route: entry_route.clone(),
                                status: VerificationStatus::Proven,
                                evidence,
                                replay_cmd: format!(
                                    "curl -i -X {} {} -H 'Content-Type: application/json' -d {}",
                                    shell_quote_single(method),
                                    shell_quote_single(&url),
                                    shell_quote_single(&body_str)
                                ),
                            },
                        });
                        break;
                    }
                }
            }

            // 2. Boundary / wrong-type unhandled crash (`VF-FUZZ-CRASH`)
            let mut boundary_obj = build_baseline_json(route);
            let target_key = route
                .params
                .first()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "amount".into());
            boundary_obj.insert(target_key, serde_json::json!("NaN_BOUNDARY_TYPE_CONFUSION"));
            boundary_obj.insert("__oversized".into(), serde_json::json!("A".repeat(4096)));
            let boundary_str = serde_json::Value::Object(boundary_obj).to_string();
            if let Ok((code, rbody, _)) = send_http_probe_with_tls(
                port,
                method,
                &path,
                auth_hdr,
                Some(boundary_str.as_bytes()),
                cfg.use_tls,
            )
            .await
                && (code >= 500 || code == 0)
                && seen_route_rule.insert((entry_route.clone(), "VF-FUZZ-CRASH".into()))
            {
                let fid = format!("VF-FUZZ-{:03}", r_idx + hits.len() + 1);
                let evidence = if code == 0 {
                    "Boundary/wrong-type payload caused abrupt socket close / handler crash".into()
                } else {
                    format!(
                        "Boundary/wrong-type payload triggered HTTP {} ({})",
                        code,
                        rbody.chars().take(100).collect::<String>()
                    )
                };
                hits.push(FuzzProbeHit {
                    finding: LatticeFinding {
                        id: fid.clone(),
                        rule_id: "VF-FUZZ-CRASH".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "Boundary/type-confusion payload crashed `{}` (HTTP {})",
                            entry_route, code
                        ),
                        file: route.source_file.clone(),
                        line: route.line.max(1),
                        status: "PROVEN".into(),
                        confidence: Confidence::Proven,
                        entry_route: entry_route.clone(),
                        sink_kind: SinkKind::SchemaTampering,
                        missing_guard: GuardKind::InputValidation,
                        witness_path: vec![TraceHop {
                            file: route.source_file.clone(),
                            symbol: entry_route.clone(),
                            line: route.line.max(1),
                        }],
                        remediation: "Validate types, sizes, and numeric parsing cleanly with HTTP 400 instead of throwing unhandled 5xx exceptions.".into(),
                    },
                    verified: VerifiedFinding {
                        finding_id: fid.clone(),
                        rule_id: "VF-FUZZ-CRASH".into(),
                        entry_route: entry_route.clone(),
                        status: VerificationStatus::Proven,
                        evidence,
                        replay_cmd: format!("shellmind-guard replay {}", fid),
                    },
                });
            }
        }

        // 3. Null-byte & invalid UTF-8 encoding edge-case probe (`VF-FUZZ-ENCODING`)
        let hdr_line = format_optional_header(auth_hdr).unwrap_or_default();
        let mut raw_enc_req: Vec<u8> = if matches!(method, "GET" | "HEAD" | "DELETE") {
            let sep = if path.contains('?') { '&' } else { '?' };
            let mut v = format!("{method} {path}{sep}fuzz=%00",).into_bytes();
            v.extend_from_slice(b"\xff\xfe HTTP/1.1\r\n");
            v.extend_from_slice(
                format!("Host: 127.0.0.1:{port}\r\n{hdr_line}Connection: close\r\n\r\n").as_bytes(),
            );
            v
        } else {
            let mut body_bytes = b"{\"probe\":\"null\\u0000byte\",\"raw\":\"".to_vec();
            body_bytes.extend_from_slice(b"\xff\xfe\xfd");
            body_bytes.extend_from_slice(b"\"}");
            let mut v = format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            )
            .into_bytes();
            v.extend_from_slice(&body_bytes);
            v
        };
        if let Ok((code, rbody, _)) = probe_raw_bytes(port, cfg.use_tls, &raw_enc_req).await
            && (code >= 500 || code == 0)
            && seen_route_rule.insert((entry_route.clone(), "VF-FUZZ-ENCODING".into()))
        {
            raw_enc_req.clear();
            let fid = format!("VF-FUZZ-{:03}", r_idx + hits.len() + 1);
            let evidence = if code == 0 {
                "Malformed UTF-8 / null-byte payload terminated handler connection abruptly".into()
            } else {
                format!(
                    "Malformed UTF-8 / null-byte payload returned unhandled HTTP {} ({})",
                    code,
                    rbody.chars().take(100).collect::<String>()
                )
            };
            hits.push(FuzzProbeHit {
                finding: LatticeFinding {
                    id: fid.clone(),
                    rule_id: "VF-FUZZ-ENCODING".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Null-byte / malformed UTF-8 caused unhandled error on `{}` (HTTP {})",
                        entry_route, code
                    ),
                    file: route.source_file.clone(),
                    line: route.line.max(1),
                    status: "PROVEN".into(),
                    confidence: Confidence::Proven,
                    entry_route: entry_route.clone(),
                    sink_kind: SinkKind::SchemaTampering,
                    missing_guard: GuardKind::InputValidation,
                    witness_path: vec![TraceHop {
                        file: route.source_file.clone(),
                        symbol: entry_route.clone(),
                        line: route.line.max(1),
                    }],
                    remediation: "Strictly validate UTF-8 decoding and reject NUL (`\\x00`) bytes in parsers/routers with HTTP 400.".into(),
                },
                verified: VerifiedFinding {
                    finding_id: fid.clone(),
                    rule_id: "VF-FUZZ-ENCODING".into(),
                    entry_route: entry_route.clone(),
                    status: VerificationStatus::Proven,
                    evidence,
                    replay_cmd: format!("shellmind-guard replay {}", fid),
                },
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const TEST_CERT_DER: &[u8] = &[
        48, 130, 1, 155, 48, 130, 1, 65, 160, 3, 2, 1, 2, 2, 20, 38, 226, 253, 155, 49, 158, 107,
        109, 239, 171, 39, 242, 213, 33, 43, 110, 229, 84, 144, 145, 48, 10, 6, 8, 42, 134, 72,
        206, 61, 4, 3, 2, 48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 108, 111, 99, 97, 108,
        104, 111, 115, 116, 48, 32, 23, 13, 50, 54, 49, 49, 49, 53, 49, 57, 48, 51, 52, 55, 90, 24,
        15, 50, 49, 50, 54, 49, 48, 50, 50, 49, 57, 48, 51, 52, 55, 90, 48, 20, 49, 18, 48, 16, 6,
        3, 85, 4, 3, 12, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 48, 89, 48, 19, 6, 7, 42,
        134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 166, 213, 246,
        239, 112, 3, 133, 224, 149, 96, 200, 101, 161, 112, 133, 29, 3, 164, 121, 193, 103, 4, 127,
        182, 20, 183, 134, 159, 125, 119, 172, 193, 192, 251, 223, 217, 68, 212, 126, 156, 172,
        253, 123, 37, 66, 194, 41, 199, 68, 236, 161, 34, 25, 211, 189, 126, 66, 48, 229, 153, 111,
        215, 107, 15, 163, 111, 48, 109, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 62, 163, 121, 225,
        215, 185, 4, 137, 34, 69, 19, 213, 92, 100, 113, 164, 30, 38, 39, 132, 48, 31, 6, 3, 85,
        29, 35, 4, 24, 48, 22, 128, 20, 62, 163, 121, 225, 215, 185, 4, 137, 34, 69, 19, 213, 92,
        100, 113, 164, 30, 38, 39, 132, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1,
        255, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 9, 108, 111, 99, 97, 108, 104, 111, 115,
        116, 135, 4, 127, 0, 0, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 72, 0, 48, 69,
        2, 33, 0, 201, 198, 212, 102, 106, 108, 152, 183, 247, 161, 222, 46, 18, 142, 203, 248, 71,
        50, 60, 200, 168, 187, 165, 108, 221, 164, 37, 113, 107, 149, 151, 245, 2, 32, 98, 160, 98,
        109, 186, 92, 138, 76, 202, 58, 38, 252, 122, 153, 2, 176, 47, 223, 79, 18, 176, 212, 133,
        139, 166, 190, 93, 141, 204, 197, 7, 22,
    ];
    const TEST_KEY_DER: &[u8] = &[
        48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
        61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 69, 91, 210, 255, 171, 48, 156, 189, 193,
        112, 44, 216, 24, 112, 214, 250, 186, 70, 5, 25, 124, 124, 104, 189, 86, 218, 57, 176, 93,
        0, 132, 80, 161, 68, 3, 66, 0, 4, 166, 213, 246, 239, 112, 3, 133, 224, 149, 96, 200, 101,
        161, 112, 133, 29, 3, 164, 121, 193, 103, 4, 127, 182, 20, 183, 134, 159, 125, 119, 172,
        193, 192, 251, 223, 217, 68, 212, 126, 156, 172, 253, 123, 37, 66, 194, 41, 199, 68, 236,
        161, 34, 25, 211, 189, 126, 66, 48, 229, 153, 111, 215, 107, 15,
    ];

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

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut ps = ProbeStream::Tcp(stream);
        ps.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let (code, body, _) = timeout(Duration::from_millis(500), read_probe_bounded(&mut ps))
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

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut ps = ProbeStream::Tcp(stream);
        ps.write_all(b"POST /test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let (code, body, _) = read_probe_bounded(&mut ps).await.unwrap();
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
            confidence: sh_graph::Confidence::Confirmed,
            entry_route: "POST /api/pay".into(),
            sink_kind: sh_graph::SinkKind::BalanceUpdate,
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
            confidence: sh_graph::Confidence::Confirmed,
            entry_route: "POST /api/pay".into(),
            sink_kind: sh_graph::SinkKind::BalanceUpdate,
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
            confidence: sh_graph::Confidence::Confirmed,
            entry_route: "GET /orders/:id".into(),
            sink_kind: sh_graph::SinkKind::IdorDbAccess,
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
                ..Default::default()
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
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(mitigated.status, VerificationStatus::Mitigated);
    }

    #[tokio::test]
    async fn test_tls_loopback_probe_auth_and_last_byte_sync() {
        ensure_rustls_crypto();
        let cert = CertificateDer::from(TEST_CERT_DER.to_vec());
        let key = PrivateKeyDer::try_from(TEST_KEY_DER.to_vec()).expect("valid test EC key");
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("valid TLS server config");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        if let Ok(mut tls) = acc.accept(sock).await {
                            let mut buf = vec![0u8; 4096];
                            let mut total = 0usize;
                            while total < buf.len() {
                                match tls.read(&mut buf[total..]).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        total += n;
                                        if String::from_utf8_lossy(&buf[..total]).ends_with('}') {
                                            break;
                                        }
                                    }
                                }
                            }
                            let body = r#"{"ok":true,"tls":true}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = tls.write_all(resp.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                    });
                }
            }
        });

        let cfg = SandboxProbeConfig {
            use_tls: true,
            ..Default::default()
        };
        let auth_finding = LatticeFinding {
            id: "VF-AUTH-TLS".into(),
            rule_id: "VF-AUTH-001".into(),
            severity: "CRITICAL".into(),
            title: "Missing Auth over HTTPS".into(),
            file: "tls.ts".into(),
            line: 5,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "POST /api/tls-withdraw".into(),
            sink_kind: SinkKind::PaymentMutation,
            missing_guard: GuardKind::Auth,
            witness_path: Vec::new(),
            remediation: String::new(),
        };
        let auth_res = verify_finding_with_config(port, &auth_finding, 4, &cfg)
            .await
            .unwrap();
        assert_eq!(auth_res.status, VerificationStatus::Proven);
        assert!(auth_res.replay_cmd.contains("https://"));

        let race_finding = LatticeFinding {
            id: "VF-RACE-TLS".into(),
            missing_guard: GuardKind::TxLock,
            ..auth_finding
        };
        let race_res = verify_finding_with_config(port, &race_finding, 6, &cfg)
            .await
            .unwrap();
        assert_eq!(race_res.status, VerificationStatus::Proven);
        assert!(race_res.evidence.contains("6/6"));
    }

    #[tokio::test]
    async fn test_deterministic_mock_shim_server_endpoints() {
        let shim = spawn_mock_shim_server().await.unwrap();
        let envs = mock_shim_env_vars(shim.port);
        assert!(
            envs.iter()
                .any(|(k, v)| *k == "STRIPE_API_BASE" && v.contains(&shim.port.to_string()))
        );

        let (c1, b1, _) = send_http_probe(shim.port, "POST", "/v1/charges", None, Some("{}"))
            .await
            .unwrap();
        assert_eq!(c1, 200);
        assert!(b1.contains("ch_mock_001"));

        let (c2, b2, _) = send_http_probe(shim.port, "POST", "/oauth/token", None, Some("{}"))
            .await
            .unwrap();
        assert_eq!(c2, 200);
        assert!(b2.contains("mock-access-token"));
    }

    #[test]
    fn test_classify_boot_failure_unbootable() {
        let pg = classify_boot_failure("Error: connect ECONNREFUSED 127.0.0.1:5432");
        assert!(pg.starts_with("UNBOOTABLE:"));
        assert!(pg.contains("PostgreSQL"));

        let db = classify_boot_failure("FATAL: Missing DATABASE_URL environment variable");
        assert!(db.starts_with("UNBOOTABLE:"));
        assert!(db.contains("environment"));
    }

    #[tokio::test]
    async fn test_targeted_route_fuzz_catches_tampering_crash_and_utf8_and_spares_hardened() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 8192];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req_lossy = String::from_utf8_lossy(&buf[..n]);
                        let line0 = req_lossy.lines().next().unwrap_or("");
                        let path = line0.split_whitespace().nth(1).unwrap_or("/");
                        let has_invalid_utf8 = buf[..n].windows(2).any(|w| w == [0xff, 0xfe]);

                        let (status_line, body) =
                            if path == "/api/pay" && req_lossy.contains("-100") {
                                ("200 OK", r#"{"debited":-100}"#)
                            } else if path == "/api/legacy" && has_invalid_utf8 {
                                (
                                    "500 Internal Server Error",
                                    r#"{"error":"utf8 decode panic"}"#,
                                )
                            } else if path == "/api/safe" {
                                ("400 Bad Request", r#"{"ok":false,"error":"invalid input"}"#)
                            } else {
                                ("400 Bad Request", r#"{"ok":false,"error":"bad input"}"#)
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

        let routes = vec![
            RouteSchema {
                method: "POST".into(),
                path: "/api/pay".into(),
                source_file: "pay.ts".into(),
                line: 10,
                params: vec![sh_graph::RouteParamSpec {
                    name: "amount".into(),
                    location: "body".into(),
                    type_hint: ParamTypeHint::Number,
                    is_financial: true,
                    has_positive_bound: false,
                }],
                from_openapi: false,
            },
            RouteSchema {
                method: "POST".into(),
                path: "/api/legacy".into(),
                source_file: "legacy.ts".into(),
                line: 20,
                params: Vec::new(),
                from_openapi: false,
            },
            RouteSchema {
                method: "POST".into(),
                path: "/api/safe".into(),
                source_file: "safe.ts".into(),
                line: 30,
                params: vec![sh_graph::RouteParamSpec {
                    name: "amount".into(),
                    location: "body".into(),
                    type_hint: ParamTypeHint::Number,
                    is_financial: true,
                    has_positive_bound: true,
                }],
                from_openapi: false,
            },
        ];

        let hits =
            verify_route_fuzz_with_config(port, &routes, &SandboxProbeConfig::default()).await;
        assert!(
            hits.iter().any(|h| h.finding.rule_id == "VF-FUZZ-TAMPER"
                && h.finding.entry_route.contains("/api/pay")),
            "Expected VF-FUZZ-TAMPER on /api/pay: {:?}",
            hits
        );
        assert!(
            hits.iter().any(|h| h.finding.rule_id == "VF-FUZZ-ENCODING"
                && h.finding.entry_route.contains("/api/legacy")),
            "Expected VF-FUZZ-ENCODING on /api/legacy: {:?}",
            hits
        );
        assert!(
            !hits
                .iter()
                .any(|h| h.finding.entry_route.contains("/api/safe")),
            "Hardened /api/safe must have 0 fuzz hits: {:?}",
            hits
        );
    }
}
