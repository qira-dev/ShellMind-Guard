//! Localhost HTTP inspection proxy engine (`smg proxy`).
//!
//! Defensive developer tooling (Burp CE-class capture plane):
//! - Intercepts plain HTTP requests (absolute-form & origin-form) end-to-end:
//!   forwards with `Connection: close`, strips `Accept-Encoding` so bodies are
//!   inspectable, captures full request/response into the shared TUI history.
//! - HTTPS `CONNECT` tunnels are relayed byte-for-byte by default. With the
//!   opt-in `--mitm-ca` flag (see `proxy_mitm`) the tunnel is terminated with
//!   an on-the-fly local-CA leaf certificate and the decrypted HTTP/1.1
//!   traffic is captured and replayable like plain HTTP (`kind: "https"`).
//! - Binds loopback only unless `--allow-remote-bind` is passed deliberately.

use crate::proxy_mitm::MitmCa;
use anyhow::{Context, Result, bail};
use smg_tui::proxy_tui::{ProxyEntry, ProxySummary};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HEAD: usize = 64 * 1024;
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_CAPTURE: usize = 8 * 1024 * 1024;
pub const DEFAULT_CAPTURE_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    pub capture_limit: usize,
    pub allow_remote_bind: bool,
    pub jsonl_log: Option<PathBuf>,
    /// Opt-in TLS interception plane (`--mitm-ca`); `None` keeps CONNECT
    /// tunnels transparent.
    pub mitm: Option<Arc<MitmCa>>,
}

pub struct ProxyHandle {
    pub entries: Arc<Mutex<Vec<Arc<ProxyEntry>>>>,
    pub summary: Arc<Mutex<ProxySummary>>,
    pub stop: Arc<AtomicBool>,
    pub bound_addr: SocketAddr,
    pub listener_thread: Option<thread::JoinHandle<()>>,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate_for_capture(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated {} bytes]", &s[..end], s.len())
}

struct ConnCtx {
    entries: Arc<Mutex<Vec<Arc<ProxyEntry>>>>,
    summary: Arc<Mutex<ProxySummary>>,
    next_id: Arc<AtomicU64>,
    capture_limit: usize,
    log_tx: Option<Sender<Arc<ProxyEntry>>>,
    mitm: Option<Arc<MitmCa>>,
}

impl ConnCtx {
    fn record(&self, entry: ProxyEntry, tunneled: bool) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = Arc::new(ProxyEntry { id, ..entry });
        {
            let mut entries = match self.entries.lock() {
                Ok(e) => e,
                Err(_) => return,
            };
            if entries.len() >= 5_000 {
                entries.remove(0);
            }
            entries.push(Arc::clone(&entry));
        }
        {
            let mut summary = match self.summary.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            if tunneled {
                summary.https_tunneled += 1;
            } else {
                summary.http_intercepted += 1;
            }
        }
        if let Some(tx) = &self.log_tx {
            let _ = tx.send(Arc::clone(&entry));
        }
    }
}

pub fn start_proxy(cfg: ProxyConfig) -> Result<ProxyHandle> {
    if !cfg.bind_addr.ip().is_loopback() && !cfg.allow_remote_bind {
        bail!(
            "Refusing to bind non-loopback address {}; the proxy is loopback-only by default (pass --allow-remote-bind deliberately to expose it).",
            cfg.bind_addr
        );
    }
    let listener = TcpListener::bind(cfg.bind_addr)
        .with_context(|| format!("Failed to bind proxy on {}", cfg.bind_addr))?;
    let bound_addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;

    let entries = Arc::new(Mutex::new(Vec::<Arc<ProxyEntry>>::new()));
    let summary = Arc::new(Mutex::new(ProxySummary {
        bind: bound_addr.to_string(),
        ..ProxySummary::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let next_id = Arc::new(AtomicU64::new(0));

    // Optional JSONL sink (headless mode).
    let (log_tx, log_rx) = channel::<Arc<ProxyEntry>>();
    let log_path = cfg.jsonl_log.clone();
    let log_enabled = log_path.is_some();
    if log_enabled {
        thread::spawn(move || {
            let Some(path) = log_path else { return };
            let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            else {
                return;
            };
            for entry in log_rx.iter() {
                if let Ok(line) = serde_json::to_string(&*entry) {
                    let _ = std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes());
                }
            }
        });
    }

    let ctx = ConnCtx {
        entries: Arc::clone(&entries),
        summary: Arc::clone(&summary),
        next_id: Arc::clone(&next_id),
        capture_limit: cfg.capture_limit.max(1024),
        log_tx: if log_enabled { Some(log_tx) } else { None },
        mitm: cfg.mitm,
    };

    let stop_flag = Arc::clone(&stop);
    let listener_ctx = ConnCtx {
        entries: Arc::clone(&ctx.entries),
        summary: Arc::clone(&ctx.summary),
        next_id: Arc::clone(&ctx.next_id),
        capture_limit: ctx.capture_limit,
        log_tx: ctx.log_tx.clone(),
        mitm: ctx.mitm.clone(),
    };
    let listener_thread = thread::spawn(move || {
        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                    {
                        let mut s = match listener_ctx.summary.lock() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        s.connections += 1;
                    }
                    let conn_ctx = ConnCtx {
                        entries: Arc::clone(&listener_ctx.entries),
                        summary: Arc::clone(&listener_ctx.summary),
                        next_id: Arc::clone(&listener_ctx.next_id),
                        capture_limit: listener_ctx.capture_limit,
                        log_tx: listener_ctx.log_tx.clone(),
                        mitm: listener_ctx.mitm.clone(),
                    };
                    thread::spawn(move || {
                        let _ = handle_connection(&mut stream, &conn_ctx);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    if let Ok(mut s) = listener_ctx.summary.lock() {
                        s.errors += 1;
                    }
                }
            }
        }
    });

    Ok(ProxyHandle {
        entries,
        summary,
        stop,
        bound_addr,
        listener_thread: Some(listener_thread),
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn read_head<S: Read>(stream: &mut S) -> Result<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_head_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        if buf.len() > MAX_HEAD {
            bail!("request head exceeds {MAX_HEAD} bytes");
        }
    }
    Ok((String::from_utf8_lossy(&buf).into_owned(), Vec::new()))
}

fn handle_connection(stream: &mut TcpStream, ctx: &ConnCtx) -> Result<()> {
    let (head, leftover) = read_head(stream)?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().trim().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        bail!("malformed request line: {request_line:?}");
    }
    if method == "CONNECT" {
        tunnel(stream, &target, ctx)
    } else {
        intercept_http(
            stream,
            &head,
            leftover,
            &method,
            &target,
            ctx,
            InterceptOpts {
                scheme: "http",
                kind: "http",
                origin_override: None,
                origin_conn: None,
            },
        )
    }
}

fn parse_headers(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// The upstream connection of an intercepted request: plain TCP for HTTP, or
/// an established TLS session (MITM path) for HTTPS.
enum OriginConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for OriginConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            OriginConn::Plain(s) => s.read(buf),
            OriginConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for OriginConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            OriginConn::Plain(s) => s.write(buf),
            OriginConn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            OriginConn::Plain(s) => s.flush(),
            OriginConn::Tls(s) => s.flush(),
        }
    }
}

/// Per-interception routing metadata. The plain-HTTP path uses the defaults;
/// the MITM path pins the CONNECT host/port, a pre-connected TLS origin, and
/// the `https` capture kind.
struct InterceptOpts<'a> {
    scheme: &'static str,
    kind: &'static str,
    origin_override: Option<(&'a str, u16)>,
    origin_conn: Option<OriginConn>,
}

fn intercept_http<S: Read + Write>(
    stream: &mut S,
    head: &str,
    leftover: Vec<u8>,
    method: &str,
    target: &str,
    ctx: &ConnCtx,
    opts: InterceptOpts<'_>,
) -> Result<()> {
    let headers = parse_headers(head);
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let (origin_host, origin_port, url, path_and_query) = match opts.origin_override {
        // MITM path: the CONNECT target is authoritative; the inner request
        // line is origin-form.
        Some((h, p)) => {
            let path = if target.starts_with('/') {
                target.to_string()
            } else {
                format!("/{target}")
            };
            (
                h.to_string(),
                p,
                format!("{}://{}:{}{}", opts.scheme, h, p, path),
                path,
            )
        }
        None => {
            let url = if target.starts_with("http://") || target.starts_with("https://") {
                target.to_string()
            } else {
                let path = if target.starts_with('/') {
                    target.to_string()
                } else {
                    format!("/{target}")
                };
                format!("{}://{}{}", opts.scheme, host, path)
            };
            let parsed = reqwest::Url::parse(&url)?;
            let origin_host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("request URL missing host"))?
                .to_string();
            let origin_port = parsed.port_or_known_default().unwrap_or(80);
            let path_and_query = match parsed.query() {
                Some(q) if !q.is_empty() => format!("{}?{}", parsed.path(), q),
                _ => {
                    let p = parsed.path();
                    if p.is_empty() {
                        "/".to_string()
                    } else {
                        p.to_string()
                    }
                }
            };
            (origin_host, origin_port, url.clone(), path_and_query)
        }
    };

    // Read the request body (Content-Length framing only; documented boundary).
    let mut body_bytes: Vec<u8> = Vec::new();
    if content_length > 0 {
        if content_length > MAX_REQUEST_BODY {
            bail!("request body exceeds {MAX_REQUEST_BODY} bytes");
        }
        let take = leftover.len().min(content_length);
        body_bytes.extend_from_slice(&leftover[..take]);
        let mut buf = [0u8; 8192];
        while body_bytes.len() < content_length {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let remaining = content_length - body_bytes.len();
            body_bytes.extend_from_slice(&buf[..n.min(remaining)]);
        }
    }
    let req_body = String::from_utf8_lossy(&body_bytes).into_owned();

    let started = Instant::now();

    // Rebuild origin-form request: strip hop-by-hop headers + compression.
    let mut out_head = format!("{method} {path_and_query} HTTP/1.1\r\n");
    for (k, v) in &headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "connection" | "proxy-connection" | "keep-alive" | "accept-encoding" | "content-length"
        ) {
            continue;
        }
        out_head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        out_head.push_str(&format!("Host: {origin_host}:{origin_port}\r\n"));
    }
    if !body_bytes.is_empty() {
        out_head.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    out_head.push_str("Connection: close\r\n\r\n");

    let mut origin: OriginConn = match opts.origin_conn {
        Some(conn) => conn,
        None => {
            let s = TcpStream::connect((origin_host.as_str(), origin_port)).with_context(|| {
                format!("proxy could not reach origin {origin_host}:{origin_port}")
            })?;
            s.set_read_timeout(Some(Duration::from_secs(30)))?;
            s.set_write_timeout(Some(Duration::from_secs(30)))?;
            OriginConn::Plain(s)
        }
    };
    origin.write_all(out_head.as_bytes())?;
    origin.write_all(&body_bytes)?;

    // Read the response until EOF (Connection: close) with bounded capture.
    let mut resp_bytes: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match origin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp_bytes.extend_from_slice(&buf[..n]);
                if resp_bytes.len() > MAX_RESPONSE_CAPTURE {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let resp_str = String::from_utf8_lossy(&resp_bytes).into_owned();
    let (resp_head, resp_body) = resp_str
        .split_once("\r\n\r\n")
        .unwrap_or((resp_str.as_str(), ""));
    let status = resp_head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    stream.write_all(&resp_bytes)?;
    stream.flush()?;

    let entry = ProxyEntry {
        id: 0,
        ts_unix_ms: now_unix_ms(),
        kind: opts.kind.into(),
        method: method.to_string(),
        url: url.clone(),
        status,
        req_headers: headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\r\n"))
            .collect(),
        req_body: truncate_for_capture(&req_body, ctx.capture_limit),
        resp_headers: resp_head
            .lines()
            .skip(1)
            .map(|l| format!("{l}\r\n"))
            .collect(),
        resp_body: truncate_for_capture(resp_body, ctx.capture_limit),
        duration_ms: started.elapsed().as_millis(),
        replay_of: None,
    };
    ctx.record(entry, opts.kind != "http");
    Ok(())
}

fn tunnel(stream: &mut TcpStream, target: &str, ctx: &ConnCtx) -> Result<()> {
    if let Some(mitm) = &ctx.mitm {
        return tunnel_mitm(stream, target, mitm, ctx);
    }
    let started = Instant::now();
    match TcpStream::connect(target) {
        Ok(mut origin) => {
            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            stream.flush()?;
            // Transparent byte relay (TLS stays opaque by design) with bounded idle timeout
            // and symmetric Shutdown::Both so half-closed peers never deadlock `up.join()`.
            let idle = Some(Duration::from_secs(60));
            let _ = origin.set_read_timeout(idle);
            let _ = origin.set_write_timeout(idle);
            let _ = stream.set_read_timeout(idle);
            let _ = stream.set_write_timeout(idle);

            let mut up_stream = stream
                .try_clone()
                .with_context(|| "failed to clone client socket for tunnel")?;
            let mut up_origin = origin
                .try_clone()
                .with_context(|| "failed to clone origin socket for tunnel")?;
            let up_bytes = Arc::new(AtomicU64::new(0));
            let up_counter = Arc::clone(&up_bytes);
            let up = thread::spawn(move || {
                let n = std::io::copy(&mut up_stream, &mut up_origin).unwrap_or(0);
                up_counter.store(n as u64, Ordering::Relaxed);
                let _ = up_origin.shutdown(std::net::Shutdown::Both);
                let _ = up_stream.shutdown(std::net::Shutdown::Both);
            });
            let down = std::io::copy(&mut origin, stream).unwrap_or(0);
            let _ = origin.shutdown(std::net::Shutdown::Both);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let _ = up.join();
            let up_n = up_bytes.load(Ordering::Relaxed);

            let entry = ProxyEntry {
                id: 0,
                ts_unix_ms: now_unix_ms(),
                kind: "tls".into(),
                method: "CONNECT".into(),
                url: target.to_string(),
                status: 200,
                req_headers: String::new(),
                req_body: String::new(),
                resp_headers: String::new(),
                resp_body: format!(
                    "tunneled transparently: {up_n} bytes upstream, {down} bytes downstream"
                ),
                duration_ms: started.elapsed().as_millis(),
                replay_of: None,
            };
            ctx.record(entry, true);
            Ok(())
        }
        Err(e) => {
            let _ = stream.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            if let Ok(mut s) = ctx.summary.lock() {
                s.errors += 1;
            }
            bail!("CONNECT tunnel to {target} failed: {e}")
        }
    }
}

/// Parses a CONNECT target (`host:443`, `[::1]:443`, `127.0.0.1:8443`).
fn parse_connect_target(target: &str) -> Result<(String, u16)> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        bail!("CONNECT target '{target}' carries no port");
    };
    let port = port.trim().parse::<u16>().unwrap_or(443);
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        bail!("CONNECT target '{target}' carries no host");
    }
    Ok((host.to_string(), port))
}

/// Opt-in TLS termination of a CONNECT tunnel (`--mitm-ca`): presents an
/// on-the-fly local-CA leaf for the tunnel host, opens an upstream TLS
/// session, and supports HTTP/1.1 keep-alive (up to 32 sequential requests per
/// tunnel) plus WebSocket upgrade logging (`kind: "ws"`).
fn tunnel_mitm(stream: &mut TcpStream, target: &str, mitm: &MitmCa, ctx: &ConnCtx) -> Result<()> {
    let (host, port) = parse_connect_target(target)?;
    // The tunnel is established first; the TLS handshake happens over it.
    stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    stream.flush()?;
    let idle = Some(Duration::from_secs(60));
    let _ = stream.set_read_timeout(idle);
    let _ = stream.set_write_timeout(idle);

    let server_cfg = mitm.server_config_for(&host)?;
    let mut client_sock = stream
        .try_clone()
        .context("failed to clone client socket for MITM")?;
    let mut client_conn = rustls::ServerConnection::new(server_cfg)
        .map_err(|e| anyhow::anyhow!("MITM server TLS init failed: {e}"))?;
    crate::proxy_mitm::drive_client_handshake(&mut client_conn, &mut client_sock)?;
    let mut client_tls = rustls::StreamOwned::new(client_conn, client_sock);

    const MAX_KEEPALIVE_REQS: usize = 32;
    for req_idx in 0..MAX_KEEPALIVE_REQS {
        if req_idx > 0 {
            let _ = client_tls
                .sock
                .set_read_timeout(Some(Duration::from_millis(250)));
        }
        let (head, leftover) = match read_head(&mut client_tls) {
            Ok(pair) => pair,
            Err(_) if req_idx > 0 => break,
            Err(e) => return Err(e),
        };
        if req_idx > 0 {
            let _ = client_tls.sock.set_read_timeout(idle);
        }
        let request_line = head.lines().next().unwrap_or_default().trim().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_ascii_uppercase();
        let req_target = parts.next().unwrap_or("").to_string();
        if method.is_empty() || req_target.is_empty() {
            if req_idx > 0 {
                break;
            }
            bail!("malformed request inside CONNECT tunnel: {request_line:?}");
        }
        let head_low = head.to_ascii_lowercase();
        let client_wants_close = head_low.contains("connection: close");
        let is_ws_upgrade = head_low.contains("upgrade: websocket");

        let origin_tls = mitm.connect_upstream(&host, port)?;
        let origin = OriginConn::Tls(Box::new(origin_tls));
        let opts = InterceptOpts {
            scheme: "https",
            kind: if is_ws_upgrade { "ws" } else { "https" },
            origin_override: Some((host.as_str(), port)),
            origin_conn: Some(origin),
        };
        intercept_http(
            &mut client_tls,
            &head,
            leftover,
            &method,
            &req_target,
            ctx,
            opts,
        )?;
        if client_wants_close || is_ws_upgrade {
            break;
        }
    }
    // Graceful TLS teardown on the client side.
    client_tls.conn.send_close_notify();
    let _ = client_tls.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a complete HTTP request (head + Content-Length body). A single
    /// `read` is not enough: under parallel test load the head and body often
    /// arrive in separate TCP segments.
    fn read_full_request(sock: &mut TcpStream) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = sock.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + content_length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn origin_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..64 {
                let Ok((mut sock, _)) = listener.accept() else {
                    break;
                };
                let req = read_full_request(&mut sock);
                if req.starts_with("POST /echo ") {
                    let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
                    let out = format!("posted:{body}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                        out.len()
                    );
                    let _ = sock.write_all(resp.as_bytes());
                } else if req.starts_with("GET /hello ") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!";
                    let _ = sock.write_all(resp.as_bytes());
                } else {
                    let _ = sock.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        });
        port
    }

    fn send_via_proxy(proxy_addr: SocketAddr, raw: &str) -> String {
        let mut sock = TcpStream::connect(proxy_addr).unwrap();
        sock.write_all(raw.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn wait_entries(handle: &ProxyHandle, min: usize) {
        // Generous budget so the loopback engine threads still complete when
        // the whole workspace test suite runs in parallel.
        for _ in 0..100 {
            if handle.entries.lock().unwrap().len() >= min {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn test_config(jsonl_log: Option<PathBuf>) -> ProxyConfig {
        ProxyConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
            allow_remote_bind: false,
            jsonl_log,
            mitm: None,
        }
    }

    #[test]
    fn proxy_forwards_get_and_captures_entry() {
        let port = origin_server();
        let handle = start_proxy(test_config(None)).unwrap();
        let raw = format!(
            "GET http://127.0.0.1:{port}/hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept-Encoding: gzip\r\n\r\n"
        );
        let response = send_via_proxy(handle.bound_addr, &raw);
        assert!(response.contains("hello!"), "got: {response}");
        wait_entries(&handle, 1);
        let entries = handle.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "GET");
        assert_eq!(entries[0].status, 200);
        assert_eq!(entries[0].kind, "http");
        assert!(entries[0].resp_body.contains("hello!"));
        handle.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn proxy_forwards_post_body() {
        let port = origin_server();
        let handle = start_proxy(test_config(None)).unwrap();
        let body = "user=alice&pass=s3cret";
        let raw = format!(
            "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = send_via_proxy(handle.bound_addr, &raw);
        assert!(response.contains("posted:user=alice"), "got: {response}");
        wait_entries(&handle, 1);
        let entries = handle.entries.lock().unwrap();
        assert!(entries[0].req_body.contains("user=alice"));
        handle.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn connect_tunnel_is_logged_and_relays_bytes() {
        // A raw TCP echo endpoint acts as the tunneled origin.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut sock, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let n = sock.read(&mut buf).unwrap_or(0);
                let _ = sock.write_all(&buf[..n]);
            }
        });

        let handle = start_proxy(test_config(None)).unwrap();
        {
            let mut sock = TcpStream::connect(handle.bound_addr).unwrap();
            sock.write_all(format!("CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap();
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            assert!(head.contains("200 Connection established"), "got: {head}");
            sock.write_all(b"ping").unwrap();
            let mut echoed = [0u8; 4];
            let _ = sock.read_exact(&mut echoed);
            assert_eq!(&echoed, b"ping");
            // Dropping the socket ends both relay directions so the tunnel
            // entry is recorded by the engine.
        }
        wait_entries(&handle, 1);
        let entries = handle.entries.lock().unwrap();
        assert_eq!(entries[0].kind, "tls");
        assert_eq!(entries[0].method, "CONNECT");
        assert!(entries[0].resp_body.contains("tunneled"));
        handle.stop.store(true, Ordering::Relaxed);
    }

    /// A loopback HTTPS origin serving one hello response per TLS session with
    /// a self-signed certificate (exercises the MITM upstream fallback path).
    fn tls_origin_server() -> (u16, rustls::pki_types::CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_cfg = Arc::new(server_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut sock, _)) = listener.accept() else {
                    break;
                };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
                let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&server_cfg)) else {
                    continue;
                };
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!";
                let _ = tls.write_all(resp);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        (port, cert_der)
    }

    #[test]
    fn mitm_connect_decrypts_https_traffic() {
        use rustls::pki_types::pem::PemObject as _;
        let (tls_port, _origin_cert) = tls_origin_server();
        let ca_dir = std::env::temp_dir().join(format!("smg-proxy-mitm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ca_dir);
        let mitm = crate::proxy_mitm::MitmCa::load_or_create(&ca_dir).unwrap();
        let ca_der = rustls::pki_types::CertificateDer::from_pem_file(&mitm.cert_pem_path).unwrap();
        let handle = start_proxy(ProxyConfig {
            mitm: Some(Arc::new(mitm)),
            ..test_config(None)
        })
        .unwrap();

        // The client trusts only our local CA: validating the on-the-fly leaf
        // proves the rcgen signing + IP-literal SAN wiring end to end.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let mut ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();

        let mut sock = TcpStream::connect(handle.bound_addr).unwrap();
        sock.write_all(format!("CONNECT 127.0.0.1:{tls_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut established = [0u8; 128];
        let n = sock.read(&mut established).unwrap();
        let established = String::from_utf8_lossy(&established[..n]).into_owned();
        assert!(
            established.contains("200 Connection established"),
            "got: {established}"
        );

        let mut conn = rustls::ClientConnection::new(Arc::new(ccfg), name).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).unwrap();
        }
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        tls.flush().unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match tls.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
            }
        }
        drop(tls);
        let response = String::from_utf8_lossy(&response).into_owned();
        assert!(response.contains("hello!"), "got: {response}");

        wait_entries(&handle, 1);
        let entries = handle.entries.lock().unwrap();
        assert_eq!(entries[0].kind, "https");
        assert_eq!(entries[0].method, "GET");
        assert_eq!(entries[0].status, 200);
        assert!(entries[0].url.starts_with("https://127.0.0.1:"));
        assert!(entries[0].resp_body.contains("hello!"));
        handle.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&ca_dir);
    }

    #[test]
    fn refuses_non_loopback_bind_without_flag() {
        let err = start_proxy(ProxyConfig {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
            allow_remote_bind: false,
            jsonl_log: None,
            mitm: None,
        });
        assert!(err.is_err());
    }

    #[test]
    fn jsonl_log_receives_entries() {
        let port = origin_server();
        let log_path =
            std::env::temp_dir().join(format!("smg-proxy-log-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&log_path);
        let handle = start_proxy(test_config(Some(log_path.clone()))).unwrap();
        let raw =
            format!("GET http://127.0.0.1:{port}/hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let _ = send_via_proxy(handle.bound_addr, &raw);
        wait_entries(&handle, 1);
        handle.stop.store(true, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(300));
        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(content.contains("\"kind\":\"http\""), "log: {content}");
        let _ = std::fs::remove_file(&log_path);
    }
}
