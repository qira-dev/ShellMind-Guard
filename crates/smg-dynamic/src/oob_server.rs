//! Self-hosted out-of-band (OOB) callback listener for interactsh-style
//! Nuclei templates (`smg oob serve`, consumed via `smg templates --oob-server`).
//!
//! - TCP: catches ANY HTTP request (the path or Host header carries the
//!   per-run token) and records it. `GET /smg-check?token=` returns the JSON
//!   hits for that token so the templates engine can verify callbacks across
//!   process boundaries.
//! - UDP: records raw datagrams the same way (custom-protocol callbacks).
//! - The in-memory hit store is size-capped (drop-oldest) so a long-running
//!   server cannot grow without bound.
//! - Tokens are per-RUN random: `blake3(run_nonce || template_id || target)`.
//!   A fully deterministic token would let a previous run's hits false-match
//!   the next scan of the same target.

use anyhow::{Context, Result, bail};
use blake3::Hasher;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default loopback bind for `smg oob serve`.
pub const DEFAULT_OOB_LISTEN: &str = "127.0.0.1:8877";
const MAX_HITS: usize = 100_000;
const MAX_HIT_PAYLOAD: usize = 4096;
const MAX_HEAD: usize = 32 * 1024;
const MAX_CONCURRENT_TCP_CONNS: usize = 64;
const MAX_CHECK_HITS_RETURNED: usize = 64;
const MAX_CHECK_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

struct ActiveConnGuard(Arc<AtomicUsize>);
impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct OobHit {
    pub ts_unix_ms: u64,
    /// `tcp` (HTTP callback) or `udp` (raw datagram).
    pub proto: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub remote: String,
    /// Truncated payload (request line + headers for TCP, raw bytes for UDP).
    pub payload: String,
}

#[derive(Debug, Clone, Default)]
struct HitStore(Arc<Mutex<VecDeque<OobHit>>>);

impl HitStore {
    fn push(&self, log: &Option<Arc<Mutex<std::fs::File>>>, hit: OobHit) {
        if let Some(file) = log
            && let Ok(mut f) = file.lock()
        {
            use std::io::Write as _;
            let _ = f.write_all(
                format!(
                    "{line}\n",
                    line = serde_json::to_string(&hit).unwrap_or_default()
                )
                .as_bytes(),
            );
        }
        if let Ok(mut q) = self.0.lock() {
            if q.len() >= MAX_HITS {
                q.pop_front();
            }
            q.push_back(hit);
        }
    }

    fn matching(&self, token: &str) -> Vec<OobHit> {
        let Ok(q) = self.0.lock() else {
            return Vec::new();
        };
        q.iter()
            .filter(|h| {
                h.path.contains(token) || h.host.contains(token) || h.payload.contains(token)
            })
            .cloned()
            .collect()
    }
}

pub struct OobServerHandle {
    /// TCP listener (HTTP callbacks + `/smg-check` verification).
    pub bound_addr: SocketAddr,
    /// UDP listener (raw datagram callbacks). Equals `bound_addr` when the
    /// caller picks a fixed port; differs under port 0.
    pub udp_addr: SocketAddr,
    pub stop: Arc<AtomicBool>,
    store: HitStore,
    tcp_thread: Option<JoinHandle<()>>,
    udp_thread: Option<JoinHandle<()>>,
}

impl OobServerHandle {
    /// Blocks until `stop` is set (caller-driven shutdown), then joins both
    /// listener threads.
    pub fn wait_for_stop(mut self) {
        while !self.stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(150));
        }
        if let Some(t) = self.tcp_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.udp_thread.take() {
            let _ = t.join();
        }
    }

    /// Callback hits whose path/host/payload contain `token` (test/inspection
    /// surface; the templates engine queries the listener over HTTP instead).
    #[allow(dead_code)]
    pub fn matching(&self, token: &str) -> Vec<OobHit> {
        self.store.matching(token)
    }
}

/// Starts the TCP + UDP callback listeners. Both share one hit store.
pub fn start_oob_server(listen: SocketAddr, log_path: Option<PathBuf>) -> Result<OobServerHandle> {
    if !listen.ip().is_loopback() {
        bail!(
            "Refusing to bind non-loopback OOB listener {listen}; the callback plane is loopback-only by default."
        );
    }
    let tcp_listener = TcpListener::bind(listen)
        .with_context(|| format!("failed to bind OOB TCP listener on {listen}"))?;
    let bound_addr = tcp_listener.local_addr()?;
    let preferred_udp = SocketAddr::new(bound_addr.ip(), bound_addr.port());
    let udp_sock = UdpSocket::bind(preferred_udp)
        .or_else(|_| UdpSocket::bind(listen))
        .with_context(|| format!("failed to bind OOB UDP listener on {listen}"))?;
    let udp_addr = udp_sock.local_addr()?;
    tcp_listener.set_nonblocking(true)?;
    udp_sock.set_nonblocking(true)?;

    let log: Option<Arc<Mutex<std::fs::File>>> = match log_path {
        Some(p) => {
            if let Ok(meta) = std::fs::symlink_metadata(&p)
                && meta.file_type().is_symlink()
            {
                bail!("Refusing to write OOB log to symlink {}", p.display());
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let file = opts
                .open(&p)
                .with_context(|| format!("failed to open OOB JSONL log at {}", p.display()))?;
            Some(Arc::new(Mutex::new(file)))
        }
        None => None,
    };

    let store = HitStore::default();
    let stop = Arc::new(AtomicBool::new(false));
    let active_conns = Arc::new(AtomicUsize::new(0));

    let tcp_store = store.clone();
    let tcp_log = log.clone();
    let tcp_stop = Arc::clone(&stop);
    let tcp_active = Arc::clone(&active_conns);
    let tcp_thread = thread::spawn(move || {
        // Phase 2 (Q97): Per-IP sliding-window rate limiter preventing single-peer callback floods.
        const MAX_OOB_HITS_PER_IP_PER_SEC: usize = 100;
        let mut ip_window: std::collections::HashMap<
            std::net::IpAddr,
            (std::time::Instant, usize),
        > = std::collections::HashMap::new();
        loop {
            if tcp_stop.load(Ordering::Relaxed) {
                break;
            }
            match tcp_listener.accept() {
                Ok((mut stream, peer)) => {
                    let now = std::time::Instant::now();
                    let entry = ip_window.entry(peer.ip()).or_insert((now, 0));
                    if now.duration_since(entry.0) >= Duration::from_secs(1) {
                        *entry = (now, 1);
                    } else {
                        entry.1 = entry.1.saturating_add(1);
                        if entry.1 > MAX_OOB_HITS_PER_IP_PER_SEC {
                            drop(stream);
                            continue;
                        }
                    }
                    if ip_window.len() > 4096 {
                        ip_window
                            .retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(5));
                    }
                    let prev = tcp_active.fetch_add(1, Ordering::AcqRel);
                    if prev >= MAX_CONCURRENT_TCP_CONNS {
                        tcp_active.fetch_sub(1, Ordering::AcqRel);
                        drop(stream);
                        continue;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let store = tcp_store.clone();
                    let log = tcp_log.clone();
                    let guard = ActiveConnGuard(Arc::clone(&tcp_active));
                    thread::spawn(move || {
                        let _guard = guard;
                        handle_tcp_callback(&mut stream, peer, &store, &log);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    let udp_store = store.clone();
    let udp_log = log.clone();
    let udp_stop = Arc::clone(&stop);
    let udp_thread = thread::spawn(move || {
        let mut buf = [0u8; MAX_HIT_PAYLOAD];
        loop {
            if udp_stop.load(Ordering::Relaxed) {
                break;
            }
            match udp_sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let payload = String::from_utf8_lossy(&buf[..n]).into_owned();
                    udp_store.push(
                        &udp_log,
                        OobHit {
                            ts_unix_ms: now_unix_ms(),
                            proto: "udp".into(),
                            method: "-".into(),
                            path: "-".into(),
                            host: peer.to_string(),
                            remote: peer.to_string(),
                            payload: payload.chars().take(MAX_HIT_PAYLOAD).collect(),
                        },
                    );
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    Ok(OobServerHandle {
        bound_addr,
        udp_addr,
        stop,
        store,
        tcp_thread: Some(tcp_thread),
        udp_thread: Some(udp_thread),
    })
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Reads one HTTP-ish head and either records the callback or answers a
/// `/smg-check` verification query.
fn handle_tcp_callback(
    stream: &mut TcpStream,
    peer: SocketAddr,
    store: &HitStore,
    log: &Option<Arc<Mutex<std::fs::File>>>,
) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > MAX_HEAD {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let req = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("").trim().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let raw_path = parts.next().unwrap_or("/").to_string();
    let host = req
        .lines()
        .skip(1)
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("host")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_default();

    if raw_path.starts_with("/smg-check") {
        let token = raw_path
            .split_once('?')
            .and_then(|(_, q)| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("token=").map(|t| t.trim().to_string()))
            })
            .unwrap_or_default();
        let is_valid_token = token.len() >= 12
            && token.len() <= 64
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let hits: Vec<OobHit> = if !is_valid_token {
            Vec::new()
        } else {
            store
                .matching(&token)
                .into_iter()
                .filter(|h| {
                    if h.proto == "tcp" {
                        h.path.contains(&token) || h.host.contains(&token)
                    } else {
                        h.payload.contains(&token)
                    }
                })
                .take(MAX_CHECK_HITS_RETURNED)
                .collect()
        };
        let body = serde_json::to_string(&serde_json::json!({ "hits": hits }))
            .unwrap_or_else(|_| "{\"hits\":[]}".into());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = std::io::Write::write_all(stream, resp.as_bytes());
        return;
    }

    store.push(
        log,
        OobHit {
            ts_unix_ms: now_unix_ms(),
            proto: "tcp".into(),
            method,
            path: raw_path.chars().take(2048).collect(),
            host,
            remote: peer.to_string(),
            payload: req.chars().take(MAX_HIT_PAYLOAD).collect(),
        },
    );
    let _ = std::io::Write::write_all(
        stream,
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsmg-oob\n",
    );
}

// ---------------------------------------------------------------------------
// Client side (templates engine)
// ---------------------------------------------------------------------------

/// 16 bytes of cross-platform OS CSPRNG entropy (via `rustls::crypto::ring::default_provider().secure_random`).
pub fn run_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    if rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .is_ok()
    {
        return nonce;
    }
    if let Ok(mut f) = std::fs::File::open("/dev/urandom")
        && f.read_exact(&mut nonce).is_ok()
    {
        return nonce;
    }
    static FALLBACK_COUNTER: AtomicUsize = AtomicUsize::new(1);
    let seq = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Hasher::new();
    h.update(&nanos.to_le_bytes());
    h.update(&std::process::id().to_le_bytes());
    h.update(&seq.to_le_bytes());
    nonce.copy_from_slice(&h.finalize().as_bytes()[..16]);
    nonce
}

/// Per-run token: `blake3(run_nonce || template_id || target)`, first 16 hex.
pub fn token_for(nonce: &[u8; 16], template_id: &str, target: &str) -> String {
    let mut h = Hasher::new();
    h.update(nonce);
    h.update(template_id.as_bytes());
    h.update(target.as_bytes());
    let hex = h.finalize().to_hex();
    hex.as_bytes()[..16].iter().map(|b| *b as char).collect()
}

/// Client handle for one templates run against one OOB server.
pub struct OobClient {
    /// `http://host:port`
    base: String,
    /// `host:port` for `{{interactsh-host}}`.
    pub host: String,
    nonce: [u8; 16],
    client: reqwest::blocking::Client,
}

impl OobClient {
    /// Accepts `host:port` or a full `http://host:port` spec.
    pub fn from_server_spec(spec: &str) -> Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            bail!("empty --oob-server spec");
        }
        let (host, base) = if let Some(rest) = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("https://"))
        {
            (
                rest.trim_end_matches('/').to_string(),
                trimmed.trim_end_matches('/').to_string(),
            )
        } else {
            (trimmed.to_string(), format!("http://{trimmed}"))
        };
        if !host.contains(':') {
            bail!("--oob-server spec '{spec}' must carry a port (host:port)");
        }
        // Unconditionally deny IMDS/link-local/unspecified/embedded-cred OOB specs (Council T5).
        let parsed = crate::idor_audit::validate_live_target_url(&base, true)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("--oob-server must use http:// or https://");
        }
        crate::idor_audit::ensure_rustls_ring_provider();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            base,
            host,
            nonce: run_nonce(),
            client,
        })
    }

    pub fn token_for_target(&self, template_id: &str, target: &str) -> String {
        token_for(&self.nonce, template_id, target)
    }

    /// The full callback URL substituted into `{{interactsh-url}}`.
    pub fn url_for(&self, template_id: &str, target: &str) -> String {
        format!(
            "{}/{}",
            self.base,
            self.token_for_target(template_id, target)
        )
    }

    /// Queries the listener for callbacks carrying this run's token.
    pub fn check(&self, token: &str) -> Result<Vec<OobHit>> {
        // Tokens are blake3 hex, so direct URL interpolation is safe.
        let resp = self
            .client
            .get(format!("{}/smg-check?token={token}", self.base))
            .send()?;
        let status = resp.status();
        let mut raw = Vec::new();
        resp.take(MAX_CHECK_RESPONSE_BYTES)
            .read_to_end(&mut raw)
            .with_context(|| {
                format!(
                    "reading /smg-check response (HTTP {status}) from {}",
                    self.base
                )
            })?;
        let body: serde_json::Value = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "parsing /smg-check response (HTTP {status}) from {}",
                self.base
            )
        })?;
        let hits = body
            .get("hits")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|h| serde_json::from_value::<OobHit>(h.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(hits)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_per_run_and_stable_within_a_run() {
        let t1 = token_for(&run_nonce(), "tpl-a", "http://127.0.0.1:8080");
        let t2 = token_for(&run_nonce(), "tpl-a", "http://127.0.0.1:8080");
        assert_eq!(t1.len(), 16);
        assert_ne!(t1, t2, "a new run nonce must change the token");
        let client = OobClient::from_server_spec("127.0.0.1:8877").unwrap();
        assert_eq!(
            client.token_for_target("tpl-a", "http://127.0.0.1:8080"),
            client.token_for_target("tpl-a", "http://127.0.0.1:8080"),
            "stable within one run"
        );
        assert_ne!(
            client.token_for_target("tpl-a", "http://127.0.0.1:8080"),
            client.token_for_target("tpl-b", "http://127.0.0.1:8080"),
            "distinct per template"
        );
    }

    #[test]
    fn tcp_callback_is_recorded_and_check_returns_it() {
        let handle = start_oob_server("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let addr = handle.bound_addr;
        let token = "toktcp1234567";
        {
            let mut sock = TcpStream::connect(addr).unwrap();
            let req = format!(
                "GET /{token}?x=1 HTTP/1.1\r\nHost: {token}.oob.test\r\nConnection: close\r\n\r\n"
            );
            std::io::Write::write_all(&mut sock, req.as_bytes()).unwrap();
            let mut buf = [0u8; 128];
            let _ = std::io::Read::read(&mut sock, &mut buf);
        }
        // Under parallel test load the listener threads may lag; poll briefly.
        let client = OobClient::from_server_spec(&addr.to_string()).unwrap();
        let mut hits = Vec::new();
        for _ in 0..50 {
            hits = client.check(token).unwrap_or_default();
            if !hits.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].proto, "tcp");
        assert!(hits[0].path.contains(token));
        assert!(client.check("missing-token-xyz").unwrap().is_empty());
        handle.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn udp_datagram_is_recorded() {
        let handle = start_oob_server("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"tokudp12345678 payload", handle.udp_addr)
            .unwrap();
        let mut hits = Vec::new();
        for _ in 0..50 {
            hits = handle.matching("tokudp12345678");
            if !hits.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].proto, "udp");
        assert!(hits[0].payload.contains("tokudp12345678"));
        handle.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn hit_store_matches_and_keeps_order() {
        let store = HitStore::default();
        for i in 0..50usize {
            store.push(
                &None,
                OobHit {
                    ts_unix_ms: i as u64,
                    proto: "tcp".into(),
                    method: "GET".into(),
                    path: format!("/{i}"),
                    host: String::new(),
                    remote: "127.0.0.1:1".into(),
                    payload: format!("hit-{i}"),
                },
            );
        }
        assert_eq!(store.matching("hit-0").len(), 1);
        assert_eq!(store.matching("hit-49").len(), 1);
        assert!(store.matching("hit-not-there").is_empty());
    }

    #[test]
    fn refuses_non_loopback_bind() {
        let err = start_oob_server("0.0.0.0:0".parse().unwrap(), None);
        assert!(err.is_err());
    }

    #[test]
    fn oob_client_rejects_imds_and_credentials() {
        assert!(OobClient::from_server_spec("169.254.169.254:80").is_err());
        assert!(OobClient::from_server_spec("http://[fd00:ec2::254]:80").is_err());
        assert!(OobClient::from_server_spec("http://user:pass@127.0.0.1:8877").is_err());
    }
}
