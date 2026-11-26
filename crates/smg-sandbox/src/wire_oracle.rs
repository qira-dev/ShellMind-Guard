use crate::verifier::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, send_http_probe_with_tls,
};
use anyhow::Result;
use smg_graph::{LatticeFinding, ParamTypeHint, RouteSchema};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

static OOB_TOKEN_SEQ: AtomicUsize = AtomicUsize::new(1);

/// Ephemeral `127.0.0.1` HTTP listener capturing blind SSRF/XXE out-of-band callbacks
/// inside `--unshare-net` or loopback test harnesses without touching external networks.
pub struct OobSsrfCatcher {
    pub port: u16,
    pub token: String,
    hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl OobSsrfCatcher {
    pub async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let seq = OOB_TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
        let token = format!("smg-oob-{}-{}", std::process::id(), seq);
        let expected_path = format!("/__smg_oob/{}", token);
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits_req = Arc::clone(&hits_srv);
                let needle = expected_path.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains(&needle) {
                        hits_req.fetch_add(1, Ordering::SeqCst);
                    }
                    let body = r#"{"smg_oob":"ok"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        Ok(Self {
            port,
            token,
            hits,
            task,
        })
    }

    pub fn callback_url(&self) -> String {
        format!("http://127.0.0.1:{}/__smg_oob/{}", self.port, self.token)
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for OobSsrfCatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Cross-OS bidirectional loopback TCP proxy recording SQL/Redis mutation frames (`INSERT`, `UPDATE`, `DELETE`, `SET`, `INCR`, `DECR`)
/// to distinguish real state mutations from idempotent HTTP 200 retries.
pub struct WireDiffProxy {
    pub listen_port: u16,
    write_mutations: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl WireDiffProxy {
    pub async fn spawn(upstream_port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let listen_port = listener.local_addr()?.port();
        let write_mutations = Arc::new(AtomicUsize::new(0));
        let writes_srv = Arc::clone(&write_mutations);

        let task = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let writes_conn = Arc::clone(&writes_srv);
                tokio::spawn(async move {
                    let Ok(upstream) = TcpStream::connect(("127.0.0.1", upstream_port)).await
                    else {
                        return;
                    };
                    let (mut cr, mut cw) = client.into_split();
                    let (mut ur, mut uw) = upstream.into_split();

                    let c2u = async move {
                        let mut buf = [0u8; 8192];
                        while let Ok(n) = cr.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            let payload = String::from_utf8_lossy(&buf[..n]).to_ascii_uppercase();
                            if payload.contains("INSERT ")
                                || payload.contains("UPDATE ")
                                || payload.contains("DELETE ")
                                || payload.contains("DECR")
                                || payload.contains("INCR")
                                || payload.contains("\r\nSET\r\n")
                            {
                                writes_conn.fetch_add(1, Ordering::SeqCst);
                            }
                            if uw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = uw.shutdown().await;
                    };
                    let u2c = async move {
                        let mut buf = [0u8; 8192];
                        while let Ok(n) = ur.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            if cw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = cw.shutdown().await;
                    };
                    let _ = tokio::join!(c2u, u2c);
                });
            }
        });

        Ok(Self {
            listen_port,
            write_mutations,
            task,
        })
    }

    pub fn write_mutations(&self) -> usize {
        self.write_mutations.load(Ordering::SeqCst)
    }
}

impl Drop for WireDiffProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Captures non-symlink BLAKE3 digests inside a temp workspace/DB directory before vs after sandbox probing.
/// Checks file metadata size (`<= 4 MiB` per file, `<= 64 MiB` and `<= 2048` files total) *before* reading.
pub fn capture_fs_digests(root: &Path) -> BTreeMap<String, String> {
    const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_FILES: usize = 2048;

    let mut map = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if map.len() >= MAX_FILES || total_bytes >= MAX_TOTAL_BYTES {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in entries.flatten() {
            if map.len() >= MAX_FILES || total_bytes >= MAX_TOTAL_BYTES {
                break;
            }
            let Ok(ft) = ent.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let p = ent.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file()
                && let Ok(meta) = std::fs::symlink_metadata(&p)
                && meta.is_file()
                && meta.len() <= MAX_FILE_BYTES
                && total_bytes.saturating_add(meta.len()) <= MAX_TOTAL_BYTES
                && let Ok(rel) = p.strip_prefix(root)
                && let Ok(f) = std::fs::File::open(&p)
            {
                use std::io::Read;
                let mut bytes = Vec::with_capacity(meta.len().min(MAX_FILE_BYTES) as usize);
                if f.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).is_ok()
                    && (bytes.len() as u64) <= MAX_FILE_BYTES
                {
                    total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                    map.insert(
                        rel.to_string_lossy().replace('\\', "/"),
                        blake3::hash(&bytes).to_hex().to_string(),
                    );
                }
            }
        }
    }
    map
}

/// Lists modified or newly written relative file paths between two `capture_fs_digests` snapshots.
pub fn diff_fs_digests(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut keys: HashSet<&String> = before.keys().collect();
    keys.extend(after.keys());
    let mut changed: Vec<String> = keys
        .into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect();
    changed.sort();
    changed
}

fn route_paths_equivalent(entry_route: &str, schema: &RouteSchema) -> bool {
    let mut parts = entry_route.split_whitespace();
    let method = parts.next().unwrap_or("POST");
    let raw_path = parts.next().unwrap_or("/");
    if !schema.method.eq_ignore_ascii_case(method) && schema.method != "ANY" {
        return false;
    }
    let a: Vec<&str> = raw_path.split('/').filter(|s| !s.is_empty()).collect();
    let b: Vec<&str> = schema.path.split('/').filter(|s| !s.is_empty()).collect();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        x.eq_ignore_ascii_case(y)
            || x.starts_with(':')
            || x.starts_with('{')
            || y.starts_with(':')
            || y.starts_with('{')
    })
}

/// Zero-LLM `<1ms` schema-driven PoC JSON synthesizer so auth/race probes clear DTO validation.
pub fn synthesize_schema_poc_body(
    finding: &LatticeFinding,
    schemas: &[RouteSchema],
) -> Option<String> {
    let schema = schemas
        .iter()
        .find(|s| route_paths_equivalent(&finding.entry_route, s))?;
    if schema.params.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    for p in &schema.params {
        if p.location == "path" {
            continue;
        }
        let low_name = p.name.to_ascii_lowercase();
        let val = match p.type_hint {
            ParamTypeHint::Number => serde_json::json!(if p.is_financial { 25.0 } else { 10.0 }),
            ParamTypeHint::Integer => serde_json::json!(if p.is_financial { 25 } else { 1 }),
            ParamTypeHint::Boolean => serde_json::json!(true),
            ParamTypeHint::String | ParamTypeHint::Unknown => {
                if p.is_financial {
                    serde_json::json!(25)
                } else if low_name.contains("email") {
                    serde_json::json!("smg-probe@localhost.invalid")
                } else if low_name.contains("uuid") || low_name.ends_with("_id") || low_name == "id"
                {
                    serde_json::json!("550e8400-e29b-41d4-a716-446655440000")
                } else if low_name.contains("url")
                    || low_name.contains("callback")
                    || low_name.contains("webhook")
                {
                    serde_json::json!("http://127.0.0.1:80/probe")
                } else {
                    serde_json::json!("smg-probe-value")
                }
            }
        };
        map.insert(p.name.clone(), val);
    }
    if map.is_empty() {
        return None;
    }
    Some(serde_json::Value::Object(map).to_string())
}

/// Active loopback OOB SSRF oracle: injects an ephemeral `127.0.0.1` callback URL and marks
/// `PROVEN` only when the target server actually connects back to the unique canary token.
pub async fn verify_ssrf_oob_with_config(
    port: u16,
    finding: &LatticeFinding,
    cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    let catcher = OobSsrfCatcher::spawn().await?;
    let oob_url = catcher.callback_url();

    let mut parts = finding.entry_route.split_whitespace();
    let method = parts.next().unwrap_or("POST");
    let raw_path = parts.next().unwrap_or("/");
    let clean_path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{}", raw_path)
    };
    let sep = if clean_path.contains('?') { '&' } else { '?' };
    let path_with_query = format!("{}{}url={}", clean_path, sep, oob_url);
    let body = serde_json::json!({
        "url": oob_url,
        "targetUrl": oob_url,
        "callback": oob_url,
        "webhook": oob_url
    })
    .to_string();

    let res = send_http_probe_with_tls(
        port,
        method,
        &path_with_query,
        cfg.user_a_header.as_deref(),
        if matches!(method, "GET" | "HEAD") {
            None
        } else {
            Some(body.as_bytes())
        },
        cfg.use_tls,
    )
    .await;

    // Brief yield to capture asynchronous outbound callback inside loopback
    sleep(Duration::from_millis(40)).await;
    let oob_hits = catcher.hits();

    let (status, evidence) = if oob_hits > 0 {
        (
            VerificationStatus::Proven,
            format!(
                "OOB Blind SSRF confirmed: target performed {} loopback HTTP callback(s) to {}",
                oob_hits, oob_url
            ),
        )
    } else if let Ok((code, _, _)) = res
        && matches!(code, 400 | 401 | 403 | 422)
    {
        (
            VerificationStatus::Mitigated,
            format!(
                "Target rejected SSRF callback URL with HTTP {} (0 OOB hits)",
                code
            ),
        )
    } else {
        (
            VerificationStatus::SuspectUnverified,
            "OOB SSRF probe dispatched with 0 confirmed loopback callback hits".into(),
        )
    };

    Ok(VerifiedFinding {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        entry_route: finding.entry_route.clone(),
        status,
        evidence,
        replay_cmd: format!("smg replay {}", finding.id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smg_graph::{Confidence, GuardKind, RouteParamSpec, SinkKind};

    #[tokio::test]
    async fn test_oob_ssrf_catcher_wire_proxy_and_schema_poc_synthesis() {
        // 1. OOB SSRF catcher + live vulnerable loopback forwarder vs allowlist-mitigated handler
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let app_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if let Some(body_start) = req.find("\r\n\r\n")
                            && let Ok(val) =
                                serde_json::from_str::<serde_json::Value>(&req[body_start + 4..])
                            && let Some(url) = val.get("url").and_then(|u| u.as_str())
                            && let Some(addr_and_path) = url.strip_prefix("http://")
                            && let Some((host_port, path)) = addr_and_path.split_once('/')
                        {
                            if let Ok(mut cb) = TcpStream::connect(host_port).await {
                                let cb_req = format!(
                                    "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                                    path, host_port
                                );
                                let _ = cb.write_all(cb_req.as_bytes()).await;
                                let _ = cb.flush().await;
                            }
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else {
                            let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\nblocked";
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                    });
                }
            }
        });

        let ssrf_finding = LatticeFinding {
            id: "SMG-SSRF-001".into(),
            rule_id: "SMG-SSRF-001".into(),
            severity: "HIGH".into(),
            title: "SSRF in webhook fetch".into(),
            file: "src/hook.ts".into(),
            line: 10,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "POST /api/fetch".into(),
            sink_kind: SinkKind::Ssrf,
            missing_guard: GuardKind::SsrfSanitizer,
            witness_path: Vec::new(),
            remediation: String::new(),
            proof_reasons: Vec::new(),
        };
        let proven =
            verify_ssrf_oob_with_config(app_port, &ssrf_finding, &SandboxProbeConfig::default())
                .await
                .unwrap();
        assert_eq!(proven.status, VerificationStatus::Proven);
        assert!(proven.evidence.contains("callback(s)"));

        let blocked = verify_ssrf_oob_with_config(
            app_port,
            &LatticeFinding {
                entry_route: "GET /api/blocked".into(),
                ..ssrf_finding.clone()
            },
            &SandboxProbeConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(blocked.status, VerificationStatus::Mitigated);

        // 2. WireDiffProxy counts SQL mutation frames cleanly
        let db_srv = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let db_port = db_srv.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = db_srv.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"OK").await;
            }
        });
        let proxy = WireDiffProxy::spawn(db_port).await.unwrap();
        for _ in 0..2 {
            let mut client = TcpStream::connect(("127.0.0.1", proxy.listen_port))
                .await
                .unwrap();
            client
                .write_all(b"UPDATE accounts SET balance = balance - 10;")
                .await
                .unwrap();
            let mut ack = [0u8; 8];
            let _ = client.read(&mut ack).await;
        }
        assert_eq!(proxy.write_mutations(), 2);

        // 3. Schema-driven `<1ms` PoC body synthesizer
        let schemas = vec![RouteSchema {
            method: "POST".into(),
            path: "/api/transfer".into(),
            source_file: "src/pay.ts".into(),
            line: 5,
            params: vec![
                RouteParamSpec {
                    name: "email".into(),
                    location: "body".into(),
                    type_hint: ParamTypeHint::String,
                    is_financial: false,
                    has_positive_bound: false,
                },
                RouteParamSpec {
                    name: "amount".into(),
                    location: "body".into(),
                    type_hint: ParamTypeHint::Number,
                    is_financial: true,
                    has_positive_bound: true,
                },
            ],
            ..Default::default()
        }];
        let synthesized = synthesize_schema_poc_body(
            &LatticeFinding {
                entry_route: "POST /api/transfer".into(),
                ..ssrf_finding
            },
            &schemas,
        )
        .unwrap();
        assert!(synthesized.contains("smg-probe@localhost.invalid"));
        assert!(synthesized.contains("25.0"));
    }
}
