use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vf_core::{
    AdvisoryRecord, AdvisoryStore, Language, ShellMindGuardConfig, parse_osv_value_into_records,
    scan_repository,
};
use vf_graph::deps::{ResolvedDependency, extract_resolved_dependencies};

pub const DEFAULT_OSV_BASE_URL: &str = "https://api.osv.dev";
const QUERYBATCH_CHUNK_SIZE: usize = 500;
const OSV_HTTP_TIMEOUT_SECS: u64 = 30;
static RUSTLS_INIT: Once = Once::new();

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DepsSyncSummary {
    pub dependencies_queried: usize,
    pub unique_vulns_fetched: usize,
    pub records_upserted: usize,
}

fn ensure_rustls_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Validates the OSV endpoint URL, enforcing HTTPS for all remote hosts and
/// permitting plain HTTP only for loopback test endpoints.
pub fn validate_osv_base_url(base_url: &str) -> Result<reqwest::Url> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        bail!("OSV base URL must not be empty");
    }
    let url = reqwest::Url::parse(trimmed)
        .with_context(|| format!("Invalid OSV base URL '{}'", trimmed))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("OSV base URL must not embed credentials");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("OSV base URL '{}' is missing host", trimmed))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_host(host) => Ok(url),
        "http" => bail!(
            "Remote OSV endpoint '{}' must use https:// (http:// is allowed only on loopback hosts)",
            host
        ),
        other => bail!("Unsupported OSV URL scheme '{}'", other),
    }
}

fn build_osv_http_client() -> Result<reqwest::blocking::Client> {
    ensure_rustls_provider();
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(OSV_HTTP_TIMEOUT_SECS))
        .user_agent("shellmind-guard/0.1")
        .build()
        .context("Failed to initialize HTTPS/TLS client for OSV sync")
}

fn to_osv_ecosystem(eco: &str) -> &str {
    let norm = eco.trim().to_ascii_lowercase();
    match norm.as_str() {
        "npm" => "npm",
        "pypi" | "pip" | "python" => "PyPI",
        "crates.io" | "cargo" | "rust" => "crates.io",
        "go" | "golang" => "Go",
        _ => eco.trim(),
    }
}

fn is_safe_vuln_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
        && id.len() <= 128
}

fn append_endpoint_segments(base: &reqwest::Url, segments: &[&str]) -> Result<reqwest::Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("OSV base URL '{}' cannot contain path segments", base))?;
        path.pop_if_empty();
        for seg in segments {
            path.push(seg);
        }
    }
    Ok(url)
}

/// Scans `root` offline for supported lockfiles/manifests and returns deduplicated
/// resolved `(ecosystem, name, version)` dependency tuples.
pub fn extract_project_dependencies(
    root: &Path,
    cfg: &ShellMindGuardConfig,
) -> Result<Vec<ResolvedDependency>> {
    let summary = scan_repository(root, cfg)?;
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut deps = Vec::new();

    for file in &summary.files {
        if file.language != Language::Manifest {
            continue;
        }
        let content = match &file.cached_bytes {
            Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            None => match fs::read_to_string(&file.abs_path) {
                Ok(text) => text,
                Err(_) => continue,
            },
        };
        for dep in extract_resolved_dependencies(&file.rel_path, &content) {
            let key = (
                dep.ecosystem.to_ascii_lowercase(),
                dep.name.to_ascii_lowercase(),
                dep.version.clone(),
            );
            if seen.insert(key) {
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

/// Queries OSV `/v1/querybatch` + `/v1/vulns/<id>` for `deps` and upserts parsed
/// vulnerability records into the local SQLite `AdvisoryStore`.
pub fn sync_osv_to_store(
    osv_base_url: &str,
    deps: &[ResolvedDependency],
    store: &mut AdvisoryStore,
) -> Result<DepsSyncSummary> {
    let base_url = validate_osv_base_url(osv_base_url)?;
    if deps.is_empty() {
        return Ok(DepsSyncSummary::default());
    }

    let client = build_osv_http_client()?;
    let querybatch_url = append_endpoint_segments(&base_url, &["v1", "querybatch"])?;
    let mut unique_ids: BTreeSet<String> = BTreeSet::new();

    for chunk in deps.chunks(QUERYBATCH_CHUNK_SIZE) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|d| {
                json!({
                    "version": d.version,
                    "package": {
                        "name": d.name,
                        "ecosystem": to_osv_ecosystem(&d.ecosystem),
                    }
                })
            })
            .collect();

        let resp = client
            .post(querybatch_url.clone())
            .json(&json!({ "queries": queries }))
            .send()
            .with_context(|| format!("OSV querybatch request to '{}' failed", querybatch_url))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!(
                "OSV querybatch endpoint returned HTTP {} ({} bytes)",
                status.as_u16(),
                body.len()
            );
        }

        let parsed: Value =
            serde_json::from_str(&body).context("OSV querybatch returned non-JSON response")?;
        if let Some(results) = parsed.get("results").and_then(Value::as_array) {
            for item in results {
                if let Some(vulns) = item.get("vulns").and_then(Value::as_array) {
                    for v in vulns {
                        if let Some(id) = v.get("id").and_then(Value::as_str) {
                            let clean_id = id.trim();
                            if is_safe_vuln_id(clean_id) {
                                unique_ids.insert(clean_id.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut records: Vec<AdvisoryRecord> = Vec::new();
    for vuln_id in &unique_ids {
        let vuln_url = append_endpoint_segments(&base_url, &["v1", "vulns", vuln_id])?;
        let resp = client
            .get(vuln_url.clone())
            .send()
            .with_context(|| format!("OSV vuln fetch for '{}' failed", vuln_id))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!(
                "OSV vuln endpoint returned HTTP {} for '{}'",
                status.as_u16(),
                vuln_id
            );
        }
        let val: Value = serde_json::from_str(&body)
            .with_context(|| format!("OSV vuln '{}' returned invalid JSON", vuln_id))?;
        let mut parsed_records = parse_osv_value_into_records(&val, now_epoch)?;
        records.append(&mut parsed_records);
    }

    let records_upserted = store.upsert_advisories(&records)?;

    Ok(DepsSyncSummary {
        dependencies_queried: deps.len(),
        unique_vulns_fetched: unique_ids.len(),
        records_upserted,
    })
}

/// Imports an offline OSV JSON bundle/entry file into the SQLite `AdvisoryStore`.
pub fn import_osv_file_to_store(file: &Path, store: &mut AdvisoryStore) -> Result<usize> {
    let raw = fs::read_to_string(file)
        .with_context(|| format!("Failed to read OSV JSON file {}", file.display()))?;
    store
        .import_osv_json(&raw)
        .with_context(|| format!("Failed to import OSV records from {}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use vf_graph::deps::scan_dependencies_with_store;

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut temp = [0u8; 4096];
        let mut content_len = 0usize;
        let mut header_end = None;

        loop {
            let n = stream.read(&mut temp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&temp[..n]);
            if header_end.is_none()
                && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let end = pos + 4;
                header_end = Some(end);
                let headers = String::from_utf8_lossy(&buf[..end]);
                for line in headers.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            if let Some(end) = header_end
                && buf.len() >= end + content_len
            {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn test_validate_osv_base_url_blocks_remote_http_and_credentials() {
        assert!(validate_osv_base_url("https://api.osv.dev").is_ok());
        assert!(validate_osv_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_osv_base_url("http://localhost:8080").is_ok());
        assert!(validate_osv_base_url("http://[::1]:8080").is_ok());

        assert!(validate_osv_base_url("http://api.osv.dev").is_err());
        assert!(validate_osv_base_url("https://user:pass@api.osv.dev").is_err());
        assert!(validate_osv_base_url("file:///etc/passwd").is_err());
        assert!(validate_osv_base_url("").is_err());
    }

    #[test]
    fn test_osv_sync_from_mock_server_and_matches_poetry_lock_offline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let req = read_http_request(&mut stream);
                let first_line = req.lines().next().unwrap_or("");
                let (status, body) = if first_line.starts_with("POST /v1/querybatch ") {
                    assert!(req.contains("\"PyPI\""));
                    assert!(req.contains("\"requests\""));
                    assert!(req.contains("\"2.28.0\""));
                    (
                        "200 OK",
                        r#"{"results":[{"vulns":[{"id":"PYSEC-2023-74"}]}]}"#,
                    )
                } else if first_line.starts_with("GET /v1/vulns/PYSEC-2023-74 ") {
                    (
                        "200 OK",
                        r#"{
                            "id": "PYSEC-2023-74",
                            "summary": "Unintended leak of Proxy-Authorization header in requests",
                            "database_specific": { "severity": "MEDIUM" },
                            "affected": [{
                                "package": { "ecosystem": "PyPI", "name": "requests" },
                                "ranges": [{
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        { "introduced": "2.3.0" },
                                        { "fixed": "2.31.0" }
                                    ]
                                }]
                            }]
                        }"#,
                    )
                } else {
                    ("404 Not Found", r#"{"error":"unexpected route"}"#)
                };

                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_dir = std::env::temp_dir().join(format!("smg-deps-sync-test-{}", stamp));
        fs::create_dir_all(&tmp_dir).unwrap();

        let poetry_lock = r#"
[[package]]
name = "requests"
version = "2.28.0"
"#;
        fs::write(tmp_dir.join("poetry.lock"), poetry_lock).unwrap();

        let db_path = tmp_dir.join("advisories.db");
        let mut store = AdvisoryStore::open_at(&db_path, false).unwrap();

        let cfg = ShellMindGuardConfig::default();
        let deps = extract_project_dependencies(&tmp_dir, &cfg).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.28.0");

        let base_url = format!("http://127.0.0.1:{}", addr.port());
        let summary = sync_osv_to_store(&base_url, &deps, &mut store).unwrap();
        server.join().unwrap();

        assert_eq!(summary.dependencies_queried, 1);
        assert_eq!(summary.unique_vulns_fetched, 1);
        assert_eq!(summary.records_upserted, 1);

        let (count, _) = store.stats().unwrap();
        assert_eq!(count, 1);

        let findings = scan_dependencies_with_store("poetry.lock", poetry_lock, Some(&store));
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("PYSEC-2023-74") && f.title.contains("requests")),
            "expected PYSEC-2023-74 match for requests@2.28.0, got: {:?}",
            findings
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_import_osv_from_file() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_dir = std::env::temp_dir().join(format!("smg-deps-file-test-{}", stamp));
        fs::create_dir_all(&tmp_dir).unwrap();

        let osv_path = tmp_dir.join("osv.json");
        fs::write(
            &osv_path,
            r#"{
                "id": "GHSA-demo-0001-0001",
                "summary": "Demo advisory for offline file import",
                "database_specific": { "severity": "HIGH" },
                "affected": [{
                    "package": { "ecosystem": "npm", "name": "minimist" },
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [{ "introduced": "1.0.0" }, { "fixed": "1.2.6" }]
                    }]
                }]
            }"#,
        )
        .unwrap();

        let mut store = AdvisoryStore::open_at(&tmp_dir.join("advisories.db"), false).unwrap();
        let imported = import_osv_file_to_store(&osv_path, &mut store).unwrap();
        assert_eq!(imported, 1);

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
