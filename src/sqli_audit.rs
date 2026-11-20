//! Defensive non-destructive SQL injection detection/prover (`smg sqli`).
//!
//! Strictly scoped to developer QA & authorized lab verification:
//! - Defaults to loopback / RFC1918 lab hosts; `--allow-remote` opt-in for the
//!   owner's own staging servers (same policy as `smg idor`).
//! - Only GET requests and urlencoded POST bodies are driven.
//! - Techniques: error-based signature detection, boolean-based differential
//!   response analysis, statistically-verified time-based delay, and ORDER BY
//!   UNION column-count detection.
//! - NEVER does: data extraction/dumping, stacked (multi-statement) queries,
//!   OS-level command execution, or WAF-evasion tamper transformations.

use anyhow::{Context, Result, bail};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const UNION_MAX_COLUMNS: usize = 16;
const TIME_BASELINE_REPS: usize = 2;
const TIME_PAYLOAD_REPS: usize = 2;

// ---------------------------------------------------------------------------
// DB error signatures
// ---------------------------------------------------------------------------

fn mysql_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(you have an error in your sql syntax|warning: mysql|mysqli?_[a-z_]+\(|mariadb server version|check the manual that corresponds to your mysql)")
            .expect("static regex")
    })
}

fn postgres_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(pg::(syntax|invalidtextrepresentation|undefinedfunction|invalidparametervalue)|unterminated quoted (string|identifier) at or near|psycopg2\.|org\.postgresql\.util|ERROR:  syntax error at)")
            .expect("static regex")
    })
}

fn sqlite_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(sqlite3?\.(operational|syntax|programming)error|SQLITE_(ERROR|CONSTRAINT|SYNTAX)|unrecognized token:|sql logic error|Warning: sqlite_)")
            .expect("static regex")
    })
}

fn mssql_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(unclosed quotation mark after|incorrect syntax near|microsoft ole db provider|SQLException:|conversion failed when converting|Warning: mssql_)")
            .expect("static regex")
    })
}

fn oracle_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(ORA-\d{5}|oracle\.jdbc|quoted string not properly terminated|ORA-00936|ORA-01756)")
            .expect("static regex")
    })
}

fn db_hint_for(text: &str) -> Option<&'static str> {
    if mysql_error_re().is_match(text) {
        Some("MySQL/MariaDB")
    } else if postgres_error_re().is_match(text) {
        Some("PostgreSQL")
    } else if sqlite_error_re().is_match(text) {
        Some("SQLite")
    } else if mssql_error_re().is_match(text) {
        Some("MSSQL")
    } else if oracle_error_re().is_match(text) {
        Some("Oracle")
    } else {
        None
    }
}

/// First matched DB error signature (db family + matched snippet, capped).
pub fn scan_error_signatures(text: &str) -> Option<(String, String)> {
    let re_chain = [
        mysql_error_re(),
        postgres_error_re(),
        sqlite_error_re(),
        mssql_error_re(),
        oracle_error_re(),
    ];
    for re in re_chain {
        if let Some(m) = re.find(text) {
            let family = db_hint_for(m.as_str()).unwrap_or("SQL");
            return Some((family.into(), m.as_str().chars().take(80).collect()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config / report model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueEvidence {
    pub technique: String,
    pub payload: String,
    pub evidence: String,
    pub db: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliParamResult {
    pub param: String,
    pub error_based: Option<TechniqueEvidence>,
    pub boolean_based: Option<TechniqueEvidence>,
    pub time_based: Option<TechniqueEvidence>,
    pub union_columns: Option<usize>,
    pub verdict: String, // VULNERABLE | CLEAN | INCONCLUSIVE
    pub db_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliAuditReport {
    pub url: String,
    pub method: String,
    pub params_tested: usize,
    pub vulnerable_params: usize,
    pub results: Vec<SqliParamResult>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct SqliAuditConfig {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub params: Vec<String>,
    pub delay_secs: u64,
    pub skip_timing: bool,
    pub allow_remote: bool,
}

// ---------------------------------------------------------------------------
// Injection plumbing
// ---------------------------------------------------------------------------

fn percent_encode_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Rebuilds a `k=v&k2=v2` string with `param` set to `value` (percent-encoded).
fn set_param_in_pairs(pairs: &str, param: &str, value: &str) -> Option<String> {
    let mut found = false;
    let rebuilt: Vec<String> = pairs
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if k == param => {
                found = true;
                format!("{k}={}", percent_encode_value(value))
            }
            _ if kv == param => {
                found = true;
                format!("{kv}={}", percent_encode_value(value))
            }
            _ => kv.to_string(),
        })
        .collect();
    if !found {
        return None;
    }
    Some(rebuilt.join("&"))
}

#[derive(Debug, Clone)]
struct Injectable {
    url: String,
    body: Option<String>,
}

fn make_injectable(cfg: &SqliAuditConfig, param: &str) -> Result<Injectable> {
    let url = reqwest::Url::parse(cfg.url.trim())
        .with_context(|| format!("Invalid URL '{}'", cfg.url))?;
    let query = url.query().unwrap_or_default().to_string();
    let in_url = set_param_in_pairs(&query, param, "x").is_some();
    let in_body = cfg
        .body
        .as_deref()
        .map(|b| set_param_in_pairs(b, param, "x").is_some())
        .unwrap_or(false);
    if !in_url && !in_body {
        bail!("Parameter '{param}' not found in URL query or POST body");
    }
    Ok(Injectable {
        url: url.to_string(),
        body: cfg.body.clone(),
    })
}

fn inject_value(
    param: &str,
    original_url: &str,
    original_body: Option<&str>,
    value: &str,
) -> Injectable {
    let mut inj = Injectable {
        url: original_url.to_string(),
        body: original_body.map(|b| b.to_string()),
    };
    if let Ok(mut u) = reqwest::Url::parse(original_url) {
        let query = u.query().unwrap_or_default().to_string();
        if let Some(nq) = set_param_in_pairs(&query, param, value) {
            u.set_query(Some(&nq));
            inj.url = u.to_string();
        }
    }
    if let Some(orig_body) = original_body
        && let Some(nb) = set_param_in_pairs(orig_body, param, value)
    {
        inj.body = Some(nb);
    }
    inj
}

struct Response {
    status: u16,
    body: String,
}

fn send_injectable(
    client: &Client,
    inj: &Injectable,
    method: &str,
    headers: &HashMap<String, String>,
) -> Result<Response> {
    let m = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
    let mut req = client.request(m, &inj.url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(body) = &inj.body {
        req = req
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.clone());
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    Ok(Response { status, body })
}

fn body_close(a: &Response, b: &Response) -> bool {
    if a.status != b.status {
        return false;
    }
    if a.body == b.body {
        return true;
    }
    let max = a.body.len().max(b.body.len()).max(1);
    let delta = (a.body.len() as i64 - b.body.len() as i64).unsigned_abs() as usize;
    delta * 100 / max <= 2
}

fn body_diverges(a: &Response, b: &Response) -> bool {
    if a.status != b.status {
        return true;
    }
    if a.body == b.body {
        return false;
    }
    let max = a.body.len().max(b.body.len()).max(1);
    let delta = (a.body.len() as i64 - b.body.len() as i64).unsigned_abs() as usize;
    delta * 100 / max > 5 || a.body.len() != b.body.len()
}

fn median_f64(samples: &mut [f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    samples[samples.len() / 2]
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

const ERROR_PROBES: &[&str] = &["'", "\"", "')", "'))", "\\"];

pub fn run_sqli_audit(cfg: &SqliAuditConfig) -> Result<SqliAuditReport> {
    if !cfg.allow_remote && !crate::idor_audit::is_lab_or_loopback_url(&cfg.url)? {
        bail!(
            "Refusing remote target '{}' by default (SQLi verification targets loopback/private lab hosts unless `--allow-remote` is explicitly passed for your own staging server).",
            cfg.url
        );
    }
    let method = cfg.method.to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST") {
        bail!(
            "Only GET and POST urlencoded methods are supported in safe SQLi verification mode (got '{method}')"
        );
    }
    if method == "POST" && cfg.body.is_none() {
        bail!("POST requires a urlencoded --data body");
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(
            cfg.delay_secs * TIME_PAYLOAD_REPS as u64 + 20,
        ))
        .redirect(Policy::none())
        .user_agent(concat!("ShellMind-Guard/", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Determine the parameter set.
    let url = reqwest::Url::parse(cfg.url.trim())?;
    let mut params: Vec<String> = cfg.params.clone();
    if params.is_empty() {
        params = url.query_pairs().map(|(k, _)| k.to_string()).collect();
    }
    if params.is_empty() {
        bail!("No query parameters found; pass --param or a URL with parameters");
    }

    let started = Instant::now();
    let mut results = Vec::new();
    let mut vulnerable = 0usize;

    for param in &params {
        let inj = make_injectable(cfg, param)?;
        let original_body = cfg.body.clone();
        let mut result = SqliParamResult {
            param: param.clone(),
            error_based: None,
            boolean_based: None,
            time_based: None,
            union_columns: None,
            verdict: "INCONCLUSIVE".into(),
            db_hints: Vec::new(),
        };

        let baseline = send_injectable(&client, &inj, &method, &cfg.headers);

        if let Ok(base) = &baseline {
            let orig_value = url
                .query_pairs()
                .find(|(k, _)| k == param.as_str())
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let send_probe = |payload: &str| -> Result<Response> {
                let probe =
                    inject_value(param, cfg.url.as_str(), original_body.as_deref(), payload);
                send_injectable(&client, &probe, &method, &cfg.headers)
            };

            // 1. Error-based
            for payload in ERROR_PROBES {
                if let Ok(resp) = send_probe(payload) {
                    let haystack = format!("{}\n{}", resp.body, resp.status);
                    if let Some((db, sig)) = scan_error_signatures(&haystack) {
                        result.error_based = Some(TechniqueEvidence {
                            technique: "error-based".into(),
                            payload: payload.to_string(),
                            evidence: sig,
                            db: Some(db.clone()),
                        });
                        if !result.db_hints.contains(&db) {
                            result.db_hints.push(db);
                        }
                        break;
                    }
                }
            }

            // 2. Boolean-based differential (2 consistent reps, zero guessing)
            let numeric = !orig_value.is_empty() && orig_value.chars().all(|c| c.is_ascii_digit());
            let (true_payload, false_payload) = if numeric {
                (
                    format!("{orig_value} AND 1=1"),
                    format!("{orig_value} AND 1=2"),
                )
            } else if !orig_value.is_empty() {
                (
                    format!("{orig_value}' AND '1'='1"),
                    format!("{orig_value}' AND '1'='2"),
                )
            } else {
                ("1 AND 1=1".to_string(), "1 AND 1=2".to_string())
            };
            let t1 = send_probe(&true_payload);
            let f1 = send_probe(&false_payload);
            if let (Ok(t1), Ok(f1)) = (&t1, &f1) {
                let truthy_matches = body_close(t1, base);
                let falsy_diverges = body_diverges(f1, base) && !body_close(f1, t1);
                if truthy_matches
                    && falsy_diverges
                    && let (Ok(t2), Ok(f2)) =
                        (send_probe(&true_payload), send_probe(&false_payload))
                    && body_close(&t2, base)
                    && body_diverges(&f2, base)
                    && !body_close(&f2, &t2)
                {
                    result.boolean_based = Some(TechniqueEvidence {
                        technique: "boolean-blind".into(),
                        payload: false_payload.clone(),
                        evidence: format!(
                            "truthy≈baseline ({}B, HTTP {}) vs falsy divergent ({}B, HTTP {})",
                            t1.body.len(),
                            t1.status,
                            f1.body.len(),
                            f1.status
                        ),
                        db: None,
                    });
                }
            }

            // 3. Time-based (only when quick checks were inconclusive; bounded)
            if result.error_based.is_none() && result.boolean_based.is_none() && !cfg.skip_timing {
                let delay = cfg.delay_secs;
                let baseline_median = {
                    let mut samples = Vec::new();
                    for _ in 0..TIME_BASELINE_REPS {
                        let t0 = Instant::now();
                        let _ = send_injectable(&client, &inj, &method, &cfg.headers);
                        samples.push(t0.elapsed().as_secs_f64());
                    }
                    median_f64(&mut samples)
                };
                let families: Vec<(&str, String)> = if numeric {
                    vec![
                        ("MySQL/MariaDB", format!("{orig_value} AND sleep({delay})")),
                        ("PostgreSQL", format!("{orig_value} AND pg_sleep({delay})")),
                        (
                            "MSSQL",
                            format!("{orig_value} AND WAITFOR DELAY '0:0:{delay}'"),
                        ),
                    ]
                } else {
                    vec![
                        (
                            "MySQL/MariaDB",
                            format!("{orig_value}' AND sleep({delay})-- "),
                        ),
                        ("PostgreSQL", format!("{orig_value}'||pg_sleep({delay})||'")),
                        (
                            "MSSQL",
                            format!("{orig_value}'; WAITFOR DELAY '0:0:{delay}'-- "),
                        ),
                    ]
                };
                for (db, payload) in &families {
                    let mut samples = Vec::new();
                    for _ in 0..TIME_PAYLOAD_REPS {
                        let t0 = Instant::now();
                        let _ = send_probe(payload);
                        samples.push(t0.elapsed().as_secs_f64());
                    }
                    let payload_median = median_f64(&mut samples);
                    if payload_median - baseline_median >= (delay as f64) * 0.7 {
                        result.time_based = Some(TechniqueEvidence {
                            technique: "time-based blind".into(),
                            payload: payload.clone(),
                            evidence: format!(
                                "baseline {baseline_median:.2}s vs payload {payload_median:.2}s (delay {delay}s)"
                            ),
                            db: Some(db.to_string()),
                        });
                        if !result.db_hints.iter().any(|h| h == db) {
                            result.db_hints.push(db.to_string());
                        }
                        break;
                    }
                }
            }

            // 4. UNION column-count detection (ORDER BY enumeration, detection-only)
            let mut columns: Option<usize> = None;
            for k in 1..=UNION_MAX_COLUMNS {
                let payload = if numeric {
                    format!("{orig_value} ORDER BY {k}")
                } else {
                    format!("{orig_value}' ORDER BY {k}-- ")
                };
                match send_probe(&payload) {
                    Ok(resp) => {
                        let broke = scan_error_signatures(&resp.body).is_some()
                            || resp.status != base.status
                            || body_diverges(&resp, base);
                        if broke {
                            if k > 1 {
                                columns = Some(k - 1);
                            }
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            result.union_columns = columns;
        }

        result.verdict = if result.error_based.is_some()
            || result.boolean_based.is_some()
            || result.time_based.is_some()
            || result.union_columns.is_some()
        {
            vulnerable += 1;
            "VULNERABLE".into()
        } else if baseline.is_ok() {
            "CLEAN".into()
        } else {
            "INCONCLUSIVE".into()
        };
        results.push(result);
    }

    let url_out = cfg.url.clone();
    let method_out = method.clone();
    Ok(SqliAuditReport {
        url: url_out,
        method: method_out,
        params_tested: results.len(),
        vulnerable_params: vulnerable,
        results,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Full percent-decoder for the mock (matches the engine's encoder).
    fn test_pct_decode(s: &str) -> String {
        let mut bytes = Vec::with_capacity(s.len());
        let raw = s.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%'
                && i + 2 < raw.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                bytes.push(v);
                i += 3;
                continue;
            }
            bytes.push(raw[i]);
            i += 1;
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Mock server with per-endpoint SQLi behaviour:
    /// - `/error?id=` → MySQL signature when value contains a quote
    /// - `/bool?q=`   → long page for truthy payloads, short for falsy
    /// - `/time?id=`  → sleeps when the payload contains "sleep"
    /// - `/union?id=` → SQL error when ORDER BY column > 3
    fn mock_server(delay: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..256 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("");
                let mut status = 200u16;
                let mut body = String::new();
                let mut sleep_secs = 0u64;
                if let Some((_, q)) = path.split_once('?') {
                    let raw_value = q
                        .split('&')
                        .find_map(|kv| {
                            kv.strip_prefix("id=")
                                .or_else(|| kv.strip_prefix("q="))
                                .map(|v| v.to_string())
                        })
                        .unwrap_or_default();
                    let decoded = test_pct_decode(&raw_value);
                    if path.starts_with("/error?") {
                        if decoded.contains('\'') || decoded.contains('"') {
                            status = 500;
                            body = "You have an error in your SQL syntax; check the manual".into();
                        } else {
                            body = format!("item {decoded}");
                        }
                    } else if path.starts_with("/bool?") {
                        if decoded.ends_with("AND '1'='1") || decoded.ends_with("AND 1=1") {
                            body = "x".repeat(500);
                        } else if decoded.ends_with("AND '1'='2") || decoded.ends_with("AND 1=2") {
                            body = "x".repeat(50);
                        } else {
                            body = "x".repeat(500);
                        }
                    } else if path.starts_with("/time?") {
                        if decoded.contains("sleep") {
                            body = "delayed".into();
                            sleep_secs = delay;
                        } else {
                            body = "quick".into();
                        }
                    } else if path.starts_with("/union?") {
                        // The baseline item is everything before the ORDER BY
                        // marker, so valid ORDER BY probes return the exact
                        // baseline body (no divergence) and only out-of-range
                        // columns break with a SQL error.
                        let base_item = decoded
                            .split(" ORDER BY")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let order_col = decoded.split("ORDER BY").nth(1).and_then(|s| {
                            s.trim().trim_end_matches("--").trim().parse::<usize>().ok()
                        });
                        match order_col {
                            Some(col) if col > 3 => {
                                status = 500;
                                body = "ERROR:  syntax error at or near".into();
                            }
                            _ => body = format!("item {base_item}"),
                        }
                    } else if path.starts_with("/clean?") {
                        // Hardened endpoint: every probe echoes the baseline
                        // item, so no technique can fire.
                        let base_item = decoded
                            .split(" ORDER BY")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        body = format!("item {base_item}");
                    }
                }
                if body.is_empty() {
                    status = 404;
                    body = "not found".into();
                }
                if sleep_secs > 0 {
                    thread::sleep(Duration::from_secs(sleep_secs));
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn cfg_for(url: &str, tweak: impl FnOnce(&mut SqliAuditConfig)) -> SqliAuditConfig {
        let mut cfg = SqliAuditConfig {
            url: url.to_string(),
            method: "GET".into(),
            headers: HashMap::new(),
            body: None,
            params: vec![],
            delay_secs: 1,
            skip_timing: false,
            allow_remote: false,
        };
        tweak(&mut cfg);
        cfg
    }

    #[test]
    fn detects_error_based_mysql_signature() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/error?id=42"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert_eq!(
            r.error_based.as_ref().unwrap().db.as_deref(),
            Some("MySQL/MariaDB")
        );
        assert_eq!(r.verdict, "VULNERABLE");
    }

    #[test]
    fn detects_boolean_differential() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/bool?q=abc"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        assert!(report.results[0].boolean_based.is_some());
    }

    #[test]
    fn detects_time_based_delay() {
        let base = mock_server(1);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/time?id=7"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        let r = &report.results[0];
        assert!(r.time_based.is_some());
        assert!(r.db_hints.iter().any(|h| h.contains("MySQL")));
    }

    #[test]
    fn detects_union_column_count() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/union?id=9"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 1);
        assert_eq!(report.results[0].union_columns, Some(3));
    }

    #[test]
    fn clean_param_yields_clean_verdict() {
        let base = mock_server(0);
        let report = run_sqli_audit(&cfg_for(&format!("{base}/clean?id=1"), |_| {})).unwrap();
        assert_eq!(report.vulnerable_params, 0);
        assert_eq!(report.results[0].verdict, "CLEAN");
    }

    #[test]
    fn refuses_remote_host_without_explicit_flag() {
        let err = run_sqli_audit(&cfg_for("https://example.com/item?id=1", |_| {}));
        assert!(err.is_err());
    }

    #[test]
    fn refuses_put_method() {
        let base = mock_server(0);
        let err = run_sqli_audit(&cfg_for(&format!("{base}/error?id=1"), |c| {
            c.method = "PUT".into();
        }));
        assert!(err.is_err());
    }
}
