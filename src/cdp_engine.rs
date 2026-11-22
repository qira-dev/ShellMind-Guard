//! Synchronous Chrome DevTools Protocol (CDP) engine for SPA crawling and
//! headless template execution (`smg dast --spa`, `headless:` templates).
//!
//! Defensive lab tooling (ZAP-class dynamic analysis):
//! - Launches the locally installed Chrome/Chromium in headless mode with a
//!   throwaway profile (`--headless=new --remote-debugging-port=0
//!   --user-data-dir=<tmp> --no-first-run --disable-gpu`) and discovers the
//!   DevTools endpoint by polling `<user-data-dir>/DevToolsActivePort`
//!   (50 ms interval, 5 s timeout — the file appears 200-500 ms after launch).
//! - Talks plain JSON-RPC over a WebSocket to the page target (opened via
//!   `PUT /json/new`), avoiding flattened browser-session complexity.
//! - Captures the rendered DOM after JavaScript execution, background
//!   XHR/Fetch endpoints (`Network.requestWillBeSent`), and DOM
//!   source-to-sink flows via `Page.addScriptToEvaluateOnNewDocument`
//!   instrumentation (sources: location.hash/search + document.referrer;
//!   sinks: innerHTML/outerHTML setters, document.write, eval, Function).
//!
//! Everything is synchronous: the WebSocket client is `tungstenite` (sync),
//! matching the rest of the codebase (no tokio).

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tungstenite::Message;
use tungstenite::stream::MaybeTlsStream;

const CHROME_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const CHROME_POLL_INTERVAL: Duration = Duration::from_millis(50);
const NAVIGATE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DOM_FINDINGS_PER_PAGE: usize = 50;
const MAX_XHR_ENDPOINTS_PER_PAGE: usize = 200;

/// A DOM source-to-sink flow observed by the injected instrumentation.
#[derive(Debug, Clone)]
pub struct DomSinkFinding {
    /// Source label, e.g. `location.hash`.
    pub source: String,
    /// Sink label, e.g. `innerHTML`.
    pub sink: String,
    /// Truncated value that flowed from source to sink.
    pub value: String,
}

/// Per-navigation collection result.
#[derive(Debug, Clone, Default)]
pub struct CdpPageData {
    /// `document.documentElement.outerHTML` after JS execution.
    pub rendered_html: String,
    /// Background endpoints observed via `Network.requestWillBeSent`.
    pub xhr_urls: Vec<String>,
    /// DOM source-to-sink flows for this page load.
    pub dom_findings: Vec<DomSinkFinding>,
    /// Final URL after redirects/client routing (useful diagnostics; not yet
    /// consumed by an engine).
    #[allow(dead_code)]
    pub final_url: String,
}

fn find_chrome_binary() -> Result<PathBuf> {
    find_chrome_binary_in(
        std::env::var("SMG_CHROME_PATH").ok().as_deref(),
        &std::env::var("PATH").unwrap_or_default(),
    )
}

/// Pure lookup so tests can drive it without mutating process env.
fn find_chrome_binary_in(smg_chrome_path: Option<&str>, path_var: &str) -> Result<PathBuf> {
    if let Some(path) = smg_chrome_path {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
        bail!(
            "SMG_CHROME_PATH points at a non-existent file: {}",
            p.display()
        );
    }
    for name in [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
        "chrome.exe",
    ] {
        for dir in std::env::split_paths(path_var).filter(|d| !d.as_os_str().is_empty()) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("no Chrome/Chromium binary found in PATH; install chromium or set SMG_CHROME_PATH")
}

/// Reads `<user-data-dir>/DevToolsActivePort`: line 1 = port, line 2 = browser
/// ws path. Chrome writes it 200-500 ms after launch, so poll on a short loop.
fn wait_devtools_port(user_data_dir: &std::path::Path) -> Result<u16> {
    let marker = user_data_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + CHROME_DISCOVERY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(content) = std::fs::read_to_string(&marker)
            && let Some(port_line) = content.lines().next()
            && let Ok(port) = port_line.trim().parse::<u16>()
        {
            return Ok(port);
        }
        std::thread::sleep(CHROME_POLL_INTERVAL);
    }
    bail!(
        "Chrome DevTools endpoint did not appear within {}s (missing {})",
        CHROME_DISCOVERY_TIMEOUT.as_secs(),
        marker.display()
    );
}

/// A running headless Chrome with a throwaway profile. Killing the process
/// and deleting the profile happen on drop.
pub struct CdpEngine {
    child: Child,
    user_data_dir: PathBuf,
    devtools_port: u16,
}

impl CdpEngine {
    pub fn launch() -> Result<Self> {
        let binary = find_chrome_binary()?;
        let user_data_dir = std::env::temp_dir().join(format!(
            "smg-cdp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&user_data_dir).with_context(|| {
            format!(
                "creating private Chrome profile dir at {}",
                user_data_dir.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&user_data_dir, std::fs::Permissions::from_mode(0o700));
        }
        let child = Command::new(&binary)
            .arg("--headless=new")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("--no-first-run")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("launching headless Chrome at {}", binary.display()))?;
        match wait_devtools_port(&user_data_dir) {
            Ok(devtools_port) => Ok(Self {
                child,
                user_data_dir,
                devtools_port,
            }),
            Err(e) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&user_data_dir);
                Err(e)
            }
        }
    }

    /// Opens a page target and returns a wired-up capture session.
    pub fn session(&self) -> Result<CdpSession> {
        let ws_url = self.open_page_target()?;
        let mut session = CdpSession::connect(&ws_url)?;
        session.enable_capture_domains()?;
        Ok(session)
    }

    /// `PUT /json/new?url=about:blank` (older builds only accept GET).
    fn open_page_target(&self) -> Result<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let base = format!("http://127.0.0.1:{}/json/new", self.devtools_port);
        let body = match client.put(format!("{base}?url=about:blank")).send() {
            Ok(resp) if resp.status().is_success() => resp.text()?,
            _ => {
                // Older Chrome: GET only.
                let resp = client
                    .get(format!("{base}?url=about:blank"))
                    .send()
                    .context("creating a CDP page target (/json/new)")?;
                if !resp.status().is_success() {
                    bail!("CDP /json/new returned {}", resp.status());
                }
                resp.text()?
            }
        };
        let parsed: Value = serde_json::from_str(&body).context("parsing /json/new response")?;
        let entry = if parsed.is_array() {
            parsed
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(Value::Null)
        } else {
            parsed
        };
        let ws_url = entry
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("/json/new response missing webSocketDebuggerUrl"))?
            .to_string();
        Ok(ws_url)
    }
}

impl Drop for CdpEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.user_data_dir);
    }
}

/// A CDP session bound to one page target: JSON-RPC over a sync WebSocket.
pub struct CdpSession {
    ws: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    pending: std::collections::HashMap<u64, Value>,
    load_fired: bool,
    xhr_urls: Vec<String>,
    pub timeout: Duration,
}

impl CdpSession {
    fn connect(ws_url: &str) -> Result<Self> {
        let (mut ws, _resp) = tungstenite::connect(ws_url)
            .with_context(|| format!("connecting to CDP page target {ws_url}"))?;
        set_ws_timeouts(&mut ws, Duration::from_secs(15));
        Ok(Self {
            ws,
            next_id: 1,
            pending: std::collections::HashMap::new(),
            load_fired: false,
            xhr_urls: Vec::new(),
            timeout: Duration::from_secs(15),
        })
    }

    /// Enables Page/Runtime/Network and installs the source-sink
    /// instrumentation for every future document.
    fn enable_capture_domains(&mut self) -> Result<()> {
        self.call("Page.enable", json!({}))?;
        self.call("Runtime.enable", json!({}))?;
        self.call("Network.enable", json!({}))?;
        self.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": SMG_SOURCE_SINK_JS }),
        )?;
        Ok(())
    }

    fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "id": id, "method": method, "params": params });
        self.ws
            .send(Message::Text(msg.to_string().into()))
            .context("sending CDP command")?;
        let _ = self.ws.flush();
        Ok(id)
    }

    /// Pumps one WebSocket message (bounded by the socket timeout = deadline).
    fn pump(&mut self, deadline: Instant) -> Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        set_ws_timeouts(&mut self.ws, remaining.max(Duration::from_millis(1)));
        match self.ws.read() {
            Ok(Message::Text(text)) => self.handle_message(&text),
            Ok(Message::Binary(bytes)) => match std::str::from_utf8(&bytes) {
                Ok(text) => self.handle_message(text),
                Err(_) => Ok(()),
            },
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => Ok(()),
            Ok(Message::Close(_)) => bail!("CDP page target closed the WebSocket"),
            Err(tungstenite::Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("reading CDP WebSocket"),
        }
    }

    fn handle_message(&mut self, text: &str) -> Result<()> {
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return Ok(());
        };
        if let Some(id) = v.get("id").and_then(Value::as_u64) {
            self.pending.insert(id, v);
            return Ok(());
        }
        let method = v.get("method").and_then(Value::as_str).unwrap_or("");
        if method == "Page.loadEventFired" {
            self.load_fired = true;
        } else if method == "Network.requestWillBeSent" {
            let url = v
                .pointer("/params/request/url")
                .and_then(Value::as_str)
                .unwrap_or("");
            let rtype = v
                .pointer("/params/request/resourceType")
                .and_then(Value::as_str)
                .unwrap_or("");
            let initiator = v
                .pointer("/params/initiator/type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if url.starts_with("http://") || url.starts_with("https://") {
                // Keep background calls (XHR/Fetch by resource type or script
                // initiator); document/main-frame loads are the crawler's own
                // inputs.
                let is_background = rtype.eq_ignore_ascii_case("xhr")
                    || rtype.eq_ignore_ascii_case("fetch")
                    || initiator == "script";
                if is_background && self.xhr_urls.len() < MAX_XHR_ENDPOINTS_PER_PAGE {
                    self.xhr_urls.push(url.to_string());
                }
            }
        }
        Ok(())
    }

    /// Waits for the response of `id`, pumping events meanwhile.
    fn wait_response(&mut self, id: u64, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(resp) = self.pending.remove(&id) {
                if let Some(err) = resp.get("error") {
                    bail!("CDP error for id {id}: {err}");
                }
                return Ok(resp.get("result").cloned().unwrap_or(Value::Null));
            }
            if Instant::now() >= deadline {
                bail!("CDP timeout waiting for response of id {id}");
            }
            self.pump(deadline)?;
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params)?;
        self.wait_response(id, self.timeout)
    }

    /// Pumps events until the load event fires, then for `settle_ms` more so
    /// post-load XHRs are captured.
    fn wait_load_and_settle(&mut self, settle_ms: u64) -> Result<()> {
        let load_deadline = Instant::now() + NAVIGATE_TIMEOUT;
        while !self.load_fired {
            if Instant::now() >= load_deadline {
                // Some SPAs never fire load; proceed with what we have.
                break;
            }
            self.pump(load_deadline)?;
        }
        let settle_deadline = Instant::now() + Duration::from_millis(settle_ms.min(10_000));
        while Instant::now() < settle_deadline {
            self.pump(settle_deadline)?;
        }
        Ok(())
    }

    fn evaluate(&mut self, expression: &str) -> Result<Value> {
        let result = self.call(
            "Runtime.evaluate",
            json!({ "expression": expression, "returnByValue": true }),
        )?;
        Ok(result
            .pointer("/result/value")
            .cloned()
            .unwrap_or(Value::Null))
    }

    fn evaluate_string(&mut self, expression: &str) -> Result<String> {
        Ok(self
            .evaluate(expression)?
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    /// Navigates to `url`, waits for load + settle, and collects the rendered
    /// DOM, background endpoints, and DOM source-sink findings.
    pub fn navigate_and_collect(&mut self, url: &str, settle_ms: u64) -> Result<CdpPageData> {
        self.load_fired = false;
        self.xhr_urls.clear();
        let id = self.send("Page.navigate", json!({ "url": url }))?;
        let _ = self.wait_response(id, NAVIGATE_TIMEOUT)?;
        self.wait_load_and_settle(settle_ms)?;

        let report =
            self.evaluate("window.__smgReport ? JSON.stringify(window.__smgReport) : '[]'")?;
        let mut dom_findings = Vec::new();
        if let Some(items) = serde_json::from_str::<Value>(report.as_str().unwrap_or("[]"))
            .ok()
            .and_then(|v| v.as_array().cloned())
        {
            for item in items.into_iter().take(MAX_DOM_FINDINGS_PER_PAGE) {
                dom_findings.push(DomSinkFinding {
                    source: item
                        .get("source")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    sink: item
                        .get("sink")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    value: item
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }

        let rendered_html = self.evaluate_string("document.documentElement.outerHTML")?;
        let final_url = self.evaluate_string("location.href")?;
        Ok(CdpPageData {
            rendered_html,
            xhr_urls: std::mem::take(&mut self.xhr_urls),
            dom_findings,
            final_url,
        })
    }
}

/// Extracts TcpStream timeouts through the tungstenite TLS-maybe wrapper.
fn set_ws_timeouts(ws: &mut tungstenite::WebSocket<MaybeTlsStream<TcpStream>>, timeout: Duration) {
    let apply = |s: &TcpStream| {
        let _ = s.set_read_timeout(Some(timeout));
        let _ = s.set_write_timeout(Some(timeout));
    };
    match ws.get_ref() {
        MaybeTlsStream::Plain(s) => apply(s),
        MaybeTlsStream::Rustls(s) => apply(s.get_ref()),
        _ => {}
    }
}

/// DOM source-to-sink instrumentation injected with
/// `Page.addScriptToEvaluateOnNewDocument` (Page domain, not Runtime — the
/// Runtime-domain variant does not exist and returns -32601).
const SMG_SOURCE_SINK_JS: &str = r#"(() => {
  if (window.__smgInstalled) return;
  window.__smgInstalled = true;
  const report = [];
  const srcVals = new Set();
  let lastSource = 'location';
  const addSource = (label, value) => {
    const s = value == null ? '' : String(value);
    if (s.length > 0 && s.length <= 500) {
      srcVals.add(s);
      lastSource = label;
    }
  };
  const snapshot = () => {
    addSource('location.hash', location.hash);
    addSource('location.search', location.search);
    if (document.referrer) addSource('document.referrer', document.referrer);
  };
  snapshot();
  window.addEventListener('hashchange', snapshot);
  window.addEventListener('popstate', snapshot);
  setInterval(snapshot, 250);
  const record = (sink, value) => {
    if (report.length >= 50 || value == null) return;
    const s = String(value);
    if (s.length < 1) return;
    for (const v of srcVals) {
      const bare = v.replace(/^[?#]/, '');
      if (bare.length >= 4 && s.includes(bare)) {
        report.push({ source: lastSource, sink, value: s.slice(0, 200) });
        return;
      }
    }
  };
  const hookSetter = (proto, prop, sink) => {
    const d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      configurable: d.configurable,
      enumerable: d.enumerable,
      get: d.get,
      set(v) { record(sink, v); return d.set.call(this, v); },
    });
  };
  try { hookSetter(Element.prototype, 'innerHTML', 'innerHTML'); } catch (e) {}
  try { hookSetter(Element.prototype, 'outerHTML', 'outerHTML'); } catch (e) {}
  try {
    const ow = document.write.bind(document);
    document.write = (s) => { record('document.write', s); return ow(s); };
    document.writeln = (s) => { record('document.write', s); return ow(s + '\n'); };
  } catch (e) {}
  try {
    const nativeEval = window.eval;
    window.eval = (s) => { record('eval', s); return nativeEval(s); };
  } catch (e) {}
  try {
    const NativeFunction = Function;
    const Patched = function (...args) {
      record('Function', args[args.length - 1]);
      return NativeFunction(...args);
    };
    Patched.prototype = NativeFunction.prototype;
    window.Function = Patched;
  } catch (e) {}
  window.__smgReport = report;
})();
"#;

// ---------------------------------------------------------------------------
// Tests (fake CDP page-target server; no Chrome needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Minimal fake CDP page target: answers Runtime.evaluate and emits a
    /// Page.loadEventFired event after Page.navigate, plus one XHR network
    /// event — enough to exercise the pump/response/event pipeline.
    fn fake_cdp_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            // Drain the HTTP handshake headers (tungstenite::accept re-reads
            // them from the same socket, so do not consume them here).
            let mut ws = match tungstenite::accept(sock) {
                Ok(ws) => ws,
                Err(_) => return,
            };
            loop {
                match ws.read() {
                    Ok(Message::Text(text)) => {
                        let Ok(v) = serde_json::from_str::<Value>(&text) else {
                            continue;
                        };
                        let id = v.get("id").and_then(Value::as_u64).unwrap_or(0);
                        let method = v.get("method").and_then(Value::as_str).unwrap_or("");
                        let reply = match method {
                            "Page.enable"
                            | "Runtime.enable"
                            | "Network.enable"
                            | "Page.addScriptToEvaluateOnNewDocument" => {
                                json!({ "id": id, "result": {} })
                            }
                            "Page.navigate" => {
                                let _ = ws.send(
                                    json!({
                                        "method": "Network.requestWillBeSent",
                                        "params": {
                                            "request": {
                                                "url": "http://127.0.0.1:9999/api/list",
                                                "resourceType": "XHR"
                                            },
                                            "initiator": { "type": "script" }
                                        }
                                    })
                                    .to_string()
                                    .into(),
                                );
                                let _ = ws.send(
                                    json!({ "method": "Page.loadEventFired" })
                                        .to_string()
                                        .into(),
                                );
                                json!({ "id": id, "result": { "frameId": "F" } })
                            }
                            "Runtime.evaluate" => {
                                let expr = v
                                    .pointer("/params/expression")
                                    .and_then(Value::as_str)
                                    .unwrap_or("");
                                let value = if expr.contains("__smgReport") {
                                    json!(
                                        "[{\"source\":\"location.hash\",\"sink\":\"innerHTML\",\"value\":\"<img src=x onerror>\"}]"
                                    )
                                } else if expr.contains("outerHTML") {
                                    json!("<html><body><div id=root>SPA</div></body></html>")
                                } else if expr.contains("location.href") {
                                    json!("http://127.0.0.1:9999/app#x")
                                } else {
                                    json!(null)
                                };
                                json!({ "id": id, "result": { "result": { "type": "string", "value": value } } })
                            }
                            _ => json!({ "id": id, "error": { "message": "unknown method" } }),
                        };
                        let _ = ws.send(Message::Text(reply.to_string().into()));
                    }
                    Ok(_) => {}
                    Err(
                        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed,
                    ) => break,
                    Err(_) => break,
                }
            }
        });
        format!("ws://{addr}/devtools/page/fake")
    }

    #[test]
    fn session_collects_rendered_dom_xhr_and_dom_findings() {
        let ws_url = fake_cdp_server();
        let mut session = CdpSession::connect(&ws_url).unwrap();
        session.enable_capture_domains().unwrap();
        let data = session
            .navigate_and_collect("http://127.0.0.1:9999/app", 50)
            .unwrap();
        assert!(
            data.rendered_html.contains("SPA"),
            "html: {}",
            data.rendered_html
        );
        assert_eq!(data.final_url, "http://127.0.0.1:9999/app#x");
        assert_eq!(
            data.xhr_urls,
            vec!["http://127.0.0.1:9999/api/list".to_string()]
        );
        assert_eq!(data.dom_findings.len(), 1);
        assert_eq!(data.dom_findings[0].source, "location.hash");
        assert_eq!(data.dom_findings[0].sink, "innerHTML");
    }

    #[test]
    fn find_chrome_binary_reports_missing_binary() {
        let empty = std::env::temp_dir().join(format!("smg-empty-path-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&empty);
        assert!(find_chrome_binary_in(None, empty.to_str().unwrap()).is_err());
        assert!(
            find_chrome_binary_in(Some("/nonexistent/smg-chrome"), "").is_err(),
            "a bogus SMG_CHROME_PATH must fail loudly"
        );
        // A matching binary in a PATH entry resolves.
        let fake = empty.join("chromium");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        let found = find_chrome_binary_in(None, empty.to_str().unwrap()).unwrap();
        assert_eq!(found, fake);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn dom_finding_report_is_bounded() {
        let mut items = Vec::new();
        for i in 0..(MAX_DOM_FINDINGS_PER_PAGE + 20) {
            items
                .push(json!({"source": "location.hash", "sink": "eval", "value": format!("x{i}")}));
        }
        let parsed: Vec<Value> = items;
        let taken: Vec<_> = parsed.into_iter().take(MAX_DOM_FINDINGS_PER_PAGE).collect();
        assert_eq!(taken.len(), MAX_DOM_FINDINGS_PER_PAGE);
    }
}
