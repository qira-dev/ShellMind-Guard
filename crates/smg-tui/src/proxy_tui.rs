//! Localhost HTTP inspection proxy TUI (`smg proxy`): live request history,
//! Repeater (replay), Base64/URL/JWT decoder, bounded wordlist fuzzer, and
//! entry export. The proxy engine lives in the root crate and pushes
//! [`ProxyEntry`] snapshots into the shared history this view renders.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_INTRUDER_WORDS: usize = 100;
const INTRUDER_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_IN_VIEW: usize = 64 * 1024;

/// One captured proxy transaction (filled by the root proxy engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: u64,
    pub ts_unix_ms: u64,
    /// "http" = fully intercepted plain HTTP; "tls" = HTTPS CONNECT tunnel (logged, not decrypted).
    pub kind: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub req_headers: String,
    pub req_body: String,
    pub resp_headers: String,
    pub resp_body: String,
    pub duration_ms: u128,
    pub replay_of: Option<u64>,
}

/// Live counters shared between the proxy engine and this TUI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySummary {
    pub bind: String,
    pub connections: u64,
    pub http_intercepted: u64,
    pub https_tunneled: u64,
    pub errors: u64,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn b64url_decode(segment: &str) -> Option<Vec<u8>> {
    let bare = segment.trim().trim_end_matches('=');
    let mut padded = bare.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    URL_SAFE.decode(padded.as_bytes()).ok()
}

fn pretty_json(raw: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

fn pct_decode(s: &str) -> String {
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
        bytes.push(if raw[i] == b'+' { b' ' } else { raw[i] });
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Deterministic multi-format decoder: Base64 (std + URL-safe) → URL → JWT.
pub fn decode_all(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return out;
    }
    let is_b64ish = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='));
    if is_b64ish {
        if let Ok(decoded) = STANDARD.decode(trimmed) {
            out.push((
                "Base64".into(),
                String::from_utf8_lossy(&decoded).into_owned(),
            ));
        } else if let Ok(decoded) = URL_SAFE_NO_PAD.decode(trimmed.trim_end_matches('=')) {
            out.push((
                "Base64-URL".into(),
                String::from_utf8_lossy(&decoded).into_owned(),
            ));
        }
    }
    if trimmed.contains('%') {
        out.push(("URL".into(), pct_decode(trimmed)));
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() == 3
        && let (Some(header), Some(payload)) = (
            b64url_decode(parts[0]).and_then(|b| pretty_json(&b)),
            b64url_decode(parts[1]).and_then(|b| pretty_json(&b)),
        )
    {
        out.push(("JWT Header".into(), header));
        out.push(("JWT Payload".into(), payload));
    }
    out
}

/// Replays a captured intercepted-HTTP request (Repeater). Returns a new entry
/// with `replay_of` pointing at the original id; the caller assigns the id.
pub fn replay_entry(client: &Client, entry: &ProxyEntry) -> Result<ProxyEntry> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if entry.kind != "http" {
        bail!("CONNECT tunnels (HTTPS) cannot be replayed; only intercepted HTTP requests can");
    }
    let method = reqwest::Method::from_bytes(entry.method.as_bytes())
        .with_context(|| format!("invalid replay method '{}'", entry.method))?;
    let mut req = client.request(method, &entry.url);
    for line in entry.req_headers.lines() {
        let Some((k, v)) = line.split_once(": ") else {
            continue;
        };
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "host" | "content-length" | "connection" | "accept-encoding" | "proxy-connection"
        ) {
            continue;
        }
        let Ok(hname) = reqwest::header::HeaderName::from_bytes(k.trim().as_bytes()) else {
            continue;
        };
        let Ok(hval) = reqwest::header::HeaderValue::from_str(v.trim()) else {
            continue;
        };
        req = req.header(hname, hval);
    }
    if !entry.req_body.is_empty() {
        req = req.body(entry.req_body.clone());
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let mut resp_headers = String::new();
    for (k, v) in resp.headers().iter() {
        resp_headers.push_str(&format!(
            "{}: {}\r\n",
            k.as_str(),
            v.to_str().unwrap_or("<binary>")
        ));
    }
    let mut bytes = Vec::new();
    let _ = std::io::Read::read_to_end(
        &mut std::io::Read::take(resp, (MAX_CAPTURE_IN_VIEW + 1) as u64),
        &mut bytes,
    );
    let body = if bytes.len() > MAX_CAPTURE_IN_VIEW {
        String::from_utf8_lossy(&bytes[..MAX_CAPTURE_IN_VIEW]).into_owned()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Ok(ProxyEntry {
        id: 0,
        ts_unix_ms: now_unix_ms(),
        kind: entry.kind.clone(),
        method: entry.method.clone(),
        url: entry.url.clone(),
        status,
        req_headers: entry.req_headers.clone(),
        req_body: entry.req_body.clone(),
        resp_headers,
        resp_body: body,
        duration_ms: 0,
        replay_of: Some(entry.id),
    })
}

/// Bounded wordlist fuzzer (Intruder): GET `{url}` with `{FUZZ}` replaced per word.
pub fn intruder_run(
    url_template: &str,
    words: &[String],
    timeout: Duration,
) -> Vec<(String, u16, usize)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Ok(client) = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for word in words.iter().take(MAX_INTRUDER_WORDS) {
        let url = url_template.replace("{FUZZ}", word);
        let outcome = match client.get(&url).send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let len = resp.bytes().map(|b| b.len()).unwrap_or(0);
                (word.clone(), status, len)
            }
            Err(_) => (word.clone(), 0, 0),
        };
        results.push(outcome);
    }
    results
}

const DIFF_MAX_LINES: usize = 1_500;

/// Line-based LCS diff: `' '` = same, `'-'` = only in `a`, `'+'` = only in `b`.
/// Bounded to the first `DIFF_MAX_LINES` lines of each side so the DP table
/// stays small even for large captured bodies.
pub fn diff_lines(a: &str, b: &str) -> Vec<(char, String)> {
    let la: Vec<&str> = a.lines().take(DIFF_MAX_LINES).collect();
    let lb: Vec<&str> = b.lines().take(DIFF_MAX_LINES).collect();
    let n = la.len();
    let m = lb.len();
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if la[i] == lb[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if la[i] == lb[j] {
            out.push((' ', la[i].to_string()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push(('-', la[i].to_string()));
            i += 1;
        } else {
            out.push(('+', lb[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        out.push(('-', la[i].to_string()));
        i += 1;
    }
    while j < m {
        out.push(('+', lb[j].to_string()));
        j += 1;
    }
    out
}

fn entry_transaction_text(entry: &ProxyEntry) -> String {
    format!(
        "{} {}\r\n{}\r\n{}\n--- response ({} {}) ---\r\n{}\r\n{}",
        entry.method,
        entry.url,
        entry.req_headers,
        entry.req_body,
        entry.status,
        entry.duration_ms,
        entry.resp_headers,
        entry.resp_body
    )
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct IntruderState {
    url_field: String,
    wordlist_field: String,
    focus: usize, // 0 url, 1 wordlist
    results: Vec<(String, u16, usize)>,
    message: Option<String>,
}

enum Modal {
    None,
    Decoder(Vec<(String, String)>),
    Intruder(IntruderState),
    Diff(Vec<(char, String)>, u64, u64),
}

struct App {
    entries: Arc<Mutex<Vec<Arc<ProxyEntry>>>>,
    summary: Arc<Mutex<ProxySummary>>,
    list_state: ListState,
    focus: usize, // 0 = history, 1 = request pane, 2 = response pane
    req_scroll: u16,
    resp_scroll: u16,
    modal: Modal,
    quit: bool,
    status_message: Option<String>,
    compare_from: Option<u64>,
}

impl App {
    fn selected(&self) -> Option<Arc<ProxyEntry>> {
        let entries = self.entries.lock().ok()?;
        let idx = self.list_state.selected()?;
        entries.get(idx).cloned()
    }

    fn select_next(&mut self, delta: i64) {
        let len = self.entries.lock().map(|e| e.len()).unwrap_or(0);
        if len == 0 {
            return;
        }
        let current = self.list_state.selected().unwrap_or(0) as i64;
        let next = (current + delta).clamp(0, len as i64 - 1) as usize;
        self.list_state.select(Some(next));
        self.req_scroll = 0;
        self.resp_scroll = 0;
    }

    fn push_entry(&mut self, entry: ProxyEntry) {
        let id = {
            let mut entries = match self.entries.lock() {
                Ok(e) => e,
                Err(_) => return,
            };
            let id = entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
            entries.push(Arc::new(ProxyEntry { id, ..entry }));
            id
        };
        let len = self.entries.lock().map(|e| e.len()).unwrap_or(0);
        if len > 0 {
            self.list_state.select(Some(len - 1));
        }
        self.status_message = Some(format!("entry #{id} captured"));
    }
}

fn detail_lines(content: &str, accent: Color) -> Vec<Line<'static>> {
    content
        .lines()
        .take(2_000)
        .enumerate()
        .map(|(i, l)| {
            let style = if i < 6 {
                Style::default().fg(accent)
            } else {
                Style::default()
            };
            Line::from(Span::styled(l.to_string(), style))
        })
        .collect()
}

fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Blue,
        400..=499 => Color::Yellow,
        500..=599 => Color::Red,
        _ => Color::DarkGray,
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let summary = app
        .summary
        .lock()
        .ok()
        .map(|s| s.clone())
        .unwrap_or_default();
    let entries_len = app.entries.lock().map(|e| e.len()).unwrap_or(0);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    let header = Line::from(vec![
        Span::styled(
            format!(" smg proxy {} ", summary.bind),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  conns: {}  http: {}  tls-tunnels: {}  errors: {}  captured: {}",
            summary.connections,
            summary.http_intercepted,
            summary.https_tunneled,
            summary.errors,
            entries_len
        )),
    ]);
    f.render_widget(Paragraph::new(header), chunks[0]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(chunks[1]);

    // History list (newest first). The three lock sites in `draw` are strictly
    // sequential (each guard drops at the end of its statement/block) — never
    // nested, so no self-deadlock is possible here.
    let items: Vec<ListItem> = {
        let entries = app.entries.lock(); // smg-ignore: SMG-ENG-DEADLOCK
        match entries {
            Ok(entries) => entries
                .iter()
                .rev()
                .take(500)
                .map(|e| {
                    let kind_tag = if e.kind == "tls" { "TLS" } else { "HTTP" };
                    let replay_tag = if e.replay_of.is_some() { " [R]" } else { "" };
                    let status_txt = if e.status == 0 {
                        "-".to_string()
                    } else {
                        e.status.to_string()
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!("{kind_tag} "),
                            Style::default().fg(if e.kind == "tls" {
                                Color::Cyan
                            } else {
                                Color::Yellow
                            }),
                        ),
                        Span::styled(
                            format!("{status_txt:>3} "),
                            Style::default().fg(status_color(e.status)),
                        ),
                        Span::raw(format!("{} {}{}", e.method, e.url, replay_tag)),
                    ]))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" History (j/k) "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, main[0], &mut app.list_state);

    // Detail panes
    let detail = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main[1]);

    let selected = app.selected();
    if let Some(entry) = selected {
        let req_content = format!(
            "{} {}\r\n{}\r\n{}",
            entry.method, entry.url, entry.req_headers, entry.req_body
        );
        let req_title = if entry.replay_of.is_some() {
            format!(" Request (replay of #{}) ", entry.replay_of.unwrap_or(0))
        } else {
            " Request ".to_string()
        };
        let req_title = if app.focus == 1 {
            format!("{req_title}[req · Tab]")
        } else {
            req_title
        };
        let req_par = Paragraph::new(detail_lines(&req_content, Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(req_title),
            )
            .wrap(Wrap { trim: false })
            .scroll((app.req_scroll, 0));
        f.render_widget(req_par, detail[0]);

        let resp_content = format!("{}\r\n{}", entry.resp_headers, entry.resp_body);
        let resp_title = format!(" Response · {} · {}ms ", entry.status, entry.duration_ms);
        let resp_title = if app.focus == 2 {
            format!("{resp_title}[resp · Tab]")
        } else {
            resp_title
        };
        let resp_par = Paragraph::new(detail_lines(&resp_content, Color::Green))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(resp_title),
            )
            .wrap(Wrap { trim: false })
            .scroll((app.resp_scroll, 0));
        f.render_widget(resp_par, detail[1]);
    } else {
        f.render_widget(
            Paragraph::new(" No captured traffic yet — point your app/browser at the proxy. "),
            main[1],
        );
    }

    let help = match &app.status_message {
        Some(msg) => Line::from(Span::styled(
            format!(" {msg} "),
            Style::default().fg(Color::Black).bg(Color::Yellow),
        )),
        None => Line::from(Span::raw(
            " j/k select · Tab focus · PgUp/PgDn scroll · r replay · d decode · i intruder · e export · x compare · q quit ",
        )),
    };
    f.render_widget(Paragraph::new(help), chunks[2]);

    match &app.modal {
        Modal::Decoder(decoded) => draw_decoder_modal(f, decoded),
        Modal::Intruder(state) => draw_intruder_modal(f, state),
        Modal::Diff(diff, from_id, to_id) => draw_diff_modal(f, diff, *from_id, *to_id),
        Modal::None => {}
    }
}

fn centered_rect(width: u16, height: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(width),
            Constraint::Fill(1),
        ])
        .split(popup[1])[1]
}

fn draw_decoder_modal(f: &mut Frame, decoded: &[(String, String)]) {
    let area = centered_rect(76, 20, f.area());
    f.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    if decoded.is_empty() {
        lines.push(Line::from(Span::raw(" (no decodable content) ")));
    }
    for (name, value) in decoded {
        lines.push(Line::from(Span::styled(
            format!("── {name} "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for l in value.lines().take(60) {
            lines.push(Line::from(Span::raw(format!("  {l}"))));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(" Decoder (Esc to close) ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_intruder_modal(f: &mut Frame, state: &IntruderState) {
    let area = centered_rect(84, 22, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(" Intruder — wordlist fuzz ({FUZZ} marker, GET, max 100 words) (Esc closes) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    let cursor = |on: bool| if on { "▸ " } else { "  " };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(cursor(state.focus == 0), Style::default().fg(Color::Yellow)),
            Span::raw("URL template: "),
            Span::styled(&state.url_field, Style::default().fg(Color::White)),
        ])),
        rows[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(cursor(state.focus == 1), Style::default().fg(Color::Yellow)),
            Span::raw("Wordlist file: "),
            Span::styled(&state.wordlist_field, Style::default().fg(Color::White)),
        ])),
        rows[2],
    );
    if let Some(msg) = &state.message {
        f.render_widget(
            Paragraph::new(Span::styled(
                msg.clone(),
                Style::default().fg(Color::Magenta),
            )),
            rows[4],
        );
    }
    let result_items: Vec<ListItem> = state
        .results
        .iter()
        .map(|(word, status, len)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{status:>3} "),
                    Style::default().fg(status_color(*status)),
                ),
                Span::raw(format!("{len:>6}B ")),
                Span::raw(word.clone()),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(result_items).block(Block::default().borders(Borders::TOP).title(" Results ")),
        rows[5],
    );
}

fn draw_diff_modal(f: &mut Frame, diff: &[(char, String)], from_id: u64, to_id: u64) {
    let area = centered_rect(88, 24, f.area());
    f.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    let same = diff.iter().filter(|(t, _)| *t == ' ').count();
    let removed = diff.iter().filter(|(t, _)| *t == '-').count();
    let added = diff.iter().filter(|(t, _)| *t == '+').count();
    lines.push(Line::from(Span::styled(
        format!(" #{from_id} → #{to_id}   same: {same}   removed: {removed}   added: {added} "),
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    for (tag, text) in diff.iter().take(900) {
        let style = match tag {
            '-' => Style::default().fg(Color::Red),
            '+' => Style::default().fg(Color::Green),
            _ => Style::default().fg(Color::DarkGray),
        };
        lines.push(Line::from(Span::styled(format!("{tag} {text}"), style)));
    }
    if diff.len() > 900 {
        lines.push(Line::from(Span::styled(
            format!(
                " … {} more lines (export entries with `e` for the full text)",
                diff.len() - 900
            ),
            Style::default().fg(Color::Yellow),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(" Compare — line diff A → B (Esc closes) ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

struct ProxyTerminalGuard;

static PROXY_TUI_PANIC_HOOK: std::sync::Once = std::sync::Once::new();

impl ProxyTerminalGuard {
    fn enter() -> Result<Self> {
        PROXY_TUI_PANIC_HOOK.call_once(|| {
            let orig = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let _ = disable_raw_mode();
                let _ = execute!(stdout(), LeaveAlternateScreen);
                orig(info);
            }));
        });
        enable_raw_mode()?;
        if let Err(e) = execute!(stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(e.into());
        }
        Ok(Self)
    }
}

impl Drop for ProxyTerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

/// Blocking TUI loop. Returns when the user presses `q` (or `Esc` closes a
/// modal / `Ctrl+C` quits) or the terminal fails.
pub fn run_proxy_tui(
    entries: Arc<Mutex<Vec<Arc<ProxyEntry>>>>,
    summary: Arc<Mutex<ProxySummary>>,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _term_guard = ProxyTerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App {
        entries,
        summary,
        list_state: ListState::default(),
        focus: 0,
        req_scroll: 0,
        resp_scroll: 0,
        modal: Modal::None,
        quit: false,
        status_message: None,
        compare_from: None,
    };

    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|f| draw(f, &mut app))?;
            if !event::poll(Duration::from_millis(250))? {
                continue;
            }
            let Ok(ev) = event::read() else {
                continue;
            };
            let Event::Key(key) = ev else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match &mut app.modal {
                Modal::Decoder(_) => {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                        app.modal = Modal::None;
                    }
                }
                Modal::Diff(_, _, _) => {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                        app.modal = Modal::None;
                    }
                }
                Modal::Intruder(state) => match key.code {
                    KeyCode::Esc => app.modal = Modal::None,
                    KeyCode::Tab => state.focus = (state.focus + 1) % 2,
                    KeyCode::Backspace => {
                        let field = if state.focus == 0 {
                            &mut state.url_field
                        } else {
                            &mut state.wordlist_field
                        };
                        field.pop();
                    }
                    KeyCode::Enter => {
                        if state.url_field.is_empty() || !state.url_field.contains("{FUZZ}") {
                            state.message = Some("URL must contain the {FUZZ} marker".into());
                        } else if state.wordlist_field.is_empty() {
                            state.message = Some("wordlist path required".into());
                        } else {
                            match std::fs::read_to_string(&state.wordlist_field) {
                                Ok(content) => {
                                    let words: Vec<String> = content
                                        .lines()
                                        .map(|l| l.trim().to_string())
                                        .filter(|l| !l.is_empty())
                                        .take(MAX_INTRUDER_WORDS)
                                        .collect();
                                    state.results =
                                        intruder_run(&state.url_field, &words, INTRUDER_TIMEOUT);
                                    state.message =
                                        Some(format!("{} word(s) tested", state.results.len()));
                                }
                                Err(e) => {
                                    state.message = Some(format!("wordlist read failed: {e}"));
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                            app.quit = true;
                            app.modal = Modal::None;
                        } else {
                            let field = if state.focus == 0 {
                                &mut state.url_field
                            } else {
                                &mut state.wordlist_field
                            };
                            field.push(c);
                        }
                    }
                    _ => {}
                },
                Modal::None => match key.code {
                    KeyCode::Char('q') => app.quit = true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.quit = true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => app.select_next(1),
                    KeyCode::Char('k') | KeyCode::Up => app.select_next(-1),
                    KeyCode::Tab => app.focus = (app.focus + 1) % 3,
                    KeyCode::PageDown => match app.focus {
                        1 => app.req_scroll = app.req_scroll.saturating_add(10),
                        2 => app.resp_scroll = app.resp_scroll.saturating_add(10),
                        _ => {}
                    },
                    KeyCode::PageUp => match app.focus {
                        1 => app.req_scroll = app.req_scroll.saturating_sub(10),
                        2 => app.resp_scroll = app.resp_scroll.saturating_sub(10),
                        _ => {}
                    },
                    KeyCode::Char('r') => {
                        let Some(entry) = app.selected() else {
                            app.status_message = Some("nothing selected".into());
                            continue;
                        };
                        let client = Client::builder()
                            .timeout(Duration::from_secs(10))
                            .redirect(reqwest::redirect::Policy::none())
                            // Replayer targets the user's own lab app only.
                            .danger_accept_invalid_certs(true) // smg-ignore: SMG-CFG-TLS
                            .build()?;
                        match replay_entry(&client, &entry) {
                            Ok(replayed) => {
                                app.push_entry(replayed);
                            }
                            Err(e) => app.status_message = Some(format!("replay failed: {e}")),
                        }
                    }
                    KeyCode::Char('d') => {
                        let Some(entry) = app.selected() else {
                            app.status_message = Some("nothing selected".into());
                            continue;
                        };
                        let source = if entry.req_body.trim().is_empty() {
                            entry.resp_body.clone()
                        } else {
                            entry.req_body.clone()
                        };
                        app.modal = Modal::Decoder(decode_all(&source));
                    }
                    KeyCode::Char('i') => {
                        app.modal = Modal::Intruder(IntruderState::default());
                    }
                    KeyCode::Char('e') => {
                        let Some(entry) = app.selected() else {
                            app.status_message = Some("nothing selected".into());
                            continue;
                        };
                        let content = format!(
                            "{} {}\n{}\n\n--- request body ---\n{}\n\n--- response ({} {}ms) ---\n{}\n{}",
                            entry.method,
                            entry.url,
                            entry.req_headers,
                            entry.req_body,
                            entry.status,
                            entry.duration_ms,
                            entry.resp_headers,
                            entry.resp_body
                        );
                        let export_res = (|| -> std::io::Result<std::path::PathBuf> {
                            let dir = std::env::temp_dir()
                                .join(format!("smg-proxy-exports-{}", std::process::id()));
                            std::fs::create_dir_all(&dir)?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(
                                    &dir,
                                    std::fs::Permissions::from_mode(0o700),
                                );
                            }
                            let path =
                                dir.join(format!("entry-{}-{}.txt", entry.id, now_unix_ms()));
                            let mut opts = std::fs::OpenOptions::new();
                            opts.write(true).create_new(true);
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::OpenOptionsExt;
                                opts.mode(0o600);
                            }
                            use std::io::Write as _;
                            let mut f = opts.open(&path)?;
                            f.write_all(content.as_bytes())?;
                            Ok(path)
                        })();
                        match export_res {
                            Ok(path) => {
                                app.status_message = Some(format!("exported to {}", path.display()))
                            }
                            Err(e) => app.status_message = Some(format!("export failed: {e}")),
                        }
                    }
                    KeyCode::Char('x') => {
                        let Some(entry) = app.selected() else {
                            app.status_message = Some("nothing selected".into());
                            continue;
                        };
                        match app.compare_from {
                            None => {
                                app.compare_from = Some(entry.id);
                                app.status_message = Some(format!(
                                    "compare-from: #{} (navigate to another entry and press x again)",
                                    entry.id
                                ));
                            }
                            Some(from_id) => {
                                if from_id == entry.id {
                                    app.status_message = Some(
                                        "compare target equals source; pick a different entry"
                                            .into(),
                                    );
                                    continue;
                                }
                                let entries = app.entries.lock().ok();
                                let Some(entries) = entries else {
                                    continue;
                                };
                                let Some(base) = entries.iter().find(|e| e.id == from_id) else {
                                    app.status_message = Some(format!(
                                        "compare-from #{} no longer captured",
                                        from_id
                                    ));
                                    app.compare_from = None;
                                    continue;
                                };
                                let diff = diff_lines(
                                    &entry_transaction_text(base),
                                    &entry_transaction_text(&entry),
                                );
                                app.modal = Modal::Diff(diff, from_id, entry.id);
                                app.compare_from = None;
                            }
                        }
                    }
                    _ => {}
                },
            }
            if app.quit {
                break;
            }
        }
        Ok(())
    })();

    drop(_term_guard);
    result
}

// ---------------------------------------------------------------------------
// Tests (pure helpers + replay/intruder against loopback mocks)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn decode_all_handles_base64_url_and_jwt() {
        let out = decode_all("aGVsbG8=");
        assert_eq!(out[0].0, "Base64");
        assert_eq!(out[0].1, "hello");

        let out = decode_all("a%20b+c");
        assert!(out.iter().any(|(n, v)| n == "URL" && v == "a b c"));

        // JWT: header {"alg":"HS256","typ":"JWT"} payload {"sub":"1234567890"}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jWCNH6pQliPdpkIcTCZYMAAAKCNhXH8";
        let out = decode_all(jwt);
        assert!(
            out.iter()
                .any(|(n, v)| n == "JWT Header" && v.contains("HS256"))
        );
        assert!(
            out.iter()
                .any(|(n, v)| n == "JWT Payload" && v.contains("1234567890"))
        );
    }

    #[test]
    fn decode_all_is_empty_for_plain_text() {
        assert!(decode_all("just some plain sentence").is_empty());
    }

    #[test]
    fn diff_lines_marks_changes_and_preserves_order() {
        let a = "GET /a\r\nHost: x\r\nid=1\r\nfooter";
        let b = "GET /b\r\nHost: x\r\nid=2\r\nfooter\r\nextra";
        let diff = diff_lines(a, b);
        let tags: Vec<char> = diff.iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, vec!['-', '+', ' ', '-', '+', ' ', '+']);
        let added: Vec<&str> = diff
            .iter()
            .filter(|(t, _)| *t == '+')
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(added, vec!["GET /b", "id=2", "extra"]);
        let removed: Vec<&str> = diff
            .iter()
            .filter(|(t, _)| *t == '-')
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(removed, vec!["GET /a", "id=1"]);
        // Identical texts produce only same-lines.
        assert!(diff_lines("a\n", "a\n").iter().all(|(t, _)| *t == ' '));
        // Long inputs are bounded.
        let big = "x\n".repeat(4_000);
        assert!(diff_lines(&big, &big).len() <= DIFF_MAX_LINES);
    }

    fn echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..128 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                // Header names arrive lowercased from hyper, so match
                // case-insensitively.
                let echo = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("x-echo:"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_else(|| "no-echo".into());
                let body = format!("echo:{echo}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn sample_entry(url: String) -> ProxyEntry {
        ProxyEntry {
            id: 7,
            ts_unix_ms: now_unix_ms(),
            kind: "http".into(),
            method: "GET".into(),
            url,
            status: 200,
            req_headers: "X-Echo: replay-token-42\r\n".into(),
            req_body: String::new(),
            resp_headers: String::new(),
            resp_body: String::new(),
            duration_ms: 0,
            replay_of: None,
        }
    }

    #[test]
    fn replay_entry_sends_headers_and_captures_response() {
        let base = echo_server();
        let entry = sample_entry(format!("{base}/echo"));
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let replayed = replay_entry(&client, &entry).unwrap();
        assert_eq!(replayed.status, 200);
        assert!(replayed.resp_body.contains("echo:replay-token-42"));
        assert_eq!(replayed.replay_of, Some(7));
    }

    #[test]
    fn replay_rejects_tls_tunnels() {
        let entry = ProxyEntry {
            id: 1,
            ts_unix_ms: 0,
            kind: "tls".into(),
            method: "CONNECT".into(),
            url: "127.0.0.1:443".into(),
            status: 200,
            req_headers: String::new(),
            req_body: String::new(),
            resp_headers: String::new(),
            resp_body: String::new(),
            duration_ms: 0,
            replay_of: None,
        };
        let client = Client::builder().build().unwrap();
        assert!(replay_entry(&client, &entry).is_err());
    }

    #[test]
    fn intruder_run_reports_status_and_size() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..32 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let word = req
                    .split(' ')
                    .nth(1)
                    .and_then(|p| p.split("w=").nth(1))
                    .unwrap_or("");
                let body = format!("hit:{word}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let results = intruder_run(
            &format!("http://{addr}/fuzz?w={{FUZZ}}"),
            &["admin".to_string(), "backup".to_string()],
            Duration::from_secs(10),
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "admin");
        assert_eq!(results[0].1, 200);
        assert!(results[0].2 > 0);
    }
}
