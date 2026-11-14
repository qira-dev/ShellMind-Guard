use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use vf_ai::build_minimal_patch_prompt;
use vf_graph::{GraphAnalysisResult, GuardKind, LatticeFinding, SinkKind};
use vf_report::{to_html_graph, to_sarif_json};
use vf_sandbox::{VerificationStatus, VerifiedFinding, verify_findings_in_sandbox};

const MAX_LOG_LINES: usize = 200;

// ============================================================================
// STRICT SEMANTIC COLOR SYSTEM (Zero Arbitrary Colors)
// - RED        (#f85149): ONLY Proven Exploit / Active Vulnerable Line
// - AMBER      (#d29922): ONLY Static Suspect / Unverified Warning
// - GREEN      (#3fb950): ONLY Safe / Mitigated / Isolated Sandbox
// - CYAN       (#58a6ff): ONLY Brand Identity / Active Focus / Navigation
// - PURPLE     (#bc8cff): Concurrency / Race Category & Language Keywords
// - CORAL      (#ffa657): Auth / Access Category & Target Symbols
// ============================================================================
const BG_CANVAS: Color = Color::Rgb(13, 17, 23);
const BG_CARD_SELECTED: Color = Color::Rgb(24, 34, 50);
const BG_VULN_LINE: Color = Color::Rgb(62, 22, 28);
const BG_PILL_DARK: Color = Color::Rgb(33, 38, 45);
const BORDER_SUBTLE: Color = Color::Rgb(48, 54, 61);
const BORDER_ACTIVE: Color = Color::Rgb(88, 166, 255);

const FG_PRIMARY: Color = Color::Rgb(230, 237, 243);
const FG_SECONDARY: Color = Color::Rgb(139, 148, 158);
const FG_DIM: Color = Color::Rgb(72, 79, 88);

const SEM_PROVEN_RED: Color = Color::Rgb(248, 81, 73);
const SEM_SUSPECT_AMBER: Color = Color::Rgb(210, 153, 34);
const SEM_SAFE_GREEN: Color = Color::Rgb(63, 185, 80);
const SEM_BRAND_CYAN: Color = Color::Rgb(88, 166, 255);
const SEM_RACE_PURPLE: Color = Color::Rgb(188, 140, 255);
const SEM_AUTH_CORAL: Color = Color::Rgb(255, 166, 87);
const SYN_STRING_BLUE: Color = Color::Rgb(165, 214, 255);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterMode {
    All,
    ProvenOnly,
    CriticalOnly,
}

impl FilterMode {
    fn next(self) -> Self {
        match self {
            FilterMode::All => FilterMode::ProvenOnly,
            FilterMode::ProvenOnly => FilterMode::CriticalOnly,
            FilterMode::CriticalOnly => FilterMode::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FilterMode::All => "ALL",
            FilterMode::ProvenOnly => "PROVEN ONLY",
            FilterMode::CriticalOnly => "CRITICAL ONLY",
        }
    }
}

pub struct TuiLaunchConfig {
    pub boot_cmd: Option<String>,
    pub port: u16,
    pub sync_race: usize,
    pub unsafe_host_fallback: bool,
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn init() -> Result<Self> {
        let orig_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            orig_hook(info);
        }));

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

struct TuiState {
    project_root: PathBuf,
    canon_root: Option<PathBuf>,
    graph: GraphAnalysisResult,
    verified_map: HashMap<String, VerifiedFinding>,
    elapsed_ms: u128,
    selected_idx: usize,
    selected_hop: usize,
    filter_mode: FilterMode,
    show_logs: bool,
    show_help: bool,
    patch_modal: Option<(String, String)>,
    logs: VecDeque<String>,
    file_cache: HashMap<String, Vec<String>>,
    sandbox_isolated: bool,
    last_action: String,
}

impl TuiState {
    fn new(
        project_root: &Path,
        graph: GraphAnalysisResult,
        verified: Vec<VerifiedFinding>,
        elapsed_ms: u128,
    ) -> Self {
        let canon_root = fs::canonicalize(project_root).ok();
        let mut verified_map = HashMap::new();
        for v in verified {
            verified_map.insert(v.finding_id.clone(), v);
        }
        let init_msg = format!(
            "Ready — Scanned {} files ({} symbols, {} edges, {} routes) in {}ms.",
            graph.parsed_files,
            graph.symbol_count,
            graph.edge_count,
            graph.route_entries,
            elapsed_ms
        );
        let logs = VecDeque::from([
            init_msg.clone(),
            format!(
                "Sandbox engine: {} ({} findings verified).",
                if vf_sandbox::has_bwrap() {
                    "Bubblewrap --unshare-all (PID/IPC/UTS/Net isolated)"
                } else {
                    "Host Fallback"
                },
                verified_map.len()
            ),
        ]);

        Self {
            project_root: project_root.to_path_buf(),
            canon_root,
            graph,
            verified_map,
            elapsed_ms,
            selected_idx: 0,
            selected_hop: 0,
            filter_mode: FilterMode::All,
            show_logs: false,
            show_help: false,
            patch_modal: None,
            logs,
            file_cache: HashMap::new(),
            sandbox_isolated: vf_sandbox::has_bwrap(),
            last_action: init_msg,
        }
    }

    fn push_log(&mut self, msg: String) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.last_action = msg.clone();
        self.logs.push_back(msg);
    }

    fn filtered_findings(&self) -> Vec<&LatticeFinding> {
        self.graph
            .findings
            .iter()
            .filter(|f| match self.filter_mode {
                FilterMode::All => true,
                FilterMode::ProvenOnly => matches!(
                    self.verified_map.get(&f.id).map(|v| &v.status),
                    Some(VerificationStatus::Proven)
                ),
                FilterMode::CriticalOnly => f.severity == "CRITICAL",
            })
            .collect()
    }

    fn current_finding(&self) -> Option<LatticeFinding> {
        let list = self.filtered_findings();
        if list.is_empty() {
            return None;
        }
        let idx = self.selected_idx.min(list.len() - 1);
        Some(list[idx].clone())
    }

    fn read_lines_contained(&mut self, rel_path: &str) -> Vec<String> {
        if let Some(cached) = self.file_cache.get(rel_path) {
            return cached.clone();
        }
        let mut lines_out = Vec::new();
        if let Some(root) = &self.canon_root {
            let joined = root.join(rel_path);
            if let Ok(canon_file) = fs::canonicalize(&joined)
                && canon_file.starts_with(root)
                && let Ok(raw) = fs::read_to_string(&canon_file)
            {
                lines_out = raw.lines().map(|s| s.to_string()).collect();
            }
        }
        self.file_cache
            .insert(rel_path.to_string(), lines_out.clone());
        lines_out
    }

    fn proof_counts(&self) -> (usize, usize, usize) {
        let mut proven = 0;
        let mut mitigated = 0;
        let mut suspect = 0;
        for f in &self.graph.findings {
            match self.verified_map.get(&f.id).map(|v| &v.status) {
                Some(VerificationStatus::Proven) => proven += 1,
                Some(VerificationStatus::Mitigated) => mitigated += 1,
                _ => suspect += 1,
            }
        }
        (proven, mitigated, suspect)
    }
}

fn render_ui(f: &mut Frame, state: &mut TuiState) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG_CANVAS)), area);

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(14),
            Constraint::Length(if state.show_logs { 8 } else { 4 }),
        ])
        .split(area);

    render_brand_header(f, root_chunks[0], state);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(root_chunks[1]);

    // Left Column: Top System & Semantic Legend (6 lines) + Bottom Vulnerability Queue
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(8)])
        .split(body_chunks[0]);

    render_system_legend_card(f, left_chunks[0], state);
    render_findings_queue(f, left_chunks[1], state);

    // Right Column: Top Cross-File Pipeline (6 lines) + Middle Source Inspector + Bottom Proof & Remediation (8 lines)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(body_chunks[1]);

    render_pipeline_card(f, right_chunks[0], state);
    render_source_inspector(f, right_chunks[1], state);
    render_proof_and_remediation(f, right_chunks[2], state);

    render_footer(f, root_chunks[2], state);

    if state.show_help {
        render_help_modal(f, area);
    } else if let Some((ref fid, ref prompt_txt)) = state.patch_modal {
        render_patch_modal(f, area, fid, prompt_txt);
    }
}

fn render_brand_header(f: &mut Frame, area: Rect, state: &TuiState) {
    let (proven, mitigated, suspect) = state.proof_counts();

    let proven_span = if proven > 0 {
        Span::styled(
            format!(" ● PROVEN: {} ", proven),
            Style::default()
                .fg(Color::White)
                .bg(SEM_PROVEN_RED)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ● PROVEN: 0 ", Style::default().fg(FG_DIM))
    };

    let suspect_span = if suspect > 0 {
        Span::styled(
            format!(" ◆ SUSPECT: {} ", suspect),
            Style::default()
                .fg(Color::Black)
                .bg(SEM_SUSPECT_AMBER)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ◆ SUSPECT: 0 ", Style::default().fg(FG_DIM))
    };

    let mitigated_span = if mitigated > 0 {
        Span::styled(
            format!(" ✓ MITIGATED: {} ", mitigated),
            Style::default()
                .fg(Color::Black)
                .bg(SEM_SAFE_GREEN)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ✓ MITIGATED: 0 ", Style::default().fg(FG_DIM))
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " ◆ VERIFORGE ",
            Style::default()
                .fg(Color::Black)
                .bg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " by Qira-Dev ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .bg(BG_PILL_DARK)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(BORDER_SUBTLE)),
        Span::styled(
            format!("{}", state.project_root.display()),
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " ({} files · {} sym · {}ms) ",
                state.graph.parsed_files, state.graph.symbol_count, state.elapsed_ms
            ),
            Style::default().fg(FG_SECONDARY),
        ),
        Span::styled("│ ", Style::default().fg(BORDER_SUBTLE)),
        proven_span,
        Span::raw(" "),
        suspect_span,
        Span::raw(" "),
        mitigated_span,
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_SUBTLE)),
    );
    f.render_widget(header, area);
}

fn render_system_legend_card(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Engine Telemetry & Color Legend ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    let sb_span = if state.sandbox_isolated {
        Span::styled(
            "● bwrap --unshare-all (Net/PID/FS Isolated)",
            Style::default()
                .fg(SEM_SAFE_GREEN)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "◆ Host Loopback Fallback",
            Style::default().fg(SEM_SUSPECT_AMBER),
        )
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Sandbox : ", Style::default().fg(FG_SECONDARY)),
            sb_span,
        ]),
        Line::from(vec![
            Span::styled("  Engine  : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "O(V+E) Guard-Set Lattice  │  Routes: {}  │  Edges: {}",
                    state.graph.route_entries, state.graph.edge_count
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Verdict : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                "● PROVEN Exploit",
                Style::default()
                    .fg(SEM_PROVEN_RED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled("◆ SUSPECT Static", Style::default().fg(SEM_SUSPECT_AMBER)),
            Span::raw("   "),
            Span::styled("✓ MITIGATED", Style::default().fg(SEM_SAFE_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  Defect  : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                "[CRIT · RACE]",
                Style::default()
                    .fg(SEM_RACE_PURPLE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Double-Spend  ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                "[HIGH · AUTH]",
                Style::default()
                    .fg(SEM_AUTH_CORAL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Missing Auth", Style::default().fg(FG_SECONDARY)),
        ]),
    ];

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_findings_queue(f: &mut Frame, area: Rect, state: &TuiState) {
    let filtered = state.filtered_findings();
    let sel_idx = if filtered.is_empty() {
        0
    } else {
        state.selected_idx.min(filtered.len() - 1)
    };

    let items: Vec<ListItem> = if filtered.is_empty() {
        vec![ListItem::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  ✓ No matching vulnerabilities in current filter.",
                Style::default()
                    .fg(SEM_SAFE_GREEN)
                    .add_modifier(Modifier::BOLD),
            )),
        ])]
    } else {
        filtered
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let is_sel = idx == sel_idx;
                let row_bg = if is_sel { BG_CARD_SELECTED } else { BG_CANVAS };

                let (verdict_icon, verdict_label, verdict_color) =
                    match state.verified_map.get(&item.id).map(|v| &v.status) {
                        Some(VerificationStatus::Proven) => ("●", "PROVEN", SEM_PROVEN_RED),
                        Some(VerificationStatus::Mitigated) => ("✓", "MITIGATED", SEM_SAFE_GREEN),
                        _ => ("◆", "SUSPECT", SEM_SUSPECT_AMBER),
                    };

                let (cat_tag, cat_color, missing_desc) = match item.missing_guard {
                    GuardKind::TxLock => (
                        "[CRIT · RACE]",
                        SEM_RACE_PURPLE,
                        "Missing: TxLock / FOR UPDATE",
                    ),
                    GuardKind::Auth => {
                        ("[HIGH · AUTH]", SEM_AUTH_CORAL, "Missing: Auth Middleware")
                    }
                };

                let sink_hop = item.witness_path.last();
                let sink_str = sink_hop
                    .map(|h| {
                        let short = h.file.rsplit('/').next().unwrap_or(&h.file);
                        format!("{}() @ {}:{}", h.symbol, short, h.line)
                    })
                    .unwrap_or_else(|| "sink".into());

                let cursor_str = if is_sel { "▌ " } else { "  " };
                let cursor_color = if is_sel { SEM_BRAND_CYAN } else { BG_CANVAS };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(
                            cursor_str,
                            Style::default()
                                .fg(cursor_color)
                                .bg(row_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{} {} ", verdict_icon, verdict_label),
                            Style::default()
                                .fg(verdict_color)
                                .bg(row_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {} ", item.id),
                            Style::default()
                                .fg(FG_PRIMARY)
                                .bg(row_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {}", cat_tag),
                            Style::default()
                                .fg(cat_color)
                                .bg(row_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ])
                    .style(Style::default().bg(row_bg)),
                    Line::from(vec![
                        Span::styled(cursor_str, Style::default().fg(cursor_color).bg(row_bg)),
                        Span::styled("  Route : ", Style::default().fg(FG_SECONDARY).bg(row_bg)),
                        Span::styled(
                            item.entry_route.clone(),
                            Style::default().fg(FG_PRIMARY).bg(row_bg),
                        ),
                    ])
                    .style(Style::default().bg(row_bg)),
                    Line::from(vec![
                        Span::styled(cursor_str, Style::default().fg(cursor_color).bg(row_bg)),
                        Span::styled("  Sink  : ", Style::default().fg(FG_SECONDARY).bg(row_bg)),
                        Span::styled(sink_str, Style::default().fg(SEM_BRAND_CYAN).bg(row_bg)),
                        Span::styled(
                            format!("  ({})", missing_desc),
                            Style::default().fg(FG_SECONDARY).bg(row_bg),
                        ),
                    ])
                    .style(Style::default().bg(row_bg)),
                ])
            })
            .collect()
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .title(Span::styled(
                format!(
                    " ◆ Vulnerability Queue ({}/{}) · Filter: {} [f] ",
                    filtered.len(),
                    state.graph.findings.len(),
                    state.filter_mode.label()
                ),
                Style::default()
                    .fg(SEM_BRAND_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

fn render_pipeline_card(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Cross-File Call & Guard Pipeline (←/→ or Tab to inspect hop) ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    let lines = if let Some(cur) = state.current_finding() {
        let total_hops = cur.witness_path.len();
        let active_hop_idx = state.selected_hop.min(total_hops.saturating_sub(1));
        let mut hop_spans = vec![Span::raw("  ")];

        for (idx, hop) in cur.witness_path.iter().enumerate() {
            if idx > 0 {
                hop_spans.push(Span::styled(" ──▶ ", Style::default().fg(SEM_BRAND_CYAN)));
            }
            let role = if idx == 0 {
                "ENTRY"
            } else if idx + 1 == total_hops {
                "SINK"
            } else {
                "CALL"
            };
            let short_file = hop.file.rsplit('/').next().unwrap_or(&hop.file);
            let badge = format!(" [{}: {}] {}:{} ", idx + 1, role, short_file, hop.line);
            if idx == active_hop_idx {
                hop_spans.push(Span::styled(
                    badge,
                    Style::default()
                        .fg(Color::Black)
                        .bg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ));
            } else {
                hop_spans.push(Span::styled(
                    badge,
                    Style::default().fg(FG_PRIMARY).bg(BG_PILL_DARK),
                ));
            }
        }

        let hop_info = cur
            .witness_path
            .get(active_hop_idx)
            .map(|h| format!("{}  ({}:{})", h.symbol, h.file, h.line))
            .unwrap_or_default();

        let (req_guard, sink_label) = match (cur.missing_guard, cur.sink_kind) {
            (GuardKind::Auth, sk) => ("Auth Guard (requireAuth / verifyJwt)", format!("{:?}", sk)),
            (GuardKind::TxLock, sk) => (
                "Atomic Lock (withTransaction / SELECT ... FOR UPDATE)",
                format!("{:?}", sk),
            ),
        };

        vec![
            Line::from(hop_spans),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Inspecting Hop : ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    hop_info,
                    Style::default()
                        .fg(SEM_AUTH_CORAL)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Missing Guard  : ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    req_guard,
                    Style::default()
                        .fg(SEM_PROVEN_RED)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  │  Target Sink: {}", sink_label),
                    Style::default().fg(FG_SECONDARY),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  Select a vulnerability from the queue to inspect its call pipeline.",
            Style::default().fg(FG_SECONDARY),
        ))]
    };

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn highlight_code_line(line: &str, row_bg: Color) -> Vec<Span<'static>> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return vec![Span::styled(
            line.to_string(),
            Style::default().fg(FG_SECONDARY).bg(row_bg),
        )];
    }

    let keywords = [
        "import", "from", "export", "default", "async", "await", "function", "const", "let",
        "return", "if", "else", "pub", "fn", "use", "def", "class",
    ];
    let security_tokens = [
        "requireAuth",
        "withTransaction",
        "processWithdrawal",
        "debitBalance",
        "creditBalanceWithTx",
        "update_role_in_db",
        "promote_user_role",
    ];

    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '\'' || ch == '"' || ch == '`' {
            if !current.is_empty() {
                spans.push(Span::styled(
                    std::mem::take(&mut current),
                    Style::default().fg(FG_PRIMARY).bg(row_bg),
                ));
            }
            let quote = ch;
            let mut s_lit = String::from(quote);
            i += 1;
            while i < chars.len() {
                let c = chars[i];
                s_lit.push(c);
                i += 1;
                if c == quote {
                    break;
                }
            }
            spans.push(Span::styled(
                s_lit,
                Style::default().fg(SYN_STRING_BLUE).bg(row_bg),
            ));
            continue;
        }

        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                current.push(chars[i]);
                i += 1;
            }
            let word = std::mem::take(&mut current);
            let style = if keywords.contains(&word.as_str()) {
                Style::default()
                    .fg(SEM_RACE_PURPLE)
                    .bg(row_bg)
                    .add_modifier(Modifier::BOLD)
            } else if security_tokens.contains(&word.as_str()) {
                Style::default()
                    .fg(SEM_AUTH_CORAL)
                    .bg(row_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(FG_PRIMARY).bg(row_bg)
            };
            spans.push(Span::styled(word, style));
            continue;
        }

        current.push(ch);
        i += 1;
    }

    if !current.is_empty() {
        spans.push(Span::styled(
            current,
            Style::default().fg(FG_PRIMARY).bg(row_bg),
        ));
    }

    spans
}

fn render_source_inspector(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let cur_opt = state.current_finding();
    let hop_opt = cur_opt.as_ref().and_then(|c| {
        let idx = state
            .selected_hop
            .min(c.witness_path.len().saturating_sub(1));
        c.witness_path
            .get(idx)
            .cloned()
            .map(|h| (idx, c.witness_path.len(), h))
    });

    let inner_width = area.width.saturating_sub(2) as usize;

    let (title, rendered_lines) = if let Some((hop_idx, total_hops, hop)) = hop_opt {
        let all_lines = state.read_lines_contained(&hop.file);
        let role = if hop_idx == 0 {
            "ENTRY ROUTE"
        } else if hop_idx + 1 == total_hops {
            "VULNERABLE SINK"
        } else {
            "CALL HOP"
        };
        let title = format!(
            " ◆ Source Inspector — {}:{} [Hop {}/{}: {}] ",
            hop.file,
            hop.line,
            hop_idx + 1,
            total_hops,
            role
        );
        if all_lines.is_empty() {
            (
                title,
                vec![Line::from(Span::styled(
                    "  <source unavailable>",
                    Style::default().fg(FG_SECONDARY),
                ))],
            )
        } else {
            let visible_rows = area.height.saturating_sub(2) as usize;
            let target_idx = hop.line.saturating_sub(1);
            let half = visible_rows / 2;
            let start = target_idx.saturating_sub(half);
            let end = (start + visible_rows).min(all_lines.len());

            let lines: Vec<Line> = (start..end)
                .map(|i| {
                    let ln = i + 1;
                    let raw_line = &all_lines[i];
                    if ln == hop.line {
                        let prefix = format!("▶ {:>4} │ ", ln);
                        let suffix = format!("  ◄ [{}]", role);
                        let used = prefix.chars().count()
                            + raw_line.chars().count()
                            + suffix.chars().count();
                        let pad = " ".repeat(inner_width.saturating_sub(used));
                        let mut spans = vec![Span::styled(
                            prefix,
                            Style::default()
                                .fg(SEM_PROVEN_RED)
                                .bg(BG_VULN_LINE)
                                .add_modifier(Modifier::BOLD),
                        )];
                        spans.extend(highlight_code_line(raw_line, BG_VULN_LINE));
                        spans.push(Span::styled(
                            format!("{}{}", suffix, pad),
                            Style::default()
                                .fg(SEM_PROVEN_RED)
                                .bg(BG_VULN_LINE)
                                .add_modifier(Modifier::BOLD),
                        ));
                        Line::from(spans).style(Style::default().bg(BG_VULN_LINE))
                    } else {
                        let mut spans = vec![Span::styled(
                            format!("  {:>4} │ ", ln),
                            Style::default().fg(FG_DIM).bg(BG_CANVAS),
                        )];
                        spans.extend(highlight_code_line(raw_line, BG_CANVAS));
                        Line::from(spans)
                    }
                })
                .collect();
            (title, lines)
        }
    } else {
        (
            " ◆ Source Inspector ".to_string(),
            vec![Line::from(Span::styled(
                "  No source hop selected.",
                Style::default().fg(FG_SECONDARY),
            ))],
        )
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            title,
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    f.render_widget(Paragraph::new(rendered_lines).block(block), area);
}

fn render_proof_and_remediation(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Sandbox Proof, Remediation & Replay ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    let lines = if let Some(cur) = state.current_finding() {
        let remediation = match (cur.missing_guard, cur.sink_kind) {
            (GuardKind::Auth, _) => format!(
                "Attach authentication middleware (`requireAuth` / `verifyJwt`) to `{}` before invoking downstream handlers.",
                cur.entry_route
            ),
            (GuardKind::TxLock, SinkKind::BalanceUpdate | SinkKind::PaymentMutation) => {
                "Wrap balance/payment mutation in an atomic DB transaction (`withTransaction` / `SELECT ... FOR UPDATE`) or enforce an idempotency key.".to_string()
            }
            (GuardKind::TxLock, _) => {
                "Acquire a transaction lock before executing state mutation.".to_string()
            }
        };

        if let Some(v) = state.verified_map.get(&cur.id) {
            let (badge_txt, badge_color) = match v.status {
                VerificationStatus::Proven => ("● EXPLOIT PROVEN", SEM_PROVEN_RED),
                VerificationStatus::Mitigated => ("✓ MITIGATED AT RUNTIME", SEM_SAFE_GREEN),
                VerificationStatus::SuspectUnverified => {
                    ("◆ SUSPECT / UNVERIFIED", SEM_SUSPECT_AMBER)
                }
            };
            vec![
                Line::from(vec![
                    Span::styled("  Proof   : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(
                        format!("{} ", badge_txt),
                        Style::default()
                            .fg(badge_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("— {}", v.evidence), Style::default().fg(FG_PRIMARY)),
                ]),
                Line::from(vec![
                    Span::styled("  Fix     : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(remediation, Style::default().fg(SEM_SAFE_GREEN)),
                ]),
                Line::from(vec![
                    Span::styled("  Replay  : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(v.replay_cmd.clone(), Style::default().fg(SEM_BRAND_CYAN)),
                ]),
            ]
        } else {
            vec![
                Line::from(vec![
                    Span::styled("  Proof   : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(
                        "◆ STATIC LATTICE WITNESS (Press [Enter] with --boot-cmd to run isolated bwrap exploit)",
                        Style::default().fg(SEM_SUSPECT_AMBER),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Fix     : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(remediation, Style::default().fg(SEM_SAFE_GREEN)),
                ]),
                Line::from(vec![
                    Span::styled("  CLI     : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(
                        format!(
                            "veriforge replay {} {}",
                            cur.id,
                            state.project_root.display()
                        ),
                        Style::default().fg(SEM_BRAND_CYAN),
                    ),
                ]),
            ]
        }
    } else {
        vec![Line::from("")]
    };

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn render_footer(f: &mut Frame, area: Rect, state: &TuiState) {
    if state.show_logs {
        let log_lines: Vec<Line> = state
            .logs
            .iter()
            .rev()
            .take(5)
            .rev()
            .map(|l| {
                Line::from(Span::styled(
                    format!("  • {}", l),
                    Style::default().fg(FG_PRIMARY),
                ))
            })
            .collect();
        let log_box = Paragraph::new(log_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(SEM_BRAND_CYAN))
                .title(" ◆ Event Log Ring-Buffer ([L] close) "),
        );
        f.render_widget(log_box, area);
    } else {
        let lines = vec![
            Line::from(vec![
                Span::styled(
                    "  Status : ",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(state.last_action.clone(), Style::default().fg(FG_PRIMARY)),
            ]),
            Line::from(vec![
                Span::styled(
                    "  [↑/↓]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Select  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[←/→/Tab]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Hop  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[Enter]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Replay Exploit  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[f]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Filter  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[p]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Patch View  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[g]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" HTML  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[s]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" SARIF  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[L]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Logs  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[?]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Help  ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    "[q]",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Quit", Style::default().fg(FG_SECONDARY)),
            ]),
        ];
        let footer = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER_SUBTLE)),
        );
        f.render_widget(footer, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn render_help_modal(f: &mut Frame, area: Rect) {
    let modal = centered_rect(72, 68, area);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(Span::styled(
            "VERIFORGE // by Qira-Dev — Power-User Reference",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "1. Strict Semantic Color System:",
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "   ● PROVEN (Red)     ",
                Style::default().fg(SEM_PROVEN_RED),
            ),
            Span::raw("— Exploit verified inside isolated Bubblewrap (--unshare-all) sandbox."),
        ]),
        Line::from(vec![
            Span::styled(
                "   ◆ SUSPECT (Amber)  ",
                Style::default().fg(SEM_SUSPECT_AMBER),
            ),
            Span::raw("— Static Guard-Set Lattice witness found; runtime not yet verified."),
        ]),
        Line::from(vec![
            Span::styled(
                "   ✓ MITIGATED (Green)",
                Style::default().fg(SEM_SAFE_GREEN),
            ),
            Span::raw("— Blocked by runtime auth middleware or transaction lock."),
        ]),
        Line::from(vec![
            Span::styled(
                "   [CRIT · RACE]      ",
                Style::default().fg(SEM_RACE_PURPLE),
            ),
            Span::raw("— Missing transaction/idempotency lock before balance/payment sink."),
        ]),
        Line::from(vec![
            Span::styled(
                "   [HIGH · AUTH]      ",
                Style::default().fg(SEM_AUTH_CORAL),
            ),
            Span::raw("— Unauthenticated route reaching a protected DB/payment sink."),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "2. Keyboard Shortcuts:",
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from("   ↑/↓ or j/k    : Select vulnerability in queue"),
        Line::from(
            "   ←/→/h/l/Tab   : Step through Cross-File Witness Hops (Entry -> Call -> Sink)",
        ),
        Line::from("   Enter         : Re-run live Last-Byte Sync / Auth PoC inside bwrap sandbox"),
        Line::from("   f             : Cycle Filter (ALL -> PROVEN ONLY -> CRITICAL ONLY)"),
        Line::from("   p             : Save & Preview <2 KB Minimal AI Patch Context"),
        Line::from("   g / s         : Export & Open HTML Graph [g] or SARIF 2.1.0 [s]"),
        Line::from("   L / ? / q     : Toggle Event Log [L], Help Modal [?], or Quit [q]"),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(BG_CANVAS))
        .border_style(Style::default().fg(SEM_BRAND_CYAN))
        .title(" ◆ Help & Semantic Color System (Press [?] or [Esc] to close) ");
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        modal,
    );
}

fn render_patch_modal(f: &mut Frame, area: Rect, fid: &str, prompt_txt: &str) {
    let modal = centered_rect(78, 76, area);
    f.render_widget(Clear, modal);
    let lines: Vec<Line> = prompt_txt
        .lines()
        .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(FG_PRIMARY))))
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(BG_CANVAS))
        .border_style(Style::default().fg(SEM_BRAND_CYAN))
        .title(format!(
            " ◆ Minimal AI Patch Context — {} ({} bytes, saved to .veriforge/patch_{}.prompt.txt) [Esc/p to close] ",
            fid,
            prompt_txt.len(),
            fid
        ));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        modal,
    );
}

pub fn run_tui(
    project_root: &Path,
    graph: GraphAnalysisResult,
    verified: Vec<VerifiedFinding>,
    elapsed_ms: u128,
    launch_cfg: TuiLaunchConfig,
) -> Result<()> {
    let mut guard = TerminalGuard::init()?;
    let mut state = TuiState::new(project_root, graph, verified, elapsed_ms);

    loop {
        guard.terminal.draw(|f| render_ui(f, &mut state))?;

        if event::poll(Duration::from_millis(80))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if state.show_help {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
                ) {
                    state.show_help = false;
                }
                continue;
            }
            if state.patch_modal.is_some() {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Char('p') | KeyCode::Char('q')
                ) {
                    state.patch_modal = None;
                }
                continue;
            }

            let filtered_len = state.filtered_findings().len();
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('?') => {
                    state.show_help = !state.show_help;
                }
                KeyCode::Char('f') => {
                    state.filter_mode = state.filter_mode.next();
                    state.selected_idx = 0;
                    state.selected_hop = 0;
                    state.push_log(format!("Filter set to: {}", state.filter_mode.label()));
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if filtered_len > 0 {
                        state.selected_idx = (state.selected_idx + 1) % filtered_len;
                        state.selected_hop = 0;
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if filtered_len > 0 {
                        state.selected_idx = if state.selected_idx == 0 {
                            filtered_len - 1
                        } else {
                            state.selected_idx - 1
                        };
                        state.selected_hop = 0;
                    }
                }
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                    if let Some(cur) = state.current_finding()
                        && !cur.witness_path.is_empty()
                    {
                        state.selected_hop = (state.selected_hop + 1) % cur.witness_path.len();
                    }
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    if let Some(cur) = state.current_finding()
                        && !cur.witness_path.is_empty()
                    {
                        state.selected_hop = if state.selected_hop == 0 {
                            cur.witness_path.len() - 1
                        } else {
                            state.selected_hop - 1
                        };
                    }
                }
                KeyCode::Enter => {
                    if let Some(cur) = state.current_finding() {
                        if let Some(cmd) = &launch_cfg.boot_cmd {
                            state.push_log(format!(
                                "Running isolated bwrap replay for {}...",
                                cur.id
                            ));
                            let _ = guard.terminal.draw(|f| render_ui(f, &mut state));
                            match verify_findings_in_sandbox(
                                &state.project_root,
                                cmd,
                                launch_cfg.port,
                                std::slice::from_ref(&cur),
                                launch_cfg.sync_race,
                                launch_cfg.unsafe_host_fallback,
                            ) {
                                Ok((_, mut res)) => {
                                    if let Some(v) = res.pop() {
                                        state.push_log(format!(
                                            "Replay {}: {:?} — {}",
                                            cur.id, v.status, v.evidence
                                        ));
                                        state.verified_map.insert(cur.id.clone(), v);
                                    }
                                }
                                Err(e) => {
                                    state.push_log(format!("Replay failed: {}", e));
                                }
                            }
                        } else {
                            state.push_log(
                                "Pass --boot-cmd <cmd> to run live sandbox replay.".into(),
                            );
                        }
                    }
                }
                KeyCode::Char('p') => {
                    if let Some(cur) = state.current_finding() {
                        let v_opt = state.verified_map.get(&cur.id).cloned();
                        if let Ok(prompt) =
                            build_minimal_patch_prompt(&state.project_root, &cur, v_opt.as_ref())
                        {
                            let out = state
                                .project_root
                                .join(".veriforge")
                                .join(format!("patch_{}.prompt.txt", cur.id));
                            let _ = fs::create_dir_all(state.project_root.join(".veriforge"));
                            let _ = fs::write(&out, &prompt);
                            state.push_log(format!(
                                "Saved & opened patch context ({} B) -> {}",
                                prompt.len(),
                                out.display()
                            ));
                            state.patch_modal = Some((cur.id.clone(), prompt));
                        }
                    }
                }
                KeyCode::Char('L') => {
                    state.show_logs = !state.show_logs;
                }
                KeyCode::Char('g') => {
                    let out = state.project_root.join(".veriforge").join("report.html");
                    let verified_vec: Vec<VerifiedFinding> =
                        state.verified_map.values().cloned().collect();
                    let html = to_html_graph(
                        &state.project_root.display().to_string(),
                        &state.graph,
                        &verified_vec,
                    );
                    match fs::create_dir_all(state.project_root.join(".veriforge"))
                        .and_then(|_| fs::write(&out, html))
                    {
                        Ok(_) => {
                            let _ = Command::new("xdg-open")
                                .arg(&out)
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .spawn();
                            state.push_log(format!("Opened HTML graph -> {}", out.display()));
                        }
                        Err(e) => state.push_log(format!("HTML export error: {}", e)),
                    }
                }
                KeyCode::Char('s') => {
                    let out = state.project_root.join(".veriforge").join("report.sarif");
                    let verified_vec: Vec<VerifiedFinding> =
                        state.verified_map.values().cloned().collect();
                    let sarif = to_sarif_json(&state.graph.findings, &verified_vec);
                    match fs::create_dir_all(state.project_root.join(".veriforge"))
                        .and_then(|_| fs::write(&out, sarif))
                    {
                        Ok(_) => state.push_log(format!("Exported SARIF -> {}", out.display())),
                        Err(e) => state.push_log(format!("SARIF export error: {}", e)),
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use vf_graph::{GuardKind, SinkKind, TraceHop};

    #[test]
    fn test_tui_renders_cleanly_at_120x36_and_80x24() {
        let graph = GraphAnalysisResult {
            parsed_files: 5,
            symbol_count: 8,
            edge_count: 6,
            route_entries: 2,
            findings: vec![LatticeFinding {
                id: "VF-RACE-002".into(),
                rule_id: "VF-RACE-001".into(),
                severity: "CRITICAL".into(),
                title: "Missing tx lock".into(),
                status: "PROVEN".into(),
                entry_route: "POST /api/v1/checkout/withdraw".into(),
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::TxLock,
                witness_path: vec![
                    TraceHop {
                        file: "src/routes/checkout.ts".into(),
                        symbol: "POST /api/v1/checkout/withdraw".into(),
                        line: 8,
                    },
                    TraceHop {
                        file: "src/db/queries.ts".into(),
                        symbol: "debitBalance".into(),
                        line: 1,
                    },
                ],
            }],
        };
        let verified = vec![VerifiedFinding {
            finding_id: "VF-RACE-002".into(),
            rule_id: "VF-RACE-001".into(),
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            status: VerificationStatus::Proven,
            evidence: "Last-Byte Sync (10x): 10x HTTP 2xx".into(),
            replay_cmd: "veriforge replay VF-RACE-002".into(),
        }];

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let mut state = TuiState::new(&root, graph, verified, 120);

        for (w, h) in [(120, 36), (80, 24)] {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| render_ui(f, &mut state)).unwrap();
        }
    }
}
