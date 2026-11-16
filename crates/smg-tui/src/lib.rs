use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, generate_patch_plan, provider_from_config,
    verify_patch_in_isolated_copy,
};
use smg_core::{ShellMindGuardConfig, StateStore, scan_repository};
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, SinkKind, analyze_codebase_cached,
    collect_deep_schema_findings, finding_matches_layer,
};
use smg_report::{to_html_graph, to_sarif_json};
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, verify_findings_in_sandbox_with_config,
};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Stdout, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const MAX_LOG_LINES: usize = 200;
const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

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
const FG_SECONDARY: Color = Color::Rgb(149, 157, 165);
const FG_DIM: Color = Color::Rgb(110, 118, 129);

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
    ConfirmedOrProven,
    CriticalOnly,
}

impl FilterMode {
    fn next(self) -> Self {
        match self {
            FilterMode::All => FilterMode::ProvenOnly,
            FilterMode::ProvenOnly => FilterMode::ConfirmedOrProven,
            FilterMode::ConfirmedOrProven => FilterMode::CriticalOnly,
            FilterMode::CriticalOnly => FilterMode::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FilterMode::All => "ALL",
            FilterMode::ProvenOnly => "PROVEN ONLY",
            FilterMode::ConfirmedOrProven => "CONFIRMED+",
            FilterMode::CriticalOnly => "CRITICAL ONLY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryFilter {
    All,
    Auth,
    RaceLock,
    Injection,
    SecretsCfg,
    Deps,
    EngineMem,
    Mobile,
    FrontendFuzz,
}

impl CategoryFilter {
    fn next(self) -> Self {
        match self {
            CategoryFilter::All => CategoryFilter::Auth,
            CategoryFilter::Auth => CategoryFilter::RaceLock,
            CategoryFilter::RaceLock => CategoryFilter::Injection,
            CategoryFilter::Injection => CategoryFilter::SecretsCfg,
            CategoryFilter::SecretsCfg => CategoryFilter::Deps,
            CategoryFilter::Deps => CategoryFilter::EngineMem,
            CategoryFilter::EngineMem => CategoryFilter::Mobile,
            CategoryFilter::Mobile => CategoryFilter::FrontendFuzz,
            CategoryFilter::FrontendFuzz => CategoryFilter::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            CategoryFilter::All => "ALL",
            CategoryFilter::Auth => "AUTH/IDOR/CSRF",
            CategoryFilter::RaceLock => "RACE/LOCK",
            CategoryFilter::Injection => "TAINT/INJ",
            CategoryFilter::SecretsCfg => "SEC/CFG",
            CategoryFilter::Deps => "DEPS",
            CategoryFilter::EngineMem => "ENGINE/MEM",
            CategoryFilter::Mobile => "MOBILE",
            CategoryFilter::FrontendFuzz => "FE/FUZZ",
        }
    }

    fn matches(self, f: &LatticeFinding) -> bool {
        match self {
            CategoryFilter::All => true,
            CategoryFilter::Auth => matches!(
                f.missing_guard,
                GuardKind::Auth | GuardKind::OwnershipCheck | GuardKind::CsrfProtection
            ),
            CategoryFilter::RaceLock => {
                matches!(f.missing_guard, GuardKind::TxLock | GuardKind::LockOrdering)
            }
            CategoryFilter::Injection => matches!(
                f.missing_guard,
                GuardKind::SqlSanitizer
                    | GuardKind::CmdSanitizer
                    | GuardKind::PathSanitizer
                    | GuardKind::SsrfSanitizer
                    | GuardKind::XssSanitizer
            ),
            CategoryFilter::SecretsCfg => matches!(
                f.missing_guard,
                GuardKind::SecretPolicy | GuardKind::ConfigPolicy
            ),
            CategoryFilter::Deps => f.missing_guard == GuardKind::DependencyPolicy,
            CategoryFilter::EngineMem => matches!(
                f.missing_guard,
                GuardKind::LockOrdering | GuardKind::ResourceCleanup | GuardKind::MemoryBounds
            ),
            CategoryFilter::Mobile => f.missing_guard == GuardKind::MobilePolicy,
            CategoryFilter::FrontendFuzz => matches!(
                f.missing_guard,
                GuardKind::FrontendContract | GuardKind::InputValidation
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TuiLaunchConfig {
    pub boot_cmd: Option<String>,
    pub port: u16,
    pub sync_race: usize,
    pub unsafe_host_fallback: bool,
    pub trust_repo_config: bool,
    pub deep: bool,
    pub layers: Vec<String>,
    pub min_confidence: Option<Confidence>,
    pub sandbox_mem_mb: Option<u64>,
    pub sandbox_tls: bool,
    pub mock_shims: bool,
    pub cgroup_v2: bool,
}

impl Default for TuiLaunchConfig {
    fn default() -> Self {
        Self {
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            layers: Vec::new(),
            min_confidence: None,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        }
    }
}

enum BgEvent {
    Replay {
        fid: String,
        result: Result<(bool, Option<VerifiedFinding>), String>,
    },
    Rescan {
        result: Result<(GraphAnalysisResult, u128), String>,
    },
    Patch {
        fid: String,
        content: String,
        diff: Option<String>,
        note: String,
    },
    ApplyCheck {
        fid: String,
        mitigated: bool,
        summary: String,
    },
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

static TUI_PANIC_HOOK_INIT: std::sync::Once = std::sync::Once::new();
const MAX_CACHED_FILES: usize = 64;

impl TerminalGuard {
    fn init() -> Result<Self> {
        TUI_PANIC_HOOK_INIT.call_once(|| {
            let orig_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
                orig_hook(info);
            }));
        });

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
            let _ = disable_raw_mode();
            return Err(e.into());
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).inspect_err(|_| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
        })?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        );
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
    source_scroll: isize,
    zoom_source: bool,
    queue_area: Rect,
    list_state: ListState,
    filter_mode: FilterMode,
    category_filter: CategoryFilter,
    search_mode: bool,
    search_query: String,
    show_logs: bool,
    show_help: bool,
    patch_modal: Option<(String, String)>,
    patch_diff: Option<String>,
    patch_scroll: u16,
    bg_running: Option<(String, usize)>,
    bg_rx: Option<Receiver<BgEvent>>,
    logs: VecDeque<String>,
    file_cache: HashMap<String, Vec<String>>,
    sandbox_isolated: bool,
    last_action: String,
}

fn severity_priority(s: &str) -> u8 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

impl TuiState {
    fn sort_findings(
        findings: &mut [LatticeFinding],
        verified_map: &HashMap<String, VerifiedFinding>,
    ) {
        findings.sort_by(|a, b| {
            let ap = matches!(
                verified_map.get(&a.id).map(|v| &v.status),
                Some(VerificationStatus::Proven)
            );
            let bp = matches!(
                verified_map.get(&b.id).map(|v| &v.status),
                Some(VerificationStatus::Proven)
            );
            bp.cmp(&ap)
                .then_with(|| severity_priority(&a.severity).cmp(&severity_priority(&b.severity)))
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.id.cmp(&b.id))
        });
    }

    fn new(
        project_root: &Path,
        mut graph: GraphAnalysisResult,
        verified: Vec<VerifiedFinding>,
        elapsed_ms: u128,
    ) -> Self {
        let canon_root = fs::canonicalize(project_root).ok();
        let mut verified_map = HashMap::new();
        for v in verified {
            verified_map.insert(v.finding_id.clone(), v);
        }
        Self::sort_findings(&mut graph.findings, &verified_map);
        let init_msg = format!(
            "Ready — Scanned {} files ({} sym · {} edges · {} routes) in {}ms. [/] Search  [r] Rescan",
            graph.parsed_files,
            graph.symbol_count,
            graph.edge_count,
            graph.route_entries,
            elapsed_ms
        );
        let logs = VecDeque::from([
            init_msg.clone(),
            format!(
                "SMG Sandbox: {} ({} findings verified).",
                if smg_sandbox::has_bwrap() {
                    "Bubblewrap --unshare-all (PID/IPC/UTS/Net isolated)"
                } else {
                    "Host Loopback"
                },
                verified_map.len()
            ),
        ]);
        let mut list_state = ListState::default();
        if !graph.findings.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            project_root: project_root.to_path_buf(),
            canon_root,
            graph,
            verified_map,
            elapsed_ms,
            selected_idx: 0,
            selected_hop: 0,
            source_scroll: 0,
            zoom_source: false,
            queue_area: Rect::default(),
            list_state,
            filter_mode: FilterMode::All,
            category_filter: CategoryFilter::All,
            search_mode: false,
            search_query: String::new(),
            show_logs: false,
            show_help: false,
            patch_modal: None,
            patch_diff: None,
            patch_scroll: 0,
            bg_running: None,
            bg_rx: None,
            logs,
            file_cache: HashMap::new(),
            sandbox_isolated: smg_sandbox::has_bwrap(),
            last_action: init_msg,
        }
    }

    fn set_selected(&mut self, idx: usize) {
        let count = self.filtered_findings().len();
        if count == 0 {
            self.selected_idx = 0;
            self.list_state.select(None);
        } else {
            let clamped = idx.min(count - 1);
            self.selected_idx = clamped;
            self.list_state.select(Some(clamped));
        }
        self.selected_hop = 0;
        self.source_scroll = 0;
    }

    fn push_log(&mut self, msg: String) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.last_action = msg.clone();
        self.logs.push_back(msg);
    }

    fn filtered_findings(&self) -> Vec<&LatticeFinding> {
        let q = self.search_query.trim().to_ascii_lowercase();
        self.graph
            .findings
            .iter()
            .filter(|f| {
                let status_ok = match self.filter_mode {
                    FilterMode::All => true,
                    FilterMode::ProvenOnly => matches!(
                        self.verified_map.get(&f.id).map(|v| &v.status),
                        Some(VerificationStatus::Proven)
                    ),
                    FilterMode::ConfirmedOrProven => {
                        matches!(
                            self.verified_map.get(&f.id).map(|v| &v.status),
                            Some(VerificationStatus::Proven)
                        ) || f.confidence >= Confidence::Confirmed
                    }
                    FilterMode::CriticalOnly => f.severity == "CRITICAL",
                };
                if !status_ok || !self.category_filter.matches(f) {
                    return false;
                }
                if q.is_empty() {
                    return true;
                }
                f.id.to_ascii_lowercase().contains(&q)
                    || f.rule_id.to_ascii_lowercase().contains(&q)
                    || f.file.to_ascii_lowercase().contains(&q)
                    || f.entry_route.to_ascii_lowercase().contains(&q)
                    || f.title.to_ascii_lowercase().contains(&q)
                    || f.witness_path.iter().any(|h| {
                        h.symbol.to_ascii_lowercase().contains(&q)
                            || h.file.to_ascii_lowercase().contains(&q)
                    })
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
        if self.file_cache.len() >= MAX_CACHED_FILES {
            self.file_cache.clear();
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

fn truncate_left_chars(s: &str, max_chars: usize) -> String {
    let len = s.chars().count();
    if len <= max_chars || max_chars < 4 {
        return s.chars().take(max_chars).collect();
    }
    let tail: String = s.chars().skip(len - (max_chars - 1)).collect();
    format!("…{}", tail)
}

fn clip_right_chars(s: &str, max_chars: usize) -> String {
    let len = s.chars().count();
    if len <= max_chars || max_chars == 0 {
        return s.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut head: String = s.chars().take(max_chars - 1).collect();
    head.push('…');
    head
}

fn render_ui(f: &mut Frame, state: &mut TuiState) {
    let area = f.area();
    let compact = area.height <= 28;
    f.render_widget(Block::default().style(Style::default().bg(BG_CANVAS)), area);

    let footer_h = if state.show_logs {
        if compact { 6 } else { 8 }
    } else if compact {
        3
    } else {
        4
    };

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(footer_h),
        ])
        .split(area);

    render_brand_header(f, root_chunks[0], state);

    if state.zoom_source {
        state.queue_area = Rect::default();
        let zoom_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(if compact { 6 } else { 8 }),
            ])
            .split(root_chunks[1]);
        render_source_inspector(f, zoom_chunks[0], state);
        render_proof_and_remediation(f, zoom_chunks[1], state, compact);
    } else {
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(root_chunks[1]);

        // Left Column: Top Telemetry Card + Bottom Scrollable Vulnerability Queue
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if compact { 5 } else { 6 }),
                Constraint::Min(6),
            ])
            .split(body_chunks[0]);

        render_system_legend_card(f, left_chunks[0], state);
        state.queue_area = left_chunks[1];
        render_findings_queue(f, left_chunks[1], state);

        // Right Column: Top Cross-File Pipeline + Middle Source Inspector + Bottom Proof & Remediation
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if compact { 5 } else { 6 }),
                Constraint::Min(5),
                Constraint::Length(if compact { 6 } else { 9 }),
            ])
            .split(body_chunks[1]);

        render_pipeline_card(f, right_chunks[0], state);
        render_source_inspector(f, right_chunks[1], state);
        render_proof_and_remediation(f, right_chunks[2], state, compact);
    }

    render_footer(f, root_chunks[2], state, compact);

    if state.show_help {
        render_help_modal(f, area);
    } else if let Some((ref fid, ref prompt_txt)) = state.patch_modal {
        render_patch_modal(
            f,
            area,
            fid,
            prompt_txt,
            state.patch_diff.as_deref(),
            state.patch_scroll,
        );
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

    let brand = if area.width < 95 {
        " ◆ SMG · SHELLMIND "
    } else {
        " ◆ SMG · SHELLMIND GUARD "
    };
    let stats_str = format!(
        " ({}f·{}s·{}ms) ",
        state.graph.parsed_files, state.graph.symbol_count, state.elapsed_ms
    );
    let badge_w = proven_span.width() + suspect_span.width() + mitigated_span.width() + 2;
    let fixed_w = brand.chars().count() + stats_str.chars().count() + badge_w + 8;
    let max_path_w = (area.width as usize).saturating_sub(fixed_w).max(8);
    let root_label = truncate_left_chars(&state.project_root.display().to_string(), max_path_w);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            brand,
            Style::default()
                .fg(Color::Black)
                .bg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(BORDER_SUBTLE)),
        Span::styled(
            root_label,
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        ),
        Span::styled(stats_str, Style::default().fg(FG_SECONDARY)),
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
            " ◆ SMG Engine Telemetry & Legend ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    let sb_span = if state.sandbox_isolated {
        Span::styled(
            "● bwrap --unshare-all (Isolated)",
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

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  Sandbox : ", Style::default().fg(FG_SECONDARY)),
            sb_span,
        ]),
        Line::from(vec![
            Span::styled("  Engine  : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "O(V+E) Lattice · Routes: {} · Edges: {}",
                    state.graph.route_entries, state.graph.edge_count
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Verdict : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                "● PROVEN",
                Style::default()
                    .fg(SEM_PROVEN_RED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("◆ SUSPECT", Style::default().fg(SEM_SUSPECT_AMBER)),
            Span::raw("  "),
            Span::styled("✓ MITIGATED", Style::default().fg(SEM_SAFE_GREEN)),
        ]),
    ];
    if area.height >= 6 {
        lines.push(Line::from(vec![
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
        ]));
    }

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_findings_queue(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let total_findings = state.graph.findings.len();
    let filter_label = state.filter_mode.label();
    let filtered_ids: Vec<LatticeFinding> =
        state.filtered_findings().into_iter().cloned().collect();
    let sel_idx = if filtered_ids.is_empty() {
        0
    } else {
        state.selected_idx.min(filtered_ids.len() - 1)
    };
    if filtered_ids.is_empty() {
        state.list_state.select(None);
    } else {
        state.list_state.select(Some(sel_idx));
    }

    let items: Vec<ListItem> = if filtered_ids.is_empty() {
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
        filtered_ids
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let is_sel = idx == sel_idx;
                let row_bg = if is_sel { BG_CARD_SELECTED } else { BG_CANVAS };

                let (verdict_icon, verdict_label, verdict_color) =
                    match state.verified_map.get(&item.id).map(|v| &v.status) {
                        Some(VerificationStatus::Proven) => ("●", "PROVEN", SEM_PROVEN_RED),
                        Some(VerificationStatus::Mitigated) => ("✓", "MITIGATED", SEM_SAFE_GREEN),
                        Some(VerificationStatus::Unbootable) => {
                            ("✖", "UNBOOTABLE", SEM_SUSPECT_AMBER)
                        }
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
                    GuardKind::SqlSanitizer => (
                        "[CRIT · SQLI]",
                        SEM_PROVEN_RED,
                        "Missing: Parameterized Query",
                    ),
                    GuardKind::CmdSanitizer => (
                        "[CRIT · CMDI]",
                        SEM_PROVEN_RED,
                        "Missing: Shell Escaping / execFile",
                    ),
                    GuardKind::PathSanitizer => (
                        "[HIGH · PATH]",
                        SEM_AUTH_CORAL,
                        "Missing: Path Canonicalization",
                    ),
                    GuardKind::SsrfSanitizer => (
                        "[HIGH · SSRF]",
                        SEM_AUTH_CORAL,
                        "Missing: URL Host Allowlist",
                    ),
                    GuardKind::XssSanitizer => (
                        "[HIGH · XSS]",
                        SEM_AUTH_CORAL,
                        "Missing: HTML Sanitizer / Escaping",
                    ),
                    GuardKind::CsrfProtection => (
                        "[HIGH · CSRF]",
                        SEM_AUTH_CORAL,
                        "Missing: Anti-CSRF Protection",
                    ),
                    GuardKind::OwnershipCheck => (
                        "[HIGH · IDOR]",
                        SEM_AUTH_CORAL,
                        "Missing: Object Ownership Filter",
                    ),
                    GuardKind::SecretPolicy => (
                        "[CRIT · SECRET]",
                        SEM_PROVEN_RED,
                        "Exposed Secret / Credential",
                    ),
                    GuardKind::ConfigPolicy => (
                        "[HIGH · CONFIG]",
                        SEM_SUSPECT_AMBER,
                        "Security Misconfiguration",
                    ),
                    GuardKind::DependencyPolicy => (
                        "[HIGH · DEPS]",
                        SEM_SUSPECT_AMBER,
                        "Vulnerable / Unpinned Dep",
                    ),
                    GuardKind::FrontendContract => (
                        "[MED · FE/API]",
                        SEM_BRAND_CYAN,
                        "Frontend Contract / UI Bug",
                    ),
                    GuardKind::LockOrdering => (
                        "[CRIT · ENGINE]",
                        SEM_RACE_PURPLE,
                        "Deadlock / Lock Inversion",
                    ),
                    GuardKind::ResourceCleanup => (
                        "[HIGH · ENGINE]",
                        SEM_SUSPECT_AMBER,
                        "Unclosed Resource / Handle Leak",
                    ),
                    GuardKind::MemoryBounds => (
                        "[CRIT · MEMORY]",
                        SEM_PROVEN_RED,
                        "Buffer Bounds / Int Overflow",
                    ),
                    GuardKind::MobilePolicy => (
                        "[HIGH · MOBILE]",
                        SEM_AUTH_CORAL,
                        "Mobile Storage / IPC / TLS",
                    ),
                    GuardKind::InputValidation => (
                        "[HIGH · FUZZ]",
                        SEM_SUSPECT_AMBER,
                        "Missing Input / Schema Bound",
                    ),
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
                        Span::styled(
                            format!(
                                " [{}]",
                                if verdict_label == "PROVEN"
                                    || item.confidence == Confidence::Proven
                                {
                                    Confidence::Proven.as_str()
                                } else {
                                    item.confidence.as_str()
                                }
                            ),
                            Style::default()
                                .fg(if verdict_label == "PROVEN" {
                                    SEM_PROVEN_RED
                                } else if item.confidence == Confidence::Confirmed {
                                    SEM_BRAND_CYAN
                                } else {
                                    SEM_SUSPECT_AMBER
                                })
                                .bg(row_bg),
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

    let cat_part = if state.category_filter != CategoryFilter::All {
        format!(" · {}", state.category_filter.label())
    } else {
        String::new()
    };
    let search_part = if !state.search_query.is_empty() {
        format!(" · /{}", clip_right_chars(&state.search_query, 14))
    } else {
        String::new()
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .title(Span::styled(
                format!(
                    " ◆ SMG Queue ({}/{}) · {}{}{} [f/1-4/c] ",
                    filtered_ids.len(),
                    total_findings,
                    filter_label,
                    cat_part,
                    search_part,
                ),
                Style::default()
                    .fg(SEM_BRAND_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
    );
    f.render_stateful_widget(list, area, &mut state.list_state);
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
            (GuardKind::SqlSanitizer, sk) => ("Parameterized SQL ($1 / ?)", format!("{:?}", sk)),
            (GuardKind::CmdSanitizer, sk) => ("Safe Argv Spawn / Allowlist", format!("{:?}", sk)),
            (GuardKind::PathSanitizer, sk) => {
                ("Path Canonicalization + BaseDir Check", format!("{:?}", sk))
            }
            (GuardKind::SsrfSanitizer, sk) => ("Outbound URL Host Allowlist", format!("{:?}", sk)),
            (GuardKind::XssSanitizer, sk) => (
                "DOMPurify / Context-Aware HTML Escaping",
                format!("{:?}", sk),
            ),
            (GuardKind::CsrfProtection, sk) => (
                "Anti-CSRF Token / SameSite Cookie / Bearer",
                format!("{:?}", sk),
            ),
            (GuardKind::OwnershipCheck, sk) => {
                ("Actor / Tenant Ownership Filter", format!("{:?}", sk))
            }
            (GuardKind::SecretPolicy, sk) => {
                ("Secret Vault & .gitignore Hygiene", format!("{:?}", sk))
            }
            (GuardKind::ConfigPolicy, sk) => {
                ("Hardened Security Configuration", format!("{:?}", sk))
            }
            (GuardKind::DependencyPolicy, sk) => ("Pinned Patched Dependency", format!("{:?}", sk)),
            (GuardKind::FrontendContract, sk) => (
                "Matching Backend Route & Error Handling",
                format!("{:?}", sk),
            ),
            (GuardKind::LockOrdering, sk) => (
                "Canonical Lock Hierarchy / Drop Before .await",
                format!("{:?}", sk),
            ),
            (GuardKind::ResourceCleanup, sk) => (
                "RAII / defer / finally Resource Cleanup",
                format!("{:?}", sk),
            ),
            (GuardKind::MemoryBounds, sk) => (
                "Bounds & Overflow Checks (checked_mul / sizeof)",
                format!("{:?}", sk),
            ),
            (GuardKind::MobilePolicy, sk) => (
                "Keystore/Keychain, Export Permission & TLS Pinning",
                format!("{:?}", sk),
            ),
            (GuardKind::InputValidation, sk) => (
                "Strict Schema & Positive/UTF-8 Input Validation",
                format!("{:?}", sk),
            ),
        };

        let mut lines = vec![Line::from(hop_spans)];
        if area.height >= 6 {
            lines.push(Line::from(""));
        }
        lines.extend([
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
        ]);
        lines
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
        "import", "from", "export", "default", "async", "await", "function", "const", "let", "var",
        "val", "fun", "return", "if", "else", "for", "while", "match", "pub", "fn", "struct",
        "enum", "impl", "use", "def", "class", "package", "func", "public", "private", "try",
        "catch", "throws", "unsafe", "select", "where",
    ];
    let security_tokens = [
        "requireAuth",
        "verifyJwt",
        "withTransaction",
        "processWithdrawal",
        "debitBalance",
        "creditBalanceWithTx",
        "update_role_in_db",
        "promote_user_role",
        "execSync",
        "query",
        "queryRaw",
        "prepare",
        "dangerouslySetInnerHTML",
        "Mutex",
        "get_unchecked",
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
        let visible_rows = area.height.saturating_sub(2) as usize;
        let target_idx = hop.line.saturating_sub(1);
        let half = visible_rows / 2;
        let base_start = target_idx.saturating_sub(half) as isize;
        let max_start = all_lines.len().saturating_sub(visible_rows) as isize;
        let clamped_start = (base_start + state.source_scroll).clamp(0, max_start.max(0)) as usize;
        let scroll_badge = if state.source_scroll != 0 && !all_lines.is_empty() {
            format!(" [L{}]", clamped_start + 1)
        } else {
            String::new()
        };
        let zoom_badge = if state.zoom_source { " [ZOOM]" } else { "" };
        let title = format!(
            " ◆ Source Inspector — {}:{} [Hop {}/{}: {}]{}{} ",
            hop.file,
            hop.line,
            hop_idx + 1,
            total_hops,
            role,
            scroll_badge,
            zoom_badge,
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
            let start = clamped_start;
            let end = (start + visible_rows).min(all_lines.len());

            let lines: Vec<Line> = (start..end)
                .map(|i| {
                    let ln = i + 1;
                    let raw_line = &all_lines[i];
                    if ln == hop.line {
                        let prefix = format!("▶ {:>4} │ ", ln);
                        let suffix = format!("  ◄ [{}]", role);
                        let avail_code = inner_width
                            .saturating_sub(prefix.chars().count() + suffix.chars().count());
                        let clipped_line = clip_right_chars(raw_line, avail_code);
                        let used = prefix.chars().count()
                            + clipped_line.chars().count()
                            + suffix.chars().count();
                        let pad = " ".repeat(inner_width.saturating_sub(used));
                        let mut spans = vec![Span::styled(
                            prefix,
                            Style::default()
                                .fg(SEM_PROVEN_RED)
                                .bg(BG_VULN_LINE)
                                .add_modifier(Modifier::BOLD),
                        )];
                        spans.extend(highlight_code_line(&clipped_line, BG_VULN_LINE));
                        spans.push(Span::styled(
                            format!("{}{}", suffix, pad),
                            Style::default()
                                .fg(SEM_PROVEN_RED)
                                .bg(BG_VULN_LINE)
                                .add_modifier(Modifier::BOLD),
                        ));
                        Line::from(spans).style(Style::default().bg(BG_VULN_LINE))
                    } else {
                        let prefix = format!("  {:>4} │ ", ln);
                        let avail_code = inner_width.saturating_sub(prefix.chars().count());
                        let clipped_line = clip_right_chars(raw_line, avail_code);
                        let mut spans = vec![Span::styled(
                            prefix,
                            Style::default().fg(FG_DIM).bg(BG_CANVAS),
                        )];
                        spans.extend(highlight_code_line(&clipped_line, BG_CANVAS));
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

fn render_proof_and_remediation(f: &mut Frame, area: Rect, state: &TuiState, compact: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ SMG Sandbox Proof, Remediation & Replay ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));

    let lines = if let Some(cur) = state.current_finding() {
        let remediation = if !cur.remediation.is_empty() {
            cur.remediation.clone()
        } else {
            match (cur.missing_guard, cur.sink_kind) {
                (GuardKind::Auth, _) => format!(
                    "Attach authentication middleware (`requireAuth` / `verifyJwt`) to `{}` before invoking downstream handlers.",
                    cur.entry_route
                ),
                (GuardKind::TxLock, SinkKind::BalanceUpdate | SinkKind::PaymentMutation) => {
                    "Wrap balance/payment mutation in an atomic DB transaction (`withTransaction` / `SELECT ... FOR UPDATE`) or enforce an idempotency key.".to_string()
                }
                (GuardKind::InputValidation, _) => {
                    "Enforce strict schema types, positive numeric bounds, and valid UTF-8 / length limits on request parameters.".to_string()
                }
                _ => "Apply the recommended security control before deploying.".to_string(),
            }
        };

        let mut out_lines = Vec::new();
        if !compact {
            out_lines.push(Line::from(vec![
                Span::styled("  Finding : ", Style::default().fg(FG_SECONDARY)),
                Span::styled(
                    format!("[{} · {}] ", cur.severity, cur.rule_id),
                    Style::default()
                        .fg(SEM_AUTH_CORAL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(cur.title.clone(), Style::default().fg(FG_PRIMARY)),
            ]));
        }

        if let Some(v) = state.verified_map.get(&cur.id) {
            let (badge_txt, badge_color) = match v.status {
                VerificationStatus::Proven => ("● EXPLOIT PROVEN", SEM_PROVEN_RED),
                VerificationStatus::Mitigated => ("✓ MITIGATED AT RUNTIME", SEM_SAFE_GREEN),
                VerificationStatus::SuspectUnverified => {
                    ("◆ SUSPECT / UNVERIFIED", SEM_SUSPECT_AMBER)
                }
                VerificationStatus::Unbootable => ("✖ SANDBOX UNBOOTABLE", SEM_SUSPECT_AMBER),
            };
            out_lines.extend([
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
            ]);
        } else {
            out_lines.extend([
                Line::from(vec![
                    Span::styled("  Proof   : ", Style::default().fg(FG_SECONDARY)),
                    Span::styled(
                        format!(
                            "◆ {} STATIC LATTICE WITNESS (Press [Enter] with --boot-cmd to run isolated bwrap exploit)",
                            cur.confidence.as_str()
                        ),
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
                        format!("smg replay {} {}", cur.id, state.project_root.display()),
                        Style::default().fg(SEM_BRAND_CYAN),
                    ),
                ]),
            ]);
        }
        out_lines
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

fn key_hint(key: &'static str, label: &'static str) -> [Span<'static>; 2] {
    [
        Span::styled(
            key,
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(label, Style::default().fg(FG_SECONDARY)),
    ]
}

fn render_footer(f: &mut Frame, area: Rect, state: &TuiState, compact: bool) {
    if state.show_logs {
        let log_lines: Vec<Line> = state
            .logs
            .iter()
            .rev()
            .take(if compact { 3 } else { 5 })
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
        let mut key_spans = vec![Span::raw("  ")];
        for (k, lbl) in [
            ("[/]", " Search "),
            ("[c]", " Cat "),
            ("[r]", " Scan "),
            ("[f/1-4]", " Filter "),
            ("[z]", " Zoom "),
            ("[\\[/\\]]", " Scroll "),
            ("[Enter]", " Replay "),
            ("[p]", " Patch "),
            ("[e]", " Edit "),
            ("[y]", " Copy "),
            ("[g/s]", " Export "),
            ("[L]", " Log "),
            ("[?]", " Help "),
            ("[q]", " Quit"),
        ] {
            key_spans.extend(key_hint(k, lbl));
        }
        let keys_line = Line::from(key_spans);

        let status_line = if state.search_mode {
            Line::from(vec![
                Span::styled(
                    "  [/] Search : ",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}▏", state.search_query),
                    Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "   (Enter keep · Esc clear · Backspace)",
                    Style::default().fg(FG_SECONDARY),
                ),
            ])
        } else if let Some((ref task_label, tick)) = state.bg_running {
            let spinner = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
            Line::from(vec![
                Span::styled(
                    format!("  {} ", spinner),
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(task_label.clone(), Style::default().fg(FG_PRIMARY)),
            ])
        } else {
            Line::from(vec![
                Span::styled(
                    "  Status : ",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(state.last_action.clone(), Style::default().fg(FG_PRIMARY)),
            ])
        };

        let lines = if compact && !state.search_mode && state.bg_running.is_none() {
            vec![keys_line]
        } else {
            vec![status_line, keys_line]
        };
        let footer = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(if state.search_mode {
                    BORDER_ACTIVE
                } else {
                    BORDER_SUBTLE
                })),
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
    let modal = centered_rect(78, 80, area);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(Span::styled(
            "SMG · SHELLMIND GUARD — Interactive Power-User Reference",
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
            "2. Keyboard & Mouse Shortcuts:",
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from("   ↑/↓ / j/k / PgUp/Dn / Home/End : Scroll & jump findings in queue"),
        Line::from("   ←/→ / h/l / Tab                : Step through Cross-File Witness Hops"),
        Line::from("   [ / ] / \\  (or mouse wheel)    : Scroll Source Inspector / reset [\\]"),
        Line::from("   z                              : Toggle Source Inspector full-pane zoom"),
        Line::from(
            "   /                              : Live fuzzy search (ID, rule, file, route, symbol)",
        ),
        Line::from(
            "   c                              : Cycle Guard Category filter (AUTH/RACE/INJ/...)",
        ),
        Line::from(
            "   f or 1 / 2 / 3 / 4             : Filter Status (ALL / PROVEN / CONFIRMED+ / CRIT)",
        ),
        Line::from("   r                              : Background delta-cached live rescan"),
        Line::from("   Enter                          : Background bwrap exploit replay (spinner)"),
        Line::from(
            "   p (then a / y / ↑↓)            : Patch Context/Diff · [a] Apply-Check · [y] Copy",
        ),
        Line::from(
            "   e / y                          : Open in $EDITOR/$VISUAL [e] · OSC 52 Copy [y]",
        ),
        Line::from(
            "   g / s / L / ? / q              : HTML [g], SARIF [s], Logs [L], Help [?], Quit [q]",
        ),
        Line::from(
            "   Mouse Click / Scroll           : Click queue item or scroll queue/source panes",
        ),
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

fn style_diff_line(line: &str) -> Line<'static> {
    if line.starts_with("+++") || line.starts_with("---") || line.starts_with("diff ") {
        Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        ))
    } else if line.starts_with("@@") {
        Line::from(Span::styled(
            line.to_string(),
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ))
    } else if line.starts_with('+') {
        Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(SEM_SAFE_GREEN),
        ))
    } else if line.starts_with('-') {
        Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(SEM_PROVEN_RED),
        ))
    } else {
        Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(FG_SECONDARY),
        ))
    }
}

fn render_patch_modal(
    f: &mut Frame,
    area: Rect,
    fid: &str,
    prompt_txt: &str,
    diff_opt: Option<&str>,
    scroll: u16,
) {
    let modal = centered_rect(82, 80, area);
    f.render_widget(Clear, modal);
    let mut lines: Vec<Line> = Vec::new();
    if let Some(diff) = diff_opt {
        lines.push(Line::from(Span::styled(
            "──── AI Proposed Unified Diff (press [a] to run isolated --apply-check) ────",
            Style::default()
                .fg(SEM_SAFE_GREEN)
                .add_modifier(Modifier::BOLD),
        )));
        lines.extend(diff.lines().map(style_diff_line));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "──── Minimal Witness Context (<= 2 KB) ────",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        )));
    }
    lines.extend(
        prompt_txt
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(FG_PRIMARY)))),
    );
    let mode_tag = if diff_opt.is_some() {
        "diff + context · a Apply-Check"
    } else {
        "<= 2 KB context"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(BG_CANVAS))
        .border_style(Style::default().fg(SEM_BRAND_CYAN))
        .title(format!(
            " ◆ SMG Patch — {} ({} B, L{}, {}) [↑/↓ scroll · y Copy · Esc/p close] ",
            fid,
            prompt_txt.len(),
            scroll + 1,
            mode_tag,
        ));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(block),
        modal,
    );
}

fn build_probe_config(
    cfg: &ShellMindGuardConfig,
    launch_cfg: &TuiLaunchConfig,
) -> SandboxProbeConfig {
    let mut probe = SandboxProbeConfig::from_sandbox_config(&cfg.sandbox);
    if let Some(mem) = launch_cfg.sandbox_mem_mb {
        probe.memory_limit_mb = Some(mem);
    }
    if launch_cfg.cgroup_v2 {
        probe.use_cgroup_v2 = true;
    }
    if launch_cfg.sandbox_tls {
        probe.use_tls = true;
    }
    if launch_cfg.mock_shims {
        probe.mock_shims = true;
    }
    probe
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn copy_osc52(text: &str) -> io::Result<()> {
    let b64 = encode_base64(text.as_bytes());
    let mut stdout = io::stdout();
    write!(stdout, "\x1b]52;c;{}\x07", b64)?;
    stdout.flush()
}

fn format_finding_clipboard_summary(
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
    root: &Path,
) -> String {
    let replay = verified
        .map(|v| v.replay_cmd.clone())
        .unwrap_or_else(|| format!("smg replay {} {}", finding.id, root.display()));
    format!(
        "[{}] {} · {}\nTitle  : {}\nSource : {}:{}\nRoute  : {}\nReplay : {}\nFix    : {}\n",
        finding.id,
        finding.severity,
        finding.rule_id,
        finding.title,
        finding.file,
        finding.line,
        finding.entry_route,
        replay,
        finding.remediation
    )
}

fn select_finding_by_id(state: &mut TuiState, fid: &str) {
    if let Some(pos) = state.filtered_findings().iter().position(|f| f.id == fid) {
        state.set_selected(pos);
    } else {
        state.set_selected(0);
    }
}

fn handle_bg_events(state: &mut TuiState) {
    let mut events = Vec::new();
    let mut disconnected = false;
    if let Some(rx) = &state.bg_rx {
        loop {
            match rx.try_recv() {
                Ok(ev) => events.push(ev),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
    }
    if disconnected {
        state.bg_running = None;
        state.bg_rx = None;
    }

    for ev in events {
        state.bg_running = None;
        state.bg_rx = None;
        match ev {
            BgEvent::Replay { fid, result } => match result {
                Ok((_unbootable, Some(v))) => {
                    let msg = format!("Replay {}: {:?} — {}", fid, v.status, v.evidence);
                    state.verified_map.insert(fid.clone(), v);
                    TuiState::sort_findings(&mut state.graph.findings, &state.verified_map);
                    select_finding_by_id(state, &fid);
                    state.push_log(msg);
                }
                Ok((_, None)) => {
                    state.push_log(format!("Replay {} returned no verification result.", fid));
                }
                Err(e) => {
                    state.push_log(format!("Replay {} failed: {}", fid, e));
                }
            },
            BgEvent::Rescan { result } => {
                state.file_cache.clear();
                match result {
                    Ok((mut graph, elapsed_ms)) => {
                        let prev_id = state.current_finding().map(|f| f.id);
                        TuiState::sort_findings(&mut graph.findings, &state.verified_map);
                        state.graph = graph;
                        state.elapsed_ms = elapsed_ms;
                        if let Some(id) = prev_id {
                            select_finding_by_id(state, &id);
                        } else {
                            state.set_selected(0);
                        }
                        state.push_log(format!(
                            "Rescan finished in {}ms — {} findings across {} files.",
                            elapsed_ms,
                            state.graph.findings.len(),
                            state.graph.parsed_files
                        ));
                    }
                    Err(e) => {
                        state.push_log(format!("Rescan failed: {}", e));
                    }
                }
            }
            BgEvent::Patch {
                fid,
                content,
                diff,
                note,
            } => {
                state.patch_modal = Some((fid, content));
                state.patch_diff = diff;
                state.patch_scroll = 0;
                state.push_log(note);
            }
            BgEvent::ApplyCheck {
                fid,
                mitigated,
                summary,
            } => {
                let tag = if mitigated {
                    "MITIGATED"
                } else {
                    "STILL EXPOSED"
                };
                state.push_log(format!("Apply-Check {} ({}): {}", fid, tag, summary));
            }
        }
    }
}

fn start_bg_job<F>(state: &mut TuiState, label: String, work: F)
where
    F: FnOnce() -> BgEvent + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    state.bg_running = Some((label, 0));
    state.bg_rx = Some(rx);
    std::thread::spawn(move || {
        let ev = work();
        let _ = tx.send(ev);
    });
}

fn spawn_bg_replay(state: &mut TuiState, launch_cfg: &TuiLaunchConfig, cur: LatticeFinding) {
    let Some(cmd) = launch_cfg.boot_cmd.clone() else {
        state.push_log("Pass --boot-cmd <cmd> to run live sandbox replay.".into());
        return;
    };
    let root = state.project_root.clone();
    let cfg_clone = launch_cfg.clone();
    let fid = cur.id.clone();
    start_bg_job(
        state,
        format!("Running isolated bwrap replay for {}...", fid),
        move || {
            let result = (|| -> Result<(bool, Option<VerifiedFinding>)> {
                let cfg = ShellMindGuardConfig::load_from_dir(&root)?;
                let eff_port = if cfg_clone.port != 39911 {
                    cfg_clone.port
                } else {
                    cfg.sandbox.loopback_port()?.unwrap_or(cfg_clone.port)
                };
                let probe_cfg = build_probe_config(&cfg, &cfg_clone);
                let (unbootable, mut res) = verify_findings_in_sandbox_with_config(
                    &root,
                    &cmd,
                    eff_port,
                    std::slice::from_ref(&cur),
                    cfg_clone.sync_race,
                    cfg_clone.unsafe_host_fallback,
                    &probe_cfg,
                )?;
                Ok((unbootable, res.pop()))
            })()
            .map_err(|e| e.to_string());
            BgEvent::Replay { fid, result }
        },
    );
}

fn spawn_bg_rescan(state: &mut TuiState, launch_cfg: &TuiLaunchConfig) {
    let root = state.project_root.clone();
    let layers = launch_cfg.layers.clone();
    let deep = launch_cfg.deep;
    let min_conf = launch_cfg.min_confidence;
    start_bg_job(
        state,
        "Running background delta-cached rescan...".to_string(),
        move || {
            let result = (|| -> Result<(GraphAnalysisResult, u128)> {
                let t0 = Instant::now();
                let cfg = ShellMindGuardConfig::load_from_dir(&root)?;
                let summary = scan_repository(&root, &cfg)?;
                let mut store = StateStore::open(&root)?;
                let (_delta, _) = store.sync_files(&summary.files)?;
                let mut graph_res = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
                if deep {
                    graph_res
                        .findings
                        .extend(collect_deep_schema_findings(&graph_res));
                }
                if !layers.is_empty() {
                    graph_res
                        .findings
                        .retain(|f| layers.iter().any(|l| finding_matches_layer(f, l)));
                }
                if let Some(mc) = min_conf {
                    graph_res.findings.retain(|f| f.confidence >= mc);
                }
                Ok((graph_res, t0.elapsed().as_millis()))
            })()
            .map_err(|e| e.to_string());
            BgEvent::Rescan { result }
        },
    );
}

fn spawn_bg_patch(
    state: &mut TuiState,
    launch_cfg: &TuiLaunchConfig,
    cur: LatticeFinding,
    v_opt: Option<VerifiedFinding>,
) {
    let root = state.project_root.clone();
    let trust_cfg = launch_cfg.trust_repo_config;
    let fid = cur.id.clone();
    start_bg_job(
        state,
        format!("Preparing <=2KB patch context for {}...", fid),
        move || {
            let prompt = match build_minimal_patch_prompt(&root, &cur, v_opt.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    return BgEvent::Patch {
                        fid: fid.clone(),
                        content: format!("Failed to build patch context: {}", e),
                        diff: None,
                        note: format!("Patch context error for {}: {}", fid, e),
                    };
                }
            };
            let smg_dir = root.join(".shellmind-guard");
            let out_prompt = smg_dir.join(format!("patch_{}.prompt.txt", fid));
            let _ = fs::create_dir_all(&smg_dir);
            let _ = fs::write(&out_prompt, &prompt);

            let mut diff_out: Option<String> = None;
            let mut note = format!(
                "Saved patch context ({} B) -> {}",
                prompt.len(),
                out_prompt.display()
            );

            if trust_cfg {
                match ShellMindGuardConfig::load_from_dir(&root)
                    .and_then(|cfg| provider_from_config(&cfg.ai))
                {
                    Ok(provider) => {
                        match generate_patch_plan(&provider, &root, &cur, v_opt.as_ref()) {
                            Ok(Some(plan)) => {
                                let out_diff = smg_dir.join(format!("patch_{}.diff", fid));
                                let _ = fs::write(&out_diff, &plan);
                                note = format!(
                                    "Generated AI diff ({} B) & context -> {} ([a] Apply-Check)",
                                    plan.len(),
                                    out_diff.display()
                                );
                                diff_out = Some(plan);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                note = format!(
                                    "Saved context ({} B); AI diff skipped: {}",
                                    prompt.len(),
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        note = format!(
                            "Saved context ({} B); AI config skipped: {}",
                            prompt.len(),
                            e
                        );
                    }
                }
            }

            BgEvent::Patch {
                fid,
                content: prompt,
                diff: diff_out,
                note,
            }
        },
    );
}

fn spawn_bg_apply_check(
    state: &mut TuiState,
    launch_cfg: &TuiLaunchConfig,
    cur: LatticeFinding,
    raw_diff: String,
) {
    let root = state.project_root.clone();
    let cfg_clone = launch_cfg.clone();
    let fid = cur.id.clone();
    start_bg_job(
        state,
        format!("Running isolated --apply-check for {}...", fid),
        move || {
            let (mitigated, summary) = match (|| -> Result<(bool, String)> {
                let cfg = ShellMindGuardConfig::load_from_dir(&root)?;
                let eff_port = if cfg_clone.port != 39911 {
                    cfg_clone.port
                } else {
                    cfg.sandbox.loopback_port()?.unwrap_or(cfg_clone.port)
                };
                let probe_cfg = build_probe_config(&cfg, &cfg_clone);
                let boot_ref = if cfg_clone.trust_repo_config {
                    cfg_clone
                        .boot_cmd
                        .clone()
                        .or_else(|| cfg.sandbox.boot_cmd.clone())
                } else {
                    cfg_clone.boot_cmd.clone()
                };
                let outcome = verify_patch_in_isolated_copy(&ApplyCheckParams {
                    project_root: &root,
                    cfg: &cfg,
                    finding: &cur,
                    raw_diff: &raw_diff,
                    boot_cmd: boot_ref.as_deref(),
                    port: eff_port,
                    sync_race: cfg_clone.sync_race,
                    unsafe_host_fallback: cfg_clone.unsafe_host_fallback,
                    probe_cfg: &probe_cfg,
                })?;
                Ok((outcome.mitigated, outcome.summary))
            })() {
                Ok(pair) => pair,
                Err(e) => (false, format!("Error: {}", e)),
            };
            BgEvent::ApplyCheck {
                fid,
                mitigated,
                summary,
            }
        },
    );
}

fn launch_editor_for_hop(
    guard: &mut TerminalGuard,
    state: &mut TuiState,
    rel_file: &str,
    line: usize,
) {
    let Some(ref root) = state.canon_root else {
        state.push_log("Cannot resolve workspace root for editor.".into());
        return;
    };
    let Ok(abs_file) = fs::canonicalize(root.join(rel_file)) else {
        state.push_log(format!("File not found on disk: {}", rel_file));
        return;
    };
    if !abs_file.starts_with(root) {
        state.push_log(format!(
            "Blocked opening path outside project: {}",
            rel_file
        ));
        return;
    }

    let editor_raw = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_string());
    let mut parts = editor_raw.split_whitespace();
    let Some(bin) = parts.next() else {
        return;
    };
    let base = Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin)
        .to_ascii_lowercase();

    let _ = disable_raw_mode();
    let _ = execute!(
        guard.terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    );
    let _ = guard.terminal.show_cursor();

    let mut cmd = Command::new(bin);
    for arg in parts {
        cmd.arg(arg);
    }
    if matches!(base.as_str(), "code" | "codium" | "cursor") {
        cmd.arg("-g")
            .arg(format!("{}:{}", abs_file.display(), line));
    } else if matches!(
        base.as_str(),
        "vi" | "vim" | "nvim" | "nano" | "hx" | "helix" | "emacs" | "emacsclient"
    ) {
        cmd.arg(format!("+{}", line)).arg(&abs_file);
    } else {
        cmd.arg(&abs_file);
    }
    let run_res = cmd.status();

    let _ = enable_raw_mode();
    let _ = execute!(
        guard.terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture
    );
    let _ = guard.terminal.clear();

    match run_res {
        Ok(st) if st.success() => {
            state.file_cache.remove(rel_file);
            state.push_log(format!("Closed editor for {}:{}", rel_file, line));
        }
        Ok(st) => state.push_log(format!("Editor exited with status {}", st)),
        Err(e) => state.push_log(format!("Failed to launch '{}': {}", bin, e)),
    }
}

fn point_in_rect(col: u16, row: u16, rect: Rect) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
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
    let mut last_tick = Instant::now();

    loop {
        handle_bg_events(&mut state);
        if let Some((_, ref mut tick)) = state.bg_running
            && last_tick.elapsed() >= Duration::from_millis(90)
        {
            *tick = tick.wrapping_add(1);
            last_tick = Instant::now();
        }

        guard.terminal.draw(|f| render_ui(f, &mut state))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }
        match event::read()? {
            Event::Mouse(mouse) => {
                if state.show_help {
                    continue;
                }
                if state.patch_modal.is_some() {
                    match mouse.kind {
                        MouseEventKind::ScrollDown => {
                            state.patch_scroll = state.patch_scroll.saturating_add(3);
                        }
                        MouseEventKind::ScrollUp => {
                            state.patch_scroll = state.patch_scroll.saturating_sub(3);
                        }
                        _ => {}
                    }
                    continue;
                }
                let in_queue = point_in_rect(mouse.column, mouse.row, state.queue_area);
                let filtered_len = state.filtered_findings().len();
                match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) if in_queue && filtered_len > 0 => {
                        let inner_top = state.queue_area.y.saturating_add(1);
                        let inner_bottom = state
                            .queue_area
                            .y
                            .saturating_add(state.queue_area.height.saturating_sub(1));
                        if mouse.row >= inner_top && mouse.row < inner_bottom {
                            let rel_row = (mouse.row - inner_top) as usize;
                            let clicked = state.list_state.offset() + (rel_row / 3);
                            if clicked < filtered_len {
                                state.set_selected(clicked);
                            }
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if in_queue && filtered_len > 0 {
                            let next = (state.selected_idx + 1).min(filtered_len - 1);
                            state.set_selected(next);
                        } else {
                            state.source_scroll = state.source_scroll.saturating_add(3);
                        }
                    }
                    MouseEventKind::ScrollUp => {
                        if in_queue && filtered_len > 0 {
                            let prev = state.selected_idx.saturating_sub(1);
                            state.set_selected(prev);
                        } else {
                            state.source_scroll = state.source_scroll.saturating_sub(3);
                        }
                    }
                    _ => {}
                }
            }
            Event::Key(key) => {
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
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('p') | KeyCode::Char('q') => {
                            state.patch_modal = None;
                            state.patch_diff = None;
                            state.patch_scroll = 0;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.patch_scroll = state.patch_scroll.saturating_add(1);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.patch_scroll = state.patch_scroll.saturating_sub(1);
                        }
                        KeyCode::PageDown => {
                            state.patch_scroll = state.patch_scroll.saturating_add(8);
                        }
                        KeyCode::PageUp => {
                            state.patch_scroll = state.patch_scroll.saturating_sub(8);
                        }
                        KeyCode::Home => state.patch_scroll = 0,
                        KeyCode::Char('y') => {
                            let clip_text = state
                                .patch_diff
                                .clone()
                                .or_else(|| state.patch_modal.as_ref().map(|(_, p)| p.clone()))
                                .unwrap_or_default();
                            match copy_osc52(&clip_text) {
                                Ok(_) => {
                                    state.push_log("Copied patch modal content via OSC 52.".into())
                                }
                                Err(e) => state.push_log(format!("Clipboard copy failed: {}", e)),
                            }
                        }
                        KeyCode::Char('a') => {
                            if state.bg_running.is_some() {
                                state.push_log("Background job already running...".into());
                            } else if let (Some(diff), Some(cur)) =
                                (state.patch_diff.clone(), state.current_finding())
                            {
                                spawn_bg_apply_check(&mut state, &launch_cfg, cur, diff);
                            } else {
                                state.push_log(
                                    "No AI diff available; configure [ai] + --trust-repo-config or run CLI --patch --apply-check.".into(),
                                );
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                if state.search_mode {
                    match key.code {
                        KeyCode::Esc => {
                            state.search_query.clear();
                            state.search_mode = false;
                            state.set_selected(0);
                            state.push_log("Search cleared.".into());
                        }
                        KeyCode::Enter => {
                            state.search_mode = false;
                            let count = state.filtered_findings().len();
                            state.push_log(format!(
                                "Search locked: '{}' ({} matches)",
                                state.search_query, count
                            ));
                        }
                        KeyCode::Backspace => {
                            state.search_query.pop();
                            state.set_selected(0);
                        }
                        KeyCode::Char(c) => {
                            state.search_query.push(c);
                            state.set_selected(0);
                        }
                        _ => {}
                    }
                    continue;
                }

                let filtered_len = state.filtered_findings().len();
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('?') => {
                        state.show_help = !state.show_help;
                    }
                    KeyCode::Char('/') => {
                        state.search_mode = true;
                    }
                    KeyCode::Char('c') => {
                        state.category_filter = state.category_filter.next();
                        state.set_selected(0);
                        state.push_log(format!(
                            "Category filter: {}",
                            state.category_filter.label()
                        ));
                    }
                    KeyCode::Char('z') => {
                        state.zoom_source = !state.zoom_source;
                        state.push_log(if state.zoom_source {
                            "Source Inspector zoomed ([z] restore).".into()
                        } else {
                            "Split dashboard restored.".into()
                        });
                    }
                    KeyCode::Char('[') => {
                        state.source_scroll = state.source_scroll.saturating_sub(3);
                    }
                    KeyCode::Char(']') => {
                        state.source_scroll = state.source_scroll.saturating_add(3);
                    }
                    KeyCode::Char('\\') => {
                        state.source_scroll = 0;
                    }
                    KeyCode::Char('f') => {
                        state.filter_mode = state.filter_mode.next();
                        state.set_selected(0);
                        state.push_log(format!("Filter set to: {}", state.filter_mode.label()));
                    }
                    KeyCode::Char('1') => {
                        state.filter_mode = FilterMode::All;
                        state.set_selected(0);
                        state.push_log("Filter set to: ALL".into());
                    }
                    KeyCode::Char('2') => {
                        state.filter_mode = FilterMode::ProvenOnly;
                        state.set_selected(0);
                        state.push_log("Filter set to: PROVEN ONLY".into());
                    }
                    KeyCode::Char('3') => {
                        state.filter_mode = FilterMode::ConfirmedOrProven;
                        state.set_selected(0);
                        state.push_log("Filter set to: CONFIRMED+".into());
                    }
                    KeyCode::Char('4') => {
                        state.filter_mode = FilterMode::CriticalOnly;
                        state.set_selected(0);
                        state.push_log("Filter set to: CRITICAL ONLY".into());
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if filtered_len > 0 {
                            let next = (state.selected_idx + 1) % filtered_len;
                            state.set_selected(next);
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if filtered_len > 0 {
                            let prev = if state.selected_idx == 0 {
                                filtered_len - 1
                            } else {
                                state.selected_idx - 1
                            };
                            state.set_selected(prev);
                        }
                    }
                    KeyCode::PageDown => {
                        if filtered_len > 0 {
                            let next = (state.selected_idx + 5).min(filtered_len - 1);
                            state.set_selected(next);
                        }
                    }
                    KeyCode::PageUp => {
                        if filtered_len > 0 {
                            let prev = state.selected_idx.saturating_sub(5);
                            state.set_selected(prev);
                        }
                    }
                    KeyCode::Home => {
                        if filtered_len > 0 {
                            state.set_selected(0);
                        }
                    }
                    KeyCode::End => {
                        if filtered_len > 0 {
                            state.set_selected(filtered_len - 1);
                        }
                    }
                    KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                        if let Some(cur) = state.current_finding()
                            && !cur.witness_path.is_empty()
                        {
                            state.selected_hop = (state.selected_hop + 1) % cur.witness_path.len();
                            state.source_scroll = 0;
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
                            state.source_scroll = 0;
                        }
                    }
                    KeyCode::Enter => {
                        if state.bg_running.is_some() {
                            state.push_log("Background job already running...".into());
                        } else if let Some(cur) = state.current_finding() {
                            spawn_bg_replay(&mut state, &launch_cfg, cur);
                        }
                    }
                    KeyCode::Char('r') => {
                        if state.bg_running.is_some() {
                            state.push_log("Background job already running...".into());
                        } else {
                            spawn_bg_rescan(&mut state, &launch_cfg);
                        }
                    }
                    KeyCode::Char('p') => {
                        if state.bg_running.is_some() {
                            state.push_log("Background job already running...".into());
                        } else if let Some(cur) = state.current_finding() {
                            let v_opt = state.verified_map.get(&cur.id).cloned();
                            spawn_bg_patch(&mut state, &launch_cfg, cur, v_opt);
                        }
                    }
                    KeyCode::Char('e') => {
                        if let Some(cur) = state.current_finding() {
                            let (file, line) = cur
                                .witness_path
                                .get(
                                    state
                                        .selected_hop
                                        .min(cur.witness_path.len().saturating_sub(1)),
                                )
                                .map(|h| (h.file.clone(), h.line))
                                .unwrap_or_else(|| (cur.file.clone(), cur.line));
                            launch_editor_for_hop(&mut guard, &mut state, &file, line);
                        }
                    }
                    KeyCode::Char('y') => {
                        if let Some(cur) = state.current_finding() {
                            let summary = format_finding_clipboard_summary(
                                &cur,
                                state.verified_map.get(&cur.id),
                                &state.project_root,
                            );
                            match copy_osc52(&summary) {
                                Ok(_) => state.push_log(format!(
                                    "Copied {} details to clipboard via OSC 52.",
                                    cur.id
                                )),
                                Err(e) => state.push_log(format!("Clipboard copy failed: {}", e)),
                            }
                        }
                    }
                    KeyCode::Char('L') => {
                        state.show_logs = !state.show_logs;
                    }
                    KeyCode::Char('g') => {
                        let out = state
                            .project_root
                            .join(".shellmind-guard")
                            .join("report.html");
                        let verified_vec: Vec<VerifiedFinding> =
                            state.verified_map.values().cloned().collect();
                        let html = to_html_graph(
                            &state.project_root.display().to_string(),
                            &state.graph,
                            &verified_vec,
                        );
                        match fs::create_dir_all(state.project_root.join(".shellmind-guard"))
                            .and_then(|_| fs::write(&out, html))
                        {
                            Ok(_) => {
                                let _ = open_path_in_browser(&out);
                                state.push_log(format!("Opened HTML graph -> {}", out.display()));
                            }
                            Err(e) => state.push_log(format!("HTML export error: {}", e)),
                        }
                    }
                    KeyCode::Char('s') => {
                        let out = state
                            .project_root
                            .join(".shellmind-guard")
                            .join("report.sarif");
                        let verified_vec: Vec<VerifiedFinding> =
                            state.verified_map.values().cloned().collect();
                        let sarif = to_sarif_json(&state.graph.findings, &verified_vec);
                        match fs::create_dir_all(state.project_root.join(".shellmind-guard"))
                            .and_then(|_| fs::write(&out, sarif))
                        {
                            Ok(_) => state.push_log(format!("Exported SARIF -> {}", out.display())),
                            Err(e) => state.push_log(format!("SARIF export error: {}", e)),
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn open_path_in_browser(path: &std::path::Path) -> std::io::Result<std::process::Child> {
    #[cfg(target_os = "macos")]
    {
        return Command::new("open")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        return Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Command::new("xdg-open")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use smg_graph::{GuardKind, SinkKind, TraceHop};

    #[test]
    fn test_tui_renders_cleanly_at_120x36_and_80x24() {
        let graph = GraphAnalysisResult {
            parsed_files: 5,
            symbol_count: 8,
            edge_count: 6,
            route_entries: 2,
            active_domains: vec!["web".to_string()],
            route_schemas: Vec::new(),
            findings: vec![LatticeFinding {
                id: "SMG-RACE-002".into(),
                rule_id: "SMG-RACE-001".into(),
                severity: "CRITICAL".into(),
                title: "Missing tx lock".into(),
                file: "src/db/queries.ts".into(),
                line: 1,
                status: "PROVEN".into(),
                confidence: Confidence::Proven,
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
                remediation: String::new(),
            }],
        };
        let verified = vec![VerifiedFinding {
            finding_id: "SMG-RACE-002".into(),
            rule_id: "SMG-RACE-001".into(),
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            status: VerificationStatus::Proven,
            evidence: "Last-Byte Sync (10x): 10x HTTP 2xx".into(),
            replay_cmd: "smg replay SMG-RACE-002".into(),
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

    #[test]
    fn test_tui_smg_branding_and_scrollable_queue_with_20_findings() {
        let mut findings = Vec::new();
        for i in 0..20usize {
            findings.push(LatticeFinding {
                id: format!("SMG-AUTH-{:03}", i + 1),
                rule_id: "SMG-AUTH-001".into(),
                severity: if i % 4 == 0 { "CRITICAL" } else { "HIGH" }.into(),
                title: format!("Missing auth guard #{}", i + 1),
                file: "src/routes/checkout.ts".into(),
                line: 8,
                status: "SUSPECT_UNGUARDED".into(),
                confidence: Confidence::Confirmed,
                entry_route: format!("POST /api/v1/route-{}", i + 1),
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::Auth,
                witness_path: vec![TraceHop {
                    file: "src/routes/checkout.ts".into(),
                    symbol: format!("handler_{}", i + 1),
                    line: 8,
                }],
                remediation: "Attach requireAuth middleware.".into(),
            });
        }
        let graph = GraphAnalysisResult {
            parsed_files: 12,
            symbol_count: 42,
            edge_count: 35,
            route_entries: 20,
            active_domains: vec!["web".to_string()],
            route_schemas: Vec::new(),
            findings,
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let mut state = TuiState::new(&root, graph, Vec::new(), 45);
        state.set_selected(15);
        assert_eq!(state.list_state.selected(), Some(15));

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_ui(f, &mut state)).unwrap();

        let buf = terminal.backend().buffer();
        let top_row: String = (0..100).map(|x| buf[(x, 1)].symbol()).collect();
        assert!(
            top_row.contains("SMG") && top_row.contains("PROVEN"),
            "Expected SMG header and visible PROVEN pill on compact terminal: {}",
            top_row
        );
    }

    #[test]
    fn test_tui_search_category_and_sort_ordering() {
        let f1 = LatticeFinding {
            id: "SMG-INJ-001".into(),
            rule_id: "SMG-SQLI-001".into(),
            severity: "HIGH".into(),
            title: "SQL injection in user query".into(),
            file: "src/users.ts".into(),
            line: 12,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "GET /api/users".into(),
            sink_kind: SinkKind::SqlInjection,
            missing_guard: GuardKind::SqlSanitizer,
            witness_path: vec![TraceHop {
                file: "src/users.ts".into(),
                symbol: "findUsers".into(),
                line: 12,
            }],
            remediation: "Use parameterized query.".into(),
        };
        let f2 = LatticeFinding {
            id: "SMG-AUTH-002".into(),
            rule_id: "SMG-AUTH-001".into(),
            severity: "CRITICAL".into(),
            title: "Unauth refund endpoint".into(),
            file: "src/refund.ts".into(),
            line: 5,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "POST /api/refund".into(),
            sink_kind: SinkKind::PaymentMutation,
            missing_guard: GuardKind::Auth,
            witness_path: vec![TraceHop {
                file: "src/refund.ts".into(),
                symbol: "handleRefund".into(),
                line: 5,
            }],
            remediation: "Require auth middleware.".into(),
        };
        let f3 = LatticeFinding {
            id: "SMG-RACE-003".into(),
            rule_id: "SMG-RACE-001".into(),
            severity: "MEDIUM".into(),
            title: "Race on balance debit".into(),
            file: "src/debit.ts".into(),
            line: 19,
            status: "SUSPECT".into(),
            confidence: Confidence::Heuristic,
            entry_route: "POST /api/debit".into(),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: vec![],
            remediation: "Use DB transaction.".into(),
        };
        let graph = GraphAnalysisResult {
            parsed_files: 3,
            symbol_count: 3,
            edge_count: 1,
            route_entries: 3,
            active_domains: vec!["web".into()],
            route_schemas: Vec::new(),
            findings: vec![f3, f1, f2],
        };
        // Mark SMG-RACE-003 (MEDIUM) as PROVEN -> must sort first ahead of CRITICAL
        let verified = vec![VerifiedFinding {
            finding_id: "SMG-RACE-003".into(),
            rule_id: "SMG-RACE-001".into(),
            entry_route: "POST /api/debit".into(),
            status: VerificationStatus::Proven,
            evidence: "Proven race".into(),
            replay_cmd: "smg replay SMG-RACE-003 .".into(),
        }];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let mut state = TuiState::new(&root, graph, verified, 10);
        assert_eq!(state.graph.findings[0].id, "SMG-RACE-003");
        assert_eq!(state.graph.findings[1].id, "SMG-AUTH-002");
        assert_eq!(state.graph.findings[2].id, "SMG-INJ-001");

        state.category_filter = CategoryFilter::Injection;
        assert_eq!(state.filtered_findings().len(), 1);
        assert_eq!(state.filtered_findings()[0].id, "SMG-INJ-001");

        state.category_filter = CategoryFilter::All;
        state.search_query = "refund".into();
        assert_eq!(state.filtered_findings().len(), 1);
        assert_eq!(state.filtered_findings()[0].id, "SMG-AUTH-002");
    }

    #[test]
    fn test_tui_zoom_patch_diff_bg_events_and_osc52() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"SMG"), "U01H");
        assert_eq!(encode_base64(b"smg!"), "c21nIQ==");

        let graph = GraphAnalysisResult {
            parsed_files: 1,
            symbol_count: 1,
            edge_count: 0,
            route_entries: 1,
            active_domains: vec!["web".into()],
            route_schemas: Vec::new(),
            findings: vec![LatticeFinding {
                id: "SMG-RACE-002".into(),
                rule_id: "SMG-RACE-001".into(),
                severity: "CRITICAL".into(),
                title: "Missing tx lock".into(),
                file: "src/db/queries.ts".into(),
                line: 1,
                status: "SUSPECT".into(),
                confidence: Confidence::Confirmed,
                entry_route: "POST /api/v1/checkout/withdraw".into(),
                sink_kind: SinkKind::BalanceUpdate,
                missing_guard: GuardKind::TxLock,
                witness_path: vec![TraceHop {
                    file: "src/routes/checkout.ts".into(),
                    symbol: "withdraw".into(),
                    line: 8,
                }],
                remediation: "Lock transaction.".into(),
            }],
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let mut state = TuiState::new(&root, graph, Vec::new(), 15);
        state.zoom_source = true;
        state.source_scroll = 2;
        state.search_mode = true;
        state.search_query = "withdraw".into();

        let (tx, rx) = mpsc::channel();
        state.bg_running = Some(("Apply-check...".into(), 3));
        state.bg_rx = Some(rx);
        tx.send(BgEvent::Patch {
            fid: "SMG-RACE-002".into(),
            content: "minimal context".into(),
            diff: Some("--- a/src/routes/checkout.ts\n+++ b/src/routes/checkout.ts\n@@ -1,2 +1,2 @@\n-old\n+new\n".into()),
            note: "Diff ready".into(),
        })
        .unwrap();
        handle_bg_events(&mut state);
        assert!(state.bg_running.is_none());
        assert!(state.patch_modal.is_some());
        assert!(state.patch_diff.is_some());

        let backend = TestBackend::new(110, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_ui(f, &mut state)).unwrap();
    }
}
