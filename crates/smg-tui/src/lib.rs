mod palette;
pub mod proxy_tui;
mod session;
mod views;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use palette::{
    DetailTab, SlashAction, WorkspaceTab, complete_slash_input, filter_slash_commands,
    ghost_hint_for_input, parse_slash_command,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use session::{
    BaselineEntry, TuiSessionPrefs, copy_clipboard, finding_baseline_key, load_baseline_keys,
    load_session_prefs, save_session_prefs, write_baseline_file,
};
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, generate_patch_plan, provider_from_config,
    verify_patch_in_isolated_copy,
};
use smg_core::{ShellMindGuardConfig, StateStore, scan_repository};
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, RULE_CATALOG, SinkKind,
    analyze_codebase_cached, collect_deep_schema_findings, finding_matches_layer,
};
use smg_report::{to_html_graph, to_sarif_json};
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, verify_findings_in_sandbox_with_config,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const MAX_LOG_LINES: usize = 200;
const MAX_WIRE_FEED: usize = 256;
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
pub(crate) const BG_CANVAS: Color = Color::Rgb(13, 17, 23);
pub(crate) const BG_CARD_SELECTED: Color = Color::Rgb(24, 34, 50);
pub(crate) const BG_VULN_LINE: Color = Color::Rgb(62, 22, 28);
pub(crate) const BG_PILL_DARK: Color = Color::Rgb(33, 38, 45);
pub(crate) const BORDER_SUBTLE: Color = Color::Rgb(48, 54, 61);
pub(crate) const BORDER_ACTIVE: Color = Color::Rgb(88, 166, 255);

pub(crate) const FG_PRIMARY: Color = Color::Rgb(230, 237, 243);
pub(crate) const FG_SECONDARY: Color = Color::Rgb(149, 157, 165);
const FG_DIM: Color = Color::Rgb(110, 118, 129);

pub(crate) const SEM_PROVEN_RED: Color = Color::Rgb(248, 81, 73);
pub(crate) const SEM_SUSPECT_AMBER: Color = Color::Rgb(210, 153, 34);
pub(crate) const SEM_SAFE_GREEN: Color = Color::Rgb(63, 185, 80);
pub(crate) const SEM_BRAND_CYAN: Color = Color::Rgb(88, 166, 255);
pub(crate) const SEM_RACE_PURPLE: Color = Color::Rgb(188, 140, 255);
pub(crate) const SEM_AUTH_CORAL: Color = Color::Rgb(255, 166, 87);
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

    fn slug(self) -> &'static str {
        match self {
            FilterMode::All => "all",
            FilterMode::ProvenOnly => "proven",
            FilterMode::ConfirmedOrProven => "confirmed",
            FilterMode::CriticalOnly => "critical",
        }
    }

    fn from_slug(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "proven" => Self::ProvenOnly,
            "confirmed" => Self::ConfirmedOrProven,
            "critical" => Self::CriticalOnly,
            _ => Self::All,
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

    fn slug(self) -> &'static str {
        match self {
            CategoryFilter::All => "all",
            CategoryFilter::Auth => "auth",
            CategoryFilter::RaceLock => "race",
            CategoryFilter::Injection => "inj",
            CategoryFilter::SecretsCfg => "sec",
            CategoryFilter::Deps => "deps",
            CategoryFilter::EngineMem => "eng",
            CategoryFilter::Mobile => "mob",
            CategoryFilter::FrontendFuzz => "fe",
        }
    }

    fn from_slug_strict(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" | "" => Some(Self::All),
            "auth" | "idor" | "csrf" => Some(Self::Auth),
            "race" | "lock" => Some(Self::RaceLock),
            "inj" | "taint" | "sqli" | "xss" | "cmdi" | "ssrf" | "path" => Some(Self::Injection),
            "sec" | "secret" | "cfg" | "config" => Some(Self::SecretsCfg),
            "deps" | "dep" => Some(Self::Deps),
            "eng" | "engine" | "mem" | "memory" => Some(Self::EngineMem),
            "mob" | "mobile" => Some(Self::Mobile),
            "fe" | "frontend" | "fuzz" => Some(Self::FrontendFuzz),
            _ => None,
        }
    }

    fn from_slug(s: &str) -> Self {
        Self::from_slug_strict(s).unwrap_or(Self::All)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FilterSignature {
    filter_mode: FilterMode,
    category_filter: CategoryFilter,
    hide_baselined: bool,
    findings_len: usize,
    verified_len: usize,
    baseline_len: usize,
    search_query: String,
}

pub(crate) struct TuiState {
    pub(crate) project_root: PathBuf,
    canon_root: Option<PathBuf>,
    pub(crate) graph: GraphAnalysisResult,
    pub(crate) verified_map: HashMap<String, VerifiedFinding>,
    pub(crate) elapsed_ms: u128,
    pub(crate) selected_idx: usize,
    selected_hop: usize,
    source_scroll: isize,
    zoom_source: bool,
    queue_area: Rect,
    list_state: ListState,
    filter_mode: FilterMode,
    category_filter: CategoryFilter,
    search_mode: bool,
    search_query: String,
    workspace: WorkspaceTab,
    detail_tab: DetailTab,
    palette_mode: bool,
    palette_input: String,
    palette_selected: usize,
    pub(crate) rules_selected: usize,
    pub(crate) wire_feed: VecDeque<String>,
    pub(crate) sandbox_scroll: usize,
    pub(crate) baseline_keys: HashSet<BaselineEntry>,
    pub(crate) hide_baselined: bool,
    pub(crate) sandbox_port: u16,
    pub(crate) sandbox_tls: bool,
    pub(crate) sandbox_cgroup_v2: bool,
    pub(crate) sandbox_mem_mb: Option<u64>,
    pub(crate) sandbox_mock_shims: bool,
    pub(crate) sandbox_has_boot_cmd: bool,
    cached_filtered_indices: Vec<usize>,
    cache_sig: Option<FilterSignature>,
    show_logs: bool,
    show_help: bool,
    patch_modal: Option<(String, String)>,
    pub(crate) patch_diff: Option<String>,
    patch_scroll: u16,
    bg_running: Option<(String, usize)>,
    bg_rx: Option<Receiver<BgEvent>>,
    logs: VecDeque<String>,
    file_cache: HashMap<String, Vec<String>>,
    pub(crate) sandbox_isolated: bool,
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
        let mut wire_feed = VecDeque::new();
        for v in verified {
            if wire_feed.len() < MAX_WIRE_FEED {
                wire_feed.push_back(format!(
                    "[INIT] {} ({:?}) -> {} — {}",
                    v.finding_id, v.status, v.entry_route, v.evidence
                ));
            }
            verified_map.insert(v.finding_id.clone(), v);
        }
        Self::sort_findings(&mut graph.findings, &verified_map);

        let prefs = load_session_prefs(project_root);
        let baseline_keys = load_baseline_keys(project_root);
        let init_msg = format!(
            "Ready — Scanned {} files ({} sym · {} edges · {} routes) in {}ms. [/] Commands · [Ctrl+F] Search",
            graph.parsed_files,
            graph.symbol_count,
            graph.edge_count,
            graph.route_entries,
            elapsed_ms
        );
        let logs = VecDeque::from([
            init_msg.clone(),
            format!(
                "SMG Sandbox: {} ({} findings verified · {} baselined).",
                if smg_sandbox::has_bwrap() {
                    "Bubblewrap --unshare-all (PID/IPC/UTS/Net isolated)"
                } else {
                    "Host Loopback"
                },
                verified_map.len(),
                baseline_keys.len()
            ),
        ]);
        let mut list_state = ListState::default();
        if !graph.findings.is_empty() {
            list_state.select(Some(0));
        }

        let mut st = Self {
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
            filter_mode: FilterMode::from_slug(&prefs.filter_mode),
            category_filter: CategoryFilter::from_slug(&prefs.category_filter),
            search_mode: false,
            search_query: String::new(),
            workspace: prefs.parse_workspace(),
            detail_tab: prefs.parse_detail_tab(),
            palette_mode: false,
            palette_input: String::new(),
            palette_selected: 0,
            rules_selected: 0,
            wire_feed,
            sandbox_scroll: 0,
            baseline_keys,
            hide_baselined: prefs.hide_baselined,
            sandbox_port: 39911,
            sandbox_tls: false,
            sandbox_cgroup_v2: false,
            sandbox_mem_mb: None,
            sandbox_mock_shims: false,
            sandbox_has_boot_cmd: false,
            cached_filtered_indices: Vec::new(),
            cache_sig: None,
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
        };
        st.refresh_filter_cache();
        st
    }

    fn apply_launch_config(&mut self, cfg: &TuiLaunchConfig) {
        self.sandbox_port = cfg.port;
        self.sandbox_tls = cfg.sandbox_tls;
        self.sandbox_cgroup_v2 = cfg.cgroup_v2;
        self.sandbox_mem_mb = cfg.sandbox_mem_mb;
        self.sandbox_mock_shims = cfg.mock_shims;
        self.sandbox_has_boot_cmd = cfg.boot_cmd.is_some();
    }

    fn persist_prefs(&self) {
        let workspace = match self.workspace {
            WorkspaceTab::Overview => "overview",
            WorkspaceTab::Findings => "findings",
            WorkspaceTab::Sandbox => "sandbox",
            WorkspaceTab::Rules => "rules",
        };
        let detail_tab = match self.detail_tab {
            DetailTab::TraceSource => "trace",
            DetailTab::ProofDiff => "proof",
            DetailTab::RuleDocs => "rules",
        };
        let prefs = TuiSessionPrefs {
            workspace: workspace.to_string(),
            filter_mode: self.filter_mode.slug().to_string(),
            category_filter: self.category_filter.slug().to_string(),
            detail_tab: detail_tab.to_string(),
            hide_baselined: self.hide_baselined,
        };
        save_session_prefs(&self.project_root, &prefs);
    }

    fn filter_signature(&self) -> FilterSignature {
        FilterSignature {
            filter_mode: self.filter_mode,
            category_filter: self.category_filter,
            hide_baselined: self.hide_baselined,
            findings_len: self.graph.findings.len(),
            verified_len: self.verified_map.len(),
            baseline_len: self.baseline_keys.len(),
            search_query: self.search_query.clone(),
        }
    }

    fn invalidate_filter_cache(&mut self) {
        self.cache_sig = None;
    }

    fn compute_filtered_indices(&self) -> Vec<usize> {
        let q = self.search_query.trim().to_ascii_lowercase();
        self.graph
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if self.hide_baselined
                    && !self.baseline_keys.is_empty()
                    && self.baseline_keys.contains(&finding_baseline_key(f))
                {
                    return false;
                }
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
            .map(|(i, _)| i)
            .collect()
    }

    pub(crate) fn refresh_filter_cache(&mut self) {
        let sig = self.filter_signature();
        if self.cache_sig.as_ref() != Some(&sig) {
            self.cached_filtered_indices = self.compute_filtered_indices();
            self.cache_sig = Some(sig);
        }
    }

    fn filtered_len_mut(&mut self) -> usize {
        self.refresh_filter_cache();
        self.cached_filtered_indices.len()
    }

    fn set_selected(&mut self, idx: usize) {
        let count = self.filtered_len_mut();
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

    fn push_wire_event(&mut self, msg: String) {
        if self.wire_feed.len() >= MAX_WIRE_FEED {
            self.wire_feed.pop_front();
        }
        self.wire_feed.push_back(msg);
    }

    fn filtered_findings(&self) -> Vec<&LatticeFinding> {
        let sig = self.filter_signature();
        if self.cache_sig.as_ref() == Some(&sig) {
            return self
                .cached_filtered_indices
                .iter()
                .filter_map(|&idx| self.graph.findings.get(idx))
                .collect();
        }
        self.compute_filtered_indices()
            .into_iter()
            .filter_map(|idx| self.graph.findings.get(idx))
            .collect()
    }

    pub(crate) fn current_finding(&self) -> Option<LatticeFinding> {
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

    pub(crate) fn proof_counts(&self) -> (usize, usize, usize) {
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

pub(crate) fn clip_right_chars(s: &str, max_chars: usize) -> String {
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
    } else if state.palette_mode || state.search_mode || state.bg_running.is_some() {
        4
    } else if compact {
        3
    } else {
        4
    };

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(9),
            Constraint::Length(footer_h),
        ])
        .split(area);

    render_brand_header(f, root_chunks[0], state);
    views::render_workspace_tab_bar(f, root_chunks[1], state);

    match state.workspace {
        WorkspaceTab::Overview => {
            state.queue_area = Rect::default();
            views::render_overview_workspace(f, root_chunks[2], state, compact);
        }
        WorkspaceTab::Findings => {
            views::render_findings_workspace(f, root_chunks[2], state, compact);
        }
        WorkspaceTab::Sandbox => {
            state.queue_area = Rect::default();
            views::render_sandbox_workspace(f, root_chunks[2], state, compact);
        }
        WorkspaceTab::Rules => {
            state.queue_area = Rect::default();
            views::render_rules_workspace(f, root_chunks[2], state);
        }
    }

    render_footer(f, root_chunks[3], state, compact);

    if state.palette_mode {
        views::render_slash_palette_popup(f, area, root_chunks[3].y, state);
    }

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

pub(crate) fn render_system_legend_card(f: &mut Frame, area: Rect, state: &TuiState) {
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

pub(crate) fn render_findings_queue(f: &mut Frame, area: Rect, state: &mut TuiState) {
    state.refresh_filter_cache();
    let total_findings = state.graph.findings.len();
    let filter_label = state.filter_mode.label();
    let filtered_count = state.cached_filtered_indices.len();
    let sel_idx = if filtered_count == 0 {
        0
    } else {
        state.selected_idx.min(filtered_count - 1)
    };
    if filtered_count == 0 {
        state.list_state.select(None);
    } else {
        state.list_state.select(Some(sel_idx));
    }

    let items: Vec<ListItem> = if filtered_count == 0 {
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
        state
            .cached_filtered_indices
            .iter()
            .enumerate()
            .filter_map(|(idx, &raw_idx)| {
                let item = state.graph.findings.get(raw_idx)?;
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

                Some(ListItem::new(vec![
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
                ]))
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
                    " ◆ SMG Queue ({}/{}) · {}{}{} [f/c/b] ",
                    filtered_count, total_findings, filter_label, cat_part, search_part,
                ),
                Style::default()
                    .fg(SEM_BRAND_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
    );
    f.render_stateful_widget(list, area, &mut state.list_state);
}

pub(crate) fn render_pipeline_card(f: &mut Frame, area: Rect, state: &TuiState) {
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

pub(crate) fn render_source_inspector(f: &mut Frame, area: Rect, state: &mut TuiState) {
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

pub(crate) fn render_proof_and_remediation(
    f: &mut Frame,
    area: Rect,
    state: &TuiState,
    compact: bool,
) {
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
            ("[1-4]", " View "),
            ("[/]", " Cmd "),
            ("[Ctrl+F]", " Search "),
            ("[t]", " Tab "),
            ("[z]", " Zoom "),
            ("[j/k/g/G]", " Nav "),
            ("[Enter]", " Replay "),
            ("[p]", " Patch "),
            ("[o/e]", " Edit "),
            ("[y]", " Copy "),
            ("[L]", " Log "),
            ("[?]", " Help "),
            ("[q]", " Quit"),
        ] {
            key_spans.extend(key_hint(k, lbl));
        }
        let keys_line = Line::from(key_spans);

        let status_line = if state.palette_mode {
            let mut spans = vec![
                Span::styled(
                    "  smg> ",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    state.palette_input.clone(),
                    Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled("▏", Style::default().fg(SEM_BRAND_CYAN)),
            ];
            if let Some(ghost) = ghost_hint_for_input(&state.palette_input) {
                spans.push(Span::styled(ghost, Style::default().fg(FG_DIM)));
            }
            spans.push(Span::styled(
                "   (Tab complete · ↑/↓ pick · Enter run · Esc cancel)",
                Style::default().fg(FG_SECONDARY),
            ));
            Line::from(spans)
        } else if state.search_mode {
            Line::from(vec![
                Span::styled(
                    "  [Ctrl+F] Search : ",
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
                    "  smg> ",
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(state.last_action.clone(), Style::default().fg(FG_PRIMARY)),
            ])
        };

        let lines =
            if compact && !state.palette_mode && !state.search_mode && state.bg_running.is_none() {
                vec![keys_line]
            } else {
                vec![status_line, keys_line]
            };
        let active_prompt = state.palette_mode || state.search_mode;
        let footer = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(if active_prompt {
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
        Line::from(
            "   1 / 2 / 3 / 4                  : Switch Workspace (Overview / Findings / Sandbox / Rules)",
        ),
        Line::from(
            "   /                              : Open bottom smg> Slash Command Palette + autocomplete",
        ),
        Line::from(
            "   Ctrl+F                         : Instant fuzzy queue filter (ID, rule, file, route, symbol)",
        ),
        Line::from(
            "   ↑/↓ / j/k / Ctrl+d/u / g/G     : Vim scroll & jump findings, wire feed, or rule catalog",
        ),
        Line::from("   ←/→ / h/l / Tab                : Step through Cross-File Witness Hops"),
        Line::from(
            "   t                              : Cycle Detail Pane (Trace+Source / Proof+Diff / Rule Docs)",
        ),
        Line::from("   [ / ] / \\  (or mouse wheel)    : Scroll Source Inspector / reset [\\]"),
        Line::from("   z                              : Toggle Source Inspector full-pane zoom"),
        Line::from(
            "   c / f / b                      : Cycle Category [c], Status Filter [f], Net-New Baseline [b]",
        ),
        Line::from(
            "   r                              : Background delta-cached live rescan (/rescan)",
        ),
        Line::from("   Enter                          : Background bwrap exploit replay (/replay)"),
        Line::from(
            "   p (then a / y / ↑↓)            : Patch Context/Diff · [a] Apply-Check · [y] Copy",
        ),
        Line::from(
            "   o / e / y                      : Open in $VISUAL/$EDITOR [o/e] · Clipboard Copy [y]",
        ),
        Line::from("   s / /export sarif|html         : Export SARIF [s] or HTML graph report"),
        Line::from("   L / ? / q                      : Event Log Drawer [L], Help [?], Quit [q]"),
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

pub(crate) fn style_diff_line(line: &str) -> Line<'static> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SideBySideDiffRow {
    left: Option<String>,
    right: Option<String>,
    tag: char,
}

fn build_side_by_side_diff_rows(diff: &str) -> Vec<SideBySideDiffRow> {
    let mut rows = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    let mut added: Vec<String> = Vec::new();

    let flush_hunk =
        |removed: &mut Vec<String>, added: &mut Vec<String>, out: &mut Vec<SideBySideDiffRow>| {
            let pairs = removed.len().max(added.len());
            for i in 0..pairs {
                let l = removed.get(i).cloned();
                let r = added.get(i).cloned();
                let tag = match (&l, &r) {
                    (Some(_), Some(_)) => '~',
                    (Some(_), None) => '-',
                    (None, Some(_)) => '+',
                    (None, None) => ' ',
                };
                out.push(SideBySideDiffRow {
                    left: l,
                    right: r,
                    tag,
                });
            }
            removed.clear();
            added.clear();
        };

    for raw in diff.lines() {
        if raw.starts_with("--- ") || raw.starts_with("+++ ") {
            flush_hunk(&mut removed, &mut added, &mut rows);
            rows.push(SideBySideDiffRow {
                left: Some(raw.to_string()),
                right: Some(raw.to_string()),
                tag: 'h',
            });
        } else if raw.starts_with("@@ ") {
            flush_hunk(&mut removed, &mut added, &mut rows);
            rows.push(SideBySideDiffRow {
                left: Some(raw.to_string()),
                right: Some(raw.to_string()),
                tag: '@',
            });
        } else if let Some(rest) = raw.strip_prefix('-') {
            removed.push(format!("-{}", rest));
        } else if let Some(rest) = raw.strip_prefix('+') {
            added.push(format!("+{}", rest));
        } else {
            flush_hunk(&mut removed, &mut added, &mut rows);
            rows.push(SideBySideDiffRow {
                left: Some(raw.to_string()),
                right: Some(raw.to_string()),
                tag: ' ',
            });
        }
    }
    flush_hunk(&mut removed, &mut added, &mut rows);
    rows
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

    if let Some(diff) = diff_opt
        && modal.width >= 110
    {
        let outer = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(BG_CANVAS))
            .border_style(Style::default().fg(SEM_BRAND_CYAN))
            .title(format!(
                " ◆ SMG Patch — {} (Side-by-Side Diff · {} B, L{}, a Apply-Check) [↑/↓ scroll · y Copy · Esc/p close] ",
                fid,
                prompt_txt.len(),
                scroll + 1,
            ));
        let inner = outer.inner(modal);
        f.render_widget(outer, modal);

        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(inner);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(split[0]);

        let sbs_rows = build_side_by_side_diff_rows(diff);
        let left_lines: Vec<Line> = sbs_rows
            .iter()
            .map(|r| match (&r.left, r.tag) {
                (Some(t), '-' | '~') => style_diff_line(t),
                (Some(t), '@') => style_diff_line(t),
                (Some(t), _) => {
                    Line::from(Span::styled(t.clone(), Style::default().fg(FG_SECONDARY)))
                }
                (None, _) => Line::from(Span::styled("·".to_string(), Style::default().fg(FG_DIM))),
            })
            .collect();
        let right_lines: Vec<Line> = sbs_rows
            .iter()
            .map(|r| match (&r.right, r.tag) {
                (Some(t), '+' | '~') => style_diff_line(t),
                (Some(t), '@') => style_diff_line(t),
                (Some(t), _) => {
                    Line::from(Span::styled(t.clone(), Style::default().fg(FG_PRIMARY)))
                }
                (None, _) => Line::from(Span::styled("·".to_string(), Style::default().fg(FG_DIM))),
            })
            .collect();

        f.render_widget(
            Paragraph::new(left_lines)
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(SEM_PROVEN_RED))
                        .title(" Original (-) "),
                ),
            cols[0],
        );
        f.render_widget(
            Paragraph::new(right_lines)
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(SEM_SAFE_GREEN))
                        .title(" Patched (+) "),
                ),
            cols[1],
        );
        let ctx_lines: Vec<Line> = prompt_txt
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(FG_PRIMARY))))
            .collect();
        f.render_widget(
            Paragraph::new(ctx_lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(BORDER_SUBTLE))
                    .title(" Witness Context (<= 2 KB) "),
            ),
            split[1],
        );
        return;
    }

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
    state.refresh_filter_cache();
    if let Some(pos) = state
        .cached_filtered_indices
        .iter()
        .position(|&idx| state.graph.findings.get(idx).is_some_and(|f| f.id == fid))
    {
        state.set_selected(pos);
    } else {
        state.set_selected(0);
    }
}

fn export_report(state: &mut TuiState, fmt: &str) {
    let verified_vec: Vec<VerifiedFinding> = state.verified_map.values().cloned().collect();
    let dir = state.project_root.join(".shellmind-guard");
    match fmt {
        "html" => {
            let out = dir.join("report.html");
            let html = to_html_graph(
                &state.project_root.display().to_string(),
                &state.graph,
                &verified_vec,
            );
            match fs::create_dir_all(&dir).and_then(|_| fs::write(&out, html)) {
                Ok(_) => {
                    let _ = open_path_in_browser(&out);
                    state.push_log(format!("Opened HTML graph -> {}", out.display()));
                }
                Err(e) => state.push_log(format!("HTML export error: {}", e)),
            }
        }
        "sarif" => {
            let out = dir.join("report.sarif");
            let sarif = to_sarif_json(&state.graph.findings, &verified_vec);
            match fs::create_dir_all(&dir).and_then(|_| fs::write(&out, sarif)) {
                Ok(_) => state.push_log(format!("Exported SARIF -> {}", out.display())),
                Err(e) => state.push_log(format!("SARIF export error: {}", e)),
            }
        }
        other => state.push_log(format!(
            "Unknown export format `{}` (use sarif|html).",
            other
        )),
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
                    state.invalidate_filter_cache();
                    select_finding_by_id(state, &fid);
                    state.push_wire_event(msg.clone());
                    state.push_log(msg);
                }
                Ok((_, None)) => {
                    let msg = format!("Replay {} returned no verification result.", fid);
                    state.push_wire_event(msg.clone());
                    state.push_log(msg);
                }
                Err(e) => {
                    let msg = format!("Replay {} FAILED: {}", fid, e);
                    state.push_wire_event(msg.clone());
                    state.push_log(msg);
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
                        state.invalidate_filter_cache();
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
                let msg = format!("Apply-Check {} ({}): {}", fid, tag, summary);
                state.push_wire_event(msg.clone());
                state.push_log(msg);
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
        if let Ok(ev) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
            let _ = tx.send(ev);
        }
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

fn copy_current_finding(state: &mut TuiState) {
    if let Some(cur) = state.current_finding() {
        let summary = format_finding_clipboard_summary(
            &cur,
            state.verified_map.get(&cur.id),
            &state.project_root,
        );
        match copy_clipboard(&summary) {
            Ok(method) => state.push_log(format!("Copied {} details via {}.", cur.id, method)),
            Err(e) => state.push_log(format!("Clipboard copy failed: {}", e)),
        }
    } else {
        state.push_log("No finding selected to copy.".into());
    }
}

fn edit_current_finding(guard: &mut TerminalGuard, state: &mut TuiState) {
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
        launch_editor_for_hop(guard, state, &file, line);
    } else {
        state.push_log("No finding selected to edit.".into());
    }
}

fn step_workspace_selection(state: &mut TuiState, delta: isize, jump: Option<bool>) {
    match state.workspace {
        WorkspaceTab::Findings => {
            let len = state.filtered_len_mut();
            if len == 0 {
                return;
            }
            let target = match jump {
                Some(false) => 0,
                Some(true) => len - 1,
                None if delta == 1 => (state.selected_idx + 1) % len,
                None if delta == -1 => {
                    if state.selected_idx == 0 {
                        len - 1
                    } else {
                        state.selected_idx - 1
                    }
                }
                None if delta > 0 => (state.selected_idx + delta as usize).min(len - 1),
                None => state.selected_idx.saturating_sub((-delta) as usize),
            };
            state.set_selected(target);
        }
        WorkspaceTab::Rules => {
            let len = RULE_CATALOG.len();
            if len == 0 {
                return;
            }
            state.rules_selected = match jump {
                Some(false) => 0,
                Some(true) => len - 1,
                None if delta >= 0 => (state.rules_selected + delta as usize).min(len - 1),
                None => state.rules_selected.saturating_sub((-delta) as usize),
            };
        }
        WorkspaceTab::Sandbox => {
            let len = state.wire_feed.len().max(1);
            state.sandbox_scroll = match jump {
                Some(false) => 0,
                Some(true) => len.saturating_sub(1),
                None if delta >= 0 => (state.sandbox_scroll + delta as usize).min(len - 1),
                None => state.sandbox_scroll.saturating_sub((-delta) as usize),
            };
        }
        WorkspaceTab::Overview => {}
    }
}

fn execute_slash_action(
    action: SlashAction,
    guard: &mut TerminalGuard,
    state: &mut TuiState,
    launch_cfg: &TuiLaunchConfig,
) -> bool {
    match action {
        SlashAction::Workspace(tab) => {
            state.workspace = tab;
            state.persist_prefs();
            state.push_log(format!("Switched to Workspace [{}].", tab.label()));
        }
        SlashAction::FilterQuery(q) => {
            state.workspace = WorkspaceTab::Findings;
            state.search_query = q;
            state.invalidate_filter_cache();
            state.set_selected(0);
            let cnt = state.filtered_len_mut();
            state.push_log(format!("Filter applied ({} matching findings).", cnt));
        }
        SlashAction::CategoryLayer(arg) => {
            if let Some(cat) = CategoryFilter::from_slug_strict(&arg) {
                state.workspace = WorkspaceTab::Findings;
                state.category_filter = cat;
                state.invalidate_filter_cache();
                state.set_selected(0);
                state.persist_prefs();
                state.push_log(format!("Category layer: {}", cat.label()));
            } else {
                state.push_log(format!(
                    "Unknown layer `{}` (expected all|auth|race|inj|sec|deps|eng|mob|fe).",
                    arg
                ));
            }
        }
        SlashAction::FilterStatus(status) => {
            state.workspace = WorkspaceTab::Findings;
            state.filter_mode = match status {
                "proven" => FilterMode::ProvenOnly,
                "confirmed" => FilterMode::ConfirmedOrProven,
                "critical" => FilterMode::CriticalOnly,
                _ => FilterMode::All,
            };
            state.invalidate_filter_cache();
            state.set_selected(0);
            state.persist_prefs();
            state.push_log(format!("Status filter: {}", state.filter_mode.label()));
        }
        SlashAction::ReplaySelected => {
            if state.bg_running.is_some() {
                state.push_log("Background job already running...".into());
            } else if let Some(cur) = state.current_finding() {
                state.push_wire_event(format!("[QUEUE] Starting bwrap replay for {}...", cur.id));
                spawn_bg_replay(state, launch_cfg, cur);
            }
        }
        SlashAction::Rescan => {
            if state.bg_running.is_some() {
                state.push_log("Background job already running...".into());
            } else {
                spawn_bg_rescan(state, launch_cfg);
            }
        }
        SlashAction::PatchSelected => {
            if state.bg_running.is_some() {
                state.push_log("Background job already running...".into());
            } else if let Some(cur) = state.current_finding() {
                let v_opt = state.verified_map.get(&cur.id).cloned();
                spawn_bg_patch(state, launch_cfg, cur, v_opt);
            }
        }
        SlashAction::ApplyCheck => {
            if state.bg_running.is_some() {
                state.push_log("Background job already running...".into());
            } else if let (Some(diff), Some(cur)) =
                (state.patch_diff.clone(), state.current_finding())
            {
                spawn_bg_apply_check(state, launch_cfg, cur, diff);
            } else {
                state.push_log("No AI diff active; run `/patch` or press [p] first.".into());
            }
        }
        SlashAction::BaselineOp(op) => match op.as_str() {
            "write" | "save" => {
                match write_baseline_file(&state.project_root, &state.graph.findings) {
                    Ok(n) => {
                        state.baseline_keys = load_baseline_keys(&state.project_root);
                        state.invalidate_filter_cache();
                        state.set_selected(0);
                        state.push_log(format!(
                            "Wrote {} entries -> .shellmind-guard/baseline.json",
                            n
                        ));
                    }
                    Err(e) => state.push_log(format!("Baseline write failed: {}", e)),
                }
            }
            "load" | "reload" => {
                state.baseline_keys = load_baseline_keys(&state.project_root);
                state.invalidate_filter_cache();
                state.set_selected(0);
                state.push_log(format!(
                    "Loaded {} baseline entries from `.shellmind-guard/baseline.json`.",
                    state.baseline_keys.len()
                ));
            }
            "on" => {
                state.hide_baselined = true;
                state.invalidate_filter_cache();
                state.set_selected(0);
                state.persist_prefs();
                state.push_log("Baseline mode: ON (showing Net-New findings only).".into());
            }
            "off" => {
                state.hide_baselined = false;
                state.invalidate_filter_cache();
                state.set_selected(0);
                state.persist_prefs();
                state.push_log("Baseline mode: OFF (showing all findings).".into());
            }
            _ => {
                state.hide_baselined = !state.hide_baselined;
                state.invalidate_filter_cache();
                state.set_selected(0);
                state.persist_prefs();
                state.push_log(if state.hide_baselined {
                    "Baseline mode: ON (showing Net-New findings only).".into()
                } else {
                    "Baseline mode: OFF (showing all findings).".into()
                });
            }
        },
        SlashAction::ExportFormat(fmt) => export_report(state, &fmt),
        SlashAction::CopySelected => copy_current_finding(state),
        SlashAction::OpenEditor => edit_current_finding(guard, state),
        SlashAction::ToggleLogs => state.show_logs = !state.show_logs,
        SlashAction::ToggleHelp => state.show_help = !state.show_help,
        SlashAction::Quit => return true,
    }
    false
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
    state.apply_launch_config(&launch_cfg);
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
                let filtered_len = state.filtered_len_mut();
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
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
                {
                    break;
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
                            match copy_clipboard(&clip_text) {
                                Ok(method) => state.push_log(format!(
                                    "Copied patch modal content via {}.",
                                    method
                                )),
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
                if state.palette_mode {
                    match key.code {
                        KeyCode::Esc => {
                            state.palette_mode = false;
                            state.palette_input.clear();
                            state.palette_selected = 0;
                        }
                        KeyCode::Up => {
                            let matches = filter_slash_commands(&state.palette_input);
                            if !matches.is_empty() {
                                state.palette_selected = if state.palette_selected == 0 {
                                    matches.len() - 1
                                } else {
                                    state.palette_selected - 1
                                };
                            }
                        }
                        KeyCode::Down => {
                            let matches = filter_slash_commands(&state.palette_input);
                            if !matches.is_empty() {
                                state.palette_selected =
                                    (state.palette_selected + 1) % matches.len();
                            }
                        }
                        KeyCode::Tab => {
                            let matches = filter_slash_commands(&state.palette_input);
                            if let Some(spec) = matches
                                .get(state.palette_selected.min(matches.len().saturating_sub(1)))
                            {
                                state.palette_input = if spec.usage.contains('<') {
                                    format!("{} ", spec.cmd)
                                } else {
                                    spec.cmd.to_string()
                                };
                                state.palette_selected = 0;
                            } else if let Some(done) = complete_slash_input(&state.palette_input) {
                                state.palette_input = done;
                                state.palette_selected = 0;
                            }
                        }
                        KeyCode::Backspace => {
                            state.palette_input.pop();
                            if state.palette_input.is_empty() {
                                state.palette_mode = false;
                            }
                            state.palette_selected = 0;
                        }
                        KeyCode::Enter => {
                            let trimmed = state.palette_input.trim().to_string();
                            let matches = filter_slash_commands(&trimmed);
                            let picked = if !trimmed.contains(' ') {
                                if matches.iter().any(|s| s.cmd == trimmed) {
                                    None
                                } else {
                                    matches.get(
                                        state.palette_selected.min(matches.len().saturating_sub(1)),
                                    )
                                }
                            } else {
                                None
                            };

                            if let Some(spec) = picked {
                                if spec.usage.contains('<') {
                                    state.palette_input = format!("{} ", spec.cmd);
                                    state.palette_selected = 0;
                                    continue;
                                }
                                state.palette_mode = false;
                                state.palette_input.clear();
                                state.palette_selected = 0;
                                if let Ok(action) = parse_slash_command(spec.cmd)
                                    && execute_slash_action(
                                        action,
                                        &mut guard,
                                        &mut state,
                                        &launch_cfg,
                                    )
                                {
                                    break;
                                }
                            } else {
                                state.palette_mode = false;
                                state.palette_input.clear();
                                state.palette_selected = 0;
                                match parse_slash_command(&trimmed) {
                                    Ok(action) => {
                                        if execute_slash_action(
                                            action,
                                            &mut guard,
                                            &mut state,
                                            &launch_cfg,
                                        ) {
                                            break;
                                        }
                                    }
                                    Err(err) => state.push_log(err),
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            state.palette_input.push(c);
                            state.palette_selected = 0;
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
                            let count = state.filtered_len_mut();
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

                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('f') | KeyCode::Char('F') => {
                            state.workspace = WorkspaceTab::Findings;
                            state.search_mode = true;
                            continue;
                        }
                        KeyCode::Char('d') | KeyCode::Char('D') => {
                            step_workspace_selection(&mut state, 8, None);
                            continue;
                        }
                        KeyCode::Char('u') | KeyCode::Char('U') => {
                            step_workspace_selection(&mut state, -8, None);
                            continue;
                        }
                        _ => {}
                    }
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('?') => {
                        state.show_help = !state.show_help;
                    }
                    KeyCode::Char('/') => {
                        state.palette_mode = true;
                        state.palette_input = "/".to_string();
                        state.palette_selected = 0;
                    }
                    KeyCode::Char('1') => {
                        state.workspace = WorkspaceTab::Overview;
                        state.persist_prefs();
                    }
                    KeyCode::Char('2') => {
                        state.workspace = WorkspaceTab::Findings;
                        state.persist_prefs();
                    }
                    KeyCode::Char('3') => {
                        state.workspace = WorkspaceTab::Sandbox;
                        state.persist_prefs();
                    }
                    KeyCode::Char('4') => {
                        state.workspace = WorkspaceTab::Rules;
                        state.persist_prefs();
                    }
                    KeyCode::Char('t') => {
                        state.detail_tab = state.detail_tab.next();
                        state.persist_prefs();
                        state.push_log(format!("Detail tab: {}", state.detail_tab.label()));
                    }
                    KeyCode::Char('b') => {
                        state.hide_baselined = !state.hide_baselined;
                        state.invalidate_filter_cache();
                        state.set_selected(0);
                        state.persist_prefs();
                        state.push_log(if state.hide_baselined {
                            "Baseline filter: ON (Net-New only).".into()
                        } else {
                            "Baseline filter: OFF (showing all findings).".into()
                        });
                    }
                    KeyCode::Char('c') => {
                        state.category_filter = state.category_filter.next();
                        state.set_selected(0);
                        state.persist_prefs();
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
                        state.persist_prefs();
                        state.push_log(format!("Filter set to: {}", state.filter_mode.label()));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        step_workspace_selection(&mut state, 1, None);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        step_workspace_selection(&mut state, -1, None);
                    }
                    KeyCode::PageDown => {
                        step_workspace_selection(&mut state, 5, None);
                    }
                    KeyCode::PageUp => {
                        step_workspace_selection(&mut state, -5, None);
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        step_workspace_selection(&mut state, 0, Some(false));
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        step_workspace_selection(&mut state, 0, Some(true));
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
                            state.push_wire_event(format!(
                                "[QUEUE] Starting bwrap replay for {}...",
                                cur.id
                            ));
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
                    KeyCode::Char('e') | KeyCode::Char('o') => {
                        edit_current_finding(&mut guard, &mut state);
                    }
                    KeyCode::Char('y') => copy_current_finding(&mut state),
                    KeyCode::Char('L') => {
                        state.show_logs = !state.show_logs;
                    }
                    KeyCode::Char('s') => export_report(&mut state, "sarif"),
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
        Command::new("open")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
    #[cfg(target_os = "windows")]
    {
        // Invoke explorer.exe directly (no cmd.exe shell parsing of &, |, ^, %).
        Command::new("explorer.exe")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
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
    use crate::session::encode_base64;
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
                proof_reasons: Vec::new(),
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
                proof_reasons: Vec::new(),
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
            proof_reasons: Vec::new(),
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
            proof_reasons: Vec::new(),
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
            proof_reasons: Vec::new(),
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
                proof_reasons: Vec::new(),
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

    #[test]
    fn test_tui_workspaces_detail_tabs_and_slash_palette_render() {
        let graph = GraphAnalysisResult {
            parsed_files: 4,
            symbol_count: 10,
            edge_count: 7,
            route_entries: 3,
            active_domains: vec!["web".into(), "concurrency".into()],
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
                witness_path: vec![TraceHop {
                    file: "src/routes/checkout.ts".into(),
                    symbol: "withdraw".into(),
                    line: 8,
                }],
                remediation: "Use SELECT ... FOR UPDATE".into(),
                proof_reasons: Vec::new(),
            }],
        };
        let verified = vec![VerifiedFinding {
            finding_id: "SMG-RACE-002".into(),
            rule_id: "SMG-RACE-001".into(),
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            status: VerificationStatus::Proven,
            evidence: "2/2 concurrent overdraft succeeded".into(),
            replay_cmd: "smg replay SMG-RACE-002".into(),
        }];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let mut state = TuiState::new(&root, graph, verified, 25);

        for (w, h) in [(100, 24), (120, 36)] {
            for ws in WorkspaceTab::ALL {
                state.workspace = ws;
                let backend = TestBackend::new(w, h);
                let mut terminal = Terminal::new(backend).unwrap();
                terminal.draw(|f| render_ui(f, &mut state)).unwrap();
                let buf = terminal.backend().buffer();
                let text: String = (0..h)
                    .flat_map(|y| (0..w).map(move |x| buf[(x, y)].symbol()))
                    .collect();
                assert!(text.contains("SMG"));
            }

            state.workspace = WorkspaceTab::Findings;
            for dt in [
                DetailTab::TraceSource,
                DetailTab::ProofDiff,
                DetailTab::RuleDocs,
            ] {
                state.detail_tab = dt;
                let backend = TestBackend::new(w, h);
                let mut terminal = Terminal::new(backend).unwrap();
                terminal.draw(|f| render_ui(f, &mut state)).unwrap();
            }

            state.palette_mode = true;
            state.palette_input = "/re".into();
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| render_ui(f, &mut state)).unwrap();
            let buf = terminal.backend().buffer();
            let text: String = (0..h)
                .flat_map(|y| (0..w).map(move |x| buf[(x, y)].symbol()))
                .collect();
            assert!(text.contains("/replay"));
            assert!(text.contains("smg>"));
            state.palette_mode = false;
        }
    }

    #[test]
    fn test_tui_baseline_cache_and_vim_stepping() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_tui_base_{}", nanos));
        fs::create_dir_all(&tmp).unwrap();

        let f1 = LatticeFinding {
            id: "SMG-AUTH-001".into(),
            rule_id: "SMG-AUTH-001".into(),
            severity: "HIGH".into(),
            title: "Unauth endpoint".into(),
            file: "a.ts".into(),
            line: 5,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "POST /a".into(),
            sink_kind: SinkKind::PaymentMutation,
            missing_guard: GuardKind::Auth,
            witness_path: vec![TraceHop {
                file: "a.ts".into(),
                symbol: "handleA".into(),
                line: 5,
            }],
            remediation: "Auth".into(),
            proof_reasons: Vec::new(),
        };
        let f2 = LatticeFinding {
            id: "SMG-SQLI-001".into(),
            rule_id: "SMG-SQLI-001".into(),
            severity: "CRITICAL".into(),
            title: "SQLi".into(),
            file: "b.ts".into(),
            line: 9,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "GET /b".into(),
            sink_kind: SinkKind::SqlInjection,
            missing_guard: GuardKind::SqlSanitizer,
            witness_path: vec![TraceHop {
                file: "b.ts".into(),
                symbol: "handleB".into(),
                line: 9,
            }],
            remediation: "Bind".into(),
            proof_reasons: Vec::new(),
        };
        let graph = GraphAnalysisResult {
            parsed_files: 2,
            symbol_count: 2,
            edge_count: 1,
            route_entries: 2,
            active_domains: vec!["web".into()],
            route_schemas: Vec::new(),
            findings: vec![f1.clone(), f2],
        };
        let mut state = TuiState::new(&tmp, graph, Vec::new(), 5);
        assert_eq!(state.filtered_len_mut(), 2);

        // Baseline only f1 -> Net-New mode must leave only f2
        assert_eq!(write_baseline_file(&tmp, &[f1]).unwrap(), 1);
        state.baseline_keys = load_baseline_keys(&tmp);
        state.hide_baselined = true;
        state.invalidate_filter_cache();
        assert_eq!(state.filtered_len_mut(), 1);
        assert_eq!(state.filtered_findings()[0].id, "SMG-SQLI-001");

        // Toggle off -> both back
        state.hide_baselined = false;
        assert_eq!(state.filtered_len_mut(), 2);

        // Vim navigation across workspaces
        state.workspace = WorkspaceTab::Findings;
        step_workspace_selection(&mut state, 0, Some(true));
        assert_eq!(state.selected_idx, 1);
        step_workspace_selection(&mut state, 0, Some(false));
        assert_eq!(state.selected_idx, 0);

        state.workspace = WorkspaceTab::Rules;
        step_workspace_selection(&mut state, 1, None);
        assert_eq!(state.rules_selected, 1);
        step_workspace_selection(&mut state, 0, Some(true));
        assert_eq!(state.rules_selected, RULE_CATALOG.len() - 1);

        let diff = "--- a/app.ts\n+++ b/app.ts\n@@ -1,3 +1,3 @@\n const a = 1;\n-db.query(`SELECT * FROM u WHERE id = ${id}`);\n+db.query('SELECT * FROM u WHERE id = $1', [id]);\n return true;";
        let rows = build_side_by_side_diff_rows(diff);
        let mod_row = rows
            .iter()
            .find(|r| r.tag == '~')
            .expect("Side-by-side diff must align -/+ replacement row");
        assert!(mod_row.left.as_deref().unwrap().contains("${id}"));
        assert!(mod_row.right.as_deref().unwrap().contains("$1"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
