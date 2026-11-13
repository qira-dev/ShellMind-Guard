use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Stdout};
use std::path::Path;
use std::time::Duration;
use vf_graph::GraphAnalysisResult;
use vf_report::{to_html_graph, to_sarif_json};
use vf_sandbox::{VerificationStatus, VerifiedFinding};

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

pub fn run_tui(
    project_root: &Path,
    graph: &GraphAnalysisResult,
    verified: &[VerifiedFinding],
    elapsed_ms: u128,
) -> Result<()> {
    let mut guard = TerminalGuard::init()?;
    let mut selected = 0usize;
    let mut show_logs = false;
    let mut logs: Vec<String> = vec![
        format!(
            "Indexed {} files ({} symbols, {} edges) in {}ms",
            graph.parsed_files, graph.symbol_count, graph.edge_count, elapsed_ms
        ),
        format!("Verified {} findings in sandbox.", verified.len()),
    ];

    let ver_map: HashMap<&str, &VerifiedFinding> = verified
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let proven_count = verified
        .iter()
        .filter(|v| v.status == VerificationStatus::Proven)
        .count();

    loop {
        guard.terminal.draw(|f| {
            let root_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(if show_logs { 7 } else { 3 }),
                ])
                .split(f.area());

            let header = Paragraph::new(Line::from(vec![
                Span::styled(
                    " VeriForge ",
                    Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    " Target: {}  |  Files: {}  |  Scan: {}ms  |  ",
                    project_root.display(),
                    graph.parsed_files,
                    elapsed_ms
                )),
                Span::styled(
                    format!("PROVEN: {}", proven_count),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(header, root_chunks[0]);

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
                .split(root_chunks[1]);

            let items: Vec<ListItem> = if graph.findings.is_empty() {
                vec![ListItem::new("No unguarded flows detected.")]
            } else {
                graph
                    .findings
                    .iter()
                    .map(|item| {
                        let tag = match ver_map.get(item.id.as_str()).map(|v| &v.status) {
                            Some(VerificationStatus::Proven) => "[PROVEN]",
                            Some(VerificationStatus::Mitigated) => "[MITIGATED]",
                            _ => "[SUSPECT]",
                        };
                        ListItem::new(format!("{} {} ({})", tag, item.id, item.severity))
                    })
                    .collect()
            };

            let mut list_state = ListState::default();
            if !graph.findings.is_empty() {
                list_state.select(Some(selected.min(graph.findings.len() - 1)));
            }
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("[1] Findings"))
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_stateful_widget(list, body_chunks[0], &mut list_state);

            let detail_text = if let Some(cur) = graph.findings.get(selected) {
                let mut lines = vec![
                    Line::from(Span::styled(
                        format!("{} — {}", cur.id, cur.title),
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(format!("Entry Route: {}", cur.entry_route)),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Multi-File Witness Chain:",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                ];
                for (i, hop) in cur.witness_path.iter().enumerate() {
                    lines.push(Line::from(format!(
                        "  [{}] {}:{}  {}",
                        i + 1,
                        hop.file,
                        hop.line,
                        hop.symbol
                    )));
                }
                if let Some(v) = ver_map.get(cur.id.as_str()) {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("Sandbox Evidence: {}", v.evidence),
                        Style::default().fg(Color::LightRed),
                    )));
                    lines.push(Line::from(format!("Replay: {}", v.replay_cmd)));
                }
                lines
            } else {
                vec![Line::from("Select a finding to inspect its multi-file trace.")]
            };

            let detail = Paragraph::new(detail_text)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("[2] Multi-File Trace & Sandbox Proof"),
                );
            f.render_widget(detail, body_chunks[1]);

            if show_logs {
                let log_lines: Vec<Line> = logs.iter().rev().take(5).rev().map(|l| Line::from(l.as_str())).collect();
                let log_box = Paragraph::new(log_lines)
                    .block(Block::default().borders(Borders::ALL).title("[L] Logs (q: quit | g: HTML | s: SARIF)"));
                f.render_widget(log_box, root_chunks[2]);
            } else {
                let footer = Paragraph::new(
                    " [Up/Down] Select  |  [g] Export HTML Graph  |  [s] Export SARIF  |  [L] Logs  |  [q] Quit ",
                )
                .block(Block::default().borders(Borders::ALL).title("Actions"));
                f.render_widget(footer, root_chunks[2]);
            }
        })?;

        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !graph.findings.is_empty() {
                            selected = (selected + 1) % graph.findings.len();
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if !graph.findings.is_empty() {
                            selected = if selected == 0 {
                                graph.findings.len() - 1
                            } else {
                                selected - 1
                            };
                        }
                    }
                    KeyCode::Char('L') | KeyCode::Char('l') => {
                        show_logs = !show_logs;
                    }
                    KeyCode::Char('g') => {
                        let out = project_root.join(".veriforge").join("report.html");
                        let _ = fs::create_dir_all(project_root.join(".veriforge"));
                        let html = to_html_graph(
                            &project_root.display().to_string(),
                            graph,
                            verified,
                        );
                        if fs::write(&out, html).is_ok() {
                            logs.push(format!("Exported HTML graph -> {}", out.display()));
                            show_logs = true;
                        }
                    }
                    KeyCode::Char('s') => {
                        let out = project_root.join(".veriforge").join("report.sarif");
                        let _ = fs::create_dir_all(project_root.join(".veriforge"));
                        let sarif = to_sarif_json(&graph.findings, verified);
                        if fs::write(&out, sarif).is_ok() {
                            logs.push(format!("Exported SARIF 2.1.0 -> {}", out.display()));
                            show_logs = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
