use crate::palette::{DetailTab, WorkspaceTab, filter_slash_commands};
use crate::{
    BG_CANVAS, BG_CARD_SELECTED, BG_PILL_DARK, BORDER_ACTIVE, BORDER_SUBTLE, FG_PRIMARY,
    FG_SECONDARY, SEM_AUTH_CORAL, SEM_BRAND_CYAN, SEM_PROVEN_RED, SEM_RACE_PURPLE, SEM_SAFE_GREEN,
    SEM_SUSPECT_AMBER, TuiState, clip_right_chars, render_findings_queue, render_pipeline_card,
    render_proof_and_remediation, render_source_inspector, render_system_legend_card,
    style_diff_line,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use smg_graph::{GuardKind, RULE_CATALOG, find_rule_doc};

/// Renders the compact `[1 Overview] [2 Findings] [3 Sandbox] [4 Rules]` workspace strip below header.
pub(crate) fn render_workspace_tab_bar(f: &mut Frame, area: Rect, state: &TuiState) {
    let mut spans = vec![Span::raw(" ")];
    for tab in WorkspaceTab::ALL {
        let active = state.workspace == tab;
        let style = if active {
            Style::default()
                .fg(Color::Black)
                .bg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(FG_SECONDARY).bg(BG_PILL_DARK)
        };
        spans.push(Span::styled(format!(" {} ", tab.label()), style));
        spans.push(Span::raw(" "));
    }

    if state.workspace == WorkspaceTab::Findings {
        spans.push(Span::styled("│ ", Style::default().fg(BORDER_SUBTLE)));
        spans.push(Span::styled("[t] ", Style::default().fg(SEM_BRAND_CYAN)));
        spans.push(Span::styled(
            state.detail_tab.label(),
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        ));
    }

    let base_count = state.baseline_keys.len();
    if base_count > 0 || state.hide_baselined {
        spans.push(Span::styled("  │ ", Style::default().fg(BORDER_SUBTLE)));
        let base_label = if state.hide_baselined {
            format!("[b] Net-New ({} baselined)", base_count)
        } else {
            format!("[b] Base:{} (shown)", base_count)
        };
        spans.push(Span::styled(
            base_label,
            Style::default().fg(if state.hide_baselined {
                SEM_SAFE_GREEN
            } else {
                SEM_SUSPECT_AMBER
            }),
        ));
    }

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(BG_CANVAS)),
        area,
    );
}

/// Workspace [1]: High-level security posture, severity breakdown, guard taxonomy, and `/` tips.
pub(crate) fn render_overview_workspace(
    f: &mut Frame,
    area: Rect,
    state: &mut TuiState,
    compact: bool,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let (proven, mitigated, suspect) = state.proof_counts();
    let total = state.graph.findings.len();
    let mut crit = 0usize;
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    let mut auth_cnt = 0usize;
    let mut race_cnt = 0usize;
    let mut inj_cnt = 0usize;
    let mut other_cnt = 0usize;

    for item in &state.graph.findings {
        match item.severity.as_str() {
            "CRITICAL" => crit += 1,
            "HIGH" => high += 1,
            "MEDIUM" => med += 1,
            _ => low += 1,
        }
        match item.missing_guard {
            GuardKind::Auth | GuardKind::OwnershipCheck | GuardKind::CsrfProtection => {
                auth_cnt += 1
            }
            GuardKind::TxLock | GuardKind::LockOrdering => race_cnt += 1,
            GuardKind::SqlSanitizer
            | GuardKind::CmdSanitizer
            | GuardKind::PathSanitizer
            | GuardKind::SsrfSanitizer
            | GuardKind::XssSanitizer => inj_cnt += 1,
            _ => other_cnt += 1,
        }
    }

    let left_lines = vec![
        Line::from(vec![
            Span::styled("  Project   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                state.project_root.display().to_string(),
                Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Graph     : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "{} files · {} symbols · {} edges · {} routes ({}ms)",
                    state.graph.parsed_files,
                    state.graph.symbol_count,
                    state.graph.edge_count,
                    state.graph.route_entries,
                    state.elapsed_ms
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Domains   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                if state.graph.active_domains.is_empty() {
                    "core".to_string()
                } else {
                    state.graph.active_domains.join(", ")
                },
                Style::default().fg(SEM_BRAND_CYAN),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Proofs    : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!("● PROVEN {}  ", proven),
                Style::default()
                    .fg(SEM_PROVEN_RED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("◆ SUSPECT {}  ", suspect),
                Style::default().fg(SEM_SUSPECT_AMBER),
            ),
            Span::styled(
                format!("✓ MITIGATED {}", mitigated),
                Style::default().fg(SEM_SAFE_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Severity  : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!("CRIT {}  ", crit),
                Style::default().fg(SEM_PROVEN_RED),
            ),
            Span::styled(
                format!("HIGH {}  ", high),
                Style::default().fg(SEM_AUTH_CORAL),
            ),
            Span::styled(
                format!("MED {}  ", med),
                Style::default().fg(SEM_SUSPECT_AMBER),
            ),
            Span::styled(format!("LOW {}", low), Style::default().fg(FG_SECONDARY)),
        ]),
        Line::from(vec![
            Span::styled("  Latency   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!("{} findings normalized · cache-aware O(V+E)", total),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
    ];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ [1] Security Overview & Graph Posture ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(left_lines)
            .wrap(Wrap { trim: false })
            .block(left_block),
        cols[0],
    );

    let right_top_h = if compact { 8 } else { 10 };
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(right_top_h), Constraint::Min(6)])
        .split(cols[1]);

    let breakdown_lines = vec![
        Line::from(vec![
            Span::styled(
                "  AUTH / IDOR / CSRF : ",
                Style::default().fg(SEM_AUTH_CORAL),
            ),
            Span::styled(format!("{}", auth_cnt), Style::default().fg(FG_PRIMARY)),
        ]),
        Line::from(vec![
            Span::styled(
                "  RACE / LOCK        : ",
                Style::default().fg(SEM_RACE_PURPLE),
            ),
            Span::styled(format!("{}", race_cnt), Style::default().fg(FG_PRIMARY)),
        ]),
        Line::from(vec![
            Span::styled(
                "  TAINT / INJECTION  : ",
                Style::default().fg(SEM_PROVEN_RED),
            ),
            Span::styled(format!("{}", inj_cnt), Style::default().fg(FG_PRIMARY)),
        ]),
        Line::from(vec![
            Span::styled(
                "  CFG / SECRETS / IO : ",
                Style::default().fg(SEM_SUSPECT_AMBER),
            ),
            Span::styled(format!("{}", other_cnt), Style::default().fg(FG_PRIMARY)),
        ]),
        Line::from(vec![
            Span::styled("  Baseline Entries   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "{} (press [b] or /baseline write)",
                    state.baseline_keys.len()
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
    ];
    let tax_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Missing Guard Distribution ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(breakdown_lines)
            .wrap(Wrap { trim: false })
            .block(tax_block),
        right_rows[0],
    );

    let quick_cmds = vec![
        Line::from("  Press [2] for Findings Queue & Cross-File Witness Trace."),
        Line::from("  Press [/] to open bottom smg> Slash Palette with live autocomplete."),
        Line::from("  Press [Ctrl+F] to instant-filter findings by ID, route, file, or symbol."),
        Line::from("  Try: /proven · /baseline write · /export sarif · /rules · /sandbox"),
    ];
    let cmd_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Power-User Workflows ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(quick_cmds)
            .wrap(Wrap { trim: false })
            .block(cmd_block),
        right_rows[1],
    );
}

/// Workspace [2]: Preserves original 2-column TUI layout while letting `[t]` switch Right Detail panes.
pub(crate) fn render_findings_workspace(
    f: &mut Frame,
    area: Rect,
    state: &mut TuiState,
    compact: bool,
) {
    if state.zoom_source {
        state.queue_area = Rect::default();
        let zoom_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(if compact { 6 } else { 8 }),
            ])
            .split(area);
        render_source_inspector(f, zoom_chunks[0], state);
        render_proof_and_remediation(f, zoom_chunks[1], state, compact);
        return;
    }

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

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

    match state.detail_tab {
        DetailTab::TraceSource => {
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
        DetailTab::ProofDiff => render_detail_proof_diff(f, body_chunks[1], state, compact),
        DetailTab::RuleDocs => render_detail_rule_docs(f, body_chunks[1], state),
    }
}

fn render_detail_proof_diff(f: &mut Frame, area: Rect, state: &TuiState, compact: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if compact { 7 } else { 10 }),
            Constraint::Min(6),
        ])
        .split(area);

    render_proof_and_remediation(f, chunks[0], state, false);

    let mut diff_lines: Vec<Line> = Vec::new();
    if let Some(ref diff) = state.patch_diff {
        diff_lines.extend(diff.lines().map(style_diff_line));
    } else if let Some(cur) = state.current_finding() {
        diff_lines.push(Line::from(Span::styled(
            format!("  Active Finding: {} ({})", cur.id, cur.rule_id),
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        )));
        diff_lines.push(Line::from(""));
        diff_lines.push(Line::from(Span::styled(
            "  No AI patch diff generated yet for this session.",
            Style::default().fg(FG_SECONDARY),
        )));
        diff_lines.push(Line::from(
            "  Press [p] or run `/patch` to build a minimal <=2 KB witness prompt + unified diff.",
        ));
        diff_lines.push(Line::from(
            "  Press [Enter] or `/replay` (with --boot-cmd) for Bubblewrap verification.",
        ));
        if !cur.witness_path.is_empty() {
            diff_lines.push(Line::from(""));
            diff_lines.push(Line::from(Span::styled(
                "  Full Cross-File Witness Hops:",
                Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
            )));
            for (idx, hop) in cur.witness_path.iter().enumerate() {
                diff_lines.push(Line::from(format!(
                    "    [{}] {}  ({}:{})",
                    idx + 1,
                    hop.symbol,
                    hop.file,
                    hop.line
                )));
            }
        }
    } else {
        diff_lines.push(Line::from("  No finding selected."));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Span::styled(
            " ◆ [t] Proof & Patch Diff View ([t] cycle · [p] Patch · [e/o] Editor) ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(diff_lines)
            .wrap(Wrap { trim: false })
            .block(block),
        chunks[1],
    );
}

fn render_detail_rule_docs(f: &mut Frame, area: Rect, state: &TuiState) {
    let lines = if let Some(cur) = state.current_finding() {
        if let Some(doc) = find_rule_doc(&cur.rule_id) {
            format_rule_doc_lines(doc, Some(&cur.remediation))
        } else {
            vec![
                Line::from(Span::styled(
                    format!("  Rule ID : {} ({})", cur.rule_id, cur.severity),
                    Style::default()
                        .fg(SEM_BRAND_CYAN)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("  Title   : {}", cur.title)),
                Line::from(format!("  Guard   : {:?}", cur.missing_guard)),
                Line::from(format!("  Sink    : {:?}", cur.sink_kind)),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  Remediation: {}", cur.remediation),
                    Style::default().fg(SEM_SAFE_GREEN),
                )),
            ]
        }
    } else {
        vec![Line::from(
            "  Select a finding to inspect its security rule documentation.",
        )]
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Span::styled(
            " ◆ [t] Built-in Rule Documentation ([4] browse all rules) ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// Workspace [3]: Isolated Bubblewrap sandbox telemetry + bounded wire-event feed.
pub(crate) fn render_sandbox_workspace(f: &mut Frame, area: Rect, state: &TuiState, compact: bool) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if compact { 7 } else { 8 }),
            Constraint::Min(6),
        ])
        .split(area);

    let sb_status = if state.sandbox_isolated {
        Span::styled(
            "● bwrap --unshare-all ACTIVE",
            Style::default()
                .fg(SEM_SAFE_GREEN)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "◆ bwrap missing — host loopback opt-in only",
            Style::default().fg(SEM_SUSPECT_AMBER),
        )
    };
    let mem_str = state
        .sandbox_mem_mb
        .map(|m| format!("{} MB", m))
        .unwrap_or_else(|| "default".to_string());
    let boot_str = if state.sandbox_has_boot_cmd {
        Span::styled(
            "Configured (Enter / `/replay` ready)",
            Style::default().fg(SEM_SAFE_GREEN),
        )
    } else {
        Span::styled(
            "Not set — launch with `--boot-cmd`",
            Style::default().fg(SEM_SUSPECT_AMBER),
        )
    };

    let cap_lines = vec![
        Line::from(vec![
            Span::styled("  Isolation : ", Style::default().fg(FG_SECONDARY)),
            sb_status,
        ]),
        Line::from(vec![
            Span::styled("  Targets   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "Loopback Port {} · TLS={} · cgroup-v2={} · Mem={} · Shims={}",
                    state.sandbox_port,
                    state.sandbox_tls,
                    state.sandbox_cgroup_v2,
                    mem_str,
                    state.sandbox_mock_shims
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Boot Cmd  : ", Style::default().fg(FG_SECONDARY)),
            boot_str,
        ]),
        Line::from(vec![
            Span::styled("  Verdict   : ", Style::default().fg(FG_SECONDARY)),
            Span::styled(
                format!(
                    "{} total verified results recorded in wire buffer ({} events).",
                    state.verified_map.len(),
                    state.wire_feed.len()
                ),
                Style::default().fg(FG_PRIMARY),
            ),
        ]),
    ];

    let top_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ [3] Bubblewrap Sandbox & Loopback Wire Oracle Posture ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(cap_lines)
            .wrap(Wrap { trim: false })
            .block(top_block),
        rows[0],
    );

    let max_events = rows[1].height.saturating_sub(2) as usize;
    let total_feed = state.wire_feed.len();
    let skip = state
        .sandbox_scroll
        .min(total_feed.saturating_sub(max_events.max(1)));
    let feed_lines: Vec<Line> = if state.wire_feed.is_empty() {
        vec![
            Line::from(Span::styled(
                "  No runtime replay wire events recorded yet.",
                Style::default().fg(FG_SECONDARY),
            )),
            Line::from("  Trigger `/replay` or press [Enter] on a finding in [2] Findings."),
        ]
    } else {
        state
            .wire_feed
            .iter()
            .rev()
            .skip(skip)
            .take(max_events.max(1))
            .map(|entry| {
                let color = if entry.contains("PROVEN") || entry.contains("FAILED") {
                    SEM_PROVEN_RED
                } else if entry.contains("MITIGATED") {
                    SEM_SAFE_GREEN
                } else {
                    FG_PRIMARY
                };
                Line::from(Span::styled(
                    format!("  • {}", entry),
                    Style::default().fg(color),
                ))
            })
            .collect()
    };

    let feed_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Span::styled(
            format!(
                " ◆ Live Wire-Oracle Event Stream ({} buffered · j/k scroll) ",
                total_feed
            ),
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(feed_lines)
            .wrap(Wrap { trim: false })
            .block(feed_block),
        rows[1],
    );
}

/// Workspace [4]: Interactive catalog browser for `smg_graph::RULE_CATALOG`.
pub(crate) fn render_rules_workspace(f: &mut Frame, area: Rect, state: &TuiState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let total = RULE_CATALOG.len();
    let sel = if total == 0 {
        0
    } else {
        state.rules_selected.min(total - 1)
    };
    let mut list_state = ListState::default();
    if total > 0 {
        list_state.select(Some(sel));
    }

    let items: Vec<ListItem> = RULE_CATALOG
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let is_sel = i == sel;
            let bg = if is_sel { BG_CARD_SELECTED } else { BG_CANVAS };
            let sev_color = match rule.severity {
                "CRITICAL" => SEM_PROVEN_RED,
                "HIGH" => SEM_AUTH_CORAL,
                _ => SEM_SUSPECT_AMBER,
            };
            let title_trim = clip_right_chars(
                rule.title,
                (cols[0].width as usize).saturating_sub(24).max(12),
            );
            ListItem::new(Line::from(vec![
                Span::styled(
                    if is_sel { " ▶ " } else { "   " },
                    Style::default().fg(SEM_BRAND_CYAN).bg(bg),
                ),
                Span::styled(
                    format!("{:<14} ", rule.rule_id),
                    Style::default()
                        .fg(sev_color)
                        .bg(bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(title_trim, Style::default().fg(FG_PRIMARY).bg(bg)),
            ]))
            .style(Style::default().bg(bg))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .title(Span::styled(
                format!(" ◆ [4] Built-in Rule Catalog ({}/{}) ", sel + 1, total),
                Style::default()
                    .fg(SEM_BRAND_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
    );
    f.render_stateful_widget(list, cols[0], &mut list_state);

    let detail_lines = if let Some(rule) = RULE_CATALOG.get(sel) {
        format_rule_doc_lines(rule, None)
    } else {
        vec![Line::from("  No built-in rules registered.")]
    };

    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " ◆ Rule Specification, Vulnerable Code & Secure Pattern ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(detail_lines)
            .wrap(Wrap { trim: false })
            .block(detail_block),
        cols[1],
    );
}

fn format_rule_doc_lines(
    doc: &smg_graph::RuleDoc,
    instance_remediation: Option<&str>,
) -> Vec<Line<'static>> {
    let sev_color = match doc.severity {
        "CRITICAL" => SEM_PROVEN_RED,
        "HIGH" => SEM_AUTH_CORAL,
        _ => SEM_SUSPECT_AMBER,
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("  {} ", doc.rule_id),
                Style::default()
                    .fg(SEM_BRAND_CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{} · {}]", doc.severity, doc.layer),
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!("  {}", doc.title),
            Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", doc.description),
            Style::default().fg(FG_PRIMARY),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Vulnerable Pattern:",
            Style::default()
                .fg(SEM_PROVEN_RED)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    for l in doc.vulnerable_example.lines() {
        lines.push(Line::from(Span::styled(
            format!("    - {}", l),
            Style::default().fg(SEM_PROVEN_RED),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Secure Fixed Pattern:",
        Style::default()
            .fg(SEM_SAFE_GREEN)
            .add_modifier(Modifier::BOLD),
    )));
    for l in doc.fixed_example.lines() {
        lines.push(Line::from(Span::styled(
            format!("    + {}", l),
            Style::default().fg(SEM_SAFE_GREEN),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Remediation : ", Style::default().fg(FG_SECONDARY)),
        Span::styled(
            instance_remediation
                .filter(|r| !r.is_empty())
                .unwrap_or(doc.remediation)
                .to_string(),
            Style::default().fg(SEM_BRAND_CYAN),
        ),
    ]));
    lines
}

/// Renders the floating `/` command autocomplete popup anchored right above `footer_area`.
pub(crate) fn render_slash_palette_popup(
    f: &mut Frame,
    area: Rect,
    footer_top_y: u16,
    state: &TuiState,
) {
    let matches = filter_slash_commands(&state.palette_input);
    if matches.is_empty() {
        return;
    }
    if area.width < 12 || area.height < 6 || footer_top_y < 4 {
        return;
    }
    let max_h = footer_top_y.saturating_sub(2).min(area.height);
    let popup_h = ((matches.len() as u16).saturating_add(2))
        .min(max_h)
        .max(3)
        .min(area.height);
    let max_w = area.width.saturating_sub(4).max(1);
    let popup_w = max_w.min(86).max(max_w.min(40));
    let x = area
        .x
        .saturating_add(2)
        .min(area.x.saturating_add(area.width.saturating_sub(popup_w)));
    let y = footer_top_y.saturating_sub(popup_h).max(area.y);
    let rect = Rect::new(x, y, popup_w, popup_h);
    f.render_widget(Clear, rect);

    let sel = state.palette_selected.min(matches.len() - 1);
    let lines: Vec<Line> = matches
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let is_sel = i == sel;
            let bg = if is_sel { BG_CARD_SELECTED } else { BG_CANVAS };
            let used_left = 26usize;
            let avail_desc = (popup_w as usize).saturating_sub(used_left + 4);
            let desc = clip_right_chars(spec.summary, avail_desc);
            Line::from(vec![
                Span::styled(
                    if is_sel { " ▶ " } else { "   " },
                    Style::default().fg(SEM_BRAND_CYAN).bg(bg),
                ),
                Span::styled(
                    format!("{:<22} ", spec.usage),
                    Style::default()
                        .fg(if is_sel { SEM_BRAND_CYAN } else { FG_PRIMARY })
                        .bg(bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(desc, Style::default().fg(FG_SECONDARY).bg(bg)),
            ])
            .style(Style::default().bg(bg))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(BG_CANVAS))
        .border_style(Style::default().fg(SEM_BRAND_CYAN))
        .title(Span::styled(
            " ◆ Slash Commands ([Tab] complete · [↑/↓] select · [Enter] run · [Esc] cancel) ",
            Style::default()
                .fg(SEM_BRAND_CYAN)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(Paragraph::new(lines).block(block), rect);
}
