/// Workspace identifier for the 4-screen Power-User TUI architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTab {
    Overview = 1,
    Findings = 2,
    Sandbox = 3,
    Rules = 4,
}

impl WorkspaceTab {
    pub const ALL: [Self; 4] = [Self::Overview, Self::Findings, Self::Sandbox, Self::Rules];

    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "1 Overview",
            Self::Findings => "2 Findings",
            Self::Sandbox => "3 Sandbox",
            Self::Rules => "4 Rules",
        }
    }
}

/// Right-hand detail pane mode inside `[2] Findings` (`[t]` cycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    TraceSource,
    ProofDiff,
    RuleDocs,
}

impl DetailTab {
    pub fn next(self) -> Self {
        match self {
            Self::TraceSource => Self::ProofDiff,
            Self::ProofDiff => Self::RuleDocs,
            Self::RuleDocs => Self::TraceSource,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TraceSource => "Trace+Source",
            Self::ProofDiff => "Proof+Diff",
            Self::RuleDocs => "Rule Docs",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlashCommandSpec {
    pub cmd: &'static str,
    pub usage: &'static str,
    pub summary: &'static str,
}

pub const SLASH_COMMANDS: &[SlashCommandSpec] = &[
    SlashCommandSpec {
        cmd: "/overview",
        usage: "/overview",
        summary: "Switch to Workspace [1] Security Overview & Posture",
    },
    SlashCommandSpec {
        cmd: "/findings",
        usage: "/findings",
        summary: "Switch to Workspace [2] Findings Queue & Inspector",
    },
    SlashCommandSpec {
        cmd: "/sandbox",
        usage: "/sandbox",
        summary: "Switch to Workspace [3] Sandbox & Live Wire Event Feed",
    },
    SlashCommandSpec {
        cmd: "/rules",
        usage: "/rules",
        summary: "Switch to Workspace [4] Built-in Security Rule Catalog",
    },
    SlashCommandSpec {
        cmd: "/filter",
        usage: "/filter <query|clear>",
        summary: "Filter queue by rule ID, file, route, or symbol",
    },
    SlashCommandSpec {
        cmd: "/layer",
        usage: "/layer <all|auth|race|inj|sec|deps|eng|mob|fe>",
        summary: "Filter queue by guard/vulnerability category",
    },
    SlashCommandSpec {
        cmd: "/proven",
        usage: "/proven",
        summary: "Toggle PROVEN-only high-assurance filter",
    },
    SlashCommandSpec {
        cmd: "/all",
        usage: "/all",
        summary: "Reset status & category filters to ALL",
    },
    SlashCommandSpec {
        cmd: "/critical",
        usage: "/critical",
        summary: "Show CRITICAL severity findings only",
    },
    SlashCommandSpec {
        cmd: "/replay",
        usage: "/replay",
        summary: "Execute Bubblewrap/Wire Oracle proof on selected finding",
    },
    SlashCommandSpec {
        cmd: "/rescan",
        usage: "/rescan",
        summary: "Run non-blocking repository rescan in background",
    },
    SlashCommandSpec {
        cmd: "/patch",
        usage: "/patch",
        summary: "Open patch modal / request AI remediation plan",
    },
    SlashCommandSpec {
        cmd: "/apply-check",
        usage: "/apply-check",
        summary: "Verify active AI diff inside isolated temporary copy",
    },
    SlashCommandSpec {
        cmd: "/baseline",
        usage: "/baseline <write|load|toggle>",
        summary: "Write, reload, or toggle Net-New vs Baselined filter",
    },
    SlashCommandSpec {
        cmd: "/export",
        usage: "/export <sarif|html>",
        summary: "Export findings report to `.shellmind-guard/`",
    },
    SlashCommandSpec {
        cmd: "/copy",
        usage: "/copy",
        summary: "Copy finding summary via OSC 52 / OS clipboard",
    },
    SlashCommandSpec {
        cmd: "/edit",
        usage: "/edit",
        summary: "Open current trace line safely in $VISUAL / $EDITOR",
    },
    SlashCommandSpec {
        cmd: "/logs",
        usage: "/logs",
        summary: "Toggle bottom Event Log ring-buffer drawer",
    },
    SlashCommandSpec {
        cmd: "/help",
        usage: "/help",
        summary: "Toggle full TUI shortcuts & slash command help",
    },
    SlashCommandSpec {
        cmd: "/quit",
        usage: "/quit",
        summary: "Exit ShellMind Guard TUI cleanly",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashAction {
    Workspace(WorkspaceTab),
    FilterQuery(String),
    CategoryLayer(String),
    FilterStatus(&'static str),
    ReplaySelected,
    Rescan,
    PatchSelected,
    ApplyCheck,
    BaselineOp(String),
    ExportFormat(String),
    CopySelected,
    OpenEditor,
    ToggleLogs,
    ToggleHelp,
    Quit,
}

/// Filters `SLASH_COMMANDS` for floating autocomplete popup as the user types `/...`.
pub fn filter_slash_commands(input: &str) -> Vec<&'static SlashCommandSpec> {
    let trimmed = input.trim().to_ascii_lowercase();
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if head.is_empty() || head == "/" {
        return SLASH_COMMANDS.iter().take(10).collect();
    }
    let q = head.trim_start_matches('/');
    let mut prefix: Vec<&'static SlashCommandSpec> = Vec::new();
    let mut contains: Vec<&'static SlashCommandSpec> = Vec::new();
    for spec in SLASH_COMMANDS {
        let name = spec.cmd.trim_start_matches('/');
        if name.starts_with(q) {
            prefix.push(spec);
        } else if name.contains(q) || spec.summary.to_ascii_lowercase().contains(q) {
            contains.push(spec);
        }
    }
    prefix.extend(contains);
    prefix.truncate(10);
    prefix
}

/// Computes the inline gray ghost suffix (`filter <query|clear>` after `/fi`) on the `smg>` prompt.
pub fn ghost_hint_for_input(input: &str) -> Option<String> {
    let trimmed = input.trim_start();
    if !trimmed.starts_with('/') {
        return None;
    }
    let matches = filter_slash_commands(trimmed);
    let top = matches.first()?;
    if !trimmed.contains(' ') {
        let head_lower = trimmed.to_ascii_lowercase();
        if top.cmd.starts_with(&head_lower) && top.usage.len() > trimmed.len() {
            return Some(top.usage[trimmed.len()..].to_string());
        }
    }
    None
}

/// Tab-completes a partial slash command to its full canonical verb (plus trailing space when args expected).
pub fn complete_slash_input(input: &str) -> Option<String> {
    let matches = filter_slash_commands(input);
    let top = matches.first()?;
    let needs_arg = top.usage.contains('<');
    Some(if needs_arg {
        format!("{} ", top.cmd)
    } else {
        top.cmd.to_string()
    })
}

/// Parses an executed `/command ...` line from the `smg>` command bar.
pub fn parse_slash_command(raw: &str) -> Result<SlashAction, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Empty slash command.".to_string());
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let verb = parts.next().unwrap_or("").to_ascii_lowercase();
    let rest = parts.next().unwrap_or("").trim();

    match verb.as_str() {
        "/overview" | "/o" | "/1" => Ok(SlashAction::Workspace(WorkspaceTab::Overview)),
        "/findings" | "/f" | "/2" => Ok(SlashAction::Workspace(WorkspaceTab::Findings)),
        "/sandbox" | "/sb" | "/3" => Ok(SlashAction::Workspace(WorkspaceTab::Sandbox)),
        "/rules" | "/ru" | "/4" => Ok(SlashAction::Workspace(WorkspaceTab::Rules)),
        "/filter" | "/search" => {
            if rest.eq_ignore_ascii_case("clear") {
                Ok(SlashAction::FilterQuery(String::new()))
            } else {
                Ok(SlashAction::FilterQuery(rest.to_string()))
            }
        }
        "/layer" | "/cat" => Ok(SlashAction::CategoryLayer(rest.to_ascii_lowercase())),
        "/proven" => Ok(SlashAction::FilterStatus("proven")),
        "/critical" => Ok(SlashAction::FilterStatus("critical")),
        "/confirmed" => Ok(SlashAction::FilterStatus("confirmed")),
        "/all" => Ok(SlashAction::FilterStatus("all")),
        "/replay" => Ok(SlashAction::ReplaySelected),
        "/rescan" | "/scan" => Ok(SlashAction::Rescan),
        "/patch" => Ok(SlashAction::PatchSelected),
        "/apply-check" | "/apply" => Ok(SlashAction::ApplyCheck),
        "/baseline" | "/base" => {
            let op = if rest.is_empty() { "toggle" } else { rest };
            Ok(SlashAction::BaselineOp(op.to_ascii_lowercase()))
        }
        "/export" => {
            if rest.is_empty() {
                Err("Specify `/export sarif` or `/export html`.".to_string())
            } else {
                Ok(SlashAction::ExportFormat(rest.to_ascii_lowercase()))
            }
        }
        "/copy" | "/y" => Ok(SlashAction::CopySelected),
        "/edit" | "/e" => Ok(SlashAction::OpenEditor),
        "/logs" | "/log" => Ok(SlashAction::ToggleLogs),
        "/help" | "/?" => Ok(SlashAction::ToggleHelp),
        "/quit" | "/exit" | "/q" => Ok(SlashAction::Quit),
        other => Err(format!(
            "Unknown command `{}` — press `/` then `Tab` or `/help`.",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slash_autocomplete_ghost_and_parser() {
        let list = filter_slash_commands("/re");
        assert!(list.iter().any(|c| c.cmd == "/replay"));
        assert!(list.iter().any(|c| c.cmd == "/rescan"));

        let ghost = ghost_hint_for_input("/fi");
        assert_eq!(ghost.as_deref(), Some("ndings"));

        assert_eq!(complete_slash_input("/exp"), Some("/export ".to_string()));
        assert_eq!(
            parse_slash_command("/export sarif").unwrap(),
            SlashAction::ExportFormat("sarif".to_string())
        );
        assert_eq!(
            parse_slash_command("/baseline write").unwrap(),
            SlashAction::BaselineOp("write".to_string())
        );
        assert_eq!(
            parse_slash_command("/sandbox").unwrap(),
            SlashAction::Workspace(WorkspaceTab::Sandbox)
        );
    }
}
