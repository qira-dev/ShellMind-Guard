use crate::palette::{DetailTab, WorkspaceTab};
use serde::{Deserialize, Serialize};
use smg_graph::LatticeFinding;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const SESSION_REL_PATH: &str = ".shellmind-guard/tui-session.json";
const BASELINE_REL_PATH: &str = ".shellmind-guard/baseline.json";

/// Strictly non-executable UI preferences persisted across TUI runs.
/// Security Trust Boundary (`0.9946`): never stores or re-executes `boot_cmd`,
/// sandbox targets, or AI provider credentials from repo state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TuiSessionPrefs {
    pub workspace: String,
    pub filter_mode: String,
    pub category_filter: String,
    pub detail_tab: String,
    pub hide_baselined: bool,
}

impl Default for TuiSessionPrefs {
    fn default() -> Self {
        Self {
            workspace: "findings".to_string(),
            filter_mode: "all".to_string(),
            category_filter: "all".to_string(),
            detail_tab: "trace".to_string(),
            hide_baselined: false,
        }
    }
}

impl TuiSessionPrefs {
    pub fn parse_workspace(&self) -> WorkspaceTab {
        match self.workspace.as_str() {
            "overview" => WorkspaceTab::Overview,
            "sandbox" => WorkspaceTab::Sandbox,
            "rules" => WorkspaceTab::Rules,
            _ => WorkspaceTab::Findings,
        }
    }

    pub fn parse_detail_tab(&self) -> DetailTab {
        match self.detail_tab.as_str() {
            "proof" => DetailTab::ProofDiff,
            "rules" => DetailTab::RuleDocs,
            _ => DetailTab::TraceSource,
        }
    }
}

fn is_symlink_path(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

pub fn load_session_prefs(root: &Path) -> TuiSessionPrefs {
    let dir = root.join(".shellmind-guard");
    let path = root.join(SESSION_REL_PATH);
    if is_symlink_path(&dir) || is_symlink_path(&path) {
        return TuiSessionPrefs::default();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<TuiSessionPrefs>(&raw).ok())
        .unwrap_or_default()
}

pub fn save_session_prefs(root: &Path, prefs: &TuiSessionPrefs) {
    let dir = root.join(".shellmind-guard");
    let path = root.join(SESSION_REL_PATH);
    if is_symlink_path(&dir) || is_symlink_path(&path) {
        return;
    }
    if fs::create_dir_all(&dir).is_ok()
        && let Ok(json) = serde_json::to_string_pretty(prefs)
    {
        let _ = fs::write(path, json);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: String,
    pub entry_route: String,
    pub sink_symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineFile {
    pub version: u32,
    pub entries: Vec<BaselineEntry>,
}

pub fn finding_baseline_key(f: &LatticeFinding) -> BaselineEntry {
    let sink_symbol = f
        .witness_path
        .last()
        .map(|h| h.symbol.clone())
        .unwrap_or_default();
    BaselineEntry {
        rule_id: f.rule_id.clone(),
        file: f.file.clone(),
        entry_route: f.entry_route.clone(),
        sink_symbol,
    }
}

pub fn load_baseline_keys(root: &Path) -> HashSet<BaselineEntry> {
    let dir = root.join(".shellmind-guard");
    let path = root.join(BASELINE_REL_PATH);
    if is_symlink_path(&dir) || is_symlink_path(&path) {
        return HashSet::new();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<BaselineFile>(&raw).ok())
        .map(|bf| bf.entries.into_iter().collect())
        .unwrap_or_default()
}

pub fn write_baseline_file(root: &Path, findings: &[LatticeFinding]) -> io::Result<usize> {
    let dir = root.join(".shellmind-guard");
    let path = root.join(BASELINE_REL_PATH);
    if is_symlink_path(&dir) || is_symlink_path(&path) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Refusing to write baseline through symlinked path",
        ));
    }
    let mut entries: Vec<BaselineEntry> = findings.iter().map(finding_baseline_key).collect();
    entries.sort();
    entries.dedup();
    let count = entries.len();
    let file = BaselineFile {
        version: 1,
        entries,
    };
    fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(&file).map_err(io::Error::other)?;
    fs::write(path, json)?;
    Ok(count)
}

pub fn encode_base64(input: &[u8]) -> String {
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

/// Copies via OSC 52 (works over SSH/tmux, capped at 64 KiB) plus optional native clipboard helper fallback (`wl-copy`/`xclip`/`pbcopy`).
pub fn copy_clipboard(text: &str) -> io::Result<&'static str> {
    const MAX_OSC52_RAW_BYTES: usize = 65_536;
    let osc_slice = if text.len() > MAX_OSC52_RAW_BYTES {
        let mut cut = MAX_OSC52_RAW_BYTES;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    } else {
        text
    };
    let b64 = encode_base64(osc_slice.as_bytes());
    let mut stdout = io::stdout();
    write!(stdout, "\x1b]52;c;{}\x07", b64)?;
    stdout.flush()?;

    for (bin, args) in [
        ("wl-copy", &[][..]),
        ("xclip", &["-selection", "clipboard"][..]),
        ("pbcopy", &[][..]),
    ] {
        if let Ok(mut child) = Command::new(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().is_ok_and(|s| s.success()) {
                return Ok(bin);
            }
        }
    }
    Ok("OSC 52")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_session_prefs_and_baseline_roundtrip_without_exec_fields() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_tui_sess_{}", nanos));
        fs::create_dir_all(&tmp).unwrap();

        let prefs = TuiSessionPrefs {
            workspace: "sandbox".into(),
            filter_mode: "proven".into(),
            category_filter: "auth".into(),
            detail_tab: "rules".into(),
            hide_baselined: true,
        };
        save_session_prefs(&tmp, &prefs);
        let raw = fs::read_to_string(tmp.join(SESSION_REL_PATH)).unwrap();
        assert!(!raw.contains("boot_cmd"));
        let loaded = load_session_prefs(&tmp);
        assert_eq!(loaded, prefs);
        assert_eq!(loaded.parse_workspace(), WorkspaceTab::Sandbox);
        assert_eq!(loaded.parse_detail_tab(), DetailTab::RuleDocs);

        let _ = fs::remove_dir_all(&tmp);
    }
}
