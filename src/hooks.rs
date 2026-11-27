#[allow(unused_imports)]
use crate::rules_catalog::{
    CompletionShell, RULE_CATALOG, find_rule_doc, render_shell_completions,
};
#[allow(unused_imports)]
use crate::*;
#[allow(unused_imports)]
use anyhow::{Context, Result};
#[allow(unused_imports)]
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
#[allow(unused_imports)]
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, export_regression_tests, generate_patch_plan,
    provider_from_config, run_cegis_patch_loop, synthesize_deterministic_codemod_diff,
    verify_patch_in_isolated_copy,
};
#[allow(unused_imports)]
use smg_core::{
    DeltaStats, ScanOptions, ShellMindGuardConfig, StateStore, scan_repository,
    scan_repository_with_options,
};
#[allow(unused_imports)]
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase_cached,
    analyze_codebase_cached_changed_since, collect_deep_schema_findings, collect_git_changed_files,
    compute_rule_telemetry, deps::extract_resolved_dependencies, finding_matches_layer,
};
#[allow(unused_imports)]
use smg_report::{to_cyclonedx_vex_json, to_html_graph, to_sarif_json};
#[allow(unused_imports)]
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, detect_sandbox_backend,
    verify_deep_fuzz_blocking_with_config, verify_deep_fuzz_in_sandbox,
    verify_finding_blocking_with_config, verify_findings_batch_blocking_with_config,
    verify_findings_in_sandbox_with_config,
};
#[allow(unused_imports)]
use smg_tui::{TuiLaunchConfig, run_tui};
#[allow(unused_imports)]
use std::collections::{HashMap, HashSet};
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::io::{IsTerminal, Write};
#[allow(unused_imports)]
use std::net::SocketAddr;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::process::{Command, ExitCode};
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::sync::atomic::Ordering;
#[allow(unused_imports)]
use std::time::{Duration, Instant};

pub(crate) fn write_ci_workflow(root: &Path) -> Result<PathBuf> {
    let wf_dir = root.join(".github").join("workflows");
    fs::create_dir_all(&wf_dir)?;
    let wf_path = wf_dir.join("shellmind-guard.yml");
    let content = r#"name: ShellMind Guard Security Gate

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  shellmind-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ShellMind Guard
        run: |
          curl -fsSL https://raw.githubusercontent.com/qira-dev/ShellMind-Guard/v1.5.5/install.sh -o install.sh
          bash install.sh --version v1.5.5
          echo "$HOME/.local/bin" >> $GITHUB_PATH
      - name: Run ShellMind Guard 6-Layer Scan (SARIF)
        run: smg scan . --format sarif --sarif shellmind-guard.sarif --ci
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shellmind-guard.sarif
"#;
    fs::write(&wf_path, content)?;
    Ok(wf_path)
}

/// Extract inner `$(...)` and backtick command substitutions from double-quoted shell strings
/// (POSIX executes these during argument expansion, unlike single-quoted literals).
pub(crate) fn extract_double_quoted_substitutions(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let ch = chars[i];
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if ch == '\\' {
            i += 2;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = true;
            i += 1;
            continue;
        }
        if ch == '"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_double && ch == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            let start = i + 2;
            let mut j = start;
            let mut depth = 1usize;
            let mut sub_sq = false;
            let mut sub_dq = false;
            while j < chars.len() && depth > 0 {
                let c = chars[j];
                if sub_sq {
                    if c == '\'' {
                        sub_sq = false;
                    }
                } else if c == '\\' {
                    j += 1;
                } else if sub_dq {
                    if c == '"' {
                        sub_dq = false;
                    }
                } else {
                    match c {
                        '\'' => sub_sq = true,
                        '"' => sub_dq = true,
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if j > start {
                out.push(chars[start..j].iter().collect());
            }
            i = j.saturating_add(1);
            continue;
        }
        if in_double && ch == '`' {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '`' {
                    break;
                }
                j += 1;
            }
            if j > start {
                out.push(chars[start..j].iter().collect());
            }
            i = j.saturating_add(1);
            continue;
        }
        i += 1;
    }
    out
}

pub(crate) fn split_shell_commands(cmd_str: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut cur_tokens: Vec<String> = Vec::new();
    let mut cur_tok = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let chars: Vec<char> = cmd_str.chars().collect();
    let mut i = 0usize;

    let flush_tok = |tok: &mut String, toks: &mut Vec<String>| {
        if !tok.is_empty() {
            toks.push(std::mem::take(tok));
        }
    };
    let flush_cmd = |toks: &mut Vec<String>, cmds: &mut Vec<Vec<String>>| {
        if !toks.is_empty() {
            cmds.push(std::mem::take(toks));
        }
    };

    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            cur_tok.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur_tok.push(ch);
            }
            i += 1;
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\'
                && i + 1 < chars.len()
                && matches!(chars[i + 1], '"' | '\\' | '$' | '`')
            {
                escaped = true;
            } else {
                cur_tok.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\\' => {
                // Only treat backslash as escape on Unix paths/shells if followed by shell meta/space
                if i + 1 < chars.len()
                    && matches!(
                        chars[i + 1],
                        ' ' | '\t' | '"' | '\'' | ';' | '&' | '|' | '(' | ')' | '`' | '\\'
                    )
                {
                    escaped = true;
                } else {
                    cur_tok.push(ch);
                }
            }
            '\'' => in_single = true,
            '"' => in_double = true,
            ' ' | '\t' | '\r' => flush_tok(&mut cur_tok, &mut cur_tokens),
            ';' | '\n' | '(' | ')' | '`' => {
                flush_tok(&mut cur_tok, &mut cur_tokens);
                flush_cmd(&mut cur_tokens, &mut commands);
            }
            '&' | '|' => {
                flush_tok(&mut cur_tok, &mut cur_tokens);
                flush_cmd(&mut cur_tokens, &mut commands);
                if i + 1 < chars.len() && chars[i + 1] == ch {
                    i += 1;
                }
            }
            _ => cur_tok.push(ch),
        }
        i += 1;
    }
    flush_tok(&mut cur_tok, &mut cur_tokens);
    flush_cmd(&mut cur_tokens, &mut commands);
    commands
}

pub(crate) fn parse_git_commit_invocation(cmd_str: &str) -> Option<PathBuf> {
    parse_git_commit_invocation_bounded(cmd_str, 0)
}

pub(crate) fn resolve_cd_relative(current_cd: Option<&PathBuf>, inner_path: PathBuf) -> PathBuf {
    match (current_cd, inner_path) {
        (Some(cd), p) if p == Path::new(".") => cd.clone(),
        (Some(cd), p) if p.is_relative() => cd.join(p),
        (_, p) => p,
    }
}

pub(crate) fn git_dir_arg_to_worktree(arg: &str) -> PathBuf {
    let p = Path::new(arg);
    if p.file_name().and_then(|n| n.to_str()) == Some(".git") {
        let parent = p.parent().unwrap_or_else(|| Path::new(""));
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    } else {
        p.to_path_buf()
    }
}

pub(crate) fn parse_git_commit_invocation_bounded(cmd_str: &str, depth: usize) -> Option<PathBuf> {
    if depth > 4 {
        return None;
    }
    let mut current_cd: Option<PathBuf> = None;
    let dq_subs = extract_double_quoted_substitutions(cmd_str);
    for mut tokens in split_shell_commands(cmd_str) {
        while let Some(first) = tokens.first().cloned() {
            let is_env_assign = first.contains('=')
                && !first.starts_with('-')
                && !first.starts_with('/')
                && !first.starts_with('.');
            let first_norm = first.replace('\\', "");
            if is_env_assign {
                if let Some(wt) = first.strip_prefix("GIT_WORK_TREE=")
                    && !wt.is_empty()
                {
                    current_cd = Some(PathBuf::from(wt));
                }
                tokens.remove(0);
            } else if matches!(
                first_norm.as_str(),
                "sudo" | "env" | "command" | "nohup" | "$" | "&"
            ) {
                tokens.remove(0);
                // Consume wrapper options like `env -i`, `env -u VAR`, `sudo -E`, `sudo -u user`, `command -p`
                while let Some(opt) = tokens.first().cloned() {
                    if opt == "--" {
                        tokens.remove(0);
                        break;
                    }
                    if let Some(dir_val) = opt.strip_prefix("--chdir=") {
                        tokens.remove(0);
                        if !dir_val.is_empty() {
                            let next = PathBuf::from(dir_val);
                            current_cd = Some(match current_cd.take() {
                                Some(base) if next.is_relative() => base.join(next),
                                _ => next,
                            });
                        }
                    } else if matches!(opt.as_str(), "-C" | "--chdir") {
                        tokens.remove(0);
                        if !tokens.is_empty() {
                            let next = PathBuf::from(tokens.remove(0));
                            current_cd = Some(match current_cd.take() {
                                Some(base) if next.is_relative() => base.join(next),
                                _ => next,
                            });
                        }
                    } else if matches!(opt.as_str(), "-u" | "-g" | "--unset") {
                        tokens.remove(0);
                        if !tokens.is_empty() {
                            tokens.remove(0);
                        }
                    } else if opt.starts_with('-') && opt.len() > 1 {
                        tokens.remove(0);
                    } else {
                        break;
                    }
                }
            } else {
                break;
            }
        }
        let Some(cmd_clean) = tokens.first().map(|s| s.as_str()) else {
            continue;
        };
        let cmd_norm = cmd_clean.replace('\\', "").to_ascii_lowercase();
        if matches!(
            cmd_norm.as_str(),
            "cd" | "pushd" | "set-location" | "push-location" | "sl"
        ) {
            if let Some(dir_clean) = tokens
                .iter()
                .skip(1)
                .find(|arg| !arg.is_empty() && !arg.starts_with('-'))
            {
                current_cd = Some(PathBuf::from(dir_clean));
            }
            continue;
        }
        // Unwrap nested shell / eval invocations (`sh -c "git commit ..."`, `bash -lc "..."`, `eval "git commit ..."`)
        let is_shell_wrapper = matches!(
            cmd_norm.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "/bin/sh" | "/bin/bash" | "/bin/zsh"
        );
        if is_shell_wrapper {
            let mut idx = 1usize;
            while idx < tokens.len() {
                let tok = &tokens[idx];
                if (tok == "-c"
                    || (tok.starts_with('-') && !tok.starts_with("--") && tok.ends_with('c')))
                    && let Some(inner_cmd) = tokens.get(idx + 1)
                    && let Some(inner_path) =
                        parse_git_commit_invocation_bounded(inner_cmd, depth + 1)
                {
                    return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
                }
                idx += 1;
            }
            continue;
        }
        if cmd_norm == "eval" && tokens.len() > 1 {
            let joined = tokens[1..].join(" ");
            if let Some(inner_path) = parse_git_commit_invocation_bounded(&joined, depth + 1) {
                return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
            }
            continue;
        }
        let unix_base = cmd_clean.rsplit('/').next().unwrap_or(cmd_clean);
        let unix_base_norm = unix_base.replace('\\', "");
        let is_git = (!cmd_clean.contains(':')
            && matches!(
                unix_base_norm.to_ascii_lowercase().as_str(),
                "git" | "git.exe"
            ))
            || cmd_clean.ends_with("/git")
            || cmd_clean.ends_with("\\git")
            || cmd_clean.ends_with("/git.exe")
            || cmd_clean.ends_with("\\git.exe");
        if !is_git {
            continue;
        }

        let mut git_dir_override: Option<PathBuf> = None;
        let mut git_worktree_explicit = false;
        let mut commit_aliases: Vec<String> = Vec::new();
        let mut subcmd: Option<String> = None;
        let mut i = 1usize;
        while i < tokens.len() {
            let t = tokens[i].as_str();
            let t_norm = t.replace('\\', "");
            if matches!(t_norm.as_str(), "-C" | "--work-tree") {
                if let Some(clean_dir) = tokens.get(i + 1) {
                    let next = PathBuf::from(clean_dir);
                    git_dir_override = Some(match (git_dir_override, next.is_relative()) {
                        (Some(prev), true) if t_norm == "-C" => prev.join(next),
                        _ => next,
                    });
                    if t_norm == "--work-tree" {
                        git_worktree_explicit = true;
                    }
                }
                i += 2;
                continue;
            }
            if let Some(rest) = t.strip_prefix("-C").filter(|r| !r.is_empty()) {
                let next = PathBuf::from(rest);
                git_dir_override = Some(match (git_dir_override, next.is_relative()) {
                    (Some(prev), true) => prev.join(next),
                    _ => next,
                });
                i += 1;
                continue;
            }
            if let Some(rest) = t.strip_prefix("--work-tree=").filter(|r| !r.is_empty()) {
                git_dir_override = Some(PathBuf::from(rest));
                git_worktree_explicit = true;
                i += 1;
                continue;
            }
            if t_norm == "--git-dir" {
                if let Some(gd) = tokens.get(i + 1)
                    && !git_worktree_explicit
                    && git_dir_override.is_none()
                {
                    git_dir_override = Some(git_dir_arg_to_worktree(gd));
                }
                i += 2;
                continue;
            }
            if let Some(rest) = t.strip_prefix("--git-dir=").filter(|r| !r.is_empty()) {
                if !git_worktree_explicit && git_dir_override.is_none() {
                    git_dir_override = Some(git_dir_arg_to_worktree(rest));
                }
                i += 1;
                continue;
            }
            if t_norm == "-c" {
                if let Some(kv) = tokens.get(i + 1)
                    && let Some((k, v)) = kv.split_once('=')
                    && let Some(alias_name) = k.strip_prefix("alias.")
                {
                    let v_trimmed = v.trim();
                    let target = v_trimmed.split_whitespace().next().unwrap_or("");
                    if matches!(target, "commit" | "ci")
                        || v_trimmed.strip_prefix('!').is_some_and(|shell_cmd| {
                            parse_git_commit_invocation_bounded(shell_cmd, depth + 1).is_some()
                        })
                    {
                        commit_aliases.push(alias_name.to_string());
                    }
                }
                i += 2;
                continue;
            }
            if let Some(kv) = t_norm.strip_prefix("-c").filter(|r| !r.is_empty()) {
                if let Some((k, v)) = kv.split_once('=')
                    && let Some(alias_name) = k.strip_prefix("alias.")
                {
                    let v_trimmed = v.trim();
                    let target = v_trimmed.split_whitespace().next().unwrap_or("");
                    if matches!(target, "commit" | "ci")
                        || v_trimmed.strip_prefix('!').is_some_and(|shell_cmd| {
                            parse_git_commit_invocation_bounded(shell_cmd, depth + 1).is_some()
                        })
                    {
                        commit_aliases.push(alias_name.to_string());
                    }
                }
                i += 1;
                continue;
            }
            if matches!(
                t_norm.as_str(),
                "--namespace" | "--exec-path" | "--super-prefix" | "--config-env" | "--list-cmds"
            ) {
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            subcmd = Some(t_norm);
            break;
        }

        if let Some(ref sc) = subcmd
            && (matches!(sc.as_str(), "commit" | "ci") || commit_aliases.iter().any(|a| a == sc))
        {
            let resolved = match (&current_cd, git_dir_override) {
                (Some(cd), Some(ov)) if ov.is_relative() => cd.join(ov),
                (_, Some(ov)) => ov,
                (Some(cd), None) => cd.clone(),
                (None, None) => PathBuf::from("."),
            };
            return Some(resolved);
        }
    }
    for sub in dq_subs {
        if let Some(inner_path) = parse_git_commit_invocation_bounded(&sub, depth + 1) {
            return Some(resolve_cd_relative(current_cd.as_ref(), inner_path));
        }
    }
    None
}

pub(crate) fn dir_has_git_marker(dir: &Path) -> bool {
    dir.ancestors().any(|a| a.join(".git").exists())
}

pub(crate) fn filter_trusted_hook_cwd<'a>(
    target_repo: &Path,
    hook_cwd: Option<&'a Path>,
    process_cwd: Option<&Path>,
) -> Option<&'a Path> {
    match hook_cwd {
        Some(h_cwd)
            if target_repo == Path::new(".")
                && (!h_cwd.exists() || !dir_has_git_marker(h_cwd))
                && process_cwd.is_some_and(dir_has_git_marker) =>
        {
            None
        }
        other => other,
    }
}

pub(crate) fn resolve_hook_scan_path(
    target_repo: &Path,
    hook_cwd: Option<&Path>,
) -> Option<PathBuf> {
    if target_repo == Path::new(".") {
        let base = hook_cwd.unwrap_or_else(|| Path::new("."));
        return base.exists().then(|| base.to_path_buf());
    }
    let candidate = if target_repo.is_relative() {
        if let Some(cwd) = hook_cwd {
            cwd.join(target_repo)
        } else {
            target_repo.to_path_buf()
        }
    } else {
        target_repo.to_path_buf()
    };
    candidate.exists().then_some(candidate)
}

pub(crate) fn handle_claude_pre_commit() -> Result<ExitCode> {
    use std::io::Read;
    const MAX_HOOK_STDIN_BYTES: u64 = 1024 * 1024;
    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_HOOK_STDIN_BYTES + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!(
            "[ShellMind Guard] Failed reading hook stdin (failing closed): {}",
            e
        );
        return Ok(ExitCode::from(2));
    }
    if raw_bytes.len() as u64 > MAX_HOOK_STDIN_BYTES {
        eprintln!(
            "[ShellMind Guard] Hook stdin exceeded {} byte limit (failing closed)",
            MAX_HOOK_STDIN_BYTES
        );
        return Ok(ExitCode::from(2));
    }
    let stdin_buf = match String::from_utf8(raw_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[ShellMind Guard] Invalid UTF-8 hook payload on stdin (failing closed): {}",
                e
            );
            return Ok(ExitCode::from(2));
        }
    };
    let payload_opt = match serde_json::from_str::<serde_json::Value>(&stdin_buf) {
        Ok(v) => Some(v),
        Err(e) => {
            if !stdin_buf.trim().is_empty() {
                eprintln!(
                    "[ShellMind Guard] Invalid hook JSON payload on stdin (failing closed): {}",
                    e
                );
                return Ok(ExitCode::from(2));
            }
            None
        }
    };

    let is_antigravity = payload_opt
        .as_ref()
        .is_some_and(|v| v.get("toolCall").is_some() && v.get("tool_input").is_none());

    let cmd_str = payload_opt
        .as_ref()
        .and_then(|v| {
            v.get("tool_input")
                .and_then(|ti| ti.get("command"))
                .and_then(|c| c.as_str())
                .or_else(|| {
                    v.get("toolCall")
                        .and_then(|tc| tc.get("args"))
                        .and_then(|a| a.get("CommandLine"))
                        .and_then(|c| c.as_str())
                })
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let hook_cwd = payload_opt.as_ref().and_then(|v| {
        v.get("cwd")
            .and_then(|c| c.as_str())
            .or_else(|| {
                v.get("workspacePaths")
                    .and_then(|wp| wp.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|s| s.as_str())
            })
            .map(PathBuf::from)
    });

    let Some(target_repo) = parse_git_commit_invocation(&cmd_str)
        .or_else(|| parse_git_commit_invocation(&cmd_str.replace('`', "")))
    else {
        if is_antigravity {
            println!("{}", serde_json::json!({ "decision": "allow" }));
        }
        return Ok(ExitCode::SUCCESS);
    };
    let proc_cwd = std::env::current_dir().ok();
    let effective_cwd =
        filter_trusted_hook_cwd(&target_repo, hook_cwd.as_deref(), proc_cwd.as_deref());
    let Some(scan_path) = resolve_hook_scan_path(&target_repo, effective_cwd) else {
        if is_antigravity {
            println!("{}", serde_json::json!({ "decision": "allow" }));
        }
        return Ok(ExitCode::SUCCESS);
    };

    // F7A-02: When `git commit` is invoked WITHOUT `-a` / `--all`, materialize the staged
    // git index into a private temporary directory (`git checkout-index --all --prefix=...`)
    // with an RAII cleanup guard so unstaged edits never mask staged secrets (or vice versa).
    struct StageCleanupGuard(PathBuf);
    impl Drop for StageCleanupGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let commit_stages_all = cmd_str.split_whitespace().any(|tok| {
        tok == "-a" || tok == "--all" || tok.starts_with("-am") || tok.starts_with("-a")
    });
    let mut _stage_guard: Option<StageCleanupGuard> = None;
    let effective_scan_path = if !commit_stages_all && scan_path.join(".git").exists() {
        let stage_dir = std::env::temp_dir().join(format!(
            "smg-staged-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if fs::create_dir_all(&stage_dir).is_ok() {
            let prefix = format!("{}/", stage_dir.to_string_lossy().trim_end_matches('/'));
            let ok = Command::new("git")
                .current_dir(&scan_path)
                .args(["checkout-index", "--all", "--force", "--prefix", &prefix])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                _stage_guard = Some(StageCleanupGuard(stage_dir.clone()));
                stage_dir
            } else {
                let _ = fs::remove_dir_all(&stage_dir);
                scan_path.clone()
            }
        } else {
            scan_path.clone()
        }
    } else {
        scan_path.clone()
    };

    let layers = vec!["secrets".to_string(), "config".to_string()];
    let outcome = execute_scan_pipeline(ScanRunOptions {
        path: &effective_scan_path,
        layers: &layers,
        min_confidence: None,
        boot_cmd: None,
        port: 39911,
        sync_race: 12,
        unsafe_host_fallback: false,
        trust_repo_config: false,
        deep: false,
        deep_audit: false,
        sandbox_mem_mb: None,
        sandbox_tls: false,
        mock_shims: false,
        cgroup_v2: false,
    })?;

    if should_fail_gate(&outcome.graph.findings, true, None) {
        if is_antigravity {
            let summary = outcome
                .graph
                .findings
                .iter()
                .take(5)
                .map(|f| format!("[{}] {} ({}:{})", f.severity, f.id, f.file, f.line))
                .collect::<Vec<_>>()
                .join("; ");
            let reason = format!(
                "[ShellMind Guard] Blocked git commit: {} secret/config issue(s) found ({}).",
                outcome.graph.findings.len(),
                summary
            );
            println!(
                "{}",
                serde_json::json!({
                    "decision": "deny",
                    "reason": reason
                })
            );
            return Ok(ExitCode::SUCCESS);
        }
        eprintln!(
            "[ShellMind Guard] Blocked git commit: {} secret/config issue(s) found.",
            outcome.graph.findings.len()
        );
        for f in &outcome.graph.findings {
            eprintln!(
                "  [{}] {} -> {} ({}:{})",
                f.severity, f.id, f.title, f.file, f.line
            );
        }
        return Ok(ExitCode::from(2));
    }
    if is_antigravity {
        println!("{}", serde_json::json!({ "decision": "allow" }));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) const HOOK_START: &str = "# >>> shellmind-guard pre-commit >>>";
pub(crate) const HOOK_END: &str = "# <<< shellmind-guard pre-commit <<<";

pub(crate) fn resolve_git_hooks_dir(root: &Path) -> Result<PathBuf> {
    if let Ok(out) = std::process::Command::new("git")
        .args([
            "-C",
            &root.to_string_lossy(),
            "rev-parse",
            "--git-path",
            "hooks",
        ])
        .output()
        && out.status.success()
    {
        let rel = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !rel.is_empty() {
            let p = PathBuf::from(&rel);
            return Ok(if p.is_absolute() { p } else { root.join(p) });
        }
    }
    let git_dir = root.join(".git");
    if !git_dir.exists() {
        anyhow::bail!(
            "Not a git repository ({} has no .git directory)",
            root.display()
        );
    }
    Ok(git_dir.join("hooks"))
}

pub(crate) fn install_git_hook(root: &Path) -> Result<PathBuf> {
    let git_meta = root.join(".git");
    if let Ok(m) = fs::symlink_metadata(&git_meta)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to install git hook through symlinked .git path: {}",
            git_meta.display()
        );
    }
    let hooks_dir = resolve_git_hooks_dir(root)?;
    if let Ok(m) = fs::symlink_metadata(&hooks_dir)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to install git hook through symlinked hooks directory: {}",
            hooks_dir.display()
        );
    }
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    if let Ok(m) = fs::symlink_metadata(&hook_path)
        && m.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to overwrite symlinked pre-commit hook: {}",
            hook_path.display()
        );
    }
    let exe_fallback = std::env::current_exe()
        .ok()
        .filter(|p| {
            let s = p.to_string_lossy();
            !s.contains("/target/") && !s.contains("\\target\\") && !s.contains("/deps/")
        })
        .map(|p| {
            let quoted = p.to_string_lossy().replace('\'', "'\\''");
            format!(" '{}'", quoted)
        })
        .unwrap_or_default();
    let block = format!(
        "{}\nSMG_BIN=\"$(command -v smg 2>/dev/null || command -v shellmind-guard 2>/dev/null || true)\"\nif [ -z \"$SMG_BIN\" ]; then\n  for cand in \"$HOME/.local/bin/smg\" \"$HOME/.local/bin/shellmind-guard\" \"$HOME/.cargo/bin/smg\" \"$HOME/.cargo/bin/shellmind-guard\" \"/usr/local/bin/smg\" \"/usr/local/bin/shellmind-guard\" \"/opt/homebrew/bin/smg\" \"/opt/homebrew/bin/shellmind-guard\"{exe_fallback}; do\n    if [ -x \"$cand\" ]; then\n      SMG_BIN=\"$cand\"\n      break\n    fi\n  done\nfi\nif [ -n \"$SMG_BIN\" ]; then\n  SMG_STAGE=\"$(mktemp -d \"${{TMPDIR:-/tmp}}/smg-stage.XXXXXX\" 2>/dev/null || true)\"\n  if [ -n \"$SMG_STAGE\" ] && git checkout-index --all --force --prefix=\"$SMG_STAGE/\" 2>/dev/null; then\n    trap 'rm -rf \"$SMG_STAGE\"' EXIT\n    \"$SMG_BIN\" scan \"$SMG_STAGE\" --layers secrets,config --ci\n  else\n    [ -n \"$SMG_STAGE\" ] && rm -rf \"$SMG_STAGE\"\n    \"$SMG_BIN\" scan . --layers secrets,config --ci\n  fi\nelse\n  echo \"[ShellMind Guard] warning: smg/shellmind-guard binary not found in PATH; skipping pre-commit scan\" >&2\nfi\n{}\n",
        HOOK_START, HOOK_END
    );

    let updated = if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)?;
        if existing.contains(HOOK_START) {
            existing
        } else if existing.ends_with('\n') {
            format!("{}\n{}", existing, block)
        } else {
            format!("{}\n\n{}", existing, block)
        }
    } else {
        format!("#!/usr/bin/env bash\nset -e\n\n{}", block)
    };

    fs::write(&hook_path, updated)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(hook_path)
}

pub(crate) fn uninstall_git_hook(root: &Path) -> Result<bool> {
    let Ok(hooks_dir) = resolve_git_hooks_dir(root) else {
        return Ok(false);
    };
    let hook_path = hooks_dir.join("pre-commit");
    if !hook_path.exists() {
        return Ok(false);
    }
    let existing = fs::read_to_string(&hook_path)?;
    let Some(start_idx) = existing.find(HOOK_START) else {
        return Ok(false);
    };
    let Some(rel_end) = existing[start_idx..].find(HOOK_END) else {
        anyhow::bail!(
            "Found {} without matching {}; refusing partial hook edit",
            HOOK_START,
            HOOK_END
        );
    };
    let end_idx = start_idx + rel_end + HOOK_END.len();
    let before = existing[..start_idx].trim_end();
    let after = existing[end_idx..].trim_start();
    let remaining = match (before.is_empty(), after.is_empty()) {
        (true, true) => String::new(),
        (false, true) => before.to_string(),
        (true, false) => after.to_string(),
        (false, false) => format!("{}\n{}", before, after),
    };
    let trimmed = remaining.trim();
    if trimmed.is_empty()
        || trimmed == "#!/usr/bin/env bash\nset -e"
        || trimmed == "#!/usr/bin/env bash"
        || trimmed == "#!/bin/sh"
    {
        fs::remove_file(&hook_path)?;
    } else {
        fs::write(&hook_path, format!("{}\n", trimmed))?;
    }
    Ok(true)
}

pub(crate) fn git_hook_status(root: &Path) -> bool {
    let Ok(hooks_dir) = resolve_git_hooks_dir(root) else {
        return false;
    };
    let hook_path = hooks_dir.join("pre-commit");
    fs::read_to_string(hook_path)
        .map(|s| s.contains(HOOK_START))
        .unwrap_or(false)
}

pub(crate) fn binary_on_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exe_name = if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(&exe_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

pub(crate) fn run_doctor(path: &Path, probe_ai: bool) {
    println!(
        "ShellMind Guard (smg) Doctor | v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let backend = detect_sandbox_backend();
    let bwrap_ok = smg_sandbox::has_bwrap();
    println!("  Sandbox Backend : {}", backend.label());
    println!(
        "  Sandbox (bwrap) : {}",
        if bwrap_ok {
            "OK (bwrap available; --unshare-all netns isolation active)"
        } else {
            "UNAVAILABLE (static scan, TUI, SARIF & MCP work; fallback sandbox uses host loopback if authorized)"
        }
    );
    let systemd_status = match Command::new("systemd-run")
        .args(["--user", "--version"])
        .output()
    {
        Ok(out) if out.status.success() => {
            "OK (systemd-run --user available for --cgroup-v2)".to_string()
        }
        _ => "unavailable (falling back to RLIMIT_AS memory bounds)".to_string(),
    };
    println!("  cgroups v2      : {}", systemd_status);
    let git_status = match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "NOT FOUND".to_string(),
    };
    println!("  Git CLI         : {}", git_status);
    let cfg_exists = path.join(".shellmind-guard.toml").exists();
    println!(
        "  Config          : {}",
        if cfg_exists {
            ".shellmind-guard.toml present"
        } else {
            "using built-in defaults (run `smg init` to customize)"
        }
    );
    let osv_db = smg_core::default_advisories_db_path();
    let osv_status = if osv_db.exists() {
        match smg_core::AdvisoryStore::open_at(&osv_db, true).and_then(|s| s.stats()) {
            Ok((total, _)) => format!("{} ({} cached advisories)", osv_db.display(), total),
            Err(_) => format!("{} (unreadable)", osv_db.display()),
        }
    } else {
        format!(
            "not initialized ({}; run `smg deps sync`)",
            osv_db.display()
        )
    };
    println!("  Offline OSV DB  : {}", osv_status);
    println!(
        "  Git Pre-Commit  : {}",
        if git_hook_status(path) {
            "ACTIVE"
        } else {
            "not installed (run `smg hook install` for zero-AI commit protection)"
        }
    );
    let smg_on_path = binary_on_path("smg");
    let legacy_on_path = binary_on_path("shellmind-guard");
    let has_plugin = path.join(".claude-plugin").join("plugin.json").exists();
    let has_mcp = path.join(".mcp.json").exists();
    let path_summary = match (&smg_on_path, &legacy_on_path) {
        (Some(p1), Some(p2)) => format!("smg={} · shellmind-guard={}", p1.display(), p2.display()),
        (Some(p1), None) => format!("smg={} (shellmind-guard not on PATH)", p1.display()),
        (None, Some(p2)) => format!("shellmind-guard={} (install `smg` alias)", p2.display()),
        (None, None) => "NEITHER `smg` NOR `shellmind-guard` on PATH".to_string(),
    };
    println!(
        "  CLI / Plugin    : {}{}",
        path_summary,
        if has_plugin || has_mcp {
            format!(" [plugin_manifest={}, mcp_config={}]", has_plugin, has_mcp)
        } else {
            String::new()
        }
    );
    if probe_ai {
        match ShellMindGuardConfig::load_trusted_from_dir(path, false) {
            Ok(cfg) => {
                if !cfg.ai.is_enabled() {
                    println!(
                        "  AI Provider     : disabled (zero network calls; configure [ai] in .shellmind-guard.toml)"
                    );
                } else {
                    match provider_from_config(&cfg.ai) {
                        Ok(smg_ai::AiProvider::Ollama { endpoint, model }) => {
                            let ping_url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
                            if let Err(e) = idor_audit::validate_live_target_url(&ping_url, false) {
                                println!(
                                    "  AI Provider     : Ollama endpoint rejected ({}): {}",
                                    endpoint, e
                                );
                            } else {
                                idor_audit::ensure_rustls_ring_provider();
                                let probe_res = reqwest::blocking::Client::builder()
                                    .redirect(reqwest::redirect::Policy::none())
                                    .timeout(std::time::Duration::from_secs(2))
                                    .build()
                                    .and_then(|c| c.get(&ping_url).send());
                                match probe_res {
                                    Ok(r) if r.status().is_success() => println!(
                                        "  AI Provider     : Ollama reachable ({}) · model={}",
                                        endpoint, model
                                    ),
                                    Ok(r) => println!(
                                        "  AI Provider     : Ollama HTTP {} at {} · model={}",
                                        r.status(),
                                        endpoint,
                                        model
                                    ),
                                    Err(e) => println!(
                                        "  AI Provider     : Ollama unreachable at {} ({})",
                                        endpoint, e
                                    ),
                                }
                            }
                        }
                        Ok(other) => {
                            let env_set = std::env::var_os(&cfg.ai.api_key_env)
                                .is_some_and(|v| !v.is_empty());
                            println!(
                                "  AI Provider     : {:?} · endpoint={} · model={} · {}={}",
                                other,
                                cfg.ai.endpoint,
                                cfg.ai.model,
                                cfg.ai.api_key_env,
                                if env_set { "SET" } else { "UNSET" }
                            );
                        }
                        Err(e) => println!("  AI Provider     : invalid config ({})", e),
                    }
                }
            }
            Err(e) => println!("  AI Provider     : failed loading config ({})", e),
        }
    }
}
