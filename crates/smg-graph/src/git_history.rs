//! Zero-bloat streaming Git commit-history credential scanner (Gitleaks `git` parity).
//!
//! Streams `git log -p -U0 --full-history` line-by-line in O(1) memory, tracks exact
//! commit SHA, author, timestamp, file path, and added-line numbers, evaluates both
//! ShellMind-Guard's built-in 45+ provider secret catalog and `.gitleaks.toml` rules/allowlists,
//! and deduplicates identical leaked tokens across merge/cherry-pick commits.

use crate::ast::{Confidence, LocalStaticFinding};
use crate::gitleaks_config::{GitleaksConfig, has_inline_allow_marker};
use crate::secrets_config::{is_placeholder_secret, scan_secrets_and_config};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// An in-memory leaked credential candidate extracted for optional `--verify-live` checks.
/// NEVER serialized to disk, JSON, SARIF, or logs.
#[derive(Debug, Clone)]
pub struct SecretCandidate {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub commit_sha: Option<String>,
    pub raw_token: String,
    pub paired_secret: Option<String>,
}

#[derive(Debug, Default)]
pub struct GitHistoryScanResult {
    pub commits_scanned: usize,
    pub findings: Vec<LocalStaticFinding>,
    pub candidates: Vec<SecretCandidate>,
}

#[derive(Debug, Default, Clone)]
struct CommitMeta {
    sha: String,
    short_sha: String,
    author: String,
    date: String,
}

fn hunk_new_start_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@").expect("valid hunk re"))
}

/// Extracts raw provider-prefixed secret tokens from a single line for allowlist matching
/// and optional `--verify-live` verification.
pub fn extract_tokens_from_line(line: &str) -> Vec<String> {
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let re = TOKEN_RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            \b(
                (?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|
                (?:sk|rk)_live_[0-9A-Za-z_]{10,}|
                whsec_[0-9A-Za-z+/=_-]{24,}|
                gh[pousr]_[0-9A-Za-z]{16,}|
                github_pat_[0-9A-Za-z_]{16,}|
                gl(?:pat|dt|rt|ft)-[0-9A-Za-z_-]{20,}|
                sk-(?:proj|svcacct|admin)-[0-9A-Za-z_-]{20,}|
                sk-ant-(?:api|admin)[0-9A-Za-z_-]{20,}|
                xox[baprs]-[0-9A-Za-z-]{16,}|
                AIza[0-9A-Za-z_-]{35}|
                hf_[A-Za-z]{24,}|
                r8_[0-9A-Za-z]{24,}|
                gsk_[0-9A-Za-z]{40,}|
                sk-or-v1-[0-9a-f]{48,}|
                SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{20,}|
                do[por]_v1_[0-9a-f]{64}|
                lin_api_[0-9A-Za-z]{35,}|
                npm_[0-9A-Za-z]{30,}|
                PMAK-[0-9a-f]{24}-[0-9a-f]{34}|
                figd_[0-9A-Za-z_-]{35,}|
                ntn_[0-9A-Za-z]{40,}|
                vcp_[0-9A-Za-z]{20,}|
                nfp_[0-9A-Za-z]{32,}|
                rnd_[0-9A-Za-z]{24,}|
                sbp_[0-9a-f]{40}|
                xai-[0-9A-Za-z]{32,}|
                re_[0-9A-Za-z]{24,}|
                [0-9]{8,12}:AA[0-9A-Za-z_-]{33}
            )\b
            ",
        )
        .expect("valid token extract re")
    });
    re.captures_iter(line)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|t| !is_placeholder_secret(t))
        .collect()
}

/// Extracts a paired 40-char AWS Secret Access Key from nearby lines if present.
pub fn extract_aws_secret_near(lines: &[&str], center_idx: usize) -> Option<String> {
    static AWS_SEC_RE: OnceLock<Regex> = OnceLock::new();
    let re = AWS_SEC_RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:aws_secret_access_key|secret_access_key|secretAccessKey|aws_secret)[^A-Za-z0-9/+=]{1,8}([A-Za-z0-9/+=]{40})\b"#)
            .expect("valid aws secret re")
    });
    let start = center_idx.saturating_sub(4);
    let end = (center_idx + 5).min(lines.len());
    for line in &lines[start..end] {
        if let Some(c) = re.captures(line)
            && let Some(m) = c.get(1)
        {
            let val = m.as_str();
            if !is_placeholder_secret(val) {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn unquote_git_path(raw: &str) -> String {
    let inner = match raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(s) => s,
        None => return raw.to_string(),
    };
    let bytes = inner.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if i + 3 < bytes.len()
                && bytes[i + 1..i + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b))
                && let Ok(oct_str) = std::str::from_utf8(&bytes[i + 1..i + 4])
                && let Ok(v) = u8::from_str_radix(oct_str, 8)
            {
                out.push(v);
                i += 4;
                continue;
            }
            let esc = match bytes[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'"' => b'"',
                b'\\' => b'\\',
                other => other,
            };
            out.push(esc);
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn should_skip_history_path(rel_path: &str, include_tests: bool) -> bool {
    let norm = rel_path.replace('\\', "/");
    let fname = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if matches!(
        fname,
        "package-lock.json"
            | "Cargo.lock"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "go.sum"
            | "poetry.lock"
            | "composer.lock"
            | ".env.example"
            | ".env.sample"
            | ".env.template"
            | ".env.dist"
    ) {
        return true;
    }
    if norm.ends_with(".min.js")
        || norm.ends_with(".map")
        || norm.ends_with(".svg")
        || norm.ends_with(".png")
        || norm.ends_with(".jpg")
        || norm.ends_with(".woff2")
        || norm.ends_with(".pdf")
    {
        return true;
    }
    if !include_tests {
        let low = norm.to_ascii_lowercase();
        if low.starts_with("test/")
            || low.starts_with("tests/")
            || low.contains("/test/")
            || low.contains("/tests/")
            || low.contains("/__tests__/")
            || low.contains("/fixtures/")
            || low.contains("/testdata/")
        {
            return true;
        }
    }
    false
}

fn match_token_for_rule<'a>(rule_id: &str, tokens: &'a [String]) -> &'a str {
    if tokens.len() <= 1 {
        return tokens.first().map(String::as_str).unwrap_or("");
    }
    let pred: fn(&str) -> bool = match rule_id {
        "SMG-SEC-AWS" => |t| t.starts_with("AKIA") || t.starts_with("ASIA"),
        "SMG-SEC-GITHUB" => |t| {
            t.starts_with("ghp_")
                || t.starts_with("gho_")
                || t.starts_with("ghs_")
                || t.starts_with("github_pat_")
        },
        "SMG-SEC-STRIPE" => |t| t.starts_with("sk_live_") || t.starts_with("rk_live_"),
        "SMG-SEC-SLACK" => |t| t.starts_with("xox"),
        "SMG-SEC-OPENAI" => |t| t.starts_with("sk-"),
        "SMG-SEC-ANTHROPIC" => |t| t.starts_with("sk-ant-"),
        "SMG-SEC-GCP" => |t| t.starts_with("AIza"),
        _ => |_| false,
    };
    tokens
        .iter()
        .find(|t| pred(t.as_str()))
        .or_else(|| tokens.first())
        .map(String::as_str)
        .unwrap_or("")
}

/// Scans git commit history of `repo_root` by streaming `git log -p -U0`.
///
/// - `max_commits`: `None` or `Some(0)` scans full history; `Some(n)` limits to latest `n` commits.
/// - `gitleaks_cfg`: optional compiled `.gitleaks.toml` (allowlists + custom rules).
pub fn scan_git_history(
    repo_root: &Path,
    max_commits: Option<usize>,
    gitleaks_cfg: Option<&GitleaksConfig>,
    include_tests: bool,
) -> Result<GitHistoryScanResult> {
    if !repo_root.join(".git").exists() {
        return Ok(GitHistoryScanResult::default());
    }

    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .arg("log")
        .arg("-p")
        .arg("-U0")
        .arg("--no-color")
        .arg("--no-ext-diff")
        .arg("--full-history")
        .arg("--format=%x00SMG_COMMIT_HDR:%H%x00%aI%x00%an");

    if let Some(n) = max_commits
        && n > 0
    {
        cmd.arg(format!("-n{n}"));
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return Ok(GitHistoryScanResult::default()),
    };

    let Some(stdout) = child.stdout.take() else {
        let _ = child.wait();
        return Ok(GitHistoryScanResult::default());
    };

    let mut result = GitHistoryScanResult::default();
    let mut seen_fingerprints: HashSet<String> = HashSet::new();
    let mut cur_commit = CommitMeta::default();
    let mut cur_file = String::new();
    let mut skip_file = false;
    let mut skip_hunk = false;
    let mut cur_line: usize = 0;
    let mut recent_added: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(6);

    const MAX_HISTORY_LINE_BYTES: usize = 64 * 1024;
    let mut reader = BufReader::with_capacity(64 * 1024, stdout);
    let mut raw_buf = Vec::with_capacity(4096);
    loop {
        raw_buf.clear();
        let mut eof = false;
        let mut truncated = false;
        loop {
            let Ok(avail) = reader.fill_buf() else {
                eof = true;
                break;
            };
            if avail.is_empty() {
                eof = true;
                break;
            }
            if let Some(nl_pos) = avail.iter().position(|&b| b == b'\n') {
                let take = nl_pos;
                if !truncated {
                    let room = MAX_HISTORY_LINE_BYTES.saturating_sub(raw_buf.len());
                    raw_buf.extend_from_slice(&avail[..take.min(room)]);
                }
                reader.consume(nl_pos + 1);
                break;
            } else {
                let len = avail.len();
                if !truncated {
                    let room = MAX_HISTORY_LINE_BYTES.saturating_sub(raw_buf.len());
                    if len <= room {
                        raw_buf.extend_from_slice(avail);
                    } else {
                        raw_buf.extend_from_slice(&avail[..room]);
                        truncated = true;
                    }
                }
                reader.consume(len);
            }
        }
        if eof && raw_buf.is_empty() {
            break;
        }
        if raw_buf.ends_with(b"\r") {
            raw_buf.pop();
        }
        let line = String::from_utf8_lossy(&raw_buf);

        if let Some(rest) = line.strip_prefix("\0SMG_COMMIT_HDR:") {
            let mut parts = rest.splitn(3, '\0');
            let sha = parts.next().unwrap_or("").trim().to_string();
            let date = parts.next().unwrap_or("").trim().to_string();
            let author = parts.next().unwrap_or("unknown").trim().to_string();
            let short_sha = sha.chars().take(8).collect();
            cur_commit = CommitMeta {
                sha,
                short_sha,
                author,
                date,
            };
            result.commits_scanned += 1;
            cur_file.clear();
            recent_added.clear();
            skip_file = false;
            skip_hunk = false;
            continue;
        }

        if let Some(path_part) = line.strip_prefix("+++ b/") {
            cur_file = unquote_git_path(path_part.trim());
            skip_file = should_skip_history_path(&cur_file, include_tests);
            skip_hunk = false;
            continue;
        }
        if let Some(path_part) = line.strip_prefix("+++ \"b/") {
            let trimmed = path_part.trim();
            cur_file = unquote_git_path(&format!("\"{trimmed}"));
            skip_file = should_skip_history_path(&cur_file, include_tests);
            skip_hunk = false;
            continue;
        }
        if line.starts_with("+++ /dev/null") {
            cur_file.clear();
            skip_file = true;
            skip_hunk = false;
            continue;
        }
        if skip_file || cur_file.is_empty() {
            continue;
        }

        if line.starts_with("@@ ") {
            skip_hunk = false;
            if let Some(caps) = hunk_new_start_re().captures(&line)
                && let Some(m) = caps.get(1)
            {
                cur_line = m.as_str().parse::<usize>().unwrap_or(1);
            }
            if !include_tests {
                // Git places the enclosing function/module signature after the second `@@`.
                if let Some(ctx) = line.split("@@").nth(2) {
                    let low_ctx = ctx.to_ascii_lowercase();
                    if low_ctx.contains("mod tests")
                        || low_ctx.contains("fn test_")
                        || low_ctx.contains("def test_")
                        || low_ctx.contains("func test")
                        || low_ctx.contains("#[test]")
                    {
                        skip_hunk = true;
                    }
                }
            }
            continue;
        }
        if skip_hunk {
            continue;
        }

        // Only inspect added lines (skip `+++` headers already handled above)
        let Some(added) = line.strip_prefix('+') else {
            continue;
        };
        let line_no = cur_line.max(1);
        cur_line = cur_line.saturating_add(1);

        if added.trim().is_empty() || has_inline_allow_marker(added) {
            continue;
        }

        if recent_added.len() >= 5 {
            recent_added.pop_front();
        }
        recent_added.push_back(added.to_string());

        let extracted_tokens = extract_tokens_from_line(added);

        // 1. Run built-in secret rules on this added line
        let raw_hits = scan_secrets_and_config(&cur_file, added);
        for mut f in raw_hits {
            if !f.rule_id.starts_with("SMG-SEC-") {
                continue;
            }
            let primary_tok = match_token_for_rule(&f.rule_id, &extracted_tokens);
            if let Some(cfg) = gitleaks_cfg
                && (cfg.is_fingerprint_ignored(
                    Some(&cur_commit.sha),
                    &cur_file,
                    &f.rule_id,
                    line_no,
                ) || cfg.is_allowed(&cur_file, Some(&cur_commit.sha), added, primary_tok))
            {
                continue;
            }
            let fp_input = format!(
                "{}|{}|{}",
                f.rule_id,
                cur_file,
                if primary_tok.is_empty() {
                    added.trim()
                } else {
                    primary_tok
                }
            );
            let fp = blake3::hash(fp_input.as_bytes()).to_hex().to_string();
            if !seen_fingerprints.insert(fp) {
                continue;
            }

            f.line = line_no;
            f.confidence = Confidence::Confirmed;
            f.symbol = format!("git:{}", cur_commit.short_sha);
            f.title = format!(
                "[git-history {} | {} | {}] {}",
                cur_commit.short_sha, cur_commit.author, cur_commit.date, f.title
            );
            if !primary_tok.is_empty() {
                let paired_secret = if f.rule_id == "SMG-SEC-AWS" {
                    let window: Vec<&str> = recent_added.iter().map(String::as_str).collect();
                    extract_aws_secret_near(&window, window.len().saturating_sub(1))
                } else {
                    None
                };
                result.candidates.push(SecretCandidate {
                    rule_id: f.rule_id.clone(),
                    file: cur_file.clone(),
                    line: line_no,
                    commit_sha: Some(cur_commit.sha.clone()),
                    raw_token: primary_tok.to_string(),
                    paired_secret,
                });
            }
            result.findings.push(f);
        }

        // 2. Run custom `.gitleaks.toml` rules on this added line
        if let Some(cfg) = gitleaks_cfg {
            for (mut f, tok) in
                cfg.scan_custom_rules_line(&cur_file, line_no, added, Some(&cur_commit.sha))
            {
                let fp = blake3::hash(format!("{}|{}|{}", f.rule_id, cur_file, tok).as_bytes())
                    .to_hex()
                    .to_string();
                if !seen_fingerprints.insert(fp) {
                    continue;
                }
                f.symbol = format!("git:{}", cur_commit.short_sha);
                f.title = format!(
                    "[git-history {} | {} | {}] {}",
                    cur_commit.short_sha, cur_commit.author, cur_commit.date, f.title
                );
                result.findings.push(f);
            }
        }
    }

    let _ = child.wait();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_deleted_secret_in_git_history_and_respects_gitleaks_allowlist() {
        let tmp = std::env::temp_dir().join(format!("smg_githist_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let run_git = |args: &[&str]| {
            let st = Command::new("git")
                .current_dir(&tmp)
                .args(args)
                .env("GIT_AUTHOR_NAME", "TestDev")
                .env("GIT_AUTHOR_EMAIL", "dev@example.com")
                .env("GIT_COMMITTER_NAME", "TestDev")
                .env("GIT_COMMITTER_EMAIL", "dev@example.com")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("git");
            assert!(st.success(), "git {args:?} failed");
        };

        run_git(&["init", "-b", "main"]);
        // Commit 1: leak a real-shaped GitHub PAT (synthetic, high entropy)
        let fake_pat = ["ghp_", "9kLm2nPq7rSt4vWx8yZa3bCd6eFg1hIj5kLm"].concat();
        fs::write(
            tmp.join("config.py"),
            format!("GITHUB_TOKEN = \"{fake_pat}\"\n"),
        )
        .unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "initial commit with leaked token"]);

        // Capture commit 1 SHA
        let sha_out = Command::new("git")
            .current_dir(&tmp)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let commit1_sha = String::from_utf8_lossy(&sha_out.stdout).trim().to_string();

        // Commit 2: remove the leaked token from working tree!
        fs::write(
            tmp.join("config.py"),
            "GITHUB_TOKEN = os.environ['GITHUB_TOKEN']\n",
        )
        .unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "remove leaked token"]);

        // Without allowlist: git history scanner MUST catch the deleted secret!
        let res = scan_git_history(&tmp, None, None, false).unwrap();
        assert_eq!(res.commits_scanned, 2);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-SEC-GITHUB" && f.rel_path == "config.py"),
            "expected SMG-SEC-GITHUB in git history, got {:?}",
            res.findings
        );
        assert_eq!(res.candidates.len(), 1);
        assert_eq!(res.candidates[0].raw_token, fake_pat);

        // With `.gitleaks.toml` allowlisting commit1_sha: MUST suppress cleanly!
        let cfg =
            GitleaksConfig::parse_toml(&format!("[allowlist]\ncommits = [\"{commit1_sha}\"]\n"))
                .unwrap();
        let res2 = scan_git_history(&tmp, None, Some(&cfg), false).unwrap();
        assert!(
            res2.findings.is_empty(),
            "expected commit allowlist to suppress finding, got {:?}",
            res2.findings
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
