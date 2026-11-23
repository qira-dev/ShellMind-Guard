pub mod codemods;
pub mod semantic_patcher;

use anyhow::{Context, Result, bail};
pub use codemods::{
    CegisOutcome, GeneratedRegressionTest, export_regression_tests, generate_regression_test,
    run_cegis_patch_loop, synthesize_deterministic_codemod_diff, verify_diff_syntax_before_sandbox,
};
pub use semantic_patcher::{
    VerifyFixOutcome, apply_patch_and_verify_fix, synthesize_16lang_multi_hunk_patch,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use smg_core::{ShellMindGuardConfig, scan_repository};
use smg_graph::{GuardKind, LatticeFinding, analyze_codebase, collect_deep_schema_findings};
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, verify_findings_in_sandbox_with_config,
};
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_PROMPT_BYTES: usize = 2048;
const DEFAULT_AI_TIMEOUT_SECS: u64 = 45;
static RUSTLS_INIT: Once = Once::new();

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum AiProvider {
    #[default]
    Disabled,
    Ollama {
        endpoint: String,
        model: String,
    },
    OpenAiCompatible {
        endpoint: String,
        model: String,
        api_key_env: String,
    },
}

/// Extracts ONLY ±6/+10 lines around each hop in a witness path, strictly contained
/// within `project_root` (blocking symlinks escaping root) and capped at <= 2048 bytes.
pub fn build_minimal_patch_prompt(
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
) -> Result<String> {
    let canon_root = fs::canonicalize(project_root)?;
    let status_label = match verified.map(|v| &v.status) {
        Some(VerificationStatus::Proven) => "PROVEN",
        Some(VerificationStatus::Mitigated) => "MITIGATED",
        _ => "SUSPECT",
    };

    let mut prompt = String::new();
    prompt.push_str(&format!(
        "Fix this {} multi-file finding with a minimal unified diff.\nRule: {} ({})\nTitle: {}\nEntry: {}\n",
        status_label, finding.id, finding.rule_id, finding.title, finding.entry_route
    ));

    if let Some(v) = verified {
        prompt.push_str(&format!("Sandbox Evidence: {}\n", v.evidence));
    }
    if !finding.remediation.is_empty() {
        prompt.push_str(&format!("Remediation: {}\n", finding.remediation));
    }

    prompt.push_str("\nRelevant Witness Hops:\n");
    for (idx, hop) in finding.witness_path.iter().enumerate() {
        let joined = canon_root.join(&hop.file);
        let snippet = match fs::canonicalize(&joined) {
            Ok(canon_file) if canon_file.starts_with(&canon_root) => {
                if let Ok(raw) = fs::read_to_string(&canon_file) {
                    let lines: Vec<&str> = raw.lines().collect();
                    let start = hop.line.saturating_sub(4).max(1);
                    let end = hop.line.saturating_add(6).min(lines.len());
                    (start..=end)
                        .map(|ln| {
                            format!("{:>4} | {}", ln, lines.get(ln - 1).copied().unwrap_or(""))
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    "<file unreadable>".to_string()
                }
            }
            Ok(_) => "<blocked: path escapes project root>".to_string(),
            Err(_) => "<file missing>".to_string(),
        };

        let block = format!(
            "\n--- Hop [{}] {}:{} ({}) ---\n{}\n",
            idx + 1,
            hop.file,
            hop.line,
            hop.symbol,
            snippet
        );
        if prompt.len() + block.len() > MAX_PROMPT_BYTES {
            let remaining = MAX_PROMPT_BYTES.saturating_sub(prompt.len() + 32);
            if remaining > 0 {
                let mut end = remaining.min(block.len());
                while !block.is_char_boundary(end) && end > 0 {
                    end -= 1;
                }
                prompt.push_str(&block[..end]);
            }
            prompt.push_str("\n...[truncated to 2KB budget]\n");
            break;
        }
        prompt.push_str(&block);
    }

    Ok(prompt)
}

/// Builds an `AiProvider` from workspace config (`AiConfig`). Default / `"disabled"`
/// remains offline with zero network calls.
pub fn provider_from_config(cfg: &smg_core::AiConfig) -> Result<AiProvider> {
    match cfg.provider.trim().to_ascii_lowercase().as_str() {
        "" | "disabled" | "none" => Ok(AiProvider::Disabled),
        "ollama" => Ok(AiProvider::Ollama {
            endpoint: cfg.endpoint.clone(),
            model: cfg.model.clone(),
        }),
        "openai" | "openai_compatible" | "openai-compatible" => Ok(AiProvider::OpenAiCompatible {
            endpoint: cfg.endpoint.clone(),
            model: cfg.model.clone(),
            api_key_env: cfg.api_key_env.clone(),
        }),
        other => bail!(
            "Unsupported [ai].provider '{}' (expected disabled, ollama, or openai_compatible)",
            other
        ),
    }
}

fn ensure_rustls_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Validates AI provider endpoint URLs so local code snippets never leak over
/// cleartext HTTP or unintended remote Ollama hosts.
pub fn validate_provider_endpoint(provider: &AiProvider) -> Result<reqwest::Url> {
    match provider {
        AiProvider::Disabled => bail!("AI provider is disabled"),
        AiProvider::Ollama { endpoint, .. } => {
            let url = reqwest::Url::parse(endpoint.trim())
                .with_context(|| format!("Invalid Ollama endpoint URL '{}'", endpoint))?;
            if !url.username().is_empty() || url.password().is_some() {
                bail!("Ollama endpoint URL must not embed credentials");
            }
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Ollama endpoint URL missing host"))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("Ollama endpoint must use http:// or https://");
            }
            if !is_loopback_host(host) {
                bail!(
                    "Ollama endpoint host '{}' is non-loopback; Ollama is restricted to loopback hosts (127.0.0.1, localhost, [::1])",
                    host
                );
            }
            Ok(url)
        }
        AiProvider::OpenAiCompatible { endpoint, .. } => {
            let url = reqwest::Url::parse(endpoint.trim())
                .with_context(|| format!("Invalid OpenAiCompatible endpoint URL '{}'", endpoint))?;
            if !url.username().is_empty() || url.password().is_some() {
                bail!("OpenAiCompatible endpoint URL must not embed credentials");
            }
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("OpenAiCompatible endpoint URL missing host"))?;
            match url.scheme() {
                "https" => Ok(url),
                "http" if is_loopback_host(host) => Ok(url),
                "http" => bail!(
                    "Remote OpenAiCompatible endpoint '{}' must use https:// (http:// is allowed only on loopback hosts)",
                    host
                ),
                other => bail!("Unsupported AI endpoint scheme '{}'", other),
            }
        }
    }
}

fn build_http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client> {
    ensure_rustls_provider();
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("Failed to construct AI HTTP/TLS client")
}

fn read_bounded_ai_body(resp: reqwest::blocking::Response) -> String {
    use std::io::Read;
    let mut s = String::new();
    let _ = resp.take(4 * 1024 * 1024).read_to_string(&mut s);
    s
}

/// Calls an explicitly opted-in AI provider over a validated HTTP/TLS client
/// (`redirect::Policy::none()`), sending ONLY the minimal <= 2048 B witness prompt.
pub fn generate_patch_plan(
    provider: &AiProvider,
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
) -> Result<Option<String>> {
    generate_patch_plan_with_env(provider, project_root, finding, verified, |name| {
        std::env::var(name).map_err(|_| anyhow::anyhow!("Environment variable '{}' is unset", name))
    })
}

fn generate_patch_plan_with_env<F>(
    provider: &AiProvider,
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
    env_lookup: F,
) -> Result<Option<String>>
where
    F: Fn(&str) -> Result<String>,
{
    match provider {
        AiProvider::Disabled => Ok(None),
        AiProvider::Ollama { endpoint, model } => {
            let mut url = validate_provider_endpoint(provider)?;
            if model.trim().is_empty() {
                bail!("Ollama model name must not be empty");
            }
            let prompt = build_minimal_patch_prompt(project_root, finding, verified)?;
            if url.path().trim_end_matches('/').is_empty() {
                url.set_path("/api/generate");
            }
            let client = build_http_client(DEFAULT_AI_TIMEOUT_SECS)?;
            let resp = client
                .post(url.clone())
                .json(&json!({
                    "model": model.trim(),
                    "prompt": format!(
                        "Output ONLY a valid unified diff inside ```diff ... ``` fences that minimally remediates the vulnerability below.\n\n{}",
                        prompt
                    ),
                    "stream": false,
                    "options": { "temperature": 0.1 }
                }))
                .send()
                .with_context(|| format!("Ollama request to '{}' failed", endpoint))?;
            let status = resp.status();
            let body_text = read_bounded_ai_body(resp);
            if !status.is_success() {
                bail!(
                    "Ollama endpoint returned HTTP {} ({} bytes)",
                    status.as_u16(),
                    body_text.len()
                );
            }
            let parsed: Value = serde_json::from_str(&body_text)
                .context("Ollama returned non-JSON response payload")?;
            let reply = parsed
                .get("response")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("Ollama response JSON missing non-empty `response` field")
                })?;
            Ok(Some(reply.to_string()))
        }
        AiProvider::OpenAiCompatible {
            endpoint,
            model,
            api_key_env,
        } => {
            let mut url = validate_provider_endpoint(provider)?;
            if model.trim().is_empty() {
                bail!("OpenAiCompatible model name must not be empty");
            }
            if api_key_env.trim().is_empty() {
                bail!("OpenAiCompatible `api_key_env` must specify an environment variable name");
            }
            let api_key = env_lookup(api_key_env.trim()).with_context(|| {
                format!(
                    "Missing API key environment variable '{}' required by OpenAiCompatible provider",
                    api_key_env
                )
            })?;
            let api_key = api_key.trim();
            if api_key.is_empty() {
                bail!("API key environment variable '{}' is empty", api_key_env);
            }
            let prompt = build_minimal_patch_prompt(project_root, finding, verified)?;
            let trimmed_path = url.path().trim_end_matches('/');
            if trimmed_path.is_empty() || trimmed_path == "/v1" {
                url.set_path("/v1/chat/completions");
            }
            let client = build_http_client(DEFAULT_AI_TIMEOUT_SECS)?;
            let resp = client
                .post(url)
                .bearer_auth(api_key)
                .json(&json!({
                    "model": model.trim(),
                    "temperature": 0.1,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security engineer. Output ONLY a valid unified diff inside ```diff ... ``` fences that minimally remediates the reported vulnerability."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                }))
                .send()
                .with_context(|| format!("OpenAiCompatible request to '{}' failed", endpoint))?;
            let status = resp.status();
            let body_text = read_bounded_ai_body(resp);
            if !status.is_success() {
                bail!(
                    "OpenAiCompatible endpoint returned HTTP {} ({} bytes)",
                    status.as_u16(),
                    body_text.len()
                );
            }
            let parsed: Value = serde_json::from_str(&body_text)
                .context("OpenAiCompatible endpoint returned non-JSON response payload")?;
            let reply = parsed
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|first| {
                    first
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(Value::as_str)
                        .or_else(|| first.get("text").and_then(Value::as_str))
                })
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("OpenAiCompatible JSON missing `choices[0].message.content`")
                })?;
            Ok(Some(reply.to_string()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPatchReport {
    pub modified_files: Vec<PathBuf>,
    pub hunks_applied: usize,
}

#[derive(Debug, Clone)]
enum HunkLine {
    Context(String),
    Delete(String),
    Add(String),
}

#[derive(Debug, Clone)]
struct DiffHunk {
    old_start: usize,
    lines: Vec<HunkLine>,
    no_trailing_newline_after_add: bool,
}

#[derive(Debug, Clone)]
struct FileDiff {
    rel_path: PathBuf,
    allow_create: bool,
    hunks: Vec<DiffHunk>,
}

/// Extracts a unified diff from either fenced markdown (```diff / ```patch / ```) or raw unified diff text.
pub fn extract_unified_diff(raw: &str) -> Result<String> {
    let normalized = raw.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.lines().collect();

    let mut fenced_blocks = Vec::new();
    let mut in_fence = false;
    let mut fence_is_diff = false;
    let mut current = Vec::new();

    for line in &lines {
        let trimmed = line.trim_start();
        if !in_fence {
            if let Some(rest) = trimmed.strip_prefix("```") {
                in_fence = true;
                let lang = rest.trim().to_ascii_lowercase();
                fence_is_diff =
                    lang.is_empty() || lang == "diff" || lang == "patch" || lang == "udiff";
                current.clear();
            }
        } else if trimmed.starts_with("```") {
            in_fence = false;
            let joined = current.join("\n");
            if fence_is_diff && joined.contains("@@ ") {
                fenced_blocks.push(joined);
            }
            current.clear();
        } else {
            current.push(*line);
        }
    }

    if !fenced_blocks.is_empty() {
        return Ok(fenced_blocks.join("\n"));
    }

    let start_idx = lines
        .iter()
        .position(|l| l.starts_with("diff --git ") || l.starts_with("--- "))
        .ok_or_else(|| anyhow::anyhow!("Patch output does not contain a unified diff header"))?;
    let candidate = lines[start_idx..].join("\n");
    if !candidate.contains("@@ ") || !candidate.contains("+++ ") {
        bail!("Patch output is missing unified diff `+++` or `@@` hunks");
    }
    Ok(candidate)
}

fn clean_header_path(raw: &str) -> &str {
    let before_tab = raw.split('\t').next().unwrap_or(raw).trim();
    before_tab.trim_matches('"')
}

fn validate_rel_diff_path(raw: &str) -> Result<PathBuf> {
    let cleaned = clean_header_path(raw);
    if cleaned.is_empty() || cleaned.contains('\0') || cleaned.contains('\r') {
        bail!("Invalid diff path '{}'", raw);
    }
    if cleaned == "/dev/null" {
        bail!("Refusing file deletion to /dev/null in automated patch");
    }
    if cleaned.starts_with('/') || cleaned.starts_with('\\') {
        bail!("Refusing absolute path '{}' in diff", cleaned);
    }
    if cleaned.chars().nth(1) == Some(':') {
        bail!("Refusing drive-qualified path '{}' in diff", cleaned);
    }
    let without_prefix = cleaned
        .strip_prefix("a/")
        .or_else(|| cleaned.strip_prefix("b/"))
        .unwrap_or(cleaned);
    let mut rel = PathBuf::new();
    for comp in Path::new(without_prefix).components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                let lower = s.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    ".git" | ".shellmind-guard" | ".shellmind-guard.toml" | ".env"
                ) || lower.starts_with(".env.")
                {
                    bail!("Refusing diff modification to protected path '{}'", cleaned);
                }
                rel.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Refusing path traversal '{}' in diff", cleaned);
            }
        }
    }
    if rel.as_os_str().is_empty() {
        bail!("Diff resolved to empty relative path");
    }
    Ok(rel)
}

fn ensure_confined_target(canonical_root: &Path, rel_path: &Path) -> Result<PathBuf> {
    let mut cur = canonical_root.to_path_buf();
    let components: Vec<_> = rel_path.components().collect();
    for (idx, comp) in components.iter().enumerate() {
        cur.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                bail!(
                    "Refusing to follow symlink '{}' inside patch workspace",
                    cur.display()
                );
            }
            let canon = fs::canonicalize(&cur)?;
            if !canon.starts_with(canonical_root) {
                bail!("Path '{}' escapes workspace root", rel_path.display());
            }
            if idx + 1 == components.len() && meta.is_dir() {
                bail!("Target path '{}' is a directory", rel_path.display());
            }
        }
    }
    Ok(cur)
}

fn parse_hunk_old_start(header: &str) -> Result<usize> {
    let rest = header
        .strip_prefix("@@ -")
        .ok_or_else(|| anyhow::anyhow!("Invalid hunk header '{}'", header))?;
    let end_marker = rest
        .find(" @@")
        .ok_or_else(|| anyhow::anyhow!("Malformed hunk header '{}'", header))?;
    let ranges = &rest[..end_marker];
    let old_range = ranges
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing old range in hunk header '{}'", header))?;
    let start_str = old_range.split(',').next().unwrap_or(old_range);
    start_str
        .parse::<usize>()
        .with_context(|| format!("Invalid hunk start line '{}'", header))
}

fn parse_unified_diff(diff_text: &str) -> Result<Vec<FileDiff>> {
    let norm = diff_text.replace("\r\n", "\n");
    let lines: Vec<&str> = norm.lines().collect();
    let mut i = 0usize;
    let mut file_diffs = Vec::new();

    while i < lines.len() {
        if lines[i].starts_with("diff --git ")
            || lines[i].starts_with("index ")
            || lines[i].trim().is_empty()
        {
            i += 1;
            continue;
        }
        if !lines[i].starts_with("--- ") {
            bail!(
                "Unexpected line while scanning diff headers: '{}'",
                lines[i]
            );
        }
        let old_hdr = clean_header_path(&lines[i][4..]).to_string();
        i += 1;
        if i >= lines.len() || !lines[i].starts_with("+++ ") {
            bail!("Missing `+++` header after `--- {}`", old_hdr);
        }
        let new_hdr = &lines[i][4..];
        let allow_create = old_hdr == "/dev/null";
        let rel_path = validate_rel_diff_path(new_hdr)?;
        if !allow_create {
            let old_rel = validate_rel_diff_path(&old_hdr)?;
            if old_rel != rel_path {
                bail!(
                    "Refusing cross-file rename in automated patch ('{}' -> '{}')",
                    old_rel.display(),
                    rel_path.display()
                );
            }
        }
        i += 1;

        let mut hunks = Vec::new();
        while i < lines.len() {
            if lines[i].starts_with("diff --git ") || lines[i].starts_with("--- ") {
                break;
            }
            if lines[i].trim().is_empty() {
                i += 1;
                continue;
            }
            if !lines[i].starts_with("@@ -") {
                bail!(
                    "Unexpected hunk line in '{}': '{}'",
                    rel_path.display(),
                    lines[i]
                );
            }
            let old_start = parse_hunk_old_start(lines[i])?;
            i += 1;
            let mut hunk_lines = Vec::new();
            let mut last_was_add = false;
            let mut no_trailing_nl_after_add = false;

            while i < lines.len() {
                let line = lines[i];
                if line.starts_with("@@ -")
                    || line.starts_with("diff --git ")
                    || line.starts_with("--- ")
                {
                    break;
                }
                if let Some(rest) = line.strip_prefix('+') {
                    hunk_lines.push(HunkLine::Add(rest.to_string()));
                    last_was_add = true;
                } else if let Some(rest) = line.strip_prefix('-') {
                    hunk_lines.push(HunkLine::Delete(rest.to_string()));
                    last_was_add = false;
                } else if let Some(rest) = line.strip_prefix(' ') {
                    hunk_lines.push(HunkLine::Context(rest.to_string()));
                    last_was_add = false;
                } else if line.starts_with("\\ No newline at end of file") {
                    if last_was_add {
                        no_trailing_nl_after_add = true;
                    }
                } else if line.is_empty()
                    && hunk_lines.iter().any(|h| {
                        matches!(
                            h,
                            HunkLine::Context(_) | HunkLine::Delete(_) | HunkLine::Add(_)
                        )
                    })
                {
                    // Stop cleanly if trailing blank lines follow a completed hunk.
                    let upcoming_diff = lines[i..]
                        .iter()
                        .find(|l| !l.trim().is_empty())
                        .is_none_or(|l| {
                            l.starts_with("@@ -")
                                || l.starts_with("diff --git ")
                                || l.starts_with("--- ")
                        });
                    if upcoming_diff {
                        break;
                    }
                    hunk_lines.push(HunkLine::Context(String::new()));
                    last_was_add = false;
                } else {
                    bail!(
                        "Invalid diff body line in '{}': '{}'",
                        rel_path.display(),
                        line
                    );
                }
                i += 1;
            }

            if hunk_lines.is_empty() {
                bail!("Empty hunk in '{}'", rel_path.display());
            }
            hunks.push(DiffHunk {
                old_start,
                lines: hunk_lines,
                no_trailing_newline_after_add: no_trailing_nl_after_add,
            });
        }

        if hunks.is_empty() {
            bail!("No hunks found for '{}'", rel_path.display());
        }
        file_diffs.push(FileDiff {
            rel_path,
            allow_create,
            hunks,
        });
    }

    if file_diffs.is_empty() {
        bail!("Diff contained no file modifications");
    }
    Ok(file_diffs)
}

fn hunk_matches_at(old_lines: &[String], start_idx: usize, lines: &[HunkLine]) -> bool {
    let mut idx = start_idx;
    for hl in lines {
        match hl {
            HunkLine::Context(expected) | HunkLine::Delete(expected) => {
                if old_lines.get(idx).map(String::as_str) != Some(expected.as_str()) {
                    return false;
                }
                idx += 1;
            }
            HunkLine::Add(_) => {}
        }
    }
    true
}

fn apply_hunks_to_text(
    rel_display: &str,
    original: &str,
    allow_create: bool,
    hunks: &[DiffHunk],
) -> Result<String> {
    let had_trailing_nl = original.ends_with('\n');
    let norm = original.replace("\r\n", "\n");
    let old_lines: Vec<String> = if norm.is_empty() {
        Vec::new()
    } else {
        let stripped = norm.strip_suffix('\n').unwrap_or(&norm);
        stripped.split('\n').map(String::from).collect()
    };

    let mut out_lines = Vec::with_capacity(old_lines.len());
    let mut cursor = 0usize;
    let mut force_no_trailing_nl = false;

    for hunk in hunks {
        let base_idx = hunk.old_start.saturating_sub(1);
        let has_old_anchors = hunk
            .lines
            .iter()
            .any(|l| matches!(l, HunkLine::Context(_) | HunkLine::Delete(_)));

        let match_idx = if base_idx >= cursor
            && base_idx <= old_lines.len()
            && hunk_matches_at(&old_lines, base_idx, &hunk.lines)
        {
            base_idx
        } else if has_old_anchors {
            let mut found = None;
            for delta in 1usize..=25usize {
                if let Some(cand) = base_idx.checked_add(delta)
                    && cand >= cursor
                    && hunk_matches_at(&old_lines, cand, &hunk.lines)
                {
                    found = Some(cand);
                    break;
                }
                if let Some(cand) = base_idx.checked_sub(delta)
                    && cand >= cursor
                    && hunk_matches_at(&old_lines, cand, &hunk.lines)
                {
                    found = Some(cand);
                    break;
                }
            }
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "Hunk context mismatch in '{}' near line {}",
                    rel_display,
                    hunk.old_start
                )
            })?
        } else {
            bail!(
                "Pure-insertion hunk at line {} did not align in '{}'",
                hunk.old_start,
                rel_display
            );
        };

        out_lines.extend(old_lines[cursor..match_idx].iter().cloned());
        let mut idx = match_idx;
        for hl in &hunk.lines {
            match hl {
                HunkLine::Context(s) => {
                    out_lines.push(s.clone());
                    idx += 1;
                }
                HunkLine::Delete(_) => {
                    idx += 1;
                }
                HunkLine::Add(s) => {
                    out_lines.push(s.clone());
                }
            }
        }
        cursor = idx;
        if hunk.no_trailing_newline_after_add {
            force_no_trailing_nl = true;
        }
    }

    out_lines.extend(old_lines[cursor..].iter().cloned());
    if out_lines.is_empty() {
        return Ok(String::new());
    }
    let mut rendered = out_lines.join("\n");
    let emit_nl = if force_no_trailing_nl {
        false
    } else if allow_create {
        true
    } else {
        had_trailing_nl || original.is_empty()
    };
    if emit_nl {
        rendered.push('\n');
    }
    Ok(rendered)
}

/// Validates every target path and hunk completely in memory before atomically writing
/// inside `workspace_root`, rejecting `..`, absolute paths, protected files, and symlinks.
pub fn apply_unified_diff_safely(
    workspace_root: &Path,
    raw_diff: &str,
) -> Result<AppliedPatchReport> {
    let canonical_root = fs::canonicalize(workspace_root).with_context(|| {
        format!(
            "Failed to canonicalize workspace root '{}'",
            workspace_root.display()
        )
    })?;
    let clean_diff = extract_unified_diff(raw_diff)?;
    let parsed_files = parse_unified_diff(&clean_diff)?;

    let mut staged_writes: Vec<(PathBuf, PathBuf, String, usize)> = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let mut total_hunks = 0usize;

    for fd in parsed_files {
        if !seen_paths.insert(fd.rel_path.clone()) {
            bail!(
                "Duplicate file header '{}' in unified diff",
                fd.rel_path.display()
            );
        }
        let target = ensure_confined_target(&canonical_root, &fd.rel_path)?;
        let original = if target.exists() {
            if fd.allow_create {
                bail!("Target file '{}' already exists", fd.rel_path.display());
            }
            fs::read_to_string(&target)
                .with_context(|| format!("Failed to read '{}'", target.display()))?
        } else if fd.allow_create {
            String::new()
        } else {
            bail!("Target file '{}' does not exist", fd.rel_path.display());
        };

        let updated = apply_hunks_to_text(
            &fd.rel_path.display().to_string(),
            &original,
            fd.allow_create,
            &fd.hunks,
        )?;
        let hunks_len = fd.hunks.len();
        total_hunks += hunks_len;
        staged_writes.push((fd.rel_path, target, updated, hunks_len));
    }

    let mut modified_files = Vec::with_capacity(staged_writes.len());
    for (rel, abs_target, updated, _) in staged_writes {
        if let Some(parent) = abs_target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&abs_target, updated)
            .with_context(|| format!("Failed to write patched file '{}'", abs_target.display()))?;
        modified_files.push(rel);
    }

    Ok(AppliedPatchReport {
        modified_files,
        hunks_applied: total_hunks,
    })
}

static APPLY_CHECK_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirCleanup(PathBuf);

impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct ApplyCheckParams<'a> {
    pub project_root: &'a Path,
    pub cfg: &'a ShellMindGuardConfig,
    pub finding: &'a LatticeFinding,
    pub raw_diff: &'a str,
    pub boot_cmd: Option<&'a str>,
    pub port: u16,
    pub sync_race: usize,
    pub unsafe_host_fallback: bool,
    pub probe_cfg: &'a SandboxProbeConfig,
}

#[derive(Debug, Clone)]
pub struct ApplyCheckOutcome {
    pub mitigated: bool,
    pub summary: String,
    pub modified_files: Vec<PathBuf>,
    pub hunks_applied: usize,
}

pub fn copy_workspace_filtered(src_root: &Path, dst_root: &Path) -> Result<()> {
    let canon_src = fs::canonicalize(src_root)?;
    let canon_dst = fs::canonicalize(dst_root)?;
    copy_dir_recursive_filtered(&canon_src, &canon_dst, &canon_dst)
}

#[cfg(unix)]
pub(crate) fn set_private_dir_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
pub(crate) fn set_private_dir_mode(_path: &Path) {}

fn copy_dir_recursive_filtered(src: &Path, dst: &Path, canonical_dst_root: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let low = name_str.to_ascii_lowercase();
        if matches!(
            name_str.as_ref(),
            ".git" | "target" | ".shellmind-guard" | ".veriforge" | ".npmrc" | ".env"
        ) || low.starts_with(".env.")
            || low.ends_with(".pem")
            || low.ends_with(".key")
        {
            continue;
        }
        // Check lstat file_type() BEFORE metadata() so broken symlinks never abort workspace copy.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let src_path = entry.path();
        if src_path == canonical_dst_root {
            continue;
        }
        let dst_path = dst.join(&name);
        if ft.is_dir() {
            fs::create_dir_all(&dst_path)?;
            set_private_dir_mode(&dst_path);
            copy_dir_recursive_filtered(&src_path, &dst_path, canonical_dst_root)?;
        } else if ft.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn finding_still_present<'a>(
    post_findings: &'a [LatticeFinding],
    target: &LatticeFinding,
) -> Option<&'a LatticeFinding> {
    // Match globally on (rule_id, sink_kind) without requiring `f.file == target.file`,
    // preventing false MITIGATED verdicts when a refactoring patch moves vulnerable code.
    post_findings.iter().find(|f| {
        f.rule_id == target.rule_id
            && f.sink_kind == target.sink_kind
            && (f.file == target.file
                || f.entry_route == target.entry_route
                || f.title == target.title)
    })
}

/// Applies `raw_diff` inside an isolated temporary workspace copy and verifies whether `finding`
/// is statically eliminated (or dynamically mitigated in sandbox when `--boot-cmd` is provided).
pub fn verify_patch_in_isolated_copy(params: &ApplyCheckParams<'_>) -> Result<ApplyCheckOutcome> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = APPLY_CHECK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_root = std::env::temp_dir().join(format!(
        "smg_apply_check_{}_{}_{}",
        std::process::id(),
        nanos,
        seq
    ));
    fs::create_dir_all(&temp_root)?;
    set_private_dir_mode(&temp_root);
    let _cleanup = TempDirCleanup(temp_root.clone());

    copy_workspace_filtered(params.project_root, &temp_root)?;
    let report = apply_unified_diff_safely(&temp_root, params.raw_diff)?;

    let post_summary = scan_repository(&temp_root, params.cfg)?;
    let mut post_graph = analyze_codebase(&post_summary.files, params.cfg)?;
    if params.finding.rule_id.starts_with("SMG-FUZZ-") {
        let deep_post = collect_deep_schema_findings(&post_graph);
        post_graph.findings.extend(deep_post);
    }

    let Some(remaining) = finding_still_present(&post_graph.findings, params.finding) else {
        return Ok(ApplyCheckOutcome {
            mitigated: true,
            summary: format!(
                "Patch eliminated {} ({}) statically in isolated verification workspace",
                params.finding.id, params.finding.rule_id
            ),
            modified_files: report.modified_files,
            hunks_applied: report.hunks_applied,
        });
    };

    if matches!(
        remaining.missing_guard,
        GuardKind::Auth | GuardKind::TxLock | GuardKind::OwnershipCheck
    ) && let Some(boot) = params.boot_cmd
    {
        let (_, post_verified) = verify_findings_in_sandbox_with_config(
            &temp_root,
            boot,
            params.port,
            std::slice::from_ref(remaining),
            params.sync_race,
            params.unsafe_host_fallback,
            params.probe_cfg,
        )?;
        if let Some(first) = post_verified.first() {
            if first.status == VerificationStatus::Mitigated {
                return Ok(ApplyCheckOutcome {
                    mitigated: true,
                    summary: format!("Runtime sandbox proved mitigation: {}", first.evidence),
                    modified_files: report.modified_files,
                    hunks_applied: report.hunks_applied,
                });
            }
            return Ok(ApplyCheckOutcome {
                mitigated: false,
                summary: format!(
                    "Patch did not mitigate {} dynamically ({})",
                    remaining.id, first.evidence
                ),
                modified_files: report.modified_files,
                hunks_applied: report.hunks_applied,
            });
        }
    }

    Ok(ApplyCheckOutcome {
        mitigated: false,
        summary: format!(
            "Patch did not eliminate {} ({}) at {}:{}",
            remaining.id, remaining.rule_id, remaining.file, remaining.line
        ),
        modified_files: report.modified_files,
        hunks_applied: report.hunks_applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smg_graph::{Confidence, GuardKind, SinkKind, TraceHop};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_finding() -> LatticeFinding {
        LatticeFinding {
            id: "SMG-RACE-002".into(),
            rule_id: "SMG-RACE-001".into(),
            severity: "CRITICAL".into(),
            title: "Missing tx lock".into(),
            file: "src/routes/checkout.ts".into(),
            line: 8,
            status: "PROVEN".into(),
            confidence: Confidence::Confirmed,
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: vec![TraceHop {
                file: "src/routes/checkout.ts".into(),
                symbol: "POST /api/v1/checkout/withdraw".into(),
                line: 8,
            }],
            remediation: String::new(),
            proof_reasons: vec![],
        }
    }

    fn spawn_mock_json_server(response_json: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock server");
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut reader = BufReader::new(stream.try_clone().expect("clone tcp stream"));
            let mut request_head = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).expect("read header");
                if n == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("content-length")
                {
                    content_length = v.trim().parse().unwrap_or(0);
                }
                request_head.push_str(&line);
            }
            let mut body_buf = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body_buf).expect("read body");
            }
            let raw_http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            stream
                .write_all(raw_http.as_bytes())
                .expect("write response");
            format!("{}\n{}", request_head, String::from_utf8_lossy(&body_buf))
        });
        (format!("http://{}", addr), handle)
    }

    #[test]
    fn test_disabled_by_default_and_minimal_prompt_budget() {
        let finding = sample_finding();

        let disabled =
            generate_patch_plan(&AiProvider::Disabled, Path::new("."), &finding, None).unwrap();
        assert!(disabled.is_none());

        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let prompt = build_minimal_patch_prompt(&fixture_root, &finding, None).unwrap();
        assert!(prompt.len() <= MAX_PROMPT_BYTES);
        assert!(prompt.contains("SMG-RACE-002"));
    }

    #[test]
    fn test_endpoint_validation_rejects_remote_http_and_non_loopback_ollama() {
        let remote_http = AiProvider::OpenAiCompatible {
            endpoint: "http://api.example.com/v1/chat/completions".into(),
            model: "gpt-4o-mini".into(),
            api_key_env: "OPENAI_API_KEY".into(),
        };
        assert!(validate_provider_endpoint(&remote_http).is_err());

        let remote_ollama = AiProvider::Ollama {
            endpoint: "https://ollama.example.com".into(),
            model: "qwen2.5-coder".into(),
        };
        assert!(validate_provider_endpoint(&remote_ollama).is_err());

        let local_ollama = AiProvider::Ollama {
            endpoint: "http://127.0.0.1:11434".into(),
            model: "qwen2.5-coder".into(),
        };
        assert!(validate_provider_endpoint(&local_ollama).is_ok());

        let remote_https = AiProvider::OpenAiCompatible {
            endpoint: "https://api.example.com/v1/chat/completions".into(),
            model: "gpt-4o-mini".into(),
            api_key_env: "OPENAI_API_KEY".into(),
        };
        assert!(validate_provider_endpoint(&remote_https).is_ok());
    }

    #[test]
    fn test_ollama_and_openai_compatible_mock_clients() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let finding = sample_finding();

        let (ollama_url, ollama_handle) = spawn_mock_json_server(
            r#"{"response":"```diff\n--- a/src/routes/checkout.ts\n+++ b/src/routes/checkout.ts\n@@ -1,1 +1,1 @@\n-old\n+new\n```"}"#.into(),
        );
        let ollama_provider = AiProvider::Ollama {
            endpoint: ollama_url,
            model: "qwen2.5-coder:7b".into(),
        };
        let ollama_out = generate_patch_plan(&ollama_provider, &fixture_root, &finding, None)
            .unwrap()
            .expect("ollama output");
        assert!(ollama_out.contains("--- a/src/routes/checkout.ts"));
        let ollama_req = ollama_handle.join().unwrap();
        assert!(ollama_req.starts_with("POST /api/generate "));
        assert!(ollama_req.contains("SMG-RACE-002"));

        let unset_provider = AiProvider::OpenAiCompatible {
            endpoint: "http://127.0.0.1:8080".into(),
            model: "local-coder".into(),
            api_key_env: "SMG_AI_TEST_DEFINITELY_UNSET_API_KEY_99123".into(),
        };
        let missing_err = generate_patch_plan(&unset_provider, &fixture_root, &finding, None)
            .expect_err("unset API key env must fail");
        assert!(
            missing_err
                .to_string()
                .contains("SMG_AI_TEST_DEFINITELY_UNSET_API_KEY_99123")
        );

        let (oai_url, oai_handle) = spawn_mock_json_server(
            r#"{"choices":[{"message":{"content":"```diff\n--- a/src/db/queries.ts\n+++ b/src/db/queries.ts\n@@ -1,1 +1,1 @@\n-raw\n+tx\n```"}}]}"#.into(),
        );
        let oai_provider = AiProvider::OpenAiCompatible {
            endpoint: oai_url,
            model: "gpt-test".into(),
            api_key_env: "SMG_AI_MOCK_KEY".into(),
        };
        let oai_out =
            generate_patch_plan_with_env(&oai_provider, &fixture_root, &finding, None, |k| {
                assert_eq!(k, "SMG_AI_MOCK_KEY");
                Ok("sk-mock-secret".into())
            })
            .unwrap()
            .expect("openai-compatible output");
        assert!(oai_out.contains("+++ b/src/db/queries.ts"));
        let oai_req = oai_handle.join().unwrap();
        assert!(oai_req.starts_with("POST /v1/chat/completions "));
        assert!(
            oai_req.contains("Authorization: Bearer sk-mock-secret")
                || oai_req.contains("authorization: Bearer sk-mock-secret")
        );
    }

    #[test]
    fn test_apply_unified_diff_safely_applies_and_blocks_traversal() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_root = std::env::temp_dir().join(format!("smg_ai_patch_test_{}", nanos));
        fs::create_dir_all(temp_root.join("src")).unwrap();
        fs::write(
            temp_root.join("src/auth.ts"),
            "export function handler(req: any) {\n  return db.query(req.query.id);\n}\n",
        )
        .unwrap();

        let good_diff = r#"
Here is the minimal fix:
```diff
--- a/src/auth.ts
+++ b/src/auth.ts
@@ -1,3 +1,3 @@
 export function handler(req: any) {
-  return db.query(req.query.id);
+  return db.query("SELECT * FROM items WHERE id = $1", [Number(req.query.id)]);
 }
```
"#;
        let report = apply_unified_diff_safely(&temp_root, good_diff).unwrap();
        assert_eq!(report.modified_files, vec![PathBuf::from("src/auth.ts")]);
        assert_eq!(report.hunks_applied, 1);
        let patched = fs::read_to_string(temp_root.join("src/auth.ts")).unwrap();
        assert!(patched.contains("SELECT * FROM items WHERE id = $1"));

        let traversal_diff =
            "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-root:x\n+pwned\n";
        assert!(apply_unified_diff_safely(&temp_root, traversal_diff).is_err());

        let protected_diff = "--- a/.git/config\n+++ b/.git/config\n@@ -1,1 +1,1 @@\n-a\n+b\n";
        assert!(apply_unified_diff_safely(&temp_root, protected_diff).is_err());

        let _ = fs::remove_dir_all(&temp_root);
    }
}
