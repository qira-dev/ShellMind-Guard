use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use smg_core::Language;
use std::collections::HashSet;
use std::sync::OnceLock;

#[allow(clippy::too_many_arguments)]
fn mk_finding(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    remediation: &str,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line: line.max(1),
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence: Confidence::Confirmed,
        remediation: remediation.to_string(),
    }
}

/// Scans structural CI/CD pipelines, Kubernetes/Helm manifests, ReDoS nested quantifiers,
/// ZipSlip archive extraction, weak Crypto modes/timing comparisons, and Async Queue taint.
pub fn scan_infra_dos_crypto_and_queues(
    rel_path: &str,
    language: Language,
    content: &str,
) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
    let low_path = rel_path.replace('\\', "/").to_ascii_lowercase();

    let is_yaml = low_path.ends_with(".yml") || low_path.ends_with(".yaml");
    if is_yaml {
        if low_path.contains(".github/workflows/") || low_path.ends_with(".gitlab-ci.yml") {
            scan_cicd_workflow(rel_path, content, &mut out);
        }
        scan_kubernetes_manifest(rel_path, content, &mut out);
        return out;
    }

    if !matches!(
        language,
        Language::TypeScript
            | Language::JavaScript
            | Language::Python
            | Language::Go
            | Language::Rust
            | Language::Java
            | Language::CSharp
            | Language::Php
            | Language::Ruby
            | Language::Kotlin
    ) {
        return out;
    }

    scan_redos_patterns(rel_path, content, &mut out);
    scan_zipslip_patterns(rel_path, language, content, &mut out);
    scan_crypto_math_patterns(rel_path, content, &mut out);
    scan_async_queue_context(rel_path, content, &mut out);

    out
}

fn untrusted_gha_expr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\$\{\{\s*(?:github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|issue\.(?:title|body)|comment\.body|discussion\.(?:title|body)|review\.(?:body)|commits\[[^\]]+\]\.message)|github\.head_ref)\b[^}]*\}\}",
        )
        .expect("valid gha expr regex")
    })
}

fn unpinned_uses_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*-?\s*uses\s*:\s*['"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s'"]+)['"]?"#)
            .expect("valid gha uses regex")
    })
}

fn scan_cicd_workflow(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    let lines: Vec<&str> = content.lines().collect();
    let has_pr_target = lines.iter().any(|l| {
        let code = l.split('#').next().unwrap_or("").trim();
        code.contains("pull_request_target") || code.contains("workflow_run")
    });

    let mut in_run_block_indent: Option<usize> = None;
    for (idx, raw) in lines.iter().enumerate() {
        let ln = idx + 1;
        let code = raw.split('#').next().unwrap_or("");
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();

        // Permissions: write-all check
        if trimmed.eq_ignore_ascii_case("permissions: write-all")
            || trimmed.eq_ignore_ascii_case("permissions:write-all")
        {
            out.push(mk_finding(
                "SMG-CICD-002",
                "HIGH",
                "CI/CD workflow grants `permissions: write-all` (excessive GITHUB_TOKEN privilege)".into(),
                rel_path,
                ln,
                "permissions",
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                "Restrict `permissions:` to least privilege (`contents: read`) at workflow or job scope.",
            ));
        }

        // Unpinned mutable @main / @master / @HEAD action ref check
        if let Some(cap) = unpinned_uses_re().captures(code) {
            let action = &cap[1];
            let reference = &cap[2];
            if matches!(reference, "main" | "master" | "HEAD" | "latest" | "dev") {
                out.push(mk_finding(
                    "SMG-CICD-002",
                    "HIGH",
                    format!(
                        "GitHub Action `{}@{}` uses mutable branch ref instead of immutable 40-char commit SHA",
                        action, reference
                    ),
                    rel_path,
                    ln,
                    action,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Pin third-party GitHub Actions to a full 40-character commit SHA (`uses: owner/action@<sha>`).",
                ));
            }
        }

        if let Some(run_indent) = in_run_block_indent {
            if indent <= run_indent {
                in_run_block_indent = None;
            } else if has_pr_target && untrusted_gha_expr_re().is_match(code) {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions `pull_request_target`/`workflow_run` evaluates untrusted `${{ github.event.* }}` directly inside `run:` shell (Pwn-Request RCE)".into(),
                    rel_path,
                    ln,
                    "pull_request_target",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Bind `${{ github.event.* }}` via `env:` variables and reference safely as quoted `\"$VAR\"` inside shell scripts, or downgrade trigger to `pull_request`.",
                ));
            }
        }

        let after_dash = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
        if let Some(after_run) = after_dash.strip_prefix("run:") {
            let rest = after_run.trim();
            if rest.starts_with('|') || rest.starts_with('>') {
                in_run_block_indent = Some(indent);
            } else if has_pr_target && untrusted_gha_expr_re().is_match(rest) {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions `pull_request_target`/`workflow_run` interpolates untrusted `${{ github.event.* }}` inside `run:` command (Pwn-Request RCE)".into(),
                    rel_path,
                    ln,
                    "pull_request_target",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Pass untrusted GitHub event context through `env:` instead of inline `${{ ... }}` shell interpolation.",
                ));
            }
        }
    }
}

fn scan_kubernetes_manifest(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    // Split multi-document YAML (`---`) keeping accurate line numbers
    let mut line_offset = 0usize;
    for doc in content.split("\n---") {
        let doc_lines: Vec<&str> = doc.lines().collect();
        analyze_k8s_doc(rel_path, line_offset, &doc_lines, out);
        line_offset += doc_lines.len();
    }
}

fn analyze_k8s_doc(
    rel_path: &str,
    base_line: usize,
    lines: &[&str],
    out: &mut Vec<LocalStaticFinding>,
) {
    let mut kind: Option<String> = None;
    let mut has_api_version = false;
    for l in lines {
        let code = l.split('#').next().unwrap_or("").trim();
        if code.starts_with("apiVersion:") {
            has_api_version = true;
        } else if let Some(rest) = code.strip_prefix("kind:") {
            kind = Some(rest.trim().trim_matches(['"', '\'']).to_string());
        }
    }
    let Some(ref k_str) = kind else {
        return;
    };
    if !has_api_version {
        return;
    }

    let is_workload = matches!(
        k_str.as_str(),
        "Pod" | "Deployment" | "DaemonSet" | "StatefulSet" | "Job" | "CronJob" | "ReplicaSet"
    );
    let is_rbac = matches!(k_str.as_str(), "ClusterRole" | "Role");

    if is_workload {
        let mut in_host_path = false;
        let mut host_path_indent = 0usize;
        for (idx, raw) in lines.iter().enumerate() {
            let ln = base_line + idx + 1;
            let code = raw.split('#').next().unwrap_or("");
            let trimmed = code.trim();
            let low = trimmed.to_ascii_lowercase();
            let indent = raw.len() - raw.trim_start().len();

            if in_host_path && indent <= host_path_indent && !trimmed.is_empty() {
                in_host_path = false;
            }
            if low.starts_with("hostpath:") {
                in_host_path = true;
                host_path_indent = indent;
                continue;
            }
            if in_host_path && let Some(p_val) = low.strip_prefix("path:") {
                let p = p_val.trim().trim_matches(['"', '\'']);
                if p.contains("docker.sock")
                    || p.contains("containerd.sock")
                    || p.contains("crio.sock")
                    || p == "/"
                    || p == "/etc"
                    || p == "/root"
                {
                    out.push(mk_finding(
                        "SMG-K8S-001",
                        "CRITICAL",
                        format!(
                            "Kubernetes `{}` mounts sensitive hostPath `{}` (container breakout risk)",
                            k_str, p
                        ),
                        rel_path,
                        ln,
                        k_str,
                        SinkKind::Misconfiguration,
                        GuardKind::ConfigPolicy,
                        "Remove sensitive `hostPath` mounts (`/`, `/var/run/docker.sock`, `/etc`) and use namespaced volumes instead.",
                    ));
                }
            }

            if low == "privileged: true" || low == "allowprivilegeescalation: true" {
                out.push(mk_finding(
                    "SMG-K8S-001",
                    "CRITICAL",
                    format!(
                        "Kubernetes `{}` enables `{}` in container securityContext",
                        k_str, trimmed
                    ),
                    rel_path,
                    ln,
                    k_str,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Set `privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, and `capabilities.drop: [ALL]`.",
                ));
            } else if low == "hostpid: true" || low == "hostipc: true" {
                out.push(mk_finding(
                    "SMG-K8S-001",
                    "HIGH",
                    format!(
                        "Kubernetes `{}` shares host namespace (`{}`)",
                        k_str, trimmed
                    ),
                    rel_path,
                    ln,
                    k_str,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Disable `hostPID` and `hostIPC` to enforce pod isolation boundaries.",
                ));
            }
        }
    }

    if is_rbac {
        let mut wildcard_line: Option<usize> = None;
        let mut has_wildcard_resources = false;
        let mut has_wildcard_verbs = false;
        for (idx, raw) in lines.iter().enumerate() {
            let ln = base_line + idx + 1;
            let trimmed = raw.split('#').next().unwrap_or("").trim();
            let low = trimmed.to_ascii_lowercase();
            if low.starts_with("resources:")
                && (low.contains("'*'") || low.contains("\"*\"") || low.contains("secrets"))
            {
                has_wildcard_resources = true;
                wildcard_line.get_or_insert(ln);
            } else if low == "- '*'" || low == "- \"*\"" || low == "- *" || low == "- secrets" {
                if let Some(prev) = lines[..idx].iter().rev().find(|p| p.contains(':')) {
                    let pl = prev.to_ascii_lowercase();
                    if pl.contains("resources:") {
                        has_wildcard_resources = true;
                        wildcard_line.get_or_insert(ln);
                    } else if pl.contains("verbs:") {
                        has_wildcard_verbs = true;
                        wildcard_line.get_or_insert(ln);
                    }
                }
            } else if low.starts_with("verbs:") && (low.contains("'*'") || low.contains("\"*\"")) {
                has_wildcard_verbs = true;
                wildcard_line.get_or_insert(ln);
            }
        }
        if has_wildcard_resources && has_wildcard_verbs {
            out.push(mk_finding(
                "SMG-K8S-002",
                "CRITICAL",
                format!(
                    "Kubernetes `{}` grants wildcard RBAC permissions (`*` verbs on `*`/secrets)",
                    k_str
                ),
                rel_path,
                wildcard_line.unwrap_or(base_line + 1),
                k_str,
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                "Scope RBAC `resources` and `verbs` strictly to specific resource names and minimal verbs (`get`, `list`).",
            ));
        }
    }
}

fn extract_regex_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r##"(?:new\s+RegExp\s*\(\s*["']([^"'\n]{3,})["']|\bre\.compile\s*\(\s*r?["']([^"'\n]{3,})["']|\bRegex::new\s*\(\s*(?:r#*"([^"]+)"#*|"([^"\n]{3,})")|\bregexp\.(?:Compile|MustCompile)\s*\(\s*[`"]([^`"\n]{3,})[`"])"##,
        )
        .expect("valid regex extractor")
    })
}

/// Inspects a regex string for nested quantifiers such as `(a+)+`, `(.*)*`, `([a-z]+)*`.
fn has_nested_quantifier_redos(pat: &str) -> bool {
    let bytes = pat.as_bytes();
    let mut stack: Vec<bool> = Vec::new();
    let mut i = 0usize;
    let mut in_char_class = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'[' && !in_char_class {
            in_char_class = true;
            i += 1;
            continue;
        }
        if b == b']' && in_char_class {
            in_char_class = false;
            i += 1;
            continue;
        }
        if in_char_class {
            i += 1;
            continue;
        }
        match b {
            b'(' => {
                // Atomic / lookaround groups avoid naive backtracking amplification
                stack.push(false);
            }
            b')' => {
                let inner_has_quant = stack.pop().unwrap_or(false);
                let next_is_quant = matches!(bytes.get(i + 1), Some(b'+' | b'*' | b'{'));
                if inner_has_quant && next_is_quant {
                    return true;
                }
                if inner_has_quant && let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            b'+' | b'*' => {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            b'{' => {
                // Only unbounded or large upper-bound repetitions `{m,}` / `{m,n}` inside groups count as quantifiers
                if let Some(close_rel) = bytes[i..].iter().position(|&c| c == b'}')
                    && let Some(inner) = std::str::from_utf8(&bytes[i + 1..i + close_rel]).ok()
                    && inner.contains(',')
                {
                    if let Some(top) = stack.last_mut() {
                        *top = true;
                    }
                    i += close_rel;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn scan_redos_patterns(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with('*')
            || crate::taint::is_pattern_matcher_or_doc_line(line)
        {
            continue;
        }
        for cap in extract_regex_call_re().captures_iter(line) {
            let pat = (1..=5).find_map(|g| cap.get(g).map(|m| m.as_str()));
            if let Some(p) = pat
                && has_nested_quantifier_redos(p)
            {
                out.push(mk_finding(
                    "SMG-DOS-001",
                    "HIGH",
                    format!(
                        "Catastrophic backtracking ReDoS pattern `{}` (nested quantifier)",
                        p
                    ),
                    rel_path,
                    idx + 1,
                    "regex",
                    SinkKind::SchemaTampering,
                    GuardKind::InputValidation,
                    "Eliminate nested quantifiers (`(a+)+`), limit input string length before matching, or use a linear-time regex engine.",
                ));
            }
        }
        // JS inline regex literal heuristic when assignment contains `=/.../` with nested `)+` or `)*`
        if (trimmed.contains("= /") || trimmed.contains("new RegExp"))
            && let Some(start) = trimmed.find("= /")
        {
            let rest = &trimmed[start + 3..];
            if let Some(end) = rest.find('/') {
                let lit = &rest[..end];
                if !lit.is_empty() && has_nested_quantifier_redos(lit) {
                    out.push(mk_finding(
                        "SMG-DOS-001",
                        "HIGH",
                        format!(
                            "Catastrophic backtracking ReDoS literal `/{}/`",
                            lit
                        ),
                        rel_path,
                        idx + 1,
                        "regex_literal",
                        SinkKind::SchemaTampering,
                        GuardKind::InputValidation,
                        "Rewrite nested quantifiers in regex literal into possessive/flat character classes and cap input length.",
                    ));
                }
            }
        }
    }
}

fn scan_zipslip_patterns(
    rel_path: &str,
    language: Language,
    content: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let low_all = content.to_ascii_lowercase();
    let has_path_containment = low_all.contains("starts_with")
        || low_all.contains("startswith")
        || low_all.contains("commonpath")
        || low_all.contains("commonprefix")
        || low_all.contains("enclosed_name")
        || low_all.contains("getcanonicalpath")
        || low_all.contains("hasprefix")
        || low_all.contains("relpath");

    if has_path_containment {
        return;
    }

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        let low = trimmed.to_ascii_lowercase();
        let is_vuln_extract = match language {
            Language::Python => {
                (low.contains(".extractall(") || low.contains(".extract("))
                    && (low_all.contains("zipfile") || low_all.contains("tarfile"))
            }
            Language::JavaScript | Language::TypeScript => {
                low.contains(".extractallto(")
                    || low.contains("unzipper.extract(")
                    || low.contains("unzip.extract(")
            }
            Language::Go => {
                low_all.contains("archive/zip")
                    && low.contains("filepath.join(")
                    && (low.contains(".name") || low.contains("header.name"))
            }
            Language::Java | Language::Kotlin => {
                (low_all.contains("zipinputstream") || low_all.contains("zipentry"))
                    && low.contains("new file(")
                    && low.contains("getname()")
            }
            Language::CSharp => {
                low.contains("zipfile.extracttodirectory(")
                    || (low.contains("extracttofile(") && low_all.contains("archive"))
            }
            Language::Rust => {
                low_all.contains("ziparchive") && low.contains(".name()") && low.contains(".join(")
            }
            _ => false,
        };
        if is_vuln_extract {
            out.push(mk_finding(
                "SMG-ZIP-001",
                "CRITICAL",
                "Unchecked archive extraction path allows arbitrary file overwrite (ZipSlip traversal)".into(),
                rel_path,
                idx + 1,
                "archive_extract",
                SinkKind::PathTraversal,
                GuardKind::PathSanitizer,
                "Resolve canonical destination path for every archive entry and verify `entry_path.starts_with(dest_root)` plus enforce max uncompressed byte limits.",
            ));
        }
    }
}

fn ecb_or_static_iv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:aes-(?:128|192|256)-ecb|['"]AES/ECB|MODE_ECB|\bmodes\.ECB\s*\(\s*\)|createCipheriv\s*\([^,\n]+,[^,\n]+,\s*(?:['"][0-9a-fA-Fx]{16,}['"]|Buffer\.from\s*\(\s*['"][^'"]+['"]))"#,
        )
        .expect("valid ecb/iv regex")
    })
}

fn secret_timing_cmp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:signature|hmac|expected_sig|expectedSig|webhook_sig|webhookSig|mac|digest|api_secret|apiSecret)\w*\s*(?:===|==|!==|!=)\s*[A-Za-z0-9_.\[\]"']+"#,
        )
        .expect("valid timing cmp regex")
    })
}

fn scan_crypto_math_patterns(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    let low_all = content.to_ascii_lowercase();
    let has_const_time_api = low_all.contains("timingsafeequal")
        || low_all.contains("compare_digest")
        || low_all.contains("hmac.equal")
        || low_all.contains("ct_eq")
        || low_all.contains("constanttimeeq")
        || low_all.contains("messagedigest.isequal");

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with('*')
            || crate::taint::is_pattern_matcher_or_doc_line(line)
        {
            continue;
        }
        if ecb_or_static_iv_re().is_match(line) {
            out.push(mk_finding(
                "SMG-CRYPTO-001",
                "HIGH",
                "Broken symmetric cipher configuration (`AES-ECB` mode or static hardcoded IV)".into(),
                rel_path,
                idx + 1,
                "cipher",
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                "Switch to authenticated encryption (`AES-256-GCM` or `ChaCha20-Poly1305`) with a fresh CSPRNG nonce per encryption.",
            ));
        } else if !has_const_time_api
            && secret_timing_cmp_re().is_match(line)
            && !line.contains("null")
            && !line.contains("None")
            && !line.contains("nil")
            && !line.contains("undefined")
            && !line.contains("length")
            && !line.contains(".len(")
            && !line.contains("len(")
        {
            out.push(mk_finding(
                "SMG-CRYPTO-001",
                "HIGH",
                "Non-constant-time (`===` / `==`) comparison of cryptographic HMAC/signature enables timing side-channel".into(),
                rel_path,
                idx + 1,
                "signature_compare",
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                "Use constant-time comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`, `hmac.Equal`, or `subtle::ConstantTimeEq`).",
            ));
        }
    }
}

fn scan_async_queue_context(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    let low_all = content.to_ascii_lowercase();
    let has_worker_keyword = low_all.contains("new worker(")
        || low_all.contains(".process(")
        || low_all.contains("@shared_task")
        || low_all.contains("@celery.task")
        || low_all.contains("channel.consume(")
        || low_all.contains("consumer.run(");
    if !has_worker_keyword {
        return;
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut seen_lines = HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        let is_job_entry = low.contains("new worker(")
            || low.contains(".process(")
            || low.contains("@shared_task")
            || low.contains("@celery.task")
            || low.contains("channel.consume(");
        if !is_job_entry {
            continue;
        }
        let end = (idx + 22).min(lines.len());
        let window = lines[idx..end].join("\n").to_ascii_lowercase();
        let uses_msg_data = window.contains("job.data")
            || window.contains("msg.content")
            || window.contains("message.body")
            || window.contains("payload");
        let hits_critical_sink = window.contains("exec(")
            || window.contains("execsync(")
            || window.contains("subprocess.")
            || window.contains("db.query(")
            || window.contains("debit")
            || window.contains("transfer");
        let has_tenant_or_schema_guard = window.contains("tenantid")
            || window.contains("tenant_id")
            || window.contains("userid")
            || window.contains("user_id")
            || window.contains("zod")
            || window.contains("parse(")
            || window.contains("validate")
            || window.contains("idempotency");

        if uses_msg_data
            && hits_critical_sink
            && !has_tenant_or_schema_guard
            && seen_lines.insert(idx)
        {
            out.push(mk_finding(
                "SMG-QUEUE-001",
                "HIGH",
                "Async queue worker executes privileged sink directly on job payload without tenant/schema/idempotency validation".into(),
                rel_path,
                idx + 1,
                "async_worker",
                SinkKind::BalanceUpdate,
                GuardKind::InputValidation,
                "Propagate verified `tenantId`/`userId` + idempotency key from authenticated producer and validate job schema inside the consumer before sinks.",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cicd_k8s_redos_zipslip_crypto_and_queue_precision_pairs() {
        // 1. CI/CD Pwn-Request vs env-bound safe workflow
        let vuln_gha = r#"
on:
  pull_request_target:
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: thirdparty/action@main
      - run: echo "${{ github.event.pull_request.title }}"
"#;
        let gha_hits = scan_infra_dos_crypto_and_queues(
            ".github/workflows/pr.yml",
            Language::Config,
            vuln_gha,
        );
        assert!(gha_hits.iter().any(|f| f.rule_id == "SMG-CICD-001"));
        assert!(gha_hits.iter().any(|f| f.rule_id == "SMG-CICD-002"));

        let safe_gha = r#"
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
"#;
        let safe_gha_hits = scan_infra_dos_crypto_and_queues(
            ".github/workflows/pr.yml",
            Language::Config,
            safe_gha,
        );
        assert!(
            safe_gha_hits.is_empty(),
            "Safe env-bound SHA-pinned workflow produced false positives: {:?}",
            safe_gha_hits
        );

        // 2. K8s privileged vs hardened pod
        let vuln_k8s = r#"
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostPID: true
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
      containers:
        - name: app
          securityContext:
            privileged: true
"#;
        let k8s_hits =
            scan_infra_dos_crypto_and_queues("k8s/deploy.yaml", Language::Config, vuln_k8s);
        assert_eq!(
            k8s_hits
                .iter()
                .filter(|f| f.rule_id == "SMG-K8S-001")
                .count(),
            3
        );

        let safe_k8s = r#"
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: true
"#;
        assert!(
            scan_infra_dos_crypto_and_queues("k8s/safe.yaml", Language::Config, safe_k8s)
                .is_empty()
        );

        // 3. ReDoS nested quantifier vs flat regex
        let redos_src =
            r#"const bad = new RegExp("^([a-zA-Z0-9]+)+$"); const ok = /^[a-z0-9_-]{3,32}$/;"#;
        let redos_hits =
            scan_infra_dos_crypto_and_queues("src/val.ts", Language::TypeScript, redos_src);
        assert_eq!(redos_hits.len(), 1);
        assert_eq!(redos_hits[0].rule_id, "SMG-DOS-001");

        // 4. ZipSlip unchecked vs checked
        let zip_vuln =
            "import zipfile\nwith zipfile.ZipFile(p) as z:\n    z.extractall('/tmp/out')\n";
        let zip_hits =
            scan_infra_dos_crypto_and_queues("src/unpack.py", Language::Python, zip_vuln);
        assert_eq!(zip_hits.len(), 1);
        assert_eq!(zip_hits[0].rule_id, "SMG-ZIP-001");

        let zip_safe = "import zipfile, os\nwith zipfile.ZipFile(p) as z:\n    for m in z.infolist():\n        if os.path.realpath(dst).startswith(root): z.extract(m, root)\n";
        assert!(
            scan_infra_dos_crypto_and_queues("src/unpack.py", Language::Python, zip_safe)
                .is_empty()
        );

        // 5. Crypto ECB/timing vs GCM/timingSafeEqual
        let crypto_vuln = "const c = crypto.createCipheriv('aes-256-ecb', key, '');\nif (signature === expectedSig) {}\n";
        let crypto_hits =
            scan_infra_dos_crypto_and_queues("src/crypto.ts", Language::TypeScript, crypto_vuln);
        assert_eq!(crypto_hits.len(), 2);

        let crypto_safe = "const c = crypto.createCipheriv('aes-256-gcm', key, nonce);\nif (crypto.timingSafeEqual(signature, expectedSig)) {}\n";
        assert!(
            scan_infra_dos_crypto_and_queues("src/crypto.ts", Language::TypeScript, crypto_safe)
                .is_empty()
        );
    }
}
