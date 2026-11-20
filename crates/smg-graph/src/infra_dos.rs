use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use smg_core::Language;
use std::collections::HashSet;
use std::sync::OnceLock;

#[allow(clippy::too_many_arguments)]
fn mk_finding_conf(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    confidence: Confidence,
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
        confidence,
        remediation: remediation.to_string(),
    }
}

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
    mk_finding_conf(
        rule_id,
        severity,
        title,
        rel_path,
        line,
        symbol,
        sink_kind,
        missing_guard,
        Confidence::Confirmed,
        remediation,
    )
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

fn strip_yaml_comment(line: &str) -> &str {
    smg_core::yaml::strip_yaml_comment_quoted(line)
}

fn has_untrusted_pr_trigger(lines: &[&str]) -> bool {
    let mut in_on_block = false;
    for raw in lines {
        let code = strip_yaml_comment(raw);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = code.len() - code.trim_start().len();
        if indent == 0 {
            if trimmed.starts_with("on:") {
                let after = trimmed.strip_prefix("on:").unwrap_or("");
                if after.contains("pull_request_target") || after.contains("workflow_run") {
                    return true;
                }
                in_on_block = after.trim().is_empty();
            } else {
                in_on_block = false;
            }
        } else if in_on_block
            && (trimmed.starts_with("pull_request_target")
                || trimmed.starts_with("workflow_run")
                || trimmed.contains("- pull_request_target")
                || trimmed.contains("- workflow_run"))
        {
            return true;
        }
    }
    false
}

fn scan_cicd_workflow(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    let is_gitlab = rel_path.to_ascii_lowercase().ends_with(".gitlab-ci.yml");
    let lines: Vec<&str> = content.lines().collect();
    if is_gitlab {
        for (idx, raw) in lines.iter().enumerate() {
            let ln = idx + 1;
            let trimmed = strip_yaml_comment(raw).trim();
            let low = trimmed.to_ascii_lowercase();
            if low.contains("docker_tls_certdir")
                && (low.ends_with("\"\"") || low.ends_with("''") || low.ends_with(':'))
            {
                out.push(mk_finding(
                    "SMG-CICD-002",
                    "HIGH",
                    "GitLab CI disables Docker-in-Docker TLS (`DOCKER_TLS_CERTDIR: \"\"`)".into(),
                    rel_path,
                    ln,
                    "DOCKER_TLS_CERTDIR",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Keep `DOCKER_TLS_CERTDIR: \"/certs\"` enabled for Docker-in-Docker CI services.",
                ));
            }
            if (low.contains("eval ") || low.contains("sh -c") || low.contains("bash -c"))
                && (trimmed.contains("$CI_MERGE_REQUEST_TITLE")
                    || trimmed.contains("$CI_COMMIT_REF_NAME"))
            {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitLab CI interpolates untrusted MR/branch variable into shell `eval`/`sh -c`".into(),
                    rel_path,
                    ln,
                    "gitlab-ci",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Pass CI variables directly as arguments instead of evaluating them through `eval` or `sh -c`.",
                ));
            }
        }
        return;
    }

    let has_pr_target = has_untrusted_pr_trigger(&lines);

    let mut in_jobs_block = false;
    let mut in_run_block_indent: Option<usize> = None;
    let mut saw_unsafe_checkout = false;
    let mut tainted_workflow_envs: HashSet<String> = HashSet::new();
    for (idx, raw) in lines.iter().enumerate() {
        let ln = idx + 1;
        let code = strip_yaml_comment(raw);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = code.len() - code.trim_start().len();
        if indent == 0 {
            in_jobs_block = trimmed == "jobs:";
            if !in_jobs_block {
                saw_unsafe_checkout = false;
            }
        } else if in_jobs_block
            && indent == 2
            && trimmed.ends_with(':')
            && !trimmed.starts_with('-')
        {
            // Entering a new job under `jobs:` resets per-job unsafe checkout taint
            saw_unsafe_checkout = false;
            in_run_block_indent = None;
        }

        // Track `ENV_NAME: ${{ github.event.* }}` bindings for workflow-to-shell taint correlation
        if let Some((ek, ev)) = trimmed.split_once(':') {
            let ek_clean = ek.trim().trim_start_matches("- ").trim();
            if !ek_clean.is_empty()
                && ek_clean
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !matches!(ek_clean, "run" | "script" | "if" | "name" | "uses" | "with")
                && untrusted_gha_expr_re().is_match(ev)
            {
                tainted_workflow_envs.insert(ek_clean.to_string());
            }
        }

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

        // Unpinned mutable ref (`@main` etc. Confirmed) & unpinned 3rd-party `@v*` tag (Heuristic)
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
            } else if !action.starts_with("actions/")
                && !action.starts_with("github/")
                && !(reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()))
            {
                out.push(mk_finding_conf(
                    "SMG-CICD-002",
                    "MEDIUM",
                    format!(
                        "Third-party GitHub Action `{}@{}` is pinned to mutable tag instead of commit SHA",
                        action, reference
                    ),
                    rel_path,
                    ln,
                    action,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    Confidence::Heuristic,
                    "Pin third-party GitHub Actions to a full 40-character commit SHA.",
                ));
            }
            if has_pr_target && action == "actions/checkout" {
                saw_unsafe_checkout = false;
                let window = lines[idx..(idx + 6).min(lines.len())].join("\n");
                if window.contains("github.event.pull_request.head.sha")
                    || window.contains("github.event.pull_request.head.ref")
                    || window.contains("github.head_ref")
                {
                    saw_unsafe_checkout = true;
                    out.push(mk_finding(
                        "SMG-CICD-001",
                        "CRITICAL",
                        "GitHub Actions `pull_request_target` checks out untrusted PR head ref (`Pwn-Request` risk)".into(),
                        rel_path,
                        ln,
                        "actions/checkout",
                        SinkKind::Misconfiguration,
                        GuardKind::ConfigPolicy,
                        "Avoid checking out PR head code in privileged `pull_request_target` workflows or isolate builds strictly with `contents: read`.",
                    ));
                }
            }
        }
        let line_sinks_tainted_env = |shell_line: &str| -> bool {
            if tainted_workflow_envs.is_empty() {
                return false;
            }
            let sl = shell_line.to_ascii_lowercase();
            let has_dangerous_shell_sink = sl.contains("eval ")
                || sl.contains("sh -c")
                || sl.contains("bash -c")
                || shell_line.contains(">> $GITHUB_ENV")
                || shell_line.contains(">> \"$GITHUB_ENV\"")
                || shell_line.contains(">> ${GITHUB_ENV}")
                || shell_line.contains(">> $GITHUB_PATH")
                || shell_line.contains(">> \"$GITHUB_PATH\"");
            if !has_dangerous_shell_sink {
                return false;
            }
            tainted_workflow_envs.iter().any(|var| {
                shell_line.contains(&format!("${}", var))
                    || shell_line.contains(&format!("${{{}}}", var))
            })
        };

        if let Some(run_indent) = in_run_block_indent {
            if indent <= run_indent {
                in_run_block_indent = None;
            } else if ((has_pr_target
                || trimmed.contains("GITHUB_ENV")
                || trimmed.contains("GITHUB_PATH"))
                && untrusted_gha_expr_re().is_match(code))
                || line_sinks_tainted_env(code)
            {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions evaluates untrusted `${{ github.event.* }}` directly inside `run:` / `GITHUB_ENV` (Pwn-Request RCE)".into(),
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
            let rest_low = rest.to_ascii_lowercase();
            let runs_checked_out_code = rest_low.contains("npm ci")
                || rest_low.contains("npm install")
                || rest_low.contains("npm test")
                || rest_low.contains("npm run")
                || rest_low.contains("yarn ")
                || rest_low.contains("pnpm ")
                || rest_low.contains("cargo ")
                || rest_low.contains("make")
                || rest_low.contains("pytest")
                || rest_low.contains("go test")
                || rest_low.contains("./");
            if has_pr_target && saw_unsafe_checkout && runs_checked_out_code {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions `pull_request_target` executes untrusted build/script after checking out PR head".into(),
                    rel_path,
                    ln,
                    "pull_request_target",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Do not execute build scripts (`npm`, `make`, `./script`) after checking out PR head in `pull_request_target`.",
                ));
            }
            if rest.starts_with('|') || rest.starts_with('>') {
                in_run_block_indent = Some(indent);
            } else if ((has_pr_target
                || rest.contains("GITHUB_ENV")
                || rest.contains("GITHUB_PATH"))
                && untrusted_gha_expr_re().is_match(rest))
                || line_sinks_tainted_env(rest)
            {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions interpolates untrusted `${{ github.event.* }}` inside `run:` / `GITHUB_ENV` command (Pwn-Request RCE)".into(),
                    rel_path,
                    ln,
                    "pull_request_target",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Pass untrusted GitHub event context through `env:` instead of inline `${{ ... }}` shell interpolation.",
                ));
            }
        } else if let Some(after_script) = after_dash.strip_prefix("script:") {
            let rest = after_script.trim();
            if rest.starts_with('|') || rest.starts_with('>') {
                in_run_block_indent = Some(indent);
            } else if has_pr_target && untrusted_gha_expr_re().is_match(rest) {
                out.push(mk_finding(
                    "SMG-CICD-001",
                    "CRITICAL",
                    "GitHub Actions `github-script` interpolates untrusted `${{ github.event.* }}` directly inside JS script".into(),
                    rel_path,
                    ln,
                    "github-script",
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Pass `${{ github.event.* }}` via `env:` and read `process.env` inside `github-script`.",
                ));
            }
        }
    }
}

fn scan_kubernetes_manifest(rel_path: &str, content: &str, out: &mut Vec<LocalStaticFinding>) {
    // Split multi-document YAML (`---` / `...`) keeping exact 1-based line alignment via smg-core::yaml
    for doc in smg_core::yaml::split_yaml_documents_preserving_lines(content) {
        let doc_lines: Vec<&str> = doc.lines().collect();
        analyze_k8s_doc(rel_path, 0, &doc_lines, out);
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
                    || p == "/var/run"
                    || p == "/proc"
                    || p == "/sys"
                    || p == "/dev"
                    || p == "/var/lib/kubelet"
                    || p == "/etc/kubernetes"
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
            } else if low == "hostpid: true"
                || low == "hostipc: true"
                || low == "hostnetwork: true"
                || low == "runasuser: 0"
                || low == "type: unconfined"
            {
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
                    "Disable `hostPID`, `hostIPC`, and `hostNetwork` to enforce pod isolation boundaries.",
                ));
            }
        }
    }

    if is_rbac {
        let mut rule_item_indent: Option<usize> = None;
        let mut wildcard_line: Option<usize> = None;
        let mut has_wildcard_resources = false;
        let mut has_wildcard_verbs = false;

        let flush_rbac_rule = |out: &mut Vec<LocalStaticFinding>,
                               has_res: &mut bool,
                               has_verbs: &mut bool,
                               w_line: &mut Option<usize>| {
            if *has_res && *has_verbs {
                out.push(mk_finding(
                    "SMG-K8S-002",
                    "CRITICAL",
                    format!(
                        "Kubernetes `{}` grants wildcard RBAC permissions (`*` verbs on `*`/secrets)",
                        k_str
                    ),
                    rel_path,
                    w_line.unwrap_or(base_line + 1),
                    k_str,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Scope RBAC `resources` and `verbs` strictly to specific resource names and minimal verbs (`get`, `list`).",
                ));
            }
            *has_res = false;
            *has_verbs = false;
            *w_line = None;
        };

        for (idx, raw) in lines.iter().enumerate() {
            let ln = base_line + idx + 1;
            let code = strip_yaml_comment(raw);
            let trimmed = code.trim();
            if trimmed.is_empty() {
                continue;
            }
            let indent = code.len() - code.trim_start().len();
            let low = trimmed.to_ascii_lowercase();

            // Detect start of a new `- ` PolicyRule entry under `rules:`
            if trimmed.starts_with("- ")
                && (low.contains("apigroups:")
                    || low.contains("resources:")
                    || low.contains("verbs:")
                    || rule_item_indent == Some(indent))
            {
                rule_item_indent = Some(indent);
                flush_rbac_rule(
                    out,
                    &mut has_wildcard_resources,
                    &mut has_wildcard_verbs,
                    &mut wildcard_line,
                );
            }

            let field_low = low.strip_prefix("- ").unwrap_or(&low).trim_start();
            if field_low.starts_with("resources:")
                && (field_low.contains("'*'")
                    || field_low.contains("\"*\"")
                    || field_low.contains("secrets"))
            {
                has_wildcard_resources = true;
                wildcard_line.get_or_insert(ln);
            } else if low == "- '*'" || low == "- \"*\"" || low == "- *" || low == "- secrets" {
                if let Some(prev) = lines[..idx].iter().rev().find(|p| p.contains(':')) {
                    let pl = prev.to_ascii_lowercase();
                    if pl.contains("resources:") {
                        has_wildcard_resources = true;
                        wildcard_line.get_or_insert(ln);
                    } else if pl.contains("verbs:") && !low.contains("secrets") {
                        has_wildcard_verbs = true;
                        wildcard_line.get_or_insert(ln);
                    }
                }
            } else if field_low.starts_with("verbs:")
                && (field_low.contains("'*'")
                    || field_low.contains("\"*\"")
                    || field_low.contains("escalate")
                    || field_low.contains("impersonate")
                    || field_low.contains("bind"))
            {
                has_wildcard_verbs = true;
                wildcard_line.get_or_insert(ln);
            }
        }
        flush_rbac_rule(
            out,
            &mut has_wildcard_resources,
            &mut has_wildcard_verbs,
            &mut wildcard_line,
        );
    }
}

fn extract_regex_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Focus strictly on backtracking regex engines (JS, Python, Java, C#, PHP).
        // Linear-time automata (`Go regexp` and `Rust regex`) are excluded to prevent FPs.
        Regex::new(
            r##"(?:new\s+RegExp\s*\(\s*["']([^"'\n]{3,})["']|\bre\.compile\s*\(\s*r?["']([^"'\n]{3,})["']|\bPattern\.compile\s*\(\s*["']([^"'\n]{3,})["']|\bnew\s+Regex\s*\(\s*@?["']([^"'\n]{3,})["']|\bpreg_match(?:_all)?\s*\(\s*["']\/([^"'\n]{3,})\/[a-z]*["'])"##,
        )
        .expect("valid regex extractor")
    })
}

/// Inspects a regex string for nested quantifiers such as `(a+)+`, `(.*)*`, `([a-z]+)*`.
fn has_nested_quantifier_redos(pat: &str) -> bool {
    let bytes = pat.as_bytes();
    // Skip patterns with unambiguous literal separator tokens inside the outer group (e.g. `([a-z0-9-]+\.)+`)
    let mut stack: Vec<(bool, bool)> = Vec::new();
    let mut i = 0usize;
    let mut in_char_class = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            if let Some(top) = stack.last_mut()
                && top.0
                && matches!(bytes.get(i + 1), Some(b'.' | b'-' | b'/' | b':' | b'_'))
            {
                // Escaped literal delimiter following an inner quantifier anchors partitions linearly
                top.0 = false;
            }
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
                // Atomic `(?>...)` and lookaround groups avoid backtracking amplification
                let is_non_bt = bytes.get(i + 1) == Some(&b'?')
                    && matches!(bytes.get(i + 2), Some(b'>' | b'=' | b'!' | b'<'));
                stack.push((false, is_non_bt));
            }
            b')' => {
                let (inner_has_quant, is_non_bt) = stack.pop().unwrap_or((false, false));
                let next_is_unbounded_quant = match bytes.get(i + 1) {
                    Some(b'+' | b'*') => true,
                    Some(b'{') => bytes[i + 1..]
                        .iter()
                        .position(|&c| c == b'}')
                        .and_then(|cl| std::str::from_utf8(&bytes[i + 2..i + 1 + cl]).ok())
                        .is_some_and(|inner| {
                            inner.split_once(',').is_some_and(|(_, max_s)| {
                                max_s.trim().is_empty()
                                    || max_s.trim().parse::<usize>().is_ok_and(|n| n > 3)
                            })
                        }),
                    _ => false,
                };
                if !is_non_bt && inner_has_quant && next_is_unbounded_quant {
                    return true;
                }
                if inner_has_quant && let Some(top) = stack.last_mut() {
                    top.0 = true;
                }
            }
            b'+' | b'*' => {
                if let Some(top) = stack.last_mut() {
                    top.0 = true;
                }
            }
            b'{' => {
                if let Some(close_rel) = bytes[i..].iter().position(|&c| c == b'}')
                    && let Some(inner) = std::str::from_utf8(&bytes[i + 1..i + close_rel]).ok()
                    && inner.split_once(',').is_some_and(|(_, max_s)| {
                        max_s.trim().is_empty()
                            || max_s.trim().parse::<usize>().is_ok_and(|n| n > 3)
                    })
                {
                    if let Some(top) = stack.last_mut() {
                        top.0 = true;
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
                out.push(mk_finding_conf(
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
                    Confidence::Heuristic,
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
                    out.push(mk_finding_conf(
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
                        Confidence::Heuristic,
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
    let lines: Vec<&str> = content.lines().collect();
    let has_local_path_containment = |win_low: &str| -> bool {
        win_low.contains("commonpath")
            || win_low.contains("commonprefix")
            || win_low.contains("getcanonicalpath")
            || win_low.contains("..\" in ")
            || win_low.contains("..' in ")
            || win_low.contains("contains(\"..\")")
            || win_low.contains("contains('..')")
            || win_low.contains("filepath.islocal(")
            || win_low.contains("filter=\"data\"")
            || win_low.contains("filter='data'")
            || win_low.contains("filter=\"tar\"")
            || win_low.contains("filter='tar'")
            || win_low.contains("enclosed_name(")
            || (win_low.contains("starts_with")
                && (win_low.contains("canonicalize")
                    || win_low.contains("dest")
                    || win_low.contains("target")
                    || win_low.contains("root")))
            || (win_low.contains("startswith")
                && (win_low.contains("realpath")
                    || win_low.contains("abspath")
                    || win_low.contains("dest")
                    || win_low.contains("target")
                    || win_low.contains("root")))
            || (win_low.contains("hasprefix")
                && (win_low.contains("clean(") || win_low.contains("dest")))
    };

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        let low = trimmed.to_ascii_lowercase();
        let local_win = lines[idx.saturating_sub(15)..(idx + 15).min(lines.len())]
            .join("\n")
            .to_ascii_lowercase();
        if has_local_path_containment(&local_win) {
            continue;
        }
        let is_vuln_extract = match language {
            Language::Python => {
                ((low.contains(".extractall(") || low.contains(".extract("))
                    && (low_all.contains("zipfile") || low_all.contains("tarfile")))
                    || low.contains("shutil.unpack_archive(")
            }
            Language::JavaScript | Language::TypeScript => {
                low.contains(".extractallto(")
                    || low.contains("unzipper.extract(")
                    || low.contains("unzip.extract(")
                    || low.contains("tar.extract(")
                    || low.contains("tar.x(")
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
            r#"(?i)(?:aes-(?:128|192|256)-ecb|des-ede3?(?:-cbc|-ecb)?|['"]rc4['"]|\brc4\.NewCipher\s*\(|\bDES\.new\s*\(|['"]AES/ECB|MODE_ECB|\bmodes\.ECB\s*\(\s*\)|createCipheriv\s*\([^,\n]+,[^,\n]+,\s*(?:['"][0-9a-fA-Fx]{16,}['"]|Buffer\.from\s*\(\s*['"][^'"]+['"]))"#,
        )
        .expect("valid ecb/iv regex")
    })
}

fn secret_timing_cmp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(signature|hmac|cmac|expected_sig|expectedSig|webhook_sig|webhookSig|mac|digest|api_secret|apiSecret|[a-z0-9_]*(?:_signature|_hmac|_digest|_mac|_secret))\s*(?:===|==|!==|!=)\s*([^\s),;&|{}:]+)"#,
        )
        .expect("valid timing cmp regex")
    })
}

fn is_benign_timing_cmp(lhs: &str, rhs: &str) -> bool {
    let lhs_low = lhs.to_ascii_lowercase();
    const BENIGN_LHS_SUFFIXES: &[&str] = &[
        "_type",
        "_kind",
        "_alg",
        "_algo",
        "_algorithm",
        "_scheme",
        "_version",
        "_ver",
        "_mode",
        "_format",
        "_encoding",
        "_len",
        "_length",
        "_size",
        "_count",
        "_header",
        "_name",
        "_addr",
        "_address",
        "_err",
        "_error",
        "_enabled",
        "_valid",
    ];
    if BENIGN_LHS_SUFFIXES.iter().any(|suf| lhs_low.ends_with(suf)) {
        return true;
    }

    let r_trimmed = rhs.trim_end_matches([';', '{', ':']);
    let r_low = r_trimmed.to_ascii_lowercase();
    if matches!(
        r_low.as_str(),
        "\"\""
            | "''"
            | "``"
            | "null"
            | "none"
            | "nil"
            | "undefined"
            | "true"
            | "false"
            | "empty"
            | "0"
            | "-1"
            | "\"nil\""
            | "'nil'"
    ) {
        return true;
    }
    if r_low.contains("length")
        || r_low.contains(".len(")
        || r_low.contains("len(")
        || r_low.contains(".size(")
    {
        return true;
    }
    if (r_trimmed.starts_with('"') && r_trimmed.ends_with('"') && r_trimmed.len() >= 2)
        || (r_trimmed.starts_with('\'') && r_trimmed.ends_with('\'') && r_trimmed.len() >= 2)
        || (r_trimmed.starts_with('`') && r_trimmed.ends_with('`') && r_trimmed.len() >= 2)
    {
        let inner = &r_trimmed[1..r_trimmed.len() - 1];
        if inner.len() < 12 {
            return true;
        }
        let inner_low = inner.to_ascii_lowercase();
        if matches!(
            inner_low.as_str(),
            "hmac-sha256" | "hmac-sha512" | "sha256" | "sha512" | "default" | "not_configured"
        ) {
            return true;
        }
    }
    false
}

fn timing_cmp_confidence(rhs: &str) -> Confidence {
    let low = rhs.to_ascii_lowercase();
    if low.contains("sig")
        || low.contains("hmac")
        || low.contains("mac")
        || low.contains("digest")
        || low.contains("secret")
        || low.contains("token")
        || low.contains("expected")
        || low.contains("computed")
        || low.contains("actual")
        || low.contains("hash")
    {
        Confidence::Confirmed
    } else {
        Confidence::Heuristic
    }
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
                "Broken symmetric cipher configuration (`AES-ECB` / `DES` / `RC4` or static hardcoded IV)".into(),
                rel_path,
                idx + 1,
                "cipher",
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                "Switch to authenticated encryption (`AES-256-GCM` or `ChaCha20-Poly1305`) with a fresh CSPRNG nonce per encryption.",
            ));
        } else if !has_const_time_api
            && let Some(cap) = secret_timing_cmp_re().captures(line)
            && !line.contains("null")
            && !line.contains("None")
            && !line.contains("nil")
            && !line.contains("undefined")
            && !line.contains("length")
            && !line.contains(".len(")
            && !line.contains("len(")
            && !is_benign_timing_cmp(&cap[1], &cap[2])
        {
            out.push(mk_finding_conf(
                "SMG-CRYPTO-001",
                "HIGH",
                "Non-constant-time (`===` / `==`) comparison of cryptographic HMAC/signature enables timing side-channel".into(),
                rel_path,
                idx + 1,
                "signature_compare",
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                timing_cmp_confidence(&cap[2]),
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
        let has_schema_parse = window.match_indices(".parse(").any(|(pos, _)| {
            let prefix = &window[..pos];
            !(prefix.ends_with("json") || prefix.ends_with("date") || prefix.ends_with("url"))
        });
        let has_tenant_or_schema_guard = window.contains("tenantid")
            || window.contains("tenant_id")
            || window.contains("userid")
            || window.contains("user_id")
            || window.contains("zod")
            || has_schema_parse
            || window.contains(".safeparse(")
            || window.contains("validate")
            || window.contains("idempotency");

        if uses_msg_data
            && hits_critical_sink
            && !has_tenant_or_schema_guard
            && seen_lines.insert(idx)
        {
            out.push(mk_finding_conf(
                "SMG-QUEUE-001",
                "HIGH",
                "Async queue worker executes privileged sink directly on job payload without tenant/schema/idempotency validation".into(),
                rel_path,
                idx + 1,
                "async_worker",
                SinkKind::BalanceUpdate,
                GuardKind::InputValidation,
                Confidence::Heuristic,
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

        let benign_digest_go = r#"
func check(digest, macAddress string) bool {
    if digest == "" || digest != "" { return false }
    if digest == "sha256" { return true }
    if macAddress == "aa:bb:cc:dd:ee:ff" { return false }
    return true
}
"#;
        assert!(
            scan_infra_dos_crypto_and_queues("pkg/hash.go", Language::Go, benign_digest_go)
                .is_empty(),
            "Benign empty string / algorithm tag / macAddress checks must not trigger SMG-CRYPTO-001"
        );
    }
}
