use crate::ast::{
    Confidence, GuardKind, ImportRef, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    node_text, strip_comments,
};
use crate::taint::{TAINT_ALL, TAINT_CMD, TAINT_PATH, TAINT_SQL, TAINT_SSRF};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tree_sitter::Node;

use super::{ExtractContext, strip_quotes};

const EXPLICIT_UNTRUSTED_ENVS: &[&str] = &[
    "QUERY_STRING",
    "REQUEST_URI",
    "PATH_INFO",
    "GITHUB_HEAD_REF",
    "GITHUB_REF_NAME",
    "GITHUB_EVENT_PATH",
    "CI_COMMIT_BRANCH",
    "SSH_ORIGINAL_COMMAND",
    "USER_INPUT",
    "PAYLOAD",
];

fn shell_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*|[1-9*@])").expect("valid shell variable regex")
    })
}

fn assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:local|export|readonly|declare)?\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
            .expect("valid bash assignment regex")
    })
}

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    collect_source_imports(root, ctx, 0);

    let mut fn_ranges: Vec<(usize, usize)> = Vec::new();
    collect_functions(root, ctx, &mut fn_ranges, 0);

    // Analyze top-level script commands outside function definitions as `<main>`.
    let full_src = std::str::from_utf8(ctx.src).unwrap_or("");
    let top_lines: Vec<(usize, String)> = full_src
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let line_no = i + 1;
            let inside_fn = fn_ranges.iter().any(|&(s, e)| line_no >= s && line_no <= e);
            if inside_fn {
                None
            } else {
                Some((line_no, strip_comments(line).trim().to_string()))
            }
        })
        .collect();

    let top_sym = analyze_shell_unit(
        ctx,
        root,
        "<main>",
        1,
        full_src.lines().count().max(1),
        &top_lines,
        false,
        &fn_ranges,
    );
    ctx.symbols.push(top_sym);
}

fn collect_source_imports(node: Node, ctx: &mut ExtractContext<'_>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "command"
        && let Some(name_node) = node.child_by_field_name("name")
    {
        let callee = node_text(name_node, ctx.src).trim();
        if matches!(callee, "source" | ".") {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.id() != name_node.id() && ch.is_named() {
                    let arg = strip_quotes(node_text(ch, ctx.src));
                    if !arg.is_empty() && !arg.starts_with('-') {
                        let spec = if arg.starts_with('.') {
                            arg
                        } else {
                            format!("sh::{}", arg.trim_start_matches("./"))
                        };
                        ctx.imports.push(ImportRef {
                            symbol_name: "*".to_string(),
                            from_specifier: spec,
                            remote_name: None,
                        });
                        break;
                    }
                }
            }
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_source_imports(ch, ctx, depth + 1);
    }
}

fn collect_functions(
    node: Node,
    ctx: &mut ExtractContext<'_>,
    fn_ranges: &mut Vec<(usize, usize)>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "function_definition" {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.src).trim().to_string())
            .unwrap_or_default();
        if !name.is_empty() {
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            fn_ranges.push((line_start, line_end));

            let body_node = node.child_by_field_name("body").unwrap_or(node);
            let raw_fn = node_text(node, ctx.src);
            let lines: Vec<(usize, String)> = raw_fn
                .lines()
                .enumerate()
                .map(|(i, l)| (line_start + i, strip_comments(l).trim().to_string()))
                .collect();

            let sym = analyze_shell_unit(
                ctx,
                body_node,
                &name,
                line_start,
                line_end,
                &lines,
                true,
                &[],
            );
            ctx.symbols.push(sym);
            return;
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_functions(ch, ctx, fn_ranges, depth + 1);
    }
}

fn collect_command_calls(
    node: Node,
    src: &[u8],
    is_top_level: bool,
    fn_ranges: &[(usize, usize)],
    out: &mut Vec<String>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if is_top_level && node.kind() == "function_definition" {
        return;
    }
    if is_top_level && !fn_ranges.is_empty() {
        let ln = node.start_position().row + 1;
        if fn_ranges.iter().any(|&(s, e)| ln >= s && ln <= e) {
            return;
        }
    }
    if node.kind() == "command"
        && let Some(n) = node.child_by_field_name("name")
    {
        let callee = node_text(n, src).trim();
        if !callee.is_empty()
            && callee
                .chars()
                .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-')
            && !out.iter().any(|x| x == callee)
        {
            out.push(callee.to_string());
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_command_calls(ch, src, is_top_level, fn_ranges, out, depth + 1);
    }
}

fn collect_pipe_to_shell_lines(
    node: Node,
    src: &[u8],
    is_top_level: bool,
    out: &mut Vec<usize>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if is_top_level && node.kind() == "function_definition" {
        return;
    }
    if node.kind() == "pipeline" {
        let mut has_remote_fetch = false;
        let mut has_shell_exec = false;
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if ch.kind() == "command"
                && let Some(cmd_name) = ch.child_by_field_name("name")
            {
                let name = node_text(cmd_name, src).trim();
                let short = name.rsplit('/').next().unwrap_or(name);
                if matches!(short, "curl" | "wget" | "fetch") {
                    has_remote_fetch = true;
                } else if has_remote_fetch
                    && matches!(short, "sh" | "bash" | "zsh" | "dash" | "eval")
                {
                    has_shell_exec = true;
                }
            }
        }
        if has_remote_fetch && has_shell_exec {
            out.push(node.start_position().row + 1);
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_pipe_to_shell_lines(ch, src, is_top_level, out, depth + 1);
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_shell_unit(
    ctx: &ExtractContext<'_>,
    ast_node: Node,
    name: &str,
    line_start: usize,
    line_end: usize,
    lines: &[(usize, String)],
    is_function: bool,
    fn_ranges: &[(usize, usize)],
) -> SymbolInfo {
    let mut calls = Vec::new();
    collect_command_calls(ast_node, ctx.src, !is_function, fn_ranges, &mut calls, 0);

    let mut pipe_to_shell_lines = Vec::new();
    collect_pipe_to_shell_lines(ast_node, ctx.src, !is_function, &mut pipe_to_shell_lines, 0);

    let mut guards = HashSet::new();
    let mut tainted_vars: HashMap<String, u8> = HashMap::new();
    let mut param_vars: HashSet<String> = HashSet::new();
    let mut fixed_https_origins: HashSet<String> = HashSet::new();
    let mut local_taint_hits: Vec<LocalStaticFinding> = Vec::new();
    let mut param_sinks: Vec<LocalStaticFinding> = Vec::new();
    let mut tainted_calls: Vec<String> = Vec::new();
    let mut tainted_call_masks: HashMap<String, u8> = HashMap::new();

    for pline in pipe_to_shell_lines {
        local_taint_hits.push(LocalStaticFinding {
            rule_id: "SMG-CMDI-001".to_string(),
            severity: "CRITICAL".to_string(),
            title: format!(
                "SMG-CMDI-001 (bash) remote pipe-to-shell execution (`curl|bash`) in `{}`",
                name
            ),
            rel_path: ctx.rel_path.to_string(),
            line: pline,
            symbol: name.to_string(),
            sink_kind: SinkKind::CommandInjection,
            missing_guard: GuardKind::CmdSanitizer,
            confidence: Confidence::Confirmed,
            remediation: "Download to a verified temporary file and verify its SHA-256 checksum or signature before execution instead of piping to `sh`/`bash`."
                .to_string(),
        });
    }

    let mut heredoc_end: Option<String> = None;
    for (abs_line, stmt) in lines {
        let abs_line = *abs_line;
        if let Some(ref end_delim) = heredoc_end {
            if stmt.trim() == end_delim {
                heredoc_end = None;
            }
            continue;
        }
        if let Some(delim) = extract_heredoc_delim(stmt) {
            heredoc_end = Some(delim);
        }
        if stmt.is_empty() {
            continue;
        }
        let low = stmt.to_ascii_lowercase();

        // Allowlist / strictly anchored (`^...$`) regex guard clears variable taint
        if (low.contains("[[") || low.contains("=~")) && stmt.contains('^') && stmt.contains('$') {
            for cap in shell_var_re().captures_iter(stmt) {
                tainted_vars.remove(&cap[1]);
                guards.insert(GuardKind::CmdSanitizer);
            }
        }

        // `read` builtin taints its destination variables directly.
        if let Some(rest) = stmt.strip_prefix("read ") {
            for tok in rest.split_whitespace() {
                if !tok.starts_with('-') && tok.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    tainted_vars.insert(tok.to_string(), TAINT_ALL);
                }
            }
            continue;
        }

        // Assignment propagation (`VAR=...`)
        if let Some(caps) = assign_re().captures(stmt) {
            let lhs = caps[1].to_string();
            let rhs = caps[2].trim();
            let rhs_low = rhs.to_ascii_lowercase();
            let trimmed_unq = rhs.trim_matches(|c| c == '"' || c == '\'');

            // Explicit fixed HTTPS/HTTP literal origin (e.g. `base_url="https://github.com/.../${tag}"`)
            if is_fixed_url_origin(trimmed_unq, &fixed_https_origins) {
                fixed_https_origins.insert(lhs.clone());
            }

            // Explicit safe values (`mktemp`, `uname`, `pwd`, `printf '%q'`, `basename`, `realpath`)
            if is_safe_bash_rhs(&rhs_low) {
                tainted_vars.remove(&lhs);
                param_vars.remove(&lhs);
                continue;
            }

            // Function parameter binding (`local target="$1"`)
            let rhs_positional = has_positional_param(rhs);
            let rhs_explicit = explicit_source_mask(rhs);
            let rhs_var_taint = referenced_taint(rhs, &tainted_vars);

            if is_function && rhs_positional && rhs_explicit == 0 {
                param_vars.insert(lhs.clone());
                tainted_vars.remove(&lhs);
            } else {
                let mut total = rhs_explicit | rhs_var_taint;
                if !is_function && rhs_positional {
                    total |= TAINT_ALL;
                }
                if total != 0 {
                    tainted_vars.insert(lhs, total);
                } else {
                    tainted_vars.remove(&lhs);
                }
            }
            continue;
        }

        // Sanitized command escaping (`printf -v out '%q' "$var"`)
        if low.contains("printf ") && low.contains("%q") {
            guards.insert(GuardKind::CmdSanitizer);
            continue;
        }

        let explicit = explicit_source_mask(stmt);
        let var_taint = referenced_taint(stmt, &tainted_vars);
        let positional = has_positional_param(stmt);
        let top_positional = if !is_function && positional {
            TAINT_ALL
        } else {
            0
        };
        let active_taint = explicit | var_taint | top_positional;
        let uses_fn_param = is_function && (positional || references_any_param(stmt, &param_vars));

        // 1. Command Injection: `eval ...` or `sh -c` / `bash -c` or `$GITHUB_ENV`/`source $var`
        if is_eval_or_shell_c_sink(&low) {
            if (active_taint & TAINT_CMD) != 0 {
                push_shell_finding(
                    &mut local_taint_hits,
                    "SMG-CMDI-001",
                    "CRITICAL",
                    &format!(
                        "SMG-CMDI-001 (bash) command injection via dynamic shell evaluation in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::CommandInjection,
                    GuardKind::CmdSanitizer,
                    Confidence::Confirmed,
                    "Avoid `eval` and `sh -c`/`bash -c` with dynamic variables; invoke commands directly with quoted array elements.",
                );
            } else if uses_fn_param {
                push_shell_finding(
                    &mut param_sinks,
                    "SMG-CMDI-001",
                    "CRITICAL",
                    &format!(
                        "SMG-CMDI-001 (bash) parameter reaches shell evaluation in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::CommandInjection,
                    GuardKind::CmdSanitizer,
                    Confidence::Heuristic,
                    "Validate parameters against an allowlist and avoid `eval` / `sh -c`.",
                );
            }
        } else if is_github_env_or_dynamic_source(stmt, &low) && (active_taint & TAINT_CMD) != 0 {
            push_shell_finding(
                &mut local_taint_hits,
                "SMG-CMDI-001",
                "CRITICAL",
                &format!(
                    "SMG-CMDI-001 (bash) untrusted variable written to GITHUB_ENV/GITHUB_PATH or sourced dynamically in `{}`",
                    name
                ),
                ctx.rel_path,
                abs_line,
                name,
                SinkKind::CommandInjection,
                GuardKind::CmdSanitizer,
                Confidence::Confirmed,
                "Sanitize multiline newlines/values before writing to `$GITHUB_ENV` / `$GITHUB_PATH`, and never `source` dynamic user-controlled file paths.",
            );
        }

        // 2. SQL Injection via CLI database clients (`psql -c`, `mysql -e`, `sqlite3`)
        if is_db_cli_sql_sink(stmt, &low) {
            if (active_taint & TAINT_SQL) != 0 {
                push_shell_finding(
                    &mut local_taint_hits,
                    "SMG-SQLI-001",
                    "CRITICAL",
                    &format!(
                        "SMG-SQLI-001 (bash) SQL injection in DB CLI invocation in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::SqlInjection,
                    GuardKind::SqlSanitizer,
                    Confidence::Confirmed,
                    "Use `psql -v var=...` bound variables (`:'var'`) instead of interpolating variables into `-c`/`-e` SQL strings.",
                );
            } else if uses_fn_param {
                push_shell_finding(
                    &mut param_sinks,
                    "SMG-SQLI-001",
                    "CRITICAL",
                    &format!(
                        "SMG-SQLI-001 (bash) parameter interpolated into SQL CLI in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::SqlInjection,
                    GuardKind::SqlSanitizer,
                    Confidence::Heuristic,
                    "Bind parameters via CLI variable flags instead of string interpolation.",
                );
            }
        }

        // 3. SSRF via `curl` / `wget` when URL scheme/authority is dynamic (not fixed `https://host/...`)
        if let Some(url_arg) = extract_dynamic_url_arg(stmt, &fixed_https_origins) {
            let url_taint = explicit_source_mask(&url_arg)
                | referenced_taint(&url_arg, &tainted_vars)
                | if !is_function && has_positional_param(&url_arg) {
                    TAINT_SSRF
                } else {
                    0
                };
            if (url_taint & TAINT_SSRF) != 0 {
                push_shell_finding(
                    &mut local_taint_hits,
                    "SMG-SSRF-001",
                    "HIGH",
                    &format!("SMG-SSRF-001 (bash) dynamic outbound URL in `{}`", name),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::Ssrf,
                    GuardKind::SsrfSanitizer,
                    Confidence::Confirmed,
                    "Anchor outbound requests to a hardcoded HTTPS scheme and allowlisted hostname.",
                );
            } else if is_function
                && (has_positional_param(&url_arg) || references_any_param(&url_arg, &param_vars))
            {
                push_shell_finding(
                    &mut param_sinks,
                    "SMG-SSRF-001",
                    "HIGH",
                    &format!(
                        "SMG-SSRF-001 (bash) parameter controls outbound URL host in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::Ssrf,
                    GuardKind::SsrfSanitizer,
                    Confidence::Heuristic,
                    "Anchor outbound URLs to an explicit host allowlist.",
                );
            }
        }

        // 4. Destructive / arbitrary Path Traversal (`rm -rf "$untrusted"`, `cat "$untrusted"`, etc.)
        if is_destructive_path_sink(&low) {
            if (active_taint & TAINT_PATH) != 0 {
                push_shell_finding(
                    &mut local_taint_hits,
                    "SMG-PATH-001",
                    "HIGH",
                    &format!(
                        "SMG-PATH-001 (bash) untrusted path in destructive filesystem command in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::PathTraversal,
                    GuardKind::PathSanitizer,
                    Confidence::Confirmed,
                    "Canonicalize paths (`realpath`) or sanitize filenames (`basename`) and verify a fixed base prefix.",
                );
            } else if uses_fn_param {
                push_shell_finding(
                    &mut param_sinks,
                    "SMG-PATH-001",
                    "HIGH",
                    &format!(
                        "SMG-PATH-001 (bash) parameter reaches destructive path sink in `{}`",
                        name
                    ),
                    ctx.rel_path,
                    abs_line,
                    name,
                    SinkKind::PathTraversal,
                    GuardKind::PathSanitizer,
                    Confidence::Heuristic,
                    "Canonicalize and prefix-check path parameters before recursive deletion.",
                );
            }
        }

        // 5. Cross-file tainted helper calls (`run_exec "$USER_INPUT"`)
        for c in &calls {
            if c == name {
                continue;
            }
            if let Some(after) = find_bash_call_args(stmt, c) {
                let c_taint = explicit_source_mask(after)
                    | referenced_taint(after, &tainted_vars)
                    | if !is_function && has_positional_param(after) {
                        TAINT_ALL
                    } else {
                        0
                    };
                if c_taint != 0 {
                    if !tainted_calls.iter().any(|x| x == c) {
                        tainted_calls.push(c.clone());
                    }
                    *tainted_call_masks.entry(c.clone()).or_insert(0) |= c_taint;
                }
            }
        }
    }

    SymbolInfo {
        id: format!("sh:{}:{}:{}", ctx.rel_path, name, line_start),
        rel_path: ctx.rel_path.to_string(),
        name: name.to_string(),
        kind: SymbolKind::Function,
        sink_kind: None,
        line_start,
        line_end,
        guards,
        calls,
        route_path: None,
        has_taint_source: false,
        tainted_calls,
        tainted_call_masks,
        local_taint_hits,
        param_sinks,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn push_shell_finding(
    dst: &mut Vec<LocalStaticFinding>,
    rule_id: &str,
    severity: &str,
    title: &str,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    confidence: Confidence,
    remediation: &str,
) {
    dst.push(LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title: title.to_string(),
        rel_path: rel_path.to_string(),
        line,
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence,
        remediation: remediation.to_string(),
    });
}

fn extract_heredoc_delim(stmt: &str) -> Option<String> {
    if let Some(pos) = stmt.find("<<") {
        let mut rest = &stmt[pos + 2..];
        if let Some(stripped) = rest.strip_prefix('-') {
            rest = stripped;
        }
        // Ignore `<<<` here-string
        if rest.starts_with('<') {
            return None;
        }
        let tok = rest.split_whitespace().next().unwrap_or("");
        let delim = tok.trim_matches(|c| c == '\'' || c == '"' || c == ';');
        if !delim.is_empty()
            && delim
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Some(delim.to_string());
        }
    }
    None
}

fn is_github_env_or_dynamic_source(stmt: &str, low: &str) -> bool {
    if (low.contains(">>") || low.contains('>'))
        && (low.contains("github_env") || low.contains("github_path"))
        && stmt.contains('$')
    {
        return true;
    }
    let trimmed = stmt.trim();
    (trimmed.starts_with("source ") || trimmed.starts_with(". ")) && trimmed.contains('$')
}

fn explicit_source_mask(expr: &str) -> u8 {
    let mut hit = false;
    for cap in shell_var_re().captures_iter(expr) {
        let v = &cap[1];
        if EXPLICIT_UNTRUSTED_ENVS.contains(&v) || v.starts_with("HTTP_") || v.starts_with("INPUT_")
        {
            hit = true;
            break;
        }
    }
    if hit { TAINT_ALL } else { 0 }
}

fn referenced_taint(expr: &str, tainted_vars: &HashMap<String, u8>) -> u8 {
    let mut mask = 0u8;
    for cap in shell_var_re().captures_iter(expr) {
        if let Some(m) = tainted_vars.get(&cap[1]) {
            mask |= *m;
        }
    }
    mask
}

fn has_positional_param(expr: &str) -> bool {
    shell_var_re().captures_iter(expr).any(|cap| {
        let v = &cap[1];
        v == "@" || v == "*" || (v.len() == 1 && v.chars().all(|c| c.is_ascii_digit()))
    })
}

fn references_any_param(expr: &str, params: &HashSet<String>) -> bool {
    shell_var_re()
        .captures_iter(expr)
        .any(|cap| params.contains(&cap[1]))
}

fn contains_word_token(haystack_low: &str, token: &str) -> bool {
    let bytes = haystack_low.as_bytes();
    let mut off = 0usize;
    while let Some(rel) = haystack_low[off..].find(token) {
        let pos = off + rel;
        let end = pos + token.len();
        let prev_ok =
            pos == 0 || (!bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_');
        let next_ok =
            end == bytes.len() || (!bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_');
        if prev_ok && next_ok {
            return true;
        }
        off = pos + 1;
    }
    false
}

fn is_safe_bash_rhs(rhs_low: &str) -> bool {
    contains_word_token(rhs_low, "mktemp")
        || contains_word_token(rhs_low, "uname")
        || contains_word_token(rhs_low, "pwd")
        || contains_word_token(rhs_low, "dirname")
        || contains_word_token(rhs_low, "basename")
        || contains_word_token(rhs_low, "realpath")
        || contains_word_token(rhs_low, "readlink")
        || rhs_low.contains("command -v")
        || rhs_low.contains("printf '%q'")
        || rhs_low.contains("printf \"%q\"")
}

fn is_fixed_url_origin(unq: &str, fixed_origins: &HashSet<String>) -> bool {
    if unq.starts_with("https://") || unq.starts_with("http://") {
        let after_scheme = unq
            .strip_prefix("https://")
            .or_else(|| unq.strip_prefix("http://"))
            .unwrap_or("");
        let authority = after_scheme.split('/').next().unwrap_or("");
        return !authority.is_empty() && !authority.contains('$');
    }
    if let Some(rest) = unq.strip_prefix("${")
        && let Some(end) = rest.find('}')
    {
        return fixed_origins.contains(&rest[..end]);
    }
    if let Some(rest) = unq.strip_prefix('$') {
        let var: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return fixed_origins.contains(&var);
    }
    false
}

fn is_eval_or_shell_c_sink(low: &str) -> bool {
    if (low.starts_with("eval ") || low.contains("; eval ") || low.contains("&& eval "))
        && low.contains('$')
    {
        return true;
    }
    (low.contains("sh -c")
        || low.contains("bash -c")
        || low.contains("zsh -c")
        || low.contains("dash -c"))
        && low.contains('$')
}

fn is_db_cli_sql_sink(stmt: &str, low: &str) -> bool {
    let is_db_client = (low.starts_with("psql ") || low.contains(" psql "))
        && (low.contains(" -c ") || low.contains("--command"))
        || ((low.starts_with("mysql ")
            || low.contains(" mysql ")
            || low.starts_with("mariadb ")
            || low.contains(" mariadb "))
            && (low.contains(" -e ") || low.contains("--execute")))
        || (low.starts_with("sqlite3 ") || low.contains(" sqlite3 "));
    if !is_db_client || !stmt.contains('$') {
        return false;
    }
    let has_sql = low.contains("select ")
        || low.contains("insert ")
        || low.contains("update ")
        || low.contains("delete ");
    has_sql && !low.contains(" -v ") && !low.contains("--set ")
}

fn extract_dynamic_url_arg(stmt: &str, fixed_origins: &HashSet<String>) -> Option<String> {
    let trimmed = stmt.trim();
    if !(trimmed.starts_with("curl ")
        || trimmed.starts_with("wget ")
        || trimmed.contains("$(curl ")
        || trimmed.contains("$(wget "))
    {
        return None;
    }
    for tok in trimmed.split_whitespace().skip(1) {
        let clean = strip_quotes(tok);
        if clean.starts_with('-') || clean.is_empty() || !clean.contains('$') {
            continue;
        }
        // Only treat tokens plausibly representing a URL/endpoint (variable-led or http://..$var/..)
        if clean.starts_with('$') || clean.starts_with("http://") || clean.starts_with("https://") {
            if is_fixed_url_origin(&clean, fixed_origins) {
                return None;
            }
            return Some(clean);
        }
    }
    None
}

fn is_destructive_path_sink(low: &str) -> bool {
    let is_rm = (low.starts_with("rm ") || low.contains(" rm "))
        && (low.contains(" -rf ") || low.contains(" -fr ") || low.contains(" -r "));
    if !is_rm || !low.contains('$') {
        return false;
    }
    !(low.contains("basename ") || low.contains("realpath "))
}

fn find_bash_call_args<'a>(stmt: &'a str, callee: &str) -> Option<&'a str> {
    let needle = format!("{} ", callee);
    let trimmed = stmt.trim();
    if let Some(rest) = trimmed.strip_prefix(&needle) {
        return Some(rest);
    }
    None
}
