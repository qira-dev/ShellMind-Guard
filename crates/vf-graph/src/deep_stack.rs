use crate::ast::{
    Confidence, GuardKind, LocalStaticFinding, SinkKind, SymbolInfo, node_text, strip_comments,
};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tree_sitter::Node;
use vf_core::Language;

fn sql_exec_concat_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:EXECUTE\s+(?:IMMEDIATE\s+)?(?:'[^']*'\s*\|\||\$[A-Za-z_0-9]+|format\s*\([^)]*%s)|sp_executesql\s+[^;]*\+|PREPARE\s+\S+\s+FROM\s+CONCAT\s*\()"#,
        )
        .expect("valid sql dynamic exec regex")
    })
}

fn sql_ident_pw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^;]*\bIDENTIFIED\s+BY\s+'([^']+)'"#)
            .expect("valid sql password regex")
    })
}

fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut in_block = false;
    while i < n {
        if in_block {
            if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                in_block = false;
                i += 2;
                continue;
            }
            if chars[i] == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
            in_block = true;
            i += 2;
            continue;
        }
        if chars[i] == '-' && i + 1 < n && chars[i + 1] == '-' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn make_deep_finding(
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
        line,
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence,
        remediation: remediation.to_string(),
    }
}

/// Deep analyzer for standalone `.sql` schemas, migrations, and stored procedures
/// (Postgres, SQLite, MySQL/MariaDB, MSSQL).
pub fn scan_sql_file(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let cleaned = strip_sql_comments(content);
    let mut findings = Vec::new();

    // Track PL/pgSQL `CREATE FUNCTION ... SECURITY DEFINER` blocks without `SET search_path`
    let mut fn_start_line: Option<usize> = None;
    let mut fn_is_sec_definer = false;
    let mut fn_has_search_path = false;
    let mut fn_sec_definer_line = 0usize;

    for (idx, line) in cleaned.lines().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let low = trimmed.to_ascii_lowercase();

        // 1. Dynamic SQL execution in procedures (`EXECUTE format('...%s...')`, `'...' || var`)
        if sql_exec_concat_re().is_match(trimmed) && !low.contains("using ") {
            findings.push(make_deep_finding(
                "VF-CFG-SQL-EXEC",
                "CRITICAL",
                "Dynamic SQL execution with unescaped `%s` or string concatenation in SQL routine"
                    .into(),
                rel_path,
                ln,
                &format!("{}:{}", rel_path, ln),
                SinkKind::SqlInjection,
                GuardKind::SqlSanitizer,
                Confidence::Confirmed,
                "Use PostgreSQL `%I`/`%L` (`format('... %I ...', tbl)`) with `EXECUTE ... USING $1` or parameterized queries instead of `%s` / `||`.",
            ));
        }

        // 2. PostgreSQL RLS disablement
        if low.contains("disable row level security") || low.contains("no force row level security")
        {
            findings.push(make_deep_finding(
                "VF-CFG-SQL-RLS",
                "HIGH",
                "Row-Level Security (RLS) disabled in SQL migration".into(),
                rel_path,
                ln,
                &format!("{}:{}", rel_path, ln),
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                Confidence::Confirmed,
                "Keep `ENABLE ROW LEVEL SECURITY` / `FORCE ROW LEVEL SECURITY` enforced on multi-tenant tables.",
            ));
        }

        // 3. Over-privileged grants / dangerous DB settings / plaintext password literals
        if low.contains("grant all privileges on *.*")
            || low.contains("grant all on database")
            || (low.contains("alter user") && low.contains("superuser"))
            || (low.contains("alter role") && low.contains("superuser"))
            || (low.contains("pragma") && low.contains("writable_schema") && low.contains("on"))
            || (low.contains("local_infile") && (low.contains("= 1") || low.contains("= on")))
        {
            findings.push(make_deep_finding(
                "VF-CFG-SQL-PRIV",
                "HIGH",
                "Excessive database privilege or unsafe engine pragma (`SUPERUSER` / `GRANT ALL *.*` / `writable_schema`)"
                    .into(),
                rel_path,
                ln,
                &format!("{}:{}", rel_path, ln),
                SinkKind::Misconfiguration,
                GuardKind::ConfigPolicy,
                Confidence::Confirmed,
                "Grant least-privilege table/schema permissions and disable dangerous server settings (`local_infile`, `writable_schema`, `SUPERUSER`).",
            ));
        }

        if let Some(cap) = sql_ident_pw_re().captures(trimmed) {
            let pw = cap[1].trim();
            if !pw.is_empty()
                && !pw.contains('$')
                && !pw.contains("{{")
                && !pw.starts_with("change")
            {
                findings.push(make_deep_finding(
                    "VF-CFG-SQL-PRIV",
                    "HIGH",
                    "Hardcoded database account password inside SQL migration script".into(),
                    rel_path,
                    ln,
                    &format!("{}:{}", rel_path, ln),
                    SinkKind::SecretLeak,
                    GuardKind::SecretPolicy,
                    Confidence::Confirmed,
                    "Inject database credentials via IAM auth or external secret manager variables rather than committing passwords in SQL migrations.",
                ));
            }
        }

        // 4. `CREATE [OR REPLACE] FUNCTION` with `SECURITY DEFINER` missing `SET search_path`
        if low.starts_with("create function ") || low.starts_with("create or replace function ") {
            fn_start_line = Some(ln);
            fn_is_sec_definer = low.contains("security definer");
            fn_has_search_path = low.contains("search_path");
            if fn_is_sec_definer {
                fn_sec_definer_line = ln;
            }
        } else if fn_start_line.is_some() {
            if low.contains("security definer") {
                fn_is_sec_definer = true;
                fn_sec_definer_line = ln;
            }
            if low.contains("search_path") {
                fn_has_search_path = true;
            }
            let closes_fn = low.ends_with("$$;")
                || low.contains("language plpgsql;")
                || low.contains("language sql;")
                || (low.starts_with("$$ language ") && low.ends_with(';'))
                || (low.starts_with('$') && low.contains("language ") && low.ends_with(';'));
            if closes_fn {
                if fn_is_sec_definer && !fn_has_search_path {
                    findings.push(make_deep_finding(
                        "VF-CFG-SQL-SEARCHPATH",
                        "HIGH",
                        "PostgreSQL `SECURITY DEFINER` function missing explicit `SET search_path`"
                            .into(),
                        rel_path,
                        fn_sec_definer_line.max(fn_start_line.unwrap_or(ln)),
                        &format!("{}:{}", rel_path, fn_sec_definer_line),
                        SinkKind::Misconfiguration,
                        GuardKind::ConfigPolicy,
                        Confidence::Confirmed,
                        "Pin `SET search_path = pg_catalog, public` (or empty `SET search_path = ''`) on all `SECURITY DEFINER` functions to prevent object-shadowing privilege escalation.",
                    ));
                }
                fn_start_line = None;
                fn_is_sec_definer = false;
                fn_has_search_path = false;
            }
        }
    }

    if fn_start_line.is_some() && fn_is_sec_definer && !fn_has_search_path {
        findings.push(make_deep_finding(
            "VF-CFG-SQL-SEARCHPATH",
            "HIGH",
            "PostgreSQL `SECURITY DEFINER` function missing explicit `SET search_path`".into(),
            rel_path,
            fn_sec_definer_line,
            &format!("{}:{}", rel_path, fn_sec_definer_line),
            SinkKind::Misconfiguration,
            GuardKind::ConfigPolicy,
            Confidence::Confirmed,
            "Pin `SET search_path = pg_catalog, public` on `SECURITY DEFINER` functions.",
        ));
    }

    findings
}

/// Deep full-stack security analysis across Database/NoSQL/ORM, Backend, and Frontend ASTs.
pub fn scan_ast_deep(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbols: &mut [SymbolInfo],
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    // Only scan target languages explicitly — skips Rust/HCL/Bash from web/JVM patterns automatically.
    if !matches!(
        lang,
        Language::TypeScript
            | Language::JavaScript
            | Language::Python
            | Language::Go
            | Language::Php
            | Language::Java
            | Language::CSharp
            | Language::Kotlin
            | Language::Ruby
    ) {
        return;
    }

    let full_src = std::str::from_utf8(src).unwrap_or("");
    let existing_xss_lines: HashSet<usize> = symbols
        .iter()
        .flat_map(|s| s.local_taint_hits.iter())
        .filter(|h| h.rule_id == "VF-XSS-001")
        .map(|h| h.line)
        .collect();

    if matches!(lang, Language::TypeScript | Language::JavaScript) {
        scan_frontend_ast(
            root,
            src,
            rel_path,
            full_src,
            &existing_xss_lines,
            static_findings,
        );
    }

    scan_backend_and_db_deep(rel_path, lang, full_src, symbols, static_findings);
}

fn scan_frontend_ast(
    node: Node,
    src: &[u8],
    rel_path: &str,
    full_src: &str,
    existing_xss_lines: &HashSet<usize>,
    out: &mut Vec<LocalStaticFinding>,
) {
    let kind = node.kind();
    let line = node.start_position().row + 1;

    // 1. React `dangerouslySetInnerHTML={{ __html: expr }}` without DOMPurify/sanitizeHtml
    if kind == "jsx_attribute" {
        let txt = node_text(node, src);
        if txt.starts_with("dangerouslySetInnerHTML") {
            let low = txt.to_ascii_lowercase();
            let has_san = low.contains("dompurify")
                || low.contains("sanitizehtml")
                || low.contains("sanitize_html")
                || low.contains("escapehtml");
            let is_static_lit = is_static_dangerously_html(txt);
            if !has_san && !is_static_lit && !existing_xss_lines.contains(&line) {
                out.push(make_deep_finding(
                    "VF-XSS-001",
                    "HIGH",
                    "Unsanitized `dangerouslySetInnerHTML` React sink (DOM XSS risk)".into(),
                    rel_path,
                    line,
                    "dangerouslySetInnerHTML",
                    SinkKind::Xss,
                    GuardKind::XssSanitizer,
                    Confidence::Confirmed,
                    "Sanitize HTML with `DOMPurify.sanitize(...)` before passing into `dangerouslySetInnerHTML`, or render structured React JSX instead.",
                ));
            }
        }
    }

    // 2. React / HTML JSX `target="_blank"` missing `rel="noopener noreferrer"` on dynamic/external href
    if kind == "jsx_opening_element" || kind == "jsx_self_closing_element" {
        let txt = node_text(node, src);
        let low = txt.to_ascii_lowercase();
        if (low.contains("target=\"_blank\"") || low.contains("target='_blank'"))
            && (low.contains("href={") || low.contains("http://") || low.contains("https://"))
            && !(low.contains("noopener") && low.contains("noreferrer"))
            && !low.contains("noopener")
        {
            out.push(make_deep_finding(
                "VF-FE-TABNAB",
                "LOW",
                "External `target=\"_blank\"` link missing `rel=\"noopener noreferrer\"`".into(),
                rel_path,
                line,
                "target=_blank",
                SinkKind::FrontendContract,
                GuardKind::FrontendContract,
                Confidence::Confirmed,
                "Add `rel=\"noopener noreferrer\"` to external links opened with `target=\"_blank\"`.",
            ));
        }
    }

    // 3. Browser client calls: `localStorage`/`sessionStorage` token storage, `postMessage` origin flaws, JS URL nav
    if kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let args_txt = node
            .child_by_field_name("arguments")
            .map(|a| node_text(a, src))
            .unwrap_or("");
        let args_low = args_txt.to_ascii_lowercase();

        // 3a. Sensitive auth tokens stored in Web Storage (`localStorage` / `sessionStorage`)
        if matches!(ftxt, "localStorage.setItem" | "sessionStorage.setItem")
            && is_sensitive_storage_item(&args_low)
        {
            out.push(make_deep_finding(
                "VF-FE-STORAGE",
                "MEDIUM",
                format!(
                    "Authentication credential stored in browser `{}` (XSS token exfiltration risk)",
                    ftxt
                ),
                rel_path,
                line,
                ftxt,
                SinkKind::FrontendContract,
                GuardKind::FrontendContract,
                Confidence::Confirmed,
                "Store session/JWT credentials in `HttpOnly; Secure; SameSite=Lax` cookies instead of `localStorage`/`sessionStorage`.",
            ));
        }

        // 3b. `window.addEventListener("message", handler)` accessing `.data` without `.origin` verification
        if (ftxt == "addEventListener" || ftxt.ends_with(".addEventListener"))
            && (args_low.contains("'message'") || args_low.contains("\"message\""))
            && args_low.contains(".data")
            && !args_low.contains(".origin")
            && !full_src.contains("allowedOrigins")
        {
            out.push(make_deep_finding(
                "VF-FE-MSG",
                "HIGH",
                "`postMessage` event listener accesses `.data` without verifying `event.origin`".into(),
                rel_path,
                line,
                "addEventListener('message')",
                SinkKind::FrontendContract,
                GuardKind::FrontendContract,
                Confidence::Confirmed,
                "Check `if (event.origin !== EXPECTED_ORIGIN) return;` at the top of the `message` listener before processing `event.data`.",
            ));
        }

        // 3c. `postMessage(payload, "*")` wildcard targetOrigin
        if (ftxt == "postMessage" || ftxt.ends_with(".postMessage"))
            && (args_txt.contains(", \"*\"")
                || args_txt.contains(",\"*\"")
                || args_txt.contains(", '*'")
                || args_txt.contains(",'*'"))
        {
            out.push(make_deep_finding(
                "VF-FE-MSG",
                "HIGH",
                "`postMessage()` uses wildcard `\"*\"` targetOrigin (cross-origin data leak risk)"
                    .into(),
                rel_path,
                line,
                "postMessage(*)",
                SinkKind::FrontendContract,
                GuardKind::FrontendContract,
                Confidence::Confirmed,
                "Pass an explicit trusted target origin (`https://app.example.com`) instead of `\"*\"` to `postMessage()`.",
            ));
        }

        // 3d. Client `window.open(untrusted)` / `eval(untrusted)` with DOM query source
        if (ftxt == "eval" || ftxt == "window.open")
            && has_dom_untrusted_source(args_txt)
            && !has_url_scheme_guard(full_src)
        {
            let (rid, title) = if ftxt == "eval" {
                (
                    "VF-XSS-001",
                    "Client DOM XSS / arbitrary JS execution via `eval()` with URL parameters"
                        .into(),
                )
            } else {
                (
                    "VF-SSRF-REDIRECT",
                    "Unsafe client navigation via `window.open()` with unvalidated URL parameters"
                        .into(),
                )
            };
            out.push(make_deep_finding(
                rid,
                "HIGH",
                title,
                rel_path,
                line,
                ftxt,
                if rid == "VF-XSS-001" {
                    SinkKind::Xss
                } else {
                    SinkKind::Ssrf
                },
                if rid == "VF-XSS-001" {
                    GuardKind::XssSanitizer
                } else {
                    GuardKind::SsrfSanitizer
                },
                Confidence::Confirmed,
                "Validate scheme (`https:`/`http:` or relative `/`) and avoid `eval()` completely.",
            ));
        }
    }

    // 4. `window.location.href = userUrl` / `location.assign(userUrl)` with unvalidated URL source
    if kind == "assignment_expression"
        && let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
    {
        let ltxt = node_text(left, src).trim();
        let rtxt = node_text(right, src).trim();
        if (ltxt == "window.location.href"
            || ltxt == "location.href"
            || ltxt == "document.location")
            && has_dom_untrusted_source(rtxt)
            && !has_url_scheme_guard(full_src)
        {
            out.push(make_deep_finding(
                "VF-SSRF-REDIRECT",
                "HIGH",
                format!("Client DOM Open Redirect / `javascript:` URI sink `{}`", ltxt),
                rel_path,
                line,
                ltxt,
                SinkKind::Ssrf,
                GuardKind::SsrfSanitizer,
                Confidence::Confirmed,
                "Parse URLs with `new URL(target, window.location.origin)` and enforce `url.protocol === 'https:'` and same-origin/allowlisted host.",
            ));
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        scan_frontend_ast(ch, src, rel_path, full_src, existing_xss_lines, out);
    }
}

fn scan_backend_and_db_deep(
    rel_path: &str,
    lang: Language,
    full_src: &str,
    symbols: &mut [SymbolInfo],
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    let all_lines: Vec<&str> = full_src.lines().collect();
    if all_lines.is_empty() {
        return;
    }

    // File-wide XML XXE check when XML factory is instantiated without disabling external entities.
    let cleaned_full = strip_comments(full_src);
    let full_low = cleaned_full.to_ascii_lowercase();
    check_file_xxe(rel_path, lang, &all_lines, &full_low, static_findings);

    for sym in symbols.iter_mut() {
        let s_idx = sym.line_start.saturating_sub(1);
        let e_idx = sym.line_end.min(all_lines.len());
        if s_idx >= e_idx {
            continue;
        }
        let body_lines = &all_lines[s_idx..e_idx];
        let raw_block = body_lines.join("\n");
        let clean_block = strip_comments(&raw_block);
        let block_low = clean_block.to_ascii_lowercase();

        // Track simple local variable aliases of raw request input objects (`const filter = req.body;`)
        let mut raw_obj_vars: HashSet<String> = HashSet::new();
        let mut scalar_taint_vars: HashSet<String> = HashSet::new();
        let has_schema_validation = block_low.contains(".parse(")
            || block_low.contains(".safeparse(")
            || block_low.contains("joi.")
            || block_low.contains("mongosanitize")
            || block_low.contains("mongo_sanitize")
            || block_low.contains(".permit(")
            || block_low.contains("validatedata")
            || block_low.contains("pydantic");
        let has_proto_guard = block_low.contains("__proto__")
            || block_low.contains("object.hasown")
            || block_low.contains("hasownproperty")
            || block_low.contains("object.create(null)");
        let has_redirect_guard = block_low.contains("allowed_hosts")
            || block_low.contains("allowedhosts")
            || block_low.contains("url_has_allowed_host_and_scheme")
            || block_low.contains("startswith(\"/\")")
            || block_low.contains("startswith('/')");

        let existing_hit_keys: HashSet<(String, usize)> = sym
            .local_taint_hits
            .iter()
            .map(|h| (h.rule_id.clone(), h.line))
            .collect();

        for (offset, line_raw) in body_lines.iter().enumerate() {
            let abs_line = sym.line_start + offset;
            let trimmed = strip_comments(line_raw).trim().to_string();
            if trimmed.is_empty() {
                continue;
            }
            let low = trimmed.to_ascii_lowercase();

            // Track assignments (`const filter = req.body;`, `data = request.json`, `tpl = req.query.tpl`)
            if let Some((lhs, rhs)) = split_simple_assign(&trimmed) {
                let rhs_trim = rhs.trim().trim_end_matches(';');
                if is_raw_request_bag(rhs_trim) {
                    raw_obj_vars.insert(lhs.clone());
                } else {
                    raw_obj_vars.remove(&lhs);
                }
                if contains_request_source(rhs_trim)
                    || scalar_taint_vars
                        .iter()
                        .any(|v| contains_ident(rhs_trim, v))
                {
                    scalar_taint_vars.insert(lhs);
                }
            }

            // 1. MongoDB / NoSQL Operator Injection (`VF-SQLI-NOSQL`) & Redis Lua Eval
            if is_nosql_injection_line(
                &low,
                &raw_obj_vars,
                &scalar_taint_vars,
                has_schema_validation,
            ) {
                sym.local_taint_hits.push(make_deep_finding(
                    "VF-SQLI-NOSQL",
                    "CRITICAL",
                    format!("NoSQL injection risk in `{}` (unvalidated query/operator)", sym.name),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::SqlInjection,
                    GuardKind::SqlSanitizer,
                    Confidence::Confirmed,
                    "Validate request payloads with a strict schema (e.g. Zod/Joi/Pydantic), cast values explicitly (`String(v)`/`ObjectId(v)`), and disallow `$`-prefixed operator keys.",
                ));
            }

            // 2. ORM Mass Assignment (`VF-SQLI-MASS`)
            if is_mass_assignment_line(&low, &raw_obj_vars, has_schema_validation) {
                sym.local_taint_hits.push(make_deep_finding(
                    "VF-SQLI-MASS",
                    "HIGH",
                    format!(
                        "ORM Mass Assignment: raw request body passed directly to DB write in `{}`",
                        sym.name
                    ),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::SqlInjection,
                    GuardKind::SqlSanitizer,
                    Confidence::Confirmed,
                    "Explicitly pick allowlisted fields or validate/strip with Zod, DTO, or Rails `params.permit(...)` before persisting.",
                ));
            }

            // 3. Server-Side Template Injection (`VF-CMDI-SSTI`)
            if is_ssti_sink_line(lang, &trimmed, &low, &scalar_taint_vars) {
                sym.local_taint_hits.push(make_deep_finding(
                    "VF-CMDI-SSTI",
                    "CRITICAL",
                    format!(
                        "Server-Side Template Injection (SSTI) with untrusted template input in `{}`",
                        sym.name
                    ),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::CommandInjection,
                    GuardKind::CmdSanitizer,
                    Confidence::Confirmed,
                    "Pass user values strictly as template context variables to pre-authored static template files rather than compiling untrusted strings.",
                ));
            }

            // 4. Insecure Deserialization (`VF-CMDI-DESER`)
            if is_unsafe_deser_line(lang, &trimmed, &low, &scalar_taint_vars, &block_low) {
                sym.local_taint_hits.push(make_deep_finding(
                    "VF-CMDI-DESER",
                    "CRITICAL",
                    format!("Insecure Deserialization risk in `{}`", sym.name),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::CommandInjection,
                    GuardKind::CmdSanitizer,
                    Confidence::Confirmed,
                    "Use safe structured parsers (`JSON`, `yaml.safe_load`, `YAML.safe_load`, PHP `allowed_classes => false`, or Java `ObjectInputFilter`).",
                ));
            }

            // 5. Prototype Pollution (`VF-CFG-PROTO`, JS/TS)
            if matches!(lang, Language::TypeScript | Language::JavaScript)
                && !has_proto_guard
                && is_proto_pollution_write(&trimmed, &block_low, &raw_obj_vars, &scalar_taint_vars)
                && !existing_hit_keys.contains(&("VF-CFG-PROTO".to_string(), abs_line))
            {
                static_findings.push(make_deep_finding(
                    "VF-CFG-PROTO",
                    "HIGH",
                    format!("Potential Prototype Pollution via unguarded dynamic property merge in `{}`", sym.name),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    Confidence::Confirmed,
                    "Reject `__proto__`, `constructor`, and `prototype` keys (`Object.hasOwn(src, key)`) or use `Map` / `Object.create(null)`.",
                ));
            }

            // 6. Open Redirect (`VF-SSRF-REDIRECT`)
            if !has_redirect_guard
                && is_open_redirect_line(lang, &trimmed, &low, &scalar_taint_vars)
            {
                sym.local_taint_hits.push(make_deep_finding(
                    "VF-SSRF-REDIRECT",
                    "HIGH",
                    format!("Unvalidated Open Redirect via untrusted target URL in `{}`", sym.name),
                    rel_path,
                    abs_line,
                    &sym.name,
                    SinkKind::Ssrf,
                    GuardKind::SsrfSanitizer,
                    Confidence::Confirmed,
                    "Restrict redirect destinations to an explicit domain allowlist or relative paths starting with single `/` (not `//`).",
                ));
            }
        }
    }

    // Track per-file lookup map so unused vars stay zero
    let _ = HashMap::<String, usize>::new();
}

fn check_file_xxe(
    rel_path: &str,
    lang: Language,
    lines: &[&str],
    full_low: &str,
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    if lang == Language::Java
        && (full_low.contains("documentbuilderfactory.newinstance")
            || full_low.contains("saxparserfactory.newinstance")
            || full_low.contains("xmlinputfactory.newinstance"))
        && !(full_low.contains("disallow-doctype-decl")
            || full_low.contains("access_external_dtd")
            || full_low.contains("is_supporting_external_entities"))
    {
        for (i, line) in lines.iter().enumerate() {
            let l = line.to_ascii_lowercase();
            if l.contains("documentbuilderfactory.newinstance")
                || l.contains("saxparserfactory.newinstance")
                || l.contains("xmlinputfactory.newinstance")
            {
                static_findings.push(make_deep_finding(
                    "VF-CFG-XXE",
                    "HIGH",
                    "Java XML parser instantiated without XXE DOCTYPE/external-entity protections"
                        .into(),
                    rel_path,
                    i + 1,
                    &format!("{}:{}", rel_path, i + 1),
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    Confidence::Confirmed,
                    "Set `factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)` and disable external entities.",
                ));
                break;
            }
        }
    }

    if lang == Language::Python
        && !full_low.contains("defusedxml")
        && (full_low.contains("elementtree.fromstring(")
            || full_low.contains("et.fromstring(")
            || full_low.contains("lxml.etree.fromstring(")
            || full_low.contains("minidom.parsestring("))
    {
        for (i, line) in lines.iter().enumerate() {
            let l = line.to_ascii_lowercase();
            if l.contains("fromstring(") || l.contains("parsestring(") {
                static_findings.push(make_deep_finding(
                    "VF-CFG-XXE",
                    "HIGH",
                    "Python standard/lxml XML parser used without `defusedxml` (XXE/billion-laughs risk)"
                        .into(),
                    rel_path,
                    i + 1,
                    &format!("{}:{}", rel_path, i + 1),
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    Confidence::Confirmed,
                    "Replace stdlib `xml.etree`/`minidom` with `defusedxml.ElementTree` when parsing untrusted XML.",
                ));
                break;
            }
        }
    }

    if lang == Language::Php && full_low.contains("libxml_noent") {
        for (i, line) in lines.iter().enumerate() {
            if line.to_ascii_uppercase().contains("LIBXML_NOENT") {
                static_findings.push(make_deep_finding(
                    "VF-CFG-XXE",
                    "HIGH",
                    "PHP XML parser enables `LIBXML_NOENT` (XML External Entity expansion)".into(),
                    rel_path,
                    i + 1,
                    &format!("{}:{}", rel_path, i + 1),
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    Confidence::Confirmed,
                    "Remove `LIBXML_NOENT` flag so XML external entities are not expanded.",
                ));
                break;
            }
        }
    }
}

fn is_static_dangerously_html(attr_txt: &str) -> bool {
    let low = attr_txt.to_ascii_lowercase();
    if let Some(pos) = low.find("__html:") {
        let rest = attr_txt[pos + 7..].trim();
        return (rest.starts_with('"') || rest.starts_with('\''))
            && !rest.contains("${")
            && !rest.contains('+');
    }
    false
}

fn is_sensitive_storage_item(args_low: &str) -> bool {
    let first_arg = args_low.split(',').next().unwrap_or("");
    let auth_key = first_arg.contains("token")
        || first_arg.contains("jwt")
        || first_arg.contains("auth")
        || first_arg.contains("secret")
        || first_arg.contains("session")
        || first_arg.contains("apikey")
        || first_arg.contains("api_key");
    let auth_val = args_low.contains("accesstoken")
        || args_low.contains("access_token")
        || args_low.contains("refreshtoken")
        || args_low.contains("refresh_token")
        || args_low.contains("id_token")
        || args_low.contains("jwt");
    auth_key || auth_val
}

fn has_dom_untrusted_source(expr: &str) -> bool {
    expr.contains("location.search")
        || expr.contains("location.hash")
        || expr.contains("URLSearchParams")
        || expr.contains("searchParams.get")
        || expr.contains("document.URL")
        || expr.contains("document.referrer")
}

fn has_url_scheme_guard(full_src: &str) -> bool {
    let low = full_src.to_ascii_lowercase();
    low.contains("new url(")
        || low.contains(".protocol ===")
        || low.contains(".protocol===")
        || low.contains("startswith(\"https://\")")
        || low.contains("startswith('https://')")
        || low.contains("startswith(\"/\")")
        || low.contains("startswith('/')")
}

fn split_simple_assign(stmt: &str) -> Option<(String, &str)> {
    let s = stmt
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("final ");
    let eq = s.find('=')?;
    if eq == 0 {
        return None;
    }
    let bytes = s.as_bytes();
    if matches!(bytes[eq - 1], b'!' | b'=' | b'<' | b'>')
        || bytes.get(eq + 1).is_some_and(|b| matches!(b, b'=' | b'>'))
    {
        return None;
    }
    let lhs = s[..eq]
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('$');
    if !lhs.is_empty() && lhs.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some((lhs.to_string(), &s[eq + 1..]))
    } else {
        None
    }
}

fn is_raw_request_bag(expr: &str) -> bool {
    let e = expr.trim();
    matches!(
        e,
        "req.body"
            | "req.query"
            | "request.body"
            | "request.query"
            | "request.json"
            | "request.get_json()"
            | "request.data"
            | "request.args"
            | "params"
            | "$_POST"
            | "$_GET"
    )
}

fn contains_request_source(expr: &str) -> bool {
    const SRC: &[&str] = &[
        "req.body",
        "req.query",
        "req.params",
        "request.json",
        "request.get_json",
        "request.args",
        "request.form",
        "request.data",
        "params[",
        "$_GET",
        "$_POST",
        "r.URL.Query",
        "c.Query(",
        "c.Param(",
    ];
    SRC.iter().any(|s| expr.contains(s))
}

fn contains_ident(haystack: &str, ident: &str) -> bool {
    static WORD_RE: OnceLock<Regex> = OnceLock::new();
    let re = WORD_RE.get_or_init(|| Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").unwrap());
    re.find_iter(haystack).any(|m| m.as_str() == ident)
}

fn extract_call_arg_inner<'a>(line: &'a str, call_marker: &str) -> Option<&'a str> {
    let low = line.to_ascii_lowercase();
    let idx = low.find(call_marker)?;
    let rest = &line[idx + call_marker.len()..];
    let end = rest.rfind(')').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

fn is_nosql_injection_line(
    low: &str,
    raw_obj_vars: &HashSet<String>,
    scalar_vars: &HashSet<String>,
    has_schema_validation: bool,
) -> bool {
    if has_schema_validation {
        return false;
    }
    const MONGO_SINKS: &[&str] = &[
        ".find(",
        ".findone(",
        ".findoneandupdate(",
        ".findoneanddelete(",
        ".updateone(",
        ".updatemany(",
        ".deleteone(",
        ".deletemany(",
        ".aggregate(",
    ];

    // Check Redis Lua script injection (`redis.eval(userInput)` / `client.evalsha(...)`)
    if (low.contains("redis.eval(") || low.contains(".evalsha("))
        && (contains_request_source(low)
            || scalar_vars
                .iter()
                .any(|v| contains_ident(low, &v.to_ascii_lowercase())))
    {
        return true;
    }

    for marker in MONGO_SINKS {
        if let Some(arg) = extract_call_arg_inner(low, marker) {
            if arg.is_empty() {
                continue;
            }
            // Direct raw object (`User.findOne(req.body)`, `db.users.find(req.query)`, `find(filter)`)
            let first_arg = arg.split(',').next().unwrap_or(arg).trim();
            if first_arg == "req.body"
                || first_arg == "req.query"
                || first_arg == "request.json"
                || first_arg == "request.args"
                || raw_obj_vars
                    .iter()
                    .any(|v| first_arg == v.to_ascii_lowercase())
            {
                return true;
            }
            // Dangerous `$where` / `$function` / unescaped `$regex` with tainted variables
            if (arg.contains("$where") || arg.contains("$function") || arg.contains("$regex"))
                && !arg.contains("escaperegexp")
                && !arg.contains("re.escape")
                && (contains_request_source(arg)
                    || scalar_vars
                        .iter()
                        .any(|v| contains_ident(arg, &v.to_ascii_lowercase()))
                    || arg.contains("${")
                    || arg.contains('+'))
            {
                return true;
            }
        }
    }
    false
}

fn is_mass_assignment_line(
    low: &str,
    raw_obj_vars: &HashSet<String>,
    has_schema_validation: bool,
) -> bool {
    if has_schema_validation {
        return false;
    }
    for marker in [
        ".create(",
        ".create!(",
        ".insert(",
        ".insertmany(",
        ".bulkcreate(",
    ] {
        if let Some(arg) = extract_call_arg_inner(low, marker) {
            let trimmed = arg.trim();
            if trimmed == "req.body"
                || trimmed == "request.json"
                || trimmed == "**request.data"
                || trimmed == "**request.json"
                || trimmed == "params"
                || trimmed.contains("data: req.body")
                || raw_obj_vars
                    .iter()
                    .any(|v| trimmed == v.to_ascii_lowercase())
            {
                return true;
            }
        }
    }
    false
}

fn is_ssti_sink_line(
    lang: Language,
    trimmed: &str,
    low: &str,
    scalar_vars: &HashSet<String>,
) -> bool {
    let has_taint =
        contains_request_source(trimmed) || scalar_vars.iter().any(|v| contains_ident(trimmed, v));
    if !has_taint {
        return false;
    }
    match lang {
        Language::Python => {
            (low.contains("render_template_string(")
                || low.contains("jinja2.template(")
                || low.contains("template(") && (low.contains("jinja") || low.contains("mako")))
                && !is_first_arg_static_string(trimmed, "(")
        }
        Language::TypeScript | Language::JavaScript => {
            low.contains("ejs.render(")
                || low.contains("pug.render(")
                || low.contains("handlebars.compile(")
                || low.contains("nunjucks.renderstring(")
                || low.contains("lodash.template(")
        }
        Language::Ruby => low.contains("erb.new(") && low.contains("params["),
        Language::Java => low.contains("velocity.evaluate("),
        _ => false,
    }
}

fn is_unsafe_deser_line(
    lang: Language,
    trimmed: &str,
    low: &str,
    scalar_vars: &HashSet<String>,
    block_low: &str,
) -> bool {
    let has_taint = contains_request_source(trimmed)
        || scalar_vars.iter().any(|v| contains_ident(trimmed, v))
        || trimmed.contains("argv")
        || trimmed.contains("payload");
    match lang {
        Language::Python => {
            has_taint
                && (low.contains("pickle.loads(")
                    || low.contains("pickle.load(")
                    || low.contains("marshal.loads(")
                    || (low.contains("yaml.load(") && !low.contains("safeloader")))
        }
        Language::TypeScript | Language::JavaScript => {
            has_taint
                && (low.contains(".unserialize(")
                    || low.contains("vm.runinnewcontext(")
                    || low.contains("vm.runinthiscontext("))
        }
        Language::Php => {
            (trimmed.contains("$_") || has_taint)
                && low.contains("unserialize(")
                && !low.contains("allowed_classes")
        }
        Language::Java => {
            (low.contains("objectinputstream") || low.contains(".readobject("))
                && low.contains(".readobject(")
                && !(block_low.contains("objectinputfilter") || block_low.contains("resolveclass"))
        }
        Language::CSharp => {
            low.contains("binaryformatter") || low.contains("netdatacontractserializer")
        }
        Language::Ruby => {
            (low.contains("marshal.load(") || low.contains("yaml.load("))
                && (low.contains("params[") || has_taint)
        }
        _ => false,
    }
}

fn is_proto_pollution_write(
    trimmed: &str,
    block_low: &str,
    raw_obj_vars: &HashSet<String>,
    scalar_vars: &HashSet<String>,
) -> bool {
    let has_loop_or_req = block_low.contains("for (")
        || block_low.contains("for(")
        || block_low.contains("object.keys(")
        || !raw_obj_vars.is_empty()
        || !scalar_vars.is_empty()
        || contains_request_source(block_low);
    if !has_loop_or_req {
        return false;
    }
    static BRACKET_ASSIGN_RE: OnceLock<Regex> = OnceLock::new();
    let re = BRACKET_ASSIGN_RE.get_or_init(|| {
        Regex::new(r#"^[A-Za-z_$][A-Za-z0-9_$.]*\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*="#)
            .expect("valid bracket assignment regex")
    });
    if let Some(cap) = re.captures(trimmed) {
        let key_var = &cap[1];
        // Numeric index loop vars (`i`, `j`, `k`, `idx`, `index`) on arrays are normal; target property names (`key`, `prop`, `k`, tainted var)
        let is_key_like = matches!(key_var, "key" | "prop" | "attr" | "field" | "path" | "k")
            || scalar_vars.contains(key_var);
        let rhs_is_untrusted = trimmed.contains("[key]")
            || trimmed.contains("[prop]")
            || trimmed.contains("[attr]")
            || contains_request_source(trimmed)
            || !raw_obj_vars.is_empty();
        return is_key_like && rhs_is_untrusted;
    }
    false
}

fn is_open_redirect_line(
    lang: Language,
    trimmed: &str,
    low: &str,
    scalar_vars: &HashSet<String>,
) -> bool {
    let is_sink = match lang {
        Language::TypeScript | Language::JavaScript => low.contains("res.redirect("),
        Language::Python => low.contains("redirect(") || low.contains("redirectresponse("),
        Language::Go => low.contains("http.redirect(") || low.contains("c.redirect("),
        Language::Ruby => low.contains("redirect_to "),
        Language::Php => low.contains("header(") && low.contains("location:"),
        _ => false,
    };
    if !is_sink {
        return false;
    }
    // Safe relative literal (`res.redirect("/dashboard")`) must NEVER fire.
    if let Some(arg) = extract_call_arg_inner(trimmed, "redirect(") {
        let a = arg.trim();
        if (a.starts_with('"') || a.starts_with('\'')) && !a.contains("${") {
            return false;
        }
    }
    contains_request_source(trimmed) || scalar_vars.iter().any(|v| contains_ident(trimmed, v))
}

fn is_first_arg_static_string(trimmed: &str, marker: &str) -> bool {
    if let Some(pos) = trimmed.find(marker) {
        let rest = trimmed[pos + marker.len()..].trim();
        return (rest.starts_with('"') || rest.starts_with('\''))
            && !rest.starts_with("f\"")
            && !rest.starts_with("f'")
            && !rest.contains(" + ")
            && !rest.contains("#{");
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::ast::{FileAstSummary, parse_file_ast};
    use crate::lattice::{GraphAnalysisResult, solve_guard_lattice};
    use std::path::PathBuf;
    use vf_core::{IndexedFile, Language, ShellMindGuardConfig};

    fn run_inline(files: &[(&str, &str)]) -> GraphAnalysisResult {
        let cfg = ShellMindGuardConfig::default();
        let summaries: Vec<FileAstSummary> = files
            .iter()
            .map(|(rel_path, code)| {
                let lang = Language::from_path(std::path::Path::new(rel_path))
                    .unwrap_or_else(|| panic!("unsupported test ext: {}", rel_path));
                let indexed = IndexedFile {
                    rel_path: (*rel_path).to_string(),
                    abs_path: PathBuf::from(rel_path),
                    language: lang,
                    blake3_hash: String::new(),
                    mtime_ns: 0,
                    size_bytes: code.len() as u64,
                    cached_bytes: Some(code.as_bytes().to_vec()),
                };
                parse_file_ast(&indexed, &cfg)
                    .unwrap_or_else(|| panic!("failed to parse {}", rel_path))
            })
            .collect();
        solve_guard_lattice(&summaries)
    }

    #[test]
    fn test_deep_sql_migrations_postgres_sqlite_mysql_vulnerable_vs_hardened() {
        let vuln = run_inline(&[(
            "migrations/001_init.sql",
            r#"
CREATE OR REPLACE FUNCTION admin_exec(tbl text) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    EXECUTE format('DELETE FROM %s', tbl);
END;
$$;

ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;
PRAGMA writable_schema = ON;
ALTER USER app_user WITH SUPERUSER;
"#,
        )]);
        let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"VF-CFG-SQL-SEARCHPATH"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-SQL-EXEC"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-SQL-RLS"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-SQL-PRIV"), "got {:?}", rules);

        let safe = run_inline(&[(
            "migrations/002_safe.sql",
            r#"
CREATE OR REPLACE FUNCTION safe_count(tbl text, uid uuid) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    cnt bigint;
BEGIN
    EXECUTE format('SELECT count(*) FROM %I WHERE owner_id = $1', tbl) INTO cnt USING uid;
    RETURN cnt;
END;
$$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
"#,
        )]);
        assert!(
            safe.findings.is_empty(),
            "expected 0 findings on hardened SQL migration, got: {:#?}",
            safe.findings
        );
    }

    #[test]
    fn test_deep_database_nosql_mass_assignment_and_orm_sql_vulnerable_vs_safe() {
        let vuln = run_inline(&[(
            "src/routes/db.ts",
            r#"import express from 'express';
const app = express();

app.post('/api/users/login', requireAuth, async (req, res) => {
    const user = await User.findOne(req.body);
    await Order.create(req.body);
    await redis.eval(req.body.script);
    await knex.raw(`SELECT * FROM users WHERE email = '${req.query.email}'`);
    res.json(user);
});
"#,
        )]);
        let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"VF-SQLI-NOSQL"), "got {:?}", rules);
        assert!(rules.contains(&"VF-SQLI-MASS"), "got {:?}", rules);
        assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);

        let safe = run_inline(&[(
            "src/routes/db_safe.ts",
            r#"import express from 'express';
import { z } from 'zod';
const app = express();
const LoginSchema = z.object({ email: z.string().email() });

app.post('/api/users/safe', requireAuth, async (req, res) => {
    const input = LoginSchema.parse(req.body);
    const user = await User.findOne({ email: String(input.email) });
    await knex.raw('SELECT * FROM users WHERE email = ?', [input.email]);
    const stmt = db.prepare('SELECT * FROM accounts WHERE email = ?');
    res.json({ user, stmt });
});
"#,
        )]);
        assert!(
            safe.findings.is_empty(),
            "expected 0 findings on schema-validated & parameterized DB route, got: {:#?}",
            safe.findings
        );
    }

    #[test]
    fn test_deep_frontend_dom_storage_postmessage_tabnab_and_client_env() {
        let vuln = run_inline(&[
            (
                "web/Profile.tsx",
                r#"import React, { useEffect } from 'react';

export function Profile({ htmlBio, redirectUrl }: { htmlBio: string; redirectUrl: string }) {
    useEffect(() => {
        localStorage.setItem('accessToken', 'tok-value');
        window.addEventListener('message', (event) => {
            console.log(event.data);
        });
        window.open(new URLSearchParams(window.location.search).get('next') || '/');
    }, []);

    return (
        <div>
            <div dangerouslySetInnerHTML={{ __html: htmlBio }} />
            <a href={redirectUrl} target="_blank">External</a>
        </div>
    );
}
"#,
            ),
            (
                ".env.local",
                "NEXT_PUBLIC_JWT_SECRET=supersecretprodkey123\n",
            ),
        ]);
        let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"VF-XSS-001"), "got {:?}", rules);
        assert!(rules.contains(&"VF-FE-STORAGE"), "got {:?}", rules);
        assert!(rules.contains(&"VF-FE-MSG"), "got {:?}", rules);
        assert!(rules.contains(&"VF-FE-TABNAB"), "got {:?}", rules);
        assert!(rules.contains(&"VF-SSRF-REDIRECT"), "got {:?}", rules);
        assert!(rules.contains(&"VF-SEC-CLIENT-ENV"), "got {:?}", rules);

        let safe = run_inline(&[(
            "web/SafeProfile.tsx",
            r#"import React, { useEffect } from 'react';
import DOMPurify from 'dompurify';

export function SafeProfile({ htmlBio, externalUrl }: { htmlBio: string; externalUrl: string }) {
    useEffect(() => {
        localStorage.setItem('theme', 'dark');
        window.addEventListener('message', (event) => {
            if (event.origin !== 'https://app.example.com') return;
            console.log(event.data);
        });
    }, []);

    return (
        <div>
            <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(htmlBio) }} />
            <a href={externalUrl} target="_blank" rel="noopener noreferrer">Safe</a>
        </div>
    );
}
"#,
        )]);
        assert!(
            safe.findings.is_empty(),
            "expected 0 findings on hardened React frontend, got: {:#?}",
            safe.findings
        );
    }

    #[test]
    fn test_deep_backend_ssti_deser_proto_xxe_redirect_and_weak_jwt() {
        let vuln = run_inline(&[
            (
                "app/views.py",
                r#"import pickle
import xml.etree.ElementTree as ET
from flask import request, render_template_string, redirect

@app.route('/render')
def render_page():
    tpl = request.args.get('tpl')
    obj = pickle.loads(request.data)
    root = ET.fromstring(request.data)
    return render_template_string(tpl)
"#,
            ),
            (
                "src/routes/auth.ts",
                r#"import jwt from 'jsonwebtoken';
app.post('/api/merge', requireAuth, (req, res) => {
    const out: any = {};
    for (const key in req.body) {
        out[key] = req.body[key];
    }
    const token = jwt.sign({ uid: 1 }, 'secret');
    res.redirect(req.query.next);
});
"#,
            ),
        ]);
        let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"VF-CMDI-SSTI"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CMDI-DESER"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-XXE"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-PROTO"), "got {:?}", rules);
        assert!(rules.contains(&"VF-CFG-JWT-LOGIC"), "got {:?}", rules);
        assert!(rules.contains(&"VF-SSRF-REDIRECT"), "got {:?}", rules);

        let safe = run_inline(&[(
            "src/routes/safe_merge.ts",
            r#"import jwt from 'jsonwebtoken';
app.post('/api/safe_merge', requireAuth, (req, res) => {
    const out: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(req.body)) {
        if (key === '__proto__' || key === 'constructor') continue;
        if (Object.hasOwn(req.body, key)) {
            out[key] = req.body[key];
        }
    }
    const token = jwt.sign({ uid: 1 }, process.env.JWT_SECRET!);
    res.redirect('/dashboard');
});
"#,
        )]);
        assert!(
            safe.findings.is_empty(),
            "expected 0 findings on hardened merge/jwt/redirect handler, got: {:#?}",
            safe.findings
        );
    }
}
