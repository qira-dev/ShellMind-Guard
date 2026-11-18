use crate::ast::{Confidence, FrontendApiCall, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use smg_core::Language;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tree_sitter::Node;

pub const TAINT_SQL: u8 = 1 << 0;
pub const TAINT_CMD: u8 = 1 << 1;
pub const TAINT_PATH: u8 = 1 << 2;
pub const TAINT_SSRF: u8 = 1 << 3;
pub const TAINT_XSS: u8 = 1 << 4;
pub const TAINT_ALL: u8 = TAINT_SQL | TAINT_CMD | TAINT_PATH | TAINT_SSRF | TAINT_XSS;

#[derive(Debug, Default)]
pub struct FunctionTaintSummary {
    pub guards: HashSet<GuardKind>,
    pub has_taint_source: bool,
    pub has_resource_id: bool,
    pub has_db_crud_sink: bool,
    pub db_crud_line: Option<usize>,
    pub tainted_calls: Vec<String>,
    pub tainted_call_masks: HashMap<String, u8>,
    pub param_forwarding_calls: Vec<String>,
    pub local_taint_hits: Vec<LocalStaticFinding>,
    pub param_sinks: Vec<LocalStaticFinding>,
    pub has_cookie_session_auth: bool,
    pub has_bearer_header_auth: bool,
    pub csrf_exempt: bool,
    pub tainted_field_calls: HashMap<String, Vec<(String, u8)>>,
    pub param_sink_fields: Vec<(LocalStaticFinding, Option<String>)>,
    pub clears_taint_mask: u8,
    pub clears_field_masks: HashMap<String, u8>,
    pub invokes_callback_mask: u8,
    pub callback_forwards: Vec<(String, String, u8)>,
    pub local_hit_wrappers: Vec<(String, usize, String, Option<String>)>,
    pub tainted_call_wrappers: Vec<(String, String, Option<String>, u8)>,
}

#[derive(Clone, Default)]
struct TaintEnv {
    direct: HashMap<String, u8>,
    params: HashMap<String, u8>,
    sql_vars: HashSet<String>,
    html_vars: HashSet<String>,
    /// Phase 10: field-sensitive taint bitmasks `(base_var, field_name) -> mask`.
    field_direct: HashMap<(String, String), u8>,
    field_params: HashMap<(String, String), u8>,
    sanitized_fields: HashSet<(String, String)>,
    object_vars: HashSet<String>,
    destructured_param_fields: HashMap<String, String>,
    /// Phase 10: `(wrapper_fn_name, optional_field_accessed)` for cross-file wrapper provenance.
    var_wrappers: HashMap<String, (String, Option<String>)>,
    /// Phase 10: `var_name -> bitmask cleared by sanitizers while deriving var_name`.
    var_cleared_masks: HashMap<String, u8>,
    /// Phase 10: `(obj_var, field_name) -> sanitizer bits cleared when creating object literal`.
    object_cleared_fields: HashMap<(String, String), u8>,
    /// Wave 3A: variables known to hold pure compile-time/string literals (must hold on all paths).
    safe_literals: HashSet<String>,
    /// Wave 3A: handler/callback lookup maps (`handlers = { a: fnA, b: fnB }`).
    handler_maps: HashMap<String, Vec<String>>,
    /// Wave 3A: local callable alias bound from a handler map (`const fn = handlers[k]`).
    handler_aliases: HashMap<String, Vec<String>>,
}

impl TaintEnv {
    fn join(&mut self, other: &Self) {
        for (k, v) in &other.direct {
            *self.direct.entry(k.clone()).or_insert(0) |= *v;
        }
        for (k, v) in &other.params {
            *self.params.entry(k.clone()).or_insert(0) |= *v;
        }
        for k in &other.sql_vars {
            self.sql_vars.insert(k.clone());
        }
        for k in &other.html_vars {
            self.html_vars.insert(k.clone());
        }
        for (k, v) in &other.field_direct {
            *self.field_direct.entry(k.clone()).or_insert(0) |= *v;
            self.sanitized_fields.remove(k);
        }
        for (k, v) in &other.field_params {
            *self.field_params.entry(k.clone()).or_insert(0) |= *v;
            self.sanitized_fields.remove(k);
        }
        for k in &other.sanitized_fields {
            if !self.field_direct.contains_key(k) && !self.field_params.contains_key(k) {
                self.sanitized_fields.insert(k.clone());
            }
        }
        for k in &other.object_vars {
            self.object_vars.insert(k.clone());
        }
        for (k, v) in &other.destructured_param_fields {
            self.destructured_param_fields
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.var_wrappers {
            self.var_wrappers
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        // `var_cleared_masks`, `object_cleared_fields`, and `safe_literals` are must-properties:
        // keep only facts guaranteed along BOTH joined control-flow branches.
        self.safe_literals.retain(|k| {
            other.safe_literals.contains(k)
                && !self.direct.contains_key(k)
                && !self.params.contains_key(k)
        });
        for (map_var, targets) in &other.handler_maps {
            let entry = self.handler_maps.entry(map_var.clone()).or_default();
            for t in targets {
                if !entry.contains(t) {
                    entry.push(t.clone());
                }
            }
        }
        for (alias, targets) in &other.handler_aliases {
            let entry = self.handler_aliases.entry(alias.clone()).or_default();
            for t in targets {
                if !entry.contains(t) {
                    entry.push(t.clone());
                }
            }
        }
        self.var_cleared_masks.retain(|k, prev| {
            if let Some(ov) = other.var_cleared_masks.get(k) {
                *prev &= *ov;
                *prev != 0
            } else {
                false
            }
        });
        self.object_cleared_fields.retain(|k, prev| {
            if let Some(ov) = other.object_cleared_fields.get(k) {
                *prev &= *ov;
                *prev != 0
            } else {
                false
            }
        });
    }

    fn join_pair(a: &Self, b: &Self) -> Self {
        let mut out = a.clone();
        out.join(b);
        out
    }

    fn clear_bits_for_vars(&mut self, vars: &HashSet<String>, clear_mask: u8) {
        for v in vars {
            if let Some(m) = self.direct.get_mut(v) {
                *m &= !clear_mask;
                if *m == 0 {
                    self.direct.remove(v);
                }
            }
            if let Some(m) = self.params.get_mut(v) {
                *m &= !clear_mask;
                if *m == 0 {
                    self.params.remove(v);
                }
            }
            let keys: Vec<(String, String)> = self
                .field_direct
                .keys()
                .chain(self.field_params.keys())
                .filter(|(obj, fld)| obj == v || fld == v)
                .cloned()
                .collect();
            for k in keys {
                if let Some(m) = self.field_direct.get_mut(&k) {
                    *m &= !clear_mask;
                    if *m == 0 {
                        self.field_direct.remove(&k);
                    }
                }
                if let Some(m) = self.field_params.get_mut(&k) {
                    *m &= !clear_mask;
                    if *m == 0 {
                        self.field_params.remove(&k);
                    }
                }
            }
            *self.var_cleared_masks.entry(v.clone()).or_insert(0) |= clear_mask;
        }
    }
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").expect("valid ident regex"))
}

fn params_mask_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:req(?:uest)?\.(?:params|query|body|args|json|form|values|data)(?:\.[A-Za-z0-9_]+|\[[^\]]*\])?|c\.(?:Param|Query|DefaultQuery|PostForm)\s*\([^)]*\)|(?:r|req|request)\.(?:PathValue|FormValue|PostFormValue)\s*\([^)]*\)|(?:r|req|request)\.URL\.Query\s*\(\s*\)\.Get\s*\([^)]*\)|chi\.URLParam\s*\([^)]*\)|mux\.Vars\s*\([^)]*\)\s*\[[^\]]*\])"#,
        )
        .expect("valid params mask regex")
    })
}

fn sql_verb_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)\b(?:SELECT\s+(?:\*|DISTINCT\b|COUNT\s*\(|SUM\s*\(|MAX\s*\(|MIN\s*\(|[A-Za-z0-9_`"'.]+(?:\s*,\s*[A-Za-z0-9_`"'.]+)*)\s+FROM\s+[A-Za-z0-9_`"'.]+|INSERT\s+INTO\s+[A-Za-z0-9_`"'.]+|UPDATE\s+[A-Za-z0-9_`"'.]+\s+SET\s+[A-Za-z0-9_`"'.]+\s*=|DELETE\s+FROM\s+[A-Za-z0-9_`"'.]+)\b"#,
        )
        .expect("valid sql verb regex")
    })
}

pub(crate) const MAX_AST_WALK_DEPTH: usize = 512;

/// Returns `true` when a source line is a string-pattern matcher, regex definition,
/// AST codemod literal replacement, or rule catalog example rather than a live runtime call/config.
pub fn is_pattern_matcher_or_doc_line(line: &str) -> bool {
    let t = line.trim();
    t.contains(".contains(\"")
        || t.contains(".contains('")
        || t.contains("has_token_boundary(")
        || t.contains("has_ident_word(")
        || t.contains("has_boundary_match(")
        || t.contains(".starts_with(\"")
        || t.contains(".ends_with(\"")
        || t.contains(".replace(\"")
        || t.contains("Regex::new")
        || t.starts_with("r#\"")
        || t.starts_with("r\"")
        || t.starts_with("vulnerable_example:")
        || t.starts_with("fixed_example:")
        || t.starts_with("title: \"")
        || t.starts_with("description: \"")
        || t.starts_with("remediation: \"")
        || t.starts_with("algorithm: \"")
        || (t.starts_with("(\"") && (t.ends_with("\"),") || t.ends_with("\")")))
        || (t.starts_with('"') && t.ends_with("\","))
}

pub fn strip_comments_simple(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    let mut in_block = false;
    let mut in_line = false;
    let mut str_delim: u8 = 0;
    while i < bytes.len() {
        if in_line {
            if bytes[i] == b'\n' {
                in_line = false;
                out.push(b'\n');
            }
            i += 1;
            continue;
        }
        if in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_block = false;
                i += 2;
            } else {
                if bytes[i] == b'\n' {
                    out.push(b'\n');
                }
                i += 1;
            }
            continue;
        }
        if str_delim != 0 {
            if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1].is_ascii() {
                out.push(bytes[i]);
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if bytes[i] == str_delim || (str_delim != b'`' && bytes[i] == b'\n') {
                str_delim = 0;
            }
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if bytes[i] == b'"'
            || bytes[i] == b'`'
            || (bytes[i] == b'\'' && is_closed_single_quote_literal(bytes, i))
        {
            str_delim = bytes[i];
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_block = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'/'
            && (i == 0 || bytes[i - 1] != b':')
        {
            in_line = true;
            i += 2;
            continue;
        }
        if bytes[i] == b'#'
            && !src[i..].starts_with("#[")
            && !src[i..].starts_with("#![")
            && !src[i..].starts_with("#include")
            && !src[i..].starts_with("#define")
            && !src[i..].starts_with("#ifdef")
            && !src[i..].starts_with("#ifndef")
            && !src[i..].starts_with("#if ")
            && !src[i..].starts_with("#if(")
            && !src[i..].starts_with("#elif")
            && !src[i..].starts_with("#else")
            && !src[i..].starts_with("#endif")
            && !src[i..].starts_with("#pragma")
            && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r'))
        {
            in_line = true;
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

fn is_closed_single_quote_literal(bytes: &[u8], quote_idx: usize) -> bool {
    if quote_idx + 1 < bytes.len()
        && (bytes[quote_idx + 1].is_ascii_alphabetic() || bytes[quote_idx + 1] == b'_')
        && bytes.get(quote_idx + 2) != Some(&b'\'')
    {
        if quote_idx > 0 && matches!(bytes[quote_idx - 1], b'&' | b'<') {
            return false;
        }
        let mut k = quote_idx + 1;
        while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
            k += 1;
        }
        if k < bytes.len() && matches!(bytes[k], b'>' | b':' | b'+' | b')' | b',') {
            return false;
        }
    }
    let mut j = quote_idx + 1;
    while j < bytes.len() && bytes[j] != b'\n' {
        if bytes[j] == b'\\' && j + 1 < bytes.len() {
            j += 2;
            continue;
        }
        if bytes[j] == b'\'' {
            return true;
        }
        if j + 1 < bytes.len()
            && bytes[j] == b'/'
            && (bytes[j + 1] == b'/' || bytes[j + 1] == b'*')
            && (j == 0 || bytes[j - 1] != b':')
        {
            return false;
        }
        j += 1;
    }
    false
}

/// Strips comments and plain prose string literals (`"..."`, `'...'`, `` `...` ``) while preserving
/// decorator/attribute annotations (`@...("...")`, `[Authorize(...)]`), middleware registrations,
/// and SQL `FOR UPDATE` clauses so log messages cannot fabricate or erase security guards.
pub(crate) fn strip_comments_and_non_attr_strings(src: &str) -> String {
    let comment_free = strip_comments_simple(src);
    let mut out = String::with_capacity(comment_free.len());
    for line in comment_free.lines() {
        let trimmed = line.trim_start();
        let keep_line_strings = trimmed.starts_with('@')
            || trimmed.starts_with('[')
            || trimmed.contains("middleware(")
            || trimmed.contains("before_action")
            || trimmed.contains("skip_before_action")
            || trimmed.contains("protect_from_forgery")
            || trimmed.contains("SameSite=")
            || trimmed.to_ascii_lowercase().contains("for update");
        if keep_line_strings {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut str_delim: u8 = 0;
        let mut lit_buf = Vec::new();
        while i < bytes.len() {
            if str_delim != 0 {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == str_delim {
                    str_delim = 0;
                    // Keep SQL queries intact when checking mutations, blank prose strings
                    let lit_low = String::from_utf8_lossy(&lit_buf).to_ascii_lowercase();
                    if lit_low.contains("select ")
                        || lit_low.contains("update ")
                        || lit_low.contains("insert into ")
                        || lit_low.contains("delete from ")
                        || lit_low.contains("for update")
                    {
                        let q = bytes[i] as char;
                        out.push(q);
                        out.push_str(&String::from_utf8_lossy(&lit_buf));
                        out.push(q);
                    } else {
                        out.push_str("\"\"");
                    }
                    lit_buf.clear();
                    i += 1;
                    continue;
                }
                lit_buf.push(bytes[i]);
                i += 1;
                continue;
            }
            if matches!(bytes[i], b'"' | b'\'' | b'`') {
                str_delim = bytes[i];
                lit_buf.clear();
                i += 1;
                continue;
            }
            let ch = line[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        if str_delim != 0 {
            out.push_str("\"\"");
        }
        out.push('\n');
    }
    out
}

/// Scans a template literal `` `...${expr}...` `` recursively (depth-bounded) to extract interpolated expressions.
fn scan_template_literal(
    bytes: &[u8],
    start_after_tick: usize,
    out: &mut Vec<u8>,
    depth: usize,
) -> usize {
    let mut i = start_after_tick;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if depth < 16 && bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            i += 2;
            let mut bd = 1usize;
            while i < bytes.len() && bd > 0 {
                if bytes[i] == b'`' {
                    out.push(b' ');
                    i = scan_template_literal(bytes, i + 1, out, depth + 1);
                    out.push(b' ');
                    continue;
                }
                if bytes[i] == b'{' {
                    bd += 1;
                } else if bytes[i] == b'}' {
                    bd -= 1;
                    if bd == 0 {
                        i += 1;
                        break;
                    }
                }
                out.push(bytes[i]);
                i += 1;
            }
            out.push(b' ');
            continue;
        }
        if bytes[i] == b'`' {
            return i + 1;
        }
        i += 1;
    }
    i
}

/// Extracts non-literal active code spans for taint-source detection:
/// strips plain `"..."` / `'...'` string literals so log/error messages like
/// `throw new Error("missing req.body")` never fabricate taint, while keeping
/// template `${...}` and Python f-string `{...}` interpolations verbatim.
fn extract_active_code_for_taint_sources(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b'"' | b'\'') {
            let is_fstring = i > 0
                && matches!(bytes[i - 1], b'f' | b'F')
                && (i < 2 || !bytes[i - 2].is_ascii_alphanumeric());
            let quote = b;
            i += 1;
            out.push(b' ');
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if is_fstring && bytes[i] == b'{' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    let mut bd = 1usize;
                    while i < bytes.len() && bd > 0 {
                        if bytes[i] == b'{' {
                            bd += 1;
                        } else if bytes[i] == b'}' {
                            bd -= 1;
                            if bd == 0 {
                                i += 1;
                                break;
                            }
                        }
                        out.push(bytes[i]);
                        i += 1;
                    }
                    out.push(b' ');
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b == b'`' {
            out.push(b' ');
            i = scan_template_literal(bytes, i + 1, &mut out, 0);
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

pub fn has_taint_source_expr(text: &str) -> bool {
    const SOURCES: &[&str] = &[
        "req.body",
        "req.query",
        "req.params",
        "req.headers",
        "req.cookies",
        "req.json(",
        "request.body",
        "request.query",
        "request.params",
        "request.cookies",
        "request.args",
        "request.json",
        "request.get_json(",
        "request.form",
        "request.values",
        "request.data",
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.FILES",
        "request.headers",
        "c.Param(",
        "c.Params(",
        "c.Query(",
        "c.DefaultQuery(",
        "c.PostForm(",
        "c.BindJSON(",
        "c.ShouldBindJSON(",
        "c.BodyParser(",
        "c.QueryParser(",
        "r.URL.Query(",
        "req.URL.Query(",
        "r.FormValue(",
        "req.FormValue(",
        "r.PostFormValue(",
        "req.PostFormValue(",
        "r.PathValue(",
        "req.PathValue(",
        "r.Header.Get(",
        "req.Header.Get(",
        "chi.URLParam(",
        "mux.Vars(",
        "ctx.query",
        "ctx.params",
        "ctx.request.body",
        "c.req.query",
        "c.req.param",
        "c.req.json",
        "searchParams.get",
        "window.location.search",
        "window.location.hash",
        "location.search",
        "location.hash",
        "document.URL",
        "document.referrer",
        "URLSearchParams",
        "web::Query",
        "web::Path",
        "web::Json",
        "web::Form",
        "axum::extract::Path",
        "axum::extract::Query",
        "axum::extract::Json",
    ];
    let active = extract_active_code_for_taint_sources(text);
    SOURCES.iter().any(|s| active.contains(s))
}

pub fn has_cookie_session_expr(text: &str) -> bool {
    const INDICATORS: &[&str] = &[
        "req.cookies",
        "req.session",
        "request.cookies",
        "request.COOKIES",
        "request.session",
        "flask.session",
        "express-session",
        "cookie-session",
        "cookieParser",
        "cookie_parser",
        "c.Cookie(",
        "r.Cookie(",
        "http.Cookie",
        "http.SetCookie",
        "django.contrib.sessions",
    ];
    INDICATORS.iter().any(|p| text.contains(p))
}

pub fn has_bearer_header_expr(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    low.contains("headers.authorization")
        || low.contains("headers['authorization']")
        || low.contains("headers[\"authorization\"]")
        || low.contains("header('authorization')")
        || low.contains("header(\"authorization\")")
        || low.contains("header.get(\"authorization\")")
        || low.contains("getheader(\"authorization\")")
        || low.contains("x-api-key")
        || low.contains("httpbearer")
        || low.contains("authorization: bearer")
        || low.contains("\"bearer \"")
        || low.contains("'bearer '")
}

pub fn has_csrf_guard_expr(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    low.contains("csurf")
        || low.contains("csrfprotect")
        || low.contains("csrf_protect")
        || low.contains("lusca.csrf")
        || low.contains("csrfviewmiddleware")
        || low.contains("django.middleware.csrf")
        || low.contains("gin-csrf")
        || low.contains("gorilla/csrf")
        || low.contains("tower_csrf")
        || low.contains("antiforgery")
        || low.contains("verifycsrf")
        || low.contains("validatecsrf")
        || low.contains("csrfmiddleware")
        || (low.contains("samesite") && (low.contains("strict") || low.contains("lax")))
}

pub fn has_global_csrf_middleware(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    low.contains("csurf(")
        || low.contains("csrfprotect(")
        || low.contains("csrf_protect(")
        || low.contains("lusca.csrf")
        || low.contains("csrfviewmiddleware")
        || low.contains("django.middleware.csrf")
        || low.contains("gorilla/csrf")
        || low.contains("gin-csrf")
        || low.contains("tower_csrf")
}

fn strip_comments_and_quoted_strings(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let prev_is_ident = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if !prev_is_ident && bytes[i] == b'r' {
            let mut hashes = 0usize;
            while i + 1 + hashes < bytes.len() && bytes[i + 1 + hashes] == b'#' {
                hashes += 1;
            }
            if i + 1 + hashes < bytes.len() && bytes[i + 1 + hashes] == b'"' {
                out.push_str("  ");
                i += 2 + hashes;
                while i < bytes.len() {
                    if bytes[i] == b'"' {
                        let mut close_hashes = 0usize;
                        while close_hashes < hashes
                            && i + 1 + close_hashes < bytes.len()
                            && bytes[i + 1 + close_hashes] == b'#'
                        {
                            close_hashes += 1;
                        }
                        if close_hashes == hashes {
                            i += 1 + hashes;
                            break;
                        }
                    }
                    out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                    i += 1;
                }
                continue;
            }
        }
        if bytes[i..].starts_with(b"//")
            || (bytes[i] == b'#' && !matches!(bytes.get(i + 1), Some(b'[' | b'!')))
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            out.push_str("  ");
            i += 2;
            while i < bytes.len() {
                if bytes[i..].starts_with(b"*/") {
                    out.push_str("  ");
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"\"\"\"") || bytes[i..].starts_with(b"'''") {
            let delim = if bytes[i] == b'"' { b"\"\"\"" } else { b"'''" };
            out.push_str("   ");
            i += 3;
            while i < bytes.len() {
                if bytes[i..].starts_with(delim) {
                    out.push_str("   ");
                    i += 3;
                    break;
                }
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        if matches!(bytes[i], b'"' | b'`') {
            let quote = bytes[i];
            out.push(' ');
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let b = bytes[i];
                out.push(if b == b'\n' { '\n' } else { ' ' });
                i += 1;
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == quote {
                    break;
                }
            }
            continue;
        }
        if bytes[i] == b'\'' {
            let mut scan = i + 1;
            let mut escaped = false;
            let mut closed_at = None;
            while scan < bytes.len() && bytes[scan] != b'\n' {
                if escaped {
                    escaped = false;
                } else if bytes[scan] == b'\\' {
                    escaped = true;
                } else if bytes[scan] == b'\'' {
                    closed_at = Some(scan + 1);
                    break;
                }
                scan += 1;
            }
            if let Some(end_idx) = closed_at {
                while i < end_idx {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn csrf_exempt_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:@csrf_exempt\b|(?:^|[^.\w])csrf_exempt\s*\(|\bcsrf(?:protection)?\s*:\s*false\b)",
        )
        .unwrap()
    })
}

pub fn has_csrf_exempt_expr(text: &str) -> bool {
    let cleaned = strip_comments_and_quoted_strings(text);
    csrf_exempt_re().is_match(&cleaned)
}

pub fn has_resource_id_expr(text: &str, route_path: Option<&str>) -> bool {
    if let Some(rp) = route_path
        && (rp.contains("/:") || rp.contains("/{") || rp.contains("/[") || rp.contains('<'))
    {
        return true;
    }
    const ID_SOURCES: &[&str] = &[
        "req.params.",
        "req.params[",
        "c.Param(",
        "c.Params(",
        "r.PathValue(",
        "chi.URLParam(",
        "mux.Vars(",
        "request.view_args",
        "Path<",
        "Path(",
        "web::Path",
    ];
    ID_SOURCES.iter().any(|s| text.contains(s))
}

fn ownership_col_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:owner_id|ownerid|tenant_id|tenantid|org_id|orgid|created_by|user_id|userid|account_id|accountid)\s*(?:=|:)\s*([^\s,);\n}]+)",
        )
        .expect("valid ownership col regex")
    })
}

fn ownership_cmp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:==|!=|===|!==)\s*(?:req\.user|request\.user|session\.user|current_user|currentuser|auth\.uid|claims\.)|(?:req\.user|request\.user|session\.user|current_user|currentuser|auth\.uid|claims\.)[^\n;]*?(?:==|!=|===|!==))",
        )
        .expect("valid ownership cmp regex")
    })
}

pub fn has_ownership_filter(code: &str) -> bool {
    has_ownership_filter_with_env(code, None)
}

fn has_ownership_filter_with_env(code: &str, env: Option<&TaintEnv>) -> bool {
    let cleaned = strip_comments_simple(code);
    let masked = params_mask_re().replace_all(&cleaned, "__UNTRUSTED_INPUT__");
    let low = masked.to_ascii_lowercase();

    for cap in ownership_col_re().captures_iter(&low) {
        let rhs = cap[1].trim_matches(|c: char| matches!(c, '\'' | '"' | '`'));
        if rhs.contains("__untrusted_input__") {
            continue;
        }
        let rhs_tainted = env.is_some_and(|e| {
            ident_re().captures_iter(rhs).any(|ic| {
                let id = &ic[1];
                e.direct.keys().any(|k| k.eq_ignore_ascii_case(id))
                    || e.params.keys().any(|k| k.eq_ignore_ascii_case(id))
            })
        });
        if !rhs_tainted {
            return true;
        }
    }
    if ownership_cmp_re().is_match(&low) {
        return true;
    }
    // Check if an authenticated user principal is passed into a DB CRUD statement (single or multi-line),
    // using active non-literal code so log strings containing `"req.user"` cannot spoof ownership.
    let active_low = strip_comments_and_non_attr_strings(&masked).to_ascii_lowercase();
    is_db_crud_stmt(&low)
        && (active_low.contains("req.user")
            || active_low.contains("request.user")
            || active_low.contains("session.user")
            || active_low.contains("current_user")
            || active_low.contains("currentuser")
            || active_low.contains("auth.uid")
            || active_low.contains("claims."))
}

fn is_universal_sanitizer(expr: &str) -> bool {
    const SANITIZERS: &[&str] = &[
        "strconv.Atoi(",
        "strconv.ParseInt(",
        "strconv.ParseUint(",
        "strconv.ParseFloat(",
        "parseInt(",
        "parseFloat(",
        "Number(",
        "BigInt(",
        "Boolean(",
        "z.number(",
        "z.coerce.number(",
        "Uuid::parse_str(",
        "uuid.Parse(",
        "uuid.MustParse(",
        "uuid.UUID(",
        ".parse::<i",
        ".parse::<u",
        ".parse::<f",
        ".parse::<bool",
        ".parse::<Uuid",
    ];
    SANITIZERS.iter().any(|s| expr.contains(s))
}

fn expr_has_path_sanitizer(expr: &str) -> bool {
    const PATH_SAN: &[&str] = &[
        "filepath.Base(",
        "path.basename(",
        "os.path.basename(",
        ".file_name(",
    ];
    PATH_SAN.iter().any(|s| expr.contains(s)) || is_universal_sanitizer(expr)
}

fn stmt_is_path_prefix_guard(stmt: &str) -> bool {
    let has_prefix_check = stmt.contains(".startsWith(")
        || stmt.contains("strings.HasPrefix(")
        || stmt.contains(".starts_with(")
        || stmt.contains("os.path.commonpath(")
        || stmt.contains("..\"");
    if !has_prefix_check
        || !(stmt.contains("if ") || stmt.contains("if(") || stmt.contains("ensure!"))
    {
        return false;
    }
    let low = stmt.to_ascii_lowercase();
    low.contains("path")
        || low.contains("resolve")
        || low.contains("norm")
        || low.contains("root")
        || low.contains("base")
        || low.contains("dir")
        || low.contains("canon")
        || low.contains("real")
        || low.contains("commonpath")
}

fn expr_has_ssrf_sanitizer(expr: &str) -> bool {
    let low = expr.to_ascii_lowercase();
    low.contains("allowlist")
        || low.contains("whitelist")
        || low.contains("allowed_hosts")
        || low.contains("allowedhosts")
        || low.contains("isallowedhost")
        || low.contains("validateurl")
        || is_universal_sanitizer(expr)
}

fn expr_has_cmd_sanitizer(expr: &str) -> bool {
    expr.contains("shlex.quote(")
        || expr.contains("shellEscape(")
        || expr.to_ascii_lowercase().contains("allowlist")
        || is_universal_sanitizer(expr)
}

fn expr_has_xss_sanitizer(expr: &str) -> bool {
    const XSS_SAN: &[&str] = &[
        "DOMPurify.sanitize(",
        "sanitizeHtml(",
        "sanitize_html(",
        "escapeHtml(",
        "escape_html(",
        "html.escape(",
        "markupsafe.escape(",
        "bleach.clean(",
        "html.EscapeString(",
        "he.encode(",
        "ammonia::clean(",
        "validator.escape(",
    ];
    XSS_SAN.iter().any(|s| expr.contains(s)) || is_universal_sanitizer(expr)
}

fn sanitizer_clear_mask(expr: &str) -> u8 {
    if is_universal_sanitizer(expr) {
        return TAINT_ALL;
    }
    let mut clear = 0u8;
    if expr_has_cmd_sanitizer(expr) {
        clear |= TAINT_CMD;
    }
    if expr_has_path_sanitizer(expr) {
        clear |= TAINT_PATH;
    }
    if expr_has_ssrf_sanitizer(expr) {
        clear |= TAINT_SSRF;
    }
    if expr_has_xss_sanitizer(expr) {
        clear |= TAINT_XSS;
    }
    clear
}

fn extract_param_names(fn_node: Node, src: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return out;
    };
    collect_param_idents(params, src, &mut out);
    for fw in [
        "req",
        "res",
        "next",
        "ctx",
        "c",
        "w",
        "r",
        "self",
        "cls",
        "request",
        "response",
        "err",
        "db",
        "tx",
        "pool",
        "session",
        "state",
        "Path",
        "Query",
        "Json",
        "Form",
        "State",
        "Extension",
        "HeaderMap",
        "Depends",
        "Security",
    ] {
        out.remove(fw);
    }
    out
}

fn collect_param_idents(node: Node, src: &[u8], out: &mut HashSet<String>) {
    let k = node.kind();
    let txt = node_text(node, src);
    // Skip DI / server-state parameter nodes (`Depends(...)`, `Security(...)`, `State<...>`, `Extension<...>`, `Data<...>`)
    if matches!(
        k,
        "default_parameter"
            | "typed_default_parameter"
            | "typed_parameter"
            | "parameter"
            | "required_parameter"
    ) && (txt.contains("Depends(")
        || txt.contains("Security(")
        || txt.contains("State<")
        || txt.contains("Extension<")
        || txt.contains("web::Data<")
        || txt.contains("BackgroundTasks")
        || txt.contains(": Session")
        || txt.contains(": AsyncSession"))
    {
        return;
    }
    if matches!(k, "identifier" | "shorthand_property_identifier_pattern") {
        let name = txt.trim();
        if !name.is_empty() && name != "_" {
            out.insert(name.to_string());
        }
        return;
    }
    if k == "parameter_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, src).trim();
            if !name.is_empty() && name != "_" {
                out.insert(name.to_string());
            }
        }
        return;
    }
    if matches!(
        k,
        "type_annotation" | "generic_type" | "pointer_type" | "qualified_type" | "type"
    ) {
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_param_idents(ch, src, out);
    }
}

fn expr_references_any(expr: &str, vars: &HashSet<String>) -> bool {
    if vars.is_empty() {
        return false;
    }
    for cap in ident_re().captures_iter(expr) {
        if vars.contains(&cap[1]) {
            return true;
        }
    }
    false
}

fn extract_assigned_targets<'a>(
    stmt: Node<'a>,
    src: &[u8],
) -> Option<(Vec<String>, Vec<String>, Node<'a>, bool)> {
    let collect_lhs = |n: Node| -> Vec<String> {
        let mut names = Vec::new();
        for cap in ident_re().captures_iter(node_text(n, src)) {
            let id = &cap[1];
            if id != "_" && id != "err" && id != "mut" {
                names.push(id.to_string());
            }
        }
        names
    };
    let k = stmt.kind();
    match k {
        "lexical_declaration" | "variable_declaration" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                if ch.kind() == "variable_declarator"
                    && let (Some(n), Some(v)) = (
                        ch.child_by_field_name("name"),
                        ch.child_by_field_name("value"),
                    )
                {
                    return Some((
                        collect_lhs(n),
                        vec![node_text(n, src).trim().to_string()],
                        v,
                        false,
                    ));
                }
            }
            None
        }
        "expression_statement" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                let is_aug = matches!(
                    ch.kind(),
                    "augmented_assignment_expression" | "augmented_assignment"
                );
                if (matches!(ch.kind(), "assignment_expression" | "assignment") || is_aug)
                    && let (Some(l), Some(r)) = (
                        ch.child_by_field_name("left"),
                        ch.child_by_field_name("right"),
                    )
                {
                    return Some((
                        collect_lhs(l),
                        vec![node_text(l, src).trim().to_string()],
                        r,
                        is_aug,
                    ));
                }
            }
            None
        }
        "short_var_declaration"
        | "assignment_statement"
        | "assignment"
        | "augmented_assignment" => {
            let is_aug = k == "augmented_assignment" || node_text(stmt, src).contains("+=");
            let left = stmt.child_by_field_name("left")?;
            let right = stmt.child_by_field_name("right")?;
            Some((
                collect_lhs(left),
                vec![node_text(left, src).trim().to_string()],
                right,
                is_aug,
            ))
        }
        "let_declaration" => {
            let pat = stmt.child_by_field_name("pattern")?;
            let val = stmt.child_by_field_name("value")?;
            Some((
                collect_lhs(pat),
                vec![node_text(pat, src).trim().to_string()],
                val,
                false,
            ))
        }
        "var_declaration" => {
            let mut c = stmt.walk();
            for ch in stmt.children(&mut c) {
                if ch.kind() == "var_spec"
                    && let (Some(n), Some(v)) = (
                        ch.child_by_field_name("name"),
                        ch.child_by_field_name("value"),
                    )
                {
                    return Some((
                        collect_lhs(n),
                        vec![node_text(n, src).trim().to_string()],
                        v,
                        false,
                    ));
                }
            }
            None
        }
        _ => None,
    }
}

fn is_db_crud_stmt(code: &str) -> bool {
    let low = code.to_ascii_lowercase();
    if low.contains("db.delete(")
        || low.contains("db.update(")
        || low.contains("db.select(")
        || low.contains("db.find(")
        || low.contains("db.get(")
        || low.contains("db.query(")
        || low.contains("db.queryrow(")
        || low.contains("db.exec(")
        || low.contains("tx.exec(")
        || low.contains("pool.query(")
        || low.contains("client.query(")
        || low.contains(".findbyid(")
        || low.contains(".findbyidandupdate(")
        || low.contains(".findbyidanddelete(")
        || low.contains(".findone(")
        || low.contains(".destroy(")
        || low.contains(".filter_by(")
        || low.contains(".objects.get(")
        || low.contains(".objects.filter(")
        || low.contains("cursor.execute(")
        || low.contains("session.query(")
        || ((low.contains("prisma.") || low.contains("db."))
            && (low.contains(".findunique(")
                || low.contains(".findfirst(")
                || low.contains(".findmany(")
                || low.contains(".update(")
                || low.contains(".updatemany(")
                || low.contains(".delete(")
                || low.contains(".deletemany(")))
    {
        return true;
    }
    (low.contains("select ") && low.contains(" from ") && low.contains(" where "))
        || (low.contains("update ") && low.contains(" set ") && low.contains(" where "))
        || (low.contains("delete from ") && low.contains(" where "))
}

#[derive(Clone, Copy)]
enum TaintSourceKind {
    Direct,
    Param,
}

fn html_markup_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)<(?:!doctype|html|head|body|div|span|p|a|h[1-6]|script|iframe|img|svg|ul|ol|li|table|tr|td|form|input|button|b|i|em|strong|pre|code|style|template)(?:\b|[\s>])",
        )
        .expect("valid html markup regex")
    })
}

fn has_html_markup_lit(text: &str) -> bool {
    html_markup_re().is_match(text)
}

pub(crate) fn is_call_sanitizer_for(ftxt: &str, full_txt: &str, sink_mask: u8) -> bool {
    if is_universal_sanitizer(full_txt) {
        return true;
    }
    let short = ftxt.rsplit('.').next().unwrap_or(ftxt);
    let short = short.rsplit("::").next().unwrap_or(short);
    if (sink_mask & TAINT_CMD != 0)
        && (ftxt == "shlex.quote"
            || short == "shellEscape"
            || ftxt.to_ascii_lowercase().contains("allowlist"))
    {
        return true;
    }
    if (sink_mask & TAINT_PATH != 0)
        && matches!(ftxt, "filepath.Base" | "path.basename" | "os.path.basename")
        || ((sink_mask & TAINT_PATH != 0) && short == "file_name")
    {
        return true;
    }
    if (sink_mask & TAINT_SSRF != 0) && expr_has_ssrf_sanitizer(ftxt) {
        return true;
    }
    if (sink_mask & TAINT_XSS != 0)
        && (expr_has_xss_sanitizer(&format!("{}(", ftxt)) || short == "escapeHtml")
    {
        return true;
    }
    false
}

fn is_plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn split_simple_member(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    let (base, field) = trimmed.split_once('.')?;
    let base = base.trim();
    let field = field.trim();
    if is_plain_ident(base) && is_plain_ident(field) {
        Some((base.to_string(), field.to_string()))
    } else {
        None
    }
}

fn extract_member_base_field(node: Node, src: &[u8]) -> Option<(String, String)> {
    let k = node.kind();
    if !matches!(
        k,
        "member_expression"
            | "attribute"
            | "subscript_expression"
            | "field_expression"
            | "selector_expression"
    ) {
        return None;
    }
    let obj = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("operand"))?;
    let base = node_text(obj, src).trim();
    if !is_plain_ident(base) {
        return None;
    }
    let prop_node = node
        .child_by_field_name("property")
        .or_else(|| node.child_by_field_name("attribute"))
        .or_else(|| node.child_by_field_name("field"))
        .or_else(|| node.child_by_field_name("subscript"))
        .or_else(|| node.child_by_field_name("index"))?;
    let field = node_text(prop_node, src)
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if is_plain_ident(field) {
        Some((base.to_string(), field.to_string()))
    } else {
        None
    }
}

fn extract_expr_param_field(node: Node, src: &[u8], env: &TaintEnv) -> Option<String> {
    if let Some((base, field)) = extract_member_base_field(node, src)
        && (env.params.contains_key(&base) || env.field_params.keys().any(|(b, _)| b == &base))
    {
        return Some(field);
    }
    if node.kind() == "identifier" {
        let id = node_text(node, src).trim();
        if let Some(fld) = env.destructured_param_fields.get(id) {
            return Some(fld.clone());
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if let Some(fld) = extract_expr_param_field(ch, src, env) {
            return Some(fld);
        }
    }
    None
}

fn extract_expr_wrapper(
    node: Node,
    src: &[u8],
    env: &TaintEnv,
) -> Option<(String, Option<String>)> {
    let txt = node_text(node, src);
    if has_taint_source_expr(txt) || env.var_wrappers.is_empty() {
        return None;
    }
    if let Some((base, field)) = extract_member_base_field(node, src)
        && let Some((wfn, prev_f)) = env.var_wrappers.get(&base)
    {
        return Some((wfn.clone(), prev_f.clone().or(Some(field))));
    }
    // Unwrap container nodes (`arguments`, `parenthesized_expression`) to preserve `member_expression` field names
    if matches!(
        node.kind(),
        "arguments" | "argument_list" | "parenthesized_expression"
    ) {
        let mut c = node.walk();
        let expr_children: Vec<Node> = node
            .children(&mut c)
            .filter(|ch| !matches!(ch.kind(), "(" | ")" | "," | "comment"))
            .collect();
        if expr_children.len() == 1
            && let Some(res) = extract_expr_wrapper(expr_children[0], src, env)
        {
            return Some(res);
        }
    }
    let mut wrapped: Option<(String, Option<String>)> = None;
    for cap in ident_re().captures_iter(txt) {
        let id = &cap[1];
        if let Some(w) = env.var_wrappers.get(id) {
            match &wrapped {
                None => wrapped = Some(w.clone()),
                Some(prev) if prev != w => return None,
                Some(_) => {}
            }
        } else if env.direct.contains_key(id) || env.params.contains_key(id) {
            // Also mixed with an unwrapped tainted variable -> do not suppress!
            return None;
        }
    }
    wrapped
}

fn expr_call_sanitized_bits(node: Node, src: &[u8], env: &TaintEnv) -> u8 {
    let k = node.kind();
    let txt = node_text(node, src);
    let mut bits = sanitizer_clear_mask(txt);
    if k == "identifier"
        && let Some(&cleared) = env.var_cleared_masks.get(txt.trim())
    {
        bits |= cleared;
    }
    if k == "call_expression" || k == "call" {
        let ftxt = node
            .child_by_field_name("function")
            .map(|f| node_text(f, src).trim())
            .unwrap_or("");
        for bit in [TAINT_SQL, TAINT_CMD, TAINT_PATH, TAINT_SSRF, TAINT_XSS] {
            if is_call_sanitizer_for(ftxt, txt, bit) {
                bits |= bit;
            }
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        bits |= expr_call_sanitized_bits(ch, src, env);
    }
    bits
}

fn ast_eval_masks(node: Node, src: &[u8], env: &TaintEnv) -> (u8, u8) {
    let k = node.kind();
    let txt = node_text(node, src);

    if matches!(
        k,
        "number"
            | "integer_literal"
            | "float_literal"
            | "true"
            | "false"
            | "null"
            | "none"
            | "nil"
            | "undefined"
            | "boolean_literal"
    ) {
        return (0, 0);
    }

    if matches!(
        k,
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "string_fragment"
    ) {
        let mut has_interp = false;
        let mut d = 0u8;
        let mut p = 0u8;
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if matches!(
                ch.kind(),
                "interpolation" | "format_expression" | "template_substitution"
            ) {
                has_interp = true;
                let (cd, cp) = ast_eval_masks(ch, src, env);
                d |= cd;
                p |= cp;
            }
        }
        if has_interp {
            return (d, p);
        }
        // Fallback for non-interpolated template or f-string text nodes without child spans
        if (txt.starts_with('`') && txt.contains("${"))
            || ((txt.starts_with("f\"") || txt.starts_with("f'")) && txt.contains('{'))
        {
            if has_taint_source_expr(txt) {
                return (TAINT_ALL, 0);
            }
            for cap in ident_re().captures_iter(&extract_active_code_for_taint_sources(txt)) {
                let id = &cap[1];
                d |= env.direct.get(id).copied().unwrap_or(0);
                p |= env.params.get(id).copied().unwrap_or(0);
            }
            return (d, p);
        }
        return (0, 0);
    }

    if k == "identifier" {
        let ident = txt.trim();
        let d = env.direct.get(ident).copied().unwrap_or(0);
        let p = env.params.get(ident).copied().unwrap_or(0);
        return (d, p);
    }

    if matches!(
        k,
        "member_expression"
            | "attribute"
            | "subscript_expression"
            | "field_expression"
            | "selector_expression"
    ) {
        if has_taint_source_expr(txt) {
            return (TAINT_ALL, 0);
        }
        if let Some((base, field)) = extract_member_base_field(node, src) {
            let f_direct = env
                .field_direct
                .get(&(base.clone(), field.clone()))
                .copied();
            let f_param = env
                .field_params
                .get(&(base.clone(), field.clone()))
                .copied();
            if f_direct.is_some() || f_param.is_some() {
                return (f_direct.unwrap_or(0), f_param.unwrap_or(0));
            }
            if env
                .sanitized_fields
                .contains(&(base.clone(), field.clone()))
            {
                return (0, 0);
            }
            if env.object_vars.contains(&base) {
                return (0, 0);
            }
        }
        let mut d = 0u8;
        let mut p = 0u8;
        if let Some(obj) = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("value"))
            .or_else(|| node.child_by_field_name("operand"))
        {
            let (od, op) = ast_eval_masks(obj, src, env);
            d |= od;
            p |= op;
        }
        if let Some(sub) = node
            .child_by_field_name("subscript")
            .or_else(|| node.child_by_field_name("index"))
        {
            let (sd, sp) = ast_eval_masks(sub, src, env);
            d |= sd;
            p |= sp;
        }
        return (d, p);
    }

    if k == "call_expression" || k == "call" {
        let ftxt = node
            .child_by_field_name("function")
            .map(|f| node_text(f, src).trim())
            .unwrap_or("");
        let mut d = 0u8;
        let mut p = 0u8;
        if has_taint_source_expr(ftxt)
            || has_taint_source_expr(txt)
                && txt.starts_with(ftxt)
                && (ftxt.contains("req.")
                    || ftxt.contains("request.")
                    || ftxt.contains("c.")
                    || ftxt.contains("r."))
        {
            d |= TAINT_ALL;
        }
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if matches!(ch.kind(), "(" | ")" | ",") {
                continue;
            }
            // For call_expression, skip bare identifier/property function name so helper fn name doesn't match a variable,
            // EXCEPT if `function` contains a chained call like `r.URL.Query().Get`.
            if node
                .child_by_field_name("function")
                .is_some_and(|fn_n| fn_n.id() == ch.id())
            {
                let mut fc = ch.walk();
                for fch in ch.children(&mut fc) {
                    if matches!(fch.kind(), "call_expression" | "call")
                        || node_text(fch, src).contains('(')
                    {
                        let (fd, fp) = ast_eval_masks(fch, src, env);
                        d |= fd;
                        p |= fp;
                    }
                }
                continue;
            }
            let (cd, cp) = ast_eval_masks(ch, src, env);
            d |= cd;
            p |= cp;
        }
        let mut clear = 0u8;
        for bit in [TAINT_SQL, TAINT_CMD, TAINT_PATH, TAINT_SSRF, TAINT_XSS] {
            if is_call_sanitizer_for(ftxt, txt, bit) {
                clear |= bit;
            }
        }
        return (d & !clear, p & !clear);
    }

    let mut d = 0u8;
    let mut p = 0u8;
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        let (cd, cp) = ast_eval_masks(ch, src, env);
        d |= cd;
        p |= cp;
    }
    if d == 0 && has_taint_source_expr(txt) {
        d |= TAINT_ALL;
    }
    (d, p)
}

fn ast_sink_status(
    node: Node,
    src: &[u8],
    sink_mask: u8,
    env: &TaintEnv,
) -> Option<(TaintSourceKind, u8)> {
    let (d, p) = ast_eval_masks(node, src, env);
    if (d & sink_mask) != 0 {
        Some((TaintSourceKind::Direct, d))
    } else if (p & sink_mask) != 0 {
        Some((TaintSourceKind::Param, p))
    } else {
        None
    }
}

fn stmt_taint_status(text: &str, sink_mask: u8, env: &TaintEnv) -> Option<TaintSourceKind> {
    let clear = sanitizer_clear_mask(text);
    if (clear & sink_mask) == sink_mask {
        return None;
    }
    if has_taint_source_expr(text) {
        return Some(TaintSourceKind::Direct);
    }
    for cap in ident_re().captures_iter(&extract_active_code_for_taint_sources(text)) {
        let id = &cap[1];
        if (env.direct.get(id).copied().unwrap_or(0) & sink_mask) != 0 {
            return Some(TaintSourceKind::Direct);
        }
        if (env.params.get(id).copied().unwrap_or(0) & sink_mask) != 0 {
            return Some(TaintSourceKind::Param);
        }
    }
    None
}

fn push_unique_hit(list: &mut Vec<LocalStaticFinding>, hit: LocalStaticFinding) {
    if !list
        .iter()
        .any(|existing| existing.rule_id == hit.rule_id && existing.line == hit.line)
    {
        list.push(hit);
    }
}

fn is_safe_sql_tagged_template(node: Node, src: &[u8]) -> bool {
    if let Some(func) = node.child_by_field_name("function") {
        let ftxt = node_text(func, src).trim();
        let base_ftxt = ftxt.split('<').next().unwrap_or(ftxt).trim();
        let is_safe_tag = !base_ftxt.contains("Unsafe")
            && (base_ftxt.ends_with("$queryRaw")
                || base_ftxt.ends_with("$executeRaw")
                || base_ftxt == "sql"
                || base_ftxt.ends_with(".sql"));
        if is_safe_tag {
            if let Some(args) = node.child_by_field_name("arguments")
                && args.kind() == "template_string"
            {
                return true;
            }
            let mut c = node.walk();
            if node
                .named_children(&mut c)
                .any(|ch| ch.kind() == "template_string")
            {
                return true;
            }
        }
    }
    false
}

fn contains_safe_sql_tagged_template(node: Node, src: &[u8]) -> bool {
    if matches!(
        node.kind(),
        "call_expression" | "tagged_template_expression"
    ) && is_safe_sql_tagged_template(node, src)
    {
        return true;
    }
    let mut c = node.walk();
    for ch in node.named_children(&mut c) {
        if matches!(
            ch.kind(),
            "await_expression"
                | "parenthesized_expression"
                | "call_expression"
                | "tagged_template_expression"
        ) && contains_safe_sql_tagged_template(ch, src)
        {
            return true;
        }
    }
    false
}

fn is_non_sql_log_or_ui_stmt(stmt_code: &str) -> bool {
    let trimmed = stmt_code.trim();
    trimmed.starts_with("console.")
        || trimmed.starts_with("logger.")
        || trimmed.starts_with("log.")
        || trimmed.starts_with("res.send(")
        || trimmed.starts_with("res.json(")
        || trimmed.starts_with("return res.send(")
        || trimmed.starts_with("return res.json(")
        || trimmed.starts_with("throw new Error(")
}

fn is_pure_safe_literal_expr(node: Node, src: &[u8], env: &TaintEnv) -> bool {
    let k = node.kind();
    let txt = node_text(node, src).trim();
    if txt.is_empty() {
        return false;
    }
    if matches!(
        k,
        "number"
            | "integer_literal"
            | "float_literal"
            | "true"
            | "false"
            | "boolean_literal"
            | "string_fragment"
            | "string_content"
    ) {
        return true;
    }
    if matches!(
        k,
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal"
    ) {
        let mut c = node.walk();
        let mut saw_interp = false;
        for ch in node.children(&mut c) {
            if matches!(
                ch.kind(),
                "interpolation" | "format_expression" | "template_substitution"
            ) {
                saw_interp = true;
                let mut ic = ch.walk();
                let mut any_expr = false;
                for ich in ch.children(&mut ic) {
                    if matches!(ich.kind(), "${" | "{" | "}" | "comment") {
                        continue;
                    }
                    any_expr = true;
                    if !is_pure_safe_literal_expr(ich, src, env) {
                        return false;
                    }
                }
                if !any_expr {
                    return false;
                }
            }
        }
        if saw_interp {
            return true;
        }
        if (txt.starts_with('`') && txt.contains("${"))
            || ((txt.starts_with("f\"") || txt.starts_with("f'")) && txt.contains('{'))
        {
            if has_taint_source_expr(txt) {
                return false;
            }
            let active = extract_active_code_for_taint_sources(txt);
            for cap in ident_re().captures_iter(&active) {
                let id = &cap[1];
                if !env.safe_literals.contains(id)
                    || env.direct.contains_key(id)
                    || env.params.contains_key(id)
                {
                    return false;
                }
            }
            return true;
        }
        return true;
    }
    if k == "template_string" {
        if !txt.contains("${") {
            return true;
        }
        let mut c = node.walk();
        let mut saw_sub = false;
        for ch in node.children(&mut c) {
            if matches!(
                ch.kind(),
                "template_substitution" | "interpolation" | "format_expression"
            ) {
                saw_sub = true;
                let mut ic = ch.walk();
                let mut any_expr = false;
                for ich in ch.children(&mut ic) {
                    if matches!(ich.kind(), "${" | "{" | "}" | "comment") {
                        continue;
                    }
                    any_expr = true;
                    if !is_pure_safe_literal_expr(ich, src, env) {
                        return false;
                    }
                }
                if !any_expr {
                    return false;
                }
            }
        }
        return saw_sub;
    }
    if k == "identifier" {
        return env.safe_literals.contains(txt)
            && !env.direct.contains_key(txt)
            && !env.params.contains_key(txt);
    }
    if k == "parenthesized_expression" {
        let mut c = node.walk();
        let inner: Vec<Node> = node
            .children(&mut c)
            .filter(|ch| !matches!(ch.kind(), "(" | ")" | "comment"))
            .collect();
        return inner.len() == 1 && is_pure_safe_literal_expr(inner[0], src, env);
    }
    if matches!(k, "binary_expression" | "binary_operator") && txt.contains('+') {
        let mut c = node.walk();
        let mut any_child = false;
        for ch in node.children(&mut c) {
            if ch.kind() == "+" || ch.kind() == "comment" {
                continue;
            }
            any_child = true;
            if !is_pure_safe_literal_expr(ch, src, env) {
                return false;
            }
        }
        return any_child;
    }
    false
}

fn collect_plus_leaves<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if matches!(node.kind(), "binary_expression" | "binary_operator") {
        let mut c = node.walk();
        let has_plus = node.children(&mut c).any(|ch| ch.kind() == "+");
        if has_plus {
            let mut c2 = node.walk();
            for ch in node.children(&mut c2) {
                if !matches!(ch.kind(), "+" | "comment") {
                    collect_plus_leaves(ch, out);
                }
            }
            return;
        }
    }
    out.push(node);
}

fn extract_callable_target_name(node: Node, src: &[u8]) -> Option<String> {
    let k = node.kind();
    let txt = node_text(node, src).trim();
    if k == "identifier" {
        if is_plain_ident(txt)
            && !matches!(
                txt,
                "true" | "false" | "null" | "undefined" | "None" | "nil" | "this" | "self"
            )
        {
            return Some(txt.to_string());
        }
        return None;
    }
    if matches!(
        k,
        "member_expression" | "attribute" | "field_expression" | "selector_expression"
    ) {
        let short = txt.rsplit('.').next().unwrap_or(txt);
        let short = short.rsplit("::").next().unwrap_or(short).trim();
        if is_plain_ident(short) {
            return Some(short.to_string());
        }
    }
    None
}

fn collect_file_handler_maps(fn_node: Node, src: &[u8]) -> HashMap<String, Vec<String>> {
    let mut maps: HashMap<String, Vec<String>> = HashMap::new();
    let mut root = fn_node;
    while let Some(p) = root.parent() {
        root = p;
    }
    let mut cursor = root.walk();
    for top in root.children(&mut cursor) {
        let mut stmts = vec![top];
        if top.kind() == "export_statement"
            && let Some(decl) = top.child_by_field_name("declaration")
        {
            stmts.push(decl);
        }
        for stmt in stmts {
            if let Some((lhs_names, _, rhs_node, is_aug)) = extract_assigned_targets(stmt, src)
                && !is_aug
                && lhs_names.len() == 1
            {
                let pairs = extract_object_pairs(rhs_node, src);
                if !pairs.is_empty() {
                    let mut targets = Vec::new();
                    for (_, vn) in pairs {
                        if let Some(t) = extract_callable_target_name(vn, src)
                            && !targets.contains(&t)
                        {
                            targets.push(t);
                        }
                    }
                    if !targets.is_empty() {
                        maps.insert(lhs_names[0].clone(), targets);
                    }
                }
            }
        }
    }
    maps
}

fn has_dynamic_sql_interpolation_with_env(node: Node, src: &[u8], env: Option<&TaintEnv>) -> bool {
    let k = node.kind();
    let txt = node_text(node, src);
    if !sql_verb_re().is_match(txt) {
        return false;
    }
    if (k == "call_expression" || k == "tagged_template_expression")
        && is_safe_sql_tagged_template(node, src)
    {
        return false;
    }
    if k == "template_string" && txt.contains("${") {
        if let Some(p) = node.parent()
            && is_safe_sql_tagged_template(p, src)
        {
            return false;
        }
        if let Some(e) = env
            && is_pure_safe_literal_expr(node, src, e)
        {
            return false;
        }
        return true;
    }
    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        if ftxt == "fmt.Sprintf"
            || ftxt.ends_with(".Sprintf")
            || ftxt.ends_with(".format")
            || ftxt.ends_with(".concat")
        {
            return true;
        }
    }
    if k == "macro_invocation" && txt.starts_with("format!") {
        return true;
    }
    if matches!(k, "string" | "concatenated_string")
        && txt.contains('{')
        && (txt.starts_with("f\"")
            || txt.starts_with("f'")
            || txt.starts_with("F\"")
            || txt.starts_with("F'")
            || txt.starts_with("fr\"")
            || txt.starts_with("rf\""))
    {
        if let Some(e) = env
            && is_pure_safe_literal_expr(node, src, e)
        {
            return false;
        }
        return true;
    }
    if matches!(k, "binary_expression" | "binary_operator")
        && (txt.contains('+') || txt.contains('%'))
    {
        let mut leaves = Vec::new();
        if txt.contains('+') {
            collect_plus_leaves(node, &mut leaves);
        } else {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if !matches!(ch.kind(), "+" | "%" | "comment") {
                    leaves.push(ch);
                }
            }
        }
        let mut has_sql_lit = false;
        let mut has_non_lit = false;
        for ch in leaves {
            let ck = ch.kind();
            if matches!(
                ck,
                "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal"
            ) {
                if sql_verb_re().is_match(node_text(ch, src)) {
                    has_sql_lit = true;
                }
            } else if env.is_some_and(|e| is_pure_safe_literal_expr(ch, src, e)) {
                // Pure constant identifier/literal — not dynamic untrusted SQL
            } else {
                has_non_lit = true;
            }
        }
        if has_sql_lit && has_non_lit {
            return true;
        }
        if has_sql_lit && !has_non_lit {
            return false;
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if matches!(ch.kind(), "statement_block" | "block") {
            continue;
        }
        if has_dynamic_sql_interpolation_with_env(ch, src, env) {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn check_call_taint_sinks(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    env: &TaintEnv,
    fn_guards: &HashSet<GuardKind>,
    summary: &mut FunctionTaintSummary,
) {
    let k = node.kind();

    // React JSX `dangerouslySetInnerHTML={{ __html: untrusted }}` (SMG-XSS-001)
    if k == "jsx_attribute"
        && !fn_guards.contains(&GuardKind::XssSanitizer)
        && node_text(node, src)
            .trim_start()
            .starts_with("dangerouslySetInnerHTML")
        && let Some((tkind, _)) = ast_sink_status(node, src, TAINT_XSS, env)
    {
        let hit = LocalStaticFinding {
            rule_id: "SMG-XSS-001".into(),
            severity: "HIGH".into(),
            title: format!("Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML` in `{}`", symbol_name),
            rel_path: rel_path.to_string(),
            line: node.start_position().row + 1,
            symbol: symbol_name.to_string(),
            sink_kind: SinkKind::Xss,
            missing_guard: GuardKind::XssSanitizer,
            confidence: Confidence::Confirmed,
            remediation: "Sanitize untrusted HTML with `DOMPurify.sanitize(...)` before passing to `dangerouslySetInnerHTML` or render plain text safely.".into(),
        };
        match tkind {
            TaintSourceKind::Direct => push_unique_hit(&mut summary.local_taint_hits, hit),
            TaintSourceKind::Param => push_unique_hit(&mut summary.param_sinks, hit),
        }
    }

    // Go `template.HTML(untrusted)` when parsed as `type_conversion_expression`
    if k == "type_conversion_expression"
        && !fn_guards.contains(&GuardKind::XssSanitizer)
        && node
            .child_by_field_name("type")
            .is_some_and(|t| node_text(t, src).trim() == "template.HTML")
        && let Some(op) = node.child_by_field_name("operand")
        && let Some((tkind, _)) = ast_sink_status(op, src, TAINT_XSS, env)
    {
        let hit = LocalStaticFinding {
            rule_id: "SMG-XSS-001".into(),
            severity: "HIGH".into(),
            title: format!("Cross-Site Scripting (XSS) via `template.HTML` in `{}`", symbol_name),
            rel_path: rel_path.to_string(),
            line: node.start_position().row + 1,
            symbol: symbol_name.to_string(),
            sink_kind: SinkKind::Xss,
            missing_guard: GuardKind::XssSanitizer,
            confidence: Confidence::Confirmed,
            remediation: "HTML-escape or sanitize untrusted input (`html.EscapeString`, Go `html/template` auto-escaping) instead of converting raw strings to `template.HTML`.".into(),
        };
        match tkind {
            TaintSourceKind::Direct => push_unique_hit(&mut summary.local_taint_hits, hit),
            TaintSourceKind::Param => push_unique_hit(&mut summary.param_sinks, hit),
        }
    }

    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let short = ftxt.rsplit('.').next().unwrap_or(ftxt);
        let short = short.rsplit("::").next().unwrap_or(short);
        let args_node = node.child_by_field_name("arguments");
        let args_txt = args_node.map(|a| node_text(a, src)).unwrap_or("");
        let line = node.start_position().row + 1;

        // Phase 10: record cross-file callback handoffs & inline closure taint propagation!
        if !short.is_empty() && env.params.contains_key(short) {
            let (cd, cp) = args_node
                .map(|an| ast_eval_masks(an, src, env))
                .unwrap_or((TAINT_ALL, TAINT_ALL));
            let invoke_mask = if (cd | cp) == 0 && args_txt.trim() == "()" {
                TAINT_ALL
            } else {
                cd | cp
            };
            summary.invokes_callback_mask |= invoke_mask;
        }

        // Track sink-typed call-arg forwarding (`(callee, bitmask)`), object field masks, wrappers & callbacks
        if !short.is_empty()
            && let Some(an) = args_node
        {
            let mut non_cb_d = 0u8;
            let mut non_cb_p = 0u8;
            let mut inline_cbs: Vec<Node> = Vec::new();
            let mut named_cbs: Vec<String> = Vec::new();
            let mut single_tainted_arg: Option<Node> = None;
            let mut tainted_arg_count = 0usize;

            // Check receiver object for array iteration helpers like `items.forEach(cb)`
            let mut recv_mask = (0u8, 0u8);
            if let Some(obj_n) = func.child_by_field_name("object") {
                recv_mask = ast_eval_masks(obj_n, src, env);
            }

            let mut ac = an.walk();
            for arg in an.children(&mut ac) {
                let ak = arg.kind();
                if matches!(ak, "(" | ")" | "," | "comment") {
                    continue;
                }
                if matches!(
                    ak,
                    "arrow_function" | "function_expression" | "closure_expression" | "lambda"
                ) {
                    inline_cbs.push(arg);
                    continue;
                }
                let (ad, ap) = ast_eval_masks(arg, src, env);
                non_cb_d |= ad;
                non_cb_p |= ap;
                if ad != 0 || ap != 0 {
                    tainted_arg_count += 1;
                    single_tainted_arg = Some(arg);
                } else if ak == "identifier" {
                    let cname = node_text(arg, src).trim();
                    if is_plain_ident(cname)
                        && !matches!(
                            cname,
                            "true" | "false" | "null" | "undefined" | "None" | "nil"
                        )
                    {
                        named_cbs.push(cname.to_string());
                    }
                }
            }

            let mut callees: Vec<String> = Vec::new();
            if matches!(func.kind(), "subscript_expression" | "index_expression") {
                if let Some(obj_n) = func
                    .child_by_field_name("object")
                    .or_else(|| func.child_by_field_name("value"))
                    .or_else(|| func.child_by_field_name("operand"))
                {
                    let obj_name = node_text(obj_n, src).trim();
                    if let Some(targets) = env.handler_maps.get(obj_name) {
                        callees.extend(targets.iter().cloned());
                    }
                }
            } else if func.kind() == "identifier"
                && let Some(targets) = env.handler_aliases.get(short)
            {
                callees.extend(targets.iter().cloned());
                if !callees.iter().any(|c| c == short) {
                    callees.push(short.to_string());
                }
            } else {
                callees.push(short.to_string());
            }

            let (d_mask, p_mask) = ast_eval_masks(an, src, env);
            for callee_name in &callees {
                if d_mask != 0 {
                    if !summary.tainted_calls.iter().any(|c| c == callee_name) {
                        summary.tainted_calls.push(callee_name.clone());
                    }
                    *summary
                        .tainted_call_masks
                        .entry(callee_name.clone())
                        .or_insert(0) |= d_mask;
                }
                if p_mask != 0 {
                    if !summary
                        .param_forwarding_calls
                        .iter()
                        .any(|c| c == callee_name)
                    {
                        summary.param_forwarding_calls.push(callee_name.clone());
                    }
                    *summary
                        .tainted_call_masks
                        .entry(callee_name.clone())
                        .or_insert(0) |= p_mask;
                }
            }

            // Field-level argument metadata when passing an object variable `helper(payload)`
            let mut call_has_object_fields = false;
            let mut ac2 = an.walk();
            for arg in an.children(&mut ac2) {
                if arg.kind() == "identifier" {
                    let aname = node_text(arg, src).trim();
                    if env.object_vars.contains(aname) {
                        let mut field_pairs: Vec<(String, u8)> = Vec::new();
                        for ((obj, fld), m) in &env.field_direct {
                            if obj == aname && *m != 0 {
                                field_pairs.push((fld.clone(), *m));
                            }
                        }
                        for ((obj, fld), m) in &env.field_params {
                            if obj == aname && *m != 0 {
                                if let Some(ex) = field_pairs.iter_mut().find(|(f, _)| f == fld) {
                                    ex.1 |= *m;
                                } else {
                                    field_pairs.push((fld.clone(), *m));
                                }
                            }
                        }
                        if !field_pairs.is_empty() {
                            call_has_object_fields = true;
                            for callee_name in &callees {
                                summary
                                    .tainted_field_calls
                                    .entry(callee_name.clone())
                                    .or_default()
                                    .extend(field_pairs.iter().cloned());
                            }
                        }
                    }
                }
            }
            // If an unrestricted (non-object-field) tainted call is also made to `callee` in this function,
            // remove field restriction for `callee` so the unrestricted call is not suppressed.
            if (d_mask != 0 || p_mask != 0) && !call_has_object_fields {
                for callee_name in &callees {
                    summary.tainted_field_calls.remove(callee_name);
                }
            }

            // Track wrapper provenance when calling `callee(cleanOrWrappedVar)`
            if d_mask != 0
                && tainted_arg_count == 1
                && let Some(sa) = single_tainted_arg
                && let Some((wfn, wf)) = extract_expr_wrapper(sa, src, env)
            {
                for callee_name in &callees {
                    summary.tainted_call_wrappers.push((
                        callee_name.clone(),
                        wfn.clone(),
                        wf.clone(),
                        d_mask,
                    ));
                }
            }

            // Record cross-file callback forwards `runTask(req.body.cmd, workerCb)`
            let cb_data_mask = non_cb_d | non_cb_p | recv_mask.0 | recv_mask.1;
            if cb_data_mask != 0 {
                for cb_name in &named_cbs {
                    for callee_name in &callees {
                        let tup = (callee_name.clone(), cb_name.clone(), cb_data_mask);
                        if !summary.callback_forwards.contains(&tup) {
                            summary.callback_forwards.push(tup);
                        }
                    }
                }
            } else if matches!(short, "spawn" | "spawn_blocking" | "spawn_local")
                && (!env.direct.is_empty() || !env.params.is_empty())
            {
                // Named task spawner (`tokio::spawn(worker)` / `thread::spawn(worker)`): propagate outer taint bits
                let direct_union = env.direct.values().copied().fold(0u8, |a, b| a | b);
                let param_union = env.params.values().copied().fold(0u8, |a, b| a | b);
                for cb_name in &named_cbs {
                    if direct_union != 0 {
                        if !summary.tainted_calls.iter().any(|c| c == cb_name) {
                            summary.tainted_calls.push(cb_name.clone());
                        }
                        *summary
                            .tainted_call_masks
                            .entry(cb_name.clone())
                            .or_insert(0) |= direct_union;
                    }
                    if param_union != 0
                        && !summary.param_forwarding_calls.iter().any(|c| c == cb_name)
                    {
                        summary.param_forwarding_calls.push(cb_name.clone());
                        *summary
                            .tainted_call_masks
                            .entry(cb_name.clone())
                            .or_insert(0) |= param_union;
                    }
                }
            }

            // Evaluate inline closure bodies `(val) => { execSync(val); worker(val); }`
            for cb_node in inline_cbs {
                let mut cb_env = env.clone();
                let seed_d = non_cb_d | recv_mask.0;
                let seed_p = non_cb_p | recv_mask.1;
                let cb_params = extract_param_names(cb_node, src);
                for cp in &cb_params {
                    if seed_d != 0 {
                        *cb_env.direct.entry(cp.clone()).or_insert(0) |= seed_d;
                    }
                    if seed_p != 0 {
                        *cb_env.params.entry(cp.clone()).or_insert(0) |= seed_p;
                    }
                    // Preserve object fields when passing an object_var to a closure
                    if tainted_arg_count == 1
                        && let Some(sa) = single_tainted_arg
                        && sa.kind() == "identifier"
                    {
                        let sa_name = node_text(sa, src).trim();
                        if env.object_vars.contains(sa_name) {
                            cb_env.object_vars.insert(cp.clone());
                            let fd: Vec<_> = env
                                .field_direct
                                .iter()
                                .filter(|((o, _), _)| o == sa_name)
                                .map(|((_, f), m)| ((cp.clone(), f.clone()), *m))
                                .collect();
                            cb_env.field_direct.extend(fd);
                            let fp: Vec<_> = env
                                .field_params
                                .iter()
                                .filter(|((o, _), _)| o == sa_name)
                                .map(|((_, f), m)| ((cp.clone(), f.clone()), *m))
                                .collect();
                            cb_env.field_params.extend(fp);
                            let sf: Vec<_> = env
                                .sanitized_fields
                                .iter()
                                .filter(|(o, _)| o == sa_name)
                                .map(|(_, f)| (cp.clone(), f.clone()))
                                .collect();
                            cb_env.sanitized_fields.extend(sf);
                        }
                    }
                }
                if let Some(cb_body) = cb_node.child_by_field_name("body") {
                    if matches!(cb_body.kind(), "statement_block" | "block") {
                        analyze_statement_block(
                            cb_body,
                            src,
                            rel_path,
                            lang,
                            symbol_name,
                            &mut cb_env,
                            summary,
                        );
                    } else {
                        check_call_taint_sinks(
                            cb_body,
                            src,
                            rel_path,
                            lang,
                            symbol_name,
                            &cb_env,
                            fn_guards,
                            summary,
                        );
                    }
                }
            }
        }

        // 0. SQL Execution Sink with tainted first argument (`db.query(q)` where `q` is tainted variable)
        let is_sql_exec_sink = matches!(
            ftxt,
            "db.query"
                | "db.queryRow"
                | "db.exec"
                | "db.prepare"
                | "db.raw"
                | "tx.query"
                | "tx.exec"
                | "pool.query"
                | "pool.execute"
                | "client.query"
                | "cursor.execute"
                | "session.execute"
                | "conn.execute"
                | "conn.fetch"
                | "knex.raw"
                | "sequelize.query"
                | "sequelize.literal"
                | "queryRunner.query"
                | "entityManager.query"
                | "sql.unsafe"
                | "sqlx::query"
        ) || ftxt.ends_with(".$queryRawUnsafe")
            || ftxt.ends_with(".$executeRawUnsafe")
            || ftxt.ends_with(".whereRaw")
            || ftxt.ends_with(".havingRaw")
            || ftxt.ends_with(".orderByRaw")
            || ftxt.ends_with(".andWhereRaw");
        if is_sql_exec_sink
            && !fn_guards.contains(&GuardKind::SqlSanitizer)
            && let Some(an) = args_node
        {
            let mut ac = an.walk();
            if let Some(arg0) = an
                .children(&mut ac)
                .find(|a| !matches!(a.kind(), "(" | ")" | ","))
            {
                let arg0_txt = node_text(arg0, src).trim();
                let is_plain_string_lit = matches!(
                    arg0.kind(),
                    "string"
                        | "string_literal"
                        | "interpreted_string_literal"
                        | "raw_string_literal"
                ) && !arg0_txt.starts_with("f\"")
                    && !arg0_txt.starts_with("f'");
                if !is_plain_string_lit
                    && let Some((tkind, _)) = ast_sink_status(arg0, src, TAINT_SQL, env)
                {
                    let hit = LocalStaticFinding {
                        rule_id: "SMG-SQLI-001".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "SQL Injection via tainted query argument in `{}`",
                            symbol_name
                        ),
                        rel_path: rel_path.to_string(),
                        line,
                        symbol: symbol_name.to_string(),
                        sink_kind: SinkKind::SqlInjection,
                        missing_guard: GuardKind::SqlSanitizer,
                        confidence: Confidence::Confirmed,
                        remediation: "Use parameterized queries (`$1`, `?`, or ORM query builders) instead of passing dynamically constructed or untrusted SQL strings.".into(),
                    };
                    match tkind {
                        TaintSourceKind::Direct => {
                            if let Some((wfn, wf)) = extract_expr_wrapper(arg0, src, env) {
                                summary.local_hit_wrappers.push((
                                    hit.rule_id.clone(),
                                    line,
                                    wfn,
                                    wf,
                                ));
                            }
                            push_unique_hit(&mut summary.local_taint_hits, hit);
                        }
                        TaintSourceKind::Param => {
                            let pf = extract_expr_param_field(arg0, src, env);
                            summary.param_sink_fields.push((hit.clone(), pf));
                            push_unique_hit(&mut summary.param_sinks, hit);
                        }
                    }
                }
            }
        }

        // 1. Command Injection (SMG-CMDI-001)
        let is_shell_exec = matches!(
            ftxt,
            "exec" | "execSync" | "child_process.exec" | "child_process.execSync"
        ) || ftxt.ends_with(".execSync")
            || (ftxt.ends_with(".exec")
                && !ftxt.starts_with("db.")
                && !ftxt.starts_with("tx.")
                && !ftxt.starts_with("stmt.")
                && !ftxt.starts_with("re.")
                && !ftxt.starts_with("regex.")
                && !ftxt.starts_with("pattern."))
            || ((short == "spawn" || short == "spawnSync" || short == "execFile")
                && args_txt.contains("shell")
                && args_txt.contains("true"))
            || ((ftxt == "exec.Command" || ftxt == "exec.CommandContext")
                && (args_txt.contains("\"-c\"") || args_txt.contains("'/c'")))
            || (ftxt.starts_with("subprocess.")
                && (args_txt.contains("shell=True")
                    || ((args_txt.contains("\"-c\"")
                        || args_txt.contains("'-c'")
                        || args_txt.contains("\"/c\"")
                        || args_txt.contains("'/c'"))
                        && (args_txt.contains("bash")
                            || args_txt.contains("\"sh\"")
                            || args_txt.contains("'sh'")
                            || args_txt.contains("/sh")
                            || args_txt.contains("zsh")
                            || args_txt.contains("cmd")))))
            || matches!(ftxt, "os.system" | "os.popen")
            || (ftxt == "Command::new"
                && (args_txt.contains("\"sh\"") || args_txt.contains("\"bash\"")))
            || ((ftxt.ends_with(".arg") || ftxt.ends_with(".args"))
                && (ftxt.contains("Command::new(\"sh\")")
                    || ftxt.contains("Command::new(\"bash\")")
                    || ftxt.contains("Command::new(\"/bin/sh\")")
                    || ftxt.contains("Command::new(\"/bin/bash\")"))
                && !args_txt.trim().eq("\"-c\""));

        if is_shell_exec
            && !fn_guards.contains(&GuardKind::CmdSanitizer)
            && let Some(an) = args_node
            && let Some((tkind, _)) = ast_sink_status(an, src, TAINT_CMD, env)
        {
            let hit = LocalStaticFinding {
                    rule_id: "SMG-CMDI-001".into(),
                    severity: "CRITICAL".into(),
                    title: format!("OS Command Injection via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Avoid invoking a shell; use `execFile`/`spawn` with an argument array (`shell: false`) or strict input allowlisting.".into(),
                };
            match tkind {
                TaintSourceKind::Direct => {
                    if let Some((wfn, wf)) = extract_expr_wrapper(an, src, env) {
                        summary
                            .local_hit_wrappers
                            .push((hit.rule_id.clone(), line, wfn, wf));
                    }
                    push_unique_hit(&mut summary.local_taint_hits, hit);
                }
                TaintSourceKind::Param => {
                    let pf = extract_expr_param_field(an, src, env);
                    summary.param_sink_fields.push((hit.clone(), pf));
                    push_unique_hit(&mut summary.param_sinks, hit);
                }
            }
        }

        // 2. Path Traversal (SMG-PATH-001)
        let is_fs_sink = matches!(
            ftxt,
            "fs.readFile"
                | "fs.readFileSync"
                | "fs.promises.readFile"
                | "fs.writeFile"
                | "fs.writeFileSync"
                | "fs.unlink"
                | "fs.unlinkSync"
                | "fs.rm"
                | "res.sendFile"
                | "sendFile"
                | "os.Open"
                | "os.ReadFile"
                | "os.WriteFile"
                | "os.Remove"
                | "ioutil.ReadFile"
                | "http.ServeFile"
                | "fs::read"
                | "fs::read_to_string"
                | "fs::File::open"
                | "fs::remove_file"
                | "send_file"
        ) || (lang == Language::Python && ftxt == "open");

        if is_fs_sink
            && !fn_guards.contains(&GuardKind::PathSanitizer)
            && let Some(an) = args_node
            && let Some((tkind, _)) = ast_sink_status(an, src, TAINT_PATH, env)
        {
            let hit = LocalStaticFinding {
                    rule_id: "SMG-PATH-001".into(),
                    severity: "HIGH".into(),
                    title: format!("Arbitrary Path Traversal via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::PathTraversal,
                    missing_guard: GuardKind::PathSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Normalize the path with `path.basename` / `filepath.Base` and verify `resolvedPath.startsWith(baseDir)` before accessing the filesystem.".into(),
                };
            match tkind {
                TaintSourceKind::Direct => {
                    if let Some((wfn, wf)) = extract_expr_wrapper(an, src, env) {
                        summary
                            .local_hit_wrappers
                            .push((hit.rule_id.clone(), line, wfn, wf));
                    }
                    push_unique_hit(&mut summary.local_taint_hits, hit);
                }
                TaintSourceKind::Param => {
                    let pf = extract_expr_param_field(an, src, env);
                    summary.param_sink_fields.push((hit.clone(), pf));
                    push_unique_hit(&mut summary.param_sinks, hit);
                }
            }
        }

        // 3. SSRF (SMG-SSRF-001)
        let is_http_sink = matches!(
            ftxt,
            "fetch"
                | "axios"
                | "axios.get"
                | "axios.post"
                | "axios.put"
                | "axios.delete"
                | "axios.request"
                | "got"
                | "http.Get"
                | "http.Post"
                | "http.NewRequest"
                | "requests.get"
                | "requests.post"
                | "requests.request"
                | "httpx.get"
                | "urllib.request.urlopen"
                | "reqwest::get"
        );
        let trimmed_args = args_txt.trim_start_matches('(').trim();
        let is_relative_api_url = trimmed_args.starts_with("\"/")
            || trimmed_args.starts_with("'/")
            || trimmed_args.starts_with("`/");

        let is_client_ui_only = (rel_path.ends_with(".tsx") || rel_path.ends_with(".jsx"))
            && matches!(
                ftxt,
                "fetch"
                    | "axios"
                    | "axios.get"
                    | "axios.post"
                    | "axios.put"
                    | "axios.delete"
                    | "axios.request"
            );

        if is_http_sink
            && !is_client_ui_only
            && !is_relative_api_url
            && !fn_guards.contains(&GuardKind::SsrfSanitizer)
            && let Some(an) = args_node
            && let Some((tkind, _)) = ast_sink_status(an, src, TAINT_SSRF, env)
        {
            let hit = LocalStaticFinding {
                    rule_id: "SMG-SSRF-001".into(),
                    severity: "HIGH".into(),
                    title: format!("Server-Side Request Forgery (SSRF) via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::Ssrf,
                    missing_guard: GuardKind::SsrfSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Parse the URL and enforce an explicit hostname allowlist while blocking loopback/private/link-local IP ranges (169.254.0.0/16, 10.0.0.0/8, 127.0.0.1).".into(),
                };
            match tkind {
                TaintSourceKind::Direct => {
                    if let Some((wfn, wf)) = extract_expr_wrapper(an, src, env) {
                        summary
                            .local_hit_wrappers
                            .push((hit.rule_id.clone(), line, wfn, wf));
                    }
                    push_unique_hit(&mut summary.local_taint_hits, hit);
                }
                TaintSourceKind::Param => {
                    let pf = extract_expr_param_field(an, src, env);
                    summary.param_sink_fields.push((hit.clone(), pf));
                    push_unique_hit(&mut summary.param_sinks, hit);
                }
            }
        }

        // 4. Cross-Site Scripting / XSS (SMG-XSS-001)
        let is_always_xss_sink = matches!(
            ftxt,
            "document.write"
                | "document.writeln"
                | "render_template_string"
                | "flask.render_template_string"
                | "mark_safe"
                | "django.utils.safestring.mark_safe"
                | "Markup"
                | "markupsafe.Markup"
                | "HTMLResponse"
                | "fastapi.responses.HTMLResponse"
                | "template.HTML"
                | "c.html"
                | "res.html"
                | "reply.html"
        ) || ftxt.ends_with(".insertAdjacentHTML");
        let is_html_conditional_sink = matches!(
            ftxt,
            "res.send" | "reply.send" | "w.Write" | "fmt.Fprintf" | "io.WriteString"
        ) && (has_html_markup_lit(args_txt)
            || expr_references_any(args_txt, &env.html_vars));

        if (is_always_xss_sink || is_html_conditional_sink)
            && !fn_guards.contains(&GuardKind::XssSanitizer)
            && let Some(an) = args_node
            && let Some((tkind, _)) = ast_sink_status(an, src, TAINT_XSS, env)
        {
            let hit = LocalStaticFinding {
                    rule_id: "SMG-XSS-001".into(),
                    severity: "HIGH".into(),
                    title: format!("Cross-Site Scripting (XSS) via `{}` in `{}`", ftxt, symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::Xss,
                    missing_guard: GuardKind::XssSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "HTML-escape or sanitize untrusted input (`DOMPurify.sanitize`, `escapeHtml`, `html.escape`, `html.EscapeString`) before HTML rendering.".into(),
                };
            match tkind {
                TaintSourceKind::Direct => {
                    if let Some((wfn, wf)) = extract_expr_wrapper(an, src, env) {
                        summary
                            .local_hit_wrappers
                            .push((hit.rule_id.clone(), line, wfn, wf));
                    }
                    push_unique_hit(&mut summary.local_taint_hits, hit);
                }
                TaintSourceKind::Param => {
                    let pf = extract_expr_param_field(an, src, env);
                    summary.param_sink_fields.push((hit.clone(), pf));
                    push_unique_hit(&mut summary.param_sinks, hit);
                }
            }
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if matches!(ch.kind(), "statement_block" | "block") {
            continue;
        }
        check_call_taint_sinks(
            ch,
            src,
            rel_path,
            lang,
            symbol_name,
            env,
            fn_guards,
            summary,
        );
    }
}

fn extract_object_pairs<'a>(rhs: Node<'a>, src: &[u8]) -> Vec<(Option<String>, Node<'a>)> {
    let mut pairs = Vec::new();
    let k = rhs.kind();
    if !matches!(
        k,
        "object" | "dictionary" | "struct_expression" | "composite_literal"
    ) {
        return pairs;
    }
    let mut c = rhs.walk();
    for ch in rhs.children(&mut c) {
        match ch.kind() {
            "pair" => {
                if let (Some(kn), Some(vn)) = (
                    ch.child_by_field_name("key"),
                    ch.child_by_field_name("value"),
                ) {
                    let key = node_text(kn, src)
                        .trim()
                        .trim_matches(|q| q == '"' || q == '\'' || q == '`')
                        .to_string();
                    if is_plain_ident(&key) {
                        pairs.push((Some(key), vn));
                    }
                }
            }
            "shorthand_property_identifier" => {
                let key = node_text(ch, src).trim().to_string();
                if is_plain_ident(&key) {
                    pairs.push((Some(key), ch));
                }
            }
            "spread_element" => {
                let mut sc = ch.walk();
                for sch in ch.children(&mut sc) {
                    if sch.kind() == "identifier" {
                        pairs.push((None, sch));
                    }
                }
            }
            "field_initializer" => {
                if let (Some(fn_n), Some(vn)) = (
                    ch.child_by_field_name("name"),
                    ch.child_by_field_name("value"),
                ) {
                    let key = node_text(fn_n, src).trim().to_string();
                    if is_plain_ident(&key) {
                        pairs.push((Some(key), vn));
                    }
                } else {
                    let txt = node_text(ch, src).trim();
                    if is_plain_ident(txt) {
                        pairs.push((Some(txt.to_string()), ch));
                    }
                }
            }
            _ => {}
        }
    }
    pairs
}

fn extract_object_pattern_keys(stmt: Node, src: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor = stmt.walk();
    for ch in stmt.children(&mut cursor) {
        if ch.kind() == "shorthand_property_identifier_pattern" {
            let k = node_text(ch, src).trim();
            if is_plain_ident(k) {
                out.push((k.to_string(), k.to_string()));
            }
        } else if ch.kind() == "pair_pattern"
            && let (Some(kn), Some(vn)) = (
                ch.child_by_field_name("key"),
                ch.child_by_field_name("value"),
            )
        {
            let k = node_text(kn, src).trim();
            let v = node_text(vn, src).trim();
            if is_plain_ident(k) && is_plain_ident(v) {
                out.push((k.to_string(), v.to_string()));
            }
        } else {
            out.extend(extract_object_pattern_keys(ch, src));
        }
    }
    out
}

fn collect_return_sanitizer_clears(
    node: Node,
    src: &[u8],
    env: &TaintEnv,
    summary: &mut FunctionTaintSummary,
) {
    let mut acc_mask: Option<u8> = None;
    let mut acc_fields: Option<HashMap<String, u8>> = None;
    collect_return_clears_rec(node, src, env, &mut acc_mask, &mut acc_fields);
    if let Some(m) = acc_mask {
        summary.clears_taint_mask |= m;
    }
    if let Some(flds) = acc_fields {
        for (k, v) in flds {
            if v != 0 {
                *summary.clears_field_masks.entry(k).or_insert(0) |= v;
            }
        }
    }
}

fn merge_return_mask(acc: &mut Option<u8>, val: u8) {
    match acc {
        Some(prev) => *prev &= val,
        None => *acc = Some(val),
    }
}

fn merge_return_fields(acc: &mut Option<HashMap<String, u8>>, cur: HashMap<String, u8>) {
    match acc {
        Some(prev) => {
            prev.retain(|k, pv| {
                if let Some(&cv) = cur.get(k) {
                    *pv &= cv;
                    *pv != 0
                } else {
                    false
                }
            });
        }
        None => *acc = Some(cur),
    }
}

fn collect_return_clears_rec(
    node: Node,
    src: &[u8],
    env: &TaintEnv,
    acc_mask: &mut Option<u8>,
    acc_fields: &mut Option<HashMap<String, u8>>,
) {
    let k = node.kind();
    if matches!(
        k,
        "arrow_function" | "function_expression" | "function_declaration" | "closure_expression"
    ) {
        return;
    }
    if matches!(k, "return_statement" | "return_expression") {
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if matches!(ch.kind(), "return" | ";") {
                continue;
            }
            let ck = ch.kind();
            if matches!(ck, "object" | "dictionary" | "struct_expression") {
                let mut cur_fields: HashMap<String, u8> = HashMap::new();
                for (key_opt, vn) in extract_object_pairs(ch, src) {
                    if let Some(fld) = key_opt {
                        let (vd, vp) = ast_eval_masks(vn, src, env);
                        let cleared = expr_call_sanitized_bits(vn, src, env) & !(vd | vp);
                        if cleared != 0 {
                            *cur_fields.entry(fld).or_insert(0) |= cleared;
                        }
                    } else if vn.kind() == "identifier" {
                        let spread_id = node_text(vn, src).trim();
                        for ((obj, fld), m) in &env.object_cleared_fields {
                            if obj == spread_id {
                                *cur_fields.entry(fld.clone()).or_insert(0) |= *m;
                            }
                        }
                    }
                }
                merge_return_mask(acc_mask, 0);
                merge_return_fields(acc_fields, cur_fields);
            } else if ck == "identifier" {
                let id = node_text(ch, src).trim();
                let (rd, rp) = ast_eval_masks(ch, src, env);
                let cleared = expr_call_sanitized_bits(ch, src, env) & !(rd | rp);
                merge_return_mask(acc_mask, cleared);
                let mut cur_fields: HashMap<String, u8> = HashMap::new();
                for ((obj, fld), m) in &env.object_cleared_fields {
                    if obj == id {
                        *cur_fields.entry(fld.clone()).or_insert(0) |= *m;
                    }
                }
                merge_return_fields(acc_fields, cur_fields);
            } else {
                let (rd, rp) = ast_eval_masks(ch, src, env);
                let cleared = expr_call_sanitized_bits(ch, src, env) & !(rd | rp);
                merge_return_mask(acc_mask, cleared);
                merge_return_fields(acc_fields, HashMap::new());
            }
        }
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_return_clears_rec(ch, src, env, acc_mask, acc_fields);
    }
}

fn stmt_unconditionally_exits(stmt: Node) -> bool {
    let k = stmt.kind();
    if matches!(
        k,
        "return_statement" | "throw_statement" | "raise_statement" | "return_expression"
    ) {
        return true;
    }
    if matches!(k, "statement_block" | "block") {
        let mut c = stmt.walk();
        return stmt
            .children(&mut c)
            .any(|ch| stmt_unconditionally_exits(ch));
    }
    false
}

fn collect_cond_idents(cond_txt: &str) -> HashSet<String> {
    let mut vars = HashSet::new();
    for cap in ident_re().captures_iter(cond_txt) {
        vars.insert(cap[1].to_string());
    }
    vars
}

fn condition_narrow_mask(cond_txt: &str) -> u8 {
    let mut narrow_mask = 0u8;
    let low = cond_txt.to_ascii_lowercase();
    if stmt_is_path_prefix_guard(cond_txt) || low.contains("isallowedpath") {
        narrow_mask |= TAINT_PATH;
    }
    if expr_has_ssrf_sanitizer(cond_txt) && !is_universal_sanitizer(cond_txt) {
        narrow_mask |= TAINT_SSRF;
    }
    // Only boolean allowlist predicates narrow CMD taint in conditionals;
    // value-returning transforms (`shlex.quote(x)`, `DOMPurify.sanitize(x)`) discard the clean result.
    if low.contains("allowlist") {
        narrow_mask |= TAINT_CMD;
    }
    narrow_mask
}

#[allow(clippy::too_many_arguments)]
fn analyze_statement_block(
    block: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    env: &mut TaintEnv,
    summary: &mut FunctionTaintSummary,
) {
    analyze_statement_block_depth(block, src, rel_path, lang, symbol_name, env, summary, 0);
}

#[allow(clippy::too_many_arguments)]
fn analyze_statement_block_depth(
    block: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    env: &mut TaintEnv,
    summary: &mut FunctionTaintSummary,
    depth: usize,
) {
    if depth >= MAX_AST_WALK_DEPTH {
        return;
    }
    let mut cursor = block.walk();
    for stmt in block.children(&mut cursor) {
        let sk = stmt.kind();
        if matches!(sk, "{" | "}" | "comment" | "line_comment" | "block_comment") {
            continue;
        }
        let is_compound = matches!(
            sk,
            "if_statement"
                | "if_expression"
                | "else_clause"
                | "try_statement"
                | "catch_clause"
                | "except_clause"
                | "finally_clause"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "with_statement"
                | "match_expression"
                | "switch_statement"
                | "statement_block"
                | "block"
        );

        let stmt_txt = node_text(stmt, src);
        let stmt_code = strip_comments_simple(stmt_txt);

        if has_cookie_session_expr(&stmt_code) {
            summary.has_cookie_session_auth = true;
        }
        if has_bearer_header_expr(&stmt_code) {
            summary.has_bearer_header_auth = true;
        }
        if has_csrf_exempt_expr(&stmt_code) {
            summary.csrf_exempt = true;
        }
        if has_csrf_guard_expr(&stmt_code) {
            summary.guards.insert(GuardKind::CsrfProtection);
        }

        if !is_compound {
            if has_taint_source_expr(&stmt_code) {
                summary.has_taint_source = true;
            }
            if has_resource_id_expr(&stmt_code, None) {
                summary.has_resource_id = true;
            }
            if has_ownership_filter_with_env(&stmt_code, Some(env)) {
                summary.guards.insert(GuardKind::OwnershipCheck);
            }
            if is_db_crud_stmt(&stmt_code) {
                summary.has_db_crud_sink = true;
                if summary.db_crud_line.is_none() {
                    summary.db_crud_line = Some(stmt.start_position().row + 1);
                }
            }
        }

        // Check SQL injection dynamic construction in statement (ignoring non-SQL console/UI prose and safe constant literals)
        if !is_non_sql_log_or_ui_stmt(&stmt_code)
            && has_dynamic_sql_interpolation_with_env(stmt, src, Some(env))
            && !is_universal_sanitizer(&stmt_code)
            && let Some(tkind) = stmt_taint_status(&stmt_code, TAINT_SQL, env)
        {
            let line = stmt.start_position().row + 1;
            let hit = LocalStaticFinding {
                rule_id: "SMG-SQLI-001".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "SQL Injection via unsanitized string interpolation in `{}`",
                    symbol_name
                ),
                rel_path: rel_path.to_string(),
                line,
                symbol: symbol_name.to_string(),
                sink_kind: SinkKind::SqlInjection,
                missing_guard: GuardKind::SqlSanitizer,
                confidence: Confidence::Confirmed,
                remediation: "Use parameterized queries (`$1`, `?`, or ORM query builders) instead of interpolating untrusted input into SQL strings.".into(),
            };
            match tkind {
                TaintSourceKind::Direct => push_unique_hit(&mut summary.local_taint_hits, hit),
                TaintSourceKind::Param => push_unique_hit(&mut summary.param_sinks, hit),
            }
        }

        // Check CMDi, Path Traversal, SSRF, XSS, SQL exec sinks, and tainted callee forwarding
        check_call_taint_sinks(
            stmt,
            src,
            rel_path,
            lang,
            symbol_name,
            env,
            &summary.guards.clone(),
            summary,
        );

        // Update local sink-typed variable taint state, `.innerHTML` assignment sink, and HTML/SQL builder vars
        if let Some((lhs_names, lhs_raws, rhs_node, is_aug)) = extract_assigned_targets(stmt, src) {
            let rhs_txt = node_text(rhs_node, src);
            let rhs_is_safe_tagged_sql = contains_safe_sql_tagged_template(rhs_node, src);
            let rhs_has_sql = !rhs_is_safe_tagged_sql && sql_verb_re().is_match(rhs_txt);
            if rhs_has_sql {
                for n in &lhs_names {
                    env.sql_vars.insert(n.clone());
                }
            }
            if has_html_markup_lit(rhs_txt) {
                for n in &lhs_names {
                    env.html_vars.insert(n.clone());
                }
            }

            // DOM `.innerHTML = rhs` / `.outerHTML = rhs` sink
            if lhs_raws
                .iter()
                .any(|raw| raw.ends_with(".innerHTML") || raw.ends_with(".outerHTML"))
                && !summary.guards.contains(&GuardKind::XssSanitizer)
                && let Some((tkind, _)) = ast_sink_status(rhs_node, src, TAINT_XSS, env)
            {
                let line = stmt.start_position().row + 1;
                let hit = LocalStaticFinding {
                    rule_id: "SMG-XSS-001".into(),
                    severity: "HIGH".into(),
                    title: format!("DOM Cross-Site Scripting (XSS) via `innerHTML` assignment in `{}`", symbol_name),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::Xss,
                    missing_guard: GuardKind::XssSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Use `textContent` for text or sanitize HTML with `DOMPurify.sanitize(...)` before assigning `innerHTML`.".into(),
                };
                match tkind {
                    TaintSourceKind::Direct => {
                        if let Some((wfn, wf)) = extract_expr_wrapper(rhs_node, src, env) {
                            summary
                                .local_hit_wrappers
                                .push((hit.rule_id.clone(), line, wfn, wf));
                        }
                        push_unique_hit(&mut summary.local_taint_hits, hit);
                    }
                    TaintSourceKind::Param => {
                        let pf = extract_expr_param_field(rhs_node, src, env);
                        summary.param_sink_fields.push((hit.clone(), pf));
                        push_unique_hit(&mut summary.param_sinks, hit);
                    }
                }
            }

            let (rhs_direct_mask, rhs_param_mask) = ast_eval_masks(rhs_node, src, env);
            let rhs_cleared = expr_call_sanitized_bits(rhs_node, src, env);
            let touches_sql_var = lhs_names.iter().any(|n| env.sql_vars.contains(n))
                || expr_references_any(rhs_txt, &env.sql_vars);

            if !rhs_is_safe_tagged_sql
                && ((rhs_direct_mask & TAINT_SQL != 0) || (rhs_param_mask & TAINT_SQL != 0))
                && touches_sql_var
                && (is_aug || rhs_txt.contains('+') || rhs_txt.contains("${"))
            {
                let line = stmt.start_position().row + 1;
                let hit = LocalStaticFinding {
                    rule_id: "SMG-SQLI-001".into(),
                    severity: "CRITICAL".into(),
                    title: format!(
                        "SQL Injection via multi-statement query concatenation in `{}`",
                        symbol_name
                    ),
                    rel_path: rel_path.to_string(),
                    line,
                    symbol: symbol_name.to_string(),
                    sink_kind: SinkKind::SqlInjection,
                    missing_guard: GuardKind::SqlSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Use parameterized queries (`$1`, `?`, or ORM query builders) instead of concatenating untrusted input into SQL strings.".into(),
                };
                if rhs_direct_mask & TAINT_SQL != 0 {
                    if let Some((wfn, wf)) = extract_expr_wrapper(rhs_node, src, env) {
                        summary
                            .local_hit_wrappers
                            .push((hit.rule_id.clone(), line, wfn, wf));
                    }
                    push_unique_hit(&mut summary.local_taint_hits, hit);
                } else {
                    let pf = extract_expr_param_field(rhs_node, src, env);
                    summary.param_sink_fields.push((hit.clone(), pf));
                    push_unique_hit(&mut summary.param_sinks, hit);
                }
            }

            // Dynamic handler map index write `handlers[k] = fnC`
            if !is_aug
                && lhs_raws.len() == 1
                && let Some(idx_pos) = lhs_raws[0].find('[')
                && let Some(base) =
                    Some(lhs_raws[0][..idx_pos].trim()).filter(|b| is_plain_ident(b))
            {
                if let Some(target_fn) = extract_callable_target_name(rhs_node, src) {
                    let entry = env.handler_maps.entry(base.to_string()).or_default();
                    if !entry.contains(&target_fn) {
                        entry.push(target_fn);
                    }
                }
            } else if !is_aug
                && lhs_raws.len() == 1
                && let Some((base, field)) = split_simple_member(&lhs_raws[0])
            {
                env.object_vars.insert(base.clone());
                if rhs_direct_mask != 0 {
                    env.field_direct
                        .insert((base.clone(), field.clone()), rhs_direct_mask);
                    env.sanitized_fields.remove(&(base.clone(), field.clone()));
                    *env.direct.entry(base.clone()).or_insert(0) |= rhs_direct_mask;
                } else {
                    env.field_direct.remove(&(base.clone(), field.clone()));
                }
                if rhs_param_mask != 0 {
                    env.field_params
                        .insert((base.clone(), field.clone()), rhs_param_mask);
                    env.sanitized_fields.remove(&(base.clone(), field.clone()));
                    *env.params.entry(base.clone()).or_insert(0) |= rhs_param_mask;
                } else {
                    env.field_params.remove(&(base.clone(), field.clone()));
                }
                if rhs_direct_mask == 0 && rhs_param_mask == 0 {
                    env.sanitized_fields.insert((base.clone(), field.clone()));
                }
                if rhs_cleared != 0 {
                    env.object_cleared_fields.insert(
                        (base, field),
                        rhs_cleared & !(rhs_direct_mask | rhs_param_mask),
                    );
                }
            } else {
                // Track cross-file wrapper call assignment `const clean = sanitizeFn(arg)`
                let rhs_wrapper: Option<(String, Option<String>)> =
                    if rhs_node.kind() == "call_expression" || rhs_node.kind() == "call" {
                        let ftxt = rhs_node
                            .child_by_field_name("function")
                            .map(|f| node_text(f, src).trim())
                            .unwrap_or("");
                        let short_fn = ftxt
                            .rsplit('.')
                            .next()
                            .unwrap_or(ftxt)
                            .rsplit("::")
                            .next()
                            .unwrap_or(ftxt);
                        if !short_fn.is_empty()
                            && !is_universal_sanitizer(ftxt)
                            && (rhs_direct_mask != 0 || rhs_param_mask != 0)
                        {
                            Some((short_fn.to_string(), None))
                        } else {
                            None
                        }
                    } else {
                        extract_expr_wrapper(rhs_node, src, env)
                    };

                // Object literal construction `const payload = { foo: req.body.cmd, safe: "ok" }`
                let obj_pairs = extract_object_pairs(rhs_node, src);
                // Object destructuring `const { foo, safe } = payload`
                let destructured_keys = extract_object_pattern_keys(stmt, src);

                if !destructured_keys.is_empty() && rhs_node.kind() == "identifier" {
                    let rhs_id = rhs_txt.trim();
                    for (orig_k, local_var) in destructured_keys {
                        if let Some((wfn, _)) = env.var_wrappers.get(rhs_id).cloned() {
                            env.var_wrappers
                                .insert(local_var.clone(), (wfn, Some(orig_k.clone())));
                        }
                        if env.params.contains_key(rhs_id) {
                            env.destructured_param_fields
                                .insert(local_var.clone(), orig_k.clone());
                        }
                        if env.object_vars.contains(rhs_id) {
                            let fd = env
                                .field_direct
                                .get(&(rhs_id.to_string(), orig_k.clone()))
                                .copied()
                                .unwrap_or(0);
                            let fp = env
                                .field_params
                                .get(&(rhs_id.to_string(), orig_k.clone()))
                                .copied()
                                .unwrap_or(0);
                            if fd != 0 {
                                env.direct.insert(local_var.clone(), fd);
                            } else {
                                env.direct.remove(&local_var);
                            }
                            if fp != 0 {
                                env.params.insert(local_var.clone(), fp);
                            } else {
                                env.params.remove(&local_var);
                            }
                        } else {
                            if rhs_direct_mask != 0 {
                                env.direct.insert(local_var.clone(), rhs_direct_mask);
                            } else {
                                env.direct.remove(&local_var);
                            }
                            if rhs_param_mask != 0 {
                                env.params.insert(local_var.clone(), rhs_param_mask);
                            } else {
                                env.params.remove(&local_var);
                            }
                        }
                    }
                } else {
                    for n in lhs_names {
                        if is_aug {
                            if rhs_direct_mask != 0 {
                                *env.direct.entry(n.clone()).or_insert(0) |= rhs_direct_mask;
                            }
                            if rhs_param_mask != 0 {
                                *env.params.entry(n.clone()).or_insert(0) |= rhs_param_mask;
                            }
                        } else {
                            if rhs_direct_mask != 0 {
                                env.direct.insert(n.clone(), rhs_direct_mask);
                                env.safe_literals.remove(&n);
                            } else {
                                env.direct.remove(&n);
                            }
                            if rhs_param_mask != 0 {
                                env.params.insert(n.clone(), rhs_param_mask);
                                env.safe_literals.remove(&n);
                            } else {
                                env.params.remove(&n);
                            }
                            if rhs_direct_mask == 0
                                && rhs_param_mask == 0
                                && is_pure_safe_literal_expr(rhs_node, src, env)
                            {
                                env.safe_literals.insert(n.clone());
                            } else {
                                env.safe_literals.remove(&n);
                            }
                            if rhs_cleared != 0 {
                                env.var_cleared_masks.insert(
                                    n.clone(),
                                    rhs_cleared & !(rhs_direct_mask | rhs_param_mask),
                                );
                            }
                            if let Some(ref w) = rhs_wrapper {
                                env.var_wrappers.insert(n.clone(), w.clone());
                            } else {
                                env.var_wrappers.remove(&n);
                            }
                            // Track alias `const fn = handlers[action]` or `handlers.get(action)`
                            if matches!(
                                rhs_node.kind(),
                                "subscript_expression" | "index_expression"
                            ) && let Some(obj_n) = rhs_node
                                .child_by_field_name("object")
                                .or_else(|| rhs_node.child_by_field_name("value"))
                                .or_else(|| rhs_node.child_by_field_name("operand"))
                                && let Some(targets) =
                                    env.handler_maps.get(node_text(obj_n, src).trim()).cloned()
                            {
                                env.handler_aliases.insert(n.clone(), targets);
                            } else if !matches!(rhs_node.kind(), "call_expression" | "call") {
                                env.handler_aliases.remove(&n);
                            }
                            if !obj_pairs.is_empty() {
                                env.object_vars.insert(n.clone());
                                let mut handler_targets = Vec::new();
                                for (k_opt, vn) in &obj_pairs {
                                    if let Some(target_fn) = extract_callable_target_name(*vn, src)
                                        && !handler_targets.contains(&target_fn)
                                    {
                                        handler_targets.push(target_fn);
                                    }
                                    if let Some(fld) = k_opt {
                                        let (fd, fp) = ast_eval_masks(*vn, src, env);
                                        let fclr =
                                            expr_call_sanitized_bits(*vn, src, env) & !(fd | fp);
                                        if fclr != 0 {
                                            env.object_cleared_fields
                                                .insert((n.clone(), fld.clone()), fclr);
                                        }
                                        if fd != 0 {
                                            env.field_direct.insert((n.clone(), fld.clone()), fd);
                                            env.sanitized_fields.remove(&(n.clone(), fld.clone()));
                                        }
                                        if fp != 0 {
                                            env.field_params.insert((n.clone(), fld.clone()), fp);
                                            env.sanitized_fields.remove(&(n.clone(), fld.clone()));
                                        }
                                        if fd == 0 && fp == 0 {
                                            env.sanitized_fields.insert((n.clone(), fld.clone()));
                                        }
                                    } else if vn.kind() == "identifier" {
                                        let sp = node_text(*vn, src).trim();
                                        let sp_fd: Vec<_> = env
                                            .field_direct
                                            .iter()
                                            .filter(|((o, _), _)| o == sp)
                                            .map(|((_, f), m)| ((n.clone(), f.clone()), *m))
                                            .collect();
                                        env.field_direct.extend(sp_fd);
                                        let sp_fp: Vec<_> = env
                                            .field_params
                                            .iter()
                                            .filter(|((o, _), _)| o == sp)
                                            .map(|((_, f), m)| ((n.clone(), f.clone()), *m))
                                            .collect();
                                        env.field_params.extend(sp_fp);
                                    }
                                }
                                if !handler_targets.is_empty() {
                                    env.handler_maps.insert(n.clone(), handler_targets);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Structured Control-Flow Lattice Join & Early-Return / Positive-Branch Pruning
        if sk == "if_statement" || sk == "if_expression" {
            let cond_node = stmt.child_by_field_name("condition");
            let cons_node = stmt.child_by_field_name("consequence");
            let alt_node = stmt.child_by_field_name("alternative");
            let mut env_then = env.clone();
            let then_exits = cons_node.is_some_and(stmt_unconditionally_exits);
            if let Some(cn) = cond_node
                && !then_exits
            {
                let cond_txt = strip_comments_simple(node_text(cn, src));
                let trimmed = cond_txt.trim_start().trim_start_matches('(').trim_start();
                if !trimmed.starts_with('!') && !trimmed.starts_with("not ") {
                    let narrow_mask = condition_narrow_mask(&cond_txt);
                    if narrow_mask != 0 {
                        let c_vars = collect_cond_idents(&cond_txt);
                        env_then.clear_bits_for_vars(&c_vars, narrow_mask);
                    }
                }
            }
            if let Some(cons) = cons_node {
                analyze_statement_block_depth(
                    cons,
                    src,
                    rel_path,
                    lang,
                    symbol_name,
                    &mut env_then,
                    summary,
                    depth + 1,
                );
            }

            if let Some(alt) = alt_node {
                let mut env_else = env.clone();
                analyze_statement_block_depth(
                    alt,
                    src,
                    rel_path,
                    lang,
                    symbol_name,
                    &mut env_else,
                    summary,
                    depth + 1,
                );
                let else_exits = stmt_unconditionally_exits(alt);
                match (then_exits, else_exits) {
                    (false, false) => *env = TaintEnv::join_pair(&env_then, &env_else),
                    (false, true) => *env = env_then,
                    (true, false) => *env = env_else,
                    (true, true) => {}
                }
            } else if then_exits {
                // Early-return validation narrowing on fall-through path (only for vars checked AFTER the guard)
                if let Some(cn) = cond_node {
                    let cond_txt = strip_comments_simple(node_text(cn, src));
                    let narrow_mask = condition_narrow_mask(&cond_txt);
                    if narrow_mask != 0 {
                        let c_vars = collect_cond_idents(&cond_txt);
                        env.clear_bits_for_vars(&c_vars, narrow_mask);
                    }
                }
            } else {
                env.join(&env_then);
            }
        } else if is_compound {
            let mut sub = stmt.walk();
            for ch in stmt.children(&mut sub) {
                if matches!(
                    ch.kind(),
                    "statement_block"
                        | "block"
                        | "if_statement"
                        | "if_expression"
                        | "else_clause"
                        | "try_statement"
                        | "catch_clause"
                        | "except_clause"
                        | "finally_clause"
                        | "switch_body"
                        | "switch_case"
                        | "switch_default"
                        | "match_block"
                        | "match_arm"
                ) {
                    analyze_statement_block_depth(
                        ch,
                        src,
                        rel_path,
                        lang,
                        symbol_name,
                        env,
                        summary,
                        depth + 1,
                    );
                }
            }
        }
    }
}

/// Runs intra-procedural sink-typed taint lattice, sanitizer, ownership, and DB CRUD extraction on a function or inline handler AST node.
pub fn analyze_function_taint(
    fn_node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbol_name: &str,
    route_path: Option<&str>,
) -> FunctionTaintSummary {
    let mut summary = FunctionTaintSummary::default();
    let fn_code = strip_comments_simple(node_text(fn_node, src));

    if has_taint_source_expr(&fn_code) {
        summary.has_taint_source = true;
    }
    if has_resource_id_expr(&fn_code, route_path) {
        summary.has_resource_id = true;
    }
    if has_cookie_session_expr(&fn_code) {
        summary.has_cookie_session_auth = true;
    }
    if has_bearer_header_expr(&fn_code) {
        summary.has_bearer_header_auth = true;
    }
    if has_csrf_exempt_expr(&fn_code) {
        summary.csrf_exempt = true;
    }
    if has_csrf_guard_expr(&fn_code) {
        summary.guards.insert(GuardKind::CsrfProtection);
    }
    let body_code = fn_node
        .child_by_field_name("body")
        .map(|b| strip_comments_simple(node_text(b, src)))
        .unwrap_or_default();

    let mut env = TaintEnv {
        handler_maps: collect_file_handler_maps(fn_node, src),
        ..Default::default()
    };
    let params_raw = fn_node
        .child_by_field_name("parameters")
        .map(|p| node_text(p, src))
        .unwrap_or("");
    for p in extract_param_names(fn_node, src) {
        let is_rust_http_extractor = lang == Language::Rust
            && ["Json(", "Query(", "Path(", "Form("]
                .iter()
                .any(|ex| params_raw.contains(&format!("{}{}", ex, p)));
        if is_rust_http_extractor {
            env.direct.insert(p, TAINT_ALL);
            summary.has_taint_source = true;
        } else {
            env.params.insert(p, TAINT_ALL);
        }
    }

    if let Some(body) = fn_node.child_by_field_name("body") {
        if matches!(body.kind(), "statement_block" | "block") {
            analyze_statement_block(
                body,
                src,
                rel_path,
                lang,
                symbol_name,
                &mut env,
                &mut summary,
            );
            collect_return_sanitizer_clears(body, src, &env, &mut summary);
        } else {
            // Expression-bodied arrow function `(req, res) => execSync(...)` or `(x) => shellEscape(x)`
            analyze_statement_block(
                fn_node,
                src,
                rel_path,
                lang,
                symbol_name,
                &mut env,
                &mut summary,
            );
            if matches!(body.kind(), "object" | "dictionary" | "struct_expression") {
                for (key_opt, vn) in extract_object_pairs(body, src) {
                    if let Some(fld) = key_opt {
                        let (vd, vp) = ast_eval_masks(vn, src, &env);
                        let cleared = expr_call_sanitized_bits(vn, src, &env) & !(vd | vp);
                        if cleared != 0 {
                            *summary.clears_field_masks.entry(fld).or_insert(0) |= cleared;
                        }
                    }
                }
            } else {
                let (rd, rp) = ast_eval_masks(body, src, &env);
                let cleared = expr_call_sanitized_bits(body, src, &env) & !(rd | rp);
                summary.clears_taint_mask |= cleared;
            }
        }
    }

    if has_ownership_filter_with_env(&body_code, Some(&env)) {
        summary.guards.insert(GuardKind::OwnershipCheck);
    }

    summary
}

pub fn normalize_api_path(raw: &str) -> String {
    let without_query = raw.split('?').next().unwrap_or(raw).trim();
    if without_query.is_empty() {
        return "/".to_string();
    }
    let mut segs: Vec<String> = Vec::new();
    for seg in without_query.split('/').filter(|s| !s.is_empty()) {
        if seg.starts_with(':')
            || (seg.starts_with('{') && seg.ends_with('}'))
            || (seg.starts_with('[') && seg.ends_with(']'))
            || seg.contains("${")
            || (seg.starts_with('<') && seg.ends_with('>'))
        {
            segs.push("*".to_string());
        } else {
            segs.push(seg.to_string());
        }
    }
    format!("/{}", segs.join("/"))
}

fn has_ancestor_kind(node: Node, target_kind: &str) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == target_kind {
            return true;
        }
        if matches!(
            p.kind(),
            "function_declaration" | "arrow_function" | "function_expression" | "method_definition"
        ) {
            break;
        }
        cur = p.parent();
    }
    false
}

fn has_dot_catch_chain(node: Node, src: &[u8]) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        let txt = node_text(p, src);
        if txt.contains(".catch(") {
            return true;
        }
        if matches!(
            p.kind(),
            "statement_block"
                | "expression_statement"
                | "lexical_declaration"
                | "function_declaration"
        ) {
            break;
        }
        cur = p.parent();
    }
    false
}

fn is_likely_frontend_file(rel_path: &str, src: &[u8]) -> bool {
    let low = rel_path.to_ascii_lowercase().replace('\\', "/");
    if low.ends_with(".tsx") || low.ends_with(".jsx") {
        return true;
    }
    if low.split('/').any(|seg| {
        matches!(
            seg,
            "web"
                | "client"
                | "frontend"
                | "ui"
                | "components"
                | "pages"
                | "views"
                | "hooks"
                | "widgets"
        )
    }) {
        return true;
    }
    let text = std::str::from_utf8(src).unwrap_or("");
    text.contains("window.")
        || text.contains("document.")
        || text.contains("useState(")
        || text.contains("useEffect(")
        || text.contains("dangerouslySetInnerHTML")
        || text.contains("localStorage.")
        || text.contains("sessionStorage.")
        || text.contains("postMessage(")
        || text.contains("$fetch(")
        || text.contains("useFetch(")
        || text.contains("fetch('/api")
        || text.contains("fetch(\"/api")
        || text.contains("fetch(`/api")
        || text.contains("axios.")
}

/// Extracts frontend `/api/...` calls (`SMG-FE-404` candidates) and UI/async functional bugs (`SMG-FE-ERR`).
pub fn extract_frontend_calls_and_bugs(
    node: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    calls_out: &mut Vec<FrontendApiCall>,
    bugs_out: &mut Vec<LocalStaticFinding>,
) {
    if !matches!(lang, Language::TypeScript | Language::JavaScript) {
        return;
    }
    let is_fe = is_likely_frontend_file(rel_path, src);

    let kind = node.kind();

    // 1. Dead/empty `onClick={() => {}}` / `onSubmit={() => {}}`
    if kind == "jsx_attribute" {
        let attr_txt = node_text(node, src);
        if (attr_txt.starts_with("onClick") || attr_txt.starts_with("onSubmit"))
            && let Some(expr_node) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "jsx_expression")
        {
            let mut c = expr_node.walk();
            for ch in expr_node.children(&mut c) {
                if matches!(ch.kind(), "arrow_function" | "function_expression")
                    && let Some(body) = ch.child_by_field_name("body")
                    && body.kind() == "statement_block"
                {
                    let has_stmt = body.children(&mut body.walk()).any(|s| {
                        !matches!(
                            s.kind(),
                            "{" | "}" | "comment" | "line_comment" | "block_comment"
                        )
                    });
                    if !has_stmt {
                        bugs_out.push(LocalStaticFinding {
                            rule_id: "SMG-FE-ERR".into(),
                            severity: "MEDIUM".into(),
                            title: "Dead/empty UI event handler (`onClick={() => {}}`)".into(),
                            rel_path: rel_path.to_string(),
                            line: node.start_position().row + 1,
                            symbol: attr_txt.split('=').next().unwrap_or("onClick").trim().to_string(),
                            sink_kind: SinkKind::FrontendContract,
                            missing_guard: GuardKind::FrontendContract,
                            confidence: Confidence::Heuristic,
                            remediation: "Wire the event handler to an actual state update, callback, or remove the dead interactive trigger.".into(),
                        });
                    }
                }
            }
        }
    }

    // 2. Frontend `fetch('/api/...')` / `axios.<method>('/api/...')` / `$fetch` / `useFetch` / Angular `this.http` contract extraction
    if kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        let is_fetch = matches!(ftxt, "fetch" | "$fetch" | "useFetch");
        let is_axios = ftxt == "axios"
            || matches!(
                ftxt,
                "axios.get"
                    | "axios.post"
                    | "axios.put"
                    | "axios.patch"
                    | "axios.delete"
                    | "this.http.get"
                    | "this.http.post"
                    | "this.http.put"
                    | "this.http.patch"
                    | "this.http.delete"
            );
        if (is_fetch || is_axios)
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut c = args.walk();
            let first_arg = args
                .children(&mut c)
                .find(|a| !matches!(a.kind(), "(" | ")" | ","));
            if let Some(arg0) = first_arg {
                let raw_arg = if arg0.kind() == "binary_expression" {
                    arg0.child_by_field_name("left")
                        .map(|l| {
                            let s = node_text(l, src)
                                .trim()
                                .trim_matches(|ch| ch == '\'' || ch == '"' || ch == '`');
                            if s.starts_with("/api/") {
                                format!("{}/*", s.trim_end_matches('/'))
                            } else {
                                String::new()
                            }
                        })
                        .unwrap_or_default()
                } else {
                    node_text(arg0, src)
                        .trim()
                        .trim_matches(|ch| ch == '\'' || ch == '"' || ch == '`')
                        .to_string()
                };
                if raw_arg.starts_with("/api/") || raw_arg == "/api" {
                    let method = if let Some(m) = ftxt.rsplit('.').next()
                        && matches!(m, "get" | "post" | "put" | "patch" | "delete")
                    {
                        m.to_ascii_uppercase()
                    } else {
                        let args_txt = node_text(args, src).to_ascii_uppercase();
                        if args_txt.contains("POST") {
                            "POST".into()
                        } else if args_txt.contains("PUT") {
                            "PUT".into()
                        } else if args_txt.contains("PATCH") {
                            "PATCH".into()
                        } else if args_txt.contains("DELETE") {
                            "DELETE".into()
                        } else {
                            "GET".into()
                        }
                    };
                    calls_out.push(FrontendApiCall {
                        rel_path: rel_path.to_string(),
                        line: node.start_position().row + 1,
                        method,
                        raw_path: raw_arg.clone(),
                        normalized_path: normalize_api_path(&raw_arg),
                        symbol: ftxt.to_string(),
                    });
                }
            }
        }
    }

    // 3. Unhandled async mutation missing `try/catch` or `.catch(...)` (frontend files only)
    if is_fe && kind == "await_expression" {
        let txt = node_text(node, src);
        let low = txt.to_ascii_lowercase();
        let is_mutation = low.contains("axios.post(")
            || low.contains("axios.put(")
            || low.contains("axios.patch(")
            || low.contains("axios.delete(")
            || low.contains(".mutateasync(")
            || (low.contains("fetch(")
                && (low.contains("post")
                    || low.contains("put")
                    || low.contains("patch")
                    || low.contains("delete")));
        if is_mutation
            && !has_ancestor_kind(node, "try_statement")
            && !has_dot_catch_chain(node, src)
        {
            bugs_out.push(LocalStaticFinding {
                rule_id: "SMG-FE-ERR".into(),
                severity: "MEDIUM".into(),
                title: "Unhandled async mutation missing `try/catch` or `.catch()` error handling"
                    .into(),
                rel_path: rel_path.to_string(),
                line: node.start_position().row + 1,
                symbol: "await mutation".into(),
                sink_kind: SinkKind::FrontendContract,
                missing_guard: GuardKind::FrontendContract,
                confidence: Confidence::Heuristic,
                remediation: "Wrap the `await` mutation in a `try { ... } catch (err) { ... }` block and surface an explicit error state to the UI.".into(),
            });
        }
    }

    // 4. Swallowed or empty `catch (e) {}` / `catch (e) { console.log(e); }` error blocks (frontend files only)
    if is_fe
        && kind == "catch_clause"
        && let Some(body) = node.child_by_field_name("body")
    {
        let mut c = body.walk();
        let stmts: Vec<Node> = body
            .children(&mut c)
            .filter(|ch| {
                !matches!(
                    ch.kind(),
                    "{" | "}" | "comment" | "line_comment" | "block_comment"
                )
            })
            .collect();
        if stmts.is_empty() {
            bugs_out.push(LocalStaticFinding {
                rule_id: "SMG-FE-ERR".into(),
                severity: "MEDIUM".into(),
                title: "Empty `catch` block silently swallows runtime/API errors".into(),
                rel_path: rel_path.to_string(),
                line: node.start_position().row + 1,
                symbol: "catch".into(),
                sink_kind: SinkKind::FrontendContract,
                missing_guard: GuardKind::FrontendContract,
                confidence: Confidence::Heuristic,
                remediation: "Handle caught errors explicitly (surface UI error feedback, report telemetry, or rethrow).".into(),
            });
        } else if stmts.len() == 1 {
            let only = node_text(stmts[0], src).trim();
            if only.starts_with("console.") {
                bugs_out.push(LocalStaticFinding {
                    rule_id: "SMG-FE-ERR".into(),
                    severity: "LOW".into(),
                    title: "`catch` block only logs to `console` without handling or surfacing error".into(),
                    rel_path: rel_path.to_string(),
                    line: node.start_position().row + 1,
                    symbol: "catch (console-only)".into(),
                    sink_kind: SinkKind::FrontendContract,
                    missing_guard: GuardKind::FrontendContract,
                    confidence: Confidence::Heuristic,
                    remediation: "Update error UI state, return an error result, or rethrow instead of only logging to console.".into(),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        extract_frontend_calls_and_bugs(ch, src, rel_path, lang, calls_out, bugs_out);
    }
}
