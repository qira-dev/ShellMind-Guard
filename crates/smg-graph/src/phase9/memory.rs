use super::{is_rust_test_subtree, make_phase9_finding};
use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind, node_text, strip_comments};
use regex::Regex;
use smg_core::Language;
use std::sync::OnceLock;
use tree_sitter::Node;

fn c_unsafe_copy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\("#)
            .expect("valid c unsafe copy regex")
    })
}

fn c_bounded_copy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(memcpy|memmove|strncpy|strncat|read|recv)\s*\("#)
            .expect("valid c bounded copy regex")
    })
}

fn c_scanf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(?:f?scanf|sscanf)\s*\([^;]*?"[^"]*(?:%s|%\[\^)""#)
            .expect("valid scanf regex")
    })
}

fn c_fmt_string_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(printf|fprintf|dprintf|syslog)\s*\("#).expect("valid c fmt regex")
    })
}

fn c_alloc_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(malloc|alloca)\s*\(([^;{}]+)\)|\brealloc\s*\([^,]+,\s*([^;{}]+)\)|\bnew\s+[A-Za-z_][A-Za-z0-9_:<>]*\s*\[([^\]]+)\]"#)
            .expect("valid c alloc regex")
    })
}

fn ident_tok_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b([A-Za-z_][A-Za-z0-9_]*)\b"#).expect("valid ident regex"))
}

/// Scans C/C++ functions and Rust `unsafe` blocks for `SMG-MEM-BOUNDS` and `SMG-ENG-INT`.
pub fn analyze_memory_and_overflows(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    match lang {
        Language::C | Language::Cpp => {
            walk_c_cpp_functions(root, src, rel_path, static_findings, 0);
        }
        Language::Rust => {
            walk_rust_unsafe(root, src, rel_path, static_findings, 0);
        }
        _ => {}
    }
}

fn walk_c_cpp_functions(
    node: Node,
    src: &[u8],
    rel_path: &str,
    out: &mut Vec<LocalStaticFinding>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "function_definition" {
        let name = node
            .child_by_field_name("declarator")
            .map(|d| {
                let t = node_text(d, src);
                t.split('(')
                    .next()
                    .unwrap_or(t)
                    .split_whitespace()
                    .last()
                    .unwrap_or("c_fn")
                    .trim_start_matches(['*', '&'])
                    .to_string()
            })
            .unwrap_or_else(|| "c_fn".to_string());
        if !name.starts_with("test_") && !name.starts_with("TEST") {
            let line_start = node.start_position().row + 1;
            let fn_code = strip_comments(node_text(node, src));
            scan_c_cpp_function(rel_path, &name, line_start, &fn_code, out);
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_c_cpp_functions(ch, src, rel_path, out, depth + 1);
    }
}

fn extract_call_args(line: &str, call_start: usize) -> Option<Vec<String>> {
    let open = line[call_start..].find('(')? + call_start;
    let mut depth = 0usize;
    let mut current = String::new();
    let mut args = Vec::new();
    for ch in line[open + 1..].chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                if depth == 0 {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        args.push(trimmed.to_string());
                    }
                    return Some(args);
                }
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    None
}

fn is_c_const_macro_expr(expr: &str) -> bool {
    let t = expr.trim();
    !t.is_empty()
        && t.chars().any(|c| c.is_ascii_uppercase())
        && t.chars().all(|c| {
            c.is_ascii_uppercase()
                || c.is_ascii_digit()
                || matches!(c, '_' | '+' | '-' | '*' | '/' | ' ' | '(' | ')')
        })
}

fn has_preceding_bounds_check(preceding_code: &str, len_expr: &str) -> bool {
    if is_c_const_macro_expr(len_expr) {
        return true;
    }
    let len_low = len_expr.to_ascii_lowercase();
    if len_low.chars().all(|c| c.is_ascii_digit() || c == '_')
        || len_low.contains("sizeof")
        || len_low.starts_with("min(")
        || len_low.starts_with("min_t(")
        || len_low.starts_with("curlmin(")
        || len_low.starts_with("clamp(")
        || len_low.starts_with("std::min")
        || len_low.contains(".min(")
    {
        return true;
    }

    let vars: Vec<String> = ident_tok_re()
        .find_iter(&len_low)
        .map(|m| m.as_str().to_string())
        .filter(|v| {
            !matches!(
                v.as_str(),
                "sizeof" | "min" | "max" | "std" | "size_t" | "int" | "unsigned"
            )
        })
        .collect();
    if vars.is_empty() {
        return true;
    }

    let prec_low = preceding_code.to_ascii_lowercase();
    for v in &vars {
        let mut verified = false;
        let mut depth: i32 = 0;
        let mut guard_if_depth: Option<i32> = None;
        let mut guard_if_exits = false;

        for line in prec_low.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let has_word_v = ident_tok_re().find_iter(trimmed).any(|m| m.as_str() == v);
            let line_exits = trimmed.contains("return")
                || trimmed.contains("break")
                || trimmed.contains("continue")
                || trimmed.contains("goto ")
                || trimmed.contains("exit(")
                || trimmed.contains("abort(")
                || trimmed.contains("throw ");

            if guard_if_depth.is_some() && line_exits {
                guard_if_exits = true;
            }

            if has_word_v {
                let is_if_or_assert = trimmed.contains("if ")
                    || trimmed.contains("if(")
                    || trimmed.contains("assert");
                let has_bound_op = trimmed.contains('<')
                    || trimmed.contains("<=")
                    || trimmed.contains('>')
                    || trimmed.contains(">=")
                    || trimmed.contains("sizeof")
                    || trimmed.contains("max")
                    || trimmed.contains("cap");
                if trimmed.contains("assert") && has_bound_op {
                    verified = true;
                } else if is_if_or_assert && has_bound_op {
                    verified = true;
                    if !line_exits && trimmed.contains('{') && !trimmed.contains('}') {
                        guard_if_depth = Some(depth);
                        guard_if_exits = false;
                    }
                } else if trimmed.contains(&format!("{} =", v))
                    || trimmed.contains(&format!("{}+=", v))
                    || trimmed.contains(&format!("{} +=", v))
                {
                    if trimmed.contains("min(") || trimmed.contains("std::min") {
                        verified = true;
                    } else {
                        // Intervening re-assignment invalidates prior bounds checks on `v`
                        verified = false;
                    }
                } else if trimmed.contains(&format!("malloc({})", v))
                    || trimmed.contains(&format!("malloc({} +", v))
                    || trimmed.contains(&format!("calloc({},", v))
                    || trimmed.contains(&format!("[{}]", v))
                    || trimmed.contains(&format!(".resize({})", v))
                    || ((trimmed.contains("malloc(")
                        || trimmed.contains("zalloc(")
                        || trimmed.contains("calloc(")
                        || trimmed.contains("realloc(")
                        || trimmed.contains("alloca("))
                        && has_word_v)
                {
                    verified = true;
                }
            }

            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth = (depth - 1).max(0);
                }
            }

            if let Some(gd) = guard_if_depth
                && depth <= gd
            {
                // A non-exiting `if (v < cap) { ... }` block that already closed before our sink
                // only guarded statements *inside* that `if`, not statements after `}`!
                if !guard_if_exits {
                    verified = false;
                }
                guard_if_depth = None;
            }
        }
        if verified {
            return true;
        }
    }
    false
}

fn strip_sizeof_clauses(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    let mut i = 0usize;
    let bytes = expr.as_bytes();
    while i < bytes.len() {
        if bytes[i..].starts_with(b"sizeof")
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
        {
            let mut j = i + 6;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes.get(j) == Some(&b'(') {
                let mut depth = 0usize;
                while j < bytes.len() {
                    if bytes[j] == b'(' {
                        depth += 1;
                    } else if bytes[j] == b')' {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                out.push('1');
                i = j;
                continue;
            } else if j > i + 6 && j < bytes.len() {
                // Handle unparenthesized unary `sizeof *ptr` or `sizeof var`
                while j < bytes.len() && (bytes[j] == b'*' || bytes[j].is_ascii_whitespace()) {
                    j += 1;
                }
                let ident_start = j;
                while j < bytes.len()
                    && (bytes[j].is_ascii_alphanumeric()
                        || bytes[j] == b'_'
                        || bytes[j] == b'.'
                        || (bytes[j] == b'-' && bytes.get(j + 1) == Some(&b'>'))
                        || (bytes[j] == b'>' && j > 0 && bytes[j - 1] == b'-'))
                {
                    j += 1;
                }
                if j > ident_start {
                    out.push('1');
                    i = j;
                    continue;
                }
            }
        }
        if let Some(ch) = expr[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn pos_inside_c_string(line: &str, target: usize) -> bool {
    let mut in_sq = false;
    let mut in_dq = false;
    let mut esc = false;
    for (idx, ch) in line.char_indices() {
        if idx >= target {
            break;
        }
        if esc {
            esc = false;
            continue;
        }
        if (in_sq || in_dq) && ch == '\\' {
            esc = true;
            continue;
        }
        if ch == '"' && !in_sq {
            in_dq = !in_dq;
        } else if ch == '\'' && !in_dq {
            in_sq = !in_sq;
        }
    }
    in_sq || in_dq
}

fn has_overflow_guard(preceding_code: &str, arith_expr: &str) -> bool {
    let low = preceding_code.to_ascii_lowercase();
    if low.contains("__builtin_mul_overflow")
        || low.contains("__builtin_add_overflow")
        || low.contains("size_max")
        || low.contains("uint_max")
        || low.contains("int_max")
        || low.contains("numeric_limits")
        || low.contains("checked_mul")
        || low.contains("checked_add")
        || low.contains("saturating_mul")
        || low.contains("saturating_add")
        || low.contains("safe_mul")
    {
        return true;
    }
    let expr_no_sizeof = strip_sizeof_clauses(&arith_expr.to_ascii_lowercase());
    let vars: Vec<String> = ident_tok_re()
        .find_iter(&expr_no_sizeof)
        .map(|m| m.as_str().to_string())
        .filter(|v| {
            !matches!(
                v.as_str(),
                "sizeof" | "size_t" | "int" | "uint32_t" | "uint64_t" | "strlen"
            )
        })
        .collect();
    if vars.is_empty() {
        return true;
    }
    let bounded_count = vars
        .iter()
        .filter(|v| {
            low.lines().any(|l| {
                let t = l.trim();
                let has_var = ident_tok_re()
                    .find_iter(t)
                    .any(|m| m.as_str() == v.as_str());
                has_var
                    && (t.contains("if ") || t.contains("if(") || t.contains("assert"))
                    && (t.contains("max")
                        || t.contains("limit")
                        || t.contains("<=")
                        || t.contains('<')
                        || t.contains('>'))
            })
        })
        .count();
    bounded_count == vars.len()
}

fn scan_c_cpp_function(
    rel_path: &str,
    fn_name: &str,
    line_start: usize,
    fn_code: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let lines: Vec<&str> = fn_code.lines().collect();
    for (idx, raw_line) in lines.iter().enumerate() {
        let ln = line_start + idx;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut preceding_cache: Option<String> = None;

        // 1. Always-unsafe unbounded C string/buffer routines (skip string literals)
        if let Some(m) = c_unsafe_copy_re().find(trimmed)
            && !pos_inside_c_string(trimmed, m.start())
        {
            let api = trimmed[m.start()..m.end()].trim_end_matches('(').trim();
            let args = extract_call_args(trimmed, m.start()).unwrap_or_default();
            let dst_arg = args.first().map(|s| s.trim()).unwrap_or("");
            let src_arg = if api == "gets" {
                "stdin"
            } else {
                args.get(1).map(|s| s.trim()).unwrap_or("")
            };
            let is_tiny_safe_literal = (api == "strcpy" || api == "strcat")
                && src_arg.starts_with('"')
                && src_arg.ends_with('"')
                && src_arg.len() <= 10;
            let dst_sized_by_strlen = (api == "strcpy" || api == "strcat")
                && !dst_arg.is_empty()
                && !src_arg.is_empty()
                && {
                    let prev_start = idx.saturating_sub(8);
                    let strlen_pat = format!("strlen({})", src_arg);
                    lines[prev_start..idx].iter().any(|prev| {
                        prev.contains(dst_arg)
                            && (prev.contains("malloc(")
                                || prev.contains("zalloc(")
                                || prev.contains("calloc(")
                                || prev.contains("alloca("))
                            && prev.contains(&strlen_pat)
                    })
                };
            let safe_numeric_sprintf =
                (api == "sprintf" || api == "vsprintf") && !trimmed.contains("%s");
            if !is_tiny_safe_literal && !dst_sized_by_strlen && !safe_numeric_sprintf {
                out.push(make_phase9_finding(
                    "SMG-MEM-BOUNDS",
                    "CRITICAL",
                    format!(
                        "Unbounded `{}` call in `{}` risks stack/heap buffer overflow",
                        api, fn_name
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::MemorySafety,
                    GuardKind::MemoryBounds,
                    Confidence::Confirmed,
                    "Replace `gets`/`strcpy`/`strcat`/`sprintf` with bounded `fgets`, `snprintf`, `strlcpy`/`strncpy` + null termination, or `std::string`.",
                ));
            }
        }

        // 1b. Format string injection (`printf(user_var)`, `fprintf(f, user_var)`, `syslog(prio, user_var)`)
        if let Some(m) = c_fmt_string_re().find(trimmed)
            && !pos_inside_c_string(trimmed, m.start())
            && !trimmed[..m.start()].ends_with('.')
            && !trimmed[..m.start()].ends_with("->")
        {
            let api = trimmed[m.start()..m.end()].trim_end_matches('(').trim();
            if let Some(args) = extract_call_args(trimmed, m.start()) {
                let fmt_idx = if api == "printf" { 0 } else { 1 };
                if let Some(fmt_arg) = args.get(fmt_idx)
                    && args.len() == fmt_idx + 1
                    && !fmt_arg.starts_with('"')
                    && !fmt_arg.starts_with('\'')
                    && !fmt_arg.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                {
                    out.push(make_phase9_finding(
                        "SMG-MEM-BOUNDS",
                        "HIGH",
                        format!(
                            "Non-literal format argument `{}` passed to `{}()` in `{}` (format-string vulnerability)",
                            fmt_arg, api, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        Confidence::Confirmed,
                        "Always pass a string literal format specifier (`printf(\"%s\", msg)`).",
                    ));
                }
            }
        }

        if c_scanf_re().is_match(trimmed) {
            out.push(make_phase9_finding(
                "SMG-MEM-BOUNDS",
                "HIGH",
                format!(
                    "Unbounded `%s` / `%[^` format specifier in `scanf`/`fscanf`/`sscanf` inside `{}`",
                    fn_name
                ),
                rel_path,
                ln,
                fn_name,
                SinkKind::MemorySafety,
                GuardKind::MemoryBounds,
                Confidence::Confirmed,
                "Specify maximum field width (e.g., `%63s` for a 64-byte buffer) or read safely with `fgets`.",
            ));
        }

        // 2. Bounded copies/reads whose length comes from an unchecked variable (skip C++ member `.read(`/`->read(`)
        if let Some(m) = c_bounded_copy_re().find(trimmed)
            && !pos_inside_c_string(trimmed, m.start())
        {
            let before = trimmed[..m.start()].trim_end();
            let is_member_call =
                before.ends_with('.') || before.ends_with("->") || before.ends_with("::");
            let api = trimmed[m.start()..m.end()].trim_end_matches('(').trim();
            let is_posix_stream = matches!(api, "read" | "recv");
            if !(is_member_call && is_posix_stream)
                && let Some(args) = extract_call_args(trimmed, m.start())
                && let Some(len_arg) = args.get(2)
            {
                if api == "strncat"
                    && len_arg.contains("sizeof(")
                    && args.first().is_some_and(|d| len_arg.contains(d))
                {
                    out.push(make_phase9_finding(
                        "SMG-MEM-BOUNDS",
                        "HIGH",
                        format!("`strncat(dst, src, sizeof(dst))` off-by-one overflow in `{}`", fn_name),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        Confidence::Confirmed,
                        "Pass remaining free capacity `sizeof(dst) - strlen(dst) - 1` rather than total `sizeof(dst)` to `strncat`.",
                    ));
                } else if api != "strncat"
                    && !has_preceding_bounds_check(
                        preceding_cache.get_or_insert_with(|| lines[..idx].join("\n")),
                        len_arg,
                    )
                {
                    out.push(make_phase9_finding(
                        "SMG-MEM-BOUNDS",
                        "HIGH",
                        format!(
                            "`{}()` copy/read uses unchecked length `{}` in `{}` (buffer overflow risk)",
                            api, len_arg, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        Confidence::Heuristic,
                        "Validate `len <= sizeof(dst)` (checking signedness `len >= 0` if signed) before calling `memcpy`/`memmove`/`read`/`recv`.",
                    ));
                }
            }
        }

        // 3. Integer overflow in `malloc(a * b)` / `realloc(p, a * b)` / `new T[a * b]`
        if !pos_inside_c_string(trimmed, 0) {
            for cap in c_alloc_re().captures_iter(trimmed) {
                if cap
                    .get(0)
                    .is_some_and(|m| pos_inside_c_string(trimmed, m.start()))
                {
                    continue;
                }
                let expr = cap
                    .get(2)
                    .or_else(|| cap.get(3))
                    .or_else(|| cap.get(4))
                    .map(|m| m.as_str().trim())
                    .unwrap_or("");
                let cleaned_expr = strip_sizeof_clauses(expr);
                let has_arith = cleaned_expr.contains('*')
                    || cleaned_expr.contains('+')
                    || cleaned_expr.contains("<<");
                let non_const = ident_tok_re().captures_iter(&cleaned_expr).any(|c| {
                    let tok = &c[1];
                    tok != "sizeof"
                        && tok != "strlen"
                        && !tok
                            .chars()
                            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
                });
                if has_arith
                    && non_const
                    && !has_overflow_guard(
                        preceding_cache.get_or_insert_with(|| lines[..idx].join("\n")),
                        expr,
                    )
                {
                    out.push(make_phase9_finding(
                        "SMG-ENG-INT",
                        "CRITICAL",
                        format!(
                            "Unchecked arithmetic `{}` in memory allocation inside `{}` (integer overflow -> undersized heap allocation)",
                            expr, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::IntegerOverflow,
                        GuardKind::MemoryBounds,
                        Confidence::Confirmed,
                        "Check for overflow with `__builtin_mul_overflow` / `SIZE_MAX / elem_size` validation or `calloc(count, elem_size)` before allocating.",
                    ));
                }
            }
        }
    }
}

fn strip_comments_and_strings(node: Node, src: &[u8]) -> String {
    let base = node.start_byte();
    let end = node.end_byte().min(src.len());
    let mut bytes = src[base..end].to_vec();
    blank_trivia_nodes(node, base, &mut bytes, 0);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn blank_trivia_nodes(node: Node, base: usize, out: &mut [u8], depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    if matches!(
        k,
        "line_comment"
            | "block_comment"
            | "comment"
            | "string_literal"
            | "raw_string_literal"
            | "char_literal"
    ) {
        let s = node.start_byte().saturating_sub(base);
        let e = node.end_byte().saturating_sub(base).min(out.len());
        for b in &mut out[s..e] {
            if *b != b'\n' && *b != b'\r' {
                *b = b' ';
            }
        }
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        blank_trivia_nodes(ch, base, out, depth + 1);
    }
}

fn walk_rust_unsafe(
    node: Node,
    src: &[u8],
    rel_path: &str,
    out: &mut Vec<LocalStaticFinding>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    if matches!(k, "mod_item" | "function_item") && is_rust_test_subtree(node, src) {
        return;
    }

    if k == "function_item" {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(n, src).trim().to_string())
            .unwrap_or_else(|| "rust_fn".to_string());
        let fn_code = strip_comments_and_strings(node, src);
        let fn_start_ln = node.start_position().row + 1;
        let fn_low = fn_code.to_ascii_lowercase();

        let is_unsafe_fn = fn_low.starts_with("unsafe fn ")
            || fn_low.starts_with("pub unsafe fn ")
            || fn_low.starts_with("pub(crate) unsafe fn ");
        // Check `wrapping_mul` / `wrapping_add` flowing directly into allocation / unsafe indexing
        if (fn_low.contains("wrapping_mul(") || fn_low.contains("wrapping_add("))
            && (fn_low.contains("with_capacity(")
                || fn_low.contains("alloc(")
                || fn_low.contains("from_size_align")
                || fn_low.contains("unsafe"))
        {
            for (idx, line) in fn_code.lines().enumerate() {
                if line.contains("wrapping_mul(") || line.contains("wrapping_add(") {
                    out.push(make_phase9_finding(
                        "SMG-ENG-INT",
                        "HIGH",
                        format!(
                            "Modular `wrapping_*` arithmetic in `{}` near allocation/unsafe memory operation",
                            name
                        ),
                        rel_path,
                        fn_start_ln + idx,
                        &name,
                        SinkKind::IntegerOverflow,
                        GuardKind::MemoryBounds,
                        Confidence::Heuristic,
                        "Use `checked_mul`/`checked_add` (`ok_or(...)`) instead of `wrapping_*` before sizing buffers or unsafe offsets.",
                    ));
                }
            }
        }

        if is_unsafe_fn {
            walk_rust_unsafe_block_lines(
                &fn_code,
                fn_start_ln,
                fn_start_ln,
                rel_path,
                &name,
                &fn_code,
                out,
            );
            return;
        }

        let mut c = node.walk();
        for ch in node.children(&mut c) {
            walk_rust_unsafe_in_fn(
                ch,
                src,
                rel_path,
                &name,
                fn_start_ln,
                &fn_code,
                out,
                depth + 1,
            );
        }
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_unsafe(ch, src, rel_path, out, depth + 1);
    }
}

fn walk_rust_unsafe_block_lines(
    block_code: &str,
    start_ln: usize,
    fn_start_ln: usize,
    rel_path: &str,
    fn_name: &str,
    enclosing_fn_code: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let fn_lines: Vec<&str> = enclosing_fn_code.lines().collect();
    let has_checked_arith = enclosing_fn_code.contains("checked_mul")
        || enclosing_fn_code.contains("checked_add")
        || enclosing_fn_code.contains("saturating_");

    let pre_block_end = start_ln.saturating_sub(fn_start_ln).min(fn_lines.len());
    let mut saw_len = false;
    let mut saw_cmp = false;
    for &l in &fn_lines[..pre_block_end] {
        saw_len |= l.contains(".len()");
        saw_cmp |= l.contains('<')
            || l.contains("<=")
            || l.contains("assert!")
            || l.contains("assert_eq!")
            || l.contains(".min(");
    }

    for (idx, raw_line) in block_code.lines().enumerate() {
        let ln = start_ln + idx;
        let trimmed = raw_line.trim();
        // O(1) cumulative bounds-guard tracking (only lines BEFORE or ON the current unsafe line)
        saw_len |= raw_line.contains(".len()");
        saw_cmp |= raw_line.contains('<')
            || raw_line.contains("<=")
            || raw_line.contains("assert!")
            || raw_line.contains("assert_eq!")
            || raw_line.contains(".min(");
        let has_bounds_guard = saw_len && saw_cmp;

        let mut is_uninit_ub = trimmed.contains("mem::uninitialized(")
            || (trimmed.contains("MaybeUninit::uninit().assume_init(")
                && !enclosing_fn_code.contains(".write(")
                && !enclosing_fn_code.contains("as_mut_ptr"));
        // Also track named `let [mut] x = MaybeUninit...::uninit(); ... x.assume_init()` without `.write(`/`.as_mut_ptr()`
        if !is_uninit_ub
            && let Some(recv) = trimmed.split(".assume_init(").next().map(|s| {
                s.rsplit([' ', '=', '(', '{', ';'])
                    .next()
                    .unwrap_or("")
                    .trim()
            })
            && !recv.is_empty()
            && recv.chars().all(|c| c.is_alphanumeric() || c == '_')
            && enclosing_fn_code.contains("MaybeUninit")
            && enclosing_fn_code.lines().any(|l| {
                let binds_recv = |pat: &str| -> bool {
                    l.find(pat).is_some_and(|i| {
                        l[i + pat.len()..]
                            .chars()
                            .next()
                            .is_some_and(|c| matches!(c, ':' | '=' | ' ' | '\t'))
                    })
                };
                l.contains("uninit")
                    && (binds_recv(&format!("let {}", recv))
                        || binds_recv(&format!("let mut {}", recv)))
            })
            && !enclosing_fn_code.contains(&format!("{}.write(", recv))
            && !enclosing_fn_code.contains(&format!("{}.as_mut_ptr", recv))
            && !enclosing_fn_code.contains(&format!("{}[", recv))
            && !enclosing_fn_code.contains(&format!("addr_of_mut!({}", recv))
            && !enclosing_fn_code.contains(&format!("&mut {}", recv))
        {
            is_uninit_ub = true;
        }
        if is_uninit_ub {
            out.push(make_phase9_finding(
                "SMG-MEM-BOUNDS",
                "CRITICAL",
                format!("Uninitialized memory UB (`mem::uninitialized`/`assume_init`) in `{}`", fn_name),
                rel_path,
                ln,
                fn_name,
                SinkKind::MemorySafety,
                GuardKind::MemoryBounds,
                Confidence::Confirmed,
                "Initialize `MaybeUninit<T>` completely via `.write(...)` before calling `.assume_init()`.",
            ));
        }

        if (trimmed.contains(".get_unchecked(") || trimmed.contains(".get_unchecked_mut("))
            && !has_bounds_guard
        {
            out.push(make_phase9_finding(
                "SMG-MEM-BOUNDS",
                "HIGH",
                format!(
                    "Unchecked slice access (`get_unchecked`) in `unsafe` block inside `{}` without `.len()` bounds validation",
                    fn_name
                ),
                rel_path,
                ln,
                fn_name,
                SinkKind::MemorySafety,
                GuardKind::MemoryBounds,
                Confidence::Confirmed,
                "Use checked `.get(idx)` or explicitly assert `idx < slice.len()` before entering `unsafe`.",
            ));
        }

        let is_raw_ptr_op = trimmed.contains("from_raw_parts")
            || trimmed.contains("copy_nonoverlapping")
            || trimmed.contains("ptr::copy(")
            || trimmed.contains(".offset(")
            || (trimmed.contains(".add(")
                && (trimmed.contains("ptr") || trimmed.contains("as_ptr")));
        if is_raw_ptr_op && !has_bounds_guard && !trimmed.contains(".min(") {
            out.push(make_phase9_finding(
                "SMG-MEM-BOUNDS",
                "HIGH",
                format!(
                    "Unchecked raw pointer/slice operation inside `unsafe` block in `{}`",
                    fn_name
                ),
                rel_path,
                ln,
                fn_name,
                SinkKind::MemorySafety,
                GuardKind::MemoryBounds,
                Confidence::Heuristic,
                "Verify non-null alignment and `len`/`offset <= cap.len()` before raw pointer manipulation.",
            ));
        }

        if (trimmed.contains("from_size_align_unchecked")
            || trimmed.contains("from_raw_parts")
            || trimmed.contains("alloc("))
            && (trimmed.contains(" * ") || trimmed.contains(" + "))
            && !has_checked_arith
        {
            out.push(make_phase9_finding(
                "SMG-ENG-INT",
                "HIGH",
                format!(
                    "Unchecked allocation arithmetic in `unsafe` block inside `{}`",
                    fn_name
                ),
                rel_path,
                ln,
                fn_name,
                SinkKind::IntegerOverflow,
                GuardKind::MemoryBounds,
                Confidence::Confirmed,
                "Compute byte sizes with `checked_mul` / `checked_add` or `Layout::array::<T>(n)?` instead of raw arithmetic.",
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_rust_unsafe_in_fn(
    node: Node,
    src: &[u8],
    rel_path: &str,
    fn_name: &str,
    fn_start_ln: usize,
    enclosing_fn_code: &str,
    out: &mut Vec<LocalStaticFinding>,
    depth: usize,
) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "unsafe_block" {
        let block_code = strip_comments_and_strings(node, src);
        let start_ln = node.start_position().row + 1;
        walk_rust_unsafe_block_lines(
            &block_code,
            start_ln,
            fn_start_ln,
            rel_path,
            fn_name,
            enclosing_fn_code,
            out,
        );
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_unsafe_in_fn(
            ch,
            src,
            rel_path,
            fn_name,
            fn_start_ln,
            enclosing_fn_code,
            out,
            depth + 1,
        );
    }
}
