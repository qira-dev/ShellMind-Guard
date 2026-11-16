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
        Regex::new(r#"\b(memcpy|memmove|strncpy|read|recv)\s*\("#)
            .expect("valid c bounded copy regex")
    })
}

fn c_scanf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bs?scanf\s*\([^;]*?"[^"]*%s"#).expect("valid scanf regex"))
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
            walk_c_cpp_functions(root, src, rel_path, static_findings);
        }
        Language::Rust => {
            walk_rust_unsafe(root, src, rel_path, static_findings);
        }
        _ => {}
    }
}

fn walk_c_cpp_functions(node: Node, src: &[u8], rel_path: &str, out: &mut Vec<LocalStaticFinding>) {
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
        walk_c_cpp_functions(ch, src, rel_path, out);
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

fn has_preceding_bounds_check(preceding_code: &str, len_expr: &str) -> bool {
    let len_low = len_expr.to_ascii_lowercase();
    if len_low.chars().all(|c| c.is_ascii_digit() || c == '_')
        || len_low.contains("sizeof")
        || len_low.starts_with("min(")
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
        for line in prec_low.lines() {
            let trimmed = line.trim();
            if (trimmed.contains("if ") || trimmed.contains("if(") || trimmed.contains("assert"))
                && trimmed.contains(v)
                && (trimmed.contains('<')
                    || trimmed.contains("<=")
                    || trimmed.contains('>')
                    || trimmed.contains(">=")
                    || trimmed.contains("sizeof")
                    || trimmed.contains("max")
                    || trimmed.contains("cap"))
            {
                return true;
            }
            if trimmed.contains(&format!("{} =", v))
                && (trimmed.contains("min(") || trimmed.contains("std::min"))
            {
                return true;
            }
            // Buffer dynamically allocated cleanly to the exact same un-overflowed length right above
            if trimmed.contains(&format!("malloc({})", v))
                || trimmed.contains(&format!("calloc({},", v))
            {
                return true;
            }
        }
    }
    false
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
    // Also honor explicit upper-bound clamp on the multiplier variables (e.g. `if (count > MAX_ITEMS)`)
    let vars: Vec<String> = ident_tok_re()
        .find_iter(&arith_expr.to_ascii_lowercase())
        .map(|m| m.as_str().to_string())
        .filter(|v| {
            !matches!(
                v.as_str(),
                "sizeof" | "size_t" | "int" | "uint32_t" | "uint64_t"
            )
        })
        .collect();
    let bounded_count = vars
        .iter()
        .filter(|v| {
            low.lines().any(|l| {
                let t = l.trim();
                (t.contains("if ") || t.contains("if(") || t.contains("assert"))
                    && t.contains(v.as_str())
                    && (t.contains("max")
                        || t.contains("limit")
                        || t.contains("<=")
                        || t.contains('>'))
            })
        })
        .count();
    !vars.is_empty() && bounded_count == vars.len()
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
        let preceding = lines[..idx].join("\n");

        // 1. Always-unsafe unbounded C string/buffer routines
        if let Some(m) = c_unsafe_copy_re().find(trimmed) {
            let api = trimmed[m.start()..m.end()].trim_end_matches('(').trim();
            let args = extract_call_args(trimmed, m.start()).unwrap_or_default();
            let src_arg = if api == "gets" {
                "stdin"
            } else {
                args.get(1).map(|s| s.as_str()).unwrap_or("")
            };
            let is_tiny_safe_literal = (api == "strcpy" || api == "strcat")
                && src_arg.starts_with('"')
                && src_arg.ends_with('"')
                && src_arg.len() <= 10;
            let safe_numeric_sprintf =
                (api == "sprintf" || api == "vsprintf") && !trimmed.contains("%s");
            if !is_tiny_safe_literal && !safe_numeric_sprintf {
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

        if c_scanf_re().is_match(trimmed) {
            out.push(make_phase9_finding(
                "SMG-MEM-BOUNDS",
                "HIGH",
                format!(
                    "Unbounded `%s` format specifier in `scanf`/`sscanf` inside `{}`",
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

        // 2. Bounded copies/reads whose length comes from an unchecked variable
        if let Some(m) = c_bounded_copy_re().find(trimmed) {
            let api = trimmed[m.start()..m.end()].trim_end_matches('(').trim();
            if let Some(args) = extract_call_args(trimmed, m.start())
                && let Some(len_arg) = args.get(2)
                && !has_preceding_bounds_check(&preceding, len_arg)
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
                    Confidence::Confirmed,
                    "Validate `len <= sizeof(dst)` (checking signedness `len >= 0` if signed) before calling `memcpy`/`memmove`/`read`/`recv`.",
                ));
            }
        }

        // 3. Integer overflow in `malloc(a * b)` / `realloc(p, a * b)` / `new T[a * b]`
        for cap in c_alloc_re().captures_iter(trimmed) {
            let expr = cap
                .get(2)
                .or_else(|| cap.get(3))
                .or_else(|| cap.get(4))
                .map(|m| m.as_str().trim())
                .unwrap_or("");
            let has_arith = expr.contains('*') || expr.contains('+') || expr.contains("<<");
            let non_const = ident_tok_re().captures_iter(expr).any(|c| {
                let tok = &c[1];
                tok != "sizeof" && !tok.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_')
            });
            if has_arith && non_const && !has_overflow_guard(&preceding, expr) {
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

fn strip_comments_and_strings(node: Node, src: &[u8]) -> String {
    let base = node.start_byte();
    let end = node.end_byte().min(src.len());
    let mut bytes = src[base..end].to_vec();
    blank_trivia_nodes(node, base, &mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn blank_trivia_nodes(node: Node, base: usize, out: &mut [u8]) {
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
        blank_trivia_nodes(ch, base, out);
    }
}

fn walk_rust_unsafe(node: Node, src: &[u8], rel_path: &str, out: &mut Vec<LocalStaticFinding>) {
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
        let fn_low = fn_code.to_ascii_lowercase();

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
                        node.start_position().row + 1 + idx,
                        &name,
                        SinkKind::IntegerOverflow,
                        GuardKind::MemoryBounds,
                        Confidence::Confirmed,
                        "Use `checked_mul`/`checked_add` (`ok_or(...)`) instead of `wrapping_*` before sizing buffers or unsafe offsets.",
                    ));
                }
            }
        }

        let mut c = node.walk();
        for ch in node.children(&mut c) {
            walk_rust_unsafe_in_fn(ch, src, rel_path, &name, &fn_code, out);
        }
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_unsafe(ch, src, rel_path, out);
    }
}

fn walk_rust_unsafe_in_fn(
    node: Node,
    src: &[u8],
    rel_path: &str,
    fn_name: &str,
    enclosing_fn_code: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    if node.kind() == "unsafe_block" {
        let block_code = strip_comments_and_strings(node, src);
        let start_ln = node.start_position().row + 1;
        let has_bounds_guard = enclosing_fn_code.contains(".len()")
            && (enclosing_fn_code.contains('<')
                || enclosing_fn_code.contains("<=")
                || enclosing_fn_code.contains("assert!")
                || enclosing_fn_code.contains("assert_eq!")
                || enclosing_fn_code.contains(".min("));
        let has_checked_arith = enclosing_fn_code.contains("checked_mul")
            || enclosing_fn_code.contains("checked_add")
            || enclosing_fn_code.contains("saturating_");

        for (idx, raw_line) in block_code.lines().enumerate() {
            let ln = start_ln + idx;
            let trimmed = raw_line.trim();

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

            if (trimmed.contains("from_raw_parts")
                || trimmed.contains("copy_nonoverlapping")
                || trimmed.contains("ptr::copy(")
                || trimmed.contains(".offset(")
                || trimmed.contains(".add("))
                && !has_bounds_guard
                && !trimmed.contains(".min(")
            {
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
                    Confidence::Confirmed,
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
        return;
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_rust_unsafe_in_fn(ch, src, rel_path, fn_name, enclosing_fn_code, out);
    }
}
