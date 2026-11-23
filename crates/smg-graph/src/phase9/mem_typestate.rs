//! Phase 28A: C/C++ Pointer Lifecycle Typestate Automaton (Use-After-Free, Double-Free,
//! Symbolic Constant Buffer-Length Overflow) + Rust Async-Mutex-Held-Across-`.await` Detector.

use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtrState {
    Live,
    Freed(usize, i32), // (freed at line, brace_depth where freed)
    Nullified,
}

fn free_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:free\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|delete(?:\s*\[\s*\])?\s+([A-Za-z_][A-Za-z0-9_]*)\s*;)").expect("valid free re")
    })
}

fn stack_buf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:char|uint8_t|unsigned\s+char|byte)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]",
        )
        .expect("valid stack buf re")
    })
}

fn malloc_buf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?(?:malloc\s*\(\s*(\d+)\s*\)|calloc\s*\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\))").expect("valid malloc re")
    })
}

/// Counts `{` and `}` on a single line outside string (`"..."`) and char (`'...'`) literals.
fn count_code_braces(line: &str) -> (i32, i32) {
    let bytes = line.as_bytes();
    let mut opens = 0i32;
    let mut closes = 0i32;
    let mut in_quote: Option<u8> = None;
    let mut esc = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if esc {
            esc = false;
            i += 1;
            continue;
        }
        if let Some(q) = in_quote {
            if b == b'\\' {
                esc = true;
            } else if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'/' if bytes.get(i + 1) == Some(&b'/') => break,
            b'"' | b'\'' => in_quote = Some(b),
            b'{' => opens += 1,
            b'}' => closes += 1,
            _ => {}
        }
        i += 1;
    }
    (opens, closes)
}

fn memcpy_const_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:memcpy|memmove|memset)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,[^,]+,\s*(\d+)\s*\)",
        )
        .expect("valid memcpy re")
    })
}

fn null_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:NULL|nullptr|0)\s*;")
            .expect("valid null assign re")
    })
}

/// Zero-allocation O(N) check for `var->`, `var[`, or `*var` with C identifier word boundaries.
fn line_derefs_ptr(line: &str, var: &str) -> bool {
    let bytes = line.as_bytes();
    let vb = var.as_bytes();
    if vb.is_empty() || bytes.len() < vb.len() + 1 {
        return false;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0usize;
    while i + vb.len() <= bytes.len() {
        if &bytes[i..i + vb.len()] == vb {
            let left_ok = i == 0 || !is_ident(bytes[i - 1]);
            if left_ok {
                // Check `*var` (prefix deref)
                if i > 0 && bytes[i - 1] == b'*' {
                    let right_ok = i + vb.len() == bytes.len() || !is_ident(bytes[i + vb.len()]);
                    if right_ok {
                        return true;
                    }
                }
                // Check `var->` or `var[` (skipping optional ASCII whitespace)
                let mut j = i + vb.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len()
                    && (bytes[j] == b'['
                        || (bytes[j] == b'-' && j + 1 < bytes.len() && bytes[j + 1] == b'>'))
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Zero-allocation check for `var = ...` reassignment anywhere on the line (excluding `==`).
fn line_reassigns_ptr(line: &str, var: &str) -> bool {
    let bytes = line.as_bytes();
    let vb = var.as_bytes();
    if vb.is_empty() || bytes.len() < vb.len() + 2 {
        return false;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0usize;
    while i + vb.len() < bytes.len() {
        if &bytes[i..i + vb.len()] == vb {
            let left_ok = i == 0 || !is_ident(bytes[i - 1]);
            if left_ok {
                let mut j = i + vb.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len()
                    && bytes[j] == b'='
                    && (j + 1 >= bytes.len() || bytes[j + 1] != b'=')
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Audits C/C++ source code for Use-After-Free, Double-Free, and provable constant
/// buffer-length overflows (`malloc(N)` / `char buf[N]` -> `memcpy(buf, src, M)` where `M > N`).
pub fn analyze_c_cpp_memory_typestate(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    let cleaned = crate::ast::strip_comments(source);
    let mut findings = Vec::new();
    let mut ptr_states: HashMap<String, PtrState> = HashMap::new();
    let mut buf_sizes: HashMap<String, (usize, i32)> = HashMap::new();
    let mut brace_depth: i32 = 0;

    for (idx, raw_line) in cleaned.lines().enumerate() {
        let ln = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Reset function-local state when exiting top-level function body,
        // and clear conditional-branch `Freed` states & inner-scope buffers on block exit.
        let (opens, closes) = count_code_braces(line);
        if brace_depth == 0 && opens > 0 {
            ptr_states.clear();
            buf_sizes.clear();
        }
        let prev_depth = brace_depth;
        brace_depth = (brace_depth + opens - closes).max(0);
        if brace_depth == 0 {
            ptr_states.clear();
            buf_sizes.clear();
            continue;
        }
        if brace_depth < prev_depth
            || line.starts_with("else")
            || line.starts_with("} else")
            || line.starts_with("case ")
            || line.starts_with("default:")
            || (line.ends_with(':') && !line.contains(' ') && !line.contains('('))
        {
            ptr_states.retain(|_, st| !matches!(st, PtrState::Freed(_, d) if *d > brace_depth));
            buf_sizes.retain(|_, (_, d)| *d <= brace_depth);
            if line.starts_with("else")
                || line.starts_with("} else")
                || line.starts_with("case ")
                || line.starts_with("default:")
            {
                ptr_states
                    .retain(|_, st| !matches!(st, PtrState::Freed(_, d) if *d >= brace_depth));
            }
        }

        // 1. Track stack & heap constant buffer capacities (with lexical brace depth)
        if let Some(c) = stack_buf_re().captures(line)
            && let (Some(v), Some(sz)) = (c.get(1), c.get(2))
            && let Ok(n) = sz.as_str().parse::<usize>()
        {
            buf_sizes.insert(v.as_str().to_string(), (n, brace_depth));
            ptr_states.insert(v.as_str().to_string(), PtrState::Live);
        }
        if let Some(c) = malloc_buf_re().captures(line)
            && let Some(v) = c.get(1)
        {
            let cap_opt = if let Some(m_sz) = c.get(2) {
                m_sz.as_str().parse::<usize>().ok()
            } else if let Some(c1) = c.get(3) {
                let n1 = c1.as_str().parse::<usize>().ok();
                let n2 = c
                    .get(4)
                    .map(|m| m.as_str().parse::<usize>().ok())
                    .unwrap_or(Some(1));
                n1.zip(n2).and_then(|(a, b)| a.checked_mul(b))
            } else {
                None
            };
            if let Some(n) = cap_opt {
                buf_sizes.insert(v.as_str().to_string(), (n, brace_depth));
                ptr_states.insert(v.as_str().to_string(), PtrState::Live);
            }
        }

        // 2. Check symbolic constant buffer-length overflow (`memcpy(buf, src, M)` where M > N)
        if let Some(c) = memcpy_const_re().captures(line)
            && let (Some(v), Some(len_m)) = (c.get(1), c.get(2))
            && let Ok(write_len) = len_m.as_str().parse::<usize>()
            && let Some(&(cap, _)) = buf_sizes.get(v.as_str())
            && write_len > cap
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-MEM-BOUNDS".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Provable buffer overflow: `{}` has capacity {} bytes but write copies {} bytes",
                    v.as_str(),
                    cap,
                    write_len
                ),
                rel_path: rel_path.to_string(),
                line: ln,
                symbol: v.as_str().to_string(),
                sink_kind: SinkKind::MemorySafety,
                missing_guard: GuardKind::MemoryBounds,
                confidence: Confidence::Proven,
                remediation: format!(
                    "Bound the copy length to `sizeof({})` ({cap} bytes) or allocate at least {write_len} bytes.",
                    v.as_str()
                ),
            });
        }

        // 3. Pointer nullification (`p = NULL;`)
        if let Some(c) = null_assign_re().captures(line)
            && let Some(v) = c.get(1)
        {
            ptr_states.insert(v.as_str().to_string(), PtrState::Nullified);
            continue;
        }

        // 4. `free(p)` / `delete p` -> Double-Free check + transition to Freed
        if let Some(c) = free_call_re().captures(line)
            && let Some(v) = c.get(1).or_else(|| c.get(2))
        {
            let var = v.as_str();
            if let Some(PtrState::Freed(first_ln, _)) = ptr_states.get(var) {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-MEM-BOUNDS".into(),
                    severity: "CRITICAL".into(),
                    title: format!(
                        "Double-free of pointer `{var}` (previously freed at line {first_ln})"
                    ),
                    rel_path: rel_path.to_string(),
                    line: ln,
                    symbol: var.to_string(),
                    sink_kind: SinkKind::MemorySafety,
                    missing_guard: GuardKind::MemoryBounds,
                    confidence: Confidence::Confirmed,
                    remediation: format!(
                        "Set `{var} = NULL` immediately after freeing and ensure single ownership."
                    ),
                });
            } else {
                // Single-line conditional `if (x) free(p);` does not unconditionally free `p`
                let is_single_line_cond =
                    (line.starts_with("if ") || line.starts_with("if(")) && !line.contains('{');
                if !is_single_line_cond {
                    ptr_states.insert(var.to_string(), PtrState::Freed(ln, brace_depth));
                }
            }
            continue;
        }

        // 5. Check Use-After-Free dereference (`p->`, `p[i]`, `*p`) on any currently Freed pointer
        if ptr_states
            .values()
            .any(|st| matches!(st, PtrState::Freed(_, _)))
        {
            let freed_vars: Vec<(String, usize)> = ptr_states
                .iter()
                .filter_map(|(k, st)| match st {
                    PtrState::Freed(fln, _) => Some((k.clone(), *fln)),
                    _ => None,
                })
                .collect();

            for (var, freed_ln) in freed_vars {
                // Reassignment (`var = ...`) revives the pointer
                if line_reassigns_ptr(line, &var) {
                    ptr_states.insert(var, PtrState::Live);
                    continue;
                }
                if line_derefs_ptr(line, &var) {
                    findings.push(LocalStaticFinding {
                        rule_id: "SMG-MEM-BOUNDS".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "Use-after-free: pointer `{var}` dereferenced after `free`/`delete` at line {freed_ln}"
                        ),
                        rel_path: rel_path.to_string(),
                        line: ln,
                        symbol: var.clone(),
                        sink_kind: SinkKind::MemorySafety,
                        missing_guard: GuardKind::MemoryBounds,
                        confidence: Confidence::Confirmed,
                        remediation: format!(
                            "Do not dereference `{var}` after freeing it; nullify `{var} = NULL` and restructure ownership."
                        ),
                    });
                }
            }
        }
    }

    findings
}

/// Detects Rust `std::sync::Mutex` / `RwLock` guards held across `.await` points inside `async fn`
/// (which causes Tokio / async executor deadlocks!).
pub fn analyze_rust_async_mutex_across_await(
    rel_path: &str,
    source: &str,
) -> Vec<LocalStaticFinding> {
    if !rel_path.ends_with(".rs") || !source.contains("async fn") || !source.contains(".await") {
        return Vec::new();
    }
    let uses_std_mutex =
        source.contains("std::sync::Mutex") || source.contains("parking_lot::Mutex");
    let uses_std_rwlock =
        source.contains("std::sync::RwLock") || source.contains("parking_lot::RwLock");
    if !uses_std_mutex && !uses_std_rwlock {
        return Vec::new();
    }

    static LOCK_GUARD_RE: OnceLock<Regex> = OnceLock::new();
    static RW_GUARD_RE: OnceLock<Regex> = OnceLock::new();
    let lock_guard_re = LOCK_GUARD_RE.get_or_init(|| {
        Regex::new(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]+\.lock\(\)")
            .expect("valid lock guard re")
    });
    let rw_guard_re = RW_GUARD_RE.get_or_init(|| {
        Regex::new(
            r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]+\.(?:lock|read|write)\(\)",
        )
        .expect("valid rw guard re")
    });
    let guard_re = if uses_std_rwlock {
        rw_guard_re
    } else {
        lock_guard_re
    };

    let cleaned = crate::ast::strip_comments(source);
    let mut findings = Vec::new();
    let mut in_async = false;
    let mut async_depth: i32 = 0;
    let mut active_guards: Vec<(String, usize, i32)> = Vec::new(); // (name, line, scope_depth)
    let mut cfg_test_pending = false;
    let mut cfg_test_in_block = false;
    let mut cfg_test_depth: i32 = 0;

    for (idx, raw_line) in cleaned.lines().enumerate() {
        let ln = idx + 1;
        let line = raw_line.trim();
        let (opens, closes) = count_code_braces(line);

        if !cfg_test_in_block && !cfg_test_pending && line.starts_with("#[cfg(test)]") {
            cfg_test_pending = true;
            if opens > 0 {
                cfg_test_in_block = true;
                cfg_test_pending = false;
                cfg_test_depth = opens - closes;
                if cfg_test_depth <= 0 {
                    cfg_test_in_block = false;
                    cfg_test_depth = 0;
                }
            } else if line.contains(';') {
                cfg_test_pending = false;
            }
            continue;
        }
        if cfg_test_pending || cfg_test_in_block {
            if opens > 0 {
                cfg_test_in_block = true;
                cfg_test_pending = false;
            }
            if cfg_test_in_block {
                cfg_test_depth += opens - closes;
                if cfg_test_depth <= 0 {
                    cfg_test_in_block = false;
                    cfg_test_pending = false;
                    cfg_test_depth = 0;
                }
            } else if line.contains(';') {
                cfg_test_pending = false;
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }

        if line.contains("async fn ") {
            in_async = true;
            async_depth = 0;
            active_guards.clear();
        }
        if !in_async {
            continue;
        }

        if let Some(c) = guard_re.captures(line)
            && let Some(gname) = c.get(1)
            && !line.contains(".await")
        {
            active_guards.push((gname.as_str().to_string(), ln, async_depth));
        }

        // Remove explicitly dropped guards (`drop(guard)`)
        active_guards.retain(|(g, _, _)| !line.contains(&format!("drop({g})")));

        // Check `.await` while blocking sync guard is live in current or outer scope
        if line.contains(".await") && !active_guards.is_empty() {
            for (gname, gln, _) in &active_guards {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-CONC-DEADLOCK".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Blocking sync mutex guard `{gname}` (acquired at line {gln}) held across `.await` point (async executor deadlock)"
                    ),
                    rel_path: rel_path.to_string(),
                    line: ln,
                    symbol: gname.clone(),
                    sink_kind: SinkKind::ConcurrencyHazard,
                    missing_guard: GuardKind::LockOrdering,
                    confidence: Confidence::Confirmed,
                    remediation: format!(
                        "Call `drop({gname})` or narrow its lexical `{{ ... }}` block before `.await`, or switch to `tokio::sync::Mutex`."
                    ),
                });
            }
            active_guards.clear();
        }

        async_depth += opens - closes;
        // Drop guards whose lexical scope closed
        active_guards.retain(|(_, _, d)| *d <= async_depth);
        if async_depth <= 0 && closes > 0 {
            in_async = false;
            active_guards.clear();
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_c_uaf_double_free_and_constant_overflow_with_zero_fp_on_nullified() {
        let vuln_c = r#"
void bad(const char *src) {
    char buf[16];
    memcpy(buf, src, 64);
    struct Node *p = malloc(32);
    free(p);
    p->val = 10;
    free(p);
}
void safe() {
    struct Node *q = malloc(32);
    free(q);
    q = NULL;
    free(q);
}
"#;
        let hits = analyze_c_cpp_memory_typestate("src/mem.c", vuln_c);
        assert!(
            hits.iter()
                .any(|h| h.title.contains("Provable buffer overflow"))
        );
        assert!(hits.iter().any(|h| h.title.contains("Use-after-free")));
        assert!(hits.iter().any(|h| h.title.contains("Double-free")));
        assert!(!hits.iter().any(|h| h.symbol == "q"));
    }

    #[test]
    fn catches_rust_std_sync_mutex_held_across_await_and_allows_dropped_guard() {
        let code = r#"
use std::sync::Mutex;
async fn deadlock(m: &Mutex<u32>) {
    let g = m.lock().unwrap();
    do_io().await;
    println!("{}", *g);
}
async fn safe_drop(m: &Mutex<u32>) {
    let g = m.lock().unwrap();
    let v = *g;
    drop(g);
    do_io(v).await;
}
"#;
        let hits = analyze_rust_async_mutex_across_await("src/worker.rs", code);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "SMG-CONC-DEADLOCK");
        assert!(hits[0].title.contains("acquired at line 4"));
    }
}
