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
        Regex::new(r"\b(?:char|uint8_t|unsigned\s+char|byte)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]").expect("valid stack buf re")
    })
}

fn malloc_buf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?(?:malloc|calloc)\s*\(\s*(\d+)\s*\)").expect("valid malloc re")
    })
}

fn memcpy_const_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:memcpy|memmove|memset)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,[^,]+,\s*(\d+)\s*\)").expect("valid memcpy re")
    })
}

fn null_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:NULL|nullptr|0)\s*;").expect("valid null assign re")
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
    let mut findings = Vec::new();
    let mut ptr_states: HashMap<String, PtrState> = HashMap::new();
    let mut buf_sizes: HashMap<String, usize> = HashMap::new();
    let mut brace_depth: i32 = 0;

    for (idx, raw_line) in source.lines().enumerate() {
        let ln = idx + 1;
        let line = raw_line.split("//").next().unwrap_or(raw_line).trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') || line.starts_with('#') {
            continue;
        }

        // Reset function-local state when exiting top-level function body,
        // and clear conditional-branch `Freed` states when exiting an inner `{ ... }` block
        // or entering an `else` / `case` / `default:` / goto-label branch.
        let opens = line.chars().filter(|&c| c == '{').count() as i32;
        let closes = line.chars().filter(|&c| c == '}').count() as i32;
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
            if line.starts_with("else")
                || line.starts_with("} else")
                || line.starts_with("case ")
                || line.starts_with("default:")
            {
                ptr_states.retain(|_, st| !matches!(st, PtrState::Freed(_, d) if *d >= brace_depth));
            }
        }

        // 1. Track stack & heap constant buffer capacities
        if let Some(c) = stack_buf_re().captures(line)
            && let (Some(v), Some(sz)) = (c.get(1), c.get(2))
            && let Ok(n) = sz.as_str().parse::<usize>()
        {
            buf_sizes.insert(v.as_str().to_string(), n);
            ptr_states.insert(v.as_str().to_string(), PtrState::Live);
        }
        if let Some(c) = malloc_buf_re().captures(line)
            && let (Some(v), Some(sz)) = (c.get(1), c.get(2))
            && let Ok(n) = sz.as_str().parse::<usize>()
        {
            buf_sizes.insert(v.as_str().to_string(), n);
            ptr_states.insert(v.as_str().to_string(), PtrState::Live);
        }

        // 2. Check symbolic constant buffer-length overflow (`memcpy(buf, src, M)` where M > N)
        if let Some(c) = memcpy_const_re().captures(line)
            && let (Some(v), Some(len_m)) = (c.get(1), c.get(2))
            && let Ok(write_len) = len_m.as_str().parse::<usize>()
            && let Some(&cap) = buf_sizes.get(v.as_str())
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
        if ptr_states.values().any(|st| matches!(st, PtrState::Freed(_, _))) {
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
pub fn analyze_rust_async_mutex_across_await(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    if !rel_path.ends_with(".rs") || !source.contains("async fn") || !source.contains(".await") {
        return Vec::new();
    }
    let uses_std_sync = source.contains("std::sync::Mutex")
        || source.contains("std::sync::RwLock")
        || source.contains("parking_lot::Mutex");
    if !uses_std_sync {
        return Vec::new();
    }

    static GUARD_RE: OnceLock<Regex> = OnceLock::new();
    let guard_re = GUARD_RE.get_or_init(|| {
        Regex::new(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]+\.(?:lock|read|write)\(\)")
            .expect("valid guard re")
    });

    let mut findings = Vec::new();
    let mut in_async = false;
    let mut async_depth: i32 = 0;
    let mut active_guards: Vec<(String, usize, i32)> = Vec::new(); // (name, line, scope_depth)
    let mut in_cfg_test = false;

    for (idx, raw_line) in source.lines().enumerate() {
        let ln = idx + 1;
        let line = raw_line.split("//").next().unwrap_or(raw_line).trim();
        if line.starts_with("#[cfg(test)]") {
            in_cfg_test = true;
        }
        if in_cfg_test || line.is_empty() {
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

        let opens = line.chars().filter(|&c| c == '{').count() as i32;
        let closes = line.chars().filter(|&c| c == '}').count() as i32;

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
        assert!(hits.iter().any(|h| h.title.contains("Provable buffer overflow")));
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
