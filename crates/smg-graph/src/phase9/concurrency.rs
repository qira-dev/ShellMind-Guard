use super::{is_rust_test_subtree, make_phase9_finding};
use crate::ast::{
    Confidence, GuardKind, LocalStaticFinding, LockHeldCall, LockOrderEdge, SinkKind, SymbolInfo,
    node_text, strip_comments,
};
use crate::lattice::{LatticeFinding, TraceHop};
use petgraph::graph::{DiGraph, NodeIndex};
use regex::Regex;
use smg_core::Language;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use tree_sitter::Node;

#[derive(Clone, Debug)]
struct ActiveLock {
    norm_name: String,
    guard_var: Option<String>,
    line: usize,
    scope_depth: usize,
    is_manual_unlock: bool,
}

#[derive(Clone, Debug)]
struct FnSpan {
    line_start: usize,
    line_end: usize,
    fn_name: String,
    code: String,
}

#[derive(Clone, Debug)]
struct EdgeWitness {
    file: String,
    hops: Vec<TraceHop>,
}

fn cpp_raii_lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(?:std::)?(?:lock_guard|unique_lock|shared_lock)\s*(?:<[^>]+>)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]+)\)"#,
        )
        .expect("valid cpp raii lock regex")
    })
}

fn pthread_lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\bpthread_mutex_lock\s*\(\s*([^)]+)\)"#).expect("valid pthread lock regex")
    })
}

fn pthread_unlock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\bpthread_mutex_unlock\s*\(\s*([^)]+)\)"#)
            .expect("valid pthread unlock regex")
    })
}

fn method_lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?([A-Za-z_][A-Za-z0-9_.\->:\(\)&]*?)\s*\.\s*(lock|Lock|rlock|RLock|wlock|WLock|write|read|blocking_lock|acquire)\s*\(\s*\)"#,
        )
        .expect("valid method lock regex")
    })
}

fn is_plausible_lock_method(method: &str, raw_recv: &str, file_uses_rwlock: bool) -> bool {
    match method {
        "read" | "write" => {
            let rl = raw_recv.to_ascii_lowercase();
            file_uses_rwlock
                || rl.contains("lock")
                || rl.contains("rw")
                || rl.contains("mtx")
                || rl.ends_with("mu")
        }
        "acquire" => {
            let rl = raw_recv.to_ascii_lowercase();
            rl.contains("lock") || rl.contains("mutex") || rl.contains("mtx")
        }
        _ => true,
    }
}

fn method_unlock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"([A-Za-z_][A-Za-z0-9_.\->:\(\)&]*?)\s*\.\s*(unlock|Unlock|runlock|RUnlock|release)\s*\(\s*\)"#,
        )
        .expect("valid method unlock regex")
    })
}

fn rust_drop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\bdrop\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#).expect("valid rust drop regex")
    })
}

fn call_ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("#).expect("valid call regex"))
}

fn c_handle_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?(?:fopen|open|socket|accept|sqlite3_open|PQconnectdb|malloc|calloc|realloc)\s*\("#,
        )
        .expect("valid c handle regex")
    })
}

fn go_handle_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:,\s*[A-Za-z_][A-Za-z0-9_]*\s*)?:?=\s*(?:os\.Open(?:File)?|sql\.Open|net\.Dial|db\.Query(?:Context)?|http\.(?:Get|Post))\s*\("#,
        )
        .expect("valid go handle regex")
    })
}

fn py_handle_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:open|sqlite3\.connect|socket\.socket)\s*\("#,
        )
        .expect("valid py handle regex")
    })
}

fn jvm_handle_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(?:val|var|[A-Za-z_][A-Za-z0-9_<>]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+)?(?:FileInputStream|FileOutputStream|Socket|ServerSocket|BufferedReader|DriverManager\.getConnection)\s*\("#,
        )
        .expect("valid jvm handle regex")
    })
}

fn js_handle_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:await\s+)?(?:fs\.openSync|fs\.promises\.open|pool\.connect|mysql\.createConnection|sqlite3\.Database)\s*\("#,
        )
        .expect("valid js handle regex")
    })
}

fn norm_lock_name(raw: &str) -> String {
    let cleaned = raw
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_start_matches("mut ")
        .trim_start_matches("this->")
        .trim_start_matches("self->")
        .trim_start_matches("self.")
        .trim_start_matches("this.")
        .trim_end_matches(".clone()")
        .trim();
    // Strip outer parentheses or first argument before `,` (e.g., `m, std::adopt_lock`)
    let before_comma = cleaned.split(',').next().unwrap_or(cleaned).trim();
    before_comma
        .trim_start_matches('&')
        .trim()
        .to_ascii_lowercase()
}

fn is_ignored_stdio_lock(norm: &str) -> bool {
    let low = norm.trim_end_matches("()");
    matches!(
        low,
        "stdin" | "stdout" | "stderr" | "io::stdin" | "io::stdout" | "io::stderr"
    ) || low.ends_with(".stdin()")
        || low.ends_with(".stdout()")
        || low.ends_with(".stderr()")
}

fn count_braces_outside_strings(line: &str) -> (usize, usize) {
    let mut open = 0usize;
    let mut close = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut esc = false;
    for ch in line.chars() {
        if esc {
            esc = false;
            continue;
        }
        if (in_sq || in_dq) && ch == '\\' {
            esc = true;
            continue;
        }
        if ch == '\'' && !in_dq {
            in_sq = !in_sq;
        } else if ch == '"' && !in_sq {
            in_dq = !in_dq;
        } else if !in_sq && !in_dq {
            if ch == '{' {
                open += 1;
            } else if ch == '}' {
                close += 1;
            }
        }
    }
    (open, close)
}

fn is_control_kw(name: &str) -> bool {
    matches!(
        name,
        "if" | "for"
            | "while"
            | "switch"
            | "match"
            | "return"
            | "sizeof"
            | "catch"
            | "lock"
            | "Lock"
            | "rlock"
            | "RLock"
            | "write"
            | "read"
            | "unlock"
            | "Unlock"
            | "drop"
            | "pthread_mutex_lock"
            | "pthread_mutex_unlock"
    )
}

fn collect_functions(node: Node, src: &[u8], lang: Language, out: &mut Vec<FnSpan>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    if lang == Language::Rust
        && matches!(k, "mod_item" | "function_item")
        && is_rust_test_subtree(node, src)
    {
        return;
    }

    let is_fn = matches!(
        k,
        "function_item"
            | "function_definition"
            | "function_declaration"
            | "method_declaration"
            | "method_definition"
            | "constructor_declaration"
    );
    if is_fn {
        let name = node
            .child_by_field_name("name")
            .or_else(|| {
                let mut c = node.walk();
                node.children(&mut c).find(|ch| {
                    matches!(
                        ch.kind(),
                        "identifier" | "simple_identifier" | "field_identifier"
                    )
                })
            })
            .map(|n| node_text(n, src).trim().to_string())
            .unwrap_or_else(|| format!("fn_{}", node.start_position().row + 1));
        out.push(FnSpan {
            line_start: node.start_position().row + 1,
            line_end: node.end_position().row + 1,
            fn_name: name,
            code: strip_comments(node_text(node, src)),
        });
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_functions(ch, src, lang, out, depth + 1);
    }
}

fn find_symbol_index_for_span(symbols: &[SymbolInfo], start: usize, end: usize) -> Option<usize> {
    symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.line_start <= start && s.line_end >= end)
        .min_by_key(|(_, s)| s.line_end.saturating_sub(s.line_start))
        .map(|(idx, _)| idx)
}

/// Runs intra-procedural concurrency/deadlock (`SMG-ENG-DEADLOCK`) and resource-leak (`SMG-ENG-LEAK`)
/// AST checks, and populates lock-ordering metadata on `SymbolInfo` for global deadlock solving.
pub fn analyze_concurrency_and_leaks(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbols: &mut [SymbolInfo],
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    let full_src = std::str::from_utf8(src).unwrap_or("");
    let file_uses_async_mutex = full_src.contains("tokio::sync::")
        && (full_src.contains("Mutex") || full_src.contains("RwLock"))
        || full_src.contains("futures::lock::")
        || full_src.contains("async_std::sync::");
    let file_uses_sync_mutex = (full_src.contains("std::sync::")
        || full_src.contains("parking_lot::"))
        && (full_src.contains("Mutex") || full_src.contains("RwLock"));
    let file_uses_rwlock = full_src.contains("RwLock");

    let mut spans = Vec::new();
    collect_functions(root, src, lang, &mut spans, 0);

    for f in spans {
        let sym_idx = find_symbol_index_for_span(symbols, f.line_start, f.line_end);
        analyze_function_locks(
            rel_path,
            lang,
            &f,
            file_uses_async_mutex,
            file_uses_sync_mutex,
            file_uses_rwlock,
            sym_idx.map(|i| &mut symbols[i]),
            static_findings,
        );
        analyze_function_leaks(rel_path, lang, &f, static_findings);
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_function_locks(
    rel_path: &str,
    lang: Language,
    f: &FnSpan,
    file_uses_async_mutex: bool,
    file_uses_sync_mutex: bool,
    file_uses_rwlock: bool,
    mut sym_opt: Option<&mut SymbolInfo>,
    out: &mut Vec<LocalStaticFinding>,
) {
    let lines: Vec<&str> = f.code.lines().collect();
    let fn_has_any_unlock = f.code.contains("unlock(")
        || f.code.contains("Unlock(")
        || f.code.contains("pthread_mutex_unlock(");
    let mut depth = 0usize;
    let mut guards: Vec<ActiveLock> = Vec::new();
    let mut go_deferred_unlocks: HashSet<String> = HashSet::new();

    for (idx, raw_line) in lines.iter().enumerate() {
        let ln = f.line_start + idx;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let low = trimmed.to_ascii_lowercase();
        let (opens, closes) = count_braces_outside_strings(trimmed);

        // Pre-apply opens if block opens on this statement (e.g. `if cond { return; }` or `{ let g = ...;`)
        let stmt_depth = depth + opens.saturating_sub(closes);
        let depth_after = (depth + opens).saturating_sub(closes);

        // Skip explicit non-blocking lock attempts (`try_lock`) or atomic C++ multi-lock (`scoped_lock`/`std::lock`)
        let is_safe_multilock = (trimmed.contains("scoped_lock") || trimmed.contains("std::lock("))
            && trimmed.contains(',');

        // 1. Track explicit Go `defer mu.Unlock()`
        if lang == Language::Go && trimmed.starts_with("defer ") {
            for cap in method_unlock_re().captures_iter(trimmed) {
                go_deferred_unlocks.insert(norm_lock_name(&cap[1]));
            }
        }

        // 2. Check blocking / `.await` inside active sync lock scope
        let has_await_kw = trimmed.contains(".await")
            || trimmed.starts_with("await ")
            || trimmed.contains(" await ");
        let is_lock_acq_await = has_await_kw && trimmed.contains(".lock(");
        let is_blocking_sleep = trimmed.contains("thread::sleep(")
            || trimmed.contains("sleep_for(")
            || trimmed.contains("usleep(");

        // Rust `std::mem::forget(guard)` while holding lock -> permanent deadlock
        if lang == Language::Rust && trimmed.contains("mem::forget(") {
            for g in &guards {
                if let Some(gv) = &g.guard_var
                    && trimmed.contains(&format!("forget({})", gv))
                {
                    out.push(make_phase9_finding(
                        "SMG-ENG-DEADLOCK",
                        "CRITICAL",
                        format!(
                            "`mem::forget({})` leaks mutex guard `{}` permanently in `{}`",
                            gv, g.norm_name, f.fn_name
                        ),
                        rel_path,
                        ln,
                        &f.fn_name,
                        SinkKind::ConcurrencyHazard,
                        GuardKind::LockOrdering,
                        Confidence::Confirmed,
                        "Drop the mutex guard instead of calling `std::mem::forget` on it.",
                    ));
                }
            }
        }

        // Python blocking HTTP/sleep calls inside `async def` stall the event loop
        if lang == Language::Python
            && f.code.trim_start().starts_with("async def ")
            && (trimmed.contains("time.sleep(")
                || trimmed.contains("requests.get(")
                || trimmed.contains("requests.post(")
                || trimmed.contains("urllib.request.urlopen("))
        {
            out.push(make_phase9_finding(
                "SMG-ENG-DEADLOCK",
                "MEDIUM",
                format!(
                    "Blocking call `{}` inside Python `async def {}` stalls asyncio event loop",
                    trimmed.split('(').next().unwrap_or(trimmed),
                    f.fn_name
                ),
                rel_path,
                ln,
                &f.fn_name,
                SinkKind::ConcurrencyHazard,
                GuardKind::LockOrdering,
                Confidence::Heuristic,
                "Use non-blocking async equivalents (`await asyncio.sleep(...)` or `httpx.AsyncClient`).",
            ));
        }

        if (has_await_kw && !is_lock_acq_await) || is_blocking_sleep {
            let sync_mutex_hazard =
                !file_uses_async_mutex || file_uses_sync_mutex || is_blocking_sleep;
            if sync_mutex_hazard
                && !guards.is_empty()
                && !(has_await_kw && matches!(lang, Language::C | Language::Cpp))
            {
                let held_names: Vec<&str> = guards.iter().map(|g| g.norm_name.as_str()).collect();
                let sync_confirmed =
                    (!file_uses_async_mutex && file_uses_sync_mutex) || is_blocking_sleep;
                out.push(make_phase9_finding(
                    "SMG-ENG-DEADLOCK",
                    "HIGH",
                    format!(
                        "Mutex/lock `{}` held across `{}` inside `{}` (executor/thread deadlock risk)",
                        held_names.join(", "),
                        if has_await_kw { ".await" } else { "blocking sleep" },
                        f.fn_name
                    ),
                    rel_path,
                    ln,
                    &f.fn_name,
                    SinkKind::ConcurrencyHazard,
                    GuardKind::LockOrdering,
                    if sync_confirmed || !file_uses_async_mutex {
                        Confidence::Confirmed
                    } else {
                        Confidence::Heuristic
                    },
                    "Drop or scope the synchronous mutex guard `{ let _g = m.lock(); ... }` before `.await` or blocking calls, or switch to an async-aware mutex.",
                ));
            }
        }

        // 3. Handle unlocks / explicit drops BEFORE early-return check and new acquisitions on same line
        for cap in rust_drop_re().captures_iter(trimmed) {
            let var = cap[1].trim();
            guards.retain(|g| g.guard_var.as_deref() != Some(var));
        }
        for cap in pthread_unlock_re().captures_iter(trimmed) {
            let norm = norm_lock_name(&cap[1]);
            guards.retain(|g| g.norm_name != norm);
        }
        if !trimmed.starts_with("defer ") {
            for cap in method_unlock_re().captures_iter(trimmed) {
                let norm = norm_lock_name(&cap[1]);
                guards.retain(|g| g.norm_name != norm);
            }
        }

        // 4. Check manual lock left un-unlocked on early return path (`C` / `C++` / `Go`)
        let is_return_stmt = trimmed.starts_with("return ")
            || trimmed == "return;"
            || trimmed == "return"
            || trimmed.contains(" return ");
        if is_return_stmt && idx > 0 && idx + 1 < lines.len() {
            for g in &guards {
                if g.is_manual_unlock
                    && fn_has_any_unlock
                    && !(lang == Language::Go && go_deferred_unlocks.contains(&g.norm_name))
                {
                    out.push(make_phase9_finding(
                        "SMG-ENG-DEADLOCK",
                        "HIGH",
                        format!(
                            "Lock `{}` acquired at line {} is not released before early `return` in `{}`",
                            g.norm_name, g.line, f.fn_name
                        ),
                        rel_path,
                        ln,
                        &f.fn_name,
                        SinkKind::ConcurrencyHazard,
                        GuardKind::LockOrdering,
                        Confidence::Confirmed,
                        "Use RAII guards (`std::lock_guard`/`std::unique_lock`), `defer mu.Unlock()`, or release the mutex cleanly on every error-return path.",
                    ));
                }
            }
        }

        // 5. Record calls made while locks are held (for cross-function lock-order graph)
        if !guards.is_empty()
            && let Some(sym) = sym_opt.as_deref_mut()
        {
            for cap in call_ident_re().captures_iter(trimmed) {
                let callee = &cap[1];
                if !is_control_kw(callee) && callee != f.fn_name {
                    for g in &guards {
                        sym.locks_held_calls.push(LockHeldCall {
                            lock_name: g.norm_name.clone(),
                            callee: callee.to_string(),
                            line: ln,
                        });
                    }
                }
            }
        }

        // 6. Detect newly acquired locks on this line
        let mut newly_acquired: Vec<ActiveLock> = Vec::new();
        if !is_safe_multilock && !low.contains("try_lock") && !low.contains("std::try_to_lock") {
            for cap in cpp_raii_lock_re().captures_iter(trimmed) {
                let norm = norm_lock_name(&cap[2]);
                if !norm.is_empty() && !is_ignored_stdio_lock(&norm) {
                    newly_acquired.push(ActiveLock {
                        norm_name: norm,
                        guard_var: Some(cap[1].trim().to_string()),
                        line: ln,
                        scope_depth: stmt_depth,
                        is_manual_unlock: false,
                    });
                }
            }
            for cap in pthread_lock_re().captures_iter(trimmed) {
                let norm = norm_lock_name(&cap[1]);
                if !norm.is_empty() && !is_ignored_stdio_lock(&norm) {
                    newly_acquired.push(ActiveLock {
                        norm_name: norm,
                        guard_var: None,
                        line: ln,
                        scope_depth: stmt_depth,
                        is_manual_unlock: true,
                    });
                }
            }
            for cap in method_lock_re().captures_iter(trimmed) {
                let guard_var = cap.get(1).map(|m| m.as_str().to_string());
                // Skip Rust `let _ = mutex.lock()` (temporary guard dropped immediately at `;`)
                if lang == Language::Rust && guard_var.as_deref() == Some("_") {
                    let norm = norm_lock_name(&cap[2]);
                    if !norm.is_empty()
                        && !is_ignored_stdio_lock(&norm)
                        && let Some(sym) = sym_opt.as_deref_mut()
                    {
                        sym.locks_acquired.push((norm, ln));
                    }
                    continue;
                }
                // Avoid matching unlock/deadlock/block calls or non-lock stream `.read()`/`.write()` accidentally
                let raw_recv = &cap[2];
                let method_name = &cap[3];
                if raw_recv.ends_with(".unlock")
                    || !is_plausible_lock_method(method_name, raw_recv, file_uses_rwlock)
                {
                    continue;
                }
                let norm = norm_lock_name(raw_recv);
                if !norm.is_empty() && !is_ignored_stdio_lock(&norm) {
                    let manual = matches!(lang, Language::C | Language::Cpp | Language::Go)
                        && guard_var.is_none();
                    newly_acquired.push(ActiveLock {
                        norm_name: norm,
                        guard_var,
                        line: ln,
                        scope_depth: stmt_depth,
                        is_manual_unlock: manual,
                    });
                }
            }
        }

        for acq in newly_acquired {
            if let Some(sym) = sym_opt.as_deref_mut()
                && !sym.locks_acquired.iter().any(|(n, _)| n == &acq.norm_name)
            {
                sym.locks_acquired.push((acq.norm_name.clone(), ln));
            }
            // Same-lock re-entry while already held -> self-deadlock
            if guards.iter().any(|g| g.norm_name == acq.norm_name) {
                out.push(make_phase9_finding(
                    "SMG-ENG-DEADLOCK",
                    "HIGH",
                    format!(
                        "Non-reentrant lock `{}` acquired twice in `{}` (self-deadlock)",
                        acq.norm_name, f.fn_name
                    ),
                    rel_path,
                    ln,
                    &f.fn_name,
                    SinkKind::ConcurrencyHazard,
                    GuardKind::LockOrdering,
                    Confidence::Confirmed,
                    "Release the existing lock guard before reacquiring the same mutex or refactor inner helper to take a guard reference.",
                ));
            } else {
                // Record nested ordered pairs (prev -> new) for global A->B vs B->A cycle solver
                if let Some(sym) = sym_opt.as_deref_mut() {
                    for held in &guards {
                        if held.norm_name != acq.norm_name {
                            sym.lock_pairs.push(LockOrderEdge {
                                first: held.norm_name.clone(),
                                second: acq.norm_name.clone(),
                                line: ln,
                            });
                        }
                    }
                }
                guards.push(acq);
            }
        }

        // 7. Pop RAII/block-scoped guards whose brace scope exited on this line (or single-line `{ ... }` blocks)
        let single_line_block = opens > 0 && opens == closes && stmt_depth == depth_after;
        depth = depth_after;
        guards.retain(|g| {
            if g.is_manual_unlock {
                !(is_return_stmt && g.scope_depth > depth)
            } else if single_line_block {
                g.scope_depth < depth
            } else {
                g.scope_depth <= depth
            }
        });
    }
}

fn is_generic_short_lock_name(name: &str) -> bool {
    matches!(
        name,
        "m" | "mu"
            | "mtx"
            | "lock"
            | "mutex"
            | "rw"
            | "guard"
            | "l"
            | "s"
            | "state"
            | "data"
            | "cache"
            | "inner"
            | "store"
            | "pool"
    )
}

fn scopes_compatible(
    a_edge: &EdgeWitness,
    b_edge: &EdgeWitness,
    lock_a: &str,
    lock_b: &str,
) -> bool {
    if a_edge.file == b_edge.file {
        return true;
    }
    let ext_a = std::path::Path::new(&a_edge.file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let ext_b = std::path::Path::new(&b_edge.file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let same_lang_family = ext_a == ext_b
        || (matches!(ext_a, "c" | "h" | "cc" | "cpp" | "cxx" | "hpp")
            && matches!(ext_b, "c" | "h" | "cc" | "cpp" | "cxx" | "hpp"));
    same_lang_family
        && lock_a.len() >= 4
        && lock_b.len() >= 4
        && !is_generic_short_lock_name(lock_a)
        && !is_generic_short_lock_name(lock_b)
}

/// Global Cross-Function Lock-Order Inversion Solver (`A -> B` and `B -> A` deadlock cycles).
pub fn solve_cross_function_deadlocks(
    graph: &DiGraph<SymbolInfo, ()>,
    arena: &crate::arena::SymbolArena,
    resolved_callee_map: &HashMap<(usize, crate::arena::SymbolId), Vec<NodeIndex>>,
) -> Vec<LatticeFinding> {
    let n = graph.node_count();
    if n == 0 {
        return Vec::new();
    }

    // 1. Precompute direct & shallow-transitive locks acquired by every symbol (depth <= 3)
    let mut reachable_locks: Vec<Vec<(String, TraceHop)>> = vec![Vec::new(); n];
    for u in graph.node_indices() {
        let mut q: VecDeque<(NodeIndex, usize)> = VecDeque::new();
        let mut visited: HashSet<usize> = HashSet::new();
        visited.insert(u.index());
        q.push_back((u, 0));

        let mut collected: Vec<(String, TraceHop)> = Vec::new();
        while let Some((cur, depth)) = q.pop_front() {
            let cur_sym = &graph[cur];
            for (lock_name, ln) in &cur_sym.locks_acquired {
                if !collected.iter().any(|(name, _)| name == lock_name) {
                    collected.push((
                        lock_name.clone(),
                        TraceHop {
                            file: cur_sym.rel_path.clone(),
                            symbol: cur_sym.name.clone(),
                            line: *ln,
                        },
                    ));
                }
            }
            if depth >= 3 {
                continue;
            }
            for callee in &cur_sym.calls {
                if let Some(cid) = arena.get(callee)
                    && let Some(nexts) = resolved_callee_map.get(&(cur.index(), cid))
                {
                    for &nx in nexts {
                        if visited.insert(nx.index()) && visited.len() <= 128 {
                            q.push_back((nx, depth + 1));
                        }
                    }
                }
            }
        }
        reachable_locks[u.index()] = collected;
    }

    // 2. Collect all lock-order edges `lock_a -> lock_b` with exact witness trace hops
    let mut order_edges: HashMap<(String, String), EdgeWitness> = HashMap::new();
    for u in graph.node_indices() {
        let sym = &graph[u];
        for lp in &sym.lock_pairs {
            order_edges
                .entry((lp.first.clone(), lp.second.clone()))
                .or_insert_with(|| EdgeWitness {
                    file: sym.rel_path.clone(),
                    hops: vec![TraceHop {
                        file: sym.rel_path.clone(),
                        symbol: sym.name.clone(),
                        line: lp.line,
                    }],
                });
        }
        for lhc in &sym.locks_held_calls {
            if let Some(cid) = arena.get(&lhc.callee)
                && let Some(callees) = resolved_callee_map.get(&(u.index(), cid))
            {
                for &v in callees {
                    for (lock_b, hop_b) in &reachable_locks[v.index()] {
                        if &lhc.lock_name != lock_b {
                            order_edges
                                .entry((lhc.lock_name.clone(), lock_b.clone()))
                                .or_insert_with(|| EdgeWitness {
                                    file: sym.rel_path.clone(),
                                    hops: vec![
                                        TraceHop {
                                            file: sym.rel_path.clone(),
                                            symbol: sym.name.clone(),
                                            line: lhc.line,
                                        },
                                        hop_b.clone(),
                                    ],
                                });
                        }
                    }
                }
            }
        }
    }

    // 3. Detect `A -> B -> A` (2-cycle) and `A -> B -> C -> A` (3-cycle) lock-order inversions deterministically
    let mut findings = Vec::new();
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
    let mut seen_triples: HashSet<(String, String, String)> = HashSet::new();
    let mut outgoing: HashMap<&str, Vec<(&str, &EdgeWitness)>> = HashMap::new();
    for ((from, to), witness) in &order_edges {
        outgoing
            .entry(from.as_str())
            .or_default()
            .push((to.as_str(), witness));
    }

    for ((a, b), raw_ab) in &order_edges {
        if let Some(raw_ba) = order_edges.get(&(b.clone(), a.clone())) {
            let (lock_a, lock_b, edge_ab, edge_ba) = if a <= b {
                (a, b, raw_ab, raw_ba)
            } else {
                (b, a, raw_ba, raw_ab)
            };
            if !seen_pairs.insert((lock_a.clone(), lock_b.clone())) {
                continue;
            }
            if !scopes_compatible(edge_ab, edge_ba, lock_a, lock_b) {
                continue;
            }
            let first_hop = edge_ab.hops.first().cloned().unwrap_or(TraceHop {
                file: edge_ab.file.clone(),
                symbol: "unknown".into(),
                line: 1,
            });
            let mut witness = edge_ab.hops.clone();
            for h in &edge_ba.hops {
                if !witness
                    .iter()
                    .any(|w| w.file == h.file && w.symbol == h.symbol && w.line == h.line)
                {
                    witness.push(h.clone());
                }
            }
            let conflict_site = edge_ba
                .hops
                .first()
                .map(|h| format!("{}:{} ({}:{})", h.symbol, h.line, h.file, h.line))
                .unwrap_or_default();
            findings.push(LatticeFinding {
                id: String::new(),
                rule_id: "SMG-ENG-DEADLOCK".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Lock-order inversion deadlock: `{}` -> `{}` vs `{}` -> `{}` (conflict in {})",
                    lock_a, lock_b, lock_b, lock_a, conflict_site
                ),
                file: first_hop.file.clone(),
                line: first_hop.line,
                status: "SUSPECT_UNGUARDED".into(),
                confidence: Confidence::Confirmed,
                entry_route: format!("LOCK {}<->{}", lock_a, lock_b),
                sink_kind: SinkKind::ConcurrencyHazard,
                missing_guard: GuardKind::LockOrdering,
                witness_path: witness,
                remediation: "Enforce a single canonical lock acquisition hierarchy (`std::scoped_lock(a, b)`, consistent global ordering) across all call paths.".into(),
                proof_reasons: vec!["LockOrderInversionCycle".into(), "U32SymbolArena".into()],
            });
        }
        if let Some(next_edges) = outgoing.get(b.as_str()) {
            for &(c_str, raw_bc) in next_edges {
                if c_str == a.as_str() || c_str == b.as_str() {
                    continue;
                }
                let c = c_str.to_string();
                if let Some(raw_ca) = order_edges.get(&(c.clone(), a.clone())) {
                    if !scopes_compatible(raw_ab, raw_bc, a, b)
                        || !scopes_compatible(raw_bc, raw_ca, b, &c)
                    {
                        continue;
                    }
                    let mut triple = [a.clone(), b.clone(), c.clone()];
                    triple.sort();
                    if !seen_triples.insert((
                        triple[0].clone(),
                        triple[1].clone(),
                        triple[2].clone(),
                    )) {
                        continue;
                    }
                    let first_hop = raw_ab.hops.first().cloned().unwrap_or(TraceHop {
                        file: raw_ab.file.clone(),
                        symbol: "unknown".into(),
                        line: 1,
                    });
                    let mut witness = raw_ab.hops.clone();
                    for h in raw_bc.hops.iter().chain(raw_ca.hops.iter()) {
                        if !witness
                            .iter()
                            .any(|w| w.file == h.file && w.symbol == h.symbol && w.line == h.line)
                        {
                            witness.push(h.clone());
                        }
                    }
                    findings.push(LatticeFinding {
                        id: String::new(),
                        rule_id: "SMG-ENG-DEADLOCK".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "3-way lock-order cycle deadlock: `{}` -> `{}` -> `{}` -> `{}`",
                            a, b, c, a
                        ),
                        file: first_hop.file.clone(),
                        line: first_hop.line,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Confirmed,
                        entry_route: format!("LOCK {}->{}->{}", a, b, c),
                        sink_kind: SinkKind::ConcurrencyHazard,
                        missing_guard: GuardKind::LockOrdering,
                        witness_path: witness,
                        remediation: "Enforce a single canonical lock acquisition hierarchy (`std::scoped_lock`, consistent global ordering) across all call paths.".into(),
                        proof_reasons: vec!["LockOrder3Cycle".into(), "U32SymbolArena".into()],
                    });
                }
            }
        }
    }
    findings.sort_by(|x, y| {
        x.entry_route
            .cmp(&y.entry_route)
            .then_with(|| x.file.cmp(&y.file))
            .then_with(|| x.line.cmp(&y.line))
    });
    findings
}

fn is_handle_null_err_guard(line: &str, var: &str) -> bool {
    let low = line.to_ascii_lowercase();
    let vlow = var.to_ascii_lowercase();
    (low.contains(&format!("!{}", vlow))
        || low.contains(&format!("{} == null", vlow))
        || low.contains(&format!("{} == nullptr", vlow))
        || low.contains(&format!("{} < 0", vlow))
        || low.contains(&format!("{} <= -1", vlow))
        || low.contains(&format!("{} == -1", vlow))
        || low.contains(&format!("{} == none", vlow))
        || low.contains("err != nil")
        || low.contains("err != null"))
        && (low.contains("return")
            || low.contains("throw")
            || low.contains("raise")
            || low.contains("goto"))
}

fn extract_raw_handle_var(lang: Language, trimmed: &str) -> Option<&str> {
    if matches!(lang, Language::C | Language::Cpp) {
        if trimmed.contains("unique_ptr")
            || trimmed.contains("shared_ptr")
            || trimmed.contains("make_unique")
            || trimmed.contains("make_shared")
        {
            return None;
        }
        return c_handle_assign_re()
            .captures(trimmed)
            .and_then(|c| c.get(1).map(|m| m.as_str()));
    }
    if lang == Language::Go {
        return go_handle_assign_re()
            .captures(trimmed)
            .and_then(|c| c.get(1).map(|m| m.as_str()));
    }
    if lang == Language::Python {
        if trimmed.starts_with("with ") {
            return None;
        }
        return py_handle_assign_re()
            .captures(trimmed)
            .and_then(|c| c.get(1).map(|m| m.as_str()));
    }
    if matches!(lang, Language::Java | Language::Kotlin) {
        if trimmed.contains("try (") || trimmed.contains("try(") || trimmed.contains(".use {") {
            return None;
        }
        return jvm_handle_assign_re()
            .captures(trimmed)
            .and_then(|c| c.get(1).map(|m| m.as_str()));
    }
    if matches!(lang, Language::TypeScript | Language::JavaScript) {
        return js_handle_assign_re()
            .captures(trimmed)
            .and_then(|c| c.get(1).map(|m| m.as_str()));
    }
    None
}

fn analyze_function_leaks(
    rel_path: &str,
    lang: Language,
    f: &FnSpan,
    out: &mut Vec<LocalStaticFinding>,
) {
    // Rust relies on `Drop` RAII handles cleanly; skip Rust here to avoid false positives.
    if lang == Language::Rust {
        return;
    }

    let lines: Vec<&str> = f.code.lines().collect();
    for (idx, raw_line) in lines.iter().enumerate() {
        let trimmed = raw_line.trim();
        let Some(var) = extract_raw_handle_var(lang, trimmed) else {
            continue;
        };
        if var == "_" || var.len() > 40 {
            continue;
        }
        let acq_line = f.line_start + idx;

        // Check tail of function after acquisition
        let rest_lines = &lines[idx + 1..];
        let rest_joined = rest_lines.join("\n");
        let rest_low = rest_joined.to_ascii_lowercase();
        let var_low = var.to_ascii_lowercase();

        // Ownership transfer check: returning handle or storing it in struct/field -> SAFE
        if rest_lines.iter().any(|l| {
            let lt = l.trim();
            (lt.starts_with("return ")
                && lt
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|tok| tok == var))
                || lt.contains(&format!("->{} =", var))
                || lt.contains(&format!("= {};", var))
                || lt.contains(&format!("this.{} =", var))
                || lt.contains(&format!("self.{} =", var))
        }) {
            continue;
        }

        // Language-specific RAII / guaranteed cleanup guards -> SAFE
        if lang == Language::Go
            && (rest_low.contains(&format!("defer {}.close(", var_low))
                || rest_low.contains(&format!("defer {}.body.close(", var_low)))
        {
            continue;
        }
        if matches!(lang, Language::C | Language::Cpp)
            && (rest_low.contains("unique_ptr<") || rest_low.contains("shared_ptr<"))
            && rest_low.contains(&format!("({}", var_low))
        {
            continue;
        }
        if matches!(
            lang,
            Language::Python
                | Language::Java
                | Language::Kotlin
                | Language::TypeScript
                | Language::JavaScript
        ) && (rest_low.contains("finally:") || rest_low.contains("finally {"))
            && (rest_low.contains(&format!("{}.close(", var_low))
                || rest_low.contains(&format!("{}.body.close(", var_low))
                || rest_low.contains("release(")
                || rest_low.contains("closesync("))
        {
            continue;
        }
        if lang == Language::Kotlin && rest_low.contains(&format!("{}.use ", var_low)) {
            continue;
        }

        let close_idx = rest_lines.iter().position(|l| {
            let ll = l.to_ascii_lowercase();
            (ll.contains(&format!("fclose({})", var_low))
                || ll.contains(&format!("close({})", var_low))
                || ll.contains(&format!("closesocket({})", var_low))
                || ll.contains(&format!("sqlite3_close({})", var_low))
                || ll.contains(&format!("pqfinish({})", var_low))
                || ll.contains(&format!("free({})", var_low))
                || ll.contains(&format!("{}.close(", var_low))
                || ll.contains(&format!("{}.body.close(", var_low))
                || ll.contains(&format!("{}.release(", var_low))
                || ll.contains(&format!("fs.closesync({})", var_low)))
                && !ll.trim_start().starts_with("if ")
        });

        // If closed at tail/happy path, check whether any early return/throw runs BEFORE close_idx!
        if let Some(cidx) = close_idx {
            let mut in_open_err_check = false;
            for (r_off, rl) in rest_lines[..cidx].iter().enumerate() {
                let rt = rl.trim();
                if r_off <= 3 && is_handle_null_err_guard(rt, var) {
                    continue;
                }
                if r_off <= 3
                    && (rt.contains(&format!("!{}", var))
                        || rt.contains(&format!("{} == NULL", var))
                        || rt.contains(&format!("{} == nullptr", var))
                        || rt.contains(&format!("{} < 0", var))
                        || rt.contains("err != nil"))
                {
                    in_open_err_check = true;
                    continue;
                }
                if in_open_err_check {
                    if rt == "}" || rt.starts_with("} else") {
                        in_open_err_check = false;
                    }
                    continue;
                }
                let r_low = rt.to_ascii_lowercase();
                let returns_early = r_low.starts_with("return ")
                    || r_low == "return;"
                    || r_low == "return"
                    || r_low.starts_with("throw ")
                    || r_low.starts_with("raise ")
                    || (r_low.contains(") return ") && !is_handle_null_err_guard(rt, var));
                let prev_non_empty = rest_lines[..r_off]
                    .iter()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.to_ascii_lowercase())
                    .unwrap_or_default();
                let has_close_in_str = |s: &str| {
                    s.contains(&format!("close({})", var_low))
                        || s.contains(&format!("fclose({})", var_low))
                        || s.contains(&format!("free({})", var_low))
                        || s.contains(&format!("{}.close(", var_low))
                };
                let closed_right_before =
                    has_close_in_str(&r_low) || has_close_in_str(&prev_non_empty);
                if returns_early && !closed_right_before {
                    out.push(make_phase9_finding(
                        "SMG-ENG-LEAK",
                        "HIGH",
                        format!(
                            "Resource/handle `{}` (line {}) leaked on early return/error path inside `{}`",
                            var, acq_line, f.fn_name
                        ),
                        rel_path,
                        acq_line + 1 + r_off,
                        &f.fn_name,
                        SinkKind::ResourceLeak,
                        GuardKind::ResourceCleanup,
                        Confidence::Confirmed,
                        "Ensure handle cleanup runs on all exit paths using RAII (`std::unique_ptr`), `defer handle.Close()`, `try/finally`, or `goto cleanup;`.",
                    ));
                    break;
                }
            }
        } else {
            // Never closed anywhere in non-factory function (heuristic: handle may transfer via struct/out-param)
            out.push(make_phase9_finding(
                "SMG-ENG-LEAK",
                "MEDIUM",
                format!(
                    "Resource/handle `{}` acquired in `{}` is never closed or released",
                    var, f.fn_name
                ),
                rel_path,
                acq_line,
                &f.fn_name,
                SinkKind::ResourceLeak,
                GuardKind::ResourceCleanup,
                Confidence::Heuristic,
                "Release every acquired file/socket/DB handle with RAII, `defer`, `try-with-resources`/`using`, or `close()`/`free()`.",
            ));
        }
    }
}
