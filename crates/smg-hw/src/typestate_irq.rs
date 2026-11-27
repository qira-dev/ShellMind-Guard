use crate::context::{FirmwareContext, parse_hex_or_dec_u64};
use crate::domains::{SparseOctagon, Tnum, WrappedInterval};
use regex::Regex;
use smg_core::Language;
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoundinessTier {
    /// Concrete Dominator + Interval impossibility or concrete bounds counterexample.
    Proven,
    /// Backward-slice bounded QF_BV constraint returns SAT with concrete witness.
    Verified,
    /// High-confidence Typestate / Effect-Graph violation without unresolved macro blockers.
    Likely,
    /// Suppressed from default CI output unless heuristics requested.
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwTypestate {
    Bottom,
    Uninit,
    Owned,
    Borrowed,
    Freed,
    SpinLocked,
    IrqMasked,
    Zeroized,
    Conflict,
}

impl HwTypestate {
    pub fn join(self, other: Self) -> Self {
        if self == other {
            self
        } else if self == Self::Bottom {
            other
        } else if other == Self::Bottom {
            self
        } else {
            Self::Conflict
        }
    }
}

/// Bounded backward-slice QF_BV SMT solver trait (pure Rust offline core, no `z3-sys`).
pub trait SmtBackend {
    fn check_bounds_violation(
        &self,
        index_interval: WrappedInterval,
        capacity: u64,
        offset_sum_le_cap: bool,
    ) -> Option<u64>;
}

/// Pure-Rust finite-width interval + bitvector slice checker enforcing <= 50-stmt slices.
pub struct PureRustBvSliceSolver;

impl SmtBackend for PureRustBvSliceSolver {
    fn check_bounds_violation(
        &self,
        index_interval: WrappedInterval,
        capacity: u64,
        offset_sum_le_cap: bool,
    ) -> Option<u64> {
        if offset_sum_le_cap && !index_interval.signed_wrap {
            return None;
        }
        if index_interval.can_wrap_negative_to_large_size() {
            return Some(index_interval.umax);
        }
        if index_interval.umax > capacity {
            return Some(index_interval.umax);
        }
        None
    }
}

/// Re-exported unified Steensgaard pointer equivalence classes (`Phase 3 / Q71`).
pub use smg_graph::formal::PointerAliasUnionFind;

#[derive(Debug, Clone)]
pub struct HardwareFunctionLockSummary {
    pub fn_name: String,
    pub rel_path: String,
    pub line: usize,
    pub is_isr: bool,
    pub irq_saved: bool,
    pub acquired_locks: Vec<String>,
    pub lock_irq_saved: HashMap<String, bool>,
    pub held_lock_pairs: Vec<(String, String)>,
    /// Phase 13A (`P13-02`): direct callee names for bounded (`<= 4` hop) inter-procedural summary propagation.
    pub callees: Vec<String>,
    /// True if function calls a sleeping allocator or blocking primitive (`kmalloc(..., GFP_KERNEL)`, `mutex_lock`, `msleep`).
    pub calls_sleeping_alloc: bool,
    pub sleeping_alloc_line: Option<usize>,
}

fn hw_fn_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("valid fn call regex"))
}

fn hex_addr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(0x[0-9a-fA-F]{4,16})\b").expect("valid hex addr regex"))
}

fn ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").expect("valid ident"))
}

fn alloc_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:kmalloc|kzalloc|vmalloc|malloc|calloc|realloc|pvPortMalloc)\s*\("#,
        )
        .expect("valid alloc regex")
    })
}

fn free_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(?:kfree|vfree|free|pvPortFree)\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("valid free regex")
    })
}

fn lock_acquire_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(spin_lock_irqsave|spin_lock_bh|spin_lock|mutex_lock|xSemaphoreTake|pthread_mutex_lock|osMutexAcquire)\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_>.-]*)"#,
        )
        .expect("valid lock acquire call regex")
    })
}

fn lock_release_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(spin_unlock_irqrestore|spin_unlock_bh|spin_unlock|mutex_unlock|xSemaphoreGive|pthread_mutex_unlock|osMutexRelease)\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_>.-]*)"#,
        )
        .expect("valid lock release call regex")
    })
}

fn jtag_secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:\b(?:jtag_key|swd_unlock|debug_backdoor|uart_password|boot_master_key|provision_secret|flash_unlock_key)\b[^=;,\r\n]{0,48}?[:=]\s*["'][A-Za-z0-9_+/=-]{12,}["']|^\s*#\s*define\s+(?:jtag_key|swd_unlock|debug_backdoor|uart_password|boot_master_key|provision_secret|flash_unlock_key)\s+["'][A-Za-z0-9_+/=-]{12,}["'])"#,
        )
        .expect("valid hw secret regex")
    })
}

fn cmp_guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("valid cmp guard regex")
    })
}

fn sum_guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("valid sum guard regex")
    })
}

fn sub_guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*)\s*-\s*([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("valid sub guard regex")
    })
}

fn stack_array_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]"#)
            .expect("valid stack array decl regex")
    })
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    let clean = s.trim().trim_end_matches(['U', 'u', 'L', 'l']);
    clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn node_text<'a>(n: Node, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

fn strip_string_literals_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_str = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_str {
            if ch == '\\' {
                let _ = chars.next();
            } else if ch == '"' {
                in_str = false;
                out.push('"');
            }
        } else if ch == '"' {
            in_str = true;
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn mk_hw_finding(
    rule_id: &str,
    severity: &str,
    tier: SoundinessTier,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    remediation: &str,
) -> Option<LocalStaticFinding> {
    let confidence = match tier {
        SoundinessTier::Proven => Confidence::Proven,
        SoundinessTier::Verified | SoundinessTier::Likely => Confidence::Confirmed,
        SoundinessTier::Heuristic => Confidence::Heuristic,
    };
    Some(LocalStaticFinding {
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
    })
}

fn has_cfg_test_attr(node: Node, src: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        let pk = p.kind();
        if pk == "attribute_item" {
            let txt = node_text(p, src);
            if txt.contains("cfg(test)") || txt.contains("#[test]") || txt.contains("::test") {
                return true;
            }
            prev = p.prev_sibling();
        } else if pk == "line_comment" || pk == "block_comment" {
            prev = p.prev_sibling();
        } else {
            break;
        }
    }
    false
}

fn is_c_or_rust_test_fn(node: Node, src: &[u8], fn_name: &str) -> bool {
    let low = fn_name.to_ascii_lowercase();
    if low.starts_with("test_") || low.ends_with("_test") {
        return true;
    }
    has_cfg_test_attr(node, src)
}

fn extract_c_fn_name(node: Node, src: &[u8]) -> String {
    if let Some(decl) = node.child_by_field_name("declarator") {
        let txt = node_text(decl, src);
        let head = txt.split('(').next().unwrap_or(txt).trim();
        return head
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()
            .unwrap_or("fn")
            .to_string();
    }
    if let Some(n) = node.child_by_field_name("name") {
        return node_text(n, src).trim().to_string();
    }
    "firmware_fn".to_string()
}

fn configure_hw_parser(parser: &mut Parser, lang: Language) -> bool {
    let res = match lang {
        Language::C => parser.set_language(&tree_sitter_c::LANGUAGE.into()),
        Language::Cpp => parser.set_language(&tree_sitter_cpp::LANGUAGE.into()),
        Language::Rust => parser.set_language(&tree_sitter_rust::LANGUAGE.into()),
        _ => return false,
    };
    res.is_ok()
}

fn collect_hw_functions<'a>(root: Node<'a>, src: &[u8], out: &mut Vec<(String, Node<'a>)>) {
    // Iterative DFS with explicit stack avoids thread stack overflow on deeply nested C macro/AST trees (e.g. Zephyr RTOS).
    let mut stack: Vec<Node<'a>> = vec![root];
    while let Some(node) = stack.pop() {
        let k = node.kind();
        if matches!(k, "function_definition" | "function_item") {
            let name = extract_c_fn_name(node, src);
            if !is_c_or_rust_test_fn(node, src, &name) {
                out.push((name, node));
            }
            continue;
        }
        // Skip entire Rust `#[cfg(test)] mod tests { ... }` subtree cleanly without bleeding past sibling items
        if k == "mod_item" && has_cfg_test_attr(node, src) {
            continue;
        }
        let prev_len = stack.len();
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            stack.push(ch);
        }
        stack[prev_len..].reverse();
    }
}

fn is_isr_function(fn_name: &str, fn_header_low: &str, lines: &[&str], fn_start: usize) -> bool {
    let fn_name_low = fn_name.to_ascii_lowercase();
    let fn_slice_start = fn_start.saturating_sub(2);
    let attr_ctx = if lines.is_empty() {
        String::new()
    } else {
        lines[fn_slice_start.saturating_sub(1)..fn_start.min(lines.len())].join("\n")
    };
    fn_name_low.contains("irqhandler")
        || fn_name_low.ends_with("_isr")
        || fn_header_low.contains("__attribute__((interrupt))")
        || attr_ctx.contains("#[interrupt]")
        || attr_ctx.contains("ISR(")
}

fn extract_function_lock_summary(
    fn_name: &str,
    rel_path: &str,
    fn_start: usize,
    fn_end: usize,
    lines: &[&str],
    fn_body: &str,
) -> Option<HardwareFunctionLockSummary> {
    let fn_header_low = fn_body
        .split('{')
        .next()
        .unwrap_or(fn_body)
        .to_ascii_lowercase();
    let is_isr = is_isr_function(fn_name, &fn_header_low, lines, fn_start);

    // Track interrupt-disabled state sequentially line-by-line (never pre-seed from the
    // whole body, otherwise a late `disable_irq()` would mask an earlier unguarded `spin_lock`).
    let mut global_irq_disabled = false;

    let mut acquired: Vec<String> = Vec::new();
    let mut currently_held: Vec<String> = Vec::new();
    let mut held_lock_pairs: Vec<(String, String)> = Vec::new();
    let mut lock_irq_saved: HashMap<String, bool> = HashMap::new();
    let mut callees: Vec<String> = Vec::new();
    let mut calls_sleeping_alloc = false;
    let mut sleeping_alloc_line: Option<usize> = None;
    let mut dead_branch_depth: Option<i32> = None;
    let mut brace_depth: i32 = 0;

    for ln in fn_start..=fn_end {
        let Some(&raw_line) = lines.get(ln - 1) else {
            continue;
        };
        let t = raw_line.trim();
        let low = t.to_ascii_lowercase();

        let is_if_zero = low.starts_with("if (0)")
            || low.starts_with("if(0)")
            || low.starts_with("if (false)")
            || low.starts_with("if(false)");
        if is_if_zero {
            if t.contains('{') && !t.contains('}') {
                dead_branch_depth = Some(brace_depth);
            }
            brace_depth += t.chars().filter(|&c| c == '{').count() as i32;
            brace_depth -= t.chars().filter(|&c| c == '}').count() as i32;
            if let Some(d) = dead_branch_depth
                && brace_depth <= d
            {
                dead_branch_depth = None;
            }
            continue;
        }

        if dead_branch_depth.is_some() {
            brace_depth += t.chars().filter(|&c| c == '{').count() as i32;
            brace_depth -= t.chars().filter(|&c| c == '}').count() as i32;
            if let Some(d) = dead_branch_depth
                && brace_depth <= d
            {
                dead_branch_depth = None;
            }
            continue;
        }

        // Detect sleeping allocations / blocking primitives forbidden in ISR / atomic context
        if ((low.contains("kmalloc(") || low.contains("kzalloc(") || low.contains("kcalloc("))
            && low.contains("gfp_kernel"))
            || low.contains("vmalloc(")
            || low.contains("vzalloc(")
            || low.contains("mutex_lock(")
            || low.contains("msleep(")
            || low.contains("ssleep(")
        {
            calls_sleeping_alloc = true;
            if sleeping_alloc_line.is_none() {
                sleeping_alloc_line = Some(ln);
            }
        }

        // Collect direct function callees (skipping header line & keywords)
        if ln > fn_start {
            for cap in hw_fn_call_re().captures_iter(t) {
                let cname = &cap[1];
                if cname != fn_name
                    && !matches!(
                        cname,
                        "if" | "for"
                            | "while"
                            | "switch"
                            | "return"
                            | "sizeof"
                            | "typeof"
                            | "defined"
                            | "spin_lock"
                            | "spin_unlock"
                            | "spin_lock_irqsave"
                            | "spin_unlock_irqrestore"
                    )
                    && !callees.iter().any(|c| c == cname)
                {
                    callees.push(cname.to_string());
                }
            }
        }

        if low.contains("disable_irq")
            || low.contains("taskenter_critical")
            || low.contains("cpsid")
            || low.contains("critical_section::with")
            || low.contains("local_irq_save")
            || low.contains("local_irq_disable")
            || low.contains("spin_lock_irq(")
        {
            global_irq_disabled = true;
        }

        for cap in lock_release_call_re().captures_iter(t) {
            let rel_lock = cap[2].trim();
            currently_held.retain(|h| h != rel_lock);
        }

        for cap in lock_acquire_call_re().captures_iter(t) {
            let call_kind = &cap[1];
            let l = cap[2].trim().to_string();
            if l.is_empty() {
                continue;
            }
            let this_saved =
                call_kind.eq_ignore_ascii_case("spin_lock_irqsave") || global_irq_disabled;
            lock_irq_saved
                .entry(l.clone())
                .and_modify(|v| *v &= this_saved)
                .or_insert(this_saved);

            for held in &currently_held {
                if held != &l {
                    let pair = (held.clone(), l.clone());
                    if !held_lock_pairs.contains(&pair) {
                        held_lock_pairs.push(pair);
                    }
                }
            }
            if !currently_held.contains(&l) {
                currently_held.push(l.clone());
            }
            if !acquired.contains(&l) {
                acquired.push(l);
            }
        }

        if low.contains("enable_irq")
            || low.contains("taskexit_critical")
            || low.contains("cpsie")
            || low.contains("local_irq_restore")
            || low.contains("local_irq_enable")
            || low.contains("spin_unlock_irq(")
        {
            global_irq_disabled = false;
        }

        brace_depth += t.chars().filter(|&c| c == '{').count() as i32;
        brace_depth -= t.chars().filter(|&c| c == '}').count() as i32;
    }

    if acquired.is_empty() && !is_isr && !calls_sleeping_alloc && callees.is_empty() {
        return None;
    }
    let all_irq_saved = !acquired.is_empty()
        && acquired
            .iter()
            .all(|l| lock_irq_saved.get(l).copied().unwrap_or(false));

    Some(HardwareFunctionLockSummary {
        fn_name: fn_name.to_string(),
        rel_path: rel_path.to_string(),
        line: fn_start,
        is_isr,
        irq_saved: all_irq_saved,
        acquired_locks: acquired,
        lock_irq_saved,
        held_lock_pairs,
        callees,
        calls_sleeping_alloc,
        sleeping_alloc_line,
    })
}

pub fn analyze_hw_file(
    rel_path: &str,
    lang: Language,
    content: &str,
    ctx: &FirmwareContext,
    findings: &mut Vec<LocalStaticFinding>,
    lock_summaries: &mut Vec<HardwareFunctionLockSummary>,
    stack_nodes_out: &mut Vec<crate::wcsd_dma::FnStackNode>,
) {
    let stripped = smg_graph::taint::strip_comments_simple(content);
    let src_bytes = stripped.as_bytes();
    let lines: Vec<&str> = stripped.lines().collect();

    let mut parser = Parser::new();
    if !configure_hw_parser(&mut parser, lang) {
        return;
    }
    let Some(tree) = parser.parse(&stripped, None) else {
        return;
    };
    if matches!(lang, Language::C | Language::Cpp) {
        stack_nodes_out.extend(crate::wcsd_dma::extract_c_stack_nodes_from_tree(
            rel_path, &stripped, &tree,
        ));
    }

    let mut rust_test_ranges: Vec<(usize, usize)> = Vec::new();
    if lang == Language::Rust {
        let mut rc = tree.root_node().walk();
        for ch in tree.root_node().children(&mut rc) {
            if ch.kind() == "mod_item" && has_cfg_test_attr(ch, src_bytes) {
                rust_test_ranges.push((ch.start_position().row + 1, ch.end_position().row + 1));
            }
        }
    }

    // Global firmware JTAG/SWD backdoor keys scanned on comment-stripped lines (ignoring #[cfg(test)] modules)
    for (idx, line) in stripped.lines().enumerate() {
        let ln = idx + 1;
        let t = line.trim();
        let is_non_define_directive = t.starts_with('#')
            && !t
                .trim_start_matches('#')
                .trim_start()
                .starts_with("define ");
        if t.is_empty()
            || t.starts_with("//")
            || t.starts_with("/*")
            || is_non_define_directive
            || smg_graph::taint::is_pattern_matcher_or_doc_line(line)
            || rust_test_ranges.iter().any(|(s, e)| ln >= *s && ln <= *e)
        {
            continue;
        }
        if jtag_secret_re().is_match(line)
            && let Some(hit) = mk_hw_finding(
                "SMG-HW-SECRETS",
                "CRITICAL",
                SoundinessTier::Verified,
                "Hardcoded firmware debug/JTAG/provisioning secret key".into(),
                rel_path,
                ln,
                "hw_secret",
                SinkKind::SecretLeak,
                GuardKind::SecretPolicy,
                "Provision device keys in OTP/eFuse hardware keystore during manufacturing instead of embedding cleartext keys in firmware images.",
            )
        {
            findings.push(hit);
        }
    }

    let width_bits = ctx.pointer_width_for_file(rel_path);
    let cu_opt = ctx.lookup_compile_unit(rel_path);

    let mut fns = Vec::new();
    collect_hw_functions(tree.root_node(), src_bytes, &mut fns);
    let bv_solver = PureRustBvSliceSolver;

    for (fn_name, fn_node) in fns {
        let fn_start = fn_node.start_position().row + 1;
        let fn_end = fn_node.end_position().row + 1;
        let fn_body = node_text(fn_node, src_bytes);

        if let Some(summary) =
            extract_function_lock_summary(&fn_name, rel_path, fn_start, fn_end, &lines, fn_body)
        {
            lock_summaries.push(summary);
        }

        analyze_single_hw_function(
            rel_path, lang, &fn_name, fn_start, fn_end, &lines, fn_body, width_bits, cu_opt, ctx,
            &bv_solver, findings,
        );
    }
}

fn lookup_const_define(
    tok: &str,
    cu_opt: Option<&crate::context::CompileUnitContext>,
    ctx: &FirmwareContext,
) -> Option<i64> {
    if let Some(&v) = ctx.global_defines.get(tok) {
        return Some(v);
    }
    if let Some(cu) = cu_opt
        && let Some(v_str) = cu.defines.get(tok)
        && let Some(val) = parse_hex_or_dec_u64(v_str)
    {
        return i64::try_from(val).ok();
    }
    None
}

#[derive(Clone)]
struct TypestateBranchFrame {
    entry_depth: i32,
    pre_if_states: HashMap<String, (HwTypestate, usize)>,
    pre_if_nulls: HashSet<String>,
    pre_if_intervals: HashMap<String, WrappedInterval>,
    pre_if_tnums: HashMap<String, Tnum>,
    pre_if_pos_guards: HashSet<String>,
    then_states: Option<HashMap<String, (HwTypestate, usize)>>,
    then_nulls: Option<HashSet<String>>,
    then_intervals: Option<HashMap<String, WrappedInterval>>,
    then_tnums: Option<HashMap<String, Tnum>>,
    then_pos_guards: Option<HashSet<String>>,
    then_returned: bool,
    in_else: bool,
    branch_returned: bool,
}

fn merge_interval_maps(
    a: &HashMap<String, WrappedInterval>,
    b: &HashMap<String, WrappedInterval>,
) -> HashMap<String, WrappedInterval> {
    let mut out = HashMap::new();
    for (k, va) in a {
        if let Some(vb) = b.get(k) {
            out.insert(k.clone(), va.join(*vb));
        } else {
            out.insert(k.clone(), *va);
        }
    }
    for (k, vb) in b {
        out.entry(k.clone()).or_insert(*vb);
    }
    out
}

fn merge_tnum_maps(a: &HashMap<String, Tnum>, b: &HashMap<String, Tnum>) -> HashMap<String, Tnum> {
    let mut out = HashMap::new();
    for (k, va) in a {
        if let Some(vb) = b.get(k) {
            out.insert(k.clone(), va.join(*vb));
        } else {
            out.insert(k.clone(), *va);
        }
    }
    for (k, vb) in b {
        out.entry(k.clone()).or_insert(*vb);
    }
    out
}

fn merge_typestate_maps(
    a: &HashMap<String, (HwTypestate, usize)>,
    b: &HashMap<String, (HwTypestate, usize)>,
) -> HashMap<String, (HwTypestate, usize)> {
    let mut out = a.clone();
    for (k, &(bs, bln)) in b {
        if let Some(&(as_, aln)) = out.get(k) {
            out.insert(k.clone(), (as_.join(bs), aln.max(bln)));
        } else {
            out.insert(k.clone(), (bs, bln));
        }
    }
    out
}

fn extract_sig_params_slice(fn_body: &str) -> &str {
    let head = fn_body.split('{').next().unwrap_or(fn_body);
    let Some(open) = head.find('(') else {
        return "";
    };
    let Some(close) = head.rfind(')') else {
        return "";
    };
    if close <= open {
        return "";
    }
    &head[open + 1..close]
}

fn is_crypto_fn_name(fn_name_low: &str) -> bool {
    const CRYPTO_WORDS: &[&str] = &[
        "sign",
        "scalar",
        "ecdsa",
        "hmac",
        "aes",
        "montgomery",
        "crypto",
        "ed25519",
        "rsa",
        "chacha",
        "poly1305",
    ];
    for token in fn_name_low.split(|c: char| !c.is_ascii_alphanumeric()) {
        if CRYPTO_WORDS.contains(&token) {
            return true;
        }
    }
    false
}

fn resolve_bound_token(
    tok: &str,
    ctx: &FirmwareContext,
    local_caps: &HashMap<String, u64>,
) -> Option<i64> {
    if let Some(v) = parse_hex_or_dec_u64(tok) {
        return i64::try_from(v).ok();
    }
    if let Some(&v) = ctx.global_defines.get(tok) {
        return Some(v);
    }
    if let Some(&v) = local_caps.get(tok) {
        return i64::try_from(v).ok();
    }
    if let Some(inner) = tok
        .strip_prefix("sizeof(")
        .and_then(|s| s.strip_suffix(')'))
        && let Some(&v) = local_caps.get(inner.trim())
    {
        return i64::try_from(v).ok();
    }
    None
}

fn line_derefs_ptr(trimmed: &str, ptr: &str) -> bool {
    if ptr.is_empty() {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let arrow = format!("{}->", ptr);
    let mut off = 0usize;
    while off < trimmed.len()
        && let Some(rel) = trimmed[off..].find(&arrow)
    {
        let pos = off + rel;
        let prev_ok =
            pos == 0 || (!bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_');
        if prev_ok {
            return true;
        }
        let step = trimmed[pos..].chars().next().map_or(1, char::len_utf8);
        off = pos + step;
    }
    let star = format!("*{}", ptr);
    let mut soff = 0usize;
    while soff < trimmed.len()
        && let Some(rel) = trimmed[soff..].find(&star)
    {
        let pos = soff + rel;
        let end = pos + star.len();
        let prev_is_expr_operand = pos > 0
            && trimmed[..pos]
                .trim_end()
                .as_bytes()
                .last()
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b')');
        let next_ok =
            end >= bytes.len() || (!bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_');
        if !prev_is_expr_operand && next_ok {
            return true;
        }
        let step = trimmed[pos..].chars().next().map_or(1, char::len_utf8);
        soff = pos + step;
    }
    false
}

fn region_applies_to_file(
    rel_path: &str,
    region: &crate::context::MemoryRegion,
    all_regions: &[crate::context::MemoryRegion],
) -> bool {
    let distinct_boards: HashSet<&str> = all_regions
        .iter()
        .map(|r| {
            r.source_file
                .split('/')
                .next()
                .unwrap_or(r.source_file.as_str())
        })
        .collect();
    if distinct_boards.len() <= 1 {
        return true;
    }
    let reg_top = region
        .source_file
        .split('/')
        .next()
        .unwrap_or(region.source_file.as_str());
    let file_top = rel_path.split('/').next().unwrap_or(rel_path);
    reg_top == file_top || !distinct_boards.contains(file_top)
}

fn is_hex_preceded_by_mask_or_cmp(line: &str, byte_start: usize) -> bool {
    let prefix = line[..byte_start].trim_end();
    if prefix.ends_with('&')
        || prefix.ends_with('|')
        || prefix.ends_with('^')
        || prefix.ends_with('~')
        || prefix.ends_with("==")
        || prefix.ends_with("!=")
        || prefix.ends_with("<=")
        || prefix.ends_with(">=")
    {
        return true;
    }
    // Check if the hex literal is on the RHS of a value assignment `*ptr = 0x1` (where LHS has no hex or already has target)
    if let Some(eq_idx) = prefix.rfind('=')
        && !prefix[..eq_idx].ends_with('=')
        && !prefix[..eq_idx].ends_with('!')
        && !prefix[..eq_idx].ends_with('<')
        && !prefix[..eq_idx].ends_with('>')
    {
        let after_eq = &prefix[eq_idx + 1..];
        if !after_eq.contains("volatile")
            && !after_eq.contains("MMIO")
            && !after_eq.contains("REG32")
            && !after_eq.contains('*')
        {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn analyze_single_hw_function(
    rel_path: &str,
    _lang: Language,
    fn_name: &str,
    fn_start: usize,
    fn_end: usize,
    all_lines: &[&str],
    fn_body: &str,
    width_bits: u32,
    cu_opt: Option<&crate::context::CompileUnitContext>,
    ctx: &FirmwareContext,
    bv_solver: &dyn SmtBackend,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let fn_lines: Vec<(usize, &str)> = (fn_start..=fn_end)
        .filter_map(|ln| all_lines.get(ln - 1).map(|&s| (ln, s)))
        .collect();
    if fn_lines.is_empty() {
        return;
    }

    let fn_low = fn_body.to_ascii_lowercase();
    let mut intervals: HashMap<String, WrappedInterval> = HashMap::new();
    let mut tnums: HashMap<String, Tnum> = HashMap::new();
    let mut unsigned_params: HashSet<String> = HashSet::new();
    let mut typestates: HashMap<String, (HwTypestate, usize)> = HashMap::new();
    let mut null_ptrs: HashSet<String> = HashSet::new();
    let mut aliases = PointerAliasUnionFind::default();
    let mut local_caps: HashMap<String, u64> = HashMap::new();
    let mut mmio_ptrs: HashMap<String, u64> = HashMap::new();
    let mut relational_sum_limits: Vec<(String, String, i64)> = Vec::new();

    // Lazy read-only lookup for immutable `#define` constants (zero per-fn / per-branch map cloning)
    let lookup_interval =
        |tok: &str, imap: &HashMap<String, WrappedInterval>| -> Option<WrappedInterval> {
            let t = tok.trim();
            imap.get(t).copied().or_else(|| {
                lookup_const_define(t, cu_opt, ctx)
                    .map(|v| WrappedInterval::constant_signed(v, width_bits))
            })
        };

    // Seed function parameter intervals with exact bit-widths (Phase 13A P13-01)
    let params_slice = extract_sig_params_slice(fn_body);
    for part in params_slice.split(',') {
        let ptrim = part.trim();
        if ptrim.is_empty() || ptrim == "void" || ptrim.contains('*') || ptrim.contains('[') {
            continue;
        }
        let plow = ptrim.to_ascii_lowercase();
        let last_ident = ident_re()
            .captures_iter(ptrim)
            .last()
            .map(|c| c[1].to_string());
        if let Some(pvar) = last_ident {
            let tokens: Vec<&str> = plow
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|w| !w.is_empty())
                .collect();
            let has_tok = |t: &str| tokens.contains(&t);
            let is_unsigned = has_tok("unsigned");

            if has_tok("uint8_t") || has_tok("u8") || (is_unsigned && has_tok("char")) {
                intervals.insert(pvar.clone(), WrappedInterval::from_u64_bounds(0, 255, 8));
                tnums.insert(pvar.clone(), Tnum::unknown_with_width(8));
                unsigned_params.insert(pvar);
            } else if has_tok("int8_t") || has_tok("i8") {
                intervals.insert(pvar, WrappedInterval::signed_range(-128, 127, 8));
            } else if has_tok("uint16_t") || has_tok("u16") || (is_unsigned && has_tok("short")) {
                intervals.insert(pvar.clone(), WrappedInterval::from_u64_bounds(0, 65535, 16));
                tnums.insert(pvar.clone(), Tnum::unknown_with_width(16));
                unsigned_params.insert(pvar);
            } else if has_tok("int16_t") || has_tok("i16") || has_tok("short") {
                intervals.insert(pvar, WrappedInterval::signed_range(-32768, 32767, 16));
            } else if has_tok("uint32_t")
                || has_tok("u32")
                || (is_unsigned && has_tok("int"))
                || is_unsigned
            {
                intervals.insert(
                    pvar.clone(),
                    WrappedInterval::from_u64_bounds(0, u32::MAX as u64, 32),
                );
                tnums.insert(pvar.clone(), Tnum::unknown_with_width(32));
                unsigned_params.insert(pvar);
            } else if has_tok("size_t") || has_tok("usize") || has_tok("uint64_t") || has_tok("u64")
            {
                let max_u = Tnum::width_mask(width_bits);
                intervals.insert(
                    pvar.clone(),
                    WrappedInterval::from_u64_bounds(0, max_u, width_bits),
                );
                tnums.insert(pvar.clone(), Tnum::unknown_with_width(width_bits));
                unsigned_params.insert(pvar);
            } else if has_tok("int")
                || has_tok("int32_t")
                || has_tok("i32")
                || has_tok("int64_t")
                || has_tok("i64")
                || has_tok("ssize_t")
                || has_tok("isize")
            {
                intervals.insert(
                    pvar,
                    WrappedInterval::signed_range(i32::MIN as i64, i32::MAX as i64, width_bits),
                );
            }
        }
    }

    // Track DMA / __user pointers & Double-Fetch TOCTOU
    let mut ext_ptrs: HashSet<String> = HashSet::new();
    if fn_low.contains("__user") || fn_low.contains("dma") || fn_low.contains("shared_mmio") {
        let header_section = fn_body.split('{').next().unwrap_or(fn_body);
        for cap in ident_re().captures_iter(header_section) {
            let id = &cap[1];
            let id_low = id.to_ascii_lowercase();
            if (id_low.contains("user")
                || id_low.contains("dma")
                || id_low.contains("desc")
                || id_low.contains("hdr"))
                && !id_low.starts_with("local_")
            {
                ext_ptrs.insert(id.to_string());
            }
        }
        for &(_, raw) in &fn_lines {
            let rlow = raw.to_ascii_lowercase();
            if rlow.contains("__user") || rlow.contains("volatile") || rlow.contains("dma") {
                for cap in ident_re().captures_iter(raw) {
                    let id = &cap[1];
                    let id_low = id.to_ascii_lowercase();
                    if (id_low.contains("user")
                        || id_low.contains("dma")
                        || id_low.contains("desc")
                        || id_low.contains("hdr"))
                        && !id_low.starts_with("local_")
                    {
                        ext_ptrs.insert(id.to_string());
                    }
                }
            }
        }
    }

    // 0. Blocking/sleeping RTOS/kernel APIs called directly inside ISR context (`SMG-HW-IRQ`)
    let fn_hdr_low = fn_body
        .split('{')
        .next()
        .unwrap_or(fn_body)
        .to_ascii_lowercase();
    let fn_is_isr = is_isr_function(fn_name, &fn_hdr_low, all_lines, fn_start);
    if fn_is_isr {
        for &(ln, raw) in &fn_lines {
            let l = strip_string_literals_line(raw).to_ascii_lowercase();
            let is_blocking_isr_api = l.contains("vtaskdelay(")
                || l.contains("pvportmalloc(")
                || l.contains("malloc(")
                || l.contains("msleep(")
                || l.contains("xsemaphoretake(")
                || l.contains("mutex_lock(")
                || (l.contains("kmalloc(") && l.contains("gfp_kernel"));
            if is_blocking_isr_api
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-IRQ",
                    "CRITICAL",
                    SoundinessTier::Verified,
                    format!(
                        "Blocking/sleeping API called inside interrupt handler `{}` (ISR deadlock/crash risk)",
                        fn_name
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::ConcurrencyHazard,
                    GuardKind::LockOrdering,
                    "Never block or sleep inside an ISR; defer work via RTOS `*FromISR` queue/semaphore APIs.",
                )
            {
                findings.push(hit);
            }
        }
    }
    let mut snapshotted_ext_ptrs: HashSet<String> = HashSet::new();
    for &(_, raw) in &fn_lines {
        let low = raw.to_ascii_lowercase();
        if low.contains("copy_from_user(")
            || low.contains("get_user(")
            || low.contains("read_once(")
            || low.contains("read_volatile")
        {
            for ep in &ext_ptrs {
                if raw.contains(ep) {
                    snapshotted_ext_ptrs.insert(ep.clone());
                }
            }
        }
    }
    let mut first_ext_load: Option<(String, String, usize, bool)> = None; // (ptr, field, line, is_cond)

    // Pre-scan secret key allocation for per-buffer scope-exit zeroize check
    let mut secret_key_bufs: Vec<(String, usize)> = Vec::new();
    let mut zeroized_bufs: HashSet<String> = HashSet::new();

    // 1. SecureBoot / Firmware OTA rollback & signature gate
    let is_boot_or_ota = (fn_low.contains("ota_apply")
        || fn_low.contains("flash_write")
        || fn_low.contains("boot_jump")
        || fn_low.contains("jump_to_image")
        || fn_low.contains("firmware_update"))
        && (fn_low.contains("flash_")
            || fn_low.contains("boot_")
            || fn_low.contains("image")
            || fn_low.contains("img"));
    if is_boot_or_ota {
        let mut saw_sig = false;
        let mut sig_vars: HashSet<String> = HashSet::new();
        let mut saw_rollback = false;
        let mut body_started = false;
        for &(ln, raw) in &fn_lines {
            let no_str = strip_string_literals_line(raw);
            let t = no_str.trim();
            let low = t.to_ascii_lowercase();
            if !body_started {
                if t.contains('{') {
                    body_started = true;
                    // If the signature line itself defines `void flash_write(...) {`, skip the header prefix before `{`
                    let after_brace = t.split_once('{').map(|(_, rhs)| rhs.trim()).unwrap_or("");
                    if after_brace.is_empty() {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            let has_sig_call = low.contains("verify_signature")
                || low.contains("ed25519_verify")
                || low.contains("ecdsa_verify")
                || low.contains("rsa_verify")
                || low.contains("crypto_verify")
                || low.contains("mbedtls_pk_verify")
                || low.contains("wc_signatureverify")
                || low.contains("wc_ed25519_verify")
                || low.contains("wc_ecc_verify")
                || low.contains("wc_rsa_verify")
                || low.contains("bootutil_img_validate")
                || low.contains("mcuboot_verify")
                || low.contains("validate_ota_signature");
            if has_sig_call {
                let checked_inline = low.starts_with("if")
                    || low.contains("if (")
                    || low.contains("if(")
                    || low.contains("assert")
                    || low.contains("require")
                    || low.contains("return ")
                    || low.contains('!')
                    || low.contains("==")
                    || low.contains("!=")
                    || low.contains('?');
                if checked_inline {
                    saw_sig = true;
                } else if let Some((lhs, _)) = t.split_once('=')
                    && let Some(v) = ident_re().captures_iter(lhs).last()
                {
                    sig_vars.insert(v[1].to_string());
                }
            }
            if !saw_sig
                && !sig_vars.is_empty()
                && (low.starts_with("if")
                    || low.contains("if (")
                    || low.contains("if(")
                    || low.contains("assert")
                    || low.contains("return"))
                && sig_vars.iter().any(|sv| t.contains(sv))
            {
                saw_sig = true;
            }

            if low.contains("min_version")
                || low.contains("rollback")
                || low.contains("monotonic")
                || low.contains("efuse")
                || low.contains("anti_rollback")
            {
                saw_rollback = true;
            }
            let is_fn_decl = low.starts_with("void ")
                || low.starts_with("int ")
                || low.starts_with("bool ")
                || low.starts_with("fn ")
                || low.starts_with("pub fn ")
                || low.starts_with("static ");
            if !is_fn_decl
                && (low.contains("flash_write(")
                    || low.contains("jump_to_image(")
                    || low.contains("boot_jump("))
                && (!saw_sig || !saw_rollback)
            {
                let missing_what = match (saw_sig, saw_rollback) {
                    (false, false) => {
                        "both cryptographic signature verification and monotonic anti-rollback fuse check"
                    }
                    (false, true) => "cryptographic signature verification",
                    (true, false) => "monotonic version / eFuse anti-rollback check",
                    (true, true) => "",
                };
                if let Some(hit) = mk_hw_finding(
                    "SMG-HW-BOOT",
                    "CRITICAL",
                    SoundinessTier::Likely,
                    format!(
                        "SecureBoot / OTA `{}` proceeds without {} before `{}`",
                        fn_name,
                        missing_what,
                        raw.trim()
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    "Enforce dominating cryptographic signature verification AND monotonic anti-rollback fuse version check before writing flash or jumping to image.",
                ) {
                    findings.push(hit);
                }
                break;
            }
        }
    }

    let mut positive_guards: HashSet<String> = HashSet::new();
    let mut branch_stack: Vec<TypestateBranchFrame> = Vec::new();
    let mut brace_depth: i32 = 0;

    for (line_pos, &(ln, raw)) in fn_lines.iter().enumerate() {
        let trimmed = raw.trim();
        let low = trimmed.to_ascii_lowercase();

        // Update typestate + abstract-domain branch stack on `}` / `else if` / `else` transitions
        let starts_with_close = trimmed.starts_with('}');
        let is_else_if = low.contains("else if");
        let has_else_transition = starts_with_close
            && (low.contains("else") || low.starts_with("} else"))
            || low.starts_with("else ")
            || low == "else"
            || low.starts_with("else{");
        if has_else_transition {
            if let Some(top) = branch_stack.last_mut()
                && !top.in_else
            {
                let accum_then = match top.then_states.take() {
                    Some(prev) => merge_typestate_maps(&prev, &typestates),
                    None => typestates.clone(),
                };
                let accum_nulls = match top.then_nulls.take() {
                    Some(prev) => prev.intersection(&null_ptrs).cloned().collect(),
                    None => null_ptrs.clone(),
                };
                let accum_ivs = match top.then_intervals.take() {
                    Some(prev) => merge_interval_maps(&prev, &intervals),
                    None => intervals.clone(),
                };
                let accum_tnums = match top.then_tnums.take() {
                    Some(prev) => merge_tnum_maps(&prev, &tnums),
                    None => tnums.clone(),
                };
                let accum_pg = match top.then_pos_guards.take() {
                    Some(prev) => prev.intersection(&positive_guards).cloned().collect(),
                    None => positive_guards.clone(),
                };
                top.then_states = Some(accum_then);
                top.then_nulls = Some(accum_nulls);
                top.then_intervals = Some(accum_ivs);
                top.then_tnums = Some(accum_tnums);
                top.then_pos_guards = Some(accum_pg);
                top.then_returned = top.then_returned && top.branch_returned;
                typestates = top.pre_if_states.clone();
                null_ptrs = top.pre_if_nulls.clone();
                intervals = top.pre_if_intervals.clone();
                tnums = top.pre_if_tnums.clone();
                positive_guards = top.pre_if_pos_guards.clone();
                top.in_else = !is_else_if;
                top.branch_returned = false;
            }
        } else if starts_with_close
            && let Some(top) = branch_stack.last()
            && brace_depth - 1 <= top.entry_depth
            && let Some(frame) = branch_stack.pop()
        {
            if frame.in_else {
                let then_st = frame.then_states.unwrap_or(frame.pre_if_states.clone());
                let then_nl = frame.then_nulls.unwrap_or(frame.pre_if_nulls.clone());
                let then_iv = frame
                    .then_intervals
                    .unwrap_or(frame.pre_if_intervals.clone());
                let then_tn = frame.then_tnums.unwrap_or(frame.pre_if_tnums.clone());
                let then_pg = frame
                    .then_pos_guards
                    .unwrap_or(frame.pre_if_pos_guards.clone());
                match (frame.then_returned, frame.branch_returned) {
                    (true, false) => {}
                    (false, true) => {
                        typestates = then_st;
                        null_ptrs = then_nl;
                        intervals = then_iv;
                        tnums = then_tn;
                        positive_guards = then_pg;
                    }
                    (true, true) => {
                        typestates = frame.pre_if_states;
                        null_ptrs = frame.pre_if_nulls;
                        intervals = frame.pre_if_intervals;
                        tnums = frame.pre_if_tnums;
                        positive_guards = frame.pre_if_pos_guards;
                    }
                    (false, false) => {
                        typestates = merge_typestate_maps(&then_st, &typestates);
                        null_ptrs = then_nl.intersection(&null_ptrs).cloned().collect();
                        intervals = merge_interval_maps(&then_iv, &intervals);
                        tnums = merge_tnum_maps(&then_tn, &tnums);
                        positive_guards = then_pg.intersection(&positive_guards).cloned().collect();
                    }
                }
            } else if frame.branch_returned {
                // Early-return `if (...) { kfree(p); return -1; }` does not propagate Freed to fallthrough
                typestates = frame.pre_if_states;
                null_ptrs = frame.pre_if_nulls;
            } else {
                typestates = merge_typestate_maps(&frame.pre_if_states, &typestates);
                intervals = merge_interval_maps(&frame.pre_if_intervals, &intervals);
                tnums = merge_tnum_maps(&frame.pre_if_tnums, &tnums);
                positive_guards = frame
                    .pre_if_pos_guards
                    .intersection(&positive_guards)
                    .cloned()
                    .collect();
            }
        }

        // Push a new branch frame when entering a multi-line `if (...) {` block
        if (low.starts_with("if ") || low.starts_with("if("))
            && trimmed.ends_with('{')
            && !trimmed.contains('}')
        {
            branch_stack.push(TypestateBranchFrame {
                entry_depth: brace_depth,
                pre_if_states: typestates.clone(),
                pre_if_nulls: null_ptrs.clone(),
                pre_if_intervals: intervals.clone(),
                pre_if_tnums: tnums.clone(),
                pre_if_pos_guards: positive_guards.clone(),
                then_states: None,
                then_nulls: None,
                then_intervals: None,
                then_tnums: None,
                then_pos_guards: None,
                then_returned: false,
                in_else: false,
                branch_returned: false,
            });
        }

        // Record stack buffer declarations (`uint8_t priv_key[32];` or `char dst[256];`)
        if trimmed.contains('[')
            && trimmed.ends_with(';')
            && !trimmed.starts_with("static ")
            && !trimmed.contains('(')
        {
            for cap in stack_array_decl_re().captures_iter(trimmed) {
                let arr_name = &cap[1];
                if let Some(sz) = parse_hex_or_dec_u64(&cap[2]) {
                    local_caps.insert(arr_name.to_string(), sz);
                }
            }
            for cap in ident_re().captures_iter(trimmed) {
                let lv = &cap[1];
                let lv_low = lv.to_ascii_lowercase();
                if (lv_low.contains("priv_key")
                    || lv_low.contains("master_key")
                    || lv_low.contains("aes_key")
                    || lv_low.contains("hmac_key")
                    || lv_low.contains("secret_key"))
                    && !secret_key_bufs.iter().any(|(b, _)| b == lv)
                {
                    secret_key_bufs.push((lv.to_string(), ln));
                    if trimmed.contains("ZeroizeOnDrop") {
                        zeroized_bufs.insert(lv.to_string());
                    }
                }
            }
        }

        // Track zeroize calls per buffer identifier
        if low.contains("explicit_bzero(")
            || low.contains("memset_s(")
            || low.contains("openssl_cleanse(")
            || low.contains("mbedtls_platform_zeroize(")
            || low.contains(".zeroize()")
            || low.contains("zeroize(")
        {
            for (buf, _) in &secret_key_bufs {
                if trimmed.contains(buf) {
                    zeroized_bufs.insert(buf.clone());
                }
            }
            for cap in ident_re().captures_iter(trimmed) {
                let id = &cap[1];
                for (buf, _) in &secret_key_bufs {
                    if aliases.same_alias(buf, id) {
                        zeroized_bufs.insert(buf.clone());
                    }
                }
            }
        }

        // Track alias `ptr2 = ptr1;`, null assignments, MMIO pointer bindings, and mask narrowing
        if let Some((lhs, rhs)) = trimmed.split_once('=')
            && !lhs.contains("==")
            && !lhs.contains("!=")
            && !lhs.contains("<=")
            && !lhs.contains(">=")
        {
            let l_trim = lhs.trim();
            let l_id = ident_re()
                .captures_iter(l_trim)
                .last()
                .map(|c| c[1].to_string());
            let r_trim = rhs.trim().trim_end_matches(';').trim();
            if let Some(lv) = l_id {
                let is_deref_store = l_trim.starts_with('*') || l_trim.contains('[');
                if !is_deref_store {
                    if matches!(r_trim, "NULL" | "nullptr" | "0" | "(void*)0" | "(void *)0") {
                        null_ptrs.insert(lv.clone());
                        typestates.insert(lv.clone(), (HwTypestate::Uninit, ln));
                    } else {
                        null_ptrs.remove(&lv);
                        if !alloc_assign_re().is_match(trimmed)
                            && matches!(
                                typestates.get(&lv).map(|(s, _)| *s),
                                Some(
                                    HwTypestate::Freed
                                        | HwTypestate::Conflict
                                        | HwTypestate::Uninit
                                )
                            )
                        {
                            typestates.insert(lv.clone(), (HwTypestate::Borrowed, ln));
                        }
                    }

                    // Bind MMIO pointer variable `volatile uint32_t *flash = (volatile uint32_t *)0x08001000;`
                    let mut bound_hex = false;
                    if l_trim.contains('*') && !r_trim.starts_with('*') {
                        for cap in hex_addr_re().captures_iter(r_trim) {
                            if let Some(addr) = parse_u64_hex(&cap[1]) {
                                mmio_ptrs.insert(lv.clone(), addr);
                                bound_hex = true;
                            }
                        }
                    }
                    if !bound_hex {
                        mmio_ptrs.remove(&lv);
                    }
                }

                if let Some(rv) = ident_re().find(r_trim).map(|m| m.as_str())
                    && r_trim == rv
                {
                    aliases.union_names(&lv, rv);
                    if snapshotted_ext_ptrs.contains(rv) {
                        snapshotted_ext_ptrs.insert(lv.clone());
                    }
                }
                if (lv.to_ascii_lowercase().contains("priv_key")
                    || lv.to_ascii_lowercase().contains("master_key")
                    || lv.to_ascii_lowercase().contains("aes_key")
                    || lv.to_ascii_lowercase().contains("hmac_key")
                    || lv.to_ascii_lowercase().contains("secret_key"))
                    && !trimmed.starts_with("static ")
                    && !secret_key_bufs.iter().any(|(b, _)| b == &lv)
                {
                    secret_key_bufs.push((lv.clone(), ln));
                }

                // Tnum + WrappedInterval arithmetic: `&`, `|`, `<<`, `>>`, `+` (Phase 13A P13-01)
                let lookup_tnum = |tok: &str,
                                   tmap: &HashMap<String, Tnum>,
                                   imap: &HashMap<String, WrappedInterval>|
                 -> Tnum {
                    let t = tok.trim();
                    if let Some(c) = parse_hex_or_dec_u64(t) {
                        return Tnum::constant(c);
                    }
                    if let Some(tn) = tmap.get(t) {
                        return *tn;
                    }
                    if let Some(iv) = imap.get(t)
                        && iv.smin >= 0
                    {
                        return Tnum::from_range(iv.umin, iv.umax);
                    }
                    if let Some(c) = lookup_const_define(t, cu_opt, ctx)
                        && c >= 0
                    {
                        return Tnum::constant(c as u64);
                    }
                    Tnum::unknown_with_width(width_bits)
                };

                if let Some((lhs_op, rhs_mask)) = r_trim.split_once('&')
                    && !r_trim.contains("&&")
                    && let Some(mask_val) = parse_hex_or_dec_u64(rhs_mask.trim())
                {
                    let base_tn = lookup_tnum(lhs_op, &tnums, &intervals);
                    let narrowed = base_tn.tnum_and(Tnum::constant(mask_val));
                    tnums.insert(lv.clone(), narrowed);
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            narrowed.min_u64(),
                            narrowed.max_u64(),
                            width_bits,
                        ),
                    );
                    positive_guards.insert(lv.clone());
                } else if let Some((lhs_op, rhs_or)) = r_trim.split_once('|')
                    && !r_trim.contains("||")
                    && let Some(or_val) = parse_hex_or_dec_u64(rhs_or.trim())
                {
                    let base_tn = lookup_tnum(lhs_op, &tnums, &intervals);
                    let res_tn = base_tn.tnum_or(Tnum::constant(or_val)).masked(width_bits);
                    tnums.insert(lv.clone(), res_tn);
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            res_tn.min_u64(),
                            res_tn.max_u64(),
                            width_bits,
                        ),
                    );
                    positive_guards.insert(lv.clone());
                } else if let Some((lhs_op, rhs_sh)) = r_trim.split_once("<<")
                    && let Some(sh) = parse_hex_or_dec_u64(rhs_sh.trim())
                    && sh < 64
                {
                    let base_tn = lookup_tnum(lhs_op, &tnums, &intervals);
                    let res_tn = base_tn.tnum_lshift(sh as u32).masked(width_bits);
                    tnums.insert(lv.clone(), res_tn);
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            res_tn.min_u64(),
                            res_tn.max_u64(),
                            width_bits,
                        ),
                    );
                    positive_guards.insert(lv.clone());
                } else if let Some((lhs_op, rhs_sh)) = r_trim.split_once(">>")
                    && let Some(sh) = parse_hex_or_dec_u64(rhs_sh.trim())
                    && sh < 64
                {
                    let base_tn = lookup_tnum(lhs_op, &tnums, &intervals);
                    let res_tn = base_tn.tnum_rshift(sh as u32);
                    tnums.insert(lv.clone(), res_tn);
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            res_tn.min_u64(),
                            res_tn.max_u64(),
                            width_bits,
                        ),
                    );
                    positive_guards.insert(lv.clone());
                } else if let Some((lhs_add, rhs_add)) = r_trim.split_once('+')
                    && !r_trim.contains("++")
                    && !r_trim.contains('"')
                {
                    let a_tok = lhs_add.trim();
                    let b_tok = rhs_add.trim();
                    let a_iv = parse_hex_or_dec_u64(a_tok)
                        .and_then(|v| i64::try_from(v).ok())
                        .map(|v| WrappedInterval::constant_signed(v, width_bits))
                        .or_else(|| lookup_interval(a_tok, &intervals));
                    let b_iv = parse_hex_or_dec_u64(b_tok)
                        .and_then(|v| i64::try_from(v).ok())
                        .map(|v| WrappedInterval::constant_signed(v, width_bits))
                        .or_else(|| lookup_interval(b_tok, &intervals));
                    if let (Some(ia), Some(ib)) = (a_iv, b_iv) {
                        let sum_iv = ia.signed_add(ib);
                        let sum_tn = lookup_tnum(a_tok, &tnums, &intervals)
                            .tnum_add_width(lookup_tnum(b_tok, &tnums, &intervals), width_bits);
                        tnums.insert(lv.clone(), sum_tn);
                        intervals.insert(lv.clone(), sum_iv);
                        if !sum_iv.signed_wrap && sum_iv.smin >= 0 {
                            positive_guards.insert(lv.clone());
                        }
                    }
                } else if r_trim.contains("(size_t)") || r_trim.contains(" as usize") {
                    for cap in ident_re().captures_iter(r_trim) {
                        if let Some(prev_iv) = lookup_interval(&cap[1], &intervals) {
                            intervals.insert(lv.clone(), prev_iv);
                            if let Some(prev_tn) = tnums.get(&cap[1]).copied() {
                                tnums.insert(lv.clone(), prev_tn);
                            }
                            if positive_guards.contains(&cap[1]) {
                                positive_guards.insert(lv.clone());
                            }
                        }
                    }
                } else if let Some(const_v) = parse_hex_or_dec_u64(r_trim)
                    && !is_deref_store
                    && !l_trim.contains('*')
                    && let Ok(iv) = i64::try_from(const_v)
                {
                    intervals.insert(lv.clone(), WrappedInterval::constant_signed(iv, width_bits));
                    tnums.insert(lv.clone(), Tnum::constant(const_v));
                }
            }
        }

        // Capture simple & relational bounds guards (`if (len < 0 || len > 256) return;`, `if (idx >= 64) return;`, `if (off + len > 256) return;`)
        if low.starts_with("if ") || low.starts_with("if(") {
            let has_abort_on_line =
                low.contains("return") || low.contains("goto ") || low.contains("break");
            // Look ahead strictly inside this `if`'s body (up to 3 lines before `}`) instead of whole-fn `return`
            let mut body_aborts = false;
            if !has_abort_on_line {
                for &(_, next_raw) in fn_lines.iter().skip(line_pos + 1).take(3) {
                    let nl = next_raw.trim().to_ascii_lowercase();
                    if nl.starts_with('}') {
                        break;
                    }
                    if nl.contains("return") || nl.contains("goto ") || nl.contains("break") {
                        body_aborts = true;
                        break;
                    }
                    if !trimmed.ends_with('{') {
                        // Single-statement `if (...) \n return;`
                        break;
                    }
                }
            }
            let is_early_reject = has_abort_on_line || body_aborts;

            for cap in sum_guard_re().captures_iter(trimmed) {
                let va = cap[1].to_string();
                let vb = cap[2].to_string();
                let op = &cap[3];
                if let Some(lim) = resolve_bound_token(&cap[4], ctx, &local_caps)
                    && ((is_early_reject && (op == ">" || op == ">="))
                        || (!is_early_reject && (op == "<=" || op == "<")))
                {
                    let adj = if op == ">=" || op == "<" {
                        lim.saturating_sub(1)
                    } else {
                        lim
                    };
                    relational_sum_limits.push((va.clone(), vb.clone(), adj));
                    positive_guards.insert(va);
                    positive_guards.insert(vb);
                }
            }

            for cap in sub_guard_re().captures_iter(trimmed) {
                let va = cap[1].to_string();
                let op = &cap[2];
                let vb = cap[4].to_string();
                if let Some(lim) = resolve_bound_token(&cap[3], ctx, &local_caps)
                    && ((is_early_reject && (op == ">" || op == ">="))
                        || (!is_early_reject && (op == "<=" || op == "<")))
                {
                    let adj = if op == ">=" || op == "<" {
                        lim.saturating_sub(1)
                    } else {
                        lim
                    };
                    relational_sum_limits.push((va.clone(), vb.clone(), adj));
                    positive_guards.insert(va);
                    positive_guards.insert(vb);
                }
            }

            for cap in cmp_guard_re().captures_iter(trimmed) {
                let Some(m) = cap.get(1) else {
                    continue;
                };
                let before_var = trimmed[..m.start()].trim_end();
                if before_var.ends_with("->") || before_var.ends_with('.') {
                    continue;
                }
                let has_unsigned_cast = before_var.ends_with("(size_t)")
                    || before_var.ends_with("(uint32_t)")
                    || before_var.ends_with("(unsigned)")
                    || before_var.ends_with("as usize");
                let v = m.as_str();
                let op = &cap[2];
                let bound_tok = &cap[3];
                let bound_val = resolve_bound_token(bound_tok, ctx, &local_caps);
                if let Some(iv) = intervals.get_mut(v) {
                    if (op == ">=" && bound_val == Some(0) && !is_early_reject)
                        || ((op == "<" || op == "<=") && bound_val == Some(0) && is_early_reject)
                    {
                        iv.smin = iv.smin.max(0);
                        iv.umin = 0;
                        if iv.smax >= 0 {
                            iv.umax = iv.umax.min(iv.smax as u64);
                        }
                        iv.signed_wrap = false;
                        iv.reduce();
                        positive_guards.insert(v.to_string());
                    } else if let Some(bval) = bound_val
                        && bval > 0
                    {
                        let narrows_upper = (is_early_reject && (op == ">" || op == ">="))
                            || (!is_early_reject && (op == "<=" || op == "<"));
                        if narrows_upper {
                            let max_allowed = if op == ">=" || op == "<" {
                                bval.saturating_sub(1).max(0)
                            } else {
                                bval
                            };
                            if has_unsigned_cast || unsigned_params.contains(v) {
                                iv.smin = iv.smin.max(0);
                                iv.umin = 0;
                                iv.signed_wrap = false;
                            }
                            iv.smax = iv.smax.min(max_allowed);
                            if iv.smin >= 0 {
                                iv.umax = iv.umax.min(max_allowed as u64);
                                iv.reduce();
                                positive_guards.insert(v.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Alloc/Free Typestate Automaton `Q_hw`: UAF & Double-Free
        for cap in alloc_assign_re().captures_iter(trimmed) {
            let v = cap[1].to_string();
            null_ptrs.remove(&v);
            typestates.insert(v, (HwTypestate::Owned, ln));
        }
        let line_returns_immediately =
            low.contains("return") || low.contains("goto ") || low.contains("panic!(");
        if let Some(cap) = free_call_re().captures(trimmed) {
            let ptr = &cap[1];
            if !null_ptrs.contains(ptr) {
                if let Some((state, prev_ln)) = typestates.get(ptr).copied()
                    && matches!(state, HwTypestate::Freed | HwTypestate::Conflict)
                {
                    let tier = if state == HwTypestate::Freed {
                        SoundinessTier::Proven
                    } else {
                        SoundinessTier::Likely
                    };
                    if let Some(hit) = mk_hw_finding(
                        "SMG-HW-TYPESTATE",
                        "CRITICAL",
                        tier,
                        format!(
                            "Double-Free of `{}` (already freed at line {}) inside `{}`",
                            ptr, prev_ln, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        "Null out freed pointers (`ptr = NULL;`) immediately and enforce single ownership before release.",
                    ) {
                        findings.push(hit);
                    }
                } else if !((low.starts_with("if ") || low.starts_with("if("))
                    && line_returns_immediately)
                {
                    typestates.insert(ptr.to_string(), (HwTypestate::Freed, ln));
                }
            }
        } else {
            // Check dereference of a Freed pointer (`ptr->...` or `*ptr`) with word boundaries
            for (ptr, (state, freed_ln)) in &typestates {
                if matches!(state, HwTypestate::Freed | HwTypestate::Conflict)
                    && line_derefs_ptr(trimmed, ptr)
                    && !trimmed.starts_with("if")
                    && !trimmed.contains("= NULL")
                    && !trimmed.contains("= nullptr")
                {
                    let tier = if *state == HwTypestate::Freed {
                        SoundinessTier::Proven
                    } else {
                        SoundinessTier::Likely
                    };
                    if let Some(hit) = mk_hw_finding(
                        "SMG-HW-TYPESTATE",
                        "CRITICAL",
                        tier,
                        format!(
                            "Use-After-Free dereference of `{}` (freed at line {}) in `{}`",
                            ptr, freed_ln, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        "Do not dereference pointers after `free`/`kfree`; restructure cleanup onto a single exit path.",
                    ) {
                        findings.push(hit);
                    }
                }
            }
        }

        if line_returns_immediately && let Some(top) = branch_stack.last_mut() {
            top.branch_returned = true;
        }

        // 2. MMIO physical dereference / SVD/Linker bounds check (`SMG-HW-MMIO`)
        let is_ptr_binding_decl = if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let lt = lhs.trim();
            let rt = rhs.trim();
            lt.contains('*') && !lt.starts_with('*') && !rt.starts_with('*')
        } else {
            false
        };
        let is_direct_write_stmt = if let Some((lhs, _)) = trimmed.split_once('=')
            && !trimmed.contains("==")
            && !trimmed.contains("!=")
        {
            let lt = lhs.trim();
            lt.starts_with('*')
                || lt.contains('[')
                || lt.starts_with("REG32")
                || lt.starts_with("MMIO")
        } else {
            trimmed.contains("write_volatile")
        };

        // Check stack-allocated buffer passed directly into async DMA TX/RX API (`SMG-HW-BOUNDS`)
        if !local_caps.is_empty()
            && (low.contains("_transmit_dma(")
                || low.contains("_receive_dma(")
                || low.contains("dma_map_single("))
        {
            for buf_name in local_caps.keys() {
                if ident_re()
                    .find_iter(trimmed)
                    .any(|m| m.as_str() == buf_name)
                {
                    if let Some(hit) = mk_hw_finding(
                        "SMG-HW-BOUNDS",
                        "HIGH",
                        SoundinessTier::Verified,
                        format!(
                            "Stack buffer `{}` passed directly to DMA API in `{}` (DMA lifetime/cache-alignment hazard)",
                            buf_name, fn_name
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        "Allocate DMA buffers in static DMA-capable SRAM (`__attribute__((aligned(32)))`) or heap DMA pools instead of stack frames.",
                    ) {
                        findings.push(hit);
                    }
                    break;
                }
            }
        }

        // Check dereference writes through bound MMIO pointer variables (`*flash = 0x1;`)
        if is_direct_write_stmt && let Some((lhs, _)) = trimmed.split_once('=') {
            for cap in ident_re().captures_iter(lhs) {
                let pvar = &cap[1];
                if let Some(&addr) = mmio_ptrs.get(pvar)
                    && ctx.memory_regions.iter().any(|r| {
                        r.contains(addr)
                            && !r.writable
                            && region_applies_to_file(rel_path, r, &ctx.memory_regions)
                    })
                    && let Some(hit) = mk_hw_finding(
                        "SMG-HW-MMIO",
                        "HIGH",
                        SoundinessTier::Proven,
                        format!(
                            "MMIO/pointer write via `{}` targets non-writable Flash/ROM region `0x{:08X}`",
                            pvar, addr
                        ),
                        rel_path,
                        ln,
                        fn_name,
                        SinkKind::MemorySafety,
                        GuardKind::MemoryBounds,
                        "Validate hardware register base addresses against board SVD/linker regions and mask dynamic register offsets (`idx & 0x...`).",
                    )
                {
                    findings.push(hit);
                }
            }
        }

        let is_mmio_deref = !is_ptr_binding_decl
            && (trimmed.contains("volatile")
                || trimmed.contains("read_volatile")
                || trimmed.contains("write_volatile")
                || trimmed.contains("MMIO")
                || trimmed.contains("REG32"));
        if is_mmio_deref {
            let has_svd = ctx.has_svd_regions();
            for cap in hex_addr_re().captures_iter(trimmed) {
                let Some(m) = cap.get(1) else {
                    continue;
                };
                if is_hex_preceded_by_mask_or_cmp(trimmed, m.start()) {
                    continue;
                }
                if let Some(addr) = parse_u64_hex(m.as_str()) {
                    let in_readonly_flash = ctx.memory_regions.iter().any(|r| {
                        r.contains(addr)
                            && !r.writable
                            && region_applies_to_file(rel_path, r, &ctx.memory_regions)
                    });
                    let unknown_unmapped = !ctx.memory_regions.is_empty()
                        && !ctx.memory_regions.iter().any(|r| {
                            r.contains(addr)
                                && region_applies_to_file(rel_path, r, &ctx.memory_regions)
                        })
                        && (has_svd || !(0x4000_0000..0x6000_0000).contains(&addr));
                    let has_mask_guard = trimmed.contains('&')
                        || trimmed.contains("in_bounds")
                        || positive_guards.iter().any(|g| trimmed.contains(g));
                    if (in_readonly_flash && is_direct_write_stmt)
                        || (unknown_unmapped && addr >= 0x1000_0000 && !has_mask_guard)
                    {
                        let tier = if in_readonly_flash {
                            SoundinessTier::Proven
                        } else {
                            SoundinessTier::Verified
                        };
                        let detail = if in_readonly_flash {
                            format!(
                                "MMIO/pointer write targets non-writable Flash region `{}`",
                                m.as_str()
                            )
                        } else {
                            format!(
                                "MMIO access `{}` falls outside declared CMSIS-SVD / linker memory regions",
                                m.as_str()
                            )
                        };
                        if let Some(hit) = mk_hw_finding(
                            "SMG-HW-MMIO",
                            "HIGH",
                            tier,
                            detail,
                            rel_path,
                            ln,
                            fn_name,
                            SinkKind::MemorySafety,
                            GuardKind::MemoryBounds,
                            "Validate hardware register base addresses against board SVD/linker regions and mask dynamic register offsets (`idx & 0x...`).",
                        ) {
                            findings.push(hit);
                        }
                    } else if addr >= 0x4000_0000 && trimmed.contains('+') && !has_mask_guard {
                        // Unmasked dynamic offset arithmetic on raw physical MMIO address
                        if let Some(hit) = mk_hw_finding(
                            "SMG-HW-MMIO",
                            "HIGH",
                            SoundinessTier::Likely,
                            format!(
                                "Unmasked offset arithmetic on physical MMIO address `{}` in `{}`",
                                m.as_str(),
                                fn_name
                            ),
                            rel_path,
                            ln,
                            fn_name,
                            SinkKind::MemorySafety,
                            GuardKind::MemoryBounds,
                            "Mask register offset with exact peripheral window mask or use checked HAL register accessors.",
                        ) {
                            findings.push(hit);
                        }
                    }
                }
            }
        }

        // Dynamic offset MMIO without hex constant (`mmio_base[idx]` or `write_volatile(mmio_base.add(idx))`)
        if !ctx.memory_regions.is_empty()
            && (low.contains("mmio_base") || low.contains("reg_base"))
            && (trimmed.contains('[') || trimmed.contains(".add("))
            && !trimmed.contains('&')
            && !low.contains("if (")
            && !low.contains("if(")
            && !positive_guards.iter().any(|g| trimmed.contains(g))
        {
            let region_cap = ctx
                .memory_regions
                .iter()
                .map(|r| r.size)
                .max()
                .unwrap_or(0x400);
            let idx_var = trimmed
                .split_once('[')
                .and_then(|(_, r)| r.split_once(']'))
                .map(|(i, _)| i.trim())
                .or_else(|| {
                    trimmed
                        .split_once(".add(")
                        .and_then(|(_, r)| r.split_once(')'))
                        .map(|(i, _)| i.trim())
                });
            let idx_iv = idx_var
                .and_then(|v| lookup_interval(v, &intervals))
                .unwrap_or_else(|| WrappedInterval::from_u64_bounds(0, 65535, width_bits));
            if bv_solver
                .check_bounds_violation(idx_iv, region_cap / 4, false)
                .is_some()
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-MMIO",
                    "HIGH",
                    SoundinessTier::Verified,
                    format!(
                        "Unchecked dynamic offset on MMIO region in `{}` can exceed peripheral size",
                        fn_name
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::MemorySafety,
                    GuardKind::MemoryBounds,
                    "Bound dynamic MMIO offsets below peripheral `addressBlock.size` via explicit range guard or bitwise mask.",
                )
            {
                findings.push(hit);
            }
        }

        // 3. Wrapped Interval + Sparse Octagon firmware bounds check (`SMG-HW-BOUNDS`)
        if (low.contains("memcpy(")
            || low.contains("memmove(")
            || low.contains("copy_from_user(")
            || low.contains("from_raw_parts"))
            && !trimmed.starts_with("//")
        {
            let args_part = trimmed.split_once('(').map(|(_, r)| r).unwrap_or(trimmed);
            let last_arg = args_part.rsplit(',').next().unwrap_or(args_part);
            let mut found_wrap_var: Option<(String, WrappedInterval)> = None;
            for cap in ident_re().captures_iter(last_arg) {
                let id = &cap[1];
                if let Some(iv) = intervals.get(id).copied()
                    && (iv.can_wrap_negative_to_large_size() || iv.signed_wrap)
                    && !positive_guards.contains(id)
                    && !unsigned_params.contains(id)
                {
                    found_wrap_var = Some((id.to_string(), iv));
                    break;
                }
            }
            if let Some((var, iv)) = found_wrap_var
                && bv_solver.check_bounds_violation(iv, 4096, false).is_some()
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-BOUNDS",
                    "CRITICAL",
                    SoundinessTier::Verified,
                    format!(
                        "Signed-to-size_t wraparound risk on `{}` passed into `{}` inside `{}`",
                        var, trimmed, fn_name
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::MemorySafety,
                    GuardKind::MemoryBounds,
                    "Use unsigned `size_t` with explicit non-negative & capacity checks (`if (len < 0 || (size_t)len > sizeof(dst)) return -EINVAL;`) before copy.",
                )
            {
                findings.push(hit);
            } else if trimmed.contains('+')
                && (low.contains("off") || low.contains("offset"))
                && !low.contains("checked_add")
                && !low.contains("cap")
            {
                // Phase 13A P13-01 / F5B-04: Parse ONLY the copy call's first argument (`arg0` = destination)
                // before the first comma and look up `local_caps` strictly on `arg0` so `src`'s array capacity
                // is never misattributed when `dst` is an opaque pointer (`memcpy(opaque_ptr, local_buf, n)`).
                let arg0 = trimmed
                    .find('(')
                    .map(|open| &trimmed[open + 1..])
                    .and_then(|after| after.split(',').next())
                    .unwrap_or("");
                let dst_cap_opt = ident_re()
                    .find_iter(arg0)
                    .filter_map(|m| local_caps.get(m.as_str()).copied())
                    .min()
                    .and_then(|v| i64::try_from(v).ok());

                if let Some(dst_cap) = dst_cap_opt {
                    // Build multi-variable `OctVarMap` (up to `MAX_OCTAGON_VARS = 12`)
                    let mut oct_vars: Vec<String> = Vec::new();
                    let mut oct_idx = |name: &str| -> Option<usize> {
                        if name.is_empty() {
                            return None;
                        }
                        if let Some(pos) = oct_vars.iter().position(|v| v == name) {
                            return Some(pos);
                        }
                        if oct_vars.len() < crate::domains::MAX_OCTAGON_VARS {
                            oct_vars.push(name.to_string());
                            return Some(oct_vars.len() - 1);
                        }
                        None
                    };

                    let mut off_name = String::new();
                    let mut len_name = String::new();
                    for cap in ident_re().captures_iter(trimmed) {
                        let id = &cap[1];
                        let id_low = id.to_ascii_lowercase();
                        if id_low.contains("off") && off_name.is_empty() {
                            off_name = id.to_string();
                        } else if (id_low.contains("len")
                            || id_low.contains("size")
                            || id_low == "n")
                            && len_name.is_empty()
                        {
                            len_name = id.to_string();
                        }
                    }

                    if let (Some(i_off), Some(i_len)) = (oct_idx(&off_name), oct_idx(&len_name)) {
                        for (va, vb, _) in &relational_sum_limits {
                            let _ = oct_idx(va);
                            let _ = oct_idx(vb);
                        }
                        let mut oct = SparseOctagon::new(oct_vars.len().max(2));
                        for (idx_v, vname) in oct_vars.iter().enumerate() {
                            if let Some(iv) = lookup_interval(vname, &intervals) {
                                if unsigned_params.contains(vname) {
                                    oct.add_lower_bound(idx_v, 0);
                                    let hi = iv.umax.min(i32::MAX as u64) as i64;
                                    oct.add_upper_bound(idx_v, hi);
                                } else {
                                    oct.add_lower_bound(idx_v, iv.smin.max(0));
                                    oct.add_upper_bound(idx_v, iv.smax.clamp(0, i32::MAX as i64));
                                }
                            } else {
                                oct.add_lower_bound(idx_v, 0);
                            }
                        }
                        for (va, vb, lim) in &relational_sum_limits {
                            if let (Some(ia), Some(ib)) = (
                                oct_vars.iter().position(|v| v == va),
                                oct_vars.iter().position(|v| v == vb),
                            ) {
                                oct.add_sum_le(ia, ib, *lim);
                            }
                        }
                        if oct.close()
                            && !oct.proves_sum_le(i_off, i_len, dst_cap)
                            && let Some(hit) = mk_hw_finding(
                                "SMG-HW-BOUNDS",
                                "HIGH",
                                SoundinessTier::Likely,
                                format!(
                                    "Buffer `offset + len` arithmetic in `{}` lacks relational capacity guard against overflow (dst cap = {})",
                                    fn_name, dst_cap
                                ),
                                rel_path,
                                ln,
                                fn_name,
                                SinkKind::MemorySafety,
                                GuardKind::MemoryBounds,
                                "Check overflow-safe relational invariant (`if (off > cap || len > cap - off) return -EINVAL;`) before pointer offset + copy.",
                            )
                        {
                            findings.push(hit);
                        }
                    }
                }
            }
        }

        // 4. DMA / Userspace Double-Fetch TOCTOU (`SMG-HW-TOCTOU`)
        if !ext_ptrs.is_empty() {
            for ep in &ext_ptrs {
                if snapshotted_ext_ptrs.contains(ep) {
                    continue;
                }
                let arrow = format!("{}->", ep);
                if let Some(pos) = trimmed.find(&arrow) {
                    let after_arrow = &trimmed[pos + arrow.len()..];
                    let curr_field = ident_re()
                        .find(after_arrow)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    let is_cond = low.starts_with("if")
                        || low.contains(" < ")
                        || low.contains(" > ")
                        || low.contains(" <= ")
                        || low.contains(" >= ");
                    let is_sink = low.contains("memcpy")
                        || low.contains("kmalloc")
                        || low.contains("alloc")
                        || low.contains("dma");
                    match &first_ext_load {
                        None => {
                            first_ext_load = Some((ep.clone(), curr_field, ln, is_cond));
                        }
                        Some((prev_p, prev_field, prev_ln, prev_cond))
                            if aliases.same_alias(prev_p, ep)
                                && ln > *prev_ln
                                && ((*prev_cond && prev_field == &curr_field)
                                    || (*prev_cond && is_sink)) =>
                        {
                            if let Some(hit) = mk_hw_finding(
                                "SMG-HW-TOCTOU",
                                "HIGH",
                                SoundinessTier::Likely,
                                format!(
                                    "Double-Fetch TOCTOU: untrusted DMA/__user pointer `{}` loaded at line {} (checked) and re-fetched at line {} without local snapshot",
                                    ep, prev_ln, ln
                                ),
                                rel_path,
                                ln,
                                fn_name,
                                SinkKind::ConcurrencyHazard,
                                GuardKind::TxLock,
                                "Read untrusted DMA / `__user` headers once via `copy_from_user` or `READ_ONCE` into a local kernel variable before validating and allocating/copying.",
                            ) {
                                findings.push(hit);
                            }
                            first_ext_load = None;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // 5. Constant-time cryptography non-interference (`SMG-HW-CT`)
        let fn_name_low = fn_name.to_ascii_lowercase();
        if is_crypto_fn_name(&fn_name_low) && !smg_graph::taint::is_pattern_matcher_or_doc_line(raw)
        {
            let has_secret_branch = (low.starts_with("if") || low.contains("if ("))
                && (low.contains("secret")
                    || low.contains("priv_key")
                    || low.contains("scalar_bit")
                    || low.contains("k["))
                && !low.contains("== null")
                && !low.contains("== nullptr")
                && !low.contains("< 0");
            let has_secret_sbox = (low.contains("sbox[") || low.contains("table["))
                && (low.contains("secret") || low.contains("priv") || low.contains("key["));
            if (has_secret_branch || has_secret_sbox)
                && !low.contains("ct_select")
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-CT",
                    "MEDIUM",
                    SoundinessTier::Likely,
                    format!(
                        "Secret-dependent branch or S-box table index leaks timing channel in `{}` (note: compiler optimization `-O3` caveats require binary verification)",
                        fn_name
                    ),
                    rel_path,
                    ln,
                    fn_name,
                    SinkKind::Misconfiguration,
                    GuardKind::ConfigPolicy,
                    "Replace secret branches and table lookups with constant-time bitmask selects (`ct_select`) or hardware AES instructions.",
                )
            {
                findings.push(hit);
            }
        }

        brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
        brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;
    }

    // Secret key retention on scope exit without per-buffer zeroization
    for (buf, ln) in secret_key_bufs {
        if !zeroized_bufs.contains(&buf)
            && let Some(hit) = mk_hw_finding(
                "SMG-HW-TYPESTATE",
                "HIGH",
                SoundinessTier::Likely,
                format!(
                    "Cryptographic key buffer `{}` exits scope in `{}` without `explicit_bzero` / `zeroize` cleanup",
                    buf, fn_name
                ),
                rel_path,
                ln,
                fn_name,
                SinkKind::ResourceLeak,
                GuardKind::ResourceCleanup,
                "Scrub sensitive key material cleanly before returning using `explicit_bzero`, `memset_s`, `mbedtls_platform_zeroize`, or Rust `ZeroizeOnDrop`.",
            )
        {
            findings.push(hit);
        }
    }
}

/// Solves cross-function RTOS interrupt priority, sleeping-in-ISR, and lock-order partial-order
/// deadlocks (`SMG-HW-IRQ`) via bounded (`<= 4` hop) `HardwareFunctionLockSummary` fixed-point
/// inter-procedural propagation (Phase 13A `P13-02`).
pub fn check_cross_fn_irq_deadlocks(
    summaries: &[HardwareFunctionLockSummary],
) -> Vec<LocalStaticFinding> {
    const MAX_HW_SUMMARY_HOPS: usize = 4;
    const MAX_ACQUIRED_LOCKS_PER_FN: usize = 32;
    const MAX_LOCK_PAIRS_PER_FN: usize = 64;

    #[derive(Clone)]
    struct MutLockState {
        calls_sleeping_alloc: bool,
        sleeping_alloc_line: Option<usize>,
        acquired_locks: Vec<String>,
        lock_irq_saved: HashMap<String, bool>,
        held_lock_pairs: Vec<(String, String)>,
    }

    // Lightweight mutable propagation state (never clones immutable `callees` / metadata per hop)
    let mut states: Vec<MutLockState> = summaries
        .iter()
        .map(|s| MutLockState {
            calls_sleeping_alloc: s.calls_sleeping_alloc,
            sleeping_alloc_line: s.sleeping_alloc_line,
            acquired_locks: s
                .acquired_locks
                .iter()
                .take(MAX_ACQUIRED_LOCKS_PER_FN)
                .cloned()
                .collect(),
            lock_irq_saved: s.lock_irq_saved.clone(),
            held_lock_pairs: s
                .held_lock_pairs
                .iter()
                .take(MAX_LOCK_PAIRS_PER_FN)
                .cloned()
                .collect(),
        })
        .collect();

    let mut name_counts: HashMap<&str, usize> = HashMap::with_capacity(summaries.len());
    let mut file_name_counts: HashMap<(&str, &str), usize> =
        HashMap::with_capacity(summaries.len());
    for s in summaries {
        *name_counts.entry(s.fn_name.as_str()).or_insert(0) += 1;
        *file_name_counts
            .entry((s.rel_path.as_str(), s.fn_name.as_str()))
            .or_insert(0) += 1;
    }
    let mut same_file_idx: HashMap<(&str, &str), usize> = HashMap::with_capacity(summaries.len());
    let mut unique_name_idx: HashMap<&str, usize> = HashMap::with_capacity(summaries.len());
    for (idx, s) in summaries.iter().enumerate() {
        if file_name_counts
            .get(&(s.rel_path.as_str(), s.fn_name.as_str()))
            .copied()
            == Some(1)
        {
            same_file_idx.insert((s.rel_path.as_str(), s.fn_name.as_str()), idx);
        }
        if name_counts.get(s.fn_name.as_str()).copied() == Some(1) {
            unique_name_idx.insert(s.fn_name.as_str(), idx);
        }
    }
    let resolve_callee = |caller_path: &str, callee_name: &str| -> Option<usize> {
        same_file_idx
            .get(&(caller_path, callee_name))
            .copied()
            .or_else(|| unique_name_idx.get(callee_name).copied())
    };

    // Bounded <= 4-hop fixed-point propagation of locks, lock pairs, and sleeping-alloc effects
    for _hop in 0..MAX_HW_SUMMARY_HOPS {
        let mut changed = false;
        let snapshot = states.clone();
        for (idx, caller_meta) in summaries.iter().enumerate() {
            let caller = &mut states[idx];
            for callee_name in &caller_meta.callees {
                let Some(ci) = resolve_callee(&caller_meta.rel_path, callee_name) else {
                    continue;
                };
                let callee = &snapshot[ci];
                let callee_irq_saved = summaries[ci].irq_saved;
                if callee.calls_sleeping_alloc && !caller.calls_sleeping_alloc {
                    caller.calls_sleeping_alloc = true;
                    caller.sleeping_alloc_line =
                        caller.sleeping_alloc_line.or(Some(caller_meta.line));
                    changed = true;
                }
                for l in &callee.acquired_locks {
                    let callee_saved = callee
                        .lock_irq_saved
                        .get(l)
                        .copied()
                        .unwrap_or(callee_irq_saved);
                    let eff_saved = callee_saved || caller_meta.irq_saved;
                    if !caller.acquired_locks.contains(l) {
                        if caller.acquired_locks.len() < MAX_ACQUIRED_LOCKS_PER_FN {
                            caller.acquired_locks.push(l.clone());
                            caller.lock_irq_saved.insert(l.clone(), eff_saved);
                            changed = true;
                        }
                    } else if let Some(prev) = caller.lock_irq_saved.get_mut(l)
                        && *prev
                        && !eff_saved
                    {
                        *prev = false;
                        changed = true;
                    }
                }
                for pair in &callee.held_lock_pairs {
                    if caller.held_lock_pairs.len() >= MAX_LOCK_PAIRS_PER_FN {
                        break;
                    }
                    if !caller.held_lock_pairs.contains(pair) {
                        caller.held_lock_pairs.push(pair.clone());
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Track which functions are called from ISR vs non-ISR contexts so ISR-only helpers
    // (like `static void safe_rx_helper(void)` invoked solely by an ISR) are not misclassified as tasks.
    let mut called_from_isr: HashSet<usize> = HashSet::new();
    let mut called_from_non_isr: HashSet<usize> = HashSet::new();
    for s in summaries {
        for cname in &s.callees {
            if let Some(ci) = resolve_callee(&s.rel_path, cname) {
                if s.is_isr {
                    called_from_isr.insert(ci);
                } else {
                    called_from_non_isr.insert(ci);
                }
            }
        }
    }
    // Transitive ISR-only helper closure (up to MAX_HW_SUMMARY_HOPS)
    for _ in 0..MAX_HW_SUMMARY_HOPS {
        let mut added = false;
        let cur: Vec<usize> = called_from_isr.iter().copied().collect();
        for ci in cur {
            for cname in &summaries[ci].callees {
                if let Some(sub) = resolve_callee(&summaries[ci].rel_path, cname)
                    && called_from_isr.insert(sub)
                {
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }

    let mut out = Vec::new();
    let mut isr_locks: HashSet<&str> = HashSet::new();
    for (idx, s) in summaries.iter().enumerate() {
        let st = &states[idx];
        let path_low = s.rel_path.replace('\\', "/").to_ascii_lowercase();
        let is_hosted_sim_port = path_low.contains("/posix/")
            || path_low.contains("/mingw")
            || path_low.contains("/msvc");
        if s.is_isr && !is_hosted_sim_port {
            for l in &st.acquired_locks {
                isr_locks.insert(l.as_str());
            }
            if st.calls_sleeping_alloc
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-IRQ",
                    "CRITICAL",
                    SoundinessTier::Verified,
                    format!(
                        "Sleeping allocation or blocking call reachable from ISR `{}` (forbidden in atomic/interrupt context)",
                        s.fn_name
                    ),
                    &s.rel_path,
                    st.sleeping_alloc_line.unwrap_or(s.line),
                    &s.fn_name,
                    SinkKind::ConcurrencyHazard,
                    GuardKind::LockOrdering,
                    "Use `GFP_ATOMIC` / lock-free ring buffers inside ISRs and defer sleeping work to a workqueue or task thread.",
                )
            {
                out.push(hit);
            }
        }
    }
    for (idx, s) in summaries.iter().enumerate() {
        let st = &states[idx];
        let is_isr_only_helper =
            called_from_isr.contains(&idx) && !called_from_non_isr.contains(&idx);
        if !s.is_isr && !is_isr_only_helper {
            for l in &st.acquired_locks {
                let saved_for_l = st.lock_irq_saved.get(l).copied().unwrap_or(s.irq_saved);
                if !saved_for_l
                    && isr_locks.contains(l.as_str())
                    && let Some(hit) = mk_hw_finding(
                        "SMG-HW-IRQ",
                        "CRITICAL",
                        SoundinessTier::Proven,
                        format!(
                            "RTOS/IRQ Self-Deadlock: task `{}` acquires `{}` with interrupts enabled while an ISR also locks `{}`",
                            s.fn_name, l, l
                        ),
                        &s.rel_path,
                        s.line,
                        &s.fn_name,
                        SinkKind::ConcurrencyHazard,
                        GuardKind::LockOrdering,
                        "Acquire ISR-shared locks strictly via `spin_lock_irqsave` / `critical_section::with` / `disable_irq` in task context.",
                    )
                {
                    out.push(hit);
                }
            }
        }
    }

    // O(P) hash-indexed ABBA inversion check across all simultaneously held lock pairs `(l1, l2)`
    let mut pair_owner: HashMap<(&str, &str), usize> = HashMap::new();
    for (idx, st) in states.iter().enumerate() {
        for (a0, a1) in &st.held_lock_pairs {
            if a0 != a1 {
                pair_owner.entry((a0.as_str(), a1.as_str())).or_insert(idx);
            }
        }
    }
    let mut seen_abba: HashSet<(&str, &str)> = HashSet::new();
    for (i, st_i) in states.iter().enumerate() {
        for (a0, a1) in &st_i.held_lock_pairs {
            if a0 == a1 {
                continue;
            }
            let canon = if a0.as_str() < a1.as_str() {
                (a0.as_str(), a1.as_str())
            } else {
                (a1.as_str(), a0.as_str())
            };
            if let Some(&j) = pair_owner.get(&(a1.as_str(), a0.as_str()))
                && i != j
                && seen_abba.insert(canon)
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-IRQ",
                    "HIGH",
                    SoundinessTier::Verified,
                    format!(
                        "ABBA Lock Inversion across `{}` ({} -> {}) and `{}` ({} -> {})",
                        summaries[i].fn_name, a0, a1, summaries[j].fn_name, a1, a0
                    ),
                    &summaries[i].rel_path,
                    summaries[i].line,
                    &summaries[i].fn_name,
                    SinkKind::ConcurrencyHazard,
                    GuardKind::LockOrdering,
                    "Enforce a single strict global lock acquisition hierarchy across all driver tasks and ISRs.",
                )
            {
                out.push(hit);
            }
        }
    }

    out
}
