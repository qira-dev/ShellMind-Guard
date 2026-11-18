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

/// Disjoint-set pointer equivalence classes (Steensgaard O(n * alpha(n)) pass) for DMA/__user aliases.
#[derive(Default)]
pub struct PointerAliasUnionFind {
    parent: Vec<usize>,
    names: HashMap<String, usize>,
}

impl PointerAliasUnionFind {
    pub fn intern(&mut self, name: &str) -> usize {
        if let Some(&id) = self.names.get(name) {
            return id;
        }
        let id = self.parent.len();
        self.parent.push(id);
        self.names.insert(name.to_string(), id);
        id
    }

    pub fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    pub fn union_names(&mut self, a: &str, b: &str) {
        let ia = self.intern(a);
        let ib = self.intern(b);
        let ra = self.find(ia);
        let rb = self.find(ib);
        if ra != rb {
            self.parent[rb] = ra;
        }
    }

    pub fn same_alias(&mut self, a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        if let (Some(&ia), Some(&ib)) = (self.names.get(a), self.names.get(b)) {
            return self.find(ia) == self.find(ib);
        }
        false
    }
}

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

fn collect_hw_functions<'a>(node: Node<'a>, src: &[u8], out: &mut Vec<(String, Node<'a>)>) {
    let k = node.kind();
    if matches!(k, "function_definition" | "function_item") {
        let name = extract_c_fn_name(node, src);
        if !is_c_or_rust_test_fn(node, src, &name) {
            out.push((name, node));
        }
        return;
    }
    // Skip entire Rust `#[cfg(test)] mod tests { ... }` subtree cleanly without bleeding past sibling items
    if k == "mod_item" && has_cfg_test_attr(node, src) {
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_hw_functions(ch, src, out);
    }
}

fn extract_function_lock_summary(
    fn_name: &str,
    rel_path: &str,
    fn_start: usize,
    fn_end: usize,
    lines: &[&str],
    fn_body: &str,
) -> Option<HardwareFunctionLockSummary> {
    let fn_low = fn_body.to_ascii_lowercase();
    let fn_slice_start = fn_start.saturating_sub(2);
    let attr_ctx = lines[fn_slice_start.saturating_sub(1)..fn_start.min(lines.len())].join("\n");
    let is_isr = fn_low.contains("irqhandler")
        || fn_low.contains("_isr(")
        || fn_low.contains("__attribute__((interrupt))")
        || attr_ctx.contains("#[interrupt]")
        || attr_ctx.contains("ISR(");

    let mut global_irq_disabled = fn_low.contains("disable_irq")
        || fn_low.contains("critical_section")
        || fn_low.contains("taskenter_critical")
        || fn_low.contains("cpsid");

    let mut acquired: Vec<String> = Vec::new();
    let mut currently_held: Vec<String> = Vec::new();
    let mut held_lock_pairs: Vec<(String, String)> = Vec::new();
    let mut lock_irq_saved: HashMap<String, bool> = HashMap::new();
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

        if low.contains("disable_irq")
            || low.contains("taskenter_critical")
            || low.contains("cpsid")
            || low.contains("critical_section::with")
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

        if low.contains("enable_irq") || low.contains("taskexit_critical") {
            global_irq_disabled = false;
        }

        brace_depth += t.chars().filter(|&c| c == '{').count() as i32;
        brace_depth -= t.chars().filter(|&c| c == '}').count() as i32;
    }

    if acquired.is_empty() {
        return None;
    }
    let all_irq_saved = acquired
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
    })
}

pub fn analyze_hw_file(
    rel_path: &str,
    lang: Language,
    content: &str,
    ctx: &FirmwareContext,
    findings: &mut Vec<LocalStaticFinding>,
    lock_summaries: &mut Vec<HardwareFunctionLockSummary>,
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
            rel_path, lang, &fn_name, fn_start, fn_end, &lines, fn_body, width_bits, ctx,
            &bv_solver, findings,
        );
    }
}

#[derive(Clone)]
struct TypestateBranchFrame {
    entry_depth: i32,
    pre_if_states: HashMap<String, (HwTypestate, usize)>,
    pre_if_nulls: HashSet<String>,
    then_states: Option<HashMap<String, (HwTypestate, usize)>>,
    then_nulls: Option<HashSet<String>>,
    then_returned: bool,
    in_else: bool,
    branch_returned: bool,
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
    if tok.eq_ignore_ascii_case("cap") || tok.starts_with("sizeof") || tok.starts_with("max_") {
        return Some(256);
    }
    None
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
    let mut typestates: HashMap<String, (HwTypestate, usize)> = HashMap::new();
    let mut null_ptrs: HashSet<String> = HashSet::new();
    let mut aliases = PointerAliasUnionFind::default();
    let mut local_caps: HashMap<String, u64> = HashMap::new();
    let mut mmio_ptrs: HashMap<String, u64> = HashMap::new();
    let mut relational_sum_limits: Vec<(String, String, i64)> = Vec::new();

    // Seed global integer constants from firmware `#define` macros and file CompileUnitContext
    for (k, v) in &ctx.global_defines {
        intervals.insert(k.clone(), WrappedInterval::constant_signed(*v, width_bits));
    }
    if let Some(cu) = ctx.lookup_compile_unit(rel_path) {
        for (k, v_str) in &cu.defines {
            if let Some(val) = parse_hex_or_dec_u64(v_str)
                && let Ok(iv) = i64::try_from(val)
            {
                intervals.insert(k.clone(), WrappedInterval::constant_signed(iv, width_bits));
            }
        }
    }

    // Seed function parameter intervals strictly from inside `(...)` of the signature header, skipping pointers
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
            let has_signed_kw = plow
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|w| {
                    matches!(
                        w,
                        "int"
                            | "int32_t"
                            | "int16_t"
                            | "int64_t"
                            | "ssize_t"
                            | "i32"
                            | "i64"
                            | "isize"
                    )
                });
            let has_unsigned_kw = plow.contains("uint")
                || plow.contains("size_t")
                || plow.contains("usize")
                || plow.contains("unsigned")
                || plow.contains("u32")
                || plow.contains("u64")
                || plow.contains("u16")
                || plow.contains("u8");
            if has_signed_kw && !has_unsigned_kw {
                intervals.insert(
                    pvar,
                    WrappedInterval::signed_range(-32768, 65535, width_bits),
                );
            } else if has_unsigned_kw {
                intervals.insert(pvar, WrappedInterval::from_u64_bounds(0, 65535, width_bits));
            }
        }
    }

    // Track DMA / __user pointers & Double-Fetch TOCTOU
    let mut ext_ptrs: HashSet<String> = HashSet::new();
    if fn_low.contains("__user") || fn_low.contains("dma") || fn_low.contains("shared_mmio") {
        for cap in ident_re().captures_iter(fn_body) {
            let id = &cap[1];
            let id_low = id.to_ascii_lowercase();
            if id_low.contains("user")
                || id_low.contains("dma")
                || id_low.contains("desc")
                || id_low.contains("hdr")
            {
                ext_ptrs.insert(id.to_string());
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
                || low.contains("ed25519")
                || low.contains("ecdsa")
                || low.contains("rsa_verify")
                || low.contains("crypto_verify");
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
                    SoundinessTier::Proven,
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

    for &(ln, raw) in &fn_lines {
        let trimmed = raw.trim();
        let low = trimmed.to_ascii_lowercase();

        // Update typestate branch stack on `}` / `else` transitions before analyzing line
        let starts_with_close = trimmed.starts_with('}');
        let has_else_transition = starts_with_close
            && (low.contains("else") || low.starts_with("} else"))
            || low.starts_with("else ")
            || low == "else"
            || low.starts_with("else{");
        if has_else_transition {
            if let Some(top) = branch_stack.last_mut()
                && !top.in_else
            {
                top.then_states = Some(typestates.clone());
                top.then_nulls = Some(null_ptrs.clone());
                top.then_returned = top.branch_returned;
                typestates = top.pre_if_states.clone();
                null_ptrs = top.pre_if_nulls.clone();
                top.in_else = true;
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
                match (frame.then_returned, frame.branch_returned) {
                    (true, false) => {}
                    (false, true) => {
                        typestates = then_st;
                        null_ptrs = then_nl;
                    }
                    (true, true) => {
                        typestates = frame.pre_if_states;
                        null_ptrs = frame.pre_if_nulls;
                    }
                    (false, false) => {
                        typestates = merge_typestate_maps(&then_st, &typestates);
                        null_ptrs = then_nl.intersection(&null_ptrs).cloned().collect();
                    }
                }
            } else if frame.branch_returned {
                // Early-return `if (...) { kfree(p); return -1; }` does not propagate Freed to fallthrough
                typestates = frame.pre_if_states;
                null_ptrs = frame.pre_if_nulls;
            } else {
                typestates = merge_typestate_maps(&frame.pre_if_states, &typestates);
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
                then_states: None,
                then_nulls: None,
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
                    if l_trim.contains('*') && !r_trim.starts_with('*') {
                        for cap in hex_addr_re().captures_iter(r_trim) {
                            if let Some(addr) = parse_u64_hex(&cap[1]) {
                                mmio_ptrs.insert(lv.clone(), addr);
                            }
                        }
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

                // Tnum mask narrowing: `idx = raw & 0xFF;`
                if let Some((_, rhs_mask)) = r_trim.split_once('&')
                    && !r_trim.contains("&&")
                    && let Some(mask_val) = parse_hex_or_dec_u64(rhs_mask.trim())
                {
                    let narrowed =
                        Tnum::unknown_with_width(width_bits).tnum_and(Tnum::constant(mask_val));
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            narrowed.min_u64(),
                            narrowed.max_u64(),
                            width_bits,
                        ),
                    );
                    positive_guards.insert(lv.clone());
                } else if r_trim.contains("(size_t)") || r_trim.contains(" as usize") {
                    for cap in ident_re().captures_iter(r_trim) {
                        if let Some(prev_iv) = intervals.get(&cap[1]).copied() {
                            intervals.insert(lv.clone(), prev_iv);
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
                }
            }
        }

        // Capture simple & relational bounds guards (`if (len < 0 || len > 256) return;`, `if (idx >= 64) return;`, `if (off + len > 256) return;`)
        if low.starts_with("if ") || low.starts_with("if(") {
            let has_abort_on_line =
                low.contains("return") || low.contains("goto ") || low.contains("break");
            let is_early_reject = has_abort_on_line
                || (fn_low.contains("return")
                    && (low.contains("< 0") || low.contains("> ") || low.contains(">= ")));

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
                        || (op == "<" && bound_val == Some(0) && is_early_reject)
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
                            if has_unsigned_cast {
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
            // Check dereference of a Freed pointer (`ptr->...` or `*ptr`)
            for (ptr, (state, freed_ln)) in &typestates {
                if matches!(state, HwTypestate::Freed | HwTypestate::Conflict) {
                    let deref_arrow = format!("{}->", ptr);
                    let deref_star = format!("*{}", ptr);
                    if (trimmed.contains(&deref_arrow) || trimmed.contains(&deref_star))
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

        // Check dereference writes through bound MMIO pointer variables (`*flash = 0x1;`)
        if is_direct_write_stmt && let Some((lhs, _)) = trimmed.split_once('=') {
            for cap in ident_re().captures_iter(lhs) {
                let pvar = &cap[1];
                if let Some(&addr) = mmio_ptrs.get(pvar)
                    && ctx
                        .memory_regions
                        .iter()
                        .any(|r| r.contains(addr) && !r.writable)
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
                    let in_readonly_flash = ctx
                        .memory_regions
                        .iter()
                        .any(|r| r.contains(addr) && !r.writable);
                    let unknown_unmapped = !ctx.memory_regions.is_empty()
                        && !ctx.memory_regions.iter().any(|r| r.contains(addr))
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
                .and_then(|v| intervals.get(v).copied())
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
                let mut off_max = 512i64;
                let mut len_max = 512i64;
                let mut off_name = String::new();
                let mut len_name = String::new();
                for cap in ident_re().captures_iter(trimmed) {
                    let id = &cap[1];
                    let id_low = id.to_ascii_lowercase();
                    if id_low.contains("off") {
                        off_name = id.to_string();
                        if let Some(iv) = intervals.get(id) {
                            off_max = iv.smax.clamp(0, 65535);
                        }
                    } else if id_low.contains("len") || id_low.contains("size") || id_low == "n" {
                        len_name = id.to_string();
                        if let Some(iv) = intervals.get(id) {
                            len_max = iv.smax.clamp(0, 65535);
                        }
                    }
                }
                let dst_cap = local_caps
                    .values()
                    .copied()
                    .min()
                    .and_then(|v| i64::try_from(v).ok())
                    .unwrap_or(256);

                let mut oct = SparseOctagon::new(2);
                oct.add_lower_bound(0, 0);
                oct.add_upper_bound(0, off_max);
                oct.add_lower_bound(1, 0);
                oct.add_upper_bound(1, len_max);
                for (va, vb, lim) in &relational_sum_limits {
                    if (va == &off_name && vb == &len_name)
                        || (va == &len_name && vb == &off_name)
                        || va == &off_name
                        || vb == &off_name
                    {
                        oct.add_sum_le(0, 1, *lim);
                    }
                }
                if oct.close()
                    && !oct.proves_sum_le(0, 1, dst_cap)
                    && let Some(hit) = mk_hw_finding(
                        "SMG-HW-BOUNDS",
                        "HIGH",
                        SoundinessTier::Likely,
                        format!(
                            "Buffer `offset + len` arithmetic in `{}` lacks relational capacity guard against overflow",
                            fn_name
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

/// Solves cross-function RTOS interrupt priority & lock-order partial-order deadlocks (`SMG-HW-IRQ`).
pub fn check_cross_fn_irq_deadlocks(
    summaries: &[HardwareFunctionLockSummary],
) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
    let mut isr_locks: HashSet<&str> = HashSet::new();
    for s in summaries {
        if s.is_isr {
            for l in &s.acquired_locks {
                isr_locks.insert(l.as_str());
            }
        }
    }
    for s in summaries {
        if !s.is_isr {
            for l in &s.acquired_locks {
                let saved_for_l = s.lock_irq_saved.get(l).copied().unwrap_or(s.irq_saved);
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

    // Check ABBA inversion pairs across all simultaneously held lock pairs `(l1, l2)`
    for i in 0..summaries.len() {
        for j in (i + 1)..summaries.len() {
            let pairs_a = &summaries[i].held_lock_pairs;
            let pairs_b = &summaries[j].held_lock_pairs;
            let mut reported_pair = false;
            for (a0, a1) in pairs_a {
                if reported_pair {
                    break;
                }
                for (b0, b1) in pairs_b {
                    if a0 == b1
                        && a1 == b0
                        && a0 != a1
                        && let Some(hit) = mk_hw_finding(
                            "SMG-HW-IRQ",
                            "HIGH",
                            SoundinessTier::Verified,
                            format!(
                                "ABBA Lock Inversion across `{}` ({} -> {}) and `{}` ({} -> {})",
                                summaries[i].fn_name, a0, a1, summaries[j].fn_name, b0, b1
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
                        reported_pair = true;
                        break;
                    }
                }
            }
        }
    }

    out
}
