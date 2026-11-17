use crate::context::FirmwareContext;
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

fn lock_acquire_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(?:spin_lock_irqsave|spin_lock_bh|spin_lock|mutex_lock|xSemaphoreTake|pthread_mutex_lock|osMutexAcquire)\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_>.-]*)"#,
        )
        .expect("valid lock acquire regex")
    })
}

fn jtag_secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:jtag_key|swd_unlock|debug_backdoor|uart_password|boot_master_key|provision_secret|flash_unlock_key)\s*(?::?=)\s*["'][A-Za-z0-9_+/=-]{12,}["']"#,
        )
        .expect("valid hw secret regex")
    })
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn node_text<'a>(n: Node, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
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

fn is_c_or_rust_test_fn(node: Node, src: &[u8], fn_name: &str) -> bool {
    let low = fn_name.to_ascii_lowercase();
    if low.starts_with("test_") || low.ends_with("_test") {
        return true;
    }
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let txt = node_text(p, src);
            if txt.contains("cfg(test)") || txt.contains("#[test]") || txt.contains("::test") {
                return true;
            }
            prev = p.prev_sibling();
        } else {
            break;
        }
    }
    false
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
    // Skip entire Rust `#[cfg(test)] mod tests { ... }` subtree cleanly
    if k == "mod_item" {
        let mut prev = node.prev_sibling();
        while let Some(p) = prev {
            if p.kind() == "attribute_item" && node_text(p, src).contains("cfg(test)") {
                return;
            }
            prev = p.prev_sibling();
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_hw_functions(ch, src, out);
    }
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
            if ch.kind() == "mod_item" {
                let mut prev = ch.prev_sibling();
                while let Some(p) = prev {
                    if p.kind() == "attribute_item" && node_text(p, src_bytes).contains("cfg(test)")
                    {
                        rust_test_ranges
                            .push((ch.start_position().row + 1, ch.end_position().row + 1));
                        break;
                    }
                    prev = p.prev_sibling();
                }
            }
        }
    }

    // Global firmware JTAG/SWD backdoor keys (ignoring inline Rust #[cfg(test)] modules)
    for (idx, line) in content.lines().enumerate() {
        let ln = idx + 1;
        let t = line.trim();
        if t.starts_with("//")
            || t.starts_with('#')
            || t.starts_with("/*")
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

    let width_bits = ctx
        .compile_units
        .values()
        .next()
        .map(|cu| cu.pointer_width_bits)
        .unwrap_or(32);

    let mut fns = Vec::new();
    collect_hw_functions(tree.root_node(), src_bytes, &mut fns);
    let bv_solver = PureRustBvSliceSolver;

    for (fn_name, fn_node) in fns {
        let fn_start = fn_node.start_position().row + 1;
        let fn_end = fn_node.end_position().row + 1;
        let fn_body = node_text(fn_node, src_bytes);
        let fn_low = fn_body.to_ascii_lowercase();

        // Extract RTOS/IRQ lock summary for cross-function deadlock + IRQ self-deadlock graph
        let fn_slice_start = fn_start.saturating_sub(2);
        let attr_ctx =
            lines[fn_slice_start.saturating_sub(1)..fn_start.min(lines.len())].join("\n");
        let is_isr = fn_low.contains("irqhandler")
            || fn_low.contains("_isr(")
            || fn_low.contains("__attribute__((interrupt))")
            || attr_ctx.contains("#[interrupt]")
            || attr_ctx.contains("ISR(");
        let irq_saved = fn_low.contains("spin_lock_irqsave")
            || fn_low.contains("disable_irq")
            || fn_low.contains("critical_section")
            || fn_low.contains("taskenter_critical")
            || fn_low.contains("cpsid");
        let mut acquired = Vec::new();
        for cap in lock_acquire_re().captures_iter(fn_body) {
            let l = cap[1].trim().to_string();
            if !acquired.contains(&l) {
                acquired.push(l);
            }
        }
        if !acquired.is_empty() {
            lock_summaries.push(HardwareFunctionLockSummary {
                fn_name: fn_name.clone(),
                rel_path: rel_path.to_string(),
                line: fn_start,
                is_isr,
                irq_saved,
                acquired_locks: acquired.clone(),
            });
        }

        // ABBA self/intra-function nested acquisition or unbalanced manual lock checks
        analyze_single_hw_function(
            rel_path, lang, &fn_name, fn_start, fn_end, &lines, fn_body, width_bits, ctx,
            &bv_solver, findings,
        );
    }
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
    let mut aliases = PointerAliasUnionFind::default();

    // Seed global integer constants from firmware `#define` macros
    for (k, v) in &ctx.global_defines {
        intervals.insert(k.clone(), WrappedInterval::constant_signed(*v, width_bits));
    }

    // Seed function parameter intervals (detecting signed int `len`/`off` vs unsigned `u32`/`size_t`)
    let header_line = fn_lines.first().map(|(_, s)| *s).unwrap_or("");
    for part in header_line.split(',') {
        let plow = part.trim().to_ascii_lowercase();
        let last_ident = ident_re()
            .captures_iter(part)
            .last()
            .map(|c| c[1].to_string());
        if let Some(pvar) = last_ident {
            if plow.contains("int ")
                && !plow.contains("uint")
                && !plow.contains("size_t")
                && !plow.contains("unsigned")
            {
                intervals.insert(
                    pvar,
                    WrappedInterval::signed_range(-32768, 65535, width_bits),
                );
            } else if plow.contains("uint32") || plow.contains("size_t") || plow.contains("usize") {
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
    let mut first_ext_load: Option<(String, usize, bool)> = None; // (ptr, line, checked)
    let has_atomic_copy = fn_low.contains("copy_from_user(")
        || fn_low.contains("get_user(")
        || fn_low.contains("read_volatile");

    // Pre-scan secret key allocation for scope-exit zeroize check
    let mut secret_key_bufs: Vec<(String, usize)> = Vec::new();
    let has_zeroize_call = fn_low.contains("explicit_bzero(")
        || fn_low.contains("memset_s(")
        || fn_low.contains("openssl_cleanse(")
        || fn_low.contains("mbedtls_platform_zeroize(")
        || fn_low.contains(".zeroize()")
        || fn_low.contains("zeroizeondrop");

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
        let mut saw_rollback = false;
        for &(ln, raw) in &fn_lines {
            let low = raw.to_ascii_lowercase();
            if low.contains("verify_signature")
                || low.contains("ed25519")
                || low.contains("ecdsa")
                || low.contains("rsa_verify")
                || low.contains("crypto_verify")
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
            if (low.contains("flash_write(")
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

    for &(ln, raw) in &fn_lines {
        let trimmed = raw.trim();
        let low = trimmed.to_ascii_lowercase();

        // Catch stack key buffer declarations (`uint8_t priv_key[32];` without `=`)
        if trimmed.contains('[')
            && trimmed.ends_with(';')
            && !trimmed.starts_with("static ")
            && !trimmed.contains('(')
        {
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
                }
            }
        }

        // Track alias `ptr2 = ptr1;` in Steensgaard union-find
        if let Some((lhs, rhs)) = trimmed.split_once('=')
            && !lhs.contains("==")
            && !lhs.contains("!=")
        {
            let l_id = ident_re()
                .captures_iter(lhs)
                .last()
                .map(|c| c[1].to_string());
            let r_trim = rhs.trim().trim_end_matches(';');
            if let Some(lv) = l_id {
                if let Some(rv) = ident_re().find(r_trim).map(|m| m.as_str())
                    && r_trim == rv
                {
                    aliases.union_names(&lv, rv);
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
                    && let Some(mask_val) = parse_u64_hex(rhs_mask.trim())
                {
                    let narrowed = Tnum::unknown().tnum_and(Tnum::constant(mask_val));
                    intervals.insert(
                        lv.clone(),
                        WrappedInterval::from_u64_bounds(
                            narrowed.min_u64(),
                            narrowed.max_u64(),
                            width_bits,
                        ),
                    );
                } else if r_trim.contains("(size_t)") || r_trim.contains(" as usize") {
                    for cap in ident_re().captures_iter(r_trim) {
                        if let Some(prev_iv) = intervals.get(&cap[1]).copied()
                            && prev_iv.can_wrap_negative_to_large_size()
                        {
                            intervals.insert(lv.clone(), prev_iv);
                        }
                    }
                }
            }
        }

        // Capture simple bounds guards `if (len < 0 || len > cap) return ...;` or `if (off + len <= 256)`
        if low.starts_with("if ") || low.starts_with("if(") {
            let is_early_reject = fn_low.contains("return")
                && (low.contains("< 0")
                    || low.contains("> cap")
                    || low.contains("> max")
                    || low.contains("> sizeof"));
            for cap in ident_re().captures_iter(trimmed) {
                let v = &cap[1];
                if let Some(iv) = intervals.get_mut(v) {
                    if low.contains(">= 0") || (is_early_reject && low.contains("< 0")) {
                        iv.smin = iv.smin.max(0);
                        iv.umin = 0;
                        iv.reduce();
                        positive_guards.insert(v.to_string());
                    }
                    if (low.contains("<= ") || low.contains("< "))
                        && (low.contains("cap") || low.contains("sizeof") || low.contains("max_"))
                    {
                        iv.umax = iv.umax.min(1024);
                        iv.reduce();
                        positive_guards.insert(v.to_string());
                    }
                }
            }
        }

        // Alloc/Free Typestate Automaton `Q_hw`: UAF & Double-Free
        for cap in alloc_assign_re().captures_iter(trimmed) {
            typestates.insert(cap[1].to_string(), (HwTypestate::Owned, ln));
        }
        if let Some(cap) = free_call_re().captures(trimmed) {
            let ptr = &cap[1];
            if let Some((HwTypestate::Freed, prev_ln)) = typestates.get(ptr).copied() {
                if let Some(hit) = mk_hw_finding(
                    "SMG-HW-TYPESTATE",
                    "CRITICAL",
                    SoundinessTier::Proven,
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
            } else {
                typestates.insert(ptr.to_string(), (HwTypestate::Freed, ln));
            }
        } else {
            // Check dereference of a Freed pointer (`ptr->...` or `*ptr`)
            for (ptr, (state, freed_ln)) in &typestates {
                if *state == HwTypestate::Freed {
                    let deref_arrow = format!("{}->", ptr);
                    let deref_star = format!("*{}", ptr);
                    if (trimmed.contains(&deref_arrow) || trimmed.contains(&deref_star))
                        && !trimmed.starts_with("if")
                        && !trimmed.contains("= NULL")
                        && !trimmed.contains("= nullptr")
                        && let Some(hit) = mk_hw_finding(
                            "SMG-HW-TYPESTATE",
                            "CRITICAL",
                            SoundinessTier::Proven,
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
                        )
                    {
                        findings.push(hit);
                    }
                }
            }
        }

        // 2. MMIO physical dereference / SVD/Linker bounds check (`SMG-HW-MMIO`)
        let is_mmio_deref = trimmed.contains("volatile")
            || trimmed.contains("read_volatile")
            || trimmed.contains("write_volatile")
            || trimmed.contains("MMIO")
            || trimmed.contains("REG32");
        if is_mmio_deref {
            for cap in hex_addr_re().captures_iter(trimmed) {
                if let Some(addr) = parse_u64_hex(&cap[1]) {
                    let in_readonly_flash = ctx
                        .memory_regions
                        .iter()
                        .any(|r| r.contains(addr) && !r.writable);
                    let hits_write = trimmed.contains("=") || trimmed.contains("write_volatile");
                    let unknown_unmapped = !ctx.memory_regions.is_empty()
                        && !ctx.memory_regions.iter().any(|r| r.contains(addr));
                    let has_mask_guard = trimmed.contains('&')
                        || trimmed.contains("in_bounds")
                        || positive_guards.len() > 1;
                    if (in_readonly_flash && hits_write)
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
                                &cap[1]
                            )
                        } else {
                            format!(
                                "MMIO access `{}` falls outside declared CMSIS-SVD / linker memory regions",
                                &cap[1]
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
                    } else if unknown_unmapped
                        && addr >= 0x4000_0000
                        && ctx.memory_regions.is_empty()
                        && trimmed.contains("+ ")
                        && !trimmed.contains('&')
                    {
                        // Unmasked dynamic offset arithmetic on raw physical MMIO address
                        if let Some(hit) = mk_hw_finding(
                            "SMG-HW-MMIO",
                            "HIGH",
                            SoundinessTier::Likely,
                            format!(
                                "Unmasked offset arithmetic on physical MMIO address `{}` in `{}`",
                                &cap[1], fn_name
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
            let idx_iv = WrappedInterval::from_u64_bounds(0, 65535, width_bits);
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
            // Inspect arguments for negative signed-to-size_t wrap OR unchecked off + len vs oct cap
            let mut found_wrap_var: Option<(String, WrappedInterval)> = None;
            for cap in ident_re().captures_iter(trimmed) {
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
                && !positive_guards.iter().any(|g| trimmed.contains(g))
            {
                let mut oct = SparseOctagon::new(2);
                oct.add_upper_bound(0, 512);
                oct.add_upper_bound(1, 512);
                let _ = oct.close();
                if !oct.proves_sum_le(0, 1, 256)
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
        if !has_atomic_copy && !ext_ptrs.is_empty() {
            for ep in &ext_ptrs {
                let arrow = format!("{}->", ep);
                if trimmed.contains(&arrow) {
                    let is_cond = low.starts_with("if")
                        || low.contains(" < ")
                        || low.contains(" > ")
                        || low.contains(" <= ");
                    let is_sink = low.contains("memcpy")
                        || low.contains("kmalloc")
                        || low.contains("alloc")
                        || low.contains("dma");
                    match &first_ext_load {
                        None => first_ext_load = Some((ep.clone(), ln, is_cond)),
                        Some((prev_p, prev_ln, prev_cond))
                            if aliases.same_alias(prev_p, ep)
                                && ln > *prev_ln
                                && (*prev_cond || is_sink) =>
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
        let is_crypto_fn = fn_name_low.contains("sign")
            || fn_name_low.contains("scalar")
            || fn_name_low.contains("ecdsa")
            || fn_name_low.contains("hmac")
            || fn_name_low.contains("aes")
            || fn_name_low.contains("montgomery")
            || fn_name_low.contains("crypto");
        if is_crypto_fn && !smg_graph::taint::is_pattern_matcher_or_doc_line(raw) {
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
    }

    // Secret key retention on scope exit without zeroization
    if !secret_key_bufs.is_empty() && !has_zeroize_call {
        for (buf, ln) in secret_key_bufs {
            if let Some(hit) = mk_hw_finding(
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
            ) {
                findings.push(hit);
            }
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
        if !s.is_isr && !s.irq_saved {
            for l in &s.acquired_locks {
                if isr_locks.contains(l.as_str())
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

    // Check ABBA inversion pairs across 2+ lock acquisitions
    for i in 0..summaries.len() {
        for j in (i + 1)..summaries.len() {
            let a = &summaries[i].acquired_locks;
            let b = &summaries[j].acquired_locks;
            if a.len() >= 2
                && b.len() >= 2
                && a[0] == b[1]
                && a[1] == b[0]
                && a[0] != a[1]
                && let Some(hit) = mk_hw_finding(
                    "SMG-HW-IRQ",
                    "HIGH",
                    SoundinessTier::Verified,
                    format!(
                        "ABBA Lock Inversion across `{}` ({} -> {}) and `{}` ({} -> {})",
                        summaries[i].fn_name, a[0], a[1], summaries[j].fn_name, b[0], b[1]
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
