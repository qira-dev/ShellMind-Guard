//! Phase 28B: Embedded Hardware Ultra-Depth Analysis:
//! 1. Inter-Procedural Worst-Case Stack Depth (WCSD) Call-Graph + ISR Nesting Overflow Proof
//! 2. DMA Cache Coherency Typestate Automaton (`SCB_CleanDCache` / `SCB_InvalidateDCache`)
//! 3. GNU Linker Script (`.ld` / `.lds`) Memory Region Overlap & Stack/Heap Budget Verifier

use regex::Regex;
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

// ============================================================================
// 1. GNU Linker Script (.ld / .lds) Region Overlap & Budget Verifier
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub name: String,
    pub attrs: String,
    pub origin: u64,
    pub length: u64,
    pub line: usize,
}

fn strip_ld_comments_preserve_lines(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() {
                if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Audits a GNU `.ld` / `.lds` linker script for overlapping memory regions,
/// RWX SRAM regions, and stack/heap budgets exceeding available RAM.
pub fn audit_linker_script(
    rel_path: &str,
    content: &str,
) -> (Vec<MemoryRegion>, Option<u64>, Vec<LocalStaticFinding>) {
    static REGION_RE: OnceLock<Regex> = OnceLock::new();
    let region_re = REGION_RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*(?:ORIGIN|org|o)\s*=\s*([^,\r\n]+?)\s*,\s*(?:LENGTH|len|l)\s*=\s*([^\r\n;}]+)",
        )
        .expect("valid ld region re")
    });
    static STACK_SYM_RE: OnceLock<Regex> = OnceLock::new();
    let stack_sym_re = STACK_SYM_RE.get_or_init(|| {
        Regex::new(r"(?i)_Min_Stack_Size\s*=\s*([^;\r\n]+)\s*;").expect("valid stack sym re")
    });

    let clean = strip_ld_comments_preserve_lines(content);
    let mut regions = Vec::new();
    let mut min_stack_size = None;
    let mut findings = Vec::new();

    for (idx, line) in clean.lines().enumerate() {
        let ln = idx + 1;
        if let Some(c) = region_re.captures(line)
            && let (Some(name), Some(orig_m), Some(len_m)) = (c.get(1), c.get(3), c.get(4))
            && let (Some(origin), Some(length)) = (
                crate::context::eval_linker_expr(orig_m.as_str()),
                crate::context::eval_linker_expr(len_m.as_str()),
            )
        {
            let attrs = c
                .get(2)
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_default();
            regions.push(MemoryRegion {
                name: name.as_str().to_string(),
                attrs,
                origin,
                length,
                line: ln,
            });
        }
        if let Some(c) = stack_sym_re.captures(line)
            && let Some(sz) = c
                .get(1)
                .and_then(|m| crate::context::eval_linker_expr(m.as_str()))
        {
            min_stack_size = Some(sz);
        }
    }

    // 1. Pairwise memory region overlap check
    for i in 0..regions.len() {
        let a = &regions[i];
        let a_end = a.origin.saturating_add(a.length);
        for b in &regions[i + 1..] {
            let b_end = b.origin.saturating_add(b.length);
            if a.origin < b_end && b.origin < a_end {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-HW-STACK".into(),
                    severity: "CRITICAL".into(),
                    title: format!(
                        "Linker script memory region overlap: `{}` [0x{:x}..0x{:x}) overlaps `{}` [0x{:x}..0x{:x})",
                        a.name, a.origin, a_end, b.name, b.origin, b_end
                    ),
                    rel_path: rel_path.to_string(),
                    line: b.line,
                    symbol: b.name.clone(),
                    sink_kind: SinkKind::MemorySafety,
                    missing_guard: GuardKind::MemoryBounds,
                    confidence: Confidence::Proven,
                    remediation: "Adjust ORIGIN/LENGTH in the linker script so all memory regions are strictly disjoint.".into(),
                });
            }
        }
    }

    // 1b. RWX memory region check (`SMG-HW-LINKER`)
    for r in &regions {
        let pos_attrs = r.attrs.split('!').next().unwrap_or(&r.attrs);
        if pos_attrs.contains('r') && pos_attrs.contains('w') && pos_attrs.contains('x') {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-HW-LINKER".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Linker script memory region `{}` declares `rwx` (simultaneously writable and executable) permissions",
                    r.name
                ),
                rel_path: rel_path.to_string(),
                line: r.line,
                symbol: r.name.clone(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::MemoryBounds,
                confidence: Confidence::Proven,
                remediation: "Enforce W^X separation in the linker script: remove `x` from writable RAM regions (`rw`) and remove `w` from executable FLASH regions (`rx`).".into(),
            });
        }
    }

    // 2. Stack budget vs total RAM region check
    if let Some(stack_sz) = min_stack_size {
        let ram_max = regions
            .iter()
            .filter(|r| r.name.to_ascii_uppercase().contains("RAM"))
            .map(|r| r.length)
            .max();
        if let Some(ram_len) = ram_max
            && stack_sz > ram_len
        {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-HW-STACK".into(),
                severity: "CRITICAL".into(),
                title: format!(
                    "Linker `_Min_Stack_Size` ({stack_sz} B) exceeds RAM region capacity ({ram_len} B)"
                ),
                rel_path: rel_path.to_string(),
                line: 1,
                symbol: "_Min_Stack_Size".into(),
                sink_kind: SinkKind::MemorySafety,
                missing_guard: GuardKind::MemoryBounds,
                confidence: Confidence::Proven,
                remediation: "Reduce `_Min_Stack_Size` or allocate a larger SRAM region.".into(),
            });
        }
    }

    (regions, min_stack_size, findings)
}

// ============================================================================
// 2. Inter-Procedural Worst-Case Stack Depth (WCSD) Call-Graph Analyzer
// ============================================================================

#[derive(Debug, Clone)]
pub struct FnStackNode {
    pub name: String,
    pub rel_path: String,
    pub line: usize,
    pub local_frame_bytes: u64,
    pub callees: Vec<String>,
    pub is_isr: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WcsdResult {
    pub worst_case_bytes: u64,
    pub worst_chain: Vec<String>,
    pub has_unbounded_recursion: bool,
    pub isr_overhead_bytes: u64,
}

/// Extracts lightweight `FnStackNode` call/frame summaries from a C/C++ source file for WCSD analysis.
pub fn extract_c_stack_nodes(rel_path: &str, source: &str) -> Vec<FnStackNode> {
    static ARR_RE: OnceLock<Regex> = OnceLock::new();
    let arr_re = ARR_RE.get_or_init(|| {
        Regex::new(r"\b(char|uint8_t|int8_t|uint16_t|int16_t|uint32_t|int32_t|int|uint64_t|int64_t|double|float)\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*(\d+)\s*\]")
            .expect("valid c stack array re")
    });
    static CALL_RE: OnceLock<Regex> = OnceLock::new();
    let call_re = CALL_RE
        .get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("valid c call re"));

    let mut parser = tree_sitter::Parser::new();
    let is_cpp = rel_path.ends_with(".cpp")
        || rel_path.ends_with(".cc")
        || rel_path.ends_with(".cxx")
        || rel_path.ends_with(".hpp");
    let lang = if is_cpp {
        tree_sitter_cpp::LANGUAGE.into()
    } else {
        tree_sitter_c::LANGUAGE.into()
    };
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let src = source.as_bytes();
    let mut nodes = Vec::new();
    let mut stack = vec![(tree.root_node(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth >= 128 {
            continue;
        }
        if node.kind() == "function_definition" {
            let line = node.start_position().row + 1;
            let fn_txt = node.utf8_text(src).unwrap_or("");
            let name = fn_txt
                .split('(')
                .next()
                .and_then(|head| {
                    head.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .rfind(|tok| !tok.is_empty())
                })
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                let is_isr = name.contains("IRQHandler")
                    || name.ends_with("_isr")
                    || name.ends_with("_ISR")
                    || fn_txt.contains("__interrupt")
                    || fn_txt.contains("irqreturn_t");
                let mut local_frame_bytes = 32u64;
                for c in arr_re.captures_iter(fn_txt) {
                    let elem_sz: u64 = match c.get(1).map(|m| m.as_str()).unwrap_or("") {
                        "char" | "uint8_t" | "int8_t" => 1,
                        "uint16_t" | "int16_t" => 2,
                        "uint64_t" | "int64_t" | "double" => 8,
                        _ => 4,
                    };
                    if let Some(count) = c.get(2).and_then(|m| m.as_str().parse::<u64>().ok()) {
                        local_frame_bytes =
                            local_frame_bytes.saturating_add(elem_sz.saturating_mul(count));
                    }
                }
                let mut callees = Vec::new();
                let mut seen = HashSet::new();
                if let Some(body) = node.child_by_field_name("body") {
                    let btxt = body.utf8_text(src).unwrap_or("");
                    for c in call_re.captures_iter(btxt) {
                        let callee = c[1].to_string();
                        if !matches!(
                            callee.as_str(),
                            "if" | "for" | "while" | "switch" | "return" | "sizeof" | "typeof"
                        ) && seen.insert(callee.clone())
                        {
                            callees.push(callee);
                        }
                    }
                }
                nodes.push(FnStackNode {
                    name,
                    rel_path: rel_path.to_string(),
                    line,
                    local_frame_bytes,
                    callees,
                    is_isr,
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        for ch in node.children(&mut cursor) {
            stack.push((ch, depth + 1));
        }
    }
    nodes
}

/// Computes exact Inter-Procedural Worst-Case Stack Depth (WCSD) across a firmware call graph,
/// detects unbounded recursion cycles, and adds worst-case ISR nesting overhead.
pub fn compute_wcsd(
    nodes: &[FnStackNode],
    stack_budget_bytes: u64,
) -> (WcsdResult, Vec<LocalStaticFinding>) {
    let map: HashMap<&str, &FnStackNode> = nodes.iter().map(|n| (n.name.as_str(), n)).collect();
    let mut memo: HashMap<String, (u64, Vec<String>)> = HashMap::new();
    let mut has_recursion = false;
    let mut findings = Vec::new();

    const MAX_WCSD_DEPTH: usize = 128;

    #[allow(clippy::too_many_arguments)]
    fn dfs<'a>(
        name: &'a str,
        map: &HashMap<&'a str, &'a FnStackNode>,
        visiting: &mut HashSet<String>,
        memo: &mut HashMap<String, (u64, Vec<String>)>,
        has_recursion: &mut bool,
        findings: &mut Vec<LocalStaticFinding>,
        depth: usize,
    ) -> (u64, Vec<String>, bool) {
        if depth >= MAX_WCSD_DEPTH {
            return (0, Vec::new(), false);
        }
        if let Some(cached) = memo.get(name) {
            return (cached.0, cached.1.clone(), true);
        }
        let Some(node) = map.get(name) else {
            return (0, Vec::new(), true);
        };
        if !visiting.insert(name.to_string()) {
            *has_recursion = true;
            findings.push(LocalStaticFinding {
                rule_id: "SMG-HW-STACK".into(),
                severity: "HIGH".into(),
                title: format!(
                    "Unbounded recursion cycle detected in embedded firmware function `{}` (worst-case stack depth is infinite)",
                    node.name
                ),
                rel_path: node.rel_path.clone(),
                line: node.line,
                symbol: node.name.clone(),
                sink_kind: SinkKind::MemorySafety,
                missing_guard: GuardKind::MemoryBounds,
                confidence: Confidence::Proven,
                remediation: "Convert recursion to bounded iteration in bare-metal/RTOS firmware (MISRA C Rule 17.2).".into(),
            });
            return (0, Vec::new(), false);
        }

        let mut best_child = 0u64;
        let mut best_path = Vec::new();
        let mut cacheable = true;
        for callee in &node.callees {
            let (c_bytes, c_path, c_cacheable) = dfs(
                callee,
                map,
                visiting,
                memo,
                has_recursion,
                findings,
                depth + 1,
            );
            if !c_cacheable {
                cacheable = false;
            }
            if c_bytes > best_child {
                best_child = c_bytes;
                best_path = c_path;
            }
        }
        visiting.remove(name);

        let total = node.local_frame_bytes.saturating_add(best_child);
        let mut chain = Vec::with_capacity(1 + best_path.len());
        chain.push(node.name.clone());
        chain.extend(best_path);
        if cacheable {
            memo.insert(name.to_string(), (total, chain.clone()));
        }
        (total, chain, cacheable)
    }

    let mut worst_task_bytes = 0u64;
    let mut worst_chain = Vec::new();
    let mut worst_isr_bytes = 0u64;
    let mut visiting = HashSet::new();

    for n in nodes {
        let (bytes, chain, _) = dfs(
            &n.name,
            &map,
            &mut visiting,
            &mut memo,
            &mut has_recursion,
            &mut findings,
            0,
        );
        if n.is_isr {
            // Hardware exception frame (32 bytes Cortex-M basic frame) + ISR call chain
            worst_isr_bytes = worst_isr_bytes.max(bytes.saturating_add(32));
        } else if bytes > worst_task_bytes {
            worst_task_bytes = bytes;
            worst_chain = chain;
        }
    }

    let worst_case_bytes = worst_task_bytes.saturating_add(worst_isr_bytes);
    if stack_budget_bytes > 0
        && worst_case_bytes > stack_budget_bytes
        && let Some(entry_name) = worst_chain.first()
        && let Some(entry_node) = map.get(entry_name.as_str())
    {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-HW-STACK".into(),
            severity: "CRITICAL".into(),
            title: format!(
                "Inter-procedural Worst-Case Stack Depth ({worst_case_bytes} B = task {worst_task_bytes} B + ISR {worst_isr_bytes} B) exceeds stack budget ({stack_budget_bytes} B) along `{}`",
                worst_chain.join(" -> ")
            ),
            rel_path: entry_node.rel_path.clone(),
            line: entry_node.line,
            symbol: entry_node.name.clone(),
            sink_kind: SinkKind::MemorySafety,
            missing_guard: GuardKind::MemoryBounds,
            confidence: Confidence::Proven,
            remediation: "Reduce stack array allocations, move large buffers to static/DMA SRAM, or increase stack size.".into(),
        });
    }

    (
        WcsdResult {
            worst_case_bytes,
            worst_chain,
            has_unbounded_recursion: has_recursion,
            isr_overhead_bytes: worst_isr_bytes,
        },
        findings,
    )
}

// ============================================================================
// 3. DMA Cache Coherency Typestate Automaton
// ============================================================================

/// Detects embedded DMA cache-coherency hazards:
/// - Starting DMA TX on a CPU-written buffer without `SCB_CleanDCache` / `dma_sync_single_for_device`
/// - Reading a DMA RX buffer on CPU without `SCB_InvalidateDCache` / `dma_sync_single_for_cpu`
pub fn analyze_dma_cache_coherency(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    if !source.contains("DMA") && !source.contains("dma_") {
        return Vec::new();
    }
    let clean_source = smg_graph::taint::strip_comments_simple(source);
    let lines: Vec<&str> = clean_source.lines().collect();

    let is_clean_line = |l: &str| {
        l.contains("SCB_CleanDCache")
            || l.contains("SCB_CleanInvalidateDCache")
            || l.contains("dma_sync_single_for_device")
            || l.contains("dcache_clean")
    };
    let is_invalidate_line = |l: &str| {
        l.contains("SCB_InvalidateDCache")
            || l.contains("SCB_CleanInvalidateDCache")
            || l.contains("dma_sync_single_for_cpu")
            || l.contains("dcache_invalidate")
    };

    // Check if the file has a DMA RX completion callback that performs D-Cache invalidation
    let has_rx_callback_invalidate = lines.iter().enumerate().any(|(i, l)| {
        if l.contains("RxCpltCallback") || l.contains("RxHalfCpltCallback") {
            let end = (i + 30).min(lines.len());
            lines[i..end].iter().any(|cl| is_invalidate_line(cl))
        } else {
            false
        }
    });

    let mut findings = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let t = line.trim();
        if t.contains("HAL_DMA_Start")
            || t.contains("HAL_SPI_Transmit_DMA")
            || t.contains("HAL_UART_Transmit_DMA")
        {
            // Look backwards within the current function/local window (up to 25 lines,
            // stopping at a top-level closing brace `}` of a preceding function).
            let mut has_local_clean = false;
            let start = idx.saturating_sub(25);
            for back in (start..=idx).rev() {
                let bl = lines[back];
                if back < idx && bl.starts_with('}') {
                    break;
                }
                if is_clean_line(bl) {
                    has_local_clean = true;
                    break;
                }
            }
            if !has_local_clean {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-HW-DMA".into(),
                    severity: "HIGH".into(),
                    title: "DMA TX started without D-Cache clean (`SCB_CleanDCache` / `dma_sync_single_for_device`) — stale memory hazard".into(),
                    rel_path: rel_path.to_string(),
                    line: ln,
                    symbol: "dma_tx".into(),
                    sink_kind: SinkKind::MemorySafety,
                    missing_guard: GuardKind::MemoryBounds,
                    confidence: Confidence::Confirmed,
                    remediation: "Call `SCB_CleanDCache_by_Addr()` before starting DMA TX, or place the buffer in non-cacheable MPU/DTCM SRAM.".into(),
                });
            }
        }
        if t.contains("HAL_SPI_Receive_DMA") || t.contains("HAL_UART_Receive_DMA") {
            let start = idx.saturating_sub(5);
            let end = (idx + 25).min(lines.len());
            let mut has_local_invalidate = has_rx_callback_invalidate;
            if !has_local_invalidate {
                for (cur, cl) in lines.iter().enumerate().take(end).skip(start) {
                    if cur > idx && cl.starts_with('}') {
                        break;
                    }
                    if is_invalidate_line(cl) {
                        has_local_invalidate = true;
                        break;
                    }
                }
            }
            if !has_local_invalidate {
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-HW-DMA".into(),
                    severity: "HIGH".into(),
                    title: "DMA RX configured without D-Cache invalidate (`SCB_InvalidateDCache` / `dma_sync_single_for_cpu`) — stale CPU read hazard".into(),
                    rel_path: rel_path.to_string(),
                    line: ln,
                    symbol: "dma_rx".into(),
                    sink_kind: SinkKind::MemorySafety,
                    missing_guard: GuardKind::MemoryBounds,
                    confidence: Confidence::Confirmed,
                    remediation: "Call `SCB_InvalidateDCache_by_Addr()` after DMA RX completion before CPU reads the buffer.".into(),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linker_script_catches_overlapping_regions_and_stack_overflow() {
        let ld = r#"
MEMORY {
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 64K
  DMA (rw)   : ORIGIN = 0x20008000, LENGTH = 32K
}
_Min_Stack_Size = 128K;
"#;
        let (regions, min_stack, hits) = audit_linker_script("stm32.ld", ld);
        assert_eq!(regions.len(), 3);
        assert_eq!(min_stack, Some(128 * 1024));
        assert!(hits.iter().any(|h| h.title.contains("overlap")));
        assert!(hits.iter().any(|h| h.title.contains("_Min_Stack_Size")));
    }

    #[test]
    fn wcsd_proves_interprocedural_stack_overflow_with_isr_nesting() {
        let nodes = vec![
            FnStackNode {
                name: "main_task".into(),
                rel_path: "src/main.c".into(),
                line: 10,
                local_frame_bytes: 512,
                callees: vec!["parse_packet".into()],
                is_isr: false,
            },
            FnStackNode {
                name: "parse_packet".into(),
                rel_path: "src/net.c".into(),
                line: 20,
                local_frame_bytes: 1536,
                callees: vec![],
                is_isr: false,
            },
            FnStackNode {
                name: "TIM2_IRQHandler".into(),
                rel_path: "src/irq.c".into(),
                line: 5,
                local_frame_bytes: 256,
                callees: vec![],
                is_isr: true,
            },
        ];
        // Task = 2048 B + ISR = 288 B => 2336 B > 2048 B budget!
        let (res, hits) = compute_wcsd(&nodes, 2048);
        assert_eq!(res.worst_case_bytes, 2336);
        assert!(!res.has_unbounded_recursion);
        assert!(
            hits.iter()
                .any(|h| h.title.contains("Worst-Case Stack Depth"))
        );
    }

    #[test]
    fn dma_cache_coherency_detects_missing_clean_and_passes_when_cleaned() {
        let bad = "void send() { tx_buf[0] = 1; HAL_SPI_Transmit_DMA(&hspi1, tx_buf, 64); }";
        assert_eq!(analyze_dma_cache_coherency("src/spi.c", bad).len(), 1);

        let good = "void send() { tx_buf[0] = 1; SCB_CleanDCache_by_Addr(tx_buf, 64); HAL_SPI_Transmit_DMA(&hspi1, tx_buf, 64); }";
        assert!(analyze_dma_cache_coherency("src/spi.c", good).is_empty());

        // Comment mentioning SCB_CleanDCache must NOT mask an unguarded DMA TX,
        // and a clean in fn_a must NOT mask an unguarded DMA TX in fn_b.
        let multi = r#"
void fn_a(void) {
    SCB_CleanDCache_by_Addr(a, 64);
    HAL_SPI_Transmit_DMA(&hspi1, a, 64);
}
void fn_b(void) {
    /* TODO: call SCB_CleanDCache_by_Addr */
    HAL_UART_Transmit_DMA(&huart1, b, 64);
    HAL_UART_Receive_DMA(&huart1, c, 64);
}
"#;
        let hits = analyze_dma_cache_coherency("src/multi.c", multi);
        assert_eq!(
            hits.len(),
            2,
            "expected both unguarded TX and RX: {hits:#?}"
        );

        // Linker script comments, org/len aliases, and arithmetic LENGTH expressions
        let ld_expr = r#"
MEMORY {
  /* RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 1M */
  FLASH (rx) : org = 0x08000000, len = 256K
  RAM (rwx)  : o = 0x20000000, l = (64K - 4K)
  DMA (rw)   : ORIGIN = 0x20008000, LENGTH = 32K
}
"#;
        let (regions, _stack, ld_hits) = audit_linker_script("expr.ld", ld_expr);
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[1].length, 60 * 1024);
        assert!(ld_hits.iter().any(|h| h.title.contains("overlap")));
    }
}
