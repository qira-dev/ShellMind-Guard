pub mod context;
pub mod domains;
pub mod typestate_irq;
pub mod wcsd_dma;

pub use wcsd_dma::{
    FnStackNode, MemoryRegion, WcsdResult, analyze_dma_cache_coherency, audit_linker_script,
    compute_wcsd,
};

use context::{collect_hw_spec_files, ingest_firmware_context};
use smg_core::{IndexedFile, Language};
use smg_graph::LocalStaticFinding;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use typestate_irq::{HardwareFunctionLockSummary, analyze_hw_file, check_cross_fn_irq_deadlocks};

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Returns `true` only when a repository actually contains C/C++/Rust firmware/driver indicators,
/// `.svd`/`.ld` linker/register specs, or `compile_commands.json` — guaranteeing 0ms overhead on pure Web/SaaS repos.
pub fn repo_has_hw_indicators(project_root: &Path, files: &[IndexedFile]) -> bool {
    if project_root.join("compile_commands.json").exists()
        || project_root.join("build/compile_commands.json").exists()
    {
        return true;
    }

    let mut has_c_cpp = false;
    let mut has_rust = false;
    for f in files {
        let low_path = f.rel_path.to_ascii_lowercase();
        if low_path.ends_with(".ld") || low_path.ends_with(".lds") || low_path.ends_with(".svd") {
            return true;
        }
        match f.language {
            Language::C | Language::Cpp => has_c_cpp = true,
            Language::Rust => has_rust = true,
            _ => {}
        }
    }
    if !has_c_cpp && !has_rust {
        return !collect_hw_spec_files(project_root, 4, 1).is_empty();
    }

    // Lightweight indicator scan on C/C++/Rust files (comment-stripped) before spinning deeper domains.
    // Whole-identifier tokens require word boundaries so userspace POSIX structs like
    // `struct __user_cap_data_struct` (nginx/Linux capabilities) do not trigger firmware mode.
    const HW_EXACT_TOKENS: &[&str] = &[
        "__iomem",
        "ioremap",
        "SCB_CleanDCache",
        "__user",
        "copy_from_user",
        "spin_lock_irqsave",
        "irqreturn_t",
        "request_irq",
        "request_threaded_irq",
        "read_volatile",
        "write_volatile",
        "mmio",
        "flash_write",
        "ota_apply",
        "boot_jump",
        "pvPortMalloc",
        "jtag_key",
    ];
    const HW_SUBSTR_TOKENS: &[&str] = &["HAL_DMA_", "NVIC_", "#[interrupt]", "IRQHandler"];

    fn is_ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    fn contains_exact_ident(haystack: &str, needle: &str) -> bool {
        let bytes = haystack.as_bytes();
        let nlen = needle.len();
        let mut start = 0usize;
        while let Some(rel) = haystack[start..].find(needle) {
            let idx = start + rel;
            let left_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
            let right_ok = idx + nlen >= bytes.len() || !is_ident_byte(bytes[idx + nlen]);
            if left_ok && right_ok {
                return true;
            }
            start = idx + 1;
        }
        false
    }

    fn has_hw_token(text: &str) -> bool {
        HW_SUBSTR_TOKENS.iter().any(|t| text.contains(t))
            || HW_EXACT_TOKENS
                .iter()
                .any(|t| contains_exact_ident(text, t))
    }

    for f in files {
        if !matches!(f.language, Language::C | Language::Cpp | Language::Rust) {
            continue;
        }
        if let Some(bytes) = f.cached_bytes.as_deref()
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            // Fast raw pre-check avoids comment-stripping allocation on pure Web/CLI Rust/C files.
            if has_hw_token(text) {
                let stripped = smg_graph::taint::strip_comments_simple(text);
                if has_hw_token(&stripped) {
                    return true;
                }
            }
        }
        if f.cached_bytes.is_none()
            && let Ok(text) = fs::read_to_string(&f.abs_path)
            && has_hw_token(&text)
        {
            let stripped = smg_graph::taint::strip_comments_simple(&text);
            if has_hw_token(&stripped) {
                return true;
            }
        }
    }
    !collect_hw_spec_files(project_root, 4, 1).is_empty()
}

/// Scans hardware, firmware, kernel driver, and embedded source files cleanly inside `smg-hw`.
pub fn scan_hardware_repo(
    project_root: &Path,
    files: &[IndexedFile],
    force_hw: bool,
) -> Vec<LocalStaticFinding> {
    if !force_hw && !repo_has_hw_indicators(project_root, files) {
        return Vec::new();
    }

    let mut sources: Vec<(String, Language, String)> = Vec::new();
    for f in files {
        if !matches!(f.language, Language::C | Language::Cpp | Language::Rust) {
            continue;
        }
        if smg_core::is_test_source_path(&f.rel_path) {
            continue;
        }
        let text = if let Some(b) = f.cached_bytes.as_deref() {
            String::from_utf8_lossy(b).into_owned()
        } else if let Ok(s) = fs::read_to_string(&f.abs_path) {
            s
        } else {
            continue;
        };
        sources.push((f.rel_path.clone(), f.language, text));
    }

    let mut raw_findings = Vec::new();
    let mut lock_summaries: Vec<HardwareFunctionLockSummary> = Vec::new();

    if !sources.is_empty() {
        let c_refs: Vec<(String, &str)> = sources
            .iter()
            .map(|(r, _, s)| (r.clone(), s.as_str()))
            .collect();
        let ctx = ingest_firmware_context(project_root, &c_refs);

        use rayon::prelude::*;
        let per_file: Vec<(Vec<LocalStaticFinding>, Vec<HardwareFunctionLockSummary>)> = sources
            .par_iter()
            .map(|(rel, lang, content)| {
                let mut local_findings = Vec::new();
                let mut local_locks = Vec::new();
                analyze_hw_file(
                    rel,
                    *lang,
                    content,
                    &ctx,
                    &mut local_findings,
                    &mut local_locks,
                );
                if matches!(lang, Language::C | Language::Cpp) {
                    local_findings.extend(wcsd_dma::analyze_dma_cache_coherency(rel, content));
                }
                (local_findings, local_locks)
            })
            .collect();
        for (lf, ll) in per_file {
            raw_findings.extend(lf);
            lock_summaries.extend(ll);
        }
    }

    let mut seen_ld_rel_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in files {
        let low = f.rel_path.to_ascii_lowercase();
        if (low.ends_with(".ld") || low.ends_with(".lds"))
            && let Ok(text) = if let Some(b) = f.cached_bytes.as_deref() {
                Ok(String::from_utf8_lossy(b).into_owned())
            } else {
                fs::read_to_string(&f.abs_path)
            }
        {
            let norm = f
                .rel_path
                .replace('\\', "/")
                .trim_start_matches("./")
                .to_string();
            if seen_ld_rel_paths.insert(norm) {
                let (_regions, _stack, ld_findings) =
                    wcsd_dma::audit_linker_script(&f.rel_path, &text);
                raw_findings.extend(ld_findings);
            }
        }
    }
    for spec_path in collect_hw_spec_files(project_root, 5, 64) {
        let low = spec_path.to_string_lossy().to_ascii_lowercase();
        if low.ends_with(".ld") || low.ends_with(".lds") {
            let rel = spec_path
                .strip_prefix(project_root)
                .unwrap_or(&spec_path)
                .to_string_lossy()
                .replace('\\', "/");
            let norm = rel.trim_start_matches("./").to_string();
            if seen_ld_rel_paths.insert(norm)
                && let Ok(text) = fs::read_to_string(&spec_path)
            {
                let (_regions, _stack, ld_findings) = wcsd_dma::audit_linker_script(&rel, &text);
                raw_findings.extend(ld_findings);
            }
        }
    }
    if !lock_summaries.is_empty() {
        raw_findings.extend(check_cross_fn_irq_deadlocks(&lock_summaries));
    }

    // Deduplicate on `(rule_id, rel_path, line)` while keeping highest severity
    let mut best_by_key: HashMap<(String, String, usize), usize> = HashMap::new();
    let mut deduped: Vec<LocalStaticFinding> = Vec::new();
    for f in raw_findings {
        let key = (f.rule_id.clone(), f.rel_path.clone(), f.line);
        if let Some(&idx) = best_by_key.get(&key) {
            if severity_rank(&f.severity) > severity_rank(&deduped[idx].severity) {
                deduped[idx] = f;
            }
        } else {
            best_by_key.insert(key, deduped.len());
            deduped.push(f);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_mem_file(rel: &str, lang: Language, code: &str) -> IndexedFile {
        let bytes = code.as_bytes().to_vec();
        IndexedFile {
            abs_path: PathBuf::from(rel),
            rel_path: rel.to_string(),
            language: lang,
            size_bytes: bytes.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(bytes),
        }
    }

    #[test]
    fn non_hw_web_repo_returns_zero_latency_and_findings() {
        let dir = PathBuf::from(".");
        let ts_file = mk_mem_file(
            "src/routes/pay.ts",
            Language::TypeScript,
            "app.post('/pay', fn);",
        );
        assert!(!repo_has_hw_indicators(
            &dir,
            std::slice::from_ref(&ts_file)
        ));
        assert!(scan_hardware_repo(&dir, &[ts_file], false).is_empty());

        // Comment-only mention of "volatile" in a Rust file does not trigger HW indicators
        let comment_only_rs = mk_mem_file(
            "src/util.rs",
            Language::Rust,
            "// note: do not use volatile or jtag_key here\npub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        );
        assert!(!repo_has_hw_indicators(
            &dir,
            std::slice::from_ref(&comment_only_rs)
        ));

        // Userspace Linux capability struct (`__user_cap_data_struct`) must not match `__user`
        let userspace_c = mk_mem_file(
            "src/os/unix/ngx_process_cycle.c",
            Language::C,
            "void drop_caps(void) { struct __user_cap_data_struct data; explicit_bzero(&data, sizeof(data)); }\n",
        );
        assert!(!repo_has_hw_indicators(
            &dir,
            std::slice::from_ref(&userspace_c)
        ));

        // Genuine kernel `__user` annotation still triggers HW indicators
        let kernel_c = mk_mem_file(
            "drivers/char/dev.c",
            Language::C,
            "ssize_t drv_write(const char __user *buf, size_t n) { return (ssize_t)n; }\n",
        );
        assert!(repo_has_hw_indicators(
            &dir,
            std::slice::from_ref(&kernel_c)
        ));
    }

    #[test]
    fn hw_positive_and_hardened_negative_matrix() {
        let dir = std::env::temp_dir().join(format!("smg-hw-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("board.ld"),
            "MEMORY {\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K\n  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K\n}\n",
        )
        .unwrap();

        let vuln_c = r#"
static const char *jtag_key = "dev_jtag_backdoor_key_99887766";

void uaf_and_abba_a(void) {
    spin_lock(&lock_alpha);
    spin_lock(&lock_beta);
    struct pkt *p = kmalloc(64);
    kfree(p);
    p->len = 12;
}

void abba_b(void) {
    spin_lock(&lock_beta);
    spin_lock(&lock_alpha);
}

void handle_dma(struct dma_desc *dma_hdr, int len, char *dst) {
    if (dma_hdr->len > 512) return;
    memcpy(dst, dma_hdr->data, (size_t)len);
    volatile uint32_t *flash = (volatile uint32_t *)0x08001000;
    *flash = 0x1;
}

void ota_apply(const uint8_t *img, uint32_t len) {
    flash_write(0x08010000, img, len);
}

void drv_task(void) {
    spin_lock(&uart_lock);
}

void UART0_IRQHandler(void) {
    spin_lock(&uart_lock);
}

void sign_tx(const uint8_t *seed, uint8_t *out) {
    uint8_t priv_key[32];
    memcpy(priv_key, seed, 32);
    if (scalar_bit & 1) { out[0] = sbox[priv_key[0]]; }
}
"#;
        let safe_c = r#"
void handle_dma_safe(const struct dma_desc *dma_user, int len, char *dst) {
    struct dma_desc local_hdr;
    if (copy_from_user(&local_hdr, dma_user, sizeof(local_hdr))) return;
    if (len < 0 || (size_t)len > 256) return;
    memcpy(dst, local_hdr.data, (size_t)len);
}

void ota_apply_safe(const uint8_t *img, uint32_t ver, uint32_t len) {
    if (!verify_signature(img, len)) return;
    if (ver < efuse_min_version()) return;
    flash_write(0x20001000, img, len);
}

void drv_task_safe(void) {
    unsigned long flags;
    spin_lock_irqsave(&uart_lock_safe, flags);
}

void UART1_IRQHandler(void) {
    spin_lock(&uart_lock_safe);
}

void sign_tx_safe(const uint8_t *seed) {
    uint8_t priv_key[32];
    memcpy(priv_key, seed, 32);
    explicit_bzero(priv_key, sizeof(priv_key));
}
"#;

        let vf = mk_mem_file("fw/vuln.c", Language::C, vuln_c);
        let vuln_hits = scan_hardware_repo(&dir, &[vf], true);
        let v_rules: Vec<&str> = vuln_hits.iter().map(|h| h.rule_id.as_str()).collect();
        for expected in [
            "SMG-HW-BOUNDS",
            "SMG-HW-MMIO",
            "SMG-HW-TOCTOU",
            "SMG-HW-BOOT",
            "SMG-HW-IRQ",
            "SMG-HW-TYPESTATE",
            "SMG-HW-CT",
            "SMG-HW-SECRETS",
        ] {
            assert!(
                v_rules.contains(&expected),
                "Missing expected hardware finding `{}` in {:?}",
                expected,
                v_rules
            );
        }
        assert!(
            vuln_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-TYPESTATE" && h.title.contains("Use-After-Free")),
            "Must detect Use-After-Free typestate violation: {:?}",
            vuln_hits
        );
        assert!(
            vuln_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-IRQ" && h.title.contains("ABBA")),
            "Must detect cross-function ABBA lock inversion: {:?}",
            vuln_hits
        );

        let sf = mk_mem_file("fw/safe.c", Language::C, safe_c);
        let safe_hits = scan_hardware_repo(&dir, &[sf], true);
        assert!(
            safe_hits.is_empty(),
            "Hardened firmware routines must produce 0 false positives: {:?}",
            safe_hits
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hw_audit_counterexamples_zero_false_positives_and_strict_detection() {
        let dir = std::env::temp_dir().join(format!("smg-hw-audit-ce-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("board.ld"),
            "MEMORY {\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K\n  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K\n}\n",
        )
        .unwrap();

        // 1. Counterexamples that MUST produce 0 false positives:
        // - Trailing comment with jtag_key
        // - Mutually exclusive if/else kfree(p)
        // - Early-return cleanup `if (err) { kfree(q); return; }` followed by `q->x = 1`
        // - `free(NULL)`
        // - Read from Flash `uint32_t v = *(volatile uint32_t *)0x08001000;`
        // - Bitmask `& 0xFFFF0000` on peripheral read
        // - Pointer parameter `int parse_pkt(struct dma_desc *hdr, char *dst)`
        // - Dynamic SparseOctagon bounds `if (off > 64 || len > 128) return; memcpy(dst + off, src, len);`
        // - Sequential lock-unlock-lock (`spin_lock(&a); spin_unlock(&a); spin_lock(&b);`)
        // - Function definition `void flash_write(...)` and string literal `"boot_jump(0)"`
        // - Word-bounded `design_layout` (does not match `sign`)
        let benign_c = r#"
int g = 1; // jtag_key = "1234567890123456"

void cleanup_branches(int cond, int err) {
    struct pkt *p = kmalloc(64);
    if (cond) {
        kfree(p);
    } else {
        kfree(p);
    }

    struct pkt *q = kmalloc(64);
    if (err) {
        kfree(q);
        return;
    }
    q->len = 16;
    kfree(q);

    char *null_p = NULL;
    kfree(null_p);
    kfree(null_p);
}

int read_flash_and_copy(struct pkt *pkt_ptr, uint32_t off, uint32_t len, char *src) {
    uint32_t flash_word = *(volatile uint32_t *)0x08001000 & 0xFFFF0000;
    char dst[256];
    if (off > 64 || len > 128) return -1;
    memcpy(dst + off, src, len);
    return (int)flash_word;
}

void sequential_locks_a(void) {
    spin_lock(&seq_a);
    spin_unlock(&seq_a);
    spin_lock(&seq_b);
    spin_unlock(&seq_b);
}

void sequential_locks_b(void) {
    spin_lock(&seq_b);
    spin_unlock(&seq_b);
    spin_lock(&seq_a);
    spin_unlock(&seq_a);
}

void flash_write(uint32_t addr, const uint8_t *img, uint32_t len) {
    printf("executing boot_jump(0x08000000)\n");
}

void design_layout(int secret) {
    if (secret > 10) { return; }
}
"#;
        let bf = mk_mem_file("fw/benign.c", Language::C, benign_c);
        let benign_hits = scan_hardware_repo(&dir, &[bf], true);
        assert!(
            benign_hits.is_empty(),
            "All audited benign firmware counterexamples must produce 0 false positives, got: {:?}",
            benign_hits
        );

        // 2. Counterexamples that MUST be caught (True Positives):
        // - Unchecked `verify_signature(img, len);` statement before `flash_write`
        // - Per-lock IRQ state: `spin_lock_irqsave(&other_lock, flags)` does NOT protect `spin_lock(&shared_irq_lock)`
        // - Second unzeroized key buffer `hmac_key` when only `priv_key` is zeroized
        // - Rust `#[cfg(test)] mod tests;` followed by production `mod prod` with `const JTAG_KEY: &str = ...`
        let subtle_vuln_c = r#"
void ota_apply_unchecked_sig(const uint8_t *img, uint32_t ver, uint32_t len) {
    verify_signature(img, len);
    if (ver < efuse_min_version()) return;
    flash_write(0x20001000, img, len);
}

void mixed_irq_task(void) {
    unsigned long flags;
    spin_lock_irqsave(&safe_lock, flags);
    spin_unlock_irqrestore(&safe_lock, flags);
    spin_lock(&shared_irq_lock);
}

void TIM2_IRQHandler(void) {
    spin_lock(&shared_irq_lock);
}

void partial_zeroize_sign(const uint8_t *seed) {
    uint8_t priv_key[32];
    uint8_t hmac_key[32];
    memcpy(priv_key, seed, 32);
    memcpy(hmac_key, seed, 32);
    explicit_bzero(priv_key, 32);
}
"#;
        let subtle_rs = r#"
#[cfg(test)]
mod tests;

pub mod prod_fw {
    pub const JTAG_KEY: &str = "prod_jtag_unlock_secret_998877";
}
"#;
        let sv_c = mk_mem_file("fw/subtle_vuln.c", Language::C, subtle_vuln_c);
        let sv_rs = mk_mem_file("fw/lib.rs", Language::Rust, subtle_rs);
        let subtle_hits = scan_hardware_repo(&dir, &[sv_c, sv_rs], true);

        assert!(
            subtle_hits.iter().any(|h| h.rule_id == "SMG-HW-BOOT"),
            "Must catch unchecked verify_signature call in ota_apply_unchecked_sig: {:?}",
            subtle_hits
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-IRQ" && h.title.contains("shared_irq_lock")),
            "Must catch per-lock unmasked IRQ acquisition on shared_irq_lock: {:?}",
            subtle_hits
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-TYPESTATE" && h.title.contains("hmac_key")),
            "Must catch unzeroized second buffer hmac_key: {:?}",
            subtle_hits
        );
        assert!(
            subtle_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-SECRETS" && h.rel_path == "fw/lib.rs"),
            "Must catch typed Rust JTAG_KEY in production module after #[cfg(test)] mod tests;: {:?}",
            subtle_hits
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sprint5_p13_01_and_p13_02_tnum_octagon_opaque_dst_and_interproc_isr() {
        let dir = std::env::temp_dir().join("smg_hw_sprint5_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // 1. Safe cases: uint8_t exact bit-width in buf[512], opaque char *dst (no 256 guess),
        //    and ISR -> helper using GFP_ATOMIC + spin_lock_irqsave in task
        let safe_c = r#"
void copy_u8_safe(uint8_t off, uint8_t len, const char *src) {
    char buf[512];
    memcpy(buf + off, src, len);
}

void copy_opaque_dst_safe(char *dst, uint32_t off, uint32_t len, const char *src) {
    memcpy(dst + off, src, len);
}

static void safe_rx_helper(void) {
    void *p = kmalloc(64, GFP_ATOMIC);
    spin_lock(&safe_lock);
    spin_unlock(&safe_lock);
    kfree(p);
}

void SAFE_IRQHandler(void) {
    safe_rx_helper();
}

void safe_task_worker(void) {
    unsigned long flags;
    spin_lock_irqsave(&safe_lock, flags);
    spin_unlock_irqrestore(&safe_lock, flags);
}
"#;
        let sf = mk_mem_file("fw/safe_s5.c", Language::C, safe_c);
        let safe_hits = scan_hardware_repo(&dir, &[sf], true);
        assert!(
            safe_hits.is_empty(),
            "Sprint 5 safe firmware cases must produce 0 FPs, got: {:?}",
            safe_hits
        );

        // 2. Vulnerable cases: real OOB on known dst[128], indirect ISR -> helper -> spin_lock
        //    self-deadlock, and indirect ISR -> helper -> kmalloc(GFP_KERNEL) sleeping-in-ISR
        let vuln_c = r#"
void copy_oob_known_cap(uint32_t off, uint32_t len, const char *src) {
    char dst[128];
    memcpy(dst + off, src, len);
}

static void ring_push_helper(void) {
    spin_lock(&dev_ring_lock);
    spin_unlock(&dev_ring_lock);
}

void DMA_IRQHandler(void) {
    ring_push_helper();
}

void dev_worker_task(void) {
    spin_lock(&dev_ring_lock);
    spin_unlock(&dev_ring_lock);
}

static void alloc_rx_pkt(void) {
    void *buf = kmalloc(64, GFP_KERNEL);
    kfree(buf);
}

void UART_IRQHandler(void) {
    alloc_rx_pkt();
}
"#;
        let vf = mk_mem_file("fw/vuln_s5.c", Language::C, vuln_c);
        let vuln_hits = scan_hardware_repo(&dir, &[vf], true);
        assert!(
            vuln_hits
                .iter()
                .any(|h| h.rule_id == "SMG-HW-BOUNDS" && h.symbol == "copy_oob_known_cap"),
            "Must catch real OOB on known dst[128]: {:?}",
            vuln_hits
        );
        assert!(
            vuln_hits.iter().any(|h| {
                h.rule_id == "SMG-HW-IRQ"
                    && h.title.contains("Self-Deadlock")
                    && h.title.contains("dev_ring_lock")
            }),
            "Must catch indirect ISR -> helper -> spin_lock self-deadlock: {:?}",
            vuln_hits
        );
        assert!(
            vuln_hits.iter().any(|h| {
                h.rule_id == "SMG-HW-IRQ"
                    && h.title.contains("Sleeping allocation")
                    && h.title.contains("UART_IRQHandler")
            }),
            "Must catch indirect ISR -> helper -> kmalloc(GFP_KERNEL) sleeping-in-ISR: {:?}",
            vuln_hits
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
