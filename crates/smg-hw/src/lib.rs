pub mod context;
pub mod domains;
pub mod typestate_irq;

use context::ingest_firmware_context;
use smg_core::{IndexedFile, Language};
use smg_graph::LocalStaticFinding;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use typestate_irq::{HardwareFunctionLockSummary, analyze_hw_file, check_cross_fn_irq_deadlocks};

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
        return false;
    }

    // Lightweight indicator scan on C/C++/Rust files before spinning deeper domains
    const HW_TOKENS: &[&str] = &[
        "volatile",
        "__user",
        "copy_from_user",
        "spin_lock",
        "read_volatile",
        "write_volatile",
        "#[interrupt]",
        "IRQHandler",
        "mmio",
        "flash_write",
        "ota_apply",
        "boot_jump",
        "pvPortMalloc",
        "explicit_bzero",
        "jtag_key",
    ];
    for f in files {
        if !matches!(f.language, Language::C | Language::Cpp | Language::Rust) {
            continue;
        }
        if let Some(bytes) = f.cached_bytes.as_deref()
            && let Ok(text) = std::str::from_utf8(bytes)
            && HW_TOKENS.iter().any(|t| text.contains(t))
        {
            return true;
        }
        if f.cached_bytes.is_none()
            && let Ok(text) = fs::read_to_string(&f.abs_path)
            && HW_TOKENS.iter().any(|t| text.contains(t))
        {
            return true;
        }
    }
    false
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

    if sources.is_empty() {
        return Vec::new();
    }

    let c_refs: Vec<(String, &str)> = sources
        .iter()
        .map(|(r, _, s)| (r.clone(), s.as_str()))
        .collect();
    let ctx = ingest_firmware_context(project_root, &c_refs);

    let mut raw_findings = Vec::new();
    let mut lock_summaries: Vec<HardwareFunctionLockSummary> = Vec::new();

    for (rel, lang, content) in &sources {
        analyze_hw_file(
            rel,
            *lang,
            content,
            &ctx,
            &mut raw_findings,
            &mut lock_summaries,
        );
    }
    raw_findings.extend(check_cross_fn_irq_deadlocks(&lock_summaries));

    // Deduplicate on `(rule_id, rel_path, line)`
    let mut seen: HashSet<(String, String, usize)> = HashSet::new();
    raw_findings.retain(|f| seen.insert((f.rule_id.clone(), f.rel_path.clone(), f.line)));
    raw_findings
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
}
