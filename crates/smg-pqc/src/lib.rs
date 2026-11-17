pub mod inventory;
pub mod lattice;

use inventory::{CryptoAssetRecord, analyze_pqc_inventory, build_static_cbom_cyclonedx};
use smg_core::IndexedFile;
use smg_graph::LocalStaticFinding;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PqcScanResult {
    pub findings: Vec<LocalStaticFinding>,
    pub cbom_json: String,
    pub assets: Vec<CryptoAssetRecord>,
}

/// Runs Post-Quantum Crypto-Agility, Mosca HNDL urgency, and honest partial CycloneDX CBOM analysis.
/// Designed for explicit opt-in `--compliance pqc`, `--layers pqc`, or `--cbom <FILE>`.
pub fn scan_pqc_repo(
    project_root: &Path,
    files: &[IndexedFile],
    min_pq_category: u8,
) -> PqcScanResult {
    let (findings, assets) = analyze_pqc_inventory(files, min_pq_category);
    let cbom_json = build_static_cbom_cyclonedx(project_root, &assets);
    PqcScanResult {
        findings,
        cbom_json,
        assets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smg_core::Language;

    fn mem_file(rel: &str, lang: Language, src: &str) -> IndexedFile {
        IndexedFile {
            rel_path: rel.into(),
            abs_path: Path::new(rel).to_path_buf(),
            language: lang,
            blake3_hash: "0".into(),
            mtime_ns: 0,
            size_bytes: src.len() as u64,
            cached_bytes: Some(src.as_bytes().to_vec()),
        }
    }

    #[test]
    fn detects_hndl_downgrade_weak_pqc_and_spares_hardened_hybrid() {
        let vuln_tls = r#"
pub fn setup_tls() {
    let kex = "ECDHE-RSA-AES128-GCM-SHA256";
    // allow silent fallback to RSA on ML-KEM error
    let fallback_kex = "fallback_to_rsa_classic_mlkem";
    let weak = "ML-KEM-512";
    let seed = [0u8; 32]; ml_kem_keygen(seed);
}
"#;
        let safe_tls = r#"
pub fn setup_pqc_tls() {
    let suite = "X25519MLKEM768-AES-256-GCM-SHA-384";
    let kdf_secret = hkdf_concat(classic_ss, pqc_ss);
}
"#;
        let files = vec![
            mem_file("src/vuln_tls.rs", Language::Rust, vuln_tls),
            mem_file("src/safe_tls.rs", Language::Rust, safe_tls),
        ];

        let res = scan_pqc_repo(Path::new("demo-pqc"), &files, 3);
        let vuln_ids: Vec<&str> = res
            .findings
            .iter()
            .filter(|f| f.rel_path == "src/vuln_tls.rs")
            .map(|f| f.rule_id.as_str())
            .collect();

        assert!(vuln_ids.contains(&"SMG-PQC-HNDL"), "{vuln_ids:?}");
        assert!(vuln_ids.contains(&"SMG-PQC-GROVER"), "{vuln_ids:?}");
        assert!(vuln_ids.contains(&"SMG-PQC-DOWNGRADE"), "{vuln_ids:?}");
        assert!(vuln_ids.contains(&"SMG-PQC-PARAMS"), "{vuln_ids:?}");

        let safe_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rel_path == "src/safe_tls.rs")
            .collect();
        assert!(
            safe_hits.is_empty(),
            "safe PQC config flagged: {safe_hits:#?}"
        );

        // Verify honest CBOM metadata explicitly marks static partial observability
        assert!(res.cbom_json.contains("CycloneDX"));
        assert!(res.cbom_json.contains("\"runtimeUnobserved\": true"));
        assert!(res.cbom_json.contains("static-source-and-config-partial"));
        assert!(res.cbom_json.contains("X25519MLKEM768"));
    }
}
