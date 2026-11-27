pub mod inventory;
pub mod lattice;
pub mod x509;
pub mod x509_starttls_elf;

pub use x509_starttls_elf::{
    DerCertAudit, ElfCryptoAudit, StartTlsProtocol, extract_cn_and_san_dns, inspect_x509_der,
    negotiate_starttls, scan_elf_crypto_symbols,
};

use inventory::{CryptoAssetRecord, analyze_pqc_inventory, build_static_cbom_cyclonedx};
use smg_core::IndexedFile;
use smg_graph::LocalStaticFinding;
use std::path::Path;
use x509::X509CertRecord;

#[derive(Debug, Clone)]
pub struct PqcScanResult {
    pub findings: Vec<LocalStaticFinding>,
    pub cbom_json: String,
    pub assets: Vec<CryptoAssetRecord>,
    pub certificates: Vec<X509CertRecord>,
}

/// Runs Post-Quantum Crypto-Agility, Mosca HNDL urgency, X.509 chain audit, and honest partial CycloneDX CBOM analysis.
/// Designed for explicit opt-in `--compliance pqc`, `--layers pqc`, or `--cbom <FILE>`.
pub fn scan_pqc_repo(
    project_root: &Path,
    files: &[IndexedFile],
    min_pq_category: u8,
) -> PqcScanResult {
    let (mut findings, assets) = analyze_pqc_inventory(files, min_pq_category);
    let mut certificates = Vec::new();
    let mut seen_rel: std::collections::HashSet<String> = std::collections::HashSet::new();
    let current_year = x509::current_utc_year();
    for f in files {
        let low = f.rel_path.to_ascii_lowercase();
        if low.ends_with(".pem") || low.ends_with(".crt") || low.ends_with(".cer") {
            let text_opt = if let Some(b) = f.cached_bytes.as_deref() {
                std::str::from_utf8(b).ok().map(str::to_string)
            } else {
                std::fs::read_to_string(&f.abs_path).ok()
            };
            if let Some(text) = text_opt {
                let parsed = x509::parse_pem_certificates(&f.rel_path, &text);
                if !parsed.is_empty() {
                    findings.extend(x509::audit_x509_chain(&parsed));
                    certificates.extend(parsed);
                }
                // Also run full DER inspection (expiry, SAN, weak MD5/SHA-1 sigs) on every decoded PEM cert block
                for der in x509::decode_pem_certificates(&text) {
                    let (_audit, der_hits) =
                        x509_starttls_elf::inspect_x509_der(&f.rel_path, &der, current_year);
                    findings.extend(der_hits);
                }
            }
        } else if low.ends_with(".der") {
            seen_rel.insert(f.rel_path.clone());
            let bytes_opt = f.cached_bytes.clone().or_else(|| {
                use std::io::Read;
                let file = std::fs::File::open(&f.abs_path).ok()?;
                let mut buf = Vec::new();
                file.take(1024 * 1024).read_to_end(&mut buf).ok()?;
                Some(buf)
            });
            if let Some(der) = bytes_opt {
                if let Some(cert) = x509::parse_x509_der(&f.rel_path, 0, &der) {
                    findings.extend(x509::audit_x509_chain(std::slice::from_ref(&cert)));
                    certificates.push(cert);
                }
                let (_audit, der_hits) =
                    x509_starttls_elf::inspect_x509_der(&f.rel_path, &der, current_year);
                findings.extend(der_hits);
            }
        } else if low.ends_with(".so") || low.contains(".so.") || low.ends_with(".elf") {
            seen_rel.insert(f.rel_path.clone());
            if let Some(elf_bytes) = f.cached_bytes.as_deref() {
                let (_audit, elf_hits) =
                    x509_starttls_elf::scan_elf_crypto_symbols(&f.rel_path, elf_bytes);
                findings.extend(elf_hits);
            } else if let Ok(mut file) = std::fs::File::open(&f.abs_path)
                && let Ok((_audit, elf_hits)) = x509_starttls_elf::scan_elf_crypto_symbols_reader(
                    &f.rel_path,
                    &mut file,
                    32 * 1024 * 1024,
                )
            {
                findings.extend(elf_hits);
            }
        }
    }
    // Phase 32: Bounded disk walk for `.der`, `.elf`, `.so` binaries skipped by source-code indexers
    fn walk_pqc_binaries(
        root: &Path,
        dir: &Path,
        depth: usize,
        current_year: u32,
        seen: &mut std::collections::HashSet<String>,
        binary_files_scanned: &mut usize,
        out: &mut Vec<LocalStaticFinding>,
    ) {
        if depth > 4 || *binary_files_scanned >= 128 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut sorted_entries: Vec<_> = entries.flatten().collect();
        sorted_entries.sort_by_key(|e| e.file_name());
        for entry in sorted_entries {
            if *binary_files_scanned >= 128 {
                break;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if ft.is_dir() {
                if matches!(
                    name_str.as_ref(),
                    ".git" | "target" | "node_modules" | ".venv" | "dist" | "build"
                ) {
                    continue;
                }
                walk_pqc_binaries(
                    root,
                    &path,
                    depth + 1,
                    current_year,
                    seen,
                    binary_files_scanned,
                    out,
                );
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if !seen.insert(rel.clone()) {
                continue;
            }
            let low = name_str.to_ascii_lowercase();
            if low.ends_with(".der") {
                *binary_files_scanned += 1;
                use std::io::Read;
                if let Ok(file) = std::fs::File::open(&path) {
                    let mut der = Vec::new();
                    if file.take(1024 * 1024).read_to_end(&mut der).is_ok() {
                        let (_a, hits) =
                            x509_starttls_elf::inspect_x509_der(&rel, &der, current_year);
                        out.extend(hits);
                    }
                }
            } else if (low.ends_with(".elf") || low.ends_with(".so") || low.contains(".so."))
                && let Ok(mut f) = std::fs::File::open(&path)
            {
                *binary_files_scanned += 1;
                if let Ok((_a, hits)) = x509_starttls_elf::scan_elf_crypto_symbols_reader(
                    &rel,
                    &mut f,
                    32 * 1024 * 1024,
                ) {
                    out.extend(hits);
                }
            }
        }
    }
    let mut binary_files_scanned = 0usize;
    walk_pqc_binaries(
        project_root,
        project_root,
        0,
        current_year,
        &mut seen_rel,
        &mut binary_files_scanned,
        &mut findings,
    );
    for f in findings.iter_mut() {
        f.rel_path = smg_core::normalize_rel_path_posix_nfc(&f.rel_path);
    }
    findings.sort_by(|a, b| {
        a.rel_path
            .cmp(&b.rel_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.title.cmp(&b.title))
    });
    let cbom_json = build_static_cbom_cyclonedx(project_root, &assets, &certificates);
    PqcScanResult {
        findings,
        cbom_json,
        assets,
        certificates,
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

    #[test]
    fn pqc_audit_counterexamples_zero_false_positives_and_strict_detection() {
        // 1. Benign PQC code that MUST produce 0 false positives:
        // - English words "reversal" / "universal" (must not match "rsa")
        // - Disabled fallback `let allow_rsa_fallback = false;`
        // - CSPRNG `os_rand()` in `ml_kem_768_keygen(os_rand())`
        // - Proper hybrid combiner `hkdf(classic_ss, pqc_ss)`
        let benign_pqc = r#"
pub fn compute_reversal_universal<'a, 'b>(input: &'a str) -> &'a str { // ECDHE-RSA-AES128-GCM-SHA256
    let _suite = "ML-KEM-768";
    let _allow_rsa_fallback = false;
    let _kp = ml_kem_768_keygen(os_rand());
    input
}
"#;
        let benign_res = scan_pqc_repo(
            Path::new("benign-pqc"),
            &[mem_file("src/benign.rs", Language::Rust, benign_pqc)],
            3,
        );
        assert!(
            benign_res.findings.is_empty(),
            "Benign PQC counterexamples must produce 0 findings, got: {:#?}",
            benign_res.findings
        );

        // 2. Subtle PQC vulnerabilities that MUST be detected:
        // - `#[cfg(test)] mod tests;` followed by production cipher suite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
        // - Broken hybrid KDF combiner that drops `pqc_ss` (`let shared_secret = hkdf(classic_ss);`)
        // - Same-line `ML-KEM-512` (MEDIUM) + `[0u8; 32]` weak seed (CRITICAL) retaining CRITICAL severity
        let subtle_pqc = r#"
#[cfg(test)]
mod tests;

pub fn broken_hybrid_and_underscore_suite() {
    let suite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    let classic_ss = x25519_dh();
    let pqc_ss = ml_kem_768_encaps();
    let shared_secret = hkdf(classic_ss);
    let bad = ("ML-KEM-512", [0u8; 32], ml_kem_keygen([0u8; 32]));
}
"#;
        let subtle_res = scan_pqc_repo(
            Path::new("subtle-pqc"),
            &[mem_file("src/subtle.rs", Language::Rust, subtle_pqc)],
            3,
        );
        let rules: Vec<&str> = subtle_res
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(
            rules.contains(&"SMG-PQC-HNDL"),
            "Must detect ECDHE/RSA inside underscore cipher suite after #[cfg(test)] mod tests;: {rules:?}"
        );
        assert!(
            rules.contains(&"SMG-PQC-HYBRID"),
            "Must detect hybrid KDF combiner that drops pqc_ss: {rules:?}"
        );
        let params_hit = subtle_res
            .findings
            .iter()
            .find(|f| f.rule_id == "SMG-PQC-PARAMS")
            .expect("Must emit SMG-PQC-PARAMS");
        assert_eq!(
            params_hit.severity, "CRITICAL",
            "Same-line deduplication must retain CRITICAL weak-seed severity over MEDIUM parameter severity"
        );
    }

    #[test]
    fn test_sprint6_p13_04_x509_der_chain_per_fn_kdf_multiline_hmac_and_pqc_algos() {
        // Helper to build minimal valid DER X.509 certificate with given signature OID & UTCTime notAfter
        fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 128 {
                out.push(content.len() as u8);
            } else {
                out.push(0x82);
                out.extend_from_slice(&(content.len() as u16).to_be_bytes());
            }
            out.extend_from_slice(content);
            out
        }
        fn b64_encode(bytes: &[u8]) -> String {
            const TAB: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let b0 = chunk[0] as usize;
                let b1 = *chunk.get(1).unwrap_or(&0) as usize;
                let b2 = *chunk.get(2).unwrap_or(&0) as usize;
                out.push(TAB[b0 >> 2] as char);
                out.push(TAB[((b0 & 3) << 4) | (b1 >> 4)] as char);
                out.push(if chunk.len() > 1 {
                    TAB[((b1 & 0xf) << 2) | (b2 >> 6)] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    TAB[b2 & 0x3f] as char
                } else {
                    '='
                });
            }
            out
        }
        fn make_pem_cert(sig_oid_bytes: &[u8], not_after_utc: &[u8]) -> String {
            let alg_seq = der_tlv(0x30, &der_tlv(0x06, sig_oid_bytes));
            let serial = der_tlv(0x02, &[0x01]);
            let issuer = der_tlv(0x30, &[]);
            let validity = der_tlv(
                0x30,
                &[
                    der_tlv(0x17, b"260101000000Z"),
                    der_tlv(0x17, not_after_utc),
                ]
                .concat(),
            );
            let subject = der_tlv(0x30, &[]);
            let tbs = der_tlv(
                0x30,
                &[serial, alg_seq.clone(), issuer, validity, subject].concat(),
            );
            let cert = der_tlv(0x30, &[tbs, alg_seq, der_tlv(0x03, &[0x00, 0xaa])].concat());
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                b64_encode(&cert)
            )
        }

        // Leaf: ML-DSA-65 (2.16.840.1.101.3.4.3.18); Root CA: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
        let mldsa65_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
        let rsa_sha256_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let chain_pem = format!(
            "{}{}",
            make_pem_cert(&mldsa65_oid, b"300101000000Z"),
            make_pem_cert(&rsa_sha256_oid, b"380101000000Z"),
        );

        // Per-function KDF isolation + multi-line HMAC SHA-256 + SecP256r1MLKEM768/FN-DSA-1024/HQC-192/BLAKE3 -> 0 FP!
        let safe_src = r#"
pub fn modern_pqc_suite() {
    let kex = "SecP256r1MLKEM768";
    let sig = "FN-DSA-1024";
    let kem = "HQC-192";
    let hash = "BLAKE3";
    let mac = hmac_init(
        key,
        "SHA-256",
    );
}

pub fn separate_pq_helper() {
    let shared_secret = ml_kem_768_encaps();
}
"#;
        let legacy_tls_src = r#"
pub fn bad_tls() {
    let min_ver = tls::VersionTLS12;
}
"#;
        let files = vec![
            mem_file("certs/chain.pem", Language::Config, &chain_pem),
            mem_file("src/safe_modern.rs", Language::Rust, safe_src),
            mem_file("src/legacy_tls.rs", Language::Rust, legacy_tls_src),
        ];
        let res = scan_pqc_repo(Path::new("sprint6-pqc"), &files, 3);

        // X.509 chain link #1 (RSA CA beneath ML-DSA-65 leaf) MUST emit SMG-PQC-HNDL & CycloneDX "certificate"
        assert_eq!(res.certificates.len(), 2);
        assert_eq!(res.certificates[0].sig_algorithm, "ML-DSA-65");
        assert_eq!(res.certificates[1].sig_algorithm, "SHA256-with-RSA");
        assert_eq!(res.certificates[1].not_after_year, Some(2038));
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-PQC-HNDL" && f.rel_path == "certs/chain.pem"),
            "Weak RSA CA beneath PQC leaf must emit SMG-PQC-HNDL: {:#?}",
            res.findings
        );
        assert!(
            res.cbom_json.contains("\"assetType\": \"certificate\""),
            "CBOM must include X.509 certificate components"
        );

        // Verify Falcon/HQC/BLAKE3 assets are not silently filtered out by FAST_STEMS
        let asset_algos: Vec<&str> = res.assets.iter().map(|a| a.algorithm.as_str()).collect();
        assert!(
            asset_algos.contains(&"HQC-192") && asset_algos.contains(&"BLAKE3"),
            "HQC-192 and BLAKE3 must appear in PQC inventory assets: {asset_algos:?}"
        );
        assert!(res.cbom_json.contains("HQC-192"));
        assert!(res.cbom_json.contains("BLAKE3"));

        // Safe modern PQC + multi-line HMAC SHA-256 + separate functions -> 0 FP!
        let safe_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rel_path == "src/safe_modern.rs")
            .collect();
        assert!(
            safe_hits.is_empty(),
            "Modern PQC algos & multi-line HMAC SHA-256 must produce 0 FPs: {safe_hits:#?}"
        );

        // Legacy TLS 1.2 -> caught!
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-PQC-DOWNGRADE" && f.rel_path == "src/legacy_tls.rs"),
            "VersionTLS12 must emit SMG-PQC-DOWNGRADE: {:#?}",
            res.findings
        );
    }
}
