use crate::lattice::{
    CryptoFamily, PqSecurityStrength, evaluate_pq_strength, mosca_hndl_urgency_years,
};
use serde::Serialize;
use serde_json::json;
use smg_core::IndexedFile;
use smg_graph::taint::{is_pattern_matcher_or_doc_line, strip_comments_simple};
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAssetRecord {
    pub algorithm: String,
    pub oid: String,
    pub family: CryptoFamily,
    pub classical_bits: u16,
    pub quantum_bits: u16,
    pub nist_category: u8,
    pub hndl_shelf_life_years: i16,
    pub hndl_urgency_years: i16,
    pub file: String,
    pub line: usize,
    pub detection_mode: &'static str,
}

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn read_text(f: &IndexedFile) -> Option<String> {
    if let Some(bytes) = f.cached_bytes.as_deref() {
        return std::str::from_utf8(bytes).ok().map(str::to_string);
    }
    fs::read_to_string(&f.abs_path).ok()
}

fn has_boundary_match(haystack: &str, needle: &str, reject_underscore: bool) -> bool {
    let bytes = haystack.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || (reject_underscore && b == b'_');
    let mut start = 0usize;
    while let Some(rel_idx) = haystack[start..].find(needle) {
        let idx = start + rel_idx;
        let end = idx + needle.len();
        let left_ok = idx == 0 || !is_word(bytes[idx - 1]);
        let right_ok = end == bytes.len() || !is_word(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

fn has_token_boundary(haystack: &str, needle: &str) -> bool {
    // Allow `_` and `-` as cipher-suite sub-token delimiters while rejecting mid-word alphanumeric matches (e.g. "reversal" != "rsa")
    has_boundary_match(haystack, needle, false)
}

fn has_ident_word(haystack: &str, needle: &str) -> bool {
    has_boundary_match(haystack, needle, false)
}

fn token_candidates_in_line(line: &str) -> Vec<&'static str> {
    let mut masked = line.to_ascii_lowercase();
    if let Some((lhs, rhs)) = masked.split_once('=')
        && rhs.trim_start().starts_with("false")
        && (lhs.contains("fallback")
            || lhs.contains("allow_")
            || lhs.contains("enable_")
            || lhs.contains("use_"))
    {
        return Vec::new();
    }
    const FAST_STEMS: &[&str] = &[
        "kem",
        "kyber",
        "dsa",
        "dilithium",
        "sphincs",
        "ecdh",
        "25519",
        "ecdsa",
        "secp",
        "prime",
        "ssh-dss",
        "diffie-hellman",
        "rsa",
        "rs256",
        "rs384",
        "rs512",
        "aes",
        "chacha",
        "sha",
    ];
    if !FAST_STEMS.iter().any(|s| masked.contains(s)) {
        return Vec::new();
    }
    let patterns: &[(&str, &str)] = &[
        ("x25519mlkem768", "X25519MLKEM768"),
        ("x25519kyber768", "X25519MLKEM768"),
        ("ml-kem-1024", "ML-KEM-1024"),
        ("ml_kem_1024", "ML-KEM-1024"),
        ("mlkem1024", "ML-KEM-1024"),
        ("kyber-1024", "ML-KEM-1024"),
        ("kyber_1024", "ML-KEM-1024"),
        ("kyber1024", "ML-KEM-1024"),
        ("ml-kem-768", "ML-KEM-768"),
        ("ml_kem_768", "ML-KEM-768"),
        ("mlkem768", "ML-KEM-768"),
        ("kyber-768", "ML-KEM-768"),
        ("kyber_768", "ML-KEM-768"),
        ("kyber768", "ML-KEM-768"),
        ("ml-kem-512", "ML-KEM-512"),
        ("ml_kem_512", "ML-KEM-512"),
        ("mlkem512", "ML-KEM-512"),
        ("kyber-512", "ML-KEM-512"),
        ("kyber_512", "ML-KEM-512"),
        ("kyber512", "ML-KEM-512"),
        ("ml-dsa-87", "ML-DSA-87"),
        ("ml_dsa_87", "ML-DSA-87"),
        ("mldsa87", "ML-DSA-87"),
        ("dilithium5", "ML-DSA-87"),
        ("ml-dsa-65", "ML-DSA-65"),
        ("ml_dsa_65", "ML-DSA-65"),
        ("mldsa65", "ML-DSA-65"),
        ("dilithium3", "ML-DSA-65"),
        ("ml-dsa-44", "ML-DSA-44"),
        ("ml_dsa_44", "ML-DSA-44"),
        ("mldsa44", "ML-DSA-44"),
        ("dilithium2", "ML-DSA-44"),
        ("slh-dsa-256s", "SLH-DSA-256"),
        ("slh-dsa-256f", "SLH-DSA-256"),
        ("slh-dsa-256", "SLH-DSA-256"),
        ("sphincs+-256", "SLH-DSA-256"),
        ("sphincs256", "SLH-DSA-256"),
        ("slh-dsa-128s", "SLH-DSA-128"),
        ("slh-dsa-128f", "SLH-DSA-128"),
        ("slh-dsa-128", "SLH-DSA-128"),
        ("sphincs+-128", "SLH-DSA-128"),
        ("sphincs128", "SLH-DSA-128"),
        ("slh-dsa-192s", "SLH-DSA-192"),
        ("slh-dsa-192f", "SLH-DSA-192"),
        ("slh-dsa-192", "SLH-DSA-192"),
        ("slh-dsa", "SLH-DSA-192"),
        ("sphincs+", "SLH-DSA-192"),
        ("sphincs", "SLH-DSA-192"),
        ("ecdhe", "ECDHE"),
        ("ecdh", "ECDH"),
        ("x25519", "X25519"),
        ("ed25519", "Ed25519"),
        ("ecdsa", "ECDSA"),
        ("secp256r1mlkem768", "SecP256r1MLKEM768"),
        ("p256_mlkem768", "SecP256r1MLKEM768"),
        ("fn-dsa-1024", "FN-DSA-1024"),
        ("falcon-1024", "FN-DSA-1024"),
        ("falcon1024", "FN-DSA-1024"),
        ("fn-dsa-512", "FN-DSA-512"),
        ("falcon-512", "FN-DSA-512"),
        ("falcon512", "FN-DSA-512"),
        ("hqc-256", "HQC-256"),
        ("hqc256", "HQC-256"),
        ("hqc-192", "HQC-192"),
        ("hqc192", "HQC-192"),
        ("hqc-128", "HQC-128"),
        ("hqc128", "HQC-128"),
        ("blake3", "BLAKE3"),
        ("secp256k1", "secp256k1"),
        ("prime256v1", "prime256v1"),
        ("secp256r1", "secp256r1"),
        ("secp192r1", "secp192r1"),
        ("prime192v1", "prime192v1"),
        ("secp224r1", "secp224r1"),
        ("secp384r1", "secp384r1"),
        ("secp521r1", "secp521r1"),
        ("ssh-dss", "ssh-dss"),
        ("diffie-hellman-group1-sha1", "diffie-hellman-group1-sha1"),
        ("rsa-512", "RSA-512"),
        ("rsa-1024", "RSA-1024"),
        ("rsa1024", "RSA-1024"),
        ("rsa-oaep", "RSA-OAEP"),
        ("rsa_oaep", "RSA-OAEP"),
        ("rsa-pss", "RSA-PSS"),
        ("rsa_pss", "RSA-PSS"),
        ("rs256", "RS256"),
        ("rs384", "RS256"),
        ("rs512", "RS256"),
        ("rsa-2048", "RSA"),
        ("rsa-3072", "RSA"),
        ("rsa-4096", "RSA"),
        ("rsa2048", "RSA"),
        ("rsa3072", "RSA"),
        ("rsa4096", "RSA"),
        ("rsa_generate", "RSA"),
        ("rsa_kex", "RSA"),
        ("rsa::new", "RSA"),
        ("generatekeypair(\"rsa\"", "RSA"),
        ("generatekeypair('rsa'", "RSA"),
        ("tls_rsa", "RSA"),
        ("_rsa_", "RSA"),
        ("-rsa-", "RSA"),
        ("aes-256", "AES-256"),
        ("aes256", "AES-256"),
        ("aes_256", "AES-256"),
        ("aes-128", "AES-128"),
        ("aes128", "AES-128"),
        ("aes_128", "AES-128"),
        ("chacha20", "ChaCha20-Poly1305"),
        ("sha-384", "SHA-384"),
        ("sha384", "SHA-384"),
        ("sha_384", "SHA-384"),
        ("sha-512", "SHA-512"),
        ("sha512", "SHA-512"),
        ("sha_512", "SHA-512"),
        ("sha-256", "SHA-256"),
        ("sha256", "SHA-256"),
        ("sha_256", "SHA-256"),
    ];
    let mut hits = Vec::new();
    for (needle, canonical) in patterns {
        if has_token_boundary(&masked, needle) {
            if !hits.contains(canonical) {
                hits.push(*canonical);
            }
            masked = masked.replace(needle, " ");
        }
    }
    hits
}

fn check_pqc_hybrid_and_downgrade(
    rel_path: &str,
    filtered_lines: &[(usize, String)],
    findings: &mut Vec<LocalStaticFinding>,
) {
    let joined: String = filtered_lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let low = joined.to_ascii_lowercase();

    // 1. Per-function Hybrid KDF combiner verification (Phase 13B P13-04):
    // Split lines by top-level function headers so unrelated classical & PQC functions in the
    // same file do not cross-contaminate hybrid KDF checks.
    let mut fn_chunks: Vec<Vec<(usize, &str)>> = vec![Vec::new()];
    for (ln, line) in filtered_lines {
        let t = line.trim_start();
        let is_fn_hdr = !line.starts_with("    ")
            && !line.starts_with('\t')
            && (t.starts_with("pub fn ")
                || t.starts_with("pub async fn ")
                || t.starts_with("fn ")
                || t.starts_with("async fn ")
                || t.starts_with("def ")
                || t.starts_with("async def ")
                || t.starts_with("func ")
                || t.starts_with("function ")
                || t.starts_with("async function ")
                || t.starts_with("export function ")
                || t.starts_with("export async function "));
        if is_fn_hdr && !fn_chunks.last().is_none_or(Vec::is_empty) {
            fn_chunks.push(Vec::new());
        }
        if let Some(last) = fn_chunks.last_mut() {
            last.push((*ln, line.as_str()));
        }
    }

    for chunk in &fn_chunks {
        let c_joined: String = chunk.iter().map(|(_, l)| *l).collect::<Vec<_>>().join("\n");
        let c_low = c_joined.to_ascii_lowercase();
        let has_classic_kex =
            has_token_boundary(&c_low, "x25519") || has_token_boundary(&c_low, "ecdh");
        let has_pqc_kex = c_low.contains("ml-kem")
            || c_low.contains("ml_kem")
            || c_low.contains("mlkem")
            || has_token_boundary(&c_low, "kyber");
        if has_classic_kex && has_pqc_kex && c_low.contains("shared_secret") {
            let combiner_lines: String = chunk
                .iter()
                .map(|(_, l)| l.to_ascii_lowercase())
                .filter(|ll| {
                    ll.contains("shared_secret")
                        || ll.contains("hkdf")
                        || ll.contains("kdf(")
                        || ll.contains("concat")
                        || ll.contains("extend_from_slice")
                        || ll.contains("append")
                        || ll.contains("combine")
                })
                .collect::<Vec<_>>()
                .join("\n");

            let combiner_has_classic = combiner_lines.contains("classic")
                || combiner_lines.contains("x25519")
                || combiner_lines.contains("ecdh");
            let combiner_has_pqc = combiner_lines.contains("pqc")
                || combiner_lines.contains("kem")
                || combiner_lines.contains("kyber")
                || combiner_lines.contains("pq_");
            let combiner_has_kdf_or_concat = combiner_lines.contains("concat")
                || combiner_lines.contains("extend_from_slice")
                || combiner_lines.contains("append")
                || combiner_lines.contains("hkdf")
                || combiner_lines.contains("sha3")
                || combiner_lines.contains("kdf(");
            let drops_one = c_low.contains("only classic")
                || c_low.contains("ignore pqc")
                || !combiner_has_classic
                || !combiner_has_pqc;

            if !combiner_has_kdf_or_concat || drops_one {
                let line_no = chunk
                    .iter()
                    .find(|(_, l)| l.to_ascii_lowercase().contains("shared_secret"))
                    .map(|(n, _)| *n)
                    .unwrap_or(1);
                findings.push(LocalStaticFinding {
                    rule_id: "SMG-PQC-HYBRID".into(),
                    severity: "HIGH".into(),
                    title: "Hybrid post-quantum handshake does not bind both classical and ML-KEM shared secrets inside KDF".into(),
                    rel_path: rel_path.into(),
                    line: line_no,
                    symbol: "hybrid_kdf_combiner".into(),
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Derive session keys via domain-separated KDF(K_classic || K_pqc || ct_pqc || pk_pqc) combining both secrets.".into(),
                });
            }
        }
    }

    // 1b. Legacy TLS <= 1.2 protocol pinning (TLS 1.2 lacks IETF hybrid ML-KEM key-share support)
    for (line_no, line) in filtered_lines {
        let ll = line.to_ascii_lowercase();
        let is_legacy_tls = ll.contains("versiontls12")
            || ll.contains("versiontls11")
            || ll.contains("versiontls10")
            || ll.contains("protocol_tlsv1_2")
            || ll.contains("tlsv1.2")
            || ll.contains("sslprotocol::tls1_2");
        let is_disabled = ll.contains("disable")
            || ll.contains("reject")
            || ll.contains("forbid")
            || ll.contains("= false");
        if is_legacy_tls && !is_disabled {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-PQC-DOWNGRADE".into(),
                severity: "HIGH".into(),
                title: "Legacy TLS <= 1.2 protocol configuration blocks hybrid post-quantum key exchange (`X25519MLKEM768` requires TLS 1.3)".into(),
                rel_path: rel_path.into(),
                line: *line_no,
                symbol: "legacy_tls_version".into(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Enforce TLS 1.3 minimum (`TLSv1.3` / `VersionTLS13`) with hybrid `X25519MLKEM768` key agreement.".into(),
            });
        }
    }

    // 2. Silent classic downgrade fallback inside handshake / TLS / KEX negotiation
    let mentions_pqc = low.contains("ml-kem")
        || low.contains("ml_kem")
        || low.contains("mlkem")
        || has_token_boundary(&low, "pqc")
        || has_token_boundary(&low, "kyber");
    for (line_no, line) in filtered_lines {
        let ll = line.to_ascii_lowercase();
        let has_downgrade_kw = ll.contains("fallback") || ll.contains("downgrade");
        let mentions_classical = has_ident_word(&ll, "rsa")
            || has_ident_word(&ll, "x25519")
            || has_ident_word(&ll, "ecdsa")
            || has_ident_word(&ll, "classic");
        let is_negated_or_disabled = ll.contains("deny")
            || ll.contains("reject")
            || ll.contains("disallow")
            || ll.contains("forbid")
            || ll.contains("prevent")
            || ll.contains("disable")
            || ll.contains("never")
            || ll.contains("= false")
            || ll.contains(": false")
            || ll.contains("return err")
            || ll.contains("bail!(")
            || ll.contains("panic!(");
        if has_downgrade_kw && mentions_classical && mentions_pqc && !is_negated_or_disabled {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-PQC-DOWNGRADE".into(),
                severity: "HIGH".into(),
                title: "Silent fallback from post-quantum hybrid handshake to classical key exchange/signature detected".into(),
                rel_path: rel_path.into(),
                line: *line_no,
                symbol: "pqc_downgrade_path".into(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Enforce fail-closed PQC policy rejection rather than silently downgrading to classical RSA/ECDH.".into(),
            });
        }

        // 3. Insecure RNG / weak seed passed into PQC keygen or encapsulation
        let is_pqc_call = ll.contains("ml_kem")
            || ll.contains("ml_dsa")
            || ll.contains("mlkem")
            || ll.contains("kyber")
            || ll.contains("dilithium");
        let has_bare_rand_call = has_boundary_match(&ll, "rand", true)
            && ll.contains("rand()")
            && !ll.contains("os_rand")
            && !ll.contains("secure_rand")
            && !ll.contains("crypto_rand");
        let weak_seed = ll.contains("math.random")
            || has_bare_rand_call
            || ll.contains("thread_rng_seed")
            || ll.contains("seed_from_u64")
            || ll.contains("0u8; 32]")
            || ll.contains("0x00; 32]")
            || ll.contains("mt_rand(");
        if is_pqc_call && weak_seed {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-PQC-PARAMS".into(),
                severity: "CRITICAL".into(),
                title: "Non-CSPRNG or hardcoded deterministic seed supplied to post-quantum keygen/encapsulation".into(),
                rel_path: rel_path.into(),
                line: *line_no,
                symbol: "pqc_weak_seed".into(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Provide OS CSPRNG entropy (`OsRng` / `getrandom` / `crypto.randomBytes`) for ML-KEM and ML-DSA key generation.".into(),
            });
        }
    }
}

/// Scans repository source & configuration files for PQC readiness and builds static CycloneDX CBOM records.
pub fn analyze_pqc_inventory(
    files: &[IndexedFile],
    min_pq_category: u8,
) -> (Vec<LocalStaticFinding>, Vec<CryptoAssetRecord>) {
    let mut raw_findings = Vec::new();
    let mut assets = Vec::new();
    let mut seen_assets: HashSet<(String, String, usize)> = HashSet::new();

    for f in files {
        let low_path = f.rel_path.to_ascii_lowercase();
        if smg_core::is_test_source_path(&f.rel_path)
            || f.rel_path.ends_with(".lock")
            || low_path.ends_with("package-lock.json")
            || low_path.ends_with("pnpm-lock.yaml")
            || low_path.ends_with("go.sum")
            || low_path.contains("sbom")
        {
            continue;
        }
        let Some(raw_text) = read_text(f) else {
            continue;
        };
        let cleaned = strip_comments_simple(&raw_text);
        let mut pending_cfg_test = false;
        let mut inside_rust_cfg_test = false;
        let mut cfg_brace_depth: i32 = 0;
        let mut filtered_lines: Vec<(usize, String)> = Vec::new();
        let is_cargo_toml = f.rel_path.ends_with("Cargo.toml");
        let file_implements_mlkem_hybrid = {
            let fl = cleaned.to_ascii_lowercase();
            (fl.contains("mlkem768")
                || fl.contains("ml-kem-768")
                || fl.contains("mlkem1024")
                || fl.contains("ml-kem-1024"))
                && fl.contains("x25519")
        };
        let lines: Vec<&str> = cleaned.lines().collect();

        for (idx, &line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[cfg(test)]") {
                pending_cfg_test = true;
                if !line.contains('{') {
                    continue;
                }
            }
            if pending_cfg_test {
                if line.contains('{') {
                    inside_rust_cfg_test = true;
                    pending_cfg_test = false;
                    cfg_brace_depth = 0;
                } else if trimmed.ends_with(';') {
                    // Single-statement `#[cfg(test)] mod tests;` or `#[cfg(test)] use ...;`
                    pending_cfg_test = false;
                    continue;
                } else {
                    continue;
                }
            }
            if inside_rust_cfg_test {
                for ch in line.chars() {
                    if ch == '{' {
                        cfg_brace_depth += 1;
                    } else if ch == '}' {
                        cfg_brace_depth -= 1;
                        if cfg_brace_depth <= 0 {
                            inside_rust_cfg_test = false;
                        }
                    }
                }
                continue;
            }
            if trimmed.is_empty()
                || is_pattern_matcher_or_doc_line(line)
                || (trimmed.starts_with('"')
                    && trimmed.ends_with('"')
                    && trimmed.contains("crypto/"))
            {
                continue;
            }
            if is_cargo_toml && (trimmed.contains("features =") || trimmed.starts_with("features"))
            {
                continue;
            }

            let line_no = idx + 1;
            filtered_lines.push((line_no, line.to_string()));
            let line_low = line.to_ascii_lowercase();

            for tok in token_candidates_in_line(line) {
                let Some(strength): Option<PqSecurityStrength> = evaluate_pq_strength(tok) else {
                    continue;
                };
                let (shelf_life, hndl_urgency) = mosca_hndl_urgency_years(line, strength.family);
                if seen_assets.insert((strength.algorithm.to_string(), f.rel_path.clone(), line_no))
                {
                    assets.push(CryptoAssetRecord {
                        algorithm: strength.algorithm.to_string(),
                        oid: strength.oid.to_string(),
                        family: strength.family,
                        classical_bits: strength.classical_bits,
                        quantum_bits: strength.quantum_bits,
                        nist_category: strength.nist_category,
                        hndl_shelf_life_years: shelf_life,
                        hndl_urgency_years: hndl_urgency,
                        file: f.rel_path.clone(),
                        line: line_no,
                        detection_mode: "static-source-and-config",
                    });
                }

                // Gate 1: Shor-vulnerable asymmetric exchange/signatures with HNDL or classical dependency
                // Phase 20B: Do not flag the X25519 half of an in-file FIPS-203 hybrid ML-KEM-768/1024 + X25519 KEX.
                if strength.quantum_bits == 0
                    && !(strength.algorithm == "X25519" && file_implements_mlkem_hybrid)
                {
                    let (rule_id, sev, msg) = if hndl_urgency > 0 {
                        (
                            "SMG-PQC-HNDL",
                            "HIGH",
                            format!(
                                "Urgent HNDL exposure (T_HNDL = +{} yrs, B_PQ = 0 bits): `{}` used in long-lived confidentiality path",
                                hndl_urgency, strength.algorithm
                            ),
                        )
                    } else {
                        (
                            "SMG-PQC-SHOR",
                            "MEDIUM",
                            format!(
                                "Shor-vulnerable classical algorithm `{}` (B_PQ = 0 bits) fails post-quantum migration compliance",
                                strength.algorithm
                            ),
                        )
                    };
                    raw_findings.push(LocalStaticFinding {
                        rule_id: rule_id.into(),
                        severity: sev.into(),
                        title: msg,
                        rel_path: f.rel_path.clone(),
                        line: line_no,
                        symbol: strength.algorithm.into(),
                        sink_kind: SinkKind::Misconfiguration,
                        missing_guard: GuardKind::ConfigPolicy,
                        confidence: Confidence::Confirmed,
                        remediation: "Migrate key exchange to FIPS 203 hybrid `X25519MLKEM768` / `ML-KEM-768` and signatures to FIPS 204 `ML-DSA-65`.".into(),
                    });
                } else {
                    // `±5`-line window for HMAC/HKDF/PBKDF2 SHA-256 PRF filter (Phase 13B P13-04)
                    let win_start = idx.saturating_sub(5);
                    let win_end = (idx + 6).min(lines.len());
                    let hmac_ctx_low = lines[win_start..win_end].join(" ").to_ascii_lowercase();
                    let is_sha256_prf_or_digest = strength.algorithm == "SHA-256"
                        && (hmac_ctx_low.contains("hmac")
                            || hmac_ctx_low.contains("hkdf")
                            || hmac_ctx_low.contains("pbkdf2")
                            || line_low.contains("tls_aes_")
                            || line_low.contains("chacha20_poly1305_sha256")
                            || line_low.contains("sha256:")
                            || line_low.contains("sha256-"));
                    if strength.quantum_bits < 128 && !is_sha256_prf_or_digest {
                        // Gate 2: Grover symmetric halving / BHT collision reduction below 128-bit quantum security
                        raw_findings.push(LocalStaticFinding {
                            rule_id: "SMG-PQC-GROVER".into(),
                            severity: "MEDIUM".into(),
                            title: format!(
                                "Grover/BHT security reduction: `{}` drops to {} quantum bits (< 128-bit PQC floor)",
                                strength.algorithm, strength.quantum_bits
                            ),
                            rel_path: f.rel_path.clone(),
                            line: line_no,
                            symbol: strength.algorithm.into(),
                            sink_kind: SinkKind::Misconfiguration,
                            missing_guard: GuardKind::ConfigPolicy,
                            confidence: Confidence::Confirmed,
                            remediation: "Upgrade symmetric ciphers to AES-256 / ChaCha20-Poly1305 and hashes to SHA-384+.".into(),
                        });
                    } else if min_pq_category >= 3
                        && matches!(
                            strength.family,
                            CryptoFamily::PostQuantumKem | CryptoFamily::PostQuantumSig
                        )
                        && strength.nist_category < min_pq_category
                    {
                        // Gate 3: Sub-threshold FIPS PQC parameter set (`ML-KEM-512` / `ML-DSA-44` / `SLH-DSA-128` under Category 3+ policy)
                        raw_findings.push(LocalStaticFinding {
                            rule_id: "SMG-PQC-PARAMS".into(),
                            severity: "MEDIUM".into(),
                            title: format!(
                                "Sub-threshold PQC parameter set `{}` (NIST Cat {}) under Category {}+ policy",
                                strength.algorithm, strength.nist_category, min_pq_category
                            ),
                            rel_path: f.rel_path.clone(),
                            line: line_no,
                            symbol: strength.algorithm.into(),
                            sink_kind: SinkKind::Misconfiguration,
                            missing_guard: GuardKind::ConfigPolicy,
                            confidence: Confidence::Confirmed,
                            remediation: "Select `ML-KEM-768` / `ML-KEM-1024` or `ML-DSA-65` / `ML-DSA-87` for NIST Category 3+ assurance.".into(),
                        });
                    }
                }
            }
        }

        check_pqc_hybrid_and_downgrade(&f.rel_path, &filtered_lines, &mut raw_findings);
    }

    // Deduplicate on `(rule_id, rel_path, line)` while strictly retaining the highest severity finding
    let mut best_by_key: HashMap<(String, String, usize), usize> = HashMap::new();
    let mut findings: Vec<LocalStaticFinding> = Vec::new();
    for f in raw_findings {
        let key = (f.rule_id.clone(), f.rel_path.clone(), f.line);
        if let Some(&idx) = best_by_key.get(&key) {
            if severity_rank(&f.severity) > severity_rank(&findings[idx].severity) {
                findings[idx] = f;
            }
        } else {
            best_by_key.insert(key, findings.len());
            findings.push(f);
        }
    }

    (findings, assets)
}

/// Builds an honest partial CycloneDX 1.5 Static Source & Config Cryptography Inventory (CBOM),
/// explicitly tagging unobserved runtime cipher negotiation, FIPS providers, and KMS/HSM keys as `runtime_unobserved`.
pub fn build_static_cbom_cyclonedx(
    project_root: &Path,
    assets: &[CryptoAssetRecord],
    certificates: &[crate::x509::X509CertRecord],
) -> String {
    let proj_name = project_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repository");
    let mut hasher = blake3::Hasher::new();
    hasher.update(proj_name.as_bytes());
    for a in assets {
        hasher.update(a.algorithm.as_bytes());
        hasher.update(a.file.as_bytes());
        hasher.update(&a.line.to_le_bytes());
    }
    for c in certificates {
        hasher.update(c.sig_oid.as_bytes());
        hasher.update(c.file.as_bytes());
    }
    let digest = hasher.finalize().to_hex().to_string();

    let mut components: Vec<serde_json::Value> = assets
        .iter()
        .enumerate()
        .map(|(i, a)| {
            json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto-{}-{}", a.algorithm, i + 1),
                "name": a.algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "oid": a.oid,
                    "algorithmProperties": {
                        "primitive": a.family.cyclonedx_primitive(),
                        "classicalSecurityLevel": a.classical_bits,
                        "nistQuantumSecurityLevel": a.nist_category,
                        "effectiveQuantumBits": a.quantum_bits,
                        "moscaHndlUrgencyYears": a.hndl_urgency_years,
                        "estimatedShelfLifeYears": a.hndl_shelf_life_years
                    }
                },
                "properties": [
                    { "name": "smg:effective_quantum_bits", "value": a.quantum_bits.to_string() },
                    { "name": "smg:mosca_hndl_urgency_years", "value": a.hndl_urgency_years.to_string() },
                    { "name": "smg:estimated_shelf_life_years", "value": a.hndl_shelf_life_years.to_string() }
                ],
                "evidence": {
                    "occurrences": [{
                        "location": format!("{}:{}", a.file, a.line)
                    }]
                }
            })
        })
        .collect();

    for (i, c) in certificates.iter().enumerate() {
        components.push(json!({
            "type": "cryptographic-asset",
            "bom-ref": format!("cert-{}-{}", i + 1, c.chain_index),
            "name": format!("{}#{}", c.file, c.chain_index),
            "cryptoProperties": {
                "assetType": "certificate",
                "oid": c.sig_oid,
                "certificateProperties": {
                    "signatureAlgorithmRef": c.sig_algorithm,
                    "notValidAfterYear": c.not_after_year,
                    "isCa": c.is_ca,
                    "shorVulnerable": c.sig_is_shor_vulnerable
                }
            },
            "evidence": {
                "occurrences": [{ "location": c.file }]
            }
        }));
    }

    serde_json::to_string_pretty(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": { "name": proj_name, "type": "application" },
            "properties": [
                { "name": "smg:completeness", "value": "static-source-and-config-partial" },
                { "name": "smg:runtime_unobserved", "value": "true" },
                { "name": "smg:blake3_digest", "value": digest },
                {
                    "name": "smg:unobserved_surfaces",
                    "value": "Runtime-negotiated TLS/QUIC cipher suites; OS OpenSSL/BoringSSL FIPS provider overrides; Live Cloud KMS/HSM hardware-resident keys; Dynamic runtime X.509 certificate chains"
                }
            ]
        },
        "runtimeUnobserved": true,
        "unobservedSurfaces": [
            "Runtime-negotiated TLS/QUIC cipher suites",
            "OS OpenSSL / BoringSSL FIPS provider overrides",
            "Live Cloud KMS / HSM hardware-resident keys",
            "Dynamic runtime X.509 certificate chains"
        ],
        "components": components
    }))
    .unwrap_or_else(|_| "{}".into())
}
