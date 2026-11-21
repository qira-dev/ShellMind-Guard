//! Phase 30A: Pure-Rust X.509 DER Deep Inspector, STARTTLS Negotiator (SMTP/IMAP/FTP),
//! and ELF Binary Crypto Symbol Scanner.

use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Summary of an inspected X.509 DER certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerCertAudit {
    pub has_sha1_sig: bool,
    pub has_md5_sig: bool,
    pub has_pqc_ml_dsa: bool,
    pub has_pqc_slh_dsa: bool,
    pub has_san_extension: bool,
    pub has_wildcard_san: bool,
    pub not_after_year: Option<u32>,
    pub expired: bool,
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Inspects a raw ASN.1 DER-encoded X.509 certificate for weak signatures (MD5/SHA-1),
/// NIST PQC signature OIDs (ML-DSA / SLH-DSA), SAN presence/wildcards, and expiry against `current_year`.
pub fn inspect_x509_der(
    rel_path: &str,
    der: &[u8],
    current_year: u32,
) -> (DerCertAudit, Vec<LocalStaticFinding>) {
    // Standard DER-encoded OID bytes:
    // sha1WithRSAEncryption: 1.2.840.113549.1.1.5
    const OID_SHA1_RSA: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    // ecdsa-with-SHA1: 1.2.840.10045.4.1
    const OID_SHA1_ECDSA: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
    // md5WithRSAEncryption: 1.2.840.113549.1.1.4
    const OID_MD5_RSA: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04];
    // NIST ML-DSA-44/65/87: 2.16.840.1.101.3.4.3.{17,18,19}
    const OID_ML_DSA_PREFIX: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    // Subject Alternative Name extension: 2.5.29.17
    const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];

    let has_sha1_sig = contains_subslice(der, OID_SHA1_RSA) || contains_subslice(der, OID_SHA1_ECDSA);
    let has_md5_sig = contains_subslice(der, OID_MD5_RSA);
    let has_san_extension = contains_subslice(der, OID_SAN);
    let has_wildcard_san = has_san_extension && contains_subslice(der, b"*.");

    let mut has_pqc_ml_dsa = false;
    let mut has_pqc_slh_dsa = false;
    for w in der.windows(OID_ML_DSA_PREFIX.len() + 1) {
        if &w[..OID_ML_DSA_PREFIX.len()] == OID_ML_DSA_PREFIX {
            let last = w[OID_ML_DSA_PREFIX.len()];
            if (17..=19).contains(&last) {
                has_pqc_ml_dsa = true;
            } else if (20..=31).contains(&last) {
                has_pqc_slh_dsa = true;
            }
        }
    }

    // Parse UTCTime (tag 0x17, YYMMDDHHMMSSZ) and GeneralizedTime (tag 0x18, YYYYMMDDHHMMSSZ)
    let mut years: Vec<u32> = Vec::new();
    let mut i = 0usize;
    while i + 2 < der.len() {
        let tag = der[i];
        let len = der[i + 1] as usize;
        if tag == 0x17 && len == 13 && i + 2 + len <= der.len() {
            let slice = &der[i + 2..i + 2 + len];
            if slice[12] == b'Z' && slice[..12].iter().all(|b| b.is_ascii_digit()) {
                let yy: u32 = ((slice[0] - b'0') as u32) * 10 + ((slice[1] - b'0') as u32);
                let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
                years.push(yyyy);
                i += 2 + len;
                continue;
            }
        } else if tag == 0x18 && len == 15 && i + 2 + len <= der.len() {
            let slice = &der[i + 2..i + 2 + len];
            if slice[14] == b'Z'
                && slice[..14].iter().all(|b| b.is_ascii_digit())
                && let Ok(s) = std::str::from_utf8(&slice[..4])
                && let Ok(yyyy) = s.parse::<u32>()
            {
                years.push(yyyy);
                i += 2 + len;
                continue;
            }
        }
        i += 1;
    }

    // The second timestamp in Validity SEQUENCE is `notAfter`
    let not_after_year = if years.len() >= 2 {
        Some(years[1])
    } else {
        years.first().copied()
    };
    let expired = not_after_year.is_some_and(|y| y < current_year);

    let mut findings = Vec::new();
    if has_md5_sig || has_sha1_sig {
        let alg = if has_md5_sig { "MD5" } else { "SHA-1" };
        findings.push(LocalStaticFinding {
            rule_id: "SMG-X509-WEAK-SIG".into(),
            severity: "CRITICAL".into(),
            title: format!(
                "X.509 DER certificate uses deprecated collision-prone `{alg}` signature algorithm"
            ),
            rel_path: rel_path.to_string(),
            line: 1,
            symbol: alg.into(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::ConfigPolicy,
            confidence: Confidence::Proven,
            remediation: "Re-issue the certificate with SHA-256/SHA-384 ECDSA or NIST PQC ML-DSA-65/87.".into(),
        });
    }
    if expired {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-X509-EXPIRED".into(),
            severity: "HIGH".into(),
            title: format!(
                "X.509 DER certificate expired (notAfter year {} < current year {current_year})",
                not_after_year.unwrap_or(0)
            ),
            rel_path: rel_path.to_string(),
            line: 1,
            symbol: "notAfter".into(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::ConfigPolicy,
            confidence: Confidence::Proven,
            remediation: "Rotate the expired X.509 certificate and enable automated ACME/PKI renewal.".into(),
        });
    }
    if !has_san_extension {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-X509-NO-SAN".into(),
            severity: "MEDIUM".into(),
            title: "X.509 DER certificate omits Subject Alternative Name (SAN) extension (RFC 6125 violation)".into(),
            rel_path: rel_path.to_string(),
            line: 1,
            symbol: "SAN".into(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::ConfigPolicy,
            confidence: Confidence::Confirmed,
            remediation: "Include explicit DNS/IP Subject Alternative Name (OID 2.5.29.17) entries instead of relying on CN.".into(),
        });
    }

    let audit = DerCertAudit {
        has_sha1_sig,
        has_md5_sig,
        has_pqc_ml_dsa,
        has_pqc_slh_dsa,
        has_san_extension,
        has_wildcard_san,
        not_after_year,
        expired,
    };
    (audit, findings)
}

/// STARTTLS application protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTlsProtocol {
    Smtp,
    Imap,
    Ftp,
}

/// Performs a pure-Rust plaintext STARTTLS upgrade handshake on an open `TcpStream`
/// so a subsequent TLS handshake can audit SMTP (25/587), IMAP (143), or FTP (21).
pub fn negotiate_starttls(
    stream: &mut TcpStream,
    proto: StartTlsProtocol,
    timeout: Duration,
) -> std::io::Result<bool> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    match proto {
        StartTlsProtocol::Smtp => {
            // Read 220 banner
            reader.read_line(&mut line)?;
            if !line.starts_with("220") {
                return Ok(false);
            }
            stream.write_all(b"EHLO smg-tls-audit.local\r\n")?;
            stream.flush()?;
            // Drain multi-line 250- responses until 250<space>
            let mut supports_starttls = false;
            for _ in 0..32 {
                line.clear();
                if reader.read_line(&mut line)? == 0 {
                    break;
                }
                if line.to_ascii_uppercase().contains("STARTTLS") {
                    supports_starttls = true;
                }
                if line.starts_with("250 ") {
                    break;
                }
            }
            if !supports_starttls {
                return Ok(false);
            }
            stream.write_all(b"STARTTLS\r\n")?;
            stream.flush()?;
            line.clear();
            reader.read_line(&mut line)?;
            Ok(line.starts_with("220"))
        }
        StartTlsProtocol::Imap => {
            reader.read_line(&mut line)?;
            if !line.starts_with("* OK") {
                return Ok(false);
            }
            stream.write_all(b"a001 STARTTLS\r\n")?;
            stream.flush()?;
            line.clear();
            reader.read_line(&mut line)?;
            Ok(line.to_ascii_uppercase().contains("A001 OK"))
        }
        StartTlsProtocol::Ftp => {
            reader.read_line(&mut line)?;
            if !line.starts_with("220") {
                return Ok(false);
            }
            stream.write_all(b"AUTH TLS\r\n")?;
            stream.flush()?;
            line.clear();
            reader.read_line(&mut line)?;
            Ok(line.starts_with("234"))
        }
    }
}

/// Summary of crypto symbols discovered inside a compiled ELF binary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElfCryptoAudit {
    pub is_elf: bool,
    pub broken_symbols: Vec<String>,
    pub quantum_vulnerable_symbols: Vec<String>,
    pub pqc_symbols: Vec<String>,
}

/// Scans an ELF (`\x7fELF`) binary's symbol/string sections for broken legacy crypto
/// (MD5/SHA-1/DES/RC4), quantum-vulnerable public-key crypto (RSA/ECDSA/DH), and PQC readiness.
pub fn scan_elf_crypto_symbols(
    rel_path: &str,
    bytes: &[u8],
) -> (ElfCryptoAudit, Vec<LocalStaticFinding>) {
    if bytes.len() < 16 || &bytes[0..4] != b"\x7fELF" {
        return (ElfCryptoAudit::default(), Vec::new());
    }

    const BROKEN_SYMS: &[&str] = &[
        "EVP_md5",
        "MD5_Init",
        "EVP_sha1",
        "SHA1_Init",
        "DES_ecb_encrypt",
        "RC4_set_key",
        "EVP_rc4",
    ];
    const QUANTUM_VULN_SYMS: &[&str] = &[
        "RSA_generate_key",
        "RSA_public_encrypt",
        "EC_KEY_new",
        "ECDSA_sign",
        "DH_generate_key",
    ];
    const PQC_SYMS: &[&str] = &[
        "OQS_KEM_",
        "OQS_SIG_",
        "EVP_PKEY_ML_KEM",
        "EVP_PKEY_ML_DSA",
        "MLKEM768",
        "MLDSA65",
    ];

    let mut audit = ElfCryptoAudit {
        is_elf: true,
        ..Default::default()
    };
    for sym in BROKEN_SYMS {
        if contains_subslice(bytes, sym.as_bytes()) {
            audit.broken_symbols.push((*sym).to_string());
        }
    }
    for sym in QUANTUM_VULN_SYMS {
        if contains_subslice(bytes, sym.as_bytes()) {
            audit.quantum_vulnerable_symbols.push((*sym).to_string());
        }
    }
    for sym in PQC_SYMS {
        if contains_subslice(bytes, sym.as_bytes()) {
            audit.pqc_symbols.push((*sym).to_string());
        }
    }

    let mut findings = Vec::new();
    if !audit.broken_symbols.is_empty() {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-ELF-BROKEN-CRYPTO".into(),
            severity: "HIGH".into(),
            title: format!(
                "ELF binary links broken legacy cryptographic symbols: {}",
                audit.broken_symbols.join(", ")
            ),
            rel_path: rel_path.to_string(),
            line: 1,
            symbol: audit.broken_symbols[0].clone(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::ConfigPolicy,
            confidence: Confidence::Proven,
            remediation: "Eliminate MD5/SHA-1/DES/RC4 symbol dependencies and migrate to SHA-256/SHA-3 + AES-256-GCM.".into(),
        });
    }
    if !audit.quantum_vulnerable_symbols.is_empty() && audit.pqc_symbols.is_empty() {
        findings.push(LocalStaticFinding {
            rule_id: "SMG-ELF-QUANTUM-VULN".into(),
            severity: "MEDIUM".into(),
            title: format!(
                "ELF binary links quantum-vulnerable asymmetric crypto ({}) without PQC hybrid symbols",
                audit.quantum_vulnerable_symbols.join(", ")
            ),
            rel_path: rel_path.to_string(),
            line: 1,
            symbol: audit.quantum_vulnerable_symbols[0].clone(),
            sink_kind: SinkKind::Misconfiguration,
            missing_guard: GuardKind::ConfigPolicy,
            confidence: Confidence::Confirmed,
            remediation: "Adopt hybrid PQC KEM/signatures (ML-KEM-768 / ML-DSA-65) to mitigate Harvest-Now-Decrypt-Later exposure.".into(),
        });
    }

    (audit, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_x509_der_sha1_expiry_no_san_and_pqc_ml_dsa() {
        // Synthetic DER payload with SHA-1 RSA OID + expired UTCTime (2020 -> 2022) + no SAN
        let mut expired_sha1 = Vec::new();
        expired_sha1.extend_from_slice(&[0x30, 0x40]);
        expired_sha1.extend_from_slice(&[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
        ]);
        expired_sha1.extend_from_slice(&[0x17, 0x0D]);
        expired_sha1.extend_from_slice(b"200101000000Z");
        expired_sha1.extend_from_slice(&[0x17, 0x0D]);
        expired_sha1.extend_from_slice(b"220101000000Z");

        let (audit, findings) = inspect_x509_der("certs/legacy.der", &expired_sha1, 2026);
        assert!(audit.has_sha1_sig);
        assert!(audit.expired);
        assert!(!audit.has_san_extension);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"SMG-X509-WEAK-SIG"));
        assert!(ids.contains(&"SMG-X509-EXPIRED"));
        assert!(ids.contains(&"SMG-X509-NO-SAN"));

        // Hardened PQC ML-DSA-65 cert with SAN and future validity (2025 -> 2030)
        let mut pqc_cert = Vec::new();
        pqc_cert.extend_from_slice(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 18,
        ]);
        pqc_cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11]);
        pqc_cert.extend_from_slice(&[0x17, 0x0D]);
        pqc_cert.extend_from_slice(b"250101000000Z");
        pqc_cert.extend_from_slice(&[0x17, 0x0D]);
        pqc_cert.extend_from_slice(b"300101000000Z");

        let (pqc_audit, pqc_findings) = inspect_x509_der("certs/pqc.der", &pqc_cert, 2026);
        assert!(pqc_audit.has_pqc_ml_dsa);
        assert!(pqc_audit.has_san_extension);
        assert!(!pqc_audit.expired);
        assert!(pqc_findings.is_empty(), "{pqc_findings:?}");
    }

    #[test]
    fn scans_elf_binary_crypto_symbols() {
        let mut elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        elf.extend_from_slice(b"\0EVP_md5\0RSA_generate_key\0");
        let (audit, findings) = scan_elf_crypto_symbols("bin/legacy_daemon", &elf);
        assert!(audit.is_elf);
        assert_eq!(audit.broken_symbols, vec!["EVP_md5"]);
        assert_eq!(audit.quantum_vulnerable_symbols, vec!["RSA_generate_key"]);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"SMG-ELF-BROKEN-CRYPTO"));
        assert!(ids.contains(&"SMG-ELF-QUANTUM-VULN"));
    }
}
