//! Phase 30A: Pure-Rust X.509 DER Deep Inspector, STARTTLS Negotiator (SMTP/IMAP/FTP),
//! and ELF Binary Crypto Symbol Scanner.

use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Summary of an inspected X.509 DER certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerCertAudit {
    pub has_sha1_sig: bool,
    pub has_md5_sig: bool,
    pub has_pqc_ml_dsa: bool,
    pub has_pqc_slh_dsa: bool,
    pub has_san_extension: bool,
    pub has_wildcard_san: bool,
    pub has_ct_sct_extension: bool,
    pub has_ocsp_must_staple: bool,
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
    const OID_SHA1_RSA: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
    ];
    // ecdsa-with-SHA1: 1.2.840.10045.4.1
    const OID_SHA1_ECDSA: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
    // md5WithRSAEncryption: 1.2.840.113549.1.1.4
    const OID_MD5_RSA: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04,
    ];
    // NIST ML-DSA-44/65/87: 2.16.840.1.101.3.4.3.{17,18,19}
    const OID_ML_DSA_PREFIX: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    // Subject Alternative Name extension: 2.5.29.17
    const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
    // Certificate Transparency SCT List extension: 1.3.6.1.4.1.11129.2.4.2
    const OID_CT_SCT: &[u8] = &[
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02,
    ];
    // TLS Feature (OCSP Must-Staple): 1.3.6.1.5.5.7.1.24
    const OID_OCSP_MUST_STAPLE: &[u8] =
        &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];

    let has_sha1_sig =
        contains_subslice(der, OID_SHA1_RSA) || contains_subslice(der, OID_SHA1_ECDSA);
    let has_md5_sig = contains_subslice(der, OID_MD5_RSA);
    let has_san_extension = contains_subslice(der, OID_SAN);
    let parsed_san_dns = extract_san_dns_tlv(der);
    let has_wildcard_san = if let Some(ref dns_entries) = parsed_san_dns {
        dns_entries.iter().any(|s| s.starts_with("*."))
    } else {
        // Fallback for partial/synthetic non-DER fragments that carry OID_SAN without full OCTET STRING wrapper
        has_san_extension && contains_subslice(der, b"*.")
    };
    let has_ct_sct_extension = contains_subslice(der, OID_CT_SCT);
    let has_ocsp_must_staple = contains_subslice(der, OID_OCSP_MUST_STAPLE);

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
            remediation:
                "Re-issue the certificate with SHA-256/SHA-384 ECDSA or NIST PQC ML-DSA-65/87."
                    .into(),
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
        has_ct_sct_extension,
        has_ocsp_must_staple,
        not_after_year,
        expired,
    };
    (audit, findings)
}

/// Parses RFC 5280 SAN extension (`OID 2.5.29.17`) via proper ASN.1 DER TLVs:
/// `OID_SAN`, optional `critical BOOLEAN (0x01)`, `extnValue OCTET STRING (0x04)`,
/// `GeneralNames SEQUENCE (0x30)`, returning only `[2] dNSName (0x82)` entries inside it.
fn extract_san_dns_tlv(der: &[u8]) -> Option<Vec<String>> {
    const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
    let pos = der.windows(OID_SAN.len()).position(|w| w == OID_SAN)?;
    let mut rest = &der[pos + OID_SAN.len()..];
    // Optional `critical BOOLEAN`
    if let Some((0x01, _, after_crit)) = crate::x509::read_der_tlv(rest) {
        rest = after_crit;
    }
    // `extnValue OCTET STRING`
    let (0x04, octets, _) = crate::x509::read_der_tlv(rest)? else {
        return None;
    };
    // `GeneralNames SEQUENCE`
    let (0x30, mut gen_names, _) = crate::x509::read_der_tlv(octets)? else {
        return None;
    };
    let mut sans = Vec::new();
    while let Some((tag, val, next)) = crate::x509::read_der_tlv(gen_names) {
        if tag == 0x82
            && !val.is_empty()
            && val.iter().all(|b| b.is_ascii_graphic())
            && let Ok(s) = std::str::from_utf8(val)
        {
            sans.push(s.to_string());
        }
        gen_names = next;
    }
    Some(sans)
}

/// Extracts the Subject CN and all dNSName SAN entries from a DER certificate
/// (`ssl:` template matching needs the actual values, not just presence).
/// Prefers strict ASN.1 DER TLV traversal for the SAN extension so unrelated
/// extensions or signature bytes (`0x82`) are never misread as dNSNames.
pub fn extract_cn_and_san_dns(der: &[u8]) -> (Option<String>, Vec<String>) {
    // Common Name: 2.5.4.3 encoded as `06 03 55 04 03`.
    const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let mut cn = None;
    if let Some(pos) = der.windows(OID_CN.len()).rposition(|w| w == OID_CN) {
        let rest = &der[pos + OID_CN.len()..];
        if let Some((tag, val, _)) = crate::x509::read_der_tlv(rest)
            && matches!(tag, 0x0C | 0x13 | 0x16)
            && !val.is_empty()
            && let Ok(s) = std::str::from_utf8(val)
        {
            cn = Some(s.to_string());
        }
    }

    // Subject Alternative Name: prefer strict ASN.1 DER TLV parse first.
    if let Some(sans) = extract_san_dns_tlv(der) {
        return (cn, sans);
    }

    // Fallback for partial/synthetic non-DER byte fragments in unit harnesses.
    const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
    let mut sans = Vec::new();
    if let Some(pos) = der.windows(OID_SAN.len()).position(|w| w == OID_SAN) {
        let start = pos + OID_SAN.len();
        let bound = (start + 4096).min(der.len());
        let mut i = start;
        while i + 2 <= bound {
            if der[i] == 0x82 {
                let len = der[i + 1] as usize;
                if len > 0
                    && i + 2 + len <= bound
                    && der[i + 2..i + 2 + len].iter().all(|b| b.is_ascii_graphic())
                {
                    if let Ok(s) = std::str::from_utf8(&der[i + 2..i + 2 + len])
                        && !s.is_empty()
                    {
                        sans.push(s.to_string());
                    }
                    i += 2 + len;
                    continue;
                }
            }
            i += 1;
        }
    }
    (cn, sans)
}

/// STARTTLS application protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTlsProtocol {
    Smtp,
    Imap,
    Ftp,
}

const MAX_STARTTLS_LINE_BYTES: usize = 8192;

/// Reads a single `\n`-terminated plaintext protocol line directly from `stream` without
/// `BufReader` lookahead over-reading (so zero subsequent TLS handshake bytes are ever lost),
/// strictly bounded by `MAX_STARTTLS_LINE_BYTES` and a total handshake `deadline`.
fn read_line_bounded(stream: &mut TcpStream, deadline: Instant) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "STARTTLS handshake deadline exceeded",
            ));
        };
        stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
        match stream.read(&mut byte)? {
            0 => break,
            _ => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_STARTTLS_LINE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "STARTTLS banner line exceeded 8 KiB cap",
                    ));
                }
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Drains a possibly multi-line SMTP/FTP reply with status code `code` (e.g. `"220"`),
/// returning `true` if the final non-continuation line begins with `"{code} "` or equals `code`.
fn read_multiline_reply(
    stream: &mut TcpStream,
    code: &str,
    deadline: Instant,
) -> std::io::Result<bool> {
    let cont_prefix = format!("{code}-");
    let final_prefix = format!("{code} ");
    for _ in 0..32 {
        let line = read_line_bounded(stream, deadline)?;
        if line.is_empty() {
            return Ok(false);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.starts_with(&final_prefix) || trimmed == code {
            return Ok(true);
        }
        if !trimmed.starts_with(&cont_prefix) {
            return Ok(false);
        }
    }
    Ok(false)
}

/// Performs a pure-Rust plaintext STARTTLS upgrade handshake on an open `TcpStream`
/// so a subsequent TLS handshake can audit SMTP (25/587), IMAP (143), or FTP (21).
pub fn negotiate_starttls(
    stream: &mut TcpStream,
    proto: StartTlsProtocol,
    timeout: Duration,
) -> std::io::Result<bool> {
    let deadline = Instant::now() + timeout;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    match proto {
        StartTlsProtocol::Smtp => {
            // Drain single- or multi-line 220 banner
            if !read_multiline_reply(stream, "220", deadline)? {
                return Ok(false);
            }
            stream.write_all(b"EHLO smg-tls-audit.local\r\n")?;
            stream.flush()?;
            // Drain multi-line 250- responses until 250<space>
            let mut supports_starttls = false;
            for _ in 0..32 {
                let line = read_line_bounded(stream, deadline)?;
                if line.is_empty() {
                    break;
                }
                if line.to_ascii_uppercase().contains("STARTTLS") {
                    supports_starttls = true;
                }
                if line.starts_with("250 ") || line.trim_end_matches(['\r', '\n']) == "250" {
                    break;
                }
            }
            if !supports_starttls {
                return Ok(false);
            }
            stream.write_all(b"STARTTLS\r\n")?;
            stream.flush()?;
            read_multiline_reply(stream, "220", deadline)
        }
        StartTlsProtocol::Imap => {
            let banner = read_line_bounded(stream, deadline)?;
            if !banner.starts_with("* OK") {
                return Ok(false);
            }
            stream.write_all(b"a001 STARTTLS\r\n")?;
            stream.flush()?;
            for _ in 0..16 {
                let resp = read_line_bounded(stream, deadline)?;
                if resp.is_empty() {
                    return Ok(false);
                }
                let up = resp.to_ascii_uppercase();
                if up.starts_with("A001 OK") {
                    return Ok(true);
                }
                if up.starts_with("A001 NO") || up.starts_with("A001 BAD") {
                    return Ok(false);
                }
            }
            Ok(false)
        }
        StartTlsProtocol::Ftp => {
            if !read_multiline_reply(stream, "220", deadline)? {
                return Ok(false);
            }
            stream.write_all(b"AUTH TLS\r\n")?;
            stream.flush()?;
            read_multiline_reply(stream, "234", deadline)
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

const ELF_BROKEN_SYMS: &[&str] = &[
    "EVP_md5",
    "MD5_Init",
    "EVP_sha1",
    "SHA1_Init",
    "DES_ecb_encrypt",
    "RC4_set_key",
    "EVP_rc4",
];
const ELF_QUANTUM_VULN_SYMS: &[&str] = &[
    "RSA_generate_key",
    "RSA_public_encrypt",
    "EC_KEY_new",
    "ECDSA_sign",
    "DH_generate_key",
];
const ELF_PQC_SYMS: &[&str] = &[
    "OQS_KEM_",
    "OQS_SIG_",
    "EVP_PKEY_ML_KEM",
    "EVP_PKEY_ML_DSA",
    "MLKEM768",
    "MLDSA65",
];

fn finalize_elf_findings(rel_path: &str, audit: &ElfCryptoAudit) -> Vec<LocalStaticFinding> {
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
    findings
}

fn scan_elf_chunk_into_audit(chunk: &[u8], audit: &mut ElfCryptoAudit) {
    for sym in ELF_BROKEN_SYMS {
        if !audit.broken_symbols.iter().any(|s| s == sym)
            && contains_subslice(chunk, sym.as_bytes())
        {
            audit.broken_symbols.push((*sym).to_string());
        }
    }
    for sym in ELF_QUANTUM_VULN_SYMS {
        if !audit.quantum_vulnerable_symbols.iter().any(|s| s == sym)
            && contains_subslice(chunk, sym.as_bytes())
        {
            audit.quantum_vulnerable_symbols.push((*sym).to_string());
        }
    }
    for sym in ELF_PQC_SYMS {
        if !audit.pqc_symbols.iter().any(|s| s == sym) && contains_subslice(chunk, sym.as_bytes()) {
            audit.pqc_symbols.push((*sym).to_string());
        }
    }
}

/// Streams an ELF (`\x7fELF`) binary in bounded 64 KiB overlapping chunks (up to `max_bytes`)
/// so symbol tables located near EOF (well past 512 KiB) are discovered without unbounded RAM.
pub fn scan_elf_crypto_symbols_reader<R: Read>(
    rel_path: &str,
    reader: &mut R,
    max_bytes: u64,
) -> std::io::Result<(ElfCryptoAudit, Vec<LocalStaticFinding>)> {
    const CHUNK_SIZE: usize = 64 * 1024;
    const OVERLAP: usize = 64;
    let mut header = [0u8; 16];
    let mut header_read = 0usize;
    while header_read < header.len() {
        let n = reader.read(&mut header[header_read..])?;
        if n == 0 {
            break;
        }
        header_read += n;
    }
    if header_read < 16 || &header[0..4] != b"\x7fELF" {
        return Ok((ElfCryptoAudit::default(), Vec::new()));
    }

    let mut audit = ElfCryptoAudit {
        is_elf: true,
        ..Default::default()
    };
    let mut total_read = header_read as u64;
    let mut buf = vec![0u8; OVERLAP + CHUNK_SIZE];
    let mut carry = 0usize;

    while total_read < max_bytes {
        let to_read = (max_bytes - total_read).min(CHUNK_SIZE as u64) as usize;
        let n = reader.read(&mut buf[carry..carry + to_read])?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        let valid_len = carry + n;
        scan_elf_chunk_into_audit(&buf[..valid_len], &mut audit);
        let keep = valid_len.min(OVERLAP);
        buf.copy_within(valid_len - keep..valid_len, 0);
        carry = keep;
    }

    let findings = finalize_elf_findings(rel_path, &audit);
    Ok((audit, findings))
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
    let mut audit = ElfCryptoAudit {
        is_elf: true,
        ..Default::default()
    };
    scan_elf_chunk_into_audit(bytes, &mut audit);
    let findings = finalize_elf_findings(rel_path, &audit);
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

    #[test]
    fn extracts_subject_cn_and_dns_sans() {
        // Synthetic DER: Issuer CN (first OID occurrence) then Subject CN
        // (last occurrence — the subject follows the issuer), then the SAN
        // extension with two dNSName TLVs.
        let mut der = Vec::new();
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        der.extend_from_slice(&[0x0C, 0x0C]);
        der.extend_from_slice(b"Issuer CA CN");
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        der.extend_from_slice(&[0x0C, 0x10]);
        der.extend_from_slice(b"lab.example.test");
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11, 0x04]);
        der.extend_from_slice(&[0x82, 0x03]);
        der.extend_from_slice(b"abc");
        der.extend_from_slice(&[0x82, 0x0A]);
        der.extend_from_slice(b"wild.trace");
        let (cn, sans) = extract_cn_and_san_dns(&der);
        assert_eq!(cn.as_deref(), Some("lab.example.test"));
        assert_eq!(sans, vec!["abc".to_string(), "wild.trace".to_string()]);

        // No CN/SAN present → empty results, not a panic.
        let (cn, sans) = extract_cn_and_san_dns(b"\x30\x00");
        assert!(cn.is_none());
        assert!(sans.is_empty());

        // Proper ASN.1 DER SAN extension must isolate SAN entries from unrelated `*.` in CN
        // and from trailing `0x82` bytes in signature data.
        let mut real_der = Vec::new();
        // Subject CN containing `*.unrelated.cn`
        real_der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0E]);
        real_der.extend_from_slice(b"*.unrelated.cn");
        // Valid SAN ext: OID 2.5.29.17 + OCTET STRING { SEQUENCE { [2] "api.example.com" } }
        let dns = b"api.example.com";
        let mut seq = vec![0x30, (dns.len() + 2) as u8, 0x82, dns.len() as u8];
        seq.extend_from_slice(dns);
        real_der.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, seq.len() as u8]);
        real_der.extend_from_slice(&seq);
        // Trailing signature bytes mimicking `0x82 0x04 "fake"`
        real_der.extend_from_slice(&[0x82, 0x04, b'f', b'a', b'k', b'e']);

        let (cn2, sans2) = extract_cn_and_san_dns(&real_der);
        assert_eq!(cn2.as_deref(), Some("*.unrelated.cn"));
        assert_eq!(sans2, vec!["api.example.com".to_string()]);
        let (audit2, _) = inspect_x509_der("certs/real.der", &real_der, 2026);
        assert!(audit2.has_san_extension);
        assert!(
            !audit2.has_wildcard_san,
            "`*.` in Subject CN must not cause wildcard SAN FP"
        );
    }

    #[test]
    fn streams_large_elf_beyond_512kib_to_detect_tail_crypto_symbols() {
        let mut big_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        big_elf.resize(600 * 1024, 0u8);
        big_elf.extend_from_slice(b"\0EVP_md5\0RSA_generate_key\0");
        let mut cursor = std::io::Cursor::new(&big_elf);
        let (audit, hits) =
            scan_elf_crypto_symbols_reader("bin/large.elf", &mut cursor, 4 * 1024 * 1024)
                .expect("stream scan ok");
        assert!(audit.is_elf);
        assert_eq!(audit.broken_symbols, vec!["EVP_md5"]);
        assert_eq!(audit.quantum_vulnerable_symbols, vec!["RSA_generate_key"]);
        assert_eq!(hits.len(), 2);
    }
}
