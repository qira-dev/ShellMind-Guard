//! Zero-dependency ASN.1 DER & PEM X.509 Certificate + CA Chain Analyzer (`Phase 13B P13-04`).
//!
//! Extracts exact `notAfter` validity years (for Mosca HNDL $X_u$), signature/public-key OIDs,
//! CA chain weak-root links, and CycloneDX 1.5 `"assetType": "certificate"` inventory records
//! without adding any external cryptography or X.509 dependencies.

use serde::{Deserialize, Serialize};
use smg_graph::{Confidence, GuardKind, LocalStaticFinding, SinkKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509CertRecord {
    pub file: String,
    pub chain_index: usize,
    pub sig_oid: String,
    pub sig_algorithm: String,
    pub sig_is_shor_vulnerable: bool,
    pub not_after_year: Option<u32>,
    pub remaining_years: Option<u32>,
    pub is_ca: bool,
}

/// Minimal zero-dep RFC 4648 Base64 decoder for PEM `-----BEGIN CERTIFICATE-----` blocks.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || !clean.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.as_chunks::<4>().0 {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

/// Parses a single ASN.1 DER TLV header, returning `(tag, content_slice, remaining_slice)`.
fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let &tag = data.first()?;
    let &len_byte = data.get(1)?;
    let (len, hdr_len) = if (len_byte & 0x80) == 0 {
        (len_byte as usize, 2usize)
    } else {
        let n_octets = (len_byte & 0x7f) as usize;
        if n_octets == 0 || n_octets > 4 || data.len() < 2 + n_octets {
            return None;
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n_octets] {
            l = (l << 8) | (b as usize);
        }
        (l, 2 + n_octets)
    };
    let end = hdr_len.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[hdr_len..end], &data[end..]))
}

/// Decodes an ASN.1 OBJECT IDENTIFIER content slice into dotted-decimal form (`"1.2.840..."`).
fn decode_oid(bytes: &[u8]) -> Option<String> {
    let &first = bytes.first()?;
    let arc0 = first / 40;
    let arc1 = first % 40;
    let mut out = format!("{arc0}.{arc1}");
    let mut cur: u64 = 0;
    for &b in &bytes[1..] {
        cur = (cur << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            out.push('.');
            out.push_str(&cur.to_string());
            cur = 0;
        }
    }
    Some(out)
}

/// Maps well-known X.509 signature / public-key OIDs to `(canonical_name, is_shor_vulnerable)`.
pub fn classify_x509_oid(oid: &str) -> (&'static str, bool) {
    match oid {
        "1.2.840.113549.1.1.5" => ("SHA1-with-RSA", true),
        "1.2.840.113549.1.1.11" => ("SHA256-with-RSA", true),
        "1.2.840.113549.1.1.12" => ("SHA384-with-RSA", true),
        "1.2.840.113549.1.1.13" => ("SHA512-with-RSA", true),
        "1.2.840.113549.1.1.10" => ("RSASSA-PSS", true),
        "1.2.840.113549.1.1.1" => ("RSA", true),
        "1.2.840.10045.4.3.2" => ("ECDSA-with-SHA256", true),
        "1.2.840.10045.4.3.3" => ("ECDSA-with-SHA384", true),
        "1.2.840.10045.4.3.4" => ("ECDSA-with-SHA512", true),
        "1.2.840.10045.2.1" => ("ECDSA", true),
        "1.3.101.112" => ("Ed25519", true),
        "1.3.101.113" => ("Ed448", true),
        // NIST FIPS 204 ML-DSA & FIPS 205 SLH-DSA OIDs
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44", false),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65", false),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87", false),
        "2.16.840.1.101.3.4.3.20"
        | "2.16.840.1.101.3.4.3.21"
        | "2.16.840.1.101.3.4.3.22"
        | "2.16.840.1.101.3.4.3.23"
        | "2.16.840.1.101.3.4.3.24"
        | "2.16.840.1.101.3.4.3.25" => ("SLH-DSA", false),
        _ => ("UNKNOWN-OID", false),
    }
}

fn parse_asn1_time_year(tag: u8, bytes: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(bytes).ok()?;
    if tag == 0x17 && s.len() >= 2 {
        // UTCTime: YYMMDDHHMMSSZ (RFC 5280: >=50 => 19xx, <50 => 20xx)
        let yy: u32 = s[..2].parse().ok()?;
        Some(if yy >= 50 { 1900 + yy } else { 2000 + yy })
    } else if tag == 0x18 && s.len() >= 4 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        s[..4].parse().ok()
    } else {
        None
    }
}

/// Parses a single DER-encoded X.509 certificate into `X509CertRecord`.
pub fn parse_x509_der(rel_path: &str, chain_index: usize, der: &[u8]) -> Option<X509CertRecord> {
    let (cert_tag, cert_body, _) = read_der_tlv(der)?;
    if cert_tag != 0x30 {
        return None;
    }
    let (tbs_tag, mut tbs, rest_after_tbs) = read_der_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return None;
    }

    // Outer signatureAlgorithm SEQUENCE -> first element is OID (0x06)
    let mut sig_oid = String::new();
    if let Some((0x30, alg_body, _)) = read_der_tlv(rest_after_tbs)
        && let Some((0x06, oid_bytes, _)) = read_der_tlv(alg_body)
        && let Some(decoded) = decode_oid(oid_bytes)
    {
        sig_oid = decoded;
    }

    // Walk TBSCertificate: [0] version (optional), serialNumber, signature, issuer, validity, subject, spki, [3] extensions
    if let Some((0xa0, _, after_ver)) = read_der_tlv(tbs) {
        tbs = after_ver;
    }
    // serialNumber
    let (_, _, after_serial) = read_der_tlv(tbs)?;
    // signature AlgorithmIdentifier
    let (_, sig_inner, after_sig) = read_der_tlv(after_serial)?;
    if sig_oid.is_empty()
        && let Some((0x06, oid_bytes, _)) = read_der_tlv(sig_inner)
        && let Some(decoded) = decode_oid(oid_bytes)
    {
        sig_oid = decoded;
    }
    // issuer
    let (_, _, after_issuer) = read_der_tlv(after_sig)?;
    // validity SEQUENCE { notBefore, notAfter }
    let mut not_after_year = None;
    let (val_tag, val_body, after_validity) = read_der_tlv(after_issuer)?;
    if val_tag == 0x30
        && let Some((_, _, after_nb)) = read_der_tlv(val_body)
        && let Some((na_tag, na_bytes, _)) = read_der_tlv(after_nb)
    {
        not_after_year = parse_asn1_time_year(na_tag, na_bytes);
    }

    // Detect BasicConstraints CA:TRUE (`2.5.29.19` OID `55 1d 13` followed by `01 01 ff`) in remaining TBS bytes
    let is_ca = after_validity.windows(3).any(|w| w == [0x55, 0x1d, 0x13])
        && after_validity.windows(3).any(|w| w == [0x01, 0x01, 0xff]);

    let (sig_alg, sig_shor) = classify_x509_oid(&sig_oid);
    let current_year = 2026u32;
    let remaining_years = not_after_year.map(|y| y.saturating_sub(current_year));

    Some(X509CertRecord {
        file: rel_path.to_string(),
        chain_index,
        sig_oid,
        sig_algorithm: sig_alg.to_string(),
        sig_is_shor_vulnerable: sig_shor,
        not_after_year,
        remaining_years,
        is_ca,
    })
}

/// Extracts all PEM `-----BEGIN CERTIFICATE-----` blocks in a file and parses their X.509 DER structures.
pub fn parse_pem_certificates(rel_path: &str, content: &str) -> Vec<X509CertRecord> {
    let mut out = Vec::new();
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let mut rest = content;
    let mut idx = 0usize;
    while let Some(start) = rest.find(begin_marker) {
        let after_begin = &rest[start + begin_marker.len()..];
        let Some(end) = after_begin.find(end_marker) else {
            break;
        };
        let b64 = &after_begin[..end];
        if let Some(der) = decode_base64(b64)
            && let Some(rec) = parse_x509_der(rel_path, idx, &der)
        {
            out.push(rec);
            idx += 1;
        }
        rest = &after_begin[end + end_marker.len()..];
    }
    out
}

/// Evaluates X.509 certificate chains for exact Mosca HNDL urgency ($X_u$ from `notAfter`)
/// and weak classical CA roots/intermediates beneath PQC leaf certificates.
pub fn audit_x509_chain(certs: &[X509CertRecord]) -> Vec<LocalStaticFinding> {
    let mut findings = Vec::new();
    if certs.is_empty() {
        return findings;
    }

    let has_pqc_leaf = certs
        .first()
        .is_some_and(|c| !c.sig_is_shor_vulnerable && c.sig_algorithm != "UNKNOWN-OID");

    for c in certs {
        // 1. Weak classical intermediate/root CA signing beneath a PQC leaf certificate
        if has_pqc_leaf && c.chain_index > 0 && c.sig_is_shor_vulnerable {
            findings.push(LocalStaticFinding {
                rule_id: "SMG-PQC-HNDL".into(),
                severity: "HIGH".into(),
                title: format!(
                    "X.509 chain link #{} uses Shor-vulnerable `{}` CA signature beneath PQC leaf certificate",
                    c.chain_index, c.sig_algorithm
                ),
                rel_path: c.file.clone(),
                line: 1,
                symbol: c.sig_algorithm.clone(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Migrate intermediate and root CA certificates in the trust chain to FIPS 204 `ML-DSA-65`/`ML-DSA-87` or composite PQC signatures.".into(),
            });
            continue;
        }

        // 2. Exact Mosca HNDL urgency using certificate `notAfter` remaining shelf-life `X_u`
        // (Migration Y_m = 3 yrs, Quantum Horizon Z_q = 10 yrs => urgent when X_u + 3 > 10, i.e., X_u > 7)
        if c.sig_is_shor_vulnerable {
            let x_u = c.remaining_years.unwrap_or(5);
            let sev = if x_u + 3 > 10 { "HIGH" } else { "MEDIUM" };
            findings.push(LocalStaticFinding {
                rule_id: "SMG-PQC-HNDL".into(),
                severity: sev.into(),
                title: format!(
                    "X.509 certificate #{} uses Shor-vulnerable `{}` (notAfter={}, X_u={}y)",
                    c.chain_index,
                    c.sig_algorithm,
                    c.not_after_year
                        .map(|y| y.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    x_u
                ),
                rel_path: c.file.clone(),
                line: 1,
                symbol: c.sig_algorithm.clone(),
                sink_kind: SinkKind::Misconfiguration,
                missing_guard: GuardKind::ConfigPolicy,
                confidence: Confidence::Confirmed,
                remediation: "Re-issue long-lived X.509 certificates with FIPS 204 `ML-DSA-65`/`ML-DSA-87` or shorter validity windows ahead of PQC migration.".into(),
            });
        }
    }

    findings
}
