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

/// Computes the current UTC calendar year from `SystemTime::now()` using Howard Hinnant's
/// civil-from-days algorithm (falling back to 2026 only if the system clock predates the Unix epoch).
pub fn current_utc_year() -> u32 {
    let Ok(dur) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return 2026;
    };
    let days = (dur.as_secs() / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    u32::try_from(year).unwrap_or(2026)
}

/// Parses a single ASN.1 DER TLV header, returning `(tag, content_slice, remaining_slice)`.
pub(crate) fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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
/// Correctly handles arc-2 subidentifiers (`first >= 80`), overflow checks, and rejects
/// truncated trailing VLQ continuation bytes.
pub(crate) fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    // Parse first base-128 subidentifier (encodes 40 * arc0 + arc1)
    let mut idx = 0usize;
    let mut first_val: u64 = 0;
    loop {
        let &b = bytes.get(idx)?;
        idx += 1;
        first_val = first_val.checked_mul(128)? | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            break;
        }
    }
    let (arc0, arc1) = if first_val < 40 {
        (0u64, first_val)
    } else if first_val < 80 {
        (1u64, first_val - 40)
    } else {
        (2u64, first_val - 80)
    };
    let mut out = format!("{arc0}.{arc1}");
    let mut cur: u64 = 0;
    let mut in_subid = false;
    for &b in &bytes[idx..] {
        cur = cur.checked_mul(128)? | ((b & 0x7f) as u64);
        in_subid = true;
        if (b & 0x80) == 0 {
            out.push('.');
            out.push_str(&cur.to_string());
            cur = 0;
            in_subid = false;
        }
    }
    if in_subid {
        return None;
    }
    Some(out)
}

/// Maps well-known X.509 signature / public-key OIDs to `(canonical_name, is_shor_vulnerable)`.
pub fn classify_x509_oid(oid: &str) -> (&'static str, bool) {
    match oid {
        "1.2.840.113549.1.1.4" => ("MD5-with-RSA", true),
        "1.2.840.113549.1.1.5" => ("SHA1-with-RSA", true),
        "1.2.840.113549.1.1.11" => ("SHA256-with-RSA", true),
        "1.2.840.113549.1.1.12" => ("SHA384-with-RSA", true),
        "1.2.840.113549.1.1.13" => ("SHA512-with-RSA", true),
        "1.2.840.113549.1.1.10" => ("RSASSA-PSS", true),
        "1.2.840.113549.1.1.1" => ("RSA", true),
        "1.2.840.10045.4.1" => ("ECDSA-with-SHA1", true),
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
    if !s.is_ascii() {
        return None;
    }
    if tag == 0x17 && s.len() >= 2 && s.as_bytes()[..2].iter().all(u8::is_ascii_digit) {
        // UTCTime: YYMMDDHHMMSSZ (RFC 5280: >=50 => 19xx, <50 => 20xx)
        let yy: u32 = s[..2].parse().ok()?;
        Some(if yy >= 50 { 1900 + yy } else { 2000 + yy })
    } else if tag == 0x18 && s.len() >= 4 && s.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
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

    // Walk remaining TBSCertificate elements (subject, spki, optional [1]/[2], optional [3] extensions)
    // and check BasicConstraints (`2.5.29.19`, OID bytes `55 1d 13`) `cA` BOOLEAN strictly inside its
    // `extnValue` OCTET STRING (never confusing `critical = TRUE` on a leaf cert with `cA = TRUE`).
    let mut is_ca = false;
    let mut rem = after_validity;
    while let Some((tag, body, next)) = read_der_tlv(rem) {
        if tag == 0xa3 {
            // [3] EXPLICIT Extensions ::= SEQUENCE OF Extension
            if let Some((0x30, mut exts, _)) = read_der_tlv(body) {
                while let Some((ext_tag, ext_body, ext_next)) = read_der_tlv(exts) {
                    if ext_tag == 0x30
                        && let Some((0x06, oid_bytes, mut ext_rest)) = read_der_tlv(ext_body)
                        && oid_bytes == [0x55, 0x1d, 0x13]
                    {
                        // Optional `critical BOOLEAN DEFAULT FALSE`
                        if let Some((0x01, _, after_crit)) = read_der_tlv(ext_rest) {
                            ext_rest = after_crit;
                        }
                        // `extnValue OCTET STRING` containing `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }`
                        if let Some((0x04, octets, _)) = read_der_tlv(ext_rest)
                            && let Some((0x30, bc_body, _)) = read_der_tlv(octets)
                            && let Some((0x01, bool_bytes, _)) = read_der_tlv(bc_body)
                            && bool_bytes.first().is_some_and(|&b| b != 0)
                        {
                            is_ca = true;
                        }
                    }
                    exts = ext_next;
                }
            }
            break;
        }
        rem = next;
    }

    let (sig_alg, sig_shor) = classify_x509_oid(&sig_oid);
    let current_year = current_utc_year();
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

/// Extracts and base64-decodes all PEM `-----BEGIN CERTIFICATE-----` blocks into raw DER byte vectors.
pub fn decode_pem_certificates(content: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let mut rest = content;
    while let Some(start) = rest.find(begin_marker) {
        let after_begin = &rest[start + begin_marker.len()..];
        let Some(end) = after_begin.find(end_marker) else {
            break;
        };
        if let Some(der) = decode_base64(&after_begin[..end]) {
            out.push(der);
        }
        rest = &after_begin[end + end_marker.len()..];
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

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

    fn build_v3_cert_with_basic_constraints(critical: bool, ca_true: bool) -> Vec<u8> {
        let ver = der_tlv(0xa0, &der_tlv(0x02, &[0x02])); // v3
        let serial = der_tlv(0x02, &[0x01]);
        let sig_alg = der_tlv(
            0x30,
            &der_tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            ),
        );
        let issuer = der_tlv(0x30, &[]);
        let validity = der_tlv(
            0x30,
            &[
                der_tlv(0x17, b"260101000000Z"),
                der_tlv(0x17, b"350101000000Z"),
            ]
            .concat(),
        );
        let subject = der_tlv(0x30, &[]);
        let spki = der_tlv(0x30, &[]);

        // BasicConstraints ext: OID 2.5.29.19, optional critical BOOLEAN, OCTET STRING { SEQUENCE { optional cA BOOLEAN } }
        let mut ext_inner = der_tlv(0x06, &[0x55, 0x1d, 0x13]);
        if critical {
            ext_inner.extend_from_slice(&der_tlv(0x01, &[0xff]));
        }
        let bc_seq = if ca_true {
            der_tlv(0x30, &der_tlv(0x01, &[0xff]))
        } else {
            der_tlv(0x30, &[])
        };
        ext_inner.extend_from_slice(&der_tlv(0x04, &bc_seq));
        let ext = der_tlv(0x30, &ext_inner);
        let exts = der_tlv(0xa3, &der_tlv(0x30, &ext));

        let tbs = der_tlv(
            0x30,
            &[
                ver,
                serial,
                sig_alg.clone(),
                issuer,
                validity,
                subject,
                spki,
                exts,
            ]
            .concat(),
        );
        der_tlv(0x30, &[tbs, sig_alg, der_tlv(0x03, &[0x00, 0xaa])].concat())
    }

    #[test]
    fn basic_constraints_critical_leaf_is_not_misclassified_as_ca() {
        let leaf_der = build_v3_cert_with_basic_constraints(true, false);
        let leaf = parse_x509_der("leaf.der", 0, &leaf_der).expect("valid leaf DER");
        assert!(
            !leaf.is_ca,
            "leaf cert with critical=TRUE and cA=FALSE must NOT be marked is_ca=true"
        );

        let ca_der = build_v3_cert_with_basic_constraints(true, true);
        let ca = parse_x509_der("ca.der", 0, &ca_der).expect("valid CA DER");
        assert!(ca.is_ca, "CA cert with cA=TRUE must be marked is_ca=true");
    }

    #[test]
    fn decode_oid_handles_arc2_and_rejects_truncation_or_overflow() {
        // 2.999.3: 40*2 + 999 = 1079 = (8 << 7) | 55 => 0x88, 0x37
        assert_eq!(decode_oid(&[0x88, 0x37, 0x03]).as_deref(), Some("2.999.3"));
        // 2.16.840.1.101.3.4.3.18 (ML-DSA-65): 40*2 + 16 = 96 = 0x60
        assert_eq!(
            decode_oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]).as_deref(),
            Some("2.16.840.1.101.3.4.3.18")
        );
        // Truncated continuation byte must fail
        assert_eq!(decode_oid(&[0x60, 0x86]), None);
        // Shift overflow (> 9 continuation bytes) must fail cleanly without panic
        assert_eq!(
            decode_oid(&[
                0x60, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01
            ]),
            None
        );
    }
}
