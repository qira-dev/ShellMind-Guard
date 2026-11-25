//! Phase 30B: Confidential Computing Attestation & Append-Only Merkle Audit Log
//! - AWS Nitro Enclave `COSE_Sign1` CBOR Attestation Document Verifier
//! - Intel TDX v4 Quote & AMD SEV-SNP Attestation Report Binary Verifiers
//! - Append-Only BLAKE3 Cryptographic Merkle Audit Log with O(log N) Inclusion Proofs

use crate::license::ct_eq_bytes;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parsed AWS Nitro Enclave `COSE_Sign1` attestation envelope (RFC 9052 Tag 18).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NitroCoseAttestation {
    pub protected_header_len: usize,
    pub payload_len: usize,
    pub signature_len: usize,
    pub module_id: String,
    pub digest_alg: String,
    pub timestamp_ms: u64,
    pub pcrs: BTreeMap<u8, String>,
    pub has_certificate: bool,
    pub cabundle_count: usize,
}

/// Structural verification summary for an AWS Nitro `COSE_Sign1` CBOR document.
/// Note: `cryptographically_verified` is always `false` until AWS Nitro Root CA + ECDSA P-384
/// verification is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NitroCoseSummary {
    pub protected_header_len: usize,
    pub payload_len: usize,
    pub signature_len: usize,
    pub cryptographically_verified: bool,
}

fn read_cbor_head(buf: &[u8], pos: &mut usize) -> Result<(u8, u64)> {
    let initial = *buf
        .get(*pos)
        .ok_or_else(|| anyhow::anyhow!("CBOR truncated at offset {}", *pos))?;
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1F;
    let arg = match info {
        0..=23 => u64::from(info),
        24 => {
            let b = *buf
                .get(*pos)
                .ok_or_else(|| anyhow::anyhow!("CBOR 1-byte length truncated"))?;
            *pos += 1;
            u64::from(b)
        }
        25 => {
            let s = buf
                .get(*pos..*pos + 2)
                .ok_or_else(|| anyhow::anyhow!("CBOR 2-byte length truncated"))?;
            *pos += 2;
            u64::from(u16::from_be_bytes([s[0], s[1]]))
        }
        26 => {
            let s = buf
                .get(*pos..*pos + 4)
                .ok_or_else(|| anyhow::anyhow!("CBOR 4-byte length truncated"))?;
            *pos += 4;
            u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        }
        27 => {
            let s = buf
                .get(*pos..*pos + 8)
                .ok_or_else(|| anyhow::anyhow!("CBOR 8-byte length truncated"))?;
            *pos += 8;
            u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        }
        _ => bail!("indefinite-length or reserved CBOR additional info {info} rejected"),
    };
    Ok((major, arg))
}

fn read_cbor_bstr<'a>(buf: &'a [u8], pos: &mut usize, field: &str) -> Result<&'a [u8]> {
    let (major, len_u64) = read_cbor_head(buf, pos)?;
    if major != 2 {
        bail!("CBOR COSE_Sign1 `{field}` must be major type 2 (bstr), got major {major}");
    }
    let len = usize::try_from(len_u64).map_err(|_| anyhow::anyhow!("CBOR `{field}` overflow"))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("CBOR `{field}` slice overflow"))?;
    let out = buf
        .get(*pos..end)
        .ok_or_else(|| anyhow::anyhow!("CBOR `{field}` payload truncated"))?;
    *pos = end;
    Ok(out)
}

fn skip_cbor_item(buf: &[u8], pos: &mut usize, depth: usize) -> Result<()> {
    if depth > 16 {
        bail!("CBOR nesting depth exceeds 16");
    }
    let (major, arg) = read_cbor_head(buf, pos)?;
    match major {
        0 | 1 | 7 => Ok(()),
        2 | 3 => {
            let len = usize::try_from(arg).map_err(|_| anyhow::anyhow!("CBOR string overflow"))?;
            let end = pos
                .checked_add(len)
                .ok_or_else(|| anyhow::anyhow!("CBOR string bounds overflow"))?;
            if end > buf.len() {
                bail!("CBOR string truncated");
            }
            *pos = end;
            Ok(())
        }
        4 => {
            if arg > 1024 {
                bail!("CBOR array in unprotected header too large");
            }
            for _ in 0..arg {
                skip_cbor_item(buf, pos, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            if arg > 1024 {
                bail!("CBOR map in unprotected header too large");
            }
            for _ in 0..arg {
                skip_cbor_item(buf, pos, depth + 1)?;
                skip_cbor_item(buf, pos, depth + 1)?;
            }
            Ok(())
        }
        6 => skip_cbor_item(buf, pos, depth + 1),
        _ => bail!("unsupported CBOR major type {major}"),
    }
}

/// Parses and structurally validates a CBOR `COSE_Sign1` envelope along with Nitro attestation
/// claims, returning a summary with `cryptographically_verified: false`.
pub fn parse_and_verify_nitro_cose_sign1(
    cose_bytes: &[u8],
    payload_json_or_cbor_claims: &NitroCoseAttestation,
    expected_pcr0_hex: Option<&str>,
    now_ms: u64,
    max_age_ms: u64,
) -> Result<NitroCoseSummary> {
    if cose_bytes.len() < 8 {
        bail!("Nitro COSE_Sign1 document truncated");
    }
    let mut pos = 0usize;
    // Optional RFC 9052 Tag 18 (`0xD2` or `0xD8 0x12`)
    if cose_bytes.first().copied() == Some(0xD2) {
        pos = 1;
    } else if cose_bytes.get(0..2) == Some(&[0xD8, 0x12]) {
        pos = 2;
    }
    let (arr_major, arr_len) = read_cbor_head(cose_bytes, &mut pos)?;
    if arr_major != 4 || arr_len != 4 {
        bail!("Nitro document is not a valid 4-element CBOR COSE_Sign1 array");
    }
    let protected_bytes = read_cbor_bstr(cose_bytes, &mut pos, "protected")?;
    if protected_bytes.is_empty() {
        bail!("Nitro COSE_Sign1 protected header bstr must not be empty");
    }
    let (unprot_major, unprot_len) = read_cbor_head(cose_bytes, &mut pos)?;
    if unprot_major != 5 || unprot_len > 256 {
        bail!("Nitro COSE_Sign1 unprotected header must be a bounded CBOR map");
    }
    for _ in 0..unprot_len {
        skip_cbor_item(cose_bytes, &mut pos, 1)?;
        skip_cbor_item(cose_bytes, &mut pos, 1)?;
    }
    let payload_bytes = read_cbor_bstr(cose_bytes, &mut pos, "payload")?;
    if payload_bytes.is_empty() {
        bail!("Nitro COSE_Sign1 payload bstr must not be empty");
    }
    let sig_bytes = read_cbor_bstr(cose_bytes, &mut pos, "signature")?;
    if pos != cose_bytes.len() {
        bail!("Nitro COSE_Sign1 has unexpected trailing bytes after 4-element array");
    }
    if sig_bytes.len() < 64 || payload_json_or_cbor_claims.signature_len < 64 {
        bail!("Nitro COSE_Sign1 signature too short for ECDSA P-384 (expected >= 64 bytes)");
    }
    if protected_bytes.len() != payload_json_or_cbor_claims.protected_header_len
        || payload_bytes.len() != payload_json_or_cbor_claims.payload_len
        || sig_bytes.len() != payload_json_or_cbor_claims.signature_len
    {
        bail!("Nitro COSE_Sign1 parsed CBOR field lengths do not match attestation claims");
    }
    if payload_json_or_cbor_claims.module_id.trim().is_empty() {
        bail!("Nitro attestation missing module_id");
    }
    if !payload_json_or_cbor_claims.has_certificate
        || payload_json_or_cbor_claims.cabundle_count == 0
    {
        bail!("Nitro attestation missing leaf certificate or AWS root CA bundle");
    }
    if payload_json_or_cbor_claims.timestamp_ms == 0
        || payload_json_or_cbor_claims.timestamp_ms > now_ms.saturating_add(300_000)
        || now_ms.saturating_sub(payload_json_or_cbor_claims.timestamp_ms) > max_age_ms
    {
        bail!("Nitro attestation timestamp missing, stale, or too far in the future");
    }
    if let Some(expected_pcr0) = expected_pcr0_hex {
        let Some(actual) = payload_json_or_cbor_claims.pcrs.get(&0) else {
            bail!("Nitro attestation missing PCR0 measurement");
        };
        let actual_norm = actual.trim().to_ascii_lowercase();
        let expected_norm = expected_pcr0.trim().to_ascii_lowercase();
        if !ct_eq_bytes(actual_norm.as_bytes(), expected_norm.as_bytes()) {
            bail!("Nitro PCR0 measurement mismatch: expected {expected_pcr0}, got {actual}");
        }
    }
    Ok(NitroCoseSummary {
        protected_header_len: protected_bytes.len(),
        payload_len: payload_bytes.len(),
        signature_len: sig_bytes.len(),
        cryptographically_verified: false,
    })
}

/// Performs structural framing & claims pre-validation on a CBOR `COSE_Sign1` envelope
/// (optional Tag 18 `0xD2`, followed by 4-element CBOR array `0x84`:
/// `[protected_bstr, unprotected_map, payload_bstr, sig_bstr]`) and validates Nitro claims
/// (PCR0 allowlist, non-empty signature & cert chain, non-future/non-stale timestamp).
///
/// NOTE (v0.4.1 fail-closed boundary): This function performs structural & claims pre-checks
/// ONLY — full cryptographic COSE_Sign1 P-384 + AWS Nitro Root CA chain verification is
/// deferred to v0.5 and callers MUST treat `cryptographically_verified` as `false`.
pub fn verify_nitro_cose_sign1(
    cose_bytes: &[u8],
    payload_json_or_cbor_claims: &NitroCoseAttestation,
    expected_pcr0_hex: Option<&str>,
    now_ms: u64,
    max_age_ms: u64,
) -> Result<()> {
    parse_and_verify_nitro_cose_sign1(
        cose_bytes,
        payload_json_or_cbor_claims,
        expected_pcr0_hex,
        now_ms,
        max_age_ms,
    )
    .map(|_| ())
}

/// Structurally parsed Intel TDX Quote v4 header & TD measurement summary.
/// Note: `cryptographically_verified` is always `false` in v0.4.1 (structural header/MRTD check only;
/// Intel DCAP PCK signature & TCB chain verification is deferred to v0.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuoteV4Summary {
    pub version: u16,
    pub tee_type: u32,
    pub debug_enabled: bool,
    pub mrtd_hex: String,
    pub cryptographically_verified: bool,
}

/// Parses and structurally checks an Intel TDX v4 Quote binary buffer (fail-closed):
/// - Minimum length `48 + 584 + 4` (`636` bytes: 48-byte header + 584-byte TD Quote Body + 4-byte `sig_data_len`)
/// - Bytes `0..2`: `version == 4` (little-endian)
/// - Bytes `4..8`: `tee_type == 0x0000_0081` (TDX)
/// - Rejects debuggable TDs (`TD_ATTR_DEBUG` bit 0 set in `td_attributes` at offset `48 + 120..48 + 128`)
/// - Extracts 48-byte `MRTD` measurement (offset `48 + 136..48 + 184`) and matches expected hex in constant time.
/// - Optionally binds 64-byte `REPORTDATA` challenge nonce at offset `48 + 520..48 + 584` (`568..632`) in constant time.
/// - Always sets `cryptographically_verified: false` until full Intel DCAP PCK verification lands.
pub fn verify_tdx_quote_v4(
    quote: &[u8],
    expected_mrtd_hex: Option<&str>,
) -> Result<TdxQuoteV4Summary> {
    verify_tdx_quote_v4_with_report_data(quote, expected_mrtd_hex, None)
}

/// Parses and structurally checks an Intel TDX v4 Quote binary buffer with optional 64-byte
/// `REPORTDATA` anti-replay challenge verification (`quote[568..632]`).
pub fn verify_tdx_quote_v4_with_report_data(
    quote: &[u8],
    expected_mrtd_hex: Option<&str>,
    expected_report_data: Option<&[u8; 64]>,
) -> Result<TdxQuoteV4Summary> {
    const MIN_TDX_V4_LEN: usize = 48 + 584 + 4;
    if quote.len() < MIN_TDX_V4_LEN {
        bail!(
            "Intel TDX v4 quote too short ({} < {MIN_TDX_V4_LEN} bytes)",
            quote.len()
        );
    }
    let sig_data_len =
        u32::from_le_bytes([quote[632], quote[633], quote[634], quote[635]]) as usize;
    if quote.len() < MIN_TDX_V4_LEN.saturating_add(sig_data_len) {
        bail!(
            "Intel TDX v4 quote signature payload truncated ({} < {} bytes)",
            quote.len(),
            MIN_TDX_V4_LEN.saturating_add(sig_data_len)
        );
    }
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    if version != 4 {
        bail!("Unsupported TDX quote version {version} (expected 4)");
    }
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);
    if tee_type != 0x0000_0081 {
        bail!("Invalid TDX tee_type 0x{tee_type:08x} (expected 0x00000081)");
    }
    let td_attrs = u64::from_le_bytes(quote[48 + 120..48 + 128].try_into().unwrap());
    let debug_enabled = (td_attrs & 1) != 0;
    if debug_enabled {
        bail!("Intel TDX enclave has TD_ATTR_DEBUG enabled — rejected fail-closed");
    }
    let mrtd_hex = hex::encode(&quote[48 + 136..48 + 184]);
    if let Some(exp) = expected_mrtd_hex {
        let exp_norm = exp.trim().to_ascii_lowercase();
        if !ct_eq_bytes(mrtd_hex.as_bytes(), exp_norm.as_bytes()) {
            bail!("Intel TDX MRTD measurement mismatch");
        }
    }
    if let Some(expected_rd) = expected_report_data
        && !ct_eq_bytes(&quote[48 + 520..48 + 584], expected_rd)
    {
        bail!("Intel TDX REPORTDATA challenge nonce mismatch");
    }
    Ok(TdxQuoteV4Summary {
        version,
        tee_type,
        debug_enabled,
        mrtd_hex,
        cryptographically_verified: false,
    })
}

/// Structurally parsed AMD SEV-SNP Attestation Report summary.
/// Note: `cryptographically_verified` is always `false` in v0.4.1 (structural header/policy check only;
/// AMD VCEK ECDSA P-384 chain verification is deferred to v0.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevSnpReportSummary {
    pub version: u32,
    pub guest_svn: u32,
    pub debug_enabled: bool,
    pub measurement_hex: String,
    pub cryptographically_verified: bool,
}

/// Parses and structurally checks an AMD SEV-SNP Attestation Report binary buffer (fail-closed):
/// - Full AMD SEV-SNP v2 ABI report size (`>= 1184` bytes / `0x4A0`, covering the 512-byte signature tail)
/// - Bytes `0..4`: `version >= 2`
/// - Bytes `4..8`: `guest_svn`
/// - Bytes `8..16`: `policy` (bit 19 = `DEBUG`; must be 0!)
/// - Bytes `80..144`: optional 64-byte `REPORT_DATA` challenge nonce
/// - Bytes `144..192`: 48-byte SHA-384 `MEASUREMENT`
/// - Always sets `cryptographically_verified: false` until full AMD VCEK verification lands.
pub fn verify_sev_snp_report(
    report: &[u8],
    expected_measurement_hex: Option<&str>,
    min_guest_svn: u32,
) -> Result<SevSnpReportSummary> {
    verify_sev_snp_report_with_report_data(report, expected_measurement_hex, min_guest_svn, None)
}

/// Parses and structurally checks an AMD SEV-SNP Attestation Report binary buffer with optional
/// 64-byte `REPORT_DATA` anti-replay challenge verification (`report[80..144]`).
pub fn verify_sev_snp_report_with_report_data(
    report: &[u8],
    expected_measurement_hex: Option<&str>,
    min_guest_svn: u32,
    expected_report_data: Option<&[u8; 64]>,
) -> Result<SevSnpReportSummary> {
    const MIN_SEV_SNP_REPORT_LEN: usize = 1184;
    if report.len() < MIN_SEV_SNP_REPORT_LEN {
        bail!(
            "AMD SEV-SNP attestation report too short ({} < {MIN_SEV_SNP_REPORT_LEN} bytes)",
            report.len()
        );
    }
    let version = u32::from_le_bytes(report[0..4].try_into().unwrap());
    if version < 2 {
        bail!("Unsupported AMD SEV-SNP report version {version} (expected >= 2)");
    }
    let guest_svn = u32::from_le_bytes(report[4..8].try_into().unwrap());
    if guest_svn < min_guest_svn {
        bail!("AMD SEV-SNP guest_svn {guest_svn} below minimum policy {min_guest_svn}");
    }
    let policy = u64::from_le_bytes(report[8..16].try_into().unwrap());
    let debug_enabled = (policy & (1u64 << 19)) != 0;
    if debug_enabled {
        bail!("AMD SEV-SNP guest policy has DEBUG bit enabled — rejected fail-closed");
    }
    let measurement_hex = hex::encode(&report[144..192]);
    if let Some(exp) = expected_measurement_hex {
        let exp_norm = exp.trim().to_ascii_lowercase();
        if !ct_eq_bytes(measurement_hex.as_bytes(), exp_norm.as_bytes()) {
            bail!("AMD SEV-SNP launch measurement mismatch");
        }
    }
    if let Some(expected_rd) = expected_report_data
        && !ct_eq_bytes(&report[80..144], expected_rd)
    {
        bail!("AMD SEV-SNP REPORT_DATA challenge nonce mismatch");
    }
    Ok(SevSnpReportSummary {
        version,
        guest_svn,
        debug_enabled,
        measurement_hex,
        cryptographically_verified: false,
    })
}

/// One step in an O(log N) Merkle inclusion proof.
/// When `sibling_hex` is empty (`""`) and `is_left == false`, the step represents an odd-trailing
/// node promotion (`0x02 || node`) at that tree height, binding exact tree height and leaf index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling_hex: String,
    pub is_left: bool,
}

/// Append-only domain-separated BLAKE3 Merkle Audit Log (`0x00 || leaf`, `0x01 || L || R`, `0x02 || promoted`).
#[derive(Debug, Clone, Default)]
pub struct MerkleAuditLog {
    leaves: Vec<[u8; 32]>,
}

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn hash_promoted(only: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x02]);
    hasher.update(only);
    *hasher.finalize().as_bytes()
}

impl MerkleAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, entry: &[u8]) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(hash_leaf(entry));
        idx
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root_hex(&self) -> Option<String> {
        if self.leaves.is_empty() {
            return None;
        }
        // Promote unpaired trailing nodes with explicit `0x02` domain separation (eliminating both
        // CVE-2012-2459 duplicate-tail root collisions and cross-height/cross-index proof ambiguity).
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_node(&chunk[0], &chunk[1]));
                } else {
                    next.push(hash_promoted(&chunk[0]));
                }
            }
            level = next;
        }
        Some(hex::encode(level[0]))
    }

    /// Generates an O(log N) inclusion proof for leaf `index`, emitting one step per tree level
    /// (including `0x02` odd-promotion steps where `sibling_hex` is empty).
    pub fn inclusion_proof(&self, mut index: usize) -> Option<Vec<MerkleProofStep>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut proof = Vec::new();
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let is_right_child = index % 2 == 1;
            if is_right_child {
                proof.push(MerkleProofStep {
                    sibling_hex: hex::encode(level[index - 1]),
                    is_left: true,
                });
            } else if index + 1 < level.len() {
                proof.push(MerkleProofStep {
                    sibling_hex: hex::encode(level[index + 1]),
                    is_left: false,
                });
            } else {
                proof.push(MerkleProofStep {
                    sibling_hex: String::new(),
                    is_left: false,
                });
            }
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_node(&chunk[0], &chunk[1]));
                } else {
                    next.push(hash_promoted(&chunk[0]));
                }
            }
            level = next;
            index /= 2;
        }
        Some(proof)
    }
}

/// Independently verifies an audit entry against a published Merkle root & inclusion proof.
pub fn verify_merkle_inclusion(
    entry: &[u8],
    proof: &[MerkleProofStep],
    expected_root_hex: &str,
) -> bool {
    let mut cur = hash_leaf(entry);
    for step in proof {
        if step.sibling_hex.is_empty() {
            if step.is_left {
                return false;
            }
            cur = hash_promoted(&cur);
            continue;
        }
        let Ok(sib_vec) = hex::decode(&step.sibling_hex) else {
            return false;
        };
        let Ok(sib): Result<[u8; 32], _> = sib_vec.try_into() else {
            return false;
        };
        cur = if step.is_left {
            hash_node(&sib, &cur)
        } else {
            hash_node(&cur, &sib)
        };
    }
    let root_norm = expected_root_hex.trim().to_ascii_lowercase();
    ct_eq_bytes(hex::encode(cur).as_bytes(), root_norm.as_bytes())
}

/// Verifies an audit entry against a published Merkle root while strictly binding `leaf_index`
/// and `total_leaves` against the exact proof path geometry.
pub fn verify_merkle_inclusion_at(
    entry: &[u8],
    leaf_index: usize,
    total_leaves: usize,
    proof: &[MerkleProofStep],
    expected_root_hex: &str,
) -> bool {
    if total_leaves == 0 || leaf_index >= total_leaves {
        return false;
    }
    let mut idx = leaf_index;
    let mut level_len = total_leaves;
    let mut step_idx = 0usize;
    while level_len > 1 {
        let Some(step) = proof.get(step_idx) else {
            return false;
        };
        let is_right = idx % 2 == 1;
        if is_right {
            if !step.is_left || step.sibling_hex.is_empty() {
                return false;
            }
        } else if idx + 1 < level_len {
            if step.is_left || step.sibling_hex.is_empty() {
                return false;
            }
        } else if step.is_left || !step.sibling_hex.is_empty() {
            return false;
        }
        level_len = level_len.div_ceil(2);
        idx /= 2;
        step_idx += 1;
    }
    if step_idx != proof.len() {
        return false;
    }
    verify_merkle_inclusion(entry, proof, expected_root_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_cose_sign1_bytes(
        protected_len: usize,
        payload_len: usize,
        sig_len: usize,
    ) -> Vec<u8> {
        fn push_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
            if bytes.len() < 24 {
                out.push(0x40 | (bytes.len() as u8));
            } else if bytes.len() <= u8::MAX as usize {
                out.push(0x58);
                out.push(bytes.len() as u8);
            } else {
                out.push(0x59);
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            }
            out.extend_from_slice(bytes);
        }
        let mut out = vec![0xD2, 0x84];
        let mut prot = vec![0xA1, 0x01, 0x38, 0x22];
        prot.resize(protected_len, 0x00);
        push_bstr(&mut out, &prot);
        out.push(0xA0); // empty unprotected map
        push_bstr(&mut out, &vec![0xAB; payload_len]);
        push_bstr(&mut out, &vec![0xCD; sig_len]);
        out
    }

    #[test]
    fn verifies_nitro_cose_tdx_v4_and_sev_snp_fail_closed() {
        // 1. Nitro COSE_Sign1 — valid 4-element CBOR array passes; 8-byte stub fails closed
        let cose = build_valid_cose_sign1_bytes(4, 128, 96);
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u8, "aabbccdd".repeat(12));
        let att = NitroCoseAttestation {
            protected_header_len: 4,
            payload_len: 128,
            signature_len: 96,
            module_id: "i-0123456789-enc01".into(),
            digest_alg: "SHA384".into(),
            timestamp_ms: 1_700_000_000_000,
            pcrs,
            has_certificate: true,
            cabundle_count: 3,
        };
        let summary = parse_and_verify_nitro_cose_sign1(
            &cose,
            &att,
            Some(&"aabbccdd".repeat(12)),
            1_700_000_010_000,
            60_000,
        )
        .unwrap();
        assert!(!summary.cryptographically_verified);
        assert_eq!(summary.signature_len, 96);
        assert!(
            verify_nitro_cose_sign1(
                &cose,
                &att,
                Some(&"aabbccdd".repeat(12)),
                1_700_000_010_000,
                60_000
            )
            .is_ok()
        );
        // Truncated 8-byte COSE_Sign1 slice must fail closed
        assert!(
            verify_nitro_cose_sign1(
                &[0xD2, 0x84, 0, 0, 0, 0, 0, 0],
                &att,
                None,
                1_700_000_010_000,
                60_000
            )
            .is_err()
        );
        // Wrong PCR0 fails closed
        assert!(
            verify_nitro_cose_sign1(&cose, &att, Some("deadbeef"), 1_700_000_010_000, 60_000)
                .is_err()
        );
        // Future Nitro timestamp (> +5m skew) fails closed
        let mut future_att = att.clone();
        future_att.timestamp_ms = 1_700_000_500_000;
        assert!(
            verify_nitro_cose_sign1(&cose, &future_att, None, 1_700_000_000_000, 60_000).is_err()
        );

        // 2. Intel TDX v4 Quote (requires >= 636 bytes + sig_data_len; 256-byte stub rejected)
        assert!(verify_tdx_quote_v4(&vec![0u8; 256], None).is_err());

        let mut tdx = vec![0u8; 700];
        tdx[0..2].copy_from_slice(&4u16.to_le_bytes());
        tdx[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes());
        tdx[48 + 136..48 + 184].fill(0x5A);
        // Real TDX quotes have XFAM bit 0 (x87) set at 48+128 — must NOT trigger false debug rejection
        tdx[48 + 128] = 0x03;
        let expected_nonce = [0x42u8; 64];
        tdx[48 + 520..48 + 584].copy_from_slice(&expected_nonce);
        tdx[632..636].copy_from_slice(&64u32.to_le_bytes());

        let tdx_ok = verify_tdx_quote_v4_with_report_data(
            &tdx,
            Some(&"5a".repeat(48)),
            Some(&expected_nonce),
        )
        .unwrap();
        assert!(!tdx_ok.debug_enabled);
        assert!(!tdx_ok.cryptographically_verified);
        // Wrong REPORTDATA nonce rejected
        assert!(verify_tdx_quote_v4_with_report_data(&tdx, None, Some(&[0x99u8; 64])).is_err());
        // Setting TD_ATTR_DEBUG at real td_attributes offset 48+120 fails closed
        tdx[48 + 120] = 1;
        assert!(verify_tdx_quote_v4(&tdx, None).is_err());

        // 3. AMD SEV-SNP Report (requires full 1184-byte ABI report + REPORT_DATA binding)
        let short_snp = vec![0u8; 256];
        assert!(verify_sev_snp_report(&short_snp, None, 0).is_err());

        let mut snp = vec![0u8; 1184];
        snp[0..4].copy_from_slice(&2u32.to_le_bytes());
        snp[4..8].copy_from_slice(&3u32.to_le_bytes());
        snp[80..144].copy_from_slice(&expected_nonce);
        snp[144..192].fill(0xAB);
        let snp_ok = verify_sev_snp_report_with_report_data(
            &snp,
            Some(&"ab".repeat(48)),
            2,
            Some(&expected_nonce),
        )
        .unwrap();
        assert!(!snp_ok.cryptographically_verified);
        assert!(
            verify_sev_snp_report_with_report_data(&snp, None, 2, Some(&[0x11u8; 64])).is_err()
        );
        // Setting policy DEBUG bit 19 fails closed
        snp[8..16].copy_from_slice(&(1u64 << 19).to_le_bytes());
        assert!(verify_sev_snp_report(&snp, None, 2).is_err());
    }

    #[test]
    fn merkle_audit_log_proves_inclusion_and_detects_tampering() {
        for n in 1..=9 {
            let mut log = MerkleAuditLog::new();
            for i in 0..n {
                log.append(format!("scan-event-{i}").as_bytes());
            }
            let root = log.root_hex().unwrap();
            for i in 0..n {
                let proof = log.inclusion_proof(i).unwrap();
                let entry = format!("scan-event-{i}");
                assert!(
                    verify_merkle_inclusion(entry.as_bytes(), &proof, &root),
                    "inclusion failed for n={n}, i={i}"
                );
                assert!(
                    verify_merkle_inclusion_at(entry.as_bytes(), i, n, &proof, &root),
                    "indexed inclusion failed for n={n}, i={i}"
                );
                if i + 1 < n {
                    assert!(!verify_merkle_inclusion_at(
                        entry.as_bytes(),
                        i + 1,
                        n,
                        &proof,
                        &root
                    ));
                }
                assert!(!verify_merkle_inclusion_at(
                    entry.as_bytes(),
                    i,
                    n.saturating_mul(2).max(2),
                    &proof,
                    &root
                ));
                if n.is_power_of_two() || i + 1 == n {
                    assert!(!verify_merkle_inclusion_at(
                        entry.as_bytes(),
                        i,
                        n + 1,
                        &proof,
                        &root
                    ));
                }
                assert!(!verify_merkle_inclusion(
                    format!("scan-event-{i}-TAMPERED").as_bytes(),
                    &proof,
                    &root
                ));
            }
        }
        // CVE-2012-2459 regression: [A, B, C] and [A, B, C, C] MUST produce distinct roots
        let mut odd = MerkleAuditLog::new();
        odd.append(b"A");
        odd.append(b"B");
        odd.append(b"C");
        let mut dup = MerkleAuditLog::new();
        dup.append(b"A");
        dup.append(b"B");
        dup.append(b"C");
        dup.append(b"C");
        assert_ne!(odd.root_hex(), dup.root_hex());
    }
}
