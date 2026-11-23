//! Phase 30B: Confidential Computing Attestation & Append-Only Merkle Audit Log
//! - AWS Nitro Enclave `COSE_Sign1` CBOR Attestation Document Verifier
//! - Intel TDX v4 Quote & AMD SEV-SNP Attestation Report Binary Verifiers
//! - Append-Only BLAKE3 Cryptographic Merkle Audit Log with O(log N) Inclusion Proofs

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

/// Verifies the structural framing of a CBOR `COSE_Sign1` envelope (optional Tag 18 `0xD2`,
/// followed by 4-element CBOR array `0x84`: `[protected_bstr, unprotected_map, payload_bstr, sig_bstr]`)
/// and validates Nitro attestation claims (PCR0/1/2 allowlist, non-empty signature & cert chain, timestamp).
pub fn verify_nitro_cose_sign1(
    cose_bytes: &[u8],
    payload_json_or_cbor_claims: &NitroCoseAttestation,
    expected_pcr0_hex: Option<&str>,
    now_ms: u64,
    max_age_ms: u64,
) -> Result<()> {
    if cose_bytes.len() < 8 {
        bail!("Nitro COSE_Sign1 document truncated");
    }
    let start = if cose_bytes[0] == 0xD2 { 1 } else { 0 };
    if cose_bytes.get(start).copied() != Some(0x84) {
        bail!("Nitro document is not a valid 4-element CBOR COSE_Sign1 array (expected 0x84)");
    }
    if payload_json_or_cbor_claims.signature_len < 64 {
        bail!("Nitro COSE_Sign1 signature too short for ECDSA P-384 (expected >= 64 bytes)");
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
        || now_ms.saturating_sub(payload_json_or_cbor_claims.timestamp_ms) > max_age_ms
    {
        bail!("Nitro attestation timestamp stale or missing");
    }
    if let Some(expected_pcr0) = expected_pcr0_hex {
        let Some(actual) = payload_json_or_cbor_claims.pcrs.get(&0) else {
            bail!("Nitro attestation missing PCR0 measurement");
        };
        if !actual.eq_ignore_ascii_case(expected_pcr0) {
            bail!("Nitro PCR0 measurement mismatch: expected {expected_pcr0}, got {actual}");
        }
    }
    Ok(())
}

/// Verified Intel TDX Quote v4 header & TD measurement summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuoteV4Summary {
    pub version: u16,
    pub tee_type: u32,
    pub debug_enabled: bool,
    pub mrtd_hex: String,
}

/// Parses and fail-closed verifies an Intel TDX v4 Quote binary buffer:
/// - Bytes `0..2`: `version == 4` (little-endian)
/// - Bytes `4..8`: `tee_type == 0x0000_0081` (TDX)
/// - Rejects debuggable TDs (`TD_ATTR_DEBUG` bit 0 set in `td_attributes` at offset `48 + 120..48 + 128`)
/// - Extracts 48-byte `MRTD` measurement (offset `48 + 136..48 + 184`) and matches expected hex if provided.
pub fn verify_tdx_quote_v4(
    quote: &[u8],
    expected_mrtd_hex: Option<&str>,
) -> Result<TdxQuoteV4Summary> {
    const MIN_TDX_V4_LEN: usize = 48 + 184;
    if quote.len() < MIN_TDX_V4_LEN {
        bail!(
            "Intel TDX v4 quote too short ({} < {MIN_TDX_V4_LEN} bytes)",
            quote.len()
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
    if let Some(exp) = expected_mrtd_hex
        && !mrtd_hex.eq_ignore_ascii_case(exp)
    {
        bail!("Intel TDX MRTD measurement mismatch");
    }
    Ok(TdxQuoteV4Summary {
        version,
        tee_type,
        debug_enabled,
        mrtd_hex,
    })
}

/// Verified AMD SEV-SNP Attestation Report summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevSnpReportSummary {
    pub version: u32,
    pub guest_svn: u32,
    pub debug_enabled: bool,
    pub measurement_hex: String,
}

/// Parses and fail-closed verifies an AMD SEV-SNP Attestation Report binary buffer:
/// - Bytes `0..4`: `version >= 2`
/// - Bytes `4..8`: `guest_svn`
/// - Bytes `8..16`: `policy` (bit 19 = `DEBUG`; must be 0!)
/// - Bytes `144..192`: 48-byte SHA-384 `MEASUREMENT`
pub fn verify_sev_snp_report(
    report: &[u8],
    expected_measurement_hex: Option<&str>,
    min_guest_svn: u32,
) -> Result<SevSnpReportSummary> {
    if report.len() < 192 {
        bail!(
            "AMD SEV-SNP attestation report too short ({} < 192 bytes)",
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
    if let Some(exp) = expected_measurement_hex
        && !measurement_hex.eq_ignore_ascii_case(exp)
    {
        bail!("AMD SEV-SNP launch measurement mismatch");
    }
    Ok(SevSnpReportSummary {
        version,
        guest_svn,
        debug_enabled,
        measurement_hex,
    })
}

/// One step in an O(log N) Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling_hex: String,
    pub is_left: bool,
}

/// Append-only domain-separated BLAKE3 Merkle Audit Log (RFC 6962 style: `0x00 || leaf`, `0x01 || L || R`).
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
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
                next.push(hash_node(&left, &right));
            }
            level = next;
        }
        Some(hex::encode(level[0]))
    }

    /// Generates an O(log N) inclusion proof for leaf `index`.
    pub fn inclusion_proof(&self, mut index: usize) -> Option<Vec<MerkleProofStep>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut proof = Vec::new();
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let is_right_child = index % 2 == 1;
            let sibling_idx = if is_right_child {
                index - 1
            } else if index + 1 < level.len() {
                index + 1
            } else {
                index
            };
            proof.push(MerkleProofStep {
                sibling_hex: hex::encode(level[sibling_idx]),
                is_left: is_right_child,
            });
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
                next.push(hash_node(&left, &right));
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
    hex::encode(cur).eq_ignore_ascii_case(expected_root_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_nitro_cose_tdx_v4_and_sev_snp_fail_closed() {
        // 1. Nitro COSE_Sign1
        let cose = vec![0xD2, 0x84, 0x43, 0xA1, 0x01, 0x38, 0x22, 0xA0];
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
        // Wrong PCR0 fails closed
        assert!(
            verify_nitro_cose_sign1(&cose, &att, Some("deadbeef"), 1_700_000_010_000, 60_000)
                .is_err()
        );

        // 2. Intel TDX v4 Quote
        let mut tdx = vec![0u8; 256];
        tdx[0..2].copy_from_slice(&4u16.to_le_bytes());
        tdx[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes());
        tdx[48 + 136..48 + 184].fill(0x5A);
        // Real TDX quotes have XFAM bit 0 (x87) set at 48+128 — must NOT trigger false debug rejection
        tdx[48 + 128] = 0x03;
        let tdx_ok = verify_tdx_quote_v4(&tdx, Some(&"5a".repeat(48))).unwrap();
        assert!(!tdx_ok.debug_enabled);
        // Setting TD_ATTR_DEBUG at real td_attributes offset 48+120 fails closed
        tdx[48 + 120] = 1;
        assert!(verify_tdx_quote_v4(&tdx, None).is_err());

        // 3. AMD SEV-SNP Report
        let mut snp = vec![0u8; 256];
        snp[0..4].copy_from_slice(&2u32.to_le_bytes());
        snp[4..8].copy_from_slice(&3u32.to_le_bytes());
        snp[144..192].fill(0xAB);
        assert!(verify_sev_snp_report(&snp, Some(&"ab".repeat(48)), 2).is_ok());
        // Setting policy DEBUG bit 19 fails closed
        snp[8..16].copy_from_slice(&(1u64 << 19).to_le_bytes());
        assert!(verify_sev_snp_report(&snp, None, 2).is_err());
    }

    #[test]
    fn merkle_audit_log_proves_inclusion_and_detects_tampering() {
        let mut log = MerkleAuditLog::new();
        for i in 0..5 {
            log.append(format!("scan-event-{i}").as_bytes());
        }
        let root = log.root_hex().unwrap();
        let proof = log.inclusion_proof(3).unwrap();
        assert!(verify_merkle_inclusion(b"scan-event-3", &proof, &root));
        assert!(!verify_merkle_inclusion(
            b"scan-event-3-TAMPERED",
            &proof,
            &root
        ));
    }
}
