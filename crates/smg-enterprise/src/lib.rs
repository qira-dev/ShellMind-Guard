pub mod attestation_merkle;
pub mod license;
pub mod tee;

pub use attestation_merkle::{
    MerkleAuditLog, MerkleProofStep, NitroCoseAttestation, NitroCoseSummary, SevSnpReportSummary,
    TdxQuoteV4Summary, parse_and_verify_nitro_cose_sign1, verify_merkle_inclusion,
    verify_merkle_inclusion_at, verify_nitro_cose_sign1, verify_sev_snp_report,
    verify_sev_snp_report_with_report_data, verify_tdx_quote_v4,
    verify_tdx_quote_v4_with_report_data,
};

pub use license::{
    LicenseClaims, LicenseTier, SignedLicenseToken, compute_binary_blake3, decode_pubkey_32,
    encode_hex, generate_challenge_nonce_hex, generate_ed25519_keypair, sign_license_claims,
    verify_license_fail_closed,
};
pub use tee::{
    AttestationPolicy, EnclaveHostProbe, RemoteTeeScanRequest, RemoteTeeScanResponse,
    TeeAttestationQuote, TeePlatform, VerifiedEnclaveSession, execute_remote_tee_scan,
    execute_remote_tee_scan_with_options, is_sensitive_secret_path, probe_local_tee_hardware,
    sign_tee_quote, validate_tee_endpoint, verify_tee_attestation_quote,
};

use anyhow::{Context, Result, bail};
use license::ct_eq_bytes;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// Signed airgapped enterprise verification bundle (`Phase 14B P14-03`) binding a scan's
/// BLAKE3 report digest, organization ID, and expiry under an offline Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AirgappedVerificationBundle {
    pub org_id: String,
    pub report_blake3_digest: String,
    pub binary_blake3: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub signature_hex: String,
}

fn airgapped_bundle_signing_bytes(
    org_id: &str,
    report_blake3_digest: &str,
    binary_blake3: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    if org_id.trim().is_empty() || org_id.len() > 256 || org_id.chars().any(|c| c.is_control()) {
        bail!(
            "airgapped bundle invalid org_id (must be 1..=256 printable chars without newlines/control chars)"
        );
    }
    for (label, digest) in [
        ("report_blake3_digest", report_blake3_digest),
        ("binary_blake3", binary_blake3),
    ] {
        if digest.len() < 32
            || !digest.len().is_multiple_of(2)
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("airgapped bundle invalid `{label}` (must be even-length ASCII hex >= 32 chars)");
        }
    }
    if issued_at_unix > expires_at_unix {
        bail!(
            "airgapped bundle invalid validity window: issued_at_unix ({issued_at_unix}) > expires_at_unix ({expires_at_unix})"
        );
    }
    Ok(format!(
        "smg-airgapped-v1\norg={org_id}\nreport={report_blake3_digest}\nbin={binary_blake3}\niss={issued_at_unix}\nexp={expires_at_unix}"
    )
    .into_bytes())
}

pub fn sign_airgapped_bundle(
    pkcs8_der: &[u8],
    org_id: &str,
    report_blake3_digest: &str,
    binary_blake3: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<AirgappedVerificationBundle> {
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8_der)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 key"))?;
    let payload = airgapped_bundle_signing_bytes(
        org_id,
        report_blake3_digest,
        binary_blake3,
        issued_at_unix,
        expires_at_unix,
    )?;
    let sig = kp.sign(&payload);
    Ok(AirgappedVerificationBundle {
        org_id: org_id.to_string(),
        report_blake3_digest: report_blake3_digest.to_string(),
        binary_blake3: binary_blake3.to_string(),
        issued_at_unix,
        expires_at_unix,
        signature_hex: encode_hex(sig.as_ref()),
    })
}

/// Verifies an airgapped verification bundle strictly offline (zero network I/O, fail-closed on
/// signature tamper, expiry, or report/binary BLAKE3 mismatch).
pub fn verify_airgapped_bundle_fail_closed(
    bundle: &AirgappedVerificationBundle,
    authority_pubkey_32: &[u8; 32],
    expected_report_digest: &str,
    expected_binary_blake3: &str,
    now_unix: u64,
) -> Result<()> {
    let payload = airgapped_bundle_signing_bytes(
        &bundle.org_id,
        &bundle.report_blake3_digest,
        &bundle.binary_blake3,
        bundle.issued_at_unix,
        bundle.expires_at_unix,
    )?;
    if now_unix > bundle.expires_at_unix {
        bail!("airgapped verification bundle expired");
    }
    if !ct_eq_bytes(
        bundle.report_blake3_digest.as_bytes(),
        expected_report_digest.as_bytes(),
    ) {
        bail!("airgapped bundle report BLAKE3 digest mismatch");
    }
    if !ct_eq_bytes(
        bundle.binary_blake3.as_bytes(),
        expected_binary_blake3.as_bytes(),
    ) {
        bail!("airgapped bundle binary BLAKE3 mismatch");
    }
    let sig_bytes = hex::decode(&bundle.signature_hex).context("invalid signature_hex")?;
    UnparsedPublicKey::new(&ED25519, authority_pubkey_32)
        .verify(&payload, &sig_bytes)
        .map_err(|_| anyhow::anyhow!("airgapped bundle Ed25519 signature verification failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smg_core::{IndexedFile, Language};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut req_bytes = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut header_end = None;
        let mut content_len = 0usize;
        loop {
            let n = stream.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                break;
            }
            req_bytes.extend_from_slice(&tmp[..n]);
            if header_end.is_none()
                && let Some(pos) = req_bytes.windows(4).position(|w| w == b"\r\n\r\n")
            {
                header_end = Some(pos + 4);
                let hdrs = String::from_utf8_lossy(&req_bytes[..pos]);
                for line in hdrs.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            if let Some(he) = header_end
                && req_bytes.len() >= he + content_len
            {
                break;
            }
        }
        let req_line = header_end
            .map(|he| {
                String::from_utf8_lossy(&req_bytes[..he - 4])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap_or_default();
        let body = header_end
            .map(|he| req_bytes[he..req_bytes.len().min(he + content_len)].to_vec())
            .unwrap_or_default();
        (req_line, body)
    }

    #[test]
    fn remote_tee_client_end_to_end_verifies_attestation_and_fails_closed() {
        let (pkcs8, pubkey) = generate_ed25519_keypair().unwrap();
        let pcr0 = "c".repeat(96);
        let nonce = "a1b2c3d4e5f60708";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let pcr0_srv = pcr0.clone();
        let pkcs8_srv = pkcs8.clone();
        let handle = thread::spawn(move || {
            // Connection 1: Phase 1 pre-attestation probe (`GET /tee-gw/v1/attest?nonce=...`)
            let (mut pre_stream, _) = listener.accept().unwrap();
            let (pre_line, pre_body) = read_http_request(&mut pre_stream);
            assert!(
                pre_line.starts_with("GET /tee-gw/v1/attest?nonce="),
                "unexpected pre-attestation request line: {pre_line}"
            );
            assert!(
                pre_body.is_empty(),
                "Phase 1 pre-attestation probe must not upload source files"
            );
            let pre_quote = sign_tee_quote(
                &pkcs8_srv,
                TeePlatform::IntelTdx,
                &pcr0_srv,
                nonce,
                now,
                "tdx-enclave-01",
            )
            .unwrap();
            let pre_json = serde_json::to_string(&pre_quote).unwrap();
            let pre_http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                pre_json.len(),
                pre_json
            );
            pre_stream.write_all(pre_http.as_bytes()).unwrap();
            drop(pre_stream);

            // Connection 2: Phase 2 scan upload (`POST /tee-gw/v1/attest-and-scan`)
            let (mut stream, _) = listener.accept().unwrap();
            let (scan_line, req_body) = read_http_request(&mut stream);
            assert!(
                scan_line.starts_with("POST /tee-gw/v1/attest-and-scan "),
                "unexpected scan request line: {scan_line}"
            );
            let parsed_req: crate::tee::RemoteTeeScanRequest =
                serde_json::from_slice(&req_body).unwrap();
            // Sensitive `.env` / `.pem` files MUST be stripped by default before upload!
            assert!(parsed_req.files.contains_key("src/app.ts"));
            assert!(!parsed_req.files.contains_key(".env"));
            assert!(!parsed_req.files.contains_key("certs/tls.pem"));
            let req_hash =
                crate::tee::compute_request_blake3_hex(&parsed_req.nonce_hex, &parsed_req.files);
            let findings: Vec<smg_graph::LatticeFinding> = Vec::new();
            let fin_bytes = serde_json::to_vec(&findings).unwrap();
            let fin_hash = blake3::hash(&fin_bytes).to_hex().to_string();
            let quote = crate::tee::sign_tee_quote_with_transcript(
                &pkcs8_srv,
                TeePlatform::IntelTdx,
                &pcr0_srv,
                nonce,
                now,
                "tdx-enclave-01",
                Some(req_hash),
                Some(fin_hash),
            )
            .unwrap();
            let body = serde_json::to_string(&RemoteTeeScanResponse {
                quote,
                findings,
                scan_elapsed_ms: 12,
            })
            .unwrap();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(http.as_bytes()).unwrap();
        });

        let files = vec![
            IndexedFile {
                rel_path: "src/app.ts".into(),
                abs_path: Path::new("src/app.ts").to_path_buf(),
                language: Language::TypeScript,
                blake3_hash: "0".into(),
                mtime_ns: 0,
                size_bytes: 16,
                cached_bytes: Some(b"export const x=1;".to_vec()),
            },
            IndexedFile {
                rel_path: ".env".into(),
                abs_path: Path::new(".env").to_path_buf(),
                language: Language::Config,
                blake3_hash: "0".into(),
                mtime_ns: 0,
                size_bytes: 12,
                cached_bytes: Some(b"PORT=8080\n".to_vec()),
            },
            IndexedFile {
                rel_path: "certs/tls.pem".into(),
                abs_path: Path::new("certs/tls.pem").to_path_buf(),
                language: Language::Config,
                blake3_hash: "0".into(),
                mtime_ns: 0,
                size_bytes: 12,
                cached_bytes: Some(b"CERTDATA".to_vec()),
            },
        ];

        let policy = AttestationPolicy {
            expected_platform: TeePlatform::IntelTdx,
            allowed_pcr0_hex: vec![pcr0.clone()],
            expected_nonce_hex: nonce.into(),
            max_age_secs: 60,
            authority_pubkey_32: pubkey,
        };

        // Verify subpath preservation (`/tee-gw` -> `/tee-gw/v1/attest` & `/tee-gw/v1/attest-and-scan`)
        let (session, resp) = execute_remote_tee_scan(
            &format!("http://127.0.0.1:{port}/tee-gw"),
            &files,
            None,
            &policy,
            now,
        )
        .unwrap();
        assert_eq!(session.platform, TeePlatform::IntelTdx);
        assert_eq!(session.pcr0_verified, pcr0);
        assert_eq!(resp.scan_elapsed_ms, 12);
        handle.join().unwrap();

        // F5B-01 regression: Rogue enclave failing Phase 1 `GET /v1/attest` MUST abort BEFORE
        // uploading any source files or license token (`POST` never sent).
        let rogue_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rogue_port = rogue_listener.local_addr().unwrap().port();
        let post_count = Arc::new(AtomicUsize::new(0));
        let post_count_srv = Arc::clone(&post_count);
        let rogue_handle = thread::spawn(move || {
            let (mut s1, _) = rogue_listener.accept().unwrap();
            let (line1, _) = read_http_request(&mut s1);
            if line1.starts_with("POST ") {
                post_count_srv.fetch_add(1, Ordering::SeqCst);
            }
            let rogue_quote = sign_tee_quote(
                &pkcs8,
                TeePlatform::IntelTdx,
                &"f".repeat(96), // unpinned PCR0!
                nonce,
                now,
                "rogue-enclave",
            )
            .unwrap();
            let j = serde_json::to_string(&rogue_quote).unwrap();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                j.len(),
                j
            );
            let _ = s1.write_all(http.as_bytes());
        });
        let rogue_err = execute_remote_tee_scan(
            &format!("http://127.0.0.1:{rogue_port}"),
            &files,
            Some("{\"tok\":1}"),
            &policy,
            now,
        )
        .unwrap_err()
        .to_string();
        assert!(rogue_err.contains("unpinned PCR0/MRTD"));
        rogue_handle.join().unwrap();
        assert_eq!(
            post_count.load(Ordering::SeqCst),
            0,
            "must never POST files when pre-attestation fails"
        );

        // Counterexample ENT-03: > 256 files must fail closed instead of silently truncating
        let mut too_many_files = Vec::new();
        for idx in 0..257 {
            too_many_files.push(IndexedFile {
                rel_path: format!("src/f_{idx}.ts"),
                abs_path: Path::new("src/app.ts").to_path_buf(),
                language: Language::TypeScript,
                blake3_hash: "0".into(),
                mtime_ns: 0,
                size_bytes: 2,
                cached_bytes: Some(b"1;".to_vec()),
            });
        }
        let err_many = execute_remote_tee_scan(
            &format!("http://127.0.0.1:{port}"),
            &too_many_files,
            None,
            &policy,
            now,
        )
        .unwrap_err()
        .to_string();
        assert!(err_many.contains("exceeds 256-file enclave payload limit"));
    }

    #[test]
    fn test_sprint8_airgapped_verification_bundle_fail_closed() {
        let (pkcs8, pubkey) = generate_ed25519_keypair().unwrap();
        let report_digest = "a".repeat(64);
        let bin_hash = "b".repeat(64);
        let now = 1_750_000_000u64;
        let bundle = sign_airgapped_bundle(
            &pkcs8,
            "acme-defense-corp",
            &report_digest,
            &bin_hash,
            now - 60,
            now + 3600,
        )
        .unwrap();

        // Valid airgapped bundle passes strictly offline
        verify_airgapped_bundle_fail_closed(&bundle, &pubkey, &report_digest, &bin_hash, now)
            .expect("valid airgapped bundle must verify");

        // F5B-02: Newline/control injection in org_id or inverted timestamps rejected fail-closed
        assert!(
            sign_airgapped_bundle(
                &pkcs8,
                "acme\nreport=0000",
                &report_digest,
                &bin_hash,
                now - 60,
                now + 3600,
            )
            .is_err()
        );
        assert!(
            sign_airgapped_bundle(
                &pkcs8,
                "acme-defense-corp",
                &report_digest,
                &bin_hash,
                now + 3600,
                now - 60,
            )
            .is_err()
        );

        // Tampered report digest fails closed
        assert!(
            verify_airgapped_bundle_fail_closed(&bundle, &pubkey, &"c".repeat(64), &bin_hash, now)
                .is_err()
        );

        // Expired bundle fails closed
        assert!(
            verify_airgapped_bundle_fail_closed(
                &bundle,
                &pubkey,
                &report_digest,
                &bin_hash,
                now + 7200
            )
            .is_err()
        );

        // Tampered org_id fails Ed25519 signature check
        let mut tampered = bundle.clone();
        tampered.org_id = "evil-org".into();
        assert!(
            verify_airgapped_bundle_fail_closed(&tampered, &pubkey, &report_digest, &bin_hash, now)
                .is_err()
        );
    }
}
