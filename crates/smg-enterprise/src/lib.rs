pub mod license;
pub mod tee;

pub use license::{
    LicenseClaims, LicenseTier, SignedLicenseToken, compute_binary_blake3, decode_pubkey_32,
    encode_hex, generate_challenge_nonce_hex, generate_ed25519_keypair, sign_license_claims,
    verify_license_fail_closed,
};
pub use tee::{
    AttestationPolicy, EnclaveHostProbe, RemoteTeeScanRequest, RemoteTeeScanResponse,
    TeeAttestationQuote, TeePlatform, VerifiedEnclaveSession, execute_remote_tee_scan,
    probe_local_tee_hardware, sign_tee_quote, validate_tee_endpoint, verify_tee_attestation_quote,
};

#[cfg(test)]
mod tests {
    use super::*;
    use smg_core::{IndexedFile, Language};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let quote = sign_tee_quote(
                &pkcs8,
                TeePlatform::IntelTdx,
                &pcr0_srv,
                nonce,
                now,
                "tdx-enclave-01",
            )
            .unwrap();
            let body = serde_json::to_string(&RemoteTeeScanResponse {
                quote,
                findings: Vec::new(),
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

        let files = vec![IndexedFile {
            rel_path: "src/app.ts".into(),
            abs_path: Path::new("src/app.ts").to_path_buf(),
            language: Language::TypeScript,
            blake3_hash: "0".into(),
            mtime_ns: 0,
            size_bytes: 16,
            cached_bytes: Some(b"export const x=1;".to_vec()),
        }];

        let policy = AttestationPolicy {
            expected_platform: TeePlatform::IntelTdx,
            allowed_pcr0_hex: vec![pcr0.clone()],
            expected_nonce_hex: nonce.into(),
            max_age_secs: 60,
            authority_pubkey_32: pubkey,
        };

        let (session, resp) = execute_remote_tee_scan(
            &format!("http://127.0.0.1:{port}"),
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
    }
}
