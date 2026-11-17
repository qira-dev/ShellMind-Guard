use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use smg_core::IndexedFile;
use smg_graph::LatticeFinding;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TeePlatform {
    AwsNitro,
    IntelTdx,
    AmdSevSnp,
}

impl TeePlatform {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "aws-nitro" | "nitro" => Ok(Self::AwsNitro),
            "intel-tdx" | "tdx" => Ok(Self::IntelTdx),
            "amd-sev-snp" | "sev-snp" | "sev" => Ok(Self::AmdSevSnp),
            other => bail!(
                "unsupported TEE platform `{other}` (use aws-nitro, intel-tdx, or amd-sev-snp)"
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationQuote {
    pub platform: TeePlatform,
    /// Hex-encoded SHA-384 Nitro PCR0 or Intel TDX MRTD / AMD SEV-SNP measurement digest.
    pub pcr0_or_mrtd_hex: String,
    pub nonce_hex: String,
    pub issued_at_unix: u64,
    pub enclave_session_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    pub expected_platform: TeePlatform,
    pub allowed_pcr0_hex: Vec<String>,
    pub expected_nonce_hex: String,
    pub max_age_secs: u64,
    pub authority_pubkey_32: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedEnclaveSession {
    pub platform: TeePlatform,
    pub pcr0_verified: String,
    pub session_id: String,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnclaveHostProbe {
    pub nitro_nsm_present: bool,
    pub intel_tdx_present: bool,
    pub amd_sev_present: bool,
    pub any_hardware_enclave_attached: bool,
}

/// Checks local Linux `/dev/*` confidential-compute device nodes honestly without spoofing hardware.
pub fn probe_local_tee_hardware() -> EnclaveHostProbe {
    let nitro = Path::new("/dev/nsm").exists();
    let tdx = Path::new("/dev/tdx_guest").exists() || Path::new("/dev/tdx-attest").exists();
    let sev = Path::new("/dev/sev-guest").exists();
    EnclaveHostProbe {
        nitro_nsm_present: nitro,
        intel_tdx_present: tdx,
        amd_sev_present: sev,
        any_hardware_enclave_attached: nitro || tdx || sev,
    }
}

fn canonical_quote_signing_bytes(q: &TeeAttestationQuote) -> Vec<u8> {
    let plat = match q.platform {
        TeePlatform::AwsNitro => "aws-nitro",
        TeePlatform::IntelTdx => "intel-tdx",
        TeePlatform::AmdSevSnp => "amd-sev-snp",
    };
    format!(
        "smg-tee-v1|{}|{}|{}|{}|{}",
        plat,
        q.pcr0_or_mrtd_hex.trim().to_ascii_lowercase(),
        q.nonce_hex.trim().to_ascii_lowercase(),
        q.issued_at_unix,
        q.enclave_session_id.trim(),
    )
    .into_bytes()
}

/// Signs a TEE attestation quote payload with a PKCS#8 Ed25519 enclave authority key (for CI/enclave issuer use).
pub fn sign_tee_quote(
    pkcs8_key: &[u8],
    platform: TeePlatform,
    pcr0_or_mrtd_hex: &str,
    nonce_hex: &str,
    issued_at_unix: u64,
    enclave_session_id: &str,
) -> Result<TeeAttestationQuote> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8_key)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 attestation key"))?;
    let mut q = TeeAttestationQuote {
        platform,
        pcr0_or_mrtd_hex: pcr0_or_mrtd_hex.trim().to_ascii_lowercase(),
        nonce_hex: nonce_hex.trim().to_ascii_lowercase(),
        issued_at_unix,
        enclave_session_id: enclave_session_id.trim().to_string(),
        signature_b64: String::new(),
    };
    let msg = canonical_quote_signing_bytes(&q);
    q.signature_b64 = URL_SAFE_NO_PAD.encode(pair.sign(&msg).as_ref());
    Ok(q)
}

/// Verifies TEE platform, anti-replay nonce, quote freshness, pinned PCR0/MRTD measurement, and Ed25519 signature.
pub fn verify_tee_attestation_quote(
    quote: &TeeAttestationQuote,
    policy: &AttestationPolicy,
    now_unix: u64,
) -> Result<VerifiedEnclaveSession> {
    if quote.platform != policy.expected_platform {
        bail!(
            "fail-closed TEE attestation: platform mismatch (expected {:?}, got {:?})",
            policy.expected_platform,
            quote.platform
        );
    }
    if quote.nonce_hex.trim().is_empty()
        || !quote
            .nonce_hex
            .trim()
            .eq_ignore_ascii_case(policy.expected_nonce_hex.trim())
    {
        bail!("fail-closed TEE attestation: nonce challenge mismatch (possible replay)");
    }
    if quote.issued_at_unix > now_unix.saturating_add(60) {
        bail!("fail-closed TEE attestation: quote timestamp is in the future");
    }
    if now_unix.saturating_sub(quote.issued_at_unix) > policy.max_age_secs {
        bail!(
            "fail-closed TEE attestation: quote expired (age {}s > max {}s)",
            now_unix.saturating_sub(quote.issued_at_unix),
            policy.max_age_secs
        );
    }

    let measured = quote.pcr0_or_mrtd_hex.trim().to_ascii_lowercase();
    if measured.is_empty()
        || !policy
            .allowed_pcr0_hex
            .iter()
            .any(|p| p.trim().eq_ignore_ascii_case(&measured))
    {
        bail!(
            "fail-closed TEE attestation: unpinned PCR0/MRTD measurement `{}`",
            measured
        );
    }

    let sig = URL_SAFE_NO_PAD
        .decode(quote.signature_b64.trim())
        .context("malformed TEE attestation signature base64url")?;
    let msg = canonical_quote_signing_bytes(quote);
    let pk = UnparsedPublicKey::new(&ED25519, &policy.authority_pubkey_32);
    pk.verify(&msg, &sig).map_err(|_| {
        anyhow::anyhow!("fail-closed TEE attestation: invalid Ed25519 quote signature")
    })?;

    Ok(VerifiedEnclaveSession {
        platform: quote.platform,
        pcr0_verified: measured,
        session_id: quote.enclave_session_id.clone(),
        issued_at_unix: quote.issued_at_unix,
    })
}

/// Validates that `--remote-tee` enforces HTTPS on remote endpoints (allowing plain HTTP only on loopback).
pub fn validate_tee_endpoint(raw_url: &str) -> Result<Url> {
    let url = Url::parse(raw_url.trim())
        .with_context(|| format!("invalid remote TEE URL `{raw_url}`"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("refusing remote TEE URL with embedded credentials");
    }
    let host = url.host_str().unwrap_or("");
    let is_loopback =
        host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback => Ok(url),
        "http" => bail!("refusing unencrypted http:// remote TEE URL `{raw_url}`; use https://"),
        other => bail!("unsupported remote TEE URL scheme `{other}`"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTeeScanRequest {
    pub nonce_hex: String,
    pub license_token_json: Option<String>,
    pub files: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTeeScanResponse {
    pub quote: TeeAttestationQuote,
    pub findings: Vec<LatticeFinding>,
    pub scan_elapsed_ms: u128,
}

/// Submits bounded source files over HTTPS/loopback to a remote TEE enclave worker and verifies its
/// cryptographic PCR0/MRTD quote before returning findings.
pub fn execute_remote_tee_scan(
    endpoint_url: &str,
    files: &[IndexedFile],
    license_token_json: Option<&str>,
    policy: &AttestationPolicy,
    now_unix: u64,
) -> Result<(VerifiedEnclaveSession, RemoteTeeScanResponse)> {
    let validated = validate_tee_endpoint(endpoint_url)?;
    let scan_url = validated.join("v1/attest-and-scan")?;

    let mut payload_files = HashMap::new();
    for f in files.iter().take(256) {
        if let Some(bytes) = f.cached_bytes.as_deref()
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            payload_files.insert(f.rel_path.clone(), text.to_string());
        } else if let Ok(text) = std::fs::read_to_string(&f.abs_path) {
            payload_files.insert(f.rel_path.clone(), text);
        }
    }

    let req_body = RemoteTeeScanRequest {
        nonce_hex: policy.expected_nonce_hex.clone(),
        license_token_json: license_token_json.map(str::to_string),
        files: payload_files,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let resp = client
        .post(scan_url)
        .json(&req_body)
        .send()
        .context("remote TEE scan request failed")?;
    if !resp.status().is_success() {
        bail!("remote TEE endpoint returned HTTP {}", resp.status());
    }
    let body: RemoteTeeScanResponse = resp.json().context("invalid remote TEE response JSON")?;
    let session = verify_tee_attestation_quote(&body.quote, policy, now_unix)?;
    Ok((session, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::generate_ed25519_keypair;

    #[test]
    fn tee_quote_pins_pcr0_nonce_platform_and_rejects_tampering() {
        let (pkcs8, pubkey) = generate_ed25519_keypair().unwrap();
        let pcr0 = "a".repeat(96);
        let nonce = "deadbeef01020304";
        let quote = sign_tee_quote(
            &pkcs8,
            TeePlatform::AwsNitro,
            &pcr0,
            nonce,
            1_795_000_000,
            "enclave-sess-99",
        )
        .unwrap();

        let policy = AttestationPolicy {
            expected_platform: TeePlatform::AwsNitro,
            allowed_pcr0_hex: vec![pcr0.clone()],
            expected_nonce_hex: nonce.into(),
            max_age_secs: 300,
            authority_pubkey_32: pubkey,
        };

        let verified = verify_tee_attestation_quote(&quote, &policy, 1_795_000_060).unwrap();
        assert_eq!(verified.pcr0_verified, pcr0);
        assert_eq!(verified.session_id, "enclave-sess-99");

        // Wrong PCR0 rejected
        let mut bad_pcr = quote.clone();
        bad_pcr.pcr0_or_mrtd_hex = "b".repeat(96);
        assert!(verify_tee_attestation_quote(&bad_pcr, &policy, 1_795_000_060).is_err());

        // Nonce replay rejected
        let mut bad_nonce = quote.clone();
        bad_nonce.nonce_hex = "cafebabe".into();
        assert!(verify_tee_attestation_quote(&bad_nonce, &policy, 1_795_000_060).is_err());

        // Remote non-HTTPS endpoint refused
        assert!(validate_tee_endpoint("http://tee.example.com").is_err());
        assert!(validate_tee_endpoint("https://tee.example.com").is_ok());
        assert!(validate_tee_endpoint("http://127.0.0.1:8443").is_ok());
    }
}
