use crate::license::ct_eq_bytes;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use smg_core::IndexedFile;
use smg_graph::LatticeFinding;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_blake3_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_blake3_hex: Option<String>,
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

fn is_strict_even_hex(s: &str, min_len: usize) -> bool {
    let t = s.trim();
    t.len() >= min_len && t.len().is_multiple_of(2) && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_quote_fields(q: &TeeAttestationQuote) -> Result<()> {
    if !is_strict_even_hex(&q.pcr0_or_mrtd_hex, 32) {
        bail!(
            "fail-closed TEE attestation: pcr0_or_mrtd_hex must be valid even-length ASCII hex (>= 32 chars)"
        );
    }
    if !is_strict_even_hex(&q.nonce_hex, 8) {
        bail!(
            "fail-closed TEE attestation: nonce_hex must be valid even-length ASCII hex (>= 8 chars)"
        );
    }
    let sess = q.enclave_session_id.trim();
    if sess.is_empty()
        || sess.len() > 128
        || sess.contains('|')
        || sess.chars().any(|c| c.is_control())
    {
        bail!(
            "fail-closed TEE attestation: invalid enclave_session_id (must be 1..=128 chars without `|` or control chars)"
        );
    }
    if let Some(ref req_h) = q.request_blake3_hex
        && !is_strict_even_hex(req_h, 64)
    {
        bail!("fail-closed TEE attestation: invalid request_blake3_hex");
    }
    if let Some(ref fin_h) = q.findings_blake3_hex
        && !is_strict_even_hex(fin_h, 64)
    {
        bail!("fail-closed TEE attestation: invalid findings_blake3_hex");
    }
    Ok(())
}

fn canonical_quote_signing_bytes(q: &TeeAttestationQuote) -> Vec<u8> {
    let plat = match q.platform {
        TeePlatform::AwsNitro => "aws-nitro",
        TeePlatform::IntelTdx => "intel-tdx",
        TeePlatform::AmdSevSnp => "amd-sev-snp",
    };
    let base = format!(
        "smg-tee-v1|{}|{}|{}|{}|{}",
        plat,
        q.pcr0_or_mrtd_hex.trim().to_ascii_lowercase(),
        q.nonce_hex.trim().to_ascii_lowercase(),
        q.issued_at_unix,
        q.enclave_session_id.trim(),
    );
    match (&q.request_blake3_hex, &q.findings_blake3_hex) {
        (None, None) => base.into_bytes(),
        (req_opt, fin_opt) => format!(
            "{}|{}|{}",
            base,
            req_opt.as_deref().unwrap_or("").trim().to_ascii_lowercase(),
            fin_opt.as_deref().unwrap_or("").trim().to_ascii_lowercase()
        )
        .into_bytes(),
    }
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
    sign_tee_quote_with_transcript(
        pkcs8_key,
        platform,
        pcr0_or_mrtd_hex,
        nonce_hex,
        issued_at_unix,
        enclave_session_id,
        None,
        None,
    )
}

/// Signs a TEE attestation quote with optional cryptographic request/findings BLAKE3 transcript hashes.
#[allow(clippy::too_many_arguments)]
pub fn sign_tee_quote_with_transcript(
    pkcs8_key: &[u8],
    platform: TeePlatform,
    pcr0_or_mrtd_hex: &str,
    nonce_hex: &str,
    issued_at_unix: u64,
    enclave_session_id: &str,
    request_blake3_hex: Option<String>,
    findings_blake3_hex: Option<String>,
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
        request_blake3_hex: request_blake3_hex.map(|s| s.trim().to_ascii_lowercase()),
        findings_blake3_hex: findings_blake3_hex.map(|s| s.trim().to_ascii_lowercase()),
    };
    validate_quote_fields(&q)?;
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
    validate_quote_fields(quote)?;
    if quote.platform != policy.expected_platform {
        bail!(
            "fail-closed TEE attestation: platform mismatch (expected {:?}, got {:?})",
            policy.expected_platform,
            quote.platform
        );
    }
    let quote_nonce = quote.nonce_hex.trim().to_ascii_lowercase();
    let expected_nonce = policy.expected_nonce_hex.trim().to_ascii_lowercase();
    if quote_nonce.is_empty() || !ct_eq_bytes(quote_nonce.as_bytes(), expected_nonce.as_bytes()) {
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
    let is_allowed_pcr = !measured.is_empty()
        && policy.allowed_pcr0_hex.iter().any(|p| {
            let p_norm = p.trim().to_ascii_lowercase();
            ct_eq_bytes(measured.as_bytes(), p_norm.as_bytes())
        });
    if !is_allowed_pcr {
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

fn is_url_strictly_loopback(url: &Url) -> bool {
    let Some(raw_host) = url.host_str() else {
        return false;
    };
    let clean_host = raw_host.trim_matches(['[', ']']);
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    if clean_host.eq_ignore_ascii_case("localhost") {
        let port = url.port_or_known_default().unwrap_or(80);
        if let Ok(addrs) = (clean_host, port).to_socket_addrs() {
            let vec: Vec<_> = addrs.collect();
            return !vec.is_empty() && vec.iter().all(|a| a.ip().is_loopback());
        }
        return true;
    }
    false
}

/// Validates that `--remote-tee` enforces HTTPS on remote endpoints (allowing plain HTTP only on verified loopback).
pub fn validate_tee_endpoint(raw_url: &str) -> Result<Url> {
    let url = Url::parse(raw_url.trim())
        .with_context(|| format!("invalid remote TEE URL `{raw_url}`"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("refusing remote TEE URL with embedded credentials");
    }
    let is_loopback = is_url_strictly_loopback(&url);
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

pub fn compute_request_blake3_hex(nonce_hex: &str, files: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = files.keys().collect();
    keys.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce_hex.trim().to_ascii_lowercase().as_bytes());
    for k in keys {
        hasher.update(k.as_bytes());
        hasher.update(&[0u8]);
        if let Some(v) = files.get(k) {
            hasher.update(v.as_bytes());
        }
        hasher.update(&[0u8]);
    }
    hasher.finalize().to_hex().to_string()
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
    if files.len() > 256 {
        bail!(
            "fail-closed remote TEE scan: repository file count ({}) exceeds 256-file enclave payload limit",
            files.len()
        );
    }

    let mut base_url = validate_tee_endpoint(endpoint_url)?;
    if !base_url.path().ends_with('/') {
        let with_slash = format!("{}/", base_url.path());
        base_url.set_path(&with_slash);
    }
    let scan_url = base_url.join("v1/attest-and-scan")?;

    let mut payload_files = HashMap::with_capacity(files.len());
    for f in files {
        let text = if let Some(bytes) = f.cached_bytes.as_deref() {
            std::str::from_utf8(bytes)
                .with_context(|| format!("file `{}` is not valid UTF-8", f.rel_path))?
                .to_string()
        } else {
            let meta = std::fs::symlink_metadata(&f.abs_path).with_context(|| {
                format!(
                    "failed to stat `{}` for remote TEE scan",
                    f.abs_path.display()
                )
            })?;
            if meta.file_type().is_symlink() {
                bail!(
                    "fail-closed remote TEE scan: refusing symlink `{}`",
                    f.rel_path
                );
            }
            if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
                bail!(
                    "fail-closed remote TEE scan: file `{}` exceeds 4 MiB limit or is not a regular file",
                    f.rel_path
                );
            }
            let s = std::fs::read_to_string(&f.abs_path)
                .with_context(|| format!("failed to read `{}`", f.rel_path))?;
            if !f.blake3_hash.is_empty() && f.blake3_hash != "0" {
                let actual_hash = blake3::hash(s.as_bytes()).to_hex().to_string();
                if actual_hash != f.blake3_hash {
                    bail!(
                        "fail-closed remote TEE scan: TOCTOU digest mismatch on `{}`",
                        f.rel_path
                    );
                }
            }
            s
        };
        payload_files.insert(f.rel_path.clone(), text);
    }

    let expected_req_hash = compute_request_blake3_hex(&policy.expected_nonce_hex, &payload_files);

    let req_body = RemoteTeeScanRequest {
        nonce_hex: policy.expected_nonce_hex.clone(),
        license_token_json: license_token_json.map(str::to_string),
        files: payload_files,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
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

    const MAX_RESP_BYTES: usize = 16 * 1024 * 1024;
    let mut raw_bytes = Vec::new();
    resp.take((MAX_RESP_BYTES + 1) as u64)
        .read_to_end(&mut raw_bytes)
        .context("failed to read remote TEE response stream")?;
    if raw_bytes.len() > MAX_RESP_BYTES {
        bail!("fail-closed remote TEE scan: response exceeds 16 MiB limit");
    }

    let body: RemoteTeeScanResponse =
        serde_json::from_slice(&raw_bytes).context("invalid remote TEE response JSON")?;

    let Some(ref quoted_req_hash) = body.quote.request_blake3_hex else {
        bail!("fail-closed TEE attestation: quote is missing mandatory request_blake3_hex binding");
    };
    if !quoted_req_hash
        .trim()
        .eq_ignore_ascii_case(&expected_req_hash)
    {
        bail!(
            "fail-closed TEE attestation: request transcript BLAKE3 mismatch (expected {}, got {})",
            expected_req_hash,
            quoted_req_hash
        );
    }
    let Some(ref quoted_fin_hash) = body.quote.findings_blake3_hex else {
        bail!(
            "fail-closed TEE attestation: quote is missing mandatory findings_blake3_hex binding"
        );
    };
    let findings_json = serde_json::to_vec(&body.findings).unwrap_or_default();
    let expected_fin_hash = blake3::hash(&findings_json).to_hex().to_string();
    if !quoted_fin_hash
        .trim()
        .eq_ignore_ascii_case(&expected_fin_hash)
    {
        bail!(
            "fail-closed TEE attestation: findings transcript BLAKE3 mismatch (expected {}, got {})",
            expected_fin_hash,
            quoted_fin_hash
        );
    }

    let verify_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(now_unix)
        .max(now_unix);
    let session = verify_tee_attestation_quote(&body.quote, policy, verify_now)?;
    Ok((session, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::generate_ed25519_keypair;

    #[test]
    fn tee_quote_pins_pcr0_nonce_platform_and_rejects_delimiter_injection_or_tampering() {
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

        // Pipe delimiter injection in session_id or non-hex in PCR0/nonce must fail closed
        assert!(
            sign_tee_quote(
                &pkcs8,
                TeePlatform::AwsNitro,
                &pcr0,
                nonce,
                1_795_000_000,
                "sess|injected",
            )
            .is_err()
        );
        assert!(
            sign_tee_quote(
                &pkcs8,
                TeePlatform::AwsNitro,
                "not-hex-at-all",
                nonce,
                1_795_000_000,
                "enclave-sess-99",
            )
            .is_err()
        );

        // Wrong PCR0 rejected
        let mut bad_pcr = quote.clone();
        bad_pcr.pcr0_or_mrtd_hex = "b".repeat(96);
        assert!(verify_tee_attestation_quote(&bad_pcr, &policy, 1_795_000_060).is_err());

        // Nonce replay rejected
        let mut bad_nonce = quote.clone();
        bad_nonce.nonce_hex = "cafebabe01020304".into();
        assert!(verify_tee_attestation_quote(&bad_nonce, &policy, 1_795_000_060).is_err());

        // Remote non-HTTPS endpoint refused
        assert!(validate_tee_endpoint("http://tee.example.com").is_err());
        assert!(validate_tee_endpoint("https://tee.example.com").is_ok());
        assert!(validate_tee_endpoint("http://127.0.0.1:8443").is_ok());
        assert!(validate_tee_endpoint("http://127.0.0.2:8443").is_ok());
    }
}
