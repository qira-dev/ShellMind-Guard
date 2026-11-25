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

fn is_forbidden_tee_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let oct = v4.octets();
    let is_alibaba_imds = oct == [100, 100, 100, 200];
    let is_oracle_imds = oct == [192, 0, 0, 192];
    v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || is_alibaba_imds
        || is_oracle_imds
}

fn is_forbidden_tee_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_tee_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                is_forbidden_tee_ipv4(mapped)
            } else {
                let segs = v6.segments();
                let is_aws_imds_v6 = segs == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254];
                v6.is_unspecified()
                    || v6.is_multicast()
                    || (segs[0] & 0xffc0) == 0xfe80
                    || is_aws_imds_v6
            }
        }
    }
}

fn is_loopback_tee_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

/// Returns `true` if `rel_path` names a secret, credential, or private-key artifact that must not
/// be uploaded to a remote TEE worker by default.
pub fn is_sensitive_secret_path(rel_path: &str) -> bool {
    let fname = rel_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel_path)
        .trim()
        .to_ascii_lowercase();
    if fname.is_empty() {
        return false;
    }
    if fname == ".env"
        || fname.ends_with(".env")
        || (fname.starts_with(".env.")
            && !matches!(
                fname.as_str(),
                ".env.example" | ".env.sample" | ".env.template"
            ))
    {
        return true;
    }
    if fname.ends_with(".pem")
        || fname.ends_with(".key")
        || fname.ends_with(".p12")
        || fname.ends_with(".pfx")
        || fname.ends_with(".pkcs8")
        || fname.ends_with(".kdbx")
        || fname.ends_with(".keystore")
        || fname.ends_with(".jks")
    {
        return true;
    }
    matches!(
        fname.as_str(),
        "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa" | ".netrc" | ".npmrc" | ".pypirc"
    )
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
        // Fail closed when `localhost` cannot be resolved cleanly.
        return false;
    }
    false
}

/// Validates that `--remote-tee` enforces HTTPS on remote endpoints (allowing plain HTTP only on verified loopback)
/// and unconditionally denies cloud metadata / link-local / unspecified hosts.
pub fn validate_tee_endpoint(raw_url: &str) -> Result<Url> {
    let url = Url::parse(raw_url.trim())
        .with_context(|| format!("invalid remote TEE URL `{raw_url}`"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("refusing remote TEE URL with embedded credentials");
    }
    if let Some(host) = url.host_str() {
        let clean = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        if matches!(
            clean.as_str(),
            "metadata.google.internal"
                | "metadata.goog"
                | "metadata.azure.com"
                | "169.254.169.254"
                | "100.100.100.200"
                | "192.0.0.192"
                | "fd00:ec2::254"
        ) {
            bail!("refusing cloud metadata host `{host}` for remote TEE endpoint");
        }
        if let Ok(ip) = clean.parse::<IpAddr>()
            && is_forbidden_tee_ip(ip)
        {
            bail!("refusing link-local/unspecified/IMDS IP `{host}` for remote TEE endpoint");
        }
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
/// cryptographic PCR0/MRTD quote before returning findings. Sensitive secret/key files (`.env`,
/// `.pem`, `.key`, `id_rsa`, etc.) are excluded from upload payloads by default.
pub fn execute_remote_tee_scan(
    endpoint_url: &str,
    files: &[IndexedFile],
    license_token_json: Option<&str>,
    policy: &AttestationPolicy,
    now_unix: u64,
) -> Result<(VerifiedEnclaveSession, RemoteTeeScanResponse)> {
    execute_remote_tee_scan_with_options(
        endpoint_url,
        files,
        license_token_json,
        policy,
        now_unix,
        false,
    )
}

/// Submits bounded source files over HTTPS/loopback to a remote TEE enclave worker with explicit
/// control over whether sensitive secret/key files may be included in the upload payload.
pub fn execute_remote_tee_scan_with_options(
    endpoint_url: &str,
    files: &[IndexedFile],
    license_token_json: Option<&str>,
    policy: &AttestationPolicy,
    now_unix: u64,
    include_secret_files: bool,
) -> Result<(VerifiedEnclaveSession, RemoteTeeScanResponse)> {
    if files.len() > 256 {
        bail!(
            "fail-closed remote TEE scan: repository file count ({}) exceeds 256-file enclave payload limit",
            files.len()
        );
    }

    let mut base_url = validate_tee_endpoint(endpoint_url)?;
    let is_strict_loopback = is_url_strictly_loopback(&base_url);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut client_builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30));

    // Verify DNS-resolved destination IPs and pin them into `reqwest` via `resolve_to_addrs`
    // to eliminate DNS-rebinding TOCTOU against loopback or cloud IMDS / link-local ranges.
    if let Some(host_owned) = base_url.host_str().map(str::to_string) {
        let clean = host_owned.trim_matches(['[', ']']);
        let default_port = if base_url.scheme() == "http" { 80 } else { 443 };
        let port = base_url.port_or_known_default().unwrap_or(default_port);
        let resolved: Vec<_> = (clean, port)
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve remote TEE host `{host_owned}`"))?
            .collect();
        if resolved.is_empty()
            || resolved.iter().any(|sa| {
                is_forbidden_tee_ip(sa.ip()) || (!is_strict_loopback && is_loopback_tee_ip(sa.ip()))
            })
        {
            bail!(
                "refusing remote TEE host `{host_owned}` resolving to loopback/link-local/IMDS/unspecified IP"
            );
        }
        if clean.parse::<IpAddr>().is_err() {
            client_builder = client_builder.resolve_to_addrs(clean, &resolved);
        }
    }

    if !base_url.path().ends_with('/') {
        let with_slash = format!("{}/", base_url.path());
        base_url.set_path(&with_slash);
    }
    let mut attest_url = base_url.join("v1/attest")?;
    attest_url
        .query_pairs_mut()
        .append_pair("nonce", &policy.expected_nonce_hex);
    let scan_url = base_url.join("v1/attest-and-scan")?;

    let client = client_builder.build()?;

    // Phase 1: Pre-upload enclave attestation handshake (`GET /v1/attest?nonce=...`) BEFORE
    // reading or transmitting any repository source files or license token.
    let pre_resp = client
        .get(attest_url)
        .send()
        .context("remote TEE pre-upload attestation probe (`GET /v1/attest`) failed")?;
    let pre_session = if pre_resp.status().is_success() {
        const MAX_ATTEST_BYTES: usize = 64 * 1024;
        let mut pre_bytes = Vec::new();
        pre_resp
            .take((MAX_ATTEST_BYTES + 1) as u64)
            .read_to_end(&mut pre_bytes)
            .context("failed to read remote TEE pre-attestation quote")?;
        if pre_bytes.len() > MAX_ATTEST_BYTES {
            bail!("fail-closed remote TEE scan: pre-attestation quote exceeds 64 KiB limit");
        }
        let pre_quote: TeeAttestationQuote = serde_json::from_slice(&pre_bytes)
            .context("invalid remote TEE pre-attestation quote JSON")?;
        let pre_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(now_unix)
            .max(now_unix);
        Some(verify_tee_attestation_quote(&pre_quote, policy, pre_now)?)
    } else if is_strict_loopback
        && base_url.scheme() == "http"
        && matches!(
            pre_resp.status(),
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
        )
    {
        None
    } else {
        bail!(
            "fail-closed remote TEE pre-attestation (`GET /v1/attest`) returned HTTP {}",
            pre_resp.status()
        );
    };

    let mut payload_files = HashMap::with_capacity(files.len());
    for f in files {
        if !include_secret_files && is_sensitive_secret_path(&f.rel_path) {
            continue;
        }
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
    let quoted_req_norm = quoted_req_hash.trim().to_ascii_lowercase();
    if !ct_eq_bytes(quoted_req_norm.as_bytes(), expected_req_hash.as_bytes()) {
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
    let quoted_fin_norm = quoted_fin_hash.trim().to_ascii_lowercase();
    if !ct_eq_bytes(quoted_fin_norm.as_bytes(), expected_fin_hash.as_bytes()) {
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
    if let Some(ref pre) = pre_session
        && !ct_eq_bytes(
            session.pcr0_verified.as_bytes(),
            pre.pcr0_verified.as_bytes(),
        )
    {
        bail!(
            "fail-closed TEE attestation: enclave PCR0/MRTD changed between pre-attestation and scan"
        );
    }
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

        // Remote non-HTTPS endpoint refused & cloud IMDS endpoints blocked
        assert!(validate_tee_endpoint("http://tee.example.com").is_err());
        assert!(validate_tee_endpoint("https://tee.example.com").is_ok());
        assert!(validate_tee_endpoint("https://100.100.100.200:8443").is_err());
        assert!(validate_tee_endpoint("https://192.0.0.192:8443").is_err());
        assert!(validate_tee_endpoint("https://[::ffff:169.254.169.254]:8443").is_err());
        assert!(validate_tee_endpoint("https://[::ffff:100.100.100.200]:8443").is_err());
        assert!(validate_tee_endpoint("http://127.0.0.1:8443").is_ok());
        assert!(validate_tee_endpoint("http://127.0.0.2:8443").is_ok());

        // Sensitive secret/key files excluded by default
        assert!(is_sensitive_secret_path(".env"));
        assert!(is_sensitive_secret_path("config/.env.production"));
        assert!(is_sensitive_secret_path("certs/private.pem"));
        assert!(is_sensitive_secret_path("keys/tls.key"));
        assert!(is_sensitive_secret_path(".ssh/id_rsa"));
        assert!(!is_sensitive_secret_path(".env.example"));
        assert!(!is_sensitive_secret_path("src/app.ts"));
    }
}
