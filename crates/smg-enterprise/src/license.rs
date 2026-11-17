use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseTier {
    Community,
    Pro,
    EnterpriseTee,
}

impl LicenseTier {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "community" | "oss" => Ok(Self::Community),
            "pro" => Ok(Self::Pro),
            "enterprise" | "enterprise-tee" | "tee" => Ok(Self::EnterpriseTee),
            other => {
                bail!("unsupported license tier `{other}` (use community, pro, or enterprise-tee)")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseClaims {
    pub license_id: String,
    pub organization: String,
    pub tier: LicenseTier,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub max_seats: u32,
    pub features: Vec<String>,
    #[serde(default)]
    pub pinned_binary_blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicenseToken {
    pub version: u8,
    pub alg: String,
    pub claims_b64: String,
    pub signature_b64: String,
}

/// Generates a fresh PKCS#8 Ed25519 signing keypair and returns `(pkcs8_bytes, raw_pubkey_32)`.
pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, [u8; 32])> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("Ed25519 key generation failed"))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("Ed25519 PKCS#8 parse failed"))?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(pair.public_key().as_ref());
    Ok((pkcs8.as_ref().to_vec(), pubkey))
}

/// Generates a 16-byte OS CSPRNG single-use TEE attestation challenge nonce as lowercase hex.
pub fn generate_challenge_nonce_hex() -> Result<String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| anyhow::anyhow!("CSPRNG nonce generation failed"))?;
    Ok(hex::encode(bytes))
}

/// Encodes raw bytes as lowercase hex cleanly without extra crate dependencies in callers.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Signs structured `LicenseClaims` with a PKCS#8 Ed25519 private key.
pub fn sign_license_claims(pkcs8_key: &[u8], claims: &LicenseClaims) -> Result<SignedLicenseToken> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8_key)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 signing key"))?;
    let claims_json = serde_json::to_vec(claims)?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);
    let sig = pair.sign(claims_b64.as_bytes());
    Ok(SignedLicenseToken {
        version: 1,
        alg: "Ed25519".to_string(),
        claims_b64,
        signature_b64: URL_SAFE_NO_PAD.encode(sig.as_ref()),
    })
}

/// Streams a binary file and returns its BLAKE3 lowercase hex digest for anti-tamper pinning.
pub fn compute_binary_blake3(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open binary {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Decodes a 32-byte Ed25519 public key from 64-char hex or base64url/base64.
pub fn decode_pubkey_32(raw: &str) -> Result<[u8; 32]> {
    let clean = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = if clean.len() == 64 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(clean).context("invalid hex Ed25519 public key")?
    } else {
        URL_SAFE_NO_PAD
            .decode(raw.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw.trim()))
            .context("invalid Ed25519 public key encoding (expected 64-hex or base64)")?
    };
    if bytes.len() != 32 {
        bail!(
            "Ed25519 public key must be exactly 32 bytes (got {})",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Strictly fail-closed Ed25519 license + binary digest + expiry + tier verification.
/// Never performs destructive host actions on failure; returns an explicit error for clean `exit(1)` / `exit(3)` halt.
pub fn verify_license_fail_closed(
    token: &SignedLicenseToken,
    pubkey_32: &[u8; 32],
    now_unix: u64,
    required_tier: LicenseTier,
    actual_binary_blake3: Option<&str>,
) -> Result<LicenseClaims> {
    if token.version != 1 || token.alg != "Ed25519" {
        bail!("unsupported signed license token envelope (expected v1 Ed25519)");
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(token.signature_b64.trim())
        .context("malformed base64url license signature")?;
    let peer_key = UnparsedPublicKey::new(&ED25519, pubkey_32);
    peer_key
        .verify(token.claims_b64.as_bytes(), &sig_bytes)
        .map_err(|_| {
            anyhow::anyhow!("fail-closed: invalid Ed25519 commercial license signature")
        })?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(token.claims_b64.trim())
        .context("malformed base64url license claims")?;
    let claims: LicenseClaims =
        serde_json::from_slice(&claims_bytes).context("malformed license claims JSON")?;

    if claims.license_id.trim().is_empty() || claims.organization.trim().is_empty() {
        bail!("fail-closed: license missing organization or license_id");
    }
    if now_unix > claims.expires_at_unix {
        bail!(
            "fail-closed: license `{}` expired at unix {} (now={})",
            claims.license_id,
            claims.expires_at_unix,
            now_unix
        );
    }
    if claims.issued_at_unix > now_unix.saturating_add(300) {
        bail!(
            "fail-closed: license `{}` issued in the future ({} > {})",
            claims.license_id,
            claims.issued_at_unix,
            now_unix
        );
    }
    if claims.tier < required_tier {
        bail!(
            "fail-closed: license tier {:?} insufficient for required {:?}",
            claims.tier,
            required_tier
        );
    }
    if let Some(expected_hash) = claims.pinned_binary_blake3.as_deref() {
        let Some(actual) = actual_binary_blake3 else {
            bail!(
                "fail-closed: license pins binary BLAKE3 `{expected_hash}` but binary digest unavailable"
            );
        };
        if !actual.eq_ignore_ascii_case(expected_hash.trim()) {
            bail!(
                "fail-closed: binary integrity digest mismatch (expected {}, got {})",
                expected_hash,
                actual
            );
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_license_verifies_valid_and_fails_closed_on_tamper_expiry_or_binary_mismatch() {
        let (pkcs8, pubkey) = generate_ed25519_keypair().unwrap();
        let claims = LicenseClaims {
            license_id: "lic-2026-ent-01".into(),
            organization: "Acme Confidential Security".into(),
            tier: LicenseTier::EnterpriseTee,
            issued_at_unix: 1_790_000_000,
            expires_at_unix: 1_800_000_000,
            max_seats: 50,
            features: vec!["hw".into(), "web3".into(), "pqc".into(), "tee".into()],
            pinned_binary_blake3: Some("deadbeef".into()),
        };

        let mut token = sign_license_claims(&pkcs8, &claims).unwrap();
        let verified = verify_license_fail_closed(
            &token,
            &pubkey,
            1_795_000_000,
            LicenseTier::EnterpriseTee,
            Some("deadbeef"),
        )
        .unwrap();
        assert_eq!(verified, claims);

        // Wrong binary hash fails closed cleanly
        let err_bin = verify_license_fail_closed(
            &token,
            &pubkey,
            1_795_000_000,
            LicenseTier::EnterpriseTee,
            Some("tampered00"),
        )
        .unwrap_err()
        .to_string();
        assert!(err_bin.contains("binary integrity digest mismatch"));

        // Expired token fails closed cleanly
        let err_exp = verify_license_fail_closed(
            &token,
            &pubkey,
            1_800_000_001,
            LicenseTier::EnterpriseTee,
            Some("deadbeef"),
        )
        .unwrap_err()
        .to_string();
        assert!(err_exp.contains("expired"));

        // Tampered payload/signature fails closed cleanly
        token.claims_b64.push('A');
        assert!(
            verify_license_fail_closed(
                &token,
                &pubkey,
                1_795_000_000,
                LicenseTier::EnterpriseTee,
                Some("deadbeef"),
            )
            .is_err()
        );
    }
}
