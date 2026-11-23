//! Opt-in TLS interception plane for the local proxy (`smg proxy --mitm-ca`).
//!
//! Defensive lab tooling (Burp CE-class HTTPS inspection):
//! - A local root CA (`~/.config/smg/ca-cert.pem` + `ca-key.pem`) is
//!   load-or-created with `rcgen` (ECDSA P-256). The key file is 0600 and the
//!   directory 0700; the CA is only ever used to sign leaf certificates for
//!   hosts the operator's own lab traffic targets.
//! - Every `CONNECT host:443` gets an on-the-fly leaf certificate with the
//!   CONNECT host as its only SAN (IP literals get `SanType::IpAddress`,
//!   domains `SanType::DnsName`), signed by the local CA and cached per host.
//! - Both sides use synchronous rustls with ALPN pinned to `http/1.1` (the
//!   proxy parser is HTTP/1.1-only, so h2 must never negotiate).
//! - Upstream TLS is validated against the OS trust store first and falls back
//!   to an accept-all verifier for lab origins with self-signed certificates —
//!   the same convention the rest of smg's live engines use on loopback hosts.

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CA_CERT_FILE: &str = "ca-cert.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CERT_CACHE_ENTRIES: usize = 512;

fn current_year() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    1970 + (secs / (365 * 24 * 3600 + 6 * 3600)) as i32
}

/// Base params for the fixed-subject local root CA. The CN is shared by the
/// generation and load paths so a signed leaf's issuer DN always matches the
/// certificate actually presented by the proxy.
fn synthetic_issuer_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "ShellMind Guard Root CA");
    params
}

/// Accept-all server-cert verifier for upstream TLS to lab origins with
/// self-signed certificates (same convention as `tls_audit` / `templates_audit`).
#[derive(Debug)]
struct UpstreamInsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for UpstreamInsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Resolver that always serves the pre-signed leaf for one CONNECT host.
#[derive(Debug)]
struct FixedCertResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

pub struct MitmCa {
    ca_dir: PathBuf,
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
    /// In-memory issuer handle for rcgen leaf signing. For a freshly
    /// generated CA this is the CA itself; for a loaded CA it is a synthetic
    /// re-materialization with the same subject DN and key pair (rcgen 0.13
    /// cannot reconstruct a `Certificate` from a PEM without the heavyweight
    /// `x509-parser` feature). Its DER is never used — only the subject DN and
    /// key identifier flow into signed leaves.
    issuer_cert: rcgen::Certificate,
    ca_key: KeyPair,
    leaf_key: KeyPair,
    leaf_key_der: PrivateKeyDer<'static>,
    upstream_validated: Arc<rustls::ClientConfig>,
    upstream_insecure: Arc<rustls::ClientConfig>,
    leaf_cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    server_cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl std::fmt::Debug for MitmCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmCa")
            .field("ca_dir", &self.ca_dir)
            .finish_non_exhaustive()
    }
}

impl MitmCa {
    /// Loads the existing local CA or generates one. Idempotent.
    pub fn load_or_create(ca_dir: &Path) -> Result<Self> {
        crate::idor_audit::ensure_rustls_ring_provider();
        create_private_dir_0700(ca_dir)
            .with_context(|| format!("failed to create CA dir {}", ca_dir.display()))?;
        restrict_dir(ca_dir);
        let cert_pem_path = ca_dir.join(CA_CERT_FILE);
        let key_pem_path = ca_dir.join(CA_KEY_FILE);
        for p in [&cert_pem_path, &key_pem_path] {
            if let Ok(meta) = std::fs::symlink_metadata(p)
                && meta.file_type().is_symlink()
            {
                bail!("Refusing symlinked CA material at {}", p.display());
            }
        }

        let (issuer_cert, ca_key) = if cert_pem_path.exists() && key_pem_path.exists() {
            let key = KeyPair::from_pem(&std::fs::read_to_string(&key_pem_path)?)
                .context("parsing ca-key.pem")?;
            // Synthetic issuer with the fixed subject DN of our CA; see the
            // `issuer_cert` field docs for why no DER round-trip is needed.
            (synthetic_issuer_params().self_signed(&key)?, key)
        } else {
            let key = KeyPair::generate().context("generating CA key")?;
            let year = current_year();
            let mut params = synthetic_issuer_params();
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
            params.not_after = rcgen::date_time_ymd(year + 10, 1, 1);
            let cert = params.self_signed(&key).context("signing local root CA")?;
            std::fs::write(&cert_pem_path, cert.pem())
                .with_context(|| format!("writing {}", cert_pem_path.display()))?;
            write_private_file_0600(&key_pem_path, key.serialize_pem().as_bytes())
                .with_context(|| format!("writing {}", key_pem_path.display()))?;
            restrict_file(&key_pem_path);
            (cert, key)
        };

        // One shared leaf signing key: every host gets its own certificate for
        // it, so a leaked leaf does not compromise the CA itself.
        let leaf_key = KeyPair::generate().context("generating shared leaf key")?;
        let leaf_key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());

        Ok(Self {
            ca_dir: ca_dir.to_path_buf(),
            cert_pem_path,
            key_pem_path,
            issuer_cert,
            ca_key,
            leaf_key,
            leaf_key_der,
            upstream_validated: Arc::new(build_upstream_config(false)?),
            upstream_insecure: Arc::new(build_upstream_config(true)?),
            leaf_cache: Mutex::new(HashMap::new()),
            server_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Signs (or fetches from cache) the on-the-fly leaf for `host`.
    fn leaf_certified_key(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(key) = self
            .leaf_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
        {
            return Ok(Arc::clone(key));
        }
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        // IP literals need an iPAddress SAN; domains a dNSName SAN.
        params.subject_alt_names = vec![match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                rcgen::Ia5String::try_from(host.to_owned())
                    .with_context(|| format!("invalid DNS name '{host}'"))?,
            ),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let year = current_year();
        params.not_before = rcgen::date_time_ymd(year, 1, 1);
        params.not_after = rcgen::date_time_ymd(year + 1, 1, 1);
        let cert = params
            .signed_by(&self.leaf_key, &self.issuer_cert, &self.ca_key)
            .with_context(|| format!("signing leaf certificate for '{host}'"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&self.leaf_key_der)
            .map_err(|e| anyhow::anyhow!("leaf signing key unsupported: {e}"))?;
        let key = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing_key));
        let mut cache = self.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_CERT_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(host.to_string(), Arc::clone(&key));
        Ok(key)
    }

    /// A cached rustls server config serving this host's leaf, ALPN pinned to
    /// HTTP/1.1.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(cfg) = self
            .server_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
        {
            return Ok(Arc::clone(cfg));
        }
        let key = self.leaf_certified_key(host)?;
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCertResolver { key }));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        let mut cache = self.server_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_CERT_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(host.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }

    /// Connects to `host:port` with TLS: OS trust store first, accept-all
    /// fallback ONLY for loopback / RFC1918 lab origins with self-signed
    /// certificates (remote internet origins always require validated TLS).
    /// Unconditionally denies cloud metadata / link-local / unspecified destinations.
    pub fn connect_upstream(
        &self,
        host: &str,
        port: u16,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let addrs = crate::idor_audit::resolve_and_validate_live_addrs(host, port, true)?;
        let addr = addrs[0];
        let name = ServerName::try_from(host.to_string())
            .with_context(|| format!("invalid upstream server name '{host}'"))?;
        let allow_insecure_fallback = crate::idor_audit::is_lab_ip(addr.ip());
        let mut configs = vec![Arc::clone(&self.upstream_validated)];
        if allow_insecure_fallback {
            configs.push(Arc::clone(&self.upstream_insecure));
        }
        let mut last_err = None;
        for cfg in configs {
            let mut attempt = match TcpStream::connect_timeout(&addr, UPSTREAM_HANDSHAKE_TIMEOUT) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(anyhow::Error::new(e).context("upstream TCP connect"));
                    continue;
                }
            };
            let _ = attempt.set_read_timeout(Some(Duration::from_secs(60)));
            let _ = attempt.set_write_timeout(Some(Duration::from_secs(60)));
            let Ok(mut conn) = rustls::ClientConnection::new(cfg, name.clone()) else {
                last_err = Some(anyhow::anyhow!("TLS client init failed"));
                continue;
            };
            // Drive the handshake on the raw socket pair; only wrap the
            // streams once it has completed (lab origins with self-signed
            // certs fail here and fall back to the accept-all config).
            match drive_upstream_handshake(&mut conn, &mut attempt) {
                Ok(()) => return Ok(rustls::StreamOwned::new(conn, attempt)),
                Err(e) => last_err = Some(e),
            }
        }
        bail!(
            "upstream TLS handshake to {host}:{port} failed: {}",
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".into())
        )
    }
}

fn build_upstream_config(insecure: bool) -> Result<rustls::ClientConfig> {
    let mut cfg = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(UpstreamInsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    // The proxy speaks HTTP/1.1 only; never let h2 negotiate.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Drives the upstream TLS handshake to completion with `complete_io`.
/// A rejected certificate (or any alert) surfaces as `Err`, which the caller
/// turns into the accept-all fallback attempt.
fn drive_upstream_handshake(
    conn: &mut rustls::ClientConnection,
    sock: &mut TcpStream,
) -> Result<()> {
    let deadline = std::time::Instant::now() + UPSTREAM_HANDSHAKE_TIMEOUT;
    while conn.is_handshaking() {
        if std::time::Instant::now() > deadline {
            bail!("upstream TLS handshake timed out");
        }
        conn.complete_io(sock).context("upstream TLS handshake")?;
    }
    Ok(())
}

/// Completes the client-side TLS handshake of a proxy MITM session. `Ok(())`
/// means the leaf was accepted (or the client warned-and-continued).
pub fn drive_client_handshake(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
) -> Result<()> {
    while conn.is_handshaking() {
        conn.complete_io(sock).context("client TLS handshake")?;
    }
    Ok(())
}

pub fn default_ca_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("HOME/USERPROFILE environment variable is not set; cannot locate ~/.config/smg")?;
    Ok(PathBuf::from(home).join(".config").join("smg"))
}

/// Loads/creates the default CA and prints (or copies) `ca-cert.pem` so the
/// user can import it into their browser/system trust store.
pub fn export_ca(out: Option<&Path>) -> Result<()> {
    let dir = default_ca_dir()?;
    let ca = MitmCa::load_or_create(&dir)?;
    let pem = std::fs::read_to_string(&ca.cert_pem_path)?;
    match out {
        Some(path) => {
            std::fs::write(path, &pem)
                .with_context(|| format!("writing CA cert to {}", path.display()))?;
            println!("CA certificate written to {}", path.display());
        }
        None => print!("{pem}"),
    }
    println!();
    println!("ShellMind Guard MITM CA (inspect with `openssl x509 -in <file> -noout -text`):");
    println!("  cert: {}", ca.cert_pem_path.display());
    println!(
        "  key:  {} (0600, never leaves this machine)",
        ca.key_pem_path.display()
    );
    println!();
    println!("Trust it (local lab only):");
    println!(
        "  Firefox: Settings > Privacy & Security > Certificates > View Certificates > Import"
    );
    println!("  Chromium/Chrome: chrome://settings/certificates > Authorities > Import, or");
    println!(
        "  `certutil -d sql:$HOME/.pki/nssdb -A -t \"CT,c,c\" -n \"ShellMind Guard Root CA\" -i {}`",
        ca.cert_pem_path.display()
    );
    println!(
        "  System (Debian/Ubuntu): sudo cp {} /usr/local/share/ca-certificates/smg-root-ca.crt && sudo update-ca-certificates",
        ca.cert_pem_path.display()
    );
    Ok(())
}

fn create_private_dir_0700(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn write_private_file_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(data)
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ca_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("smg-mitm-ca-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ca_generation_is_idempotent() {
        let dir = temp_ca_dir("idempotent");
        let ca1 = MitmCa::load_or_create(&dir).unwrap();
        let pem1 = std::fs::read_to_string(&ca1.cert_pem_path).unwrap();
        let ca2 = MitmCa::load_or_create(&dir).unwrap();
        let pem2 = std::fs::read_to_string(&ca2.cert_pem_path).unwrap();
        assert_eq!(pem1, pem2, "second load must reuse the persisted CA");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaf_sans_cover_ip_literals_and_domains() {
        let dir = temp_ca_dir("san");
        let ca = MitmCa::load_or_create(&dir).unwrap();
        // Both resolve paths must succeed; the IP literal proves the
        // SanType::IpAddress branch (curl/browser validation depends on it).
        let ip_key = ca.leaf_certified_key("127.0.0.1").unwrap();
        let dns_key = ca.leaf_certified_key("lab.example.test").unwrap();
        assert!(!ip_key.cert.is_empty());
        assert!(!dns_key.cert.is_empty());
        // Cached second call returns the same leaf (cheap, no re-sign).
        let ip_key2 = ca.leaf_certified_key("127.0.0.1").unwrap();
        assert!(Arc::ptr_eq(&ip_key, &ip_key2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
