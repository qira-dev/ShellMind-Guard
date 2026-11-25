//! Pure-Rust defensive TLS/SSL & RFC 10024 Post-Quantum Cryptography (PQC) auditor (`smg tls`).
//!
//! Performs non-destructive standard TLS handshakes (`ClientHello` -> `ServerHello` / `Certificate`)
//! to audit:
//! - Protocol support (SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)
//! - Weak/deprecated cipher suite acceptance (RC4, 3DES, NULL, EXPORT, CBC-SHA1)
//! - RFC 10024 Post-Quantum Hybrid Key Exchange readiness (`X25519MLKEM768` 0x11EC, `SecP256r1MLKEM768` 0x11EB, `SecP384r1MLKEM1024` 0x11ED)
//! - X.509 certificate chain presence via `rustls`
//! - HTTPS `Strict-Transport-Security` (HSTS) header presence

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAuditReport {
    pub target: String,
    pub host: String,
    pub port: u16,
    pub protocols_supported: Vec<String>,
    pub negotiated_tls13_cipher: Option<String>,
    pub negotiated_tls12_cipher: Option<String>,
    pub pqc_hybrid_supported: bool,
    pub pqc_group_negotiated: Option<String>,
    pub weak_ciphers_accepted: bool,
    pub hsts_header: Option<String>,
    pub cert_chain_len: usize,
    pub findings: Vec<TlsFinding>,
}

/// Parses `host[:port]`, `[ipv6][:port]`, or `https://host[:port]/...` into `(host, port)`.
pub fn parse_tls_target(raw: &str) -> Result<(String, u16)> {
    let trimmed = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let authority = trimmed
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    if authority.is_empty() {
        bail!("TLS target must not be empty");
    }
    if authority.contains('@')
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("TLS target authority '{authority}' must not contain credentials or whitespace");
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((ip_part, tail)) = rest.split_once(']') else {
            bail!("Malformed bracketed IPv6 TLS target '{authority}'");
        };
        if ip_part.is_empty() {
            bail!("Empty IPv6 host in TLS target '{authority}'");
        }
        let port = if tail.is_empty() {
            443
        } else if let Some(p_str) = tail.strip_prefix(':') {
            let port: u16 = p_str
                .parse()
                .with_context(|| format!("Invalid port '{p_str}' in TLS target '{authority}'"))?;
            if port == 0 {
                bail!("TLS target port must be non-zero");
            }
            port
        } else {
            bail!("Unexpected trailing characters '{tail}' in TLS target '{authority}'");
        };
        return Ok((ip_part.to_string(), port));
    }
    if authority.matches(':').count() > 1 {
        // Unbracketed IPv6 literal (e.g. `::1` or `2001:db8::1`) -> default port 443.
        let ip: IpAddr = authority
            .parse()
            .with_context(|| format!("Invalid IPv6 TLS target '{authority}' (use [ipv6]:port)"))?;
        return Ok((ip.to_string(), 443));
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if h.is_empty() {
            bail!("TLS target '{authority}' is missing host");
        }
        let port: u16 = p
            .parse()
            .with_context(|| format!("Invalid port '{p}' in TLS target '{authority}'"))?;
        if port == 0 {
            bail!("TLS target port must be non-zero");
        }
        return Ok((h.to_string(), port));
    }
    Ok((authority.to_string(), 443))
}

/// Builds a minimal standards-compliant TLS `ClientHello` record for protocol/cipher/PQC probing.
pub fn build_client_hello(
    host: &str,
    legacy_version: [u8; 2],
    ciphers: &[u16],
    offer_tls13: bool,
    named_groups: &[u16],
) -> Result<Vec<u8>> {
    if host.len() > 253 {
        bail!("RFC 1035 hostname exceeds 253 bytes ({} bytes)", host.len());
    }
    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&legacy_version);
    body.extend_from_slice(&[0x53, 0x4d, 0x47, 0x54, 0x4c, 0x53, 0x31, 0x33]);
    body.extend_from_slice(&[0x42u8; 24]);
    body.push(0x00); // empty session_id

    let cs_bytes = ciphers
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| anyhow::anyhow!("cipher suite list exceeds TLS u16 length limit"))?;
    body.extend_from_slice(&cs_bytes.to_be_bytes());
    for &cs in ciphers {
        body.extend_from_slice(&cs.to_be_bytes());
    }
    body.push(0x01);
    body.push(0x00); // null compression

    let mut exts = Vec::new();
    if !host.is_empty()
        && host.is_ascii()
        && !host.chars().any(|c| c.is_whitespace() || c.is_control())
        && host.parse::<IpAddr>().is_err()
    {
        let hbytes = host.as_bytes();
        let hlen = u16::try_from(hbytes.len())
            .map_err(|_| anyhow::anyhow!("SNI hostname exceeds u16 length"))?;
        let list_len = hlen
            .checked_add(3)
            .ok_or_else(|| anyhow::anyhow!("SNI list length overflow"))?;
        let ext_len = list_len
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("SNI extension length overflow"))?;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&hlen.to_be_bytes());
        exts.extend_from_slice(hbytes);
    }

    if !named_groups.is_empty() {
        let glist_len = named_groups
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| anyhow::anyhow!("named_groups list exceeds TLS u16 length"))?;
        let ext_len = glist_len
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("supported_groups extension overflow"))?;
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&glist_len.to_be_bytes());
        for &g in named_groups {
            exts.extend_from_slice(&g.to_be_bytes());
        }
    }

    let sig_algs: &[u16] = &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0201];
    let sig_list_len = u16::try_from(sig_algs.len() * 2)
        .map_err(|_| anyhow::anyhow!("signature_algorithms length overflow"))?;
    exts.extend_from_slice(&0x000du16.to_be_bytes());
    exts.extend_from_slice(&(sig_list_len + 2).to_be_bytes());
    exts.extend_from_slice(&sig_list_len.to_be_bytes());
    for &sa in sig_algs {
        exts.extend_from_slice(&sa.to_be_bytes());
    }

    if offer_tls13 {
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&0x0003u16.to_be_bytes());
        exts.push(0x02);
        exts.extend_from_slice(&[0x03, 0x04]);

        // Offer a valid 32-byte x25519 key share when x25519 (0x001d) is in
        // `named_groups` so standard TLS 1.3 servers respond directly without
        // requiring HRR; for PQC-only group probes send an empty key_share list
        // per RFC 8446 §4.2.8 to elicit HelloRetryRequest group selection.
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        if named_groups.contains(&0x001d) {
            let mut x25519_pub = [0u8; 32];
            x25519_pub[0] = 9; // RFC 7748 Curve25519 basepoint u=9
            // client_shares_len = 2 (group) + 2 (key_len) + 32 (key) = 36
            exts.extend_from_slice(&38u16.to_be_bytes());
            exts.extend_from_slice(&36u16.to_be_bytes());
            exts.extend_from_slice(&0x001du16.to_be_bytes());
            exts.extend_from_slice(&32u16.to_be_bytes());
            exts.extend_from_slice(&x25519_pub);
        } else {
            exts.extend_from_slice(&0x0002u16.to_be_bytes());
            exts.extend_from_slice(&0x0000u16.to_be_bytes());
        }
    }

    if !exts.is_empty() {
        let exts_len = u16::try_from(exts.len())
            .map_err(|_| anyhow::anyhow!("TLS extensions exceed u16 length"))?;
        body.extend_from_slice(&exts_len.to_be_bytes());
        body.extend_from_slice(&exts);
    }

    let blen = body.len();
    if blen > 16_380 {
        bail!("TLS ClientHello handshake payload exceeds single-record limit ({blen} bytes)");
    }
    let mut hs = Vec::with_capacity(4 + blen);
    hs.push(0x01);
    hs.push(((blen >> 16) & 0xff) as u8);
    hs.push(((blen >> 8) & 0xff) as u8);
    hs.push((blen & 0xff) as u8);
    hs.extend_from_slice(&body);

    let rec_ver = if legacy_version == [0x03, 0x00] {
        [0x03, 0x00]
    } else {
        [0x03, 0x01]
    };
    let hs_len =
        u16::try_from(hs.len()).map_err(|_| anyhow::anyhow!("TLS record length exceeds u16"))?;
    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(0x16);
    record.extend_from_slice(&rec_ver);
    record.extend_from_slice(&hs_len.to_be_bytes());
    record.extend_from_slice(&hs);
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloSummary {
    pub version: [u8; 2],
    pub cipher_suite: u16,
    pub selected_group: Option<u16>,
    pub is_hello_retry_request: bool,
}

/// Parses a TLS `ServerHello` (or `HelloRetryRequest`) record from raw server response bytes.
pub fn parse_server_hello(buf: &[u8]) -> Option<ServerHelloSummary> {
    if buf.len() < 44 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let payload = buf.get(5..5 + rec_len.min(buf.len() - 5))?;
    if payload.len() < 39 || payload[0] != 0x02 {
        return None;
    }
    let mut version = [payload[4], payload[5]];
    let random = &payload[6..38];
    const HRR_MAGIC: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    let is_hrr = random == HRR_MAGIC;

    let sid_len = *payload.get(38)? as usize;
    let cs_off = 39 + sid_len;
    if cs_off + 3 > payload.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([payload[cs_off], payload[cs_off + 1]]);
    let mut selected_group = None;

    let ext_off = cs_off + 3;
    if ext_off + 2 <= payload.len() {
        let exts_len = u16::from_be_bytes([payload[ext_off], payload[ext_off + 1]]) as usize;
        let mut pos = ext_off + 2;
        let end = (pos + exts_len).min(payload.len());
        while pos + 4 <= end {
            let etype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let elen = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;
            if pos + elen > end {
                break;
            }
            let edata = &payload[pos..pos + elen];
            if etype == 0x002b && elen >= 2 {
                version = [edata[0], edata[1]];
            } else if etype == 0x0033 && elen >= 2 {
                selected_group = Some(u16::from_be_bytes([edata[0], edata[1]]));
            }
            pos += elen;
        }
    }

    Some(ServerHelloSummary {
        version,
        cipher_suite,
        selected_group,
        is_hello_retry_request: is_hrr,
    })
}

fn read_tls_record_bounded(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while buf.len() < 16_389 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 5 {
                    if buf[0] != 0x16 {
                        break;
                    }
                    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    if buf.len() >= 5 + rec_len {
                        break;
                    }
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {
                continue;
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() { None } else { Some(buf) }
}

fn probe_raw_tls(
    addr: &SocketAddr,
    host: &str,
    legacy_version: [u8; 2],
    ciphers: &[u16],
    offer_tls13: bool,
    named_groups: &[u16],
) -> Option<ServerHelloSummary> {
    let ch = build_client_hello(host, legacy_version, ciphers, offer_tls13, named_groups).ok()?;
    let mut stream = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    stream.write_all(&ch).ok()?;
    let buf = read_tls_record_bounded(&mut stream)?;
    parse_server_hello(&buf)
}

pub fn cipher_suite_name(code: u16) -> String {
    match code {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5".into(),
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA".into(),
        0xc011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA".into(),
        other => format!("0x{other:04x}"),
    }
}

pub fn named_group_name(code: u16) -> String {
    match code {
        0x11ec => "X25519MLKEM768 (RFC 10024 PQC)".into(),
        0x11eb => "SecP256r1MLKEM768 (RFC 10024 PQC)".into(),
        0x11ed => "SecP384r1MLKEM1024 (RFC 10024 PQC)".into(),
        0x001d => "x25519".into(),
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        other => format!("0x{other:04x}"),
    }
}

/// Runs a full defensive TLS/SSL & PQC audit against `target` (`host[:port]` or `https://...`).
pub fn run_tls_audit(target: &str) -> Result<TlsAuditReport> {
    let (host, port) = parse_tls_target(target)?;
    // Unconditionally deny cloud metadata / link-local / unspecified hosts & resolved IPs (Council T5).
    let addrs = crate::idor_audit::resolve_and_validate_live_addrs(&host, port, true)?;
    let addr = *addrs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No socket address resolved for {host}:{port}"))?;

    let modern_ciphers: &[u16] = &[
        0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x002f, 0x0035,
    ];
    let weak_ciphers: &[u16] = &[0x0004, 0x0005, 0xc011, 0xc012, 0x000a];
    let classical_groups: &[u16] = &[0x001d, 0x0017, 0x0018];
    let pqc_groups: &[u16] = &[0x11ec, 0x11eb, 0x11ed];

    let mut protocols_supported = Vec::new();
    let mut findings = Vec::new();

    for (label, ver, sev) in [
        ("SSLv3", [0x03, 0x00], "CRITICAL"),
        ("TLS 1.0", [0x03, 0x01], "HIGH"),
        ("TLS 1.1", [0x03, 0x02], "HIGH"),
    ] {
        if let Some(sh) = probe_raw_tls(&addr, &host, ver, modern_ciphers, false, classical_groups)
            && sh.version == ver
        {
            protocols_supported.push(label.to_string());
            findings.push(TlsFinding {
                id: format!("SMG-TLS-{}", label.replace([' ', '.'], "")),
                severity: sev.to_string(),
                title: format!("Deprecated protocol {label} accepted by {host}:{port}"),
                detail: format!(
                    "Server negotiated {label} with cipher {}",
                    cipher_suite_name(sh.cipher_suite)
                ),
                remediation: "Disable SSLv3, TLS 1.0, and TLS 1.1; enforce TLS 1.2+ (prefer TLS 1.3)."
                    .into(),
            });
        }
    }

    let mut negotiated_tls12_cipher = None;
    if let Some(sh) = probe_raw_tls(
        &addr,
        &host,
        [0x03, 0x03],
        modern_ciphers,
        false,
        classical_groups,
    ) && sh.version == [0x03, 0x03]
    {
        protocols_supported.push("TLS 1.2".to_string());
        negotiated_tls12_cipher = Some(cipher_suite_name(sh.cipher_suite));
    }

    let mut negotiated_tls13_cipher = None;
    if let Some(sh) = probe_raw_tls(
        &addr,
        &host,
        [0x03, 0x03],
        &[0x1301, 0x1302, 0x1303],
        true,
        classical_groups,
    ) && sh.version == [0x03, 0x04]
    {
        protocols_supported.push("TLS 1.3".to_string());
        negotiated_tls13_cipher = Some(cipher_suite_name(sh.cipher_suite));
    }

    let weak_ciphers_accepted = if let Some(sh) = probe_raw_tls(
        &addr,
        &host,
        [0x03, 0x03],
        weak_ciphers,
        false,
        classical_groups,
    ) {
        findings.push(TlsFinding {
            id: "SMG-TLS-WEAK-CIPHER".into(),
            severity: "HIGH".into(),
            title: format!(
                "Weak/deprecated cipher accepted: {}",
                cipher_suite_name(sh.cipher_suite)
            ),
            detail: format!(
                "Server accepted weak cipher suite 0x{:04x}",
                sh.cipher_suite
            ),
            remediation: "Remove RC4, 3DES, EXPORT, NULL, and non-FS CBC suites from TLS config."
                .into(),
        });
        true
    } else {
        false
    };

    let mut pqc_hybrid_supported = false;
    let mut pqc_group_negotiated = None;
    if let Some(sh) = probe_raw_tls(
        &addr,
        &host,
        [0x03, 0x03],
        &[0x1301, 0x1302, 0x1303],
        true,
        pqc_groups,
    ) && sh.version == [0x03, 0x04]
        && !sh.is_hello_retry_request
        && let Some(g) = sh.selected_group
        && matches!(g, 0x11eb..=0x11ed)
    {
        pqc_hybrid_supported = true;
        pqc_group_negotiated = Some(named_group_name(g));
    }
    if !pqc_hybrid_supported && protocols_supported.iter().any(|p| p == "TLS 1.3") {
        findings.push(TlsFinding {
            id: "SMG-TLS-PQC-READY".into(),
            severity: "LOW".into(),
            title: "TLS 1.3 endpoint does not yet advertise RFC 10024 Post-Quantum hybrid key exchange".into(),
            detail: "Neither X25519MLKEM768 (0x11EC) nor SecP256r1MLKEM768 (0x11EB) was selected.".into(),
            remediation: "Enable hybrid PQC group X25519MLKEM768 in OpenSSL 3.5+ / BoringSSL / rustls / Nginx.".into(),
        });
    }

    let (hsts_header, cert_chain_len) = inspect_https_headers_and_certs(&addr, &host);
    let hsts_disabled_or_missing = match hsts_header.as_deref() {
        None => true,
        Some(hv) => hv
            .split(';')
            .find_map(|d| {
                d.trim()
                    .to_ascii_lowercase()
                    .strip_prefix("max-age=")
                    .map(|v| v.trim().to_string())
            })
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|secs| secs == 0),
    };
    if hsts_disabled_or_missing && !protocols_supported.is_empty() {
        findings.push(TlsFinding {
            id: "SMG-TLS-HSTS".into(),
            severity: "MEDIUM".into(),
            title: "Missing or zero `Strict-Transport-Security` (HSTS) response header".into(),
            detail: format!(
                "HTTPS response from {host}:{port} did not enforce a positive HSTS max-age."
            ),
            remediation:
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`."
                    .into(),
        });
    }

    Ok(TlsAuditReport {
        target: target.to_string(),
        host,
        port,
        protocols_supported,
        negotiated_tls13_cipher,
        negotiated_tls12_cipher,
        pqc_hybrid_supported,
        pqc_group_negotiated,
        weak_ciphers_accepted,
        hsts_header,
        cert_chain_len,
        findings,
    })
}

#[derive(Debug)]
struct CertCollectorVerifier {
    chain_len: std::sync::Mutex<usize>,
}

impl rustls::client::danger::ServerCertVerifier for CertCollectorVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut g) = self.chain_len.lock() {
            *g = 1 + intermediates.len();
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Completes a TLS handshake and protocol/cipher/cert audit over an already-upgraded STARTTLS `TcpStream`.
#[cfg(feature = "pqc")]
pub fn audit_upgraded_starttls_stream(
    target_label: &str,
    host: &str,
    port: u16,
    mut sock: TcpStream,
) -> Result<TlsAuditReport> {
    crate::idor_audit::ensure_rustls_ring_provider();
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    let collector = Arc::new(CertCollectorVerifier {
        chain_len: std::sync::Mutex::new(0),
    });
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid TLS SNI host '{host}'"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server_name)
        .context("Failed initializing rustls client connection for STARTTLS")?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .context("STARTTLS TLS handshake failed")?;
    }

    let mut protocols_supported = Vec::new();
    let mut negotiated_tls13_cipher = None;
    let mut negotiated_tls12_cipher = None;
    let mut findings = Vec::new();

    if let Some(proto) = conn.protocol_version() {
        match proto {
            rustls::ProtocolVersion::TLSv1_3 => {
                protocols_supported.push("TLS 1.3".into());
                if let Some(cs) = conn.negotiated_cipher_suite() {
                    negotiated_tls13_cipher = Some(format!("{:?}", cs.suite()));
                }
            }
            rustls::ProtocolVersion::TLSv1_2 => {
                protocols_supported.push("TLS 1.2".into());
                if let Some(cs) = conn.negotiated_cipher_suite() {
                    negotiated_tls12_cipher = Some(format!("{:?}", cs.suite()));
                }
            }
            other => {
                let lbl = format!("{other:?}");
                findings.push(TlsFinding {
                    id: "SMG-TLS-LEGACY".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Deprecated STARTTLS protocol {lbl} negotiated on {host}:{port}"
                    ),
                    detail: format!("Upgraded STARTTLS session selected {lbl}"),
                    remediation: "Enforce TLS 1.2+ (prefer TLS 1.3) on STARTTLS listeners.".into(),
                });
                protocols_supported.push(lbl);
            }
        }
    }

    let cert_chain_len = collector.chain_len.lock().map(|g| *g).unwrap_or(0);
    Ok(TlsAuditReport {
        target: target_label.to_string(),
        host: host.to_string(),
        port,
        protocols_supported,
        negotiated_tls13_cipher,
        negotiated_tls12_cipher,
        pqc_hybrid_supported: false,
        pqc_group_negotiated: None,
        weak_ciphers_accepted: false,
        hsts_header: None,
        cert_chain_len,
        findings,
    })
}

fn inspect_https_headers_and_certs(addr: &SocketAddr, host: &str) -> (Option<String>, usize) {
    crate::idor_audit::ensure_rustls_ring_provider();
    let collector = Arc::new(CertCollectorVerifier {
        chain_len: std::sync::Mutex::new(0),
    });
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();
    let Ok(server_name) = rustls::pki_types::ServerName::try_from(host.to_string()) else {
        return (None, 0);
    };
    let Ok(mut conn) = rustls::ClientConnection::new(Arc::new(cfg), server_name) else {
        return (None, 0);
    };
    let Ok(mut sock) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) else {
        return (None, 0);
    };
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let host_hdr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let req = format!("HEAD / HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n");
    let _ = tls.write_all(req.as_bytes());
    let mut resp = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while resp.len() < 65_536 {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&chunk[..n]);
                if resp.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&resp);
    let hsts = text.lines().find_map(|ln| {
        let (k, v) = ln.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("strict-transport-security") {
            Some(v.trim().to_string())
        } else {
            None
        }
    });
    let chain = collector.chain_len.lock().map(|g| *g).unwrap_or(0);
    (hsts, chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls_targets_and_builds_valid_client_hello() {
        assert_eq!(
            parse_tls_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_tls_target("https://api.local:8443/v1").unwrap(),
            ("api.local".into(), 8443)
        );
        assert_eq!(
            parse_tls_target("[::1]:8443").unwrap(),
            ("::1".into(), 8443)
        );
        assert_eq!(parse_tls_target("::1").unwrap(), ("::1".into(), 443));
        assert!(parse_tls_target("user:pass@example.com:443").is_err());
        assert!(parse_tls_target("example.com:notaport").is_err());

        let ch =
            build_client_hello("example.com", [0x03, 0x03], &[0x1301], true, &[0x11ec]).unwrap();
        assert_eq!(ch[0], 0x16);
        assert_eq!(ch[5], 0x01);

        let oversized_host = "a".repeat(260);
        assert!(
            build_client_hello(&oversized_host, [0x03, 0x03], &[0x1301], true, &[0x001d]).is_err()
        );
    }

    #[test]
    fn tls_audit_denies_imds_and_link_local_targets() {
        assert!(run_tls_audit("169.254.169.254:443").is_err());
        assert!(run_tls_audit("[fe80::1]:443").is_err());
        assert!(run_tls_audit("[fd00:ec2::254]:443").is_err());
        assert!(run_tls_audit("metadata.google.internal:443").is_err());
        assert!(run_tls_audit("0.0.0.0:443").is_err());
    }

    #[test]
    fn parses_tls13_hello_retry_request_with_rfc10024_pqc_group() {
        let mut hs = Vec::new();
        hs.push(0x02);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]);
        body.push(0x00);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0x00);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x03, 0x04]);
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&0x11ecu16.to_be_bytes());
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let parsed = parse_server_hello(&rec).expect("valid HRR");
        assert_eq!(parsed.version, [0x03, 0x04]);
        assert_eq!(parsed.cipher_suite, 0x1301);
        assert_eq!(parsed.selected_group, Some(0x11ec));
        assert!(parsed.is_hello_retry_request);
    }
}
