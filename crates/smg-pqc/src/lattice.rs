use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoFamily {
    AsymmetricKex,
    AsymmetricSig,
    SymmetricCipher,
    HashFunction,
    PostQuantumKem,
    PostQuantumSig,
    HybridKex,
}

impl CryptoFamily {
    pub const fn cyclonedx_primitive(self) -> &'static str {
        match self {
            Self::AsymmetricKex | Self::HybridKex => "key-agree",
            Self::AsymmetricSig | Self::PostQuantumSig => "signature",
            Self::SymmetricCipher => "ae",
            Self::HashFunction => "hash",
            Self::PostQuantumKem => "kem",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PqSecurityStrength {
    pub algorithm: &'static str,
    pub oid: &'static str,
    pub family: CryptoFamily,
    pub classical_bits: u16,
    /// Effective post-quantum security bits under Shor (`0`), Grover (`b/2`), BHT (`h/3`), or NIST category.
    pub quantum_bits: u16,
    /// NIST Post-Quantum security category (`0` = broken/sub-128, `1` = AES-128 eq, `3` = AES-192 eq, `5` = AES-256 eq).
    pub nist_category: u8,
}

/// Evaluates effective post-quantum security bits B_PQ(a) across Shor, Grover, BHT, and NIST PQC standards.
pub fn evaluate_pq_strength(algo_token: &str) -> Option<PqSecurityStrength> {
    let low = algo_token.to_ascii_lowercase();

    // Post-Quantum / Hybrid standards
    if low.contains("x25519mlkem768") || low.contains("x25519kyber768") {
        return Some(PqSecurityStrength {
            algorithm: "X25519MLKEM768",
            oid: "1.3.6.1.4.1.2.267.12.4.4",
            family: CryptoFamily::HybridKex,
            classical_bits: 192,
            quantum_bits: 192,
            nist_category: 3,
        });
    }
    if low.contains("ml-kem-1024")
        || low.contains("mlkem1024")
        || low.contains("kyber-1024")
        || low.contains("kyber1024")
    {
        return Some(PqSecurityStrength {
            algorithm: "ML-KEM-1024",
            oid: "2.16.840.1.101.3.4.4.3",
            family: CryptoFamily::PostQuantumKem,
            classical_bits: 256,
            quantum_bits: 256,
            nist_category: 5,
        });
    }
    if low.contains("ml-kem-768")
        || low.contains("mlkem768")
        || low.contains("kyber-768")
        || low.contains("kyber768")
    {
        return Some(PqSecurityStrength {
            algorithm: "ML-KEM-768",
            oid: "2.16.840.1.101.3.4.4.2",
            family: CryptoFamily::PostQuantumKem,
            classical_bits: 192,
            quantum_bits: 192,
            nist_category: 3,
        });
    }
    if low.contains("ml-kem-512")
        || low.contains("mlkem512")
        || low.contains("kyber-512")
        || low.contains("kyber512")
    {
        return Some(PqSecurityStrength {
            algorithm: "ML-KEM-512",
            oid: "2.16.840.1.101.3.4.4.1",
            family: CryptoFamily::PostQuantumKem,
            classical_bits: 128,
            quantum_bits: 128,
            nist_category: 1,
        });
    }
    if low.contains("ml-dsa-87") || low.contains("mldsa87") || low.contains("dilithium5") {
        return Some(PqSecurityStrength {
            algorithm: "ML-DSA-87",
            oid: "2.16.840.1.101.3.4.3.19",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 256,
            quantum_bits: 256,
            nist_category: 5,
        });
    }
    if low.contains("ml-dsa-65") || low.contains("mldsa65") || low.contains("dilithium3") {
        return Some(PqSecurityStrength {
            algorithm: "ML-DSA-65",
            oid: "2.16.840.1.101.3.4.3.18",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 192,
            quantum_bits: 192,
            nist_category: 3,
        });
    }
    if low.contains("ml-dsa-44") || low.contains("mldsa44") || low.contains("dilithium2") {
        return Some(PqSecurityStrength {
            algorithm: "ML-DSA-44",
            oid: "2.16.840.1.101.3.4.3.17",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 128,
            quantum_bits: 128,
            nist_category: 1,
        });
    }
    if low.contains("slh-dsa-256")
        || low.contains("slh_dsa_256")
        || low.contains("sphincs+-256")
        || low.contains("sphincs256")
    {
        return Some(PqSecurityStrength {
            algorithm: "SLH-DSA-256",
            oid: "2.16.840.1.101.3.4.3.24",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 256,
            quantum_bits: 256,
            nist_category: 5,
        });
    }
    if low.contains("slh-dsa-128")
        || low.contains("slh_dsa_128")
        || low.contains("sphincs+-128")
        || low.contains("sphincs128")
    {
        return Some(PqSecurityStrength {
            algorithm: "SLH-DSA-128",
            oid: "2.16.840.1.101.3.4.3.20",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 128,
            quantum_bits: 128,
            nist_category: 1,
        });
    }
    if low.contains("slh-dsa") || low.contains("sphincs") {
        return Some(PqSecurityStrength {
            algorithm: "SLH-DSA-192",
            oid: "2.16.840.1.101.3.4.3.22",
            family: CryptoFamily::PostQuantumSig,
            classical_bits: 192,
            quantum_bits: 192,
            nist_category: 3,
        });
    }

    // Classical Asymmetric Key Exchange & Signatures -> Shor breaks in polynomial time => B_PQ = 0
    if low.contains("ecdhe") || low.contains("ecdh") {
        return Some(PqSecurityStrength {
            algorithm: "ECDH",
            oid: "1.2.840.10045.2.1",
            family: CryptoFamily::AsymmetricKex,
            classical_bits: 128,
            quantum_bits: 0,
            nist_category: 0,
        });
    }
    if low.contains("x25519") {
        return Some(PqSecurityStrength {
            algorithm: "X25519",
            oid: "1.3.101.110",
            family: CryptoFamily::AsymmetricKex,
            classical_bits: 128,
            quantum_bits: 0,
            nist_category: 0,
        });
    }
    if low.contains("ed25519") {
        return Some(PqSecurityStrength {
            algorithm: "Ed25519",
            oid: "1.3.101.112",
            family: CryptoFamily::AsymmetricSig,
            classical_bits: 128,
            quantum_bits: 0,
            nist_category: 0,
        });
    }
    if low.contains("ecdsa")
        || low.contains("secp256k1")
        || low.contains("prime256v1")
        || low.contains("secp256r1")
    {
        return Some(PqSecurityStrength {
            algorithm: "ECDSA",
            oid: "1.2.840.10045.4.3.2",
            family: CryptoFamily::AsymmetricSig,
            classical_bits: 128,
            quantum_bits: 0,
            nist_category: 0,
        });
    }
    if low.contains("rs256")
        || low.contains("rs384")
        || low.contains("rs512")
        || low.contains("rsa-pss")
        || low.contains("rsa_pss")
        || low.contains("rsa_sign")
    {
        return Some(PqSecurityStrength {
            algorithm: "RS256",
            oid: "1.2.840.113549.1.1.11",
            family: CryptoFamily::AsymmetricSig,
            classical_bits: 112,
            quantum_bits: 0,
            nist_category: 0,
        });
    }
    if low.contains("rsa") || low.contains("rsa-oaep") {
        return Some(PqSecurityStrength {
            algorithm: "RSA",
            oid: "1.2.840.113549.1.1.1",
            family: CryptoFamily::AsymmetricKex,
            classical_bits: 112,
            quantum_bits: 0,
            nist_category: 0,
        });
    }

    // Symmetric Ciphers -> Grover halving floor(b / 2)
    if low.contains("aes-256") || low.contains("aes256") || low.contains("aes_256") {
        return Some(PqSecurityStrength {
            algorithm: "AES-256",
            oid: "2.16.840.1.101.3.4.1.46",
            family: CryptoFamily::SymmetricCipher,
            classical_bits: 256,
            quantum_bits: 128,
            nist_category: 5,
        });
    }
    if low.contains("chacha20") {
        return Some(PqSecurityStrength {
            algorithm: "ChaCha20-Poly1305",
            oid: "1.2.840.113549.1.9.16.3.18",
            family: CryptoFamily::SymmetricCipher,
            classical_bits: 256,
            quantum_bits: 128,
            nist_category: 5,
        });
    }
    if low.contains("aes-128") || low.contains("aes128") || low.contains("aes_128") {
        return Some(PqSecurityStrength {
            algorithm: "AES-128",
            oid: "2.16.840.1.101.3.4.1.6",
            family: CryptoFamily::SymmetricCipher,
            classical_bits: 128,
            quantum_bits: 64,
            nist_category: 0,
        });
    }

    // Hash Functions -> BHT collision floor(h / 3)
    if low.contains("sha-384") || low.contains("sha384") || low.contains("sha_384") {
        return Some(PqSecurityStrength {
            algorithm: "SHA-384",
            oid: "2.16.840.1.101.3.4.2.2",
            family: CryptoFamily::HashFunction,
            classical_bits: 192,
            quantum_bits: 128,
            nist_category: 3,
        });
    }
    if low.contains("sha-512") || low.contains("sha512") || low.contains("sha_512") {
        return Some(PqSecurityStrength {
            algorithm: "SHA-512",
            oid: "2.16.840.1.101.3.4.2.3",
            family: CryptoFamily::HashFunction,
            classical_bits: 256,
            quantum_bits: 170,
            nist_category: 5,
        });
    }
    if low.contains("sha-256") || low.contains("sha256") || low.contains("sha_256") {
        return Some(PqSecurityStrength {
            algorithm: "SHA-256",
            oid: "2.16.840.1.101.3.4.2.1",
            family: CryptoFamily::HashFunction,
            classical_bits: 128,
            quantum_bits: 85,
            nist_category: 1,
        });
    }

    None
}

/// Evaluates Mosca's Harvest-Now-Decrypt-Later urgency equation:
/// T_HNDL(u) = (X_u + Y_u) - Z, where Z = 8y CRQC threat horizon, Y_u = 2y migration lead time.
/// Note: Ephemeral key exchange (`ECDHE` / `X25519` with `CryptoFamily::AsymmetricKex`) IS vulnerable to
/// passive HNDL transcript recording and NEVER receives `X_u = 0`. Only non-KEX integrity/authentication
/// contexts (`csrf`, `hmac`, `session`, `nonce`, `otp`) or hash functions receive `X_u = 0`.
pub fn mosca_hndl_urgency_years(context_line: &str, family: CryptoFamily) -> (i16, i16) {
    let low = context_line.to_ascii_lowercase();
    let z_crqc: i16 = 8;
    let y_migration: i16 = 2;

    if family == CryptoFamily::HashFunction {
        let x = 0;
        return (x, (x + y_migration) - z_crqc);
    }

    // Short-lived non-KEX authentication/integrity tokens (`csrf`, `hmac`, `session`, `nonce`, `otp`) -> X_u = 0
    if family != CryptoFamily::AsymmetricKex
        && (low.contains("csrf")
            || low.contains("hmac")
            || low.contains("otp")
            || low.contains("session")
            || low.contains("nonce")
            || low.contains("ephemeral"))
    {
        let x = 0;
        return (x, (x + y_migration) - z_crqc);
    }

    // Long-lived confidentiality transport/storage (`AsymmetricKex`, or explicit encryption/archive/KMS)
    let long_lived_confidential = matches!(family, CryptoFamily::AsymmetricKex)
        || (family != CryptoFamily::AsymmetricSig
            && (low.contains("tls")
                || low.contains("ssl")
                || low.contains("kms")
                || low.contains("encrypt")
                || low.contains("decrypt")
                || low.contains("oaep")
                || low.contains("archive")
                || low.contains("vault")
                || low.contains("ssh")
                || low.contains("vpn")
                || low.contains("pem")
                || low.contains("wrap")));

    let x_shelf_life = if long_lived_confidential { 10 } else { 4 };
    (x_shelf_life, (x_shelf_life + y_migration) - z_crqc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_lattice_computes_shor_grover_bht_slh_dsa_and_mosca_hndl() {
        let rsa = evaluate_pq_strength("RSA-2048").unwrap();
        assert_eq!(rsa.quantum_bits, 0);
        assert_eq!(rsa.nist_category, 0);
        assert_eq!(rsa.family, CryptoFamily::AsymmetricKex);

        let rs256 = evaluate_pq_strength("RS256").unwrap();
        assert_eq!(rs256.family, CryptoFamily::AsymmetricSig);
        assert_eq!(rs256.quantum_bits, 0);

        let slh128 = evaluate_pq_strength("SLH-DSA-128s").unwrap();
        assert_eq!(slh128.quantum_bits, 128);
        assert_eq!(slh128.nist_category, 1);

        let slh256 = evaluate_pq_strength("SLH-DSA-256f").unwrap();
        assert_eq!(slh256.quantum_bits, 256);
        assert_eq!(slh256.nist_category, 5);

        let aes128 = evaluate_pq_strength("AES-128-GCM").unwrap();
        assert_eq!(aes128.quantum_bits, 64);

        let aes256 = evaluate_pq_strength("AES-256-GCM").unwrap();
        assert_eq!(aes256.quantum_bits, 128);
        assert_eq!(aes256.nist_category, 5);

        let sha256 = evaluate_pq_strength("SHA-256").unwrap();
        assert_eq!(sha256.quantum_bits, 85);

        let mlkem768 = evaluate_pq_strength("ML-KEM-768").unwrap();
        assert_eq!(mlkem768.quantum_bits, 192);
        assert_eq!(mlkem768.nist_category, 3);

        // Mosca urgency: TLS KEX X_u = 10 -> T_HNDL = (10 + 2) - 8 = +4
        let (x_tls, t_tls) =
            mosca_hndl_urgency_years("tls_config rsa_kex", CryptoFamily::AsymmetricKex);
        assert_eq!(x_tls, 10);
        assert_eq!(t_tls, 4);

        // Counterexample PQC-02: Ephemeral ECDHE KEX is still HNDL-vulnerable (X_u = 10, T_HNDL = +4)
        let (x_ecdhe, t_ecdhe) =
            mosca_hndl_urgency_years("ecdhe_ephemeral_handshake", CryptoFamily::AsymmetricKex);
        assert_eq!(x_ecdhe, 10);
        assert_eq!(t_ecdhe, 4);

        // Ephemeral HMAC/Session signature X_u = 0 -> negative urgency (-6)
        let (x_hmac, t_hmac) =
            mosca_hndl_urgency_years("hmac_sha256_csrf", CryptoFamily::AsymmetricSig);
        assert_eq!(x_hmac, 0);
        assert!(t_hmac < 0);
    }
}
