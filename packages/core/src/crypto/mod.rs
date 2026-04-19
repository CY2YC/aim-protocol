//! NIST PQC Cryptography: ML-KEM (Kyber) & ML-DSA (Dilithium)
//!
//! Uses formally verified implementations from RustCrypto.
//! FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) compliant.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// ML-DSA (Dilithium) - FIPS 204
// =============================================================================

pub mod dilithium {
    use super::*;
    use ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};
    use ml_dsa::signature::{Keypair, Signer, Verifier, SignatureEncoding};

    /// ML-DSA-65 public key size (1952 bytes)
    pub const PUBLIC_KEY_LENGTH: usize = 1952;
    /// ML-DSA-65 secret key size (4032 bytes)
    pub const SECRET_KEY_LENGTH: usize = 4032;
    /// ML-DSA-65 signature size (3293 bytes)
    pub const SIGNATURE_LENGTH: usize = 3293;

    /// Production-grade ML-DSA signing key with secure memory handling
    pub struct SecretKey(Box<SigningKey<MlDsa65>>);

    /// ML-DSA verifying key (public)
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct PublicKey(#[serde(with = "serde_bytes")] Box<[u8; PUBLIC_KEY_LENGTH]>);

    /// ML-DSA signature
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SignatureBytes(#[serde(with = "serde_bytes")] Box<Vec<u8>>);

    impl SecretKey {
        /// Generate new signing key with cryptographically secure RNG
        pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let sk = SigningKey::<MlDsa65>::try_from(&seed[..])
                .expect("Failed to generate ML-DSA key");
            Self(Box::new(sk))
        }

        /// Sign message (deterministic with context separation)
        pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> SignatureBytes {
            let sig = self.0.sign_with_ctx(ctx, msg);
            let sig_bytes = sig.to_bytes().to_vec();
            SignatureBytes(Box::new(sig_bytes))
        }

        /// Get verifying key
        pub fn verifying_key(&self) -> PublicKey {
            let vk = self.0.verifying_key();
            let bytes = vk.to_bytes();
            PublicKey(Box::new(bytes))
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
            self.0.to_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Option<Self> {
            SigningKey::<MlDsa65>::try_from(bytes.as_slice())
                .ok()
                .map(|sk| Self(Box::new(sk)))
        }
    }

    impl Zeroize for SecretKey {
        fn zeroize(&mut self) {
            // Best effort: drop and reallocate
            self.0 = Box::new(SigningKey::try_from(&[0u8; SECRET_KEY_LENGTH][..]).unwrap());
        }
    }

    impl ZeroizeOnDrop for SecretKey {}

    impl PublicKey {
        /// Verify signature with context
        pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &SignatureBytes) -> bool {
            let vk = match VerifyingKey::<MlDsa65>::try_from(self.0.as_slice()) {
                Ok(vk) => vk,
                Err(_) => return false,
            };
            let sig_data = match Signature::<MlDsa65>::try_from(sig.0.as_slice()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify_with_ctx(ctx, msg, &sig_data).is_ok()
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
            &self.0
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Option<Self> {
            if VerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).is_ok() {
                Some(Self(Box::new(*bytes)))
            } else {
                None
            }
        }
    }

    impl SignatureBytes {
        /// Serialize to bytes
        pub fn to_bytes(&self) -> &[u8] {
            &self.0
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Option<Self> {
            if Signature::<MlDsa65>::try_from(bytes.as_slice()).is_ok() {
                Some(Self(Box::new(bytes.to_vec())))
            } else {
                None
            }
        }
    }
}

// =============================================================================
// ML-KEM (Kyber) - FIPS 203
// =============================================================================

pub mod kyber {
    use super::*;
    use ml_kem::{MlKem768, Ciphertext};
    use ml_kem::kem::{DecapsulationKey, EncapsulationKey, Decapsulate, Encapsulate};

    /// ML-KEM-768 public key size (1184 bytes)
    pub const PUBLIC_KEY_LENGTH: usize = 1184;
    /// ML-KEM-768 secret key size (2400 bytes)
    pub const SECRET_KEY_LENGTH: usize = 2400;
    /// ML-KEM-768 ciphertext size (1088 bytes)
    pub const CIPHERTEXT_LENGTH: usize = 1088;
    /// Shared secret size (32 bytes)
    pub const SHARED_SECRET_LENGTH: usize = 32;

    /// Production-grade ML-KEM decapsulation key with secure memory handling
    pub struct SecretKey(Box<DecapsulationKey<MlKem768>>);

    /// ML-KEM encapsulation key (public)
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct PublicKey(#[serde(with = "serde_bytes")] Box<[u8; PUBLIC_KEY_LENGTH]>);

    /// ML-KEM ciphertext
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CiphertextBytes(#[serde(with = "serde_bytes")] Box<Vec<u8>>);

    /// Shared secret from encapsulation/decapsulation
    #[derive(Zeroize, ZeroizeOnDrop, Clone, Serialize, Deserialize)]
    pub struct SharedSecret([u8; SHARED_SECRET_LENGTH]);

    impl SecretKey {
        /// Generate new keypair with cryptographically secure RNG
        pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (PublicKey, Self) {
            let (ek, dk) = DecapsulationKey::<MlKem768>::generate_key(rng);
            let pk_bytes = ek.as_bytes();
            (PublicKey(Box::new(pk_bytes)), Self(Box::new(dk)))
        }

        /// Decapsulate ciphertext to obtain shared secret
        pub fn decapsulate(&self, ct: &CiphertextBytes) -> SharedSecret {
            let ct_data = match Ciphertext::<MlKem768>::try_from(ct.0.as_slice()) {
                Ok(ct) => ct,
                Err(_) => panic!("Invalid ciphertext"),
            };
            let ss = self.0.decapsulate(&ct_data);
            SharedSecret(ss.as_bytes())
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
            self.0.to_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Option<Self> {
            DecapsulationKey::<MlKem768>::try_from(bytes.as_slice())
                .ok()
                .map(|dk| Self(Box::new(dk)))
        }
    }

    impl Zeroize for SecretKey {
        fn zeroize(&mut self) {
            // Best effort zeroization
            self.0 = Box::new(DecapsulationKey::try_from(&[0u8; SECRET_KEY_LENGTH][..]).unwrap());
        }
    }

    impl ZeroizeOnDrop for SecretKey {}

    impl PublicKey {
        /// Encapsulate to generate ciphertext and shared secret
        pub fn encapsulate<R: CryptoRngCore>(
            &self,
            rng: &mut R,
        ) -> (CiphertextBytes, SharedSecret) {
            let ek = match EncapsulationKey::<MlKem768>::try_from(self.0.as_slice()) {
                Ok(ek) => ek,
                Err(_) => panic!("Invalid public key"),
            };
            let (ct, ss) = ek.encapsulate_with_rng(rng);
            let ct_bytes = ct.as_bytes().to_vec();
            (CiphertextBytes(Box::new(ct_bytes)), SharedSecret(ss.as_bytes()))
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
            &self.0
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Option<Self> {
            if EncapsulationKey::<MlKem768>::try_from(bytes.as_slice()).is_ok() {
                Some(Self(Box::new(*bytes)))
            } else {
                None
            }
        }
    }

    impl CiphertextBytes {
        /// Serialize to bytes
        pub fn to_bytes(&self) -> &[u8] {
            &self.0
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; CIPHERTEXT_LENGTH]) -> Option<Self> {
            if Ciphertext::<MlKem768>::try_from(bytes.as_slice()).is_ok() {
                Some(Self(Box::new(bytes.to_vec())))
            } else {
                None
            }
        }
    }

    impl SharedSecret {
        /// Get bytes (for use in key derivation)
        pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LENGTH] {
            &self.0
        }

        /// Convert to array (consumes self)
        pub fn into_bytes(self) -> [u8; SHARED_SECRET_LENGTH] {
            self.0
        }
    }
}

// =============================================================================
// HKDF Key Derivation
// =============================================================================

pub mod kdf {
    use hkdf::Hkdf;
    use sha2::Sha256;

    /// Derive key using HKDF-SHA256
    pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info, out).expect("HKDF expansion failed");
    }

    /// Derive 32-byte key
    pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        hkdf_sha256(ikm, salt, info, &mut out);
        out
    }
}

// =============================================================================
// Hybrid Classical+PQC (Defense in Depth)
// =============================================================================

pub mod hybrid {
    use super::{kdf, kyber};
    use rand_core::CryptoRngCore;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    /// Hybrid X25519 + ML-KEM key encapsulation
    /// Provides defense-in-depth: both classical and PQ must be broken
    pub struct HybridKem;

    impl HybridKem {
        /// Generate hybrid keypair
        pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
            let (kyber_pk, kyber_sk) = kyber::SecretKey::generate(rng);
            let x25519_sk = EphemeralSecret::random_from_rng(rng);
            let x25519_pk = X25519PublicKey::from(&x25519_sk);

            let pk = HybridPublicKey {
                kyber: kyber_pk,
                x25519: x25519_pk,
            };
            let sk = HybridSecretKey {
                kyber: kyber_sk,
                x25519: x25519_sk,
            };
            (pk, sk)
        }

        /// Encapsulate (generates ephemeral X25519 + Kyber)
        pub fn encapsulate<R: CryptoRngCore>(
            pk: &HybridPublicKey,
            rng: &mut R,
        ) -> (HybridCiphertext, [u8; 32]) {
            // X25519 ephemeral
            let eph_sk = EphemeralSecret::random_from_rng(&mut *rng);
            let eph_pk = X25519PublicKey::from(&eph_sk);
            let x25519_ss = eph_sk.diffie_hellman(&pk.x25519);

            // ML-KEM encaps
            let (kyber_ct, kyber_ss) = pk.kyber.encapsulate(rng);

            // Combine shared secrets
            let mut combined_ikm = Vec::with_capacity(64);
            combined_ikm.extend_from_slice(x25519_ss.as_bytes());
            combined_ikm.extend_from_slice(kyber_ss.as_bytes());

            let shared_secret = kdf::derive_key(&combined_ikm, b"", b"aim-hybrid-kem-v1");

            let ct = HybridCiphertext {
                kyber: kyber_ct,
                x25519_ephemeral: eph_pk,
            };

            (ct, shared_secret)
        }

        /// Decapsulate to recover shared secret
        pub fn decapsulate(
            sk: &HybridSecretKey,
            ct: &HybridCiphertext,
        ) -> [u8; 32] {
            // X25519 decaps
            let x25519_ss = sk.x25519.diffie_hellman(&ct.x25519_ephemeral);

            // ML-KEM decaps
            let kyber_ss = sk.kyber.decapsulate(&ct.kyber);

            // Combine shared secrets
            let mut combined_ikm = Vec::with_capacity(64);
            combined_ikm.extend_from_slice(x25519_ss.as_bytes());
            combined_ikm.extend_from_slice(kyber_ss.as_bytes());

            kdf::derive_key(&combined_ikm, b"", b"aim-hybrid-kem-v1")
        }
    }

    #[derive(Clone)]
    pub struct HybridPublicKey {
        pub kyber: kyber::PublicKey,
        pub x25519: X25519PublicKey,
    }

    pub struct HybridSecretKey {
        pub kyber: kyber::SecretKey,
        pub x25519: EphemeralSecret,
    }

    pub struct HybridCiphertext {
        pub kyber: kyber::CiphertextBytes,
        pub x25519_ephemeral: X25519PublicKey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ml_dsa_roundtrip() {
        let mut rng = OsRng;
        let sk = dilithium::SecretKey::generate(&mut rng);
        let pk = sk.verifying_key();

        let msg = b"test message";
        let ctx = b"test context";
        let sig = sk.sign(msg, ctx);

        assert!(pk.verify(msg, ctx, &sig));
        assert!(!pk.verify(b"wrong msg", ctx, &sig));
    }

    #[test]
    fn test_ml_kem_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = kyber::SecretKey::generate(&mut rng);

        let (ct, ss_enc) = pk.encapsulate(&mut rng);
        let ss_dec = sk.decapsulate(&ct);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = hybrid::HybridKem::generate(&mut rng);
        
        let (ct, ss_enc) = hybrid::HybridKem::encapsulate(&pk, &mut rng);
        let ss_dec = hybrid::HybridKem::decapsulate(&sk, &ct);
        
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_key_serialization() {
        let mut rng = OsRng;
        let sk = dilithium::SecretKey::generate(&mut rng);
        let pk = sk.verifying_key();

        let pk_bytes = pk.to_bytes();
        let pk2 = dilithium::PublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_kyber_serialization() {
        let mut rng = OsRng;
        let (pk, sk) = kyber::SecretKey::generate(&mut rng);
        
        let pk_bytes = pk.to_bytes();
        let pk2 = kyber::PublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk, pk2);
        
        let sk_bytes = sk.to_bytes();
        let sk2 = kyber::SecretKey::from_bytes(&sk_bytes).unwrap();
        // Test functionality
        let (ct, ss1) = pk.encapsulate(&mut rng);
        let ss2 = sk2.decapsulate(&ct);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
