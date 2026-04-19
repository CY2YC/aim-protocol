//! NIST PQC Cryptography: ML-KEM (Kyber) & ML-DSA (Dilithium)
//!
//! Uses formally verified implementations from RustCrypto.
//! FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) compliant.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// ML-DSA (Dilithium) - FIPS 204
// =============================================================================

pub mod dilithium {
    use super::*;
    use ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};

    /// ML-DSA-65 public key size (1952 bytes)
    pub const PUBLIC_KEY_LENGTH: usize = 1952;
    /// ML-DSA-65 secret key size (4032 bytes)
    pub const SECRET_KEY_LENGTH: usize = 4032;
    /// ML-DSA-65 signature size (3293 bytes)
    pub const SIGNATURE_LENGTH: usize = 3293;

    /// Production-grade ML-DSA signing key with secure memory handling
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SecretKey(Box<SigningKey<MlDsa65>>);

    /// ML-DSA verifying key (public)
    #[derive(Clone, Debug, PartialEq)]
    pub struct PublicKey(VerifyingKey<MlDsa65>);

    /// ML-DSA signature
    #[derive(Clone, Debug)]
    pub struct SignatureBytes(Box<Signature<MlDsa65>>);

    impl SecretKey {
        /// Generate new signing key with cryptographically secure RNG
        pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
            let sk = SigningKey::<MlDsa65>::generate(rng);
            Self(Box::new(sk))
        }

        /// Sign message (deterministic with context separation)
        pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> SignatureBytes {
            let sig = self.0.sign_with_context(msg, ctx);
            SignatureBytes(Box::new(sig))
        }

        /// Get verifying key
        pub fn verifying_key(&self) -> PublicKey {
            PublicKey(self.0.verifying_key())
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
            self.0.to_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Option<Self> {
            SigningKey::<MlDsa65>::try_from(bytes)
                .ok()
                .map(|sk| Self(Box::new(sk)))
        }
    }

    impl PublicKey {
        /// Verify signature with context
        pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &SignatureBytes) -> bool {
            self.0.verify_with_context(msg, ctx, &sig.0).is_ok()
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
            self.0.to_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Option<Self> {
            VerifyingKey::<MlDsa65>::try_from(bytes).ok().map(Self)
        }
    }

    impl SignatureBytes {
        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
            self.0.to_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Option<Self> {
            Signature::<MlDsa65>::try_from(bytes)
                .ok()
                .map(|s| Self(Box::new(s)))
        }
    }
}

// =============================================================================
// ML-KEM (Kyber) - FIPS 203
// =============================================================================

pub mod kyber {
    use super::*;
    use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};

    /// ML-KEM-768 public key size (1184 bytes)
    pub const PUBLIC_KEY_LENGTH: usize = 1184;
    /// ML-KEM-768 secret key size (2400 bytes)
    pub const SECRET_KEY_LENGTH: usize = 2400;
    /// ML-KEM-768 ciphertext size (1088 bytes)
    pub const CIPHERTEXT_LENGTH: usize = 1088;
    /// Shared secret size (32 bytes)
    pub const SHARED_SECRET_LENGTH: usize = 32;

    /// Production-grade ML-KEM decapsulation key with secure memory handling
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SecretKey(Box<DecapsulationKey<MlKem768>>);

    /// ML-KEM encapsulation key (public)
    #[derive(Clone, Debug, PartialEq)]
    pub struct PublicKey(EncapsulationKey<MlKem768>);

    /// ML-KEM ciphertext
    #[derive(Clone, Debug)]
    pub struct CiphertextBytes(Box<Ciphertext<MlKem768>>);

    /// Shared secret from encapsulation/decapsulation
    #[derive(Zeroize, ZeroizeOnDrop, Clone)]
    pub struct SharedSecret([u8; SHARED_SECRET_LENGTH]);

    impl SecretKey {
        /// Generate new keypair with cryptographically secure RNG
        pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (PublicKey, Self) {
            let (ek, dk) = DecapsulationKey::<MlKem768>::generate(rng);
            (PublicKey(ek), Self(Box::new(dk)))
        }

        /// Decapsulate ciphertext to obtain shared secret
        pub fn decapsulate(&self, ct: &CiphertextBytes) -> SharedSecret {
            let ss = self.0.decapsulate(&ct.0);
            SharedSecret(ss.into())
        }

        /// Get encapsulation key
        pub fn encapsulation_key(&self) -> PublicKey {
            PublicKey(self.0.encapsulation_key())
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
            self.0.as_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Option<Self> {
            DecapsulationKey::<MlKem768>::try_from(bytes)
                .ok()
                .map(|dk| Self(Box::new(dk)))
        }
    }

    impl PublicKey {
        /// Encapsulate to generate ciphertext and shared secret
        pub fn encapsulate<R: CryptoRngCore>(
            &self,
            rng: &mut R,
        ) -> (CiphertextBytes, SharedSecret) {
            let (ct, ss) = self.0.encapsulate(rng);
            (CiphertextBytes(Box::new(ct)), SharedSecret(ss.into()))
        }

        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
            self.0.as_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Option<Self> {
            EncapsulationKey::<MlKem768>::try_from(bytes).ok().map(Self)
        }
    }

    impl CiphertextBytes {
        /// Serialize to bytes
        pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LENGTH] {
            self.0.as_bytes()
        }

        /// Deserialize from bytes
        pub fn from_bytes(bytes: &[u8; CIPHERTEXT_LENGTH]) -> Option<Self> {
            Ciphertext::<MlKem768>::try_from(bytes)
                .ok()
                .map(|ct| Self(Box::new(ct)))
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
            let eph_sk = EphemeralSecret::random_from_rng(rng);
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
    }

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
    fn test_key_serialization() {
        let mut rng = OsRng;
        let sk = dilithium::SecretKey::generate(&mut rng);
        let pk = sk.verifying_key();

        let pk_bytes = pk.to_bytes();
        let pk2 = dilithium::PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk2);
    }
}
