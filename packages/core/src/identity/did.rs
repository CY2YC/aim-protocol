//! Decentralized Identity (DID) with Shamir Secret Sharing recovery
//!
//! Implements did:aim method with post-quantum cryptographic binding.

use crate::crypto::{dilithium, kyber};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AIM Protocol DID Document
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DigitalID {
    /// DID identifier (did:aim:<fingerprint>)
    pub did: String,
    /// ML-DSA public key for authentication
    pub dilithium_pk: dilithium::PublicKey,
    /// ML-KEM public key for key encapsulation
    pub kyber_pk: kyber::PublicKey,
    /// Reputation Merkle root
    pub reputation_root: [u8; 32],
    /// Current epoch for key rotation
    pub epoch: u64,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Optional TEE attestation quote
    pub tee_quote: Option<Vec<u8>>,
}

/// Secret components of a DigitalID (must be protected)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DigitalIDSecret {
    /// ML-DSA signing key
    pub dilithium_sk: dilithium::SecretKey,
    /// ML-KEM decapsulation key
    pub kyber_sk: kyber::SecretKey,
    /// Recovery seed (32 bytes)
    #[zeroize(skip)]
    pub recovery_seed: [u8; 32],
}

/// Recovery share for Shamir Secret Sharing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryShare {
    pub index: u8,
    pub value: Vec<u8>,
}

impl DigitalID {
    /// Generate new DigitalID with fresh PQC keypair
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self, DigitalIDSecret) {
        let (kyber_pk, kyber_sk) = kyber::SecretKey::generate(rng);
        let dilithium_sk = dilithium::SecretKey::generate(rng);
        let dilithium_pk = dilithium_sk.verifying_key();

        // Generate recovery seed
        let mut recovery_seed = [0u8; 32];
        rng.fill_bytes(&mut recovery_seed);

        // Compute DID fingerprint
        let did = Self::compute_did(&dilithium_pk, &kyber_pk);

        let id = Self {
            did,
            dilithium_pk,
            kyber_pk,
            reputation_root: [0u8; 32],
            epoch: 1,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tee_quote: None,
        };

        let secret = DigitalIDSecret { dilithium_sk, kyber_sk, recovery_seed };

        (id, secret)
    }

    /// Compute did:aim identifier from public keys
    fn compute_did(dilithium_pk: &dilithium::PublicKey, kyber_pk: &kyber::PublicKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"did:aim:v1:");
        hasher.update(dilithium_pk.to_bytes());
        hasher.update(kyber_pk.to_bytes());
        let fingerprint = hex::encode(hasher.finalize());
        format!("did:aim:{}", &fingerprint[..32])
    }

    /// Verify DID matches public keys (anti-tampering)
    pub fn verify_did_binding(&self) -> bool {
        let computed = Self::compute_did(&self.dilithium_pk, &self.kyber_pk);
        self.did == computed
    }

    /// Sign a message using ML-DSA with context
    pub fn sign(
        &self,
        secret: &DigitalIDSecret,
        msg: &[u8],
        ctx: &[u8],
    ) -> dilithium::SignatureBytes {
        secret.dilithium_sk.sign(msg, ctx)
    }

    /// Verify signature
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &dilithium::SignatureBytes) -> bool {
        self.dilithium_pk.verify(msg, ctx, sig)
    }

    /// Generate 3-of-5 Shamir secret sharing recovery shares
    /// CRITICAL: Uses production-grade shamir-vault crate [^32^]
    pub fn generate_recovery_shares(&self, secret: &DigitalIDSecret) -> Vec<RecoveryShare> {
        use shamir_vault::{split_secret, ShamirShare};

        // Combine secrets for recovery
        let mut master_secret = Vec::new();
        master_secret.extend_from_slice(&secret.dilithium_sk.to_bytes());
        master_secret.extend_from_slice(&secret.kyber_sk.to_bytes());
        master_secret.extend_from_slice(&secret.recovery_seed);

        // Split into 5 shares, need 3 to reconstruct
        let shares = split_secret(&master_secret, 3, 5)
            .expect("Failed to generate recovery shares");

        shares
            .into_iter()
            .map(|s| RecoveryShare { index: s.index as u8, value: s.value })
            .collect()
    }

    /// Recover secrets from shares (need at least threshold)
    pub fn recover_from_shares(shares: &[RecoveryShare]) -> Option<Vec<u8>> {
        use shamir_vault::{recover_secret, ShamirShare};

        if shares.len() < 3 {
            return None;
        }

        let shamir_shares: Vec<ShamirShare> = shares
            .iter()
            .map(|s| ShamirShare { index: s.index as usize, value: s.value.clone() })
            .collect();

        recover_secret(&shamir_shares).ok()
    }

    /// Rotate to new epoch (post-compromise security)
    pub fn rotate_epoch<R: CryptoRngCore>(&mut self, secret: &mut DigitalIDSecret, rng: &mut R) {
        // Generate new keys
        let (new_kyber_pk, new_kyber_sk) = kyber::SecretKey::generate(rng);
        let new_dilithium_sk = dilithium::SecretKey::generate(rng);
        let new_dilithium_pk = new_dilithium_sk.verifying_key();

        // Update ID
        self.kyber_pk = new_kyber_pk;
        self.dilithium_pk = new_dilithium_pk;
        self.epoch += 1;
        self.did = Self::compute_did(&self.dilithium_pk, &self.kyber_pk);

        // Update secret
        secret.dilithium_sk = new_dilithium_sk;
        secret.kyber_sk = new_kyber_sk;
    }

    /// Serialize to bytes (postcard format)
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Serialization failed")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_did_generation() {
        let mut rng = OsRng;
        let (id, _secret) = DigitalID::generate(&mut rng);

        assert!(id.did.starts_with("did:aim:"));
        assert_eq!(id.did.len(), 40); // "did:aim:" + 32 hex chars
        assert!(id.verify_did_binding());
    }

    #[test]
    fn test_sign_verify() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        let msg = b"important message";
        let ctx = b"aim-v1-auth";
        let sig = id.sign(&secret, msg, ctx);

        assert!(id.verify(msg, ctx, &sig));
        assert!(!id.verify(b"tampered", ctx, &sig));
    }

    #[test]
    fn test_recovery_shares() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        let shares = id.generate_recovery_shares(&secret);
        assert_eq!(shares.len(), 5);

        // Recover with 3 shares
        let recovered = DigitalID::recover_from_shares(&shares[..3]);
        assert!(recovered.is_some());

        // Fail with 2 shares
        let failed = DigitalID::recover_from_shares(&shares[..2]);
        assert!(failed.is_none());
    }

    #[test]
    fn test_epoch_rotation() {
        let mut rng = OsRng;
        let (mut id, mut secret) = DigitalID::generate(&mut rng);
        let old_did = id.did.clone();

        id.rotate_epoch(&mut secret, &mut rng);

        assert_ne!(id.did, old_did);
        assert_eq!(id.epoch, 2);
        assert!(id.verify_did_binding());
    }

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;
        let (id, _secret) = DigitalID::generate(&mut rng);

        let bytes = id.to_bytes();
        let recovered = DigitalID::from_bytes(&bytes).unwrap();

        assert_eq!(id, recovered);
    }
}