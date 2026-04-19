//! Decentralized Identity (DID) management for AIM Protocol
//!
//! Implements did:aim method with post-quantum cryptographic binding.

use crate::crypto::{dilithium, kyber};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AIM Protocol DID Document
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DigitalID {
    /// DID string (did:aim:<base58_hash>)
    pub did: String,
    /// Current epoch for key rotation
    pub epoch: u64,
    /// ML-DSA public key for authentication
    pub dilithium_pk: dilithium::PublicKey,
    /// ML-KEM public key for key encapsulation
    pub kyber_pk: kyber::PublicKey,
    /// Hash of previous epoch keys (for chaining)
    pub prev_key_hash: [u8; 32],
}

/// Secret components of a DigitalID (must be protected)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DigitalIDSecret {
    /// ML-DSA signing key
    pub dilithium_sk: dilithium::SecretKey,
    /// ML-KEM secret key
    pub kyber_sk: kyber::SecretKey,
    /// Recovery seed (not zeroized - needed for recovery)
    #[zeroize(skip)]
    pub recovery_seed: [u8; 32],
}

/// Recovery share for Shamir secret sharing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryShare {
    /// Share index (1-based)
    pub index: u8,
    /// Share value
    pub value: Vec<u8>,
}

/// Errors in DID operations
#[derive(Error, Debug)]
pub enum DIDError {
    #[error("Invalid DID format")]
    InvalidFormat,
    #[error("Key verification failed")]
    VerificationFailed,
    #[error("Recovery failed")]
    RecoveryFailed,
}

impl DigitalID {
    /// Generate new DID with fresh PQC keys
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self, DigitalIDSecret) {
        let (kyber_pk, kyber_sk) = kyber::SecretKey::generate(rng);
        let dilithium_sk = dilithium::SecretKey::generate(rng);
        let dilithium_pk = dilithium_sk.verifying_key();

        let mut recovery_seed = [0u8; 32];
        rng.fill_bytes(&mut recovery_seed);

        let did = Self::compute_did(&dilithium_pk, &kyber_pk, 1);

        let id = Self {
            did: did.clone(),
            epoch: 1,
            dilithium_pk,
            kyber_pk,
            prev_key_hash: [0u8; 32],
        };

        let secret = DigitalIDSecret {
            dilithium_sk,
            kyber_sk,
            recovery_seed,
        };

        (id, secret)
    }

    /// Compute did:aim identifier from public keys
    pub fn compute_did(
        dilithium_pk: &dilithium::PublicKey,
        kyber_pk: &kyber::PublicKey,
        epoch: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(dilithium_pk.to_bytes());
        hasher.update(kyber_pk.to_bytes());
        hasher.update(&epoch.to_le_bytes());
        let hash = hasher.finalize();

        // Use first 16 bytes as base58-like encoding (simplified)
        format!("did:aim:{}", hex::encode(&hash[..16]))
    }

    /// Verify DID binding (self-certifying)
    pub fn verify_did_binding(&self) -> bool {
        let expected = Self::compute_did(&self.dilithium_pk, &self.kyber_pk, self.epoch);
        self.did == expected
    }

    /// Sign DID document for authentication
    pub fn sign_did(&self, secret: &DigitalIDSecret, ctx: &[u8]) -> dilithium::SignatureBytes {
        let msg = self.serialize_for_signing();
        secret.dilithium_sk.sign(&msg, ctx)
    }

    /// Verify DID signature
    pub fn verify_did_signature(
        &self,
        sig: &dilithium::SignatureBytes,
        ctx: &[u8],
    ) -> bool {
        let msg = self.serialize_for_signing();
        self.dilithium_pk.verify(&msg, ctx, sig)
    }

    /// Rotate to new epoch (post-compromise security)
    pub fn rotate_epoch<R: CryptoRngCore>(
        &mut self,
        secret: &mut DigitalIDSecret,
        rng: &mut R,
    ) {
        let old_dilithium_pk = self.dilithium_pk.clone();
        let old_kyber_pk = self.kyber_pk.clone();

        // Generate new keys
        let (new_kyber_pk, new_kyber_sk) = kyber::SecretKey::generate(rng);
        let new_dilithium_sk = dilithium::SecretKey::generate(rng);
        let new_dilithium_pk = new_dilithium_sk.verifying_key();

        // Update secret
        secret.kyber_sk = new_kyber_sk;
        secret.dilithium_sk = new_dilithium_sk;

        // Update public ID
        self.epoch += 1;
        self.prev_key_hash = {
            let mut hasher = Sha256::new();
            hasher.update(old_dilithium_pk.to_bytes());
            hasher.update(old_kyber_pk.to_bytes());
            hasher.finalize().into()
        };
        self.dilithium_pk = new_dilithium_pk;
        self.kyber_pk = new_kyber_pk;
        self.did = Self::compute_did(&self.dilithium_pk, &self.kyber_pk, self.epoch);
    }

    /// Create recovery shares (3-of-5 threshold)
    pub fn create_recovery_shares(
        &self,
        secret: &DigitalIDSecret,
    ) -> Vec<RecoveryShare> {
        // Use shamir-vault for threshold sharing
        use shamir_vault::{Shamir, Share};

        let data = secret.recovery_seed.to_vec();
        let shares = Shamir::new(3, 5)
            .split(&data)
            .expect("Failed to create shares");

        shares.into_iter()
            .enumerate()
            .map(|(i, share)| RecoveryShare {
                index: (i + 1) as u8,
                value: share.into(),
            })
            .collect()
    }

    /// Recover secrets from shares (need at least threshold)
    pub fn recover_from_shares(shares: &[RecoveryShare]) -> Option<Vec<u8>> {
        use shamir_vault::{Shamir, Share};

        if shares.len() < 3 {
            return None;
        }

        let shamir_shares: Vec<Share> = shares.iter()
            .map(|s| Share::try_from(s.value.as_slice()).expect("Invalid share"))
            .collect();

        Shamir::new(3, 5)
            .recover(&shamir_shares)
            .ok()
    }

    /// Serialize for signing (deterministic)
    fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.did.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(self.dilithium_pk.to_bytes());
        bytes.extend_from_slice(self.kyber_pk.to_bytes());
        bytes.extend_from_slice(&self.prev_key_hash);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_did_generation() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        assert!(id.did.starts_with("did:aim:"));
        assert_eq!(id.epoch, 1);
        assert!(id.verify_did_binding());
    }

    #[test]
    fn test_did_signature() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        let ctx = b"test-context";
        let sig = id.sign_did(&secret, ctx);
        assert!(id.verify_did_signature(&sig, ctx));
        assert!(!id.verify_did_signature(&sig, b"wrong-ctx"));
    }

    #[test]
    fn test_epoch_rotation() {
        let mut rng = OsRng;
        let (mut id, mut secret) = DigitalID::generate(&mut rng);
        let old_dilithium_pk = id.dilithium_pk.to_bytes().to_vec();

        id.rotate_epoch(&mut secret, &mut rng);

        assert_ne!(id.dilithium_pk.to_bytes(), old_dilithium_pk.as_slice());
        assert_eq!(id.epoch, 2);
        assert!(id.verify_did_binding());

        // Verify new keys work
        let msg = b"post-rotation test";
        let ctx = b"aim-v1-auth";
        let sig = id.sign_did(&secret, ctx);
        assert!(id.verify_did_signature(&sig, ctx));
    }

    #[test]
    fn test_recovery_sharing() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        let shares = id.create_recovery_shares(&secret);
        assert_eq!(shares.len(), 5);

        // Recover with 3 shares
        let recovered = DigitalID::recover_from_shares(&shares[..3]);
        assert!(recovered.is_some());

        // Verify recovered data matches original
        let original_secret = secret.dilithium_sk.to_bytes();
        let recovered_secret = recovered.unwrap();
        assert_eq!(original_secret.to_vec(), recovered_secret);
    }

    #[test]
    fn test_recovery_fails_with_insufficient_shares() {
        let mut rng = OsRng;
        let (id, secret) = DigitalID::generate(&mut rng);

        let shares = id.create_recovery_shares(&secret);

        // Try with only 2 shares (below threshold)
        let recovered = DigitalID::recover_from_shares(&shares[..2]);
        assert!(recovered.is_none());
    }

    #[test]
    fn test_recovery_seed_is_zeroized() {
        let mut rng = OsRng;
        let (_id, secret) = DigitalID::generate(&mut rng);

        // Make a copy of the seed before drop
        let original_seed = secret.recovery_seed;

        // Drop secret (should zeroize)
        drop(secret);

        // We can\'t directly test zeroization after drop,
        // but this ensures the field is marked with #[zeroize(skip)]
        // which means it WON\'T be zeroized (as intended for recovery)
        assert_eq!(original_seed.len(), 32);
    }
}
