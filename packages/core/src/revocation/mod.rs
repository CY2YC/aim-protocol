//! Revocation system using Sparse Merkle Trees (SMT) + Bloom filters
//!
//! Provides efficient revocation checking with cryptographic proofs.

use blake3::Hasher as Blake3;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors in revocation operations
#[derive(Error, Debug)]
pub enum RevocationError {
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Entry not found")]
    NotFound,
}

/// Sparse Merkle Tree for revocation
pub struct RevocationSmt {
    /// Monotree instance
    tree: monotree::Monotree<Blake3, monotree::database::MemoryDB>,
    /// Current root hash
    root: Option<monotree::Hash>,
}

/// Revocation entry for a DID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// DID being revoked
    pub did: String,
    /// Epoch when revoked
    pub epoch: u64,
    /// Reason code
    pub reason: u16,
    /// Signature by authority
    pub signature: Vec<u8>,
}

/// Merkle proof for revocation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Proof data (None if direct lookup)
    pub proof: Option<monotree::Proof>,
}

impl RevocationSmt {
    /// Create new empty SMT
    pub fn new() -> Self {
        Self {
            tree: monotree::Monotree::new(),
            root: None,
        }
    }

    /// Add revocation entry
    pub fn revoke(
        &mut self,
        did: &str,
        entry: &RevocationEntry,
    ) -> Result<[u8; 32], RevocationError> {
        // Serialize entry
        let value = postcard::to_allocvec(entry)
            .map_err(|_| RevocationError::SerializationFailed)?;

        // Hash DID to get key (256-bit for SMT path)
        let key = Self::hash_did(did);

        // Hash the value
        let value_hash = blake3::hash(&value).into();

        // Insert into tree
        self.root = self
            .tree
            .insert(self.root.as_ref(), &key, &value_hash)
            .map_err(|_| RevocationError::SerializationFailed)?;

        Ok(self.root.unwrap_or([0u8; 32]))
    }

    /// Check if DID is revoked and get proof
    pub fn is_revoked(&self, did: &str) -> (bool, Option<MerkleProof>) {
        let key = Self::hash_did(did);

        match self.tree.get(self.root.as_ref(), &key) {
            Ok(Some(_)) => {
                // Generate proof
                match self.tree.get_proof(self.root.as_ref(), &key) {
                    Ok(proof) => (true, Some(MerkleProof { proof: Some(proof) })),
                    Err(_) => (true, Some(MerkleProof { proof: None })),
                }
            }
            _ => (false, None),
        }
    }

    /// Verify Merkle proof
    pub fn verify_proof(&self, did: &str, entry_hash: &[u8; 32], proof: &MerkleProof) -> bool {
        let key = Self::hash_did(did);

        match &proof.proof {
            Some(proof_data) => {
                monotree::verify_proof(self.root.as_ref(), &key, entry_hash, proof_data)
            }
            None => false,
        }
    }

    /// Hash DID to 256-bit key
    fn hash_did(did: &str) -> [u8; 32] {
        blake3::hash(did.as_bytes()).into()
    }
}

impl Default for RevocationSmt {
    fn default() -> Self {
        Self::new()
    }
}

/// Bloom filter for probabilistic revocation checking
pub struct RevocationBloomFilter {
    filter: bloomfilter::Bloom<Vec<u8>>,
}

impl RevocationBloomFilter {
    /// Create new bloom filter
    pub fn new(capacity: u32, fp_rate: f64) -> Self {
        Self {
            filter: bloomfilter::Bloom::new_for_fp_rate(capacity, fp_rate),
        }
    }

    /// Add DID to filter
    pub fn add(&mut self, did: &str) {
        self.filter.set(did.as_bytes());
    }

    /// Check if DID might be revoked (probabilistic)
    pub fn probably_contains(&self, did: &str) -> bool {
        self.filter.check(did.as_bytes())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.filter).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|filter| Self { filter })
    }
}

/// Combined revocation checker (SMT + Bloom filter)
pub struct RevocationChecker {
    /// Sparse Merkle Tree for exact checking
    smt: RevocationSmt,
    /// Bloom filter for fast negative checks
    bloom: RevocationBloomFilter,
}

impl RevocationChecker {
    /// Create new checker
    pub fn new() -> Self {
        Self {
            smt: RevocationSmt::new(),
            bloom: RevocationBloomFilter::new(10000, 0.001),
        }
    }

    /// Revoke a DID
    pub fn revoke(
        &mut self,
        did: &str,
        entry: &RevocationEntry,
    ) -> Result<[u8; 32], RevocationError> {
        self.bloom.add(did);
        self.smt.revoke(did, entry)
    }

    /// Check if revoked (fast negative via Bloom, exact via SMT)
    pub fn is_revoked(&self, did: &str) -> (bool, Option<MerkleProof>) {
        // Fast negative check
        if !self.bloom.probably_contains(did) {
            return (false, None);
        }

        // Exact check via SMT
        self.smt.is_revoked(did)
    }

    /// Get current SMT root
    pub fn root(&self) -> Option<[u8; 32]> {
        self.smt.root
    }
}

impl Default for RevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_revocation() {
        let mut smt = RevocationSmt::new();

        let entry = RevocationEntry {
            did: "did:aim:test1".to_string(),
            epoch: 1,
            reason: 1,
            signature: vec![1u8; 64],
        };

        let root = smt.revoke("did:aim:test1", &entry).unwrap();
        assert_ne!(root, [0u8; 32]);

        let (revoked, proof) = smt.is_revoked("did:aim:test1");
        assert!(revoked);
        assert!(proof.is_some());

        let (not_revoked, _) = smt.is_revoked("did:aim:unknown");
        assert!(!not_revoked);
    }

    #[test]
    fn test_bloom_filter() {
        let mut bloom = RevocationBloomFilter::new(1000, 0.01);
        bloom.add("did:aim:test1");

        assert!(bloom.probably_contains("did:aim:test1"));
        assert!(!bloom.probably_contains("did:aim:test2"));
    }

    #[test]
    fn test_combined_checker() {
        let mut checker = RevocationChecker::new();

        let entry = RevocationEntry {
            did: "did:aim:test1".to_string(),
            epoch: 1,
            reason: 1,
            signature: vec![1u8; 64],
        };

        checker.revoke("did:aim:test1", &entry).unwrap();

        let (revoked, _) = checker.is_revoked("did:aim:test1");
        assert!(revoked);

        let (not_revoked, _) = checker.is_revoked("did:aim:unknown");
        assert!(!not_revoked);
    }

    #[test]
    fn test_bloom_serialization() {
        let mut bloom1 = RevocationBloomFilter::new(1000, 0.01);
        bloom1.add("did:aim:test1");

        let bytes = bloom1.to_bytes();
        let bloom2 = RevocationBloomFilter::from_bytes(&bytes).unwrap();

        assert!(bloom2.probably_contains("did:aim:test1"));
    }
}
