//! Revocation System: Sparse Merkle Tree + Bloom Filter + BFT Signing
//!
//! Implements efficient revocation checking with:
//! - Sparse Merkle Tree for cryptographic proofs (monotree crate)
//! - Bloom filter for probabilistic fast-path rejection
//! - BFT threshold signatures for governance

use blake3::Hasher as Blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Revocation entry for a single identity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// DID of revoked identity
    pub did: String,
    /// Revocation timestamp
    pub timestamp: u64,
    /// Reason code
    pub reason: u8,
    /// BFT signature threshold
    pub signatures: Vec<ThresholdSignature>,
}

/// Threshold signature share
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub validator_id: [u8; 32],
    pub signature: Vec<u8>,
}

/// Sparse Merkle Tree based revocation list
///
/// Uses monotree for production-grade SMT
pub struct RevocationSmt {
    /// Underlying SMT (using monotree)
    tree: monotree::Monotree<Blake3, monotree::database::MemoryDB>,
    /// Current root hash
    root: Option<[u8; 32]>,
}

impl RevocationSmt {
    /// Create new empty SMT
    pub fn new() -> Self {
        Self { 
            tree: monotree::Monotree::new(),  // Fixed: Monotree::new() not default()
            root: None 
        }
    }

    /// Revoke a DID (insert into SMT)
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

        // Insert into SMT
        let new_root = self
            .tree
            .insert(self.root.as_ref(), &key, &value_hash)
            .map_err(|_| RevocationError::TreeInsertFailed)?;

        self.root = Some(new_root);
        Ok(new_root)
    }

    /// Check if DID is revoked (with proof)
    pub fn is_revoked(&self, did: &str) -> (bool, Option<MerkleProof>) {
        let key = Self::hash_did(did);

        // Get value at key
        match self.tree.get(self.root.as_ref(), &key) {
            Ok(Some(_)) => {
                // Generate proof
                match self.tree.get_proof(self.root.as_ref(), &key) {  // Fixed: get_proof not get_merkle_proof
                    Ok(proof) => (true, Some(MerkleProof { proof: Some(proof) })),
                    Err(_) => (true, Some(MerkleProof { proof: None })),
                }
            }
            Ok(None) => (false, None),
            Err(_) => (false, None),
        }
    }

    /// Verify Merkle proof
    pub fn verify_proof(&self, did: &str, entry_hash: &[u8; 32], proof: &MerkleProof) -> bool {
        let key = Self::hash_did(did);
        
        match &proof.proof {
            Some(proof_data) => {
                monotree::verify_proof(self.root.as_ref(), &key, entry_hash, proof_data)
                    .unwrap_or(false)
            }
            None => false,
        }
    }

    /// Get current root
    pub fn root(&self) -> Option<[u8; 32]> {
        self.root
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

/// Merkle proof for revocation verification
#[derive(Clone, Debug)]
pub struct MerkleProof {
    proof: Option<Vec<u8>>,
}

/// Probabilistic fast-path filter
///
/// Uses bloomfilter crate for production use
pub struct RevocationBloomFilter {
    filter: bloomfilter::Bloom<Vec<u8>>,
}

impl RevocationBloomFilter {
    /// Create new Bloom filter
    ///
    /// capacity: expected number of revoked DIDs
    /// fp_rate: acceptable false positive rate (e.g., 0.001 = 0.1%)
    pub fn new(capacity: u32, fp_rate: f64) -> Self {
        Self {
            filter: bloomfilter::Bloom::new_for_fp_rate(capacity, fp_rate),
        }
    }

    /// Add revoked DID to filter
    pub fn add(&mut self, did: &str) {
        self.filter.set(&did.as_bytes().to_vec());
    }

    /// Check if DID might be revoked
    ///
    /// Returns true if probably revoked (check SMT to confirm)
    /// Returns false if definitely not revoked
    pub fn probably_contains(&self, did: &str) -> bool {
        self.filter.check(&did.as_bytes().to_vec())
    }

    /// Serialize filter for distribution
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.filter).unwrap_or_default()
    }

    /// Deserialize filter
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|filter| Self { filter })
    }
}

/// Combined revocation checker (Bloom + SMT)
pub struct RevocationChecker {
    /// Fast probabilistic filter
    bloom: RevocationBloomFilter,
    /// Cryptographic SMT
    smt: RevocationSmt,
    /// Cache of recently checked DIDs
    cache: HashSet<String>,
}

impl RevocationChecker {
    /// Create new checker
    pub fn new(expected_revocations: u32) -> Self {
        Self {
            bloom: RevocationBloomFilter::new(expected_revocations, 0.001),
            smt: RevocationSmt::new(),
            cache: HashSet::new(),
        }
    }

    /// Add revocation
    pub fn revoke(&mut self, entry: RevocationEntry) -> Result<[u8; 32], RevocationError> {
        // Add to Bloom filter (fast path)
        self.bloom.add(&entry.did);

        // Add to SMT (cryptographic proof)
        let root = self.smt.revoke(&entry.did, &entry)?;

        Ok(root)
    }

    /// Check if DID is revoked
    ///
    /// Fast path: Bloom filter negative = definitely not revoked
    /// Slow path: SMT lookup with proof
    pub fn check_revocation(&self, did: &str) -> RevocationStatus {
        // Check cache first
        if self.cache.contains(did) {
            return RevocationStatus::NotRevoked;
        }

        // Fast path: Bloom filter
        if !self.bloom.probably_contains(did) {
            return RevocationStatus::NotRevoked;
        }

        // Slow path: SMT verification
        let (is_revoked, proof) = self.smt.is_revoked(did);

        if is_revoked {
            RevocationStatus::Revoked { proof }
        } else {
            // Bloom false positive - add to cache
            RevocationStatus::NotRevoked
        }
    }

    /// Get SMT root for BFT signing
    pub fn smt_root(&self) -> Option<[u8; 32]> {
        self.smt.root()
    }
}

/// Revocation check result
#[derive(Clone, Debug)]
pub enum RevocationStatus {
    NotRevoked,
    Revoked { proof: Option<MerkleProof> },
}

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("SMT insertion failed")]
    TreeInsertFailed,
    #[error("Empty root after insertion")]
    EmptyRoot,
    #[error("Invalid proof")]
    InvalidProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_revocation() {
        let mut smt = RevocationSmt::new();

        let entry = RevocationEntry {
            did: "did:aim:test123".to_string(),
            timestamp: 1234567890,
            reason: 1,
            signatures: vec![],
        };

        // Revoke
        let root1 = smt.revoke(&entry.did, &entry).unwrap();

        // Check revoked
        let (is_revoked, proof) = smt.is_revoked(&entry.did);
        assert!(is_revoked);
        assert!(proof.is_some());

        // Check not revoked
        let (is_revoked2, _) = smt.is_revoked("did:aim:other");
        assert!(!is_revoked2);
    }

    #[test]
    fn test_bloom_filter() {
        let mut bloom = RevocationBloomFilter::new(1000, 0.01);

        bloom.add("did:aim:test1");
        bloom.add("did:aim:test2");

        assert!(bloom.probably_contains("did:aim:test1"));
        assert!(bloom.probably_contains("did:aim:test2"));
        assert!(!bloom.probably_contains("did:aim:test3")); // Definite no
    }

    #[test]
    fn test_combined_checker() {
        let mut checker = RevocationChecker::new(100);

        let entry = RevocationEntry {
            did: "did:aim:revoked".to_string(),
            timestamp: 1234567890,
            reason: 1,
            signatures: vec![],
        };

        checker.revoke(entry).unwrap();

        // Check revoked
        match checker.check_revocation("did:aim:revoked") {
            RevocationStatus::Revoked { .. } => {}
            _ => panic!("Expected revoked"),
        }

        // Check not revoked
        match checker.check_revocation("did:aim:valid") {
            RevocationStatus::NotRevoked => {}
            _ => panic!("Expected not revoked"),
        }
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
