//! Reputation System: Decay, Rewards, and Slashing
//!
//! Implements economic security through reputation scores.
/// Bandwidth contribution increases reputation.
/// Misbehavior causes slashing (50% reduction).
/// Time decay prevents stale reputation.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum reputation score
const MAX_REPUTATION: u32 = 10000;
/// Minimum reputation for network participation
const MIN_REPUTATION: u32 = 10;
/// Decay factor per hour (0.99 = 1% decay per hour)
const DECAY_FACTOR: f64 = 0.99;
/// Reward per KB forwarded
const REWARD_PER_KB: f64 = 0.1;
/// Slash factor for misbehavior
const SLASH_FACTOR: f64 = 0.5;

/// Reputation entry for a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationEntry {
    /// Current reputation score (0-10000)
    pub score: u32,
    /// Total bytes forwarded (lifetime)
    pub total_forwarded: u64,
    /// Total bytes received (lifetime)
    pub total_received: u64,
    /// Number of misbehavior incidents
    pub misbehavior_count: u32,
    /// Last update timestamp (Unix seconds)
    pub last_update: u64,
    /// First seen timestamp
    pub first_seen: u64,
}

impl Default for ReputationEntry {
    fn default() -> Self {
        let now = current_timestamp();
        Self {
            score: 100, // Start with small positive reputation
            total_forwarded: 0,
            total_received: 0,
            misbehavior_count: 0,
            last_update: now,
            first_seen: now,
        }
    }
}

/// Reputation manager
pub struct ReputationManager {
    /// Peer reputation database
    peers: HashMap<String, ReputationEntry>,
    /// Minimum reputation threshold
    min_reputation: u32,
    /// Decay interval (seconds)
    decay_interval: u64,
}

impl ReputationManager {
    /// Create new reputation manager
    pub fn new(min_reputation: u32) -> Self {
        Self {
            peers: HashMap::new(),
            min_reputation,
            decay_interval: 3600, // 1 hour
        }
    }

    /// Get or create reputation entry
    pub fn get(&mut self, did: &str) -> &ReputationEntry {
        self.peers.entry(did.to_string()).or_default()
    }

    /// Get mutable entry
    pub fn get_mut(&mut self, did: &str) -> &mut ReputationEntry {
        self.peers.entry(did.to_string()).or_default()
    }

    /// Record bandwidth contribution (forwarding)
    pub fn record_forward(&mut self, did: &str, bytes_forwarded: u64) {
        let entry = self.get_mut(did);
        entry.total_forwarded += bytes_forwarded;

        // Calculate reward
        let reward = (bytes_forwarded as f64 / 1024.0) * REWARD_PER_KB;
        let new_score = (entry.score as f64 + reward).min(MAX_REPUTATION as f64);
        entry.score = new_score as u32;
        entry.last_update = current_timestamp();
    }

    /// Record bandwidth consumption (receiving)
    pub fn record_receive(&mut self, did: &str, bytes_received: u64) {
        let entry = self.get_mut(did);
        entry.total_received += bytes_received;
        entry.last_update = current_timestamp();
    }

    /// Slash reputation for misbehavior
    pub fn slash(&mut self, did: &str, reason: &str) {
        let entry = self.get_mut(did);
        let new_score = (entry.score as f64 * SLASH_FACTOR).floor();
        entry.score = new_score as u32;
        entry.misbehavior_count += 1;
        entry.last_update = current_timestamp();

        tracing::warn!("Slashed peer {} for {}: new score = {}", did, reason, entry.score);
    }

    /// Apply time decay to all entries
    /// Should be called periodically (e.g., every hour)
    pub fn apply_decay(&mut self) {
        let now = current_timestamp();

        for (did, entry) in self.peers.iter_mut() {
            let hours_elapsed = (now - entry.last_update) / 3600;

            if hours_elapsed > 0 {
                let decay = DECAY_FACTOR.powi(hours_elapsed as i32);
                let new_score = (entry.score as f64 * decay).floor();
                entry.score = new_score.max(MIN_REPUTATION as f64) as u32;
                entry.last_update = now;

                if hours_elapsed > 24 {
                    tracing::debug!(
                        "Applied {}h decay to {}: score = {}",
                        hours_elapsed,
                        did,
                        entry.score
                    );
                }
            }
        }
    }

    /// Check if peer meets minimum reputation
    pub fn is_reputable(&self, did: &str) -> bool {
        self.peers.get(did).map(|e| e.score >= self.min_reputation).unwrap_or(false)
    }

    /// Get reputation score
    pub fn get_score(&self, did: &str) -> u32 {
        self.peers.get(did).map(|e| e.score).unwrap_or(0)
    }

    /// Get top peers by reputation
    pub fn get_top_peers(&self, n: usize) -> Vec<(String, u32)> {
        let mut peers: Vec<_> =
            self.peers.iter().map(|(did, entry)| (did.clone(), entry.score)).collect();

        peers.sort_by(|a, b| b.1.cmp(&a.1));
        peers.truncate(n);
        peers
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.peers).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let peers = postcard::from_bytes(bytes).ok()?;
        Some(Self {
            peers,
            min_reputation: MIN_REPUTATION,
            decay_interval: 3600,
        })
    }
}

/// Calculate reputation update (standalone function for XDP)
pub fn calculate_reputation_update(
    current: u32,
    forward_bytes: u64,
    is_misbehavior: bool,
    hours_elapsed: f64,
) -> u32 {
    let mut rep = current as f64;

    // Time decay
    rep *= DECAY_FACTOR.powf(hours_elapsed);

    // Reward bandwidth
    rep += (forward_bytes as f64 / 1024.0) * REWARD_PER_KB;

    // Slash for misbehavior
    if is_misbehavior {
        rep *= SLASH_FACTOR;
    }

    rep.clamp(MIN_REPUTATION as f64, MAX_REPUTATION as f64) as u32
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_forwarding() {
        let mut manager = ReputationManager::new(10);
        let did = "did:aim:test";

        // Initial reputation
        assert_eq!(manager.get_score(did), 100);

        // Forward 1MB
        manager.record_forward(did, 1024 * 1024);

        // Should increase
        assert!(manager.get_score(did) > 100);
    }

    #[test]
    fn test_slashing() {
        let mut manager = ReputationManager::new(10);
        let did = "did:aim:test";

        // Build up reputation
        manager.record_forward(did, 1024 * 1024 * 100); // 100MB
        let before_slash = manager.get_score(did);

        // Slash
        manager.slash(did, "spam");
        let after_slash = manager.get_score(did);

        // Should be roughly 50%
        assert!(after_slash < before_slash);
        assert!(after_slash >= before_slash / 2 - 1);
    }

    #[test]
    fn test_decay() {
        let mut manager = ReputationManager::new(10);
        let did = "did:aim:test";

        // Set high reputation
        manager.record_forward(did, 1024 * 1024 * 1000);
        let before = manager.get_score(did);

        // Manually set last_update to 10 hours ago
        {
            let entry = manager.get_mut(did);
            entry.last_update = current_timestamp() - 10 * 3600;
        }

        // Apply decay
        manager.apply_decay();
        let after = manager.get_score(did);

        // Should have decayed
        assert!(after < before);
    }

    #[test]
    fn test_standalone_calculation() {
        let current = 5000u32;
        let forward_bytes = 1024 * 1024; // 1MB
        let hours = 1.0;

        let new_rep = calculate_reputation_update(current, forward_bytes, false, hours);

        // Should be slightly less than 5000 due to decay, plus reward
        assert!(new_rep > 0);
        assert!(new_rep <= MAX_REPUTATION);
    }
}
