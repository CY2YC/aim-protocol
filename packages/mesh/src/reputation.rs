//! Reputation system with slashing and decay
//!
//! Implements a decentralized reputation mechanism where peers
//! gain/lose reputation based on behavior, with automatic decay.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reputation entry for a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationEntry {
    /// Peer DID
    pub peer_id: String,
    /// Current reputation score (0-100)
    pub score: f64,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
    /// Number of successful interactions
    pub successful_interactions: u64,
    /// Number of failed interactions
    pub failed_interactions: u64,
    /// Number of slashings
    pub slash_count: u32,
    /// Is currently banned
    pub banned: bool,
}

impl ReputationEntry {
    /// Create new reputation entry
    pub fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            score: 50.0, // Neutral starting score
            last_update: Utc::now(),
            successful_interactions: 0,
            failed_interactions: 0,
            slash_count: 0,
            banned: false,
        }
    }

    /// Update score based on interaction result
    pub fn update(&mut self, success: bool) {
        self.last_update = Utc::now();

        if success {
            self.successful_interactions += 1;
            self.score = (self.score + 5.0).min(100.0);
        } else {
            self.failed_interactions += 1;
            self.score = (self.score - 10.0).max(0.0);
        }
    }

    /// Apply slashing penalty
    pub fn slash(&mut self, penalty: f64) {
        self.slash_count += 1;
        self.score = (self.score - penalty).max(0.0);
        self.last_update = Utc::now();

        // Auto-ban if score too low or too many slashes
        if self.score < 10.0 || self.slash_count >= 3 {
            self.banned = true;
        }
    }

    /// Apply time-based decay
    pub fn apply_decay(&mut self) {
        let now = Utc::now();
        let days_since_update = (now - self.last_update).num_days() as f64;

        if days_since_update > 0.0 {
            // Decay: lose 1% per day of inactivity
            let decay = days_since_update * 1.0;
            self.score = (self.score - decay).max(0.0);
        }
    }

    /// Check if peer is trusted (score >= 70)
    pub fn is_trusted(&self) -> bool {
        !self.banned && self.score >= 70.0
    }

    /// Check if peer is banned
    pub fn is_banned(&self) -> bool {
        self.banned
    }
}

/// Reputation manager
pub struct ReputationManager {
    /// Peer reputation entries
    entries: HashMap<String, ReputationEntry>,
    /// Minimum score for bootstrap participation
    bootstrap_threshold: f64,
}

impl ReputationManager {
    /// Create new reputation manager
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            bootstrap_threshold: 50.0,
        }
    }

    /// Get or create entry for peer
    pub fn get_or_create(&mut self, peer_id: &str) -> &mut ReputationEntry {
        self.entries
            .entry(peer_id.to_string())
            .or_insert_with(|| ReputationEntry::new(peer_id.to_string()))
    }

    /// Record successful interaction
    pub fn record_success(&mut self, peer_id: &str) {
        let entry = self.get_or_create(peer_id);
        entry.update(true);
    }

    /// Record failed interaction
    pub fn record_failure(&mut self, peer_id: &str) {
        let entry = self.get_or_create(peer_id);
        entry.update(false);
    }

    /// Slash a peer for misbehavior
    pub fn slash(&mut self, peer_id: &str, penalty: f64) {
        let entry = self.get_or_create(peer_id);
        entry.slash(penalty);
    }

    /// Apply decay to all entries
    pub fn apply_global_decay(&mut self) {
        for entry in self.entries.values_mut() {
            entry.apply_decay();
        }

        // Remove entries with score 0
        self.entries.retain(|_, entry| entry.score > 0.0);
    }

    /// Get trusted peers for bootstrap
    pub fn get_trusted_peers(&self) -> Vec<&ReputationEntry> {
        self.entries
            .values()
            .filter(|entry| entry.is_trusted())
            .collect()
    }

    /// Check if peer can participate in bootstrap
    pub fn can_bootstrap(&self, peer_id: &str) -> bool {
        self.entries
            .get(peer_id)
            .map(|entry| entry.score >= self.bootstrap_threshold && !entry.banned)
            .unwrap_or(false)
    }

    /// Get entry for peer
    pub fn get(&self, peer_id: &str) -> Option<&ReputationEntry> {
        self.entries.get(peer_id)
    }

    /// Get all entries
    pub fn all_entries(&self) -> &HashMap<String, ReputationEntry> {
        &self.entries
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate reputation update based on interaction quality
pub fn calculate_reputation_update(
    current_score: f64,
    interaction_quality: f64, // -1.0 to 1.0
) -> f64 {
    let change = interaction_quality * 10.0;
    (current_score + change).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_entry() {
        let mut entry = ReputationEntry::new("did:aim:test".to_string());

        assert_eq!(entry.score, 50.0);
        assert!(!entry.is_trusted());

        // Successful interactions increase score
        entry.update(true);
        assert_eq!(entry.score, 55.0);

        // Failed interactions decrease score more
        entry.update(false);
        assert_eq!(entry.score, 45.0);
    }

    #[test]
    fn test_slashing() {
        let mut entry = ReputationEntry::new("did:aim:test".to_string());

        entry.slash(20.0);
        assert_eq!(entry.score, 30.0);
        assert_eq!(entry.slash_count, 1);
        assert!(!entry.banned);

        // Multiple slashes lead to ban
        entry.slash(20.0);
        entry.slash(20.0);
        assert!(entry.banned);
    }

    #[test]
    fn test_trusted_status() {
        let mut entry = ReputationEntry::new("did:aim:test".to_string());

        assert!(!entry.is_trusted());

        // Need score >= 70 to be trusted
        for _ in 0..10 {
            entry.update(true);
        }

        assert!(entry.is_trusted());
        assert!(entry.score >= 70.0);
    }

    #[test]
    fn test_reputation_manager() {
        let mut manager = ReputationManager::new();

        manager.record_success("peer1");
        manager.record_success("peer1");
        manager.record_failure("peer2");

        let peer1 = manager.get("peer1").unwrap();
        assert_eq!(peer1.score, 60.0);

        let peer2 = manager.get("peer2").unwrap();
        assert_eq!(peer2.score, 40.0);

        // Only peer1 can bootstrap
        assert!(manager.can_bootstrap("peer1"));
        assert!(!manager.can_bootstrap("peer2"));
    }

    #[test]
    fn test_global_decay() {
        let mut manager = ReputationManager::new();

        manager.record_success("peer1");
        manager.record_success("peer2");

        // Apply decay (no actual time passed, so no change)
        manager.apply_global_decay();

        let peer1 = manager.get("peer1").unwrap();
        assert_eq!(peer1.score, 60.0); // No decay yet
    }
}
