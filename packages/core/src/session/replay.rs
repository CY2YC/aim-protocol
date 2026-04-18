//! Replay Protection & Session Key Rotation
//!
//! Implements 64-bit sliding window for replay detection
//! and HKDF-based key rotation for post-compromise security.

use crate::crypto::kdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 64-packet sliding window for replay detection
///
/// Design: Uses 64-bit bitmap with base sequence number.
/// Allows out-of-order delivery within window, rejects old packets.
pub struct ReplayWindow {
    /// Base sequence number (all seq < base are rejected)
    base_seq: u64,
    /// Bitmap of received packets (bit i = packet base_seq + i)
    bitmap: u64,
    /// Maximum window size (fixed at 64)
    max_window: usize,
}

impl ReplayWindow {
    /// Create new replay window
    pub fn new() -> Self {
        Self { 
            base_seq: 0, 
            bitmap: 0, 
            max_window: 64 
        }
    }

    /// Check if sequence number is a replay
    ///
    /// Returns true if packet should be rejected (replay or too old)
    pub fn is_replay(&mut self, seq: u64) -> bool {
        // Reject if too old (outside window)
        if seq < self.base_seq {
            return true;
        }

        let offset = seq.saturating_sub(self.base_seq);

        // Reject if beyond window (would require shifting too far)
        if offset >= self.max_window as u64 {
            // Shift window to accommodate new sequence
            let shift = offset - (self.max_window as u64 - 1);
            self.base_seq += shift;
            self.bitmap >>= shift;
            let new_offset = seq - self.base_seq;

            // Check again after shift
            if new_offset >= self.max_window as u64 {
                return true; // Still too far ahead
            }
        }

        let bit = 1u64 << (seq - self.base_seq);

        // Check if already received
        if (self.bitmap & bit) != 0 {
            return true; // Replay detected
        }

        // Mark as received
        self.bitmap |= bit;
        false
    }

    /// Get current base sequence
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }

    /// Get number of packets in current window
    pub fn received_count(&self) -> u32 {
        self.bitmap.count_ones()
    }

    /// Reset window (e.g., after key rotation)
    pub fn reset(&mut self, new_base: u64) {
        self.base_seq = new_base;
        self.bitmap = 0;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Session key manager with automatic rotation
#[derive(Zeroize)]
#[zeroize(drop)]  // Fixed: Use attribute instead of manual impl
pub struct SessionKeyManager {
    /// Current base key
    base_key: [u8; 32],
    /// Current epoch
    epoch: u32,
    /// Maximum epochs before re-handshake required
    max_epochs: u32,
    /// Keys for each direction (derived per-epoch)
    tx_key: [u8; 32],
    rx_key: [u8; 32],
}

impl SessionKeyManager {
    /// Create new key manager from initial handshake key
    pub fn new(base_key: [u8; 32], max_epochs: u32) -> Self {
        let (tx, rx) = Self::derive_epoch_keys(&base_key, 0);

        Self {
            base_key,
            epoch: 0,
            max_epochs,
            tx_key: tx,
            rx_key: rx,
        }
    }

    /// Rotate to next epoch
    ///
    /// Returns false if max epochs reached (re-handshake required)
    pub fn rotate(&mut self) -> bool {
        if self.epoch >= self.max_epochs {
            return false;
        }

        self.epoch += 1;
        let (tx, rx) = Self::derive_epoch_keys(&self.base_key, self.epoch);
        self.tx_key = tx;
        self.rx_key = rx;

        true
    }

    /// Derive keys for specific epoch using HKDF
    fn derive_epoch_keys(base: &[u8; 32], epoch: u32) -> ([u8; 32], [u8; 32]) {
        let mut tx = [0u8; 32];
        let mut rx = [0u8; 32];

        let info_tx = format!("aim-epoch-{}-tx", epoch);
        let info_rx = format!("aim-epoch-{}-rx", epoch);

        kdf::hkdf_sha256(base, b"", info_tx.as_bytes(), &mut tx);
        kdf::hkdf_sha256(base, b"", info_rx.as_bytes(), &mut rx);

        (tx, rx)
    }

    /// Get current transmission key
    pub fn tx_key(&self) -> &[u8; 32] {
        &self.tx_key
    }

    /// Get current reception key
    pub fn rx_key(&self) -> &[u8; 32] {
        &self.rx_key
    }

    /// Get current epoch
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Check if rotation is needed (based on packet count or time)
    pub fn needs_rotation(&self, packets_sent: u64) -> bool {
        // Rotate every 1M packets or at max epochs
        packets_sent > 1_000_000 || self.epoch >= self.max_epochs - 1
    }
}

// ZeroizeOnDrop is automatically handled by #[zeroize(drop)]
// No manual impl needed

/// Combined session state (replay + keys)
pub struct SecureSession {
    replay_window: ReplayWindow,
    key_manager: SessionKeyManager,
    packets_processed: u64,
    session_id: [u8; 16],
}

impl SecureSession {
    /// Create new secure session
    /// Note: Uses direct crate import instead of super::handshake
    pub fn new(session_keys: SessionKeys, max_epochs: u32) -> Self {
        let key_manager = SessionKeyManager::new(
            session_keys.tx_key, // Use tx as base
            max_epochs,
        );

        Self {
            replay_window: ReplayWindow::new(),
            key_manager,
            packets_processed: 0,
            session_id: session_keys.session_id,
        }
    }

    /// Process incoming packet
    ///
    /// Returns Some(plaintext) if valid, None if replay/invalid
    pub fn process_incoming(&mut self, seq: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Check replay
        if self.replay_window.is_replay(seq) {
            return None;
        }

        // TODO: Decrypt with self.key_manager.rx_key()
        // let plaintext = decrypt(ciphertext, self.key_manager.rx_key());

        self.packets_processed += 1;

        // Auto-rotate if needed
        if self.key_manager.needs_rotation(self.packets_processed) {
            if !self.key_manager.rotate() {
                // Max epochs reached - trigger re-handshake
                return None;
            }
            self.replay_window.reset(seq + 1);
        }

        Some(ciphertext.to_vec()) // Placeholder
    }

    /// Encrypt outgoing packet
    pub fn process_outgoing(&mut self, _seq: u64, plaintext: &[u8]) -> Vec<u8> {
        // TODO: Encrypt with self.key_manager.tx_key()
        // let ciphertext = encrypt(plaintext, self.key_manager.tx_key());
        
        self.packets_processed += 1;
        plaintext.to_vec() // Placeholder
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
}

/// Session keys from handshake
#[derive(Clone)]
pub struct SessionKeys {
    pub session_id: [u8; 16],
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new();

        // First packet
        assert!(!window.is_replay(0));
        // Replay
        assert!(window.is_replay(0));
        // New packet
        assert!(!window.is_replay(1));
        // Old packet (replay)
        assert!(window.is_replay(0));
    }

    #[test]
    fn test_replay_window_out_of_order() {
        let mut window = ReplayWindow::new();

        // Receive packets out of order
        assert!(!window.is_replay(5));
        assert!(!window.is_replay(3));
        assert!(!window.is_replay(7));

        // Replay
        assert!(window.is_replay(5));

        // New packet far ahead - window shifts
        assert!(!window.is_replay(100));
        assert!(window.is_replay(5)); // Now too old
    }

    #[test]
    fn test_key_rotation() {
        let base = [0x42u8; 32];
        let mut manager = SessionKeyManager::new(base, 10);

        let key_0 = *manager.tx_key();

        assert!(manager.rotate());
        let key_1 = *manager.tx_key();

        // Keys should be different
        assert_ne!(key_0, key_1);

        // Epoch should increment
        assert_eq!(manager.epoch(), 1);
    }

    #[test]
    fn test_max_epochs() {
        let base = [0x42u8; 32];
        let mut manager = SessionKeyManager::new(base, 3);

        assert!(manager.rotate()); // epoch 1
        assert!(manager.rotate()); // epoch 2
        assert!(manager.rotate()); // epoch 3 - still true since epoch < max_epochs
        assert!(!manager.rotate()); // epoch 4 - max reached

        assert_eq!(manager.epoch(), 3);
    }

    #[test]
    fn test_needs_rotation() {
        let base = [0x42u8; 32];
        let manager = SessionKeyManager::new(base, 10);

        // Not needed initially
        assert!(!manager.needs_rotation(0));
        
        // Packet threshold reached
        assert!(manager.needs_rotation(1_000_001));
    }

    #[test]
    fn test_session_creation() {
        let session_keys = SessionKeys {
            session_id: [1u8; 16],
            tx_key: [2u8; 32],
            rx_key: [3u8; 32],
        };
        
        let session = SecureSession::new(session_keys, 5);
        assert_eq!(session.session_id(), &[1u8; 16]);
    }
}
