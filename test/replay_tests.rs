//! Replay protection and key rotation tests

use aim_core::session::replay::{ReplayWindow, SessionKeyManager, SecureSession};
use aim_core::handshake::SessionKeys;

#[test]
fn test_replay_window_basic() {
    let mut window = ReplayWindow::new();
    
    // First packet at seq 0
    assert!(!window.is_replay(0));
    
    // Same seq is replay
    assert!(window.is_replay(0));
    
    // New packet at seq 1
    assert!(!window.is_replay(1));
    
    // Old packet is replay
    assert!(window.is_replay(0));
}

#[test]
fn test_replay_window_out_of_order() {
    let mut window = ReplayWindow::new();
    
    // Receive packets out of order within window
    assert!(!window.is_replay(5));
    assert!(!window.is_replay(3));
    assert!(!window.is_replay(7));
    
    // Replay detection
    assert!(window.is_replay(5));
    assert!(window.is_replay(3));
    
    // New packet
    assert!(!window.is_replay(6));
}

#[test]
fn test_replay_window_advance() {
    let mut window = ReplayWindow::new();
    
    // Fill window
    for i in 0..64 {
        assert!(!window.is_replay(i));
    }
    
    // Window is full, old packets are replays
    assert!(window.is_replay(0));
    
    // New packet advances window
    assert!(!window.is_replay(64));
    
    // Very old packet still replay
    assert!(window.is_replay(0));
}

#[test]
fn test_session_key_rotation() {
    let base_key = [0x42u8; 32];
    let mut manager = SessionKeyManager::new(base_key, 10);
    
    let key_0 = *manager.tx_key();
    
    // Rotate to epoch 1
    assert!(manager.rotate());
    let key_1 = *manager.tx_key();
    
    // Keys should be different
    assert_ne!(key_0, key_1);
    
    // Rotate again
    assert!(manager.rotate());
    let key_2 = *manager.tx_key();
    
    assert_ne!(key_1, key_2);
    assert_eq!(manager.epoch(), 2);
}

#[test]
fn test_max_epochs_limit() {
    let base_key = [0x42u8; 32];
    let mut manager = SessionKeyManager::new(base_key, 3);
    
    // Rotate to max
    assert!(manager.rotate()); // 1
    assert!(manager.rotate()); // 2
    assert!(!manager.rotate()); // 3 - max reached
    
    assert_eq!(manager.epoch(), 3);
}

#[test]
fn test_key_derivation_consistency() {
    let base_key = [0x42u8; 32];
    let manager1 = SessionKeyManager::new(base_key, 10);
    
    let mut manager2 = SessionKeyManager::new(base_key, 10);
    manager2.rotate();
    
    // Same base, different epochs = different keys
    assert_ne!(manager1.tx_key(), manager2.tx_key());
    
    // But same epoch should derive same keys
    let manager3 = SessionKeyManager::new(base_key, 10);
    assert_eq!(manager1.tx_key(), manager3.tx_key());
}

#[test]
fn test_secure_session_creation() {
    let session_keys = SessionKeys {
        tx_key: [0x01u8; 32],
        rx_key: [0x02u8; 32],
        session_id: [0x03u8; 16],
        epoch: 0,
    };
    
    let session = SecureSession::new(session_keys, 10);
    
    assert_eq!(session.session_id(), &[0x03u8; 16]);
}

#[test]
fn test_replay_window_reset() {
    let mut window = ReplayWindow::new();
    
    // Add some packets
    window.is_replay(10);
    window.is_replay(11);
    window.is_replay(12);
    
    assert_eq!(window.base_seq(), 0);
    
    // Reset to new base
    window.reset(100);
    
    assert_eq!(window.base_seq(), 100);
    
    // Old packets are now replays
    assert!(window.is_replay(10));
    
    // New packets at new base
    assert!(!window.is_replay(100));
}

#[test]
fn test_packet_processing_simulation() {
    let session_keys = SessionKeys {
        tx_key: [0x01u8; 32],
        rx_key: [0x02u8; 32],
        session_id: [0x03u8; 16],
        epoch: 0,
    };
    
    let mut session = SecureSession::new(session_keys, 10);
    
    // Simulate receiving packets
    let result1 = session.process_incoming(0, b"packet1");
    assert!(result1.is_some());
    
    // Replay should be rejected
    let result2 = session.process_incoming(0, b"packet1");
    assert!(result2.is_none());
    
    // New packet should pass
    let result3 = session.process_incoming(1, b"packet2");
    assert!(result3.is_some());
}
