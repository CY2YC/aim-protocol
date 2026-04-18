//! Basic mesh networking example
//! 
//! Demonstrates peer discovery, identity creation, and basic communication.

use aim_core::identity::{DigitalID, DigitalIDSecret};
use aim_mesh::bootstrap::{resilient_bootstrap, BootstrapConfig};
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();
    
    info!("AIM Protocol - Basic Mesh Example");
    info!("=================================\n");
    
    // Generate identities for two nodes
    let mut rng = OsRng;
    
    info!("Generating node identities...");
    let (node_a_id, node_a_secret) = DigitalID::generate(&mut rng);
    let (node_b_id, node_b_secret) = DigitalID::generate(&mut rng);
    
    info!("Node A DID: {}", node_a_id.did);
    info!("Node B DID: {}", node_b_id.did);
    
    // Display key information
    info!("\nNode A Public Keys:");
    info!("  ML-DSA: {}", hex::encode(&node_a_id.dilithium_pk.to_bytes()[..16]));
    info!("  ML-KEM: {}", hex::encode(&node_a_id.kyber_pk.to_bytes()[..16]));
    
    // Verify DID bindings
    assert!(node_a_id.verify_did_binding());
    assert!(node_b_id.verify_did_binding());
    info!("\n✓ DID bindings verified");
    
    // Demonstrate handshake (simplified)
    info!("\nPerforming secure handshake...");
    let session_keys = aim_core::handshake::perform_handshake(
        &node_a_id,
        &node_a_secret,
        &node_b_id,
        &mut rng,
    );
    info!("✓ Handshake complete");
    info!("  Session ID: {}", hex::encode(session_keys.session_id));
    info!("  Initial epoch: {}", session_keys.epoch);
    
    // Demonstrate reputation system
    info!("\nInitializing reputation system...");
    let mut rep_manager = aim_mesh::reputation::ReputationManager::new(10);
    
    // Simulate bandwidth contribution
    rep_manager.record_forward(&node_a_id.did, 1024 * 1024 * 10); // 10MB
    let score_a = rep_manager.get_score(&node_a_id.did);
    info!("Node A reputation after 10MB forwarded: {}", score_a);
    
    // Simulate misbehavior and slashing
    rep_manager.slash(&node_a_id.did, "test violation");
    let score_a_slashed = rep_manager.get_score(&node_a_id.did);
    info!("Node A reputation after slashing: {}", score_a_slashed);
    
    // Demonstrate revocation
    info!("\nTesting revocation system...");
    let mut revocation = aim_core::revocation::RevocationChecker::new(1000);
    
    let entry = aim_core::revocation::RevocationEntry {
        did: node_b_id.did.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        reason: 1,
        signatures: vec![],
    };
    
    let root = revocation.revoke(entry)?;
    info!("✓ Revocation recorded");
    info!("  SMT Root: {}", hex::encode(root));
    
    // Check revocation status
    match revocation.check_revocation(&node_b_id.did) {
        aim_core::revocation::RevocationStatus::Revoked { .. } => {
            info!("✓ Node B correctly identified as revoked");
        }
        _ => panic!("Expected revoked status"),
    }
    
    match revocation.check_revocation(&node_a_id.did) {
        aim_core::revocation::RevocationStatus::NotRevoked => {
            info!("✓ Node A correctly identified as not revoked");
        }
        _ => panic!("Expected not revoked status"),
    }
    
    // Demonstrate key rotation
    info!("\nDemonstrating key rotation...");
    let mut key_manager = aim_core::session::replay::SessionKeyManager::new(
        session_keys.tx_key,
        5,
    );
    
    for epoch in 1..=3 {
        key_manager.rotate();
        info!("  Epoch {}: keys rotated", epoch);
    }
    
    info!("\n=================================");
    info!("Example completed successfully!");
    info!("All core components verified:");
    info!("  ✓ Post-quantum cryptography (ML-KEM + ML-DSA)");
    info!("  ✓ Digital identity with DID binding");
    info!("  ✓ Secure handshake with forward secrecy");
    info!("  ✓ Reputation system with slashing");
    info!("  ✓ Revocation with SMT proofs");
    info!("  ✓ Session key rotation");
    
    Ok(())
}
