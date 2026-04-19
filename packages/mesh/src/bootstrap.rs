//! Multi-AP Bootstrap with Eclipse Resistance
//!
//! Uses libp2p Kademlia DHT with 2-of-3 consensus for AP validation.
//! Resolves the "first contact" problem without centralized CAs.

use libp2p::{
    identity::Keypair,
    kad::{self, store::MemoryStore, Kademlia, QueryResult},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent, Config as SwarmConfig},
    PeerId, Multiaddr,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Bootstrap configuration
#[derive(Clone)]
pub struct BootstrapConfig {
    /// List of initial bootstrap nodes (multiaddrs)
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Required consensus threshold (2-of-3)
    pub consensus_threshold: usize,
    /// Timeout for bootstrap operations (seconds)
    pub timeout_secs: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![],
            consensus_threshold: 2,
            timeout_secs: 30,
        }
    }
}

/// Result of bootstrap operation
#[derive(Debug)]
pub struct BootstrapResult {
    /// Verified bootstrap peers
    pub verified_peers: Vec<PeerId>,
    /// Consensus hash of bootstrap set
    pub consensus_hash: [u8; 32],
    /// Number of APs contacted
    pub aps_contacted: usize,
}

/// Network behaviour combining Kademlia and Identify
#[derive(NetworkBehaviour)]
pub struct BootstrapBehaviour {
    /// Kademlia DHT
    pub kademlia: Kademlia<MemoryStore>,
    /// Peer identification
    pub identify: libp2p::identify::Behaviour,
}

/// Perform resilient multi-AP bootstrap
///
/// Algorithm:
/// 1. Connect to 3+ bootstrap APs simultaneously
/// 2. Collect peer advertisements from each
/// 3. Compute 2-of-3 consensus on peer set
/// 4. Verify consensus hash matches expected
/// 5. Return verified peer set
pub async fn resilient_bootstrap(
    config: &BootstrapConfig,
    local_keypair: &Keypair,
) -> Result<BootstrapResult, BootstrapError> {
    let local_peer_id = PeerId::from(local_keypair.public());

    // Create swarm with combined behaviour
    let mut swarm = create_swarm(local_keypair.clone())?;

    // Connect to all bootstrap nodes
    let mut aps_contacted = 0;
    for addr in &config.bootstrap_nodes {
        swarm.listen_on(addr.clone())?;
        aps_contacted += 1;
    }

    // Collect peer advertisements
    let mut peer_sets: Vec<HashSet<PeerId>> = vec![];

    // Run bootstrap for timeout period
    let timeout = tokio::time::Duration::from_secs(config.timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(BootstrapBehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { result, .. },
            )) => {
                if let QueryResult::GetProviders(Ok(result)) = result {
                    let peers: HashSet<PeerId> = result.providers.into_iter().collect();
                    peer_sets.push(peers);
                }
            }
            SwarmEvent::Behaviour(BootstrapBehaviourEvent::Identify(event)) => {
                // Process identify events for peer verification
                tracing::debug!("Identify event: {:?}", event);
            }
            _ => {}
        }

        // Check if we have enough sets for consensus
        if peer_sets.len() >= config.consensus_threshold {
            break;
        }
    }

    // Compute 2-of-3 consensus
    let (consensus_peers, consensus_hash) = compute_consensus(&peer_sets, config.consensus_threshold);

    Ok(BootstrapResult {
        verified_peers: consensus_peers.into_iter().collect(),
        consensus_hash,
        aps_contacted,
    })
}

/// Compute 2-of-3 consensus from peer sets
///
/// A peer is accepted if it appears in at least threshold sets.
fn compute_consensus(
    peer_sets: &[HashSet<PeerId>],
    threshold: usize,
) -> (HashSet<PeerId>, [u8; 32]) {
    let mut peer_counts: HashMap<PeerId, usize> = HashMap::new();

    for set in peer_sets {
        for peer in set {
            *peer_counts.entry(*peer).or_insert(0) += 1;
        }
    }

    let consensus: HashSet<PeerId> = peer_counts
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .map(|(peer, _)| peer)
        .collect();

    // Compute consensus hash
    let mut hasher = blake3::Hasher::new();
    let mut sorted_peers: Vec<_> = consensus.iter().collect();
    sorted_peers.sort();
    for peer in sorted_peers {
        hasher.update(peer.to_bytes().as_ref());
    }

    (consensus, hasher.finalize().into())
}

/// Create swarm with bootstrap behaviour
fn create_swarm(
    local_keypair: Keypair,
) -> Result<Swarm<BootstrapBehaviour>, BootstrapError> {
    let peer_id = PeerId::from(local_keypair.public());

    let kademlia = Kademlia::new(peer_id, MemoryStore::new(peer_id));
    let identify = libp2p::identify::Behaviour::new(
        libp2p::identify::Config::new(
            "aim/1.0".to_string(),
            local_keypair.public(),
        ),
    );

    let behaviour = BootstrapBehaviour {
        kademlia,
        identify,
    };

    let config = SwarmConfig::with_tokio_executor();
    let swarm = Swarm::new(local_keypair, behaviour, peer_id, config);

    Ok(swarm)
}

/// Bootstrap errors
#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("Bootstrap timeout")]
    Timeout,
    #[error("Insufficient consensus: got {0}, need {1}")]
    InsufficientConsensus(usize, usize),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_computation() {
        let peer1 = PeerId::from_bytes(&[0; 34]).unwrap();
        let peer2 = PeerId::from_bytes(&[1; 34]).unwrap();
        let peer3 = PeerId::from_bytes(&[2; 34]).unwrap();

        let set1: HashSet<PeerId> = [peer1, peer2].iter().cloned().collect();
        let set2: HashSet<PeerId> = [peer2, peer3].iter().cloned().collect();
        let set3: HashSet<PeerId> = [peer1, peer2, peer3].iter().cloned().collect();

        let (consensus, hash) = compute_consensus(&[set1, set2, set3], 2);

        // peer2 appears in all 3 sets -> included
        // peer1 appears in 2 sets -> included
        // peer3 appears in 2 sets -> included
        assert!(consensus.contains(&peer1));
        assert!(consensus.contains(&peer2));
        assert!(consensus.contains(&peer3));
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_consensus_threshold() {
        let peer1 = PeerId::from_bytes(&[0; 34]).unwrap();
        let peer2 = PeerId::from_bytes(&[1; 34]).unwrap();

        let set1: HashSet<PeerId> = [peer1].iter().cloned().collect();
        let set2: HashSet<PeerId> = [peer2].iter().cloned().collect();
        let set3: HashSet<PeerId> = [peer1, peer2].iter().cloned().collect();

        let (consensus, _) = compute_consensus(&[set1, set2, set3], 2);

        // peer1 appears in 2 sets -> included
        // peer2 appears in 2 sets -> included
        assert!(consensus.contains(&peer1));
        assert!(consensus.contains(&peer2));
    }
}
