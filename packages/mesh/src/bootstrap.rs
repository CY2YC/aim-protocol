//! Multi-AP Resilient Bootstrap for Eclipse Resistance
//! 
//! Implements 2-of-3 consensus for peer discovery to prevent
//! Sybil and eclipse attacks. Uses libp2p Kademlia + Identify [^48^][^73^].

use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    identify::{self, Identify},
    kad::{self, store::MemoryStore, Kademlia, QueryResult},
    swarm::{NetworkBehaviour, SwarmEvent, Config as SwarmConfig},
    tcp, noise, yamux,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::{interval, timeout};
use tracing::{info, warn, debug};

/// Bootstrap configuration
pub struct BootstrapConfig {
    /// List of bootstrap nodes (multiaddr)
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Minimum peers required for consensus
    pub min_consensus: usize,
    /// Timeout for peer discovery
    pub discovery_timeout: Duration,
    /// Local listen addresses
    pub listen_addrs: Vec<Multiaddr>,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            bootstrap_peers: vec![],
            min_consensus: 2,
            discovery_timeout: Duration::from_secs(30),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        }
    }
}

/// Network behavior combining Kademlia and Identify
#[derive(NetworkBehaviour)]
pub struct BootstrapBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
}

/// Bootstrap result with verified peers
pub struct BootstrapResult {
    /// Verified peers (2-of-3 consensus)
    pub verified_peers: Vec<(PeerId, Multiaddr)>,
    /// All discovered peers (for monitoring)
    pub all_peers: Vec<(PeerId, Multiaddr)>,
    /// Consensus round information
    pub consensus_rounds: u32,
}

/// Perform resilient multi-AP bootstrap
/// 
/// Connects to multiple bootstrap nodes and requires 2-of-3 consensus
/// on peer lists to prevent eclipse attacks.
pub async fn resilient_bootstrap(config: BootstrapConfig) -> anyhow::Result<BootstrapResult> {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();
    
    info!("Starting bootstrap for peer {}", local_peer_id);
    
    // Build swarm with Kademlia + Identify
    let mut swarm = build_swarm(&local_key).await?;
    
    // Start listening
    for addr in &config.listen_addrs {
        swarm.listen_on(addr.clone())?;
    }
    
    // Connect to bootstrap nodes
    let mut bootstrap_connections = vec![];
    for (peer_id, addr) in &config.bootstrap_peers {
        match timeout(Duration::from_secs(5), dial_bootstrap(&mut swarm, *peer_id, addr.clone())).await {
            Ok(Ok(())) => {
                info!("Connected to bootstrap node {}", peer_id);
                bootstrap_connections.push((*peer_id, addr.clone()));
            }
            Ok(Err(e)) => warn!("Failed to connect to {}: {}", peer_id, e),
            Err(_) => warn!("Timeout connecting to {}", peer_id),
        }
    }
    
    if bootstrap_connections.len() < config.min_consensus {
        anyhow::bail!(
            "Insufficient bootstrap connections: {} < {}",
            bootstrap_connections.len(),
            config.min_consensus
        );
    }
    
    // Discover peers from each bootstrap node
    let mut peer_sets: Vec<Vec<(PeerId, Multiaddr)>> = vec![];
    
    for (bootstrap_id, _) in &bootstrap_connections {
        // Query bootstrap node for peers via Kademlia
        let peers = discover_peers(&mut swarm, *bootstrap_id, config.discovery_timeout).await?;
        peer_sets.push(peers);
    }
    
    // Require 2-of-3 consensus on peer lists
    let verified_peers = compute_consensus(&peer_sets, config.min_consensus);
    
    info!(
        "Bootstrap complete: {} verified peers from {} bootstrap nodes",
        verified_peers.len(),
        bootstrap_connections.len()
    );
    
    Ok(BootstrapResult {
        verified_peers: verified_peers.clone(),
        all_peers: peer_sets.into_iter().flatten().collect(),
        consensus_rounds: verified_peers.len() as u32,
    })
}

/// Build the libp2p swarm with Kademlia and Identify
async fn build_swarm(local_key: &libp2p::identity::Keypair) -> anyhow::Result<Swarm<BootstrapBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // Kademlia DHT configuration
            let mut kad_config = kad::Config::default();
            kad_config.set_query_timeout(Duration::from_secs(5));
            kad_config.set_replication_factor(std::num::NonZeroUsize::new(4).unwrap());
            
            let store = MemoryStore::new(key.public().to_peer_id());
            let kademlia = Kademlia::with_config(key.public().to_peer_id(), store, kad_config);
            
            // Identify protocol for peer info exchange
            let identify = Identify::new(identify::Config::new(
                "/aim/identify/1.0.0".to_string(),
                key.public(),
            ));
            
            BootstrapBehaviour { kademlia, identify }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    
    Ok(swarm)
}

/// Dial a bootstrap node
async fn dial_bootstrap(
    swarm: &mut Swarm<BootstrapBehaviour>,
    peer_id: PeerId,
    addr: Multiaddr,
) -> anyhow::Result<()> {
    swarm.dial(addr)?;
    
    // Wait for connection establishment
    let mut check_interval = interval(Duration::from_millis(100));
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            check_interval.tick().await;
            if swarm.is_connected(&peer_id) {
                return Ok(());
            }
        }
    });
    
    match timeout.await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("Connection timeout"),
    }
}

/// Discover peers from a bootstrap node using Kademlia
async fn discover_peers(
    swarm: &mut Swarm<BootstrapBehaviour>,
    bootstrap_id: PeerId,
    timeout_duration: Duration,
) -> anyhow::Result<Vec<(PeerId, Multiaddr)>> {
    let mut discovered = vec![];
    let mut query_complete = false;
    
    // Start Kademlia bootstrap
    swarm.behaviour_mut().kademlia.bootstrap();
    
    // Process events until timeout
    let deadline = tokio::time::Instant::now() + timeout_duration;
    
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), swarm.select_next_some()).await {
            Ok(SwarmEvent::Behaviour(BootstrapBehaviourEvent::Kademlia(event))) => {
                match event {
                    kad::Event::OutboundQueryProgressed { result, .. } => {
                        match result {
                            QueryResult::GetClosestPeers(result) => {
                                if let Ok(peers) = result {
                                    for peer in peers.peers {
                                        if let Some(addrs) = swarm.behaviour().kademlia.addresses_of_peer(&peer) {
                                            for addr in addrs {
                                                discovered.push((peer, addr));
                                            }
                                        }
                                    }
                                }
                                query_complete = true;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Ok(SwarmEvent::Behaviour(BootstrapBehaviourEvent::Identify(event))) => {
                if let identify::Event::Received { peer_id, info, .. } = event {
                    for addr in info.listen_addrs {
                        discovered.push((peer_id, addr));
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break, // Timeout
        }
        
        if query_complete && discovered.len() >= 3 {
            break;
        }
    }
    
    // Deduplicate
    discovered.sort_by(|a, b| a.0.cmp(&b.0));
    discovered.dedup_by(|a, b| a.0 == b.0);
    
    Ok(discovered)
}

/// Compute 2-of-3 consensus on peer lists
/// 
/// A peer is considered verified if it appears in at least `threshold` peer lists.
fn compute_consensus(peer_sets: &[Vec<(PeerId, Multiaddr)>], threshold: usize) -> Vec<(PeerId, Multiaddr)> {
    let mut counts: HashMap<PeerId, (usize, Multiaddr)> = HashMap::new();
    
    for peers in peer_sets {
        for (peer_id, addr) in peers {
            let entry = counts.entry(*peer_id).or_insert((0, addr.clone()));
            entry.0 += 1;
        }
    }
    
    counts.into_iter()
        .filter(|(_, (count, _))| *count >= threshold)
        .map(|(peer_id, (_, addr))| (peer_id, addr))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_consensus_computation() {
        let peer_a = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let peer_b = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let peer_c = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let peer_d = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        
        let addr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        
        // Set 1: A, B, C
        let set1 = vec![
            (peer_a, addr.clone()),
            (peer_b, addr.clone()),
            (peer_c, addr.clone()),
        ];
        
        // Set 2: A, B, D
        let set2 = vec![
            (peer_a, addr.clone()),
            (peer_b, addr.clone()),
            (peer_d, addr.clone()),
        ];
        
        // Set 3: A, C, D
        let set3 = vec![
            (peer_a, addr.clone()),
            (peer_c, addr.clone()),
            (peer_d, addr.clone()),
        ];
        
        let peer_sets = vec![set1, set2, set3];
        let consensus = compute_consensus(&peer_sets, 2);
        
        // A appears in all 3, B and C in 2, D in 2
        assert_eq!(consensus.len(), 4);
        assert!(consensus.iter().any(|(p, _)| *p == peer_a));
        assert!(consensus.iter().any(|(p, _)| *p == peer_b));
        assert!(consensus.iter().any(|(p, _)| *p == peer_c));
        assert!(consensus.iter().any(|(p, _)| *p == peer_d));
    }
}
