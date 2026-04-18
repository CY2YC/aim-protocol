//! AIM Protocol Mesh Networking
//!
//! libp2p-based peer discovery, reputation system, and multi-AP bootstrap.

pub mod bootstrap;
pub mod reputation;

pub use bootstrap::{BootstrapBehaviour, BootstrapConfig, BootstrapResult, resilient_bootstrap};
pub use reputation::{ReputationEntry, ReputationManager, calculate_reputation_update};
