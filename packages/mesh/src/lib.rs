//! AIM Protocol Mesh Networking
//!
//! libp2p-based peer discovery, reputation system, and multi-AP bootstrap.

pub mod bootstrap;
pub mod reputation;

pub use bootstrap::{resilient_bootstrap, BootstrapConfig, BootstrapResult, BootstrapBehaviour};
pub use reputation::{ReputationManager, ReputationEntry, calculate_reputation_update};