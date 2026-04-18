//! AIM Protocol Core Library
//! 
//! Post-quantum cryptographic primitives, identity management,
//! secure sessions, and revocation.

pub mod crypto;
pub mod handshake;
pub mod identity;
pub mod revocation;
pub mod session;

// Public re-exports (matches ARCHITECTURE.md clean API requirement)
pub use crypto::*;
pub use handshake::Handshake;
pub use identity::{Identity, ShamirShare}; // once implemented
pub use session::{Session, ReplayWindow};
pub use revocation::RevocationStore;