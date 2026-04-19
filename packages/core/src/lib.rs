//! AIM Protocol Core Library
//!
//! Post-quantum cryptographic primitives, identity management,
//! secure sessions, and revocation.

pub mod crypto;
pub mod handshake;
pub mod identity;
pub mod revocation;
pub mod session;

// Re-exports for ergonomic API
pub use crypto::{dilithium, hybrid, kdf, kyber};
pub use handshake::{Handshake, HandshakeState, perform_handshake};
pub use identity::{DigitalID, DigitalIDSecret, RecoveryShare};
pub use revocation::{RevocationChecker, RevocationEntry};
pub use session::{ReplayWindow, SecureSession, SessionKeyManager, SessionKeys};
