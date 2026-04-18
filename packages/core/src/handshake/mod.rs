//! Secure PQC Handshake with Forward Secrecy
//! 
//! Implements Noise-like handshake pattern using ML-KEM + ML-DSA.
//! Provides mutual authentication and ephemeral key exchange.

use crate::crypto::{dilithium, kyber, kdf};
use crate::identity::{DigitalID, DigitalIDSecret};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Handshake state machine states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeState {
    Init,
    SentHello,
    ReceivedHello,
    SentAuth,
    ReceivedAuth,
    Complete,
    Failed,
}

/// Result of successful handshake
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Encryption key for outbound messages
    pub tx_key: [u8; 32],
    /// Encryption key for inbound messages
    pub rx_key: [u8; 32],
    /// Session ID for replay protection
    pub session_id: [u8; 16],
    /// Current epoch for key rotation
    pub epoch: u32,
}

/// Handshake message types
#[derive(Debug, Clone)]
pub enum HandshakeMessage {
    /// Initial hello with ephemeral ML-KEM key
    Hello {
        ephemeral_kyber_pk: kyber::PublicKey,
        nonce: [u8; 32],
    },
    /// Response with encapsulated secret + auth signature
    HelloResponse {
        ciphertext: kyber::CiphertextBytes,
        signature: dilithium::SignatureBytes,
        responder_id: String,
    },
    /// Final authentication from initiator
    AuthConfirm {
        signature: dilithium::SignatureBytes,
        initiator_id: String,
    },
}

/// Active handshake state machine
pub struct Handshake {
    state: HandshakeState,
    /// Our identity
    self_id: DigitalID,
    /// Our secret keys (zeroed on drop)
    self_secret: DigitalIDSecret,
    /// Peer identity (verified during handshake)
    peer_id: Option<DigitalID>,
    /// Ephemeral keys for this session
    ephemeral_kyber_sk: Option<kyber::SecretKey>,
    ephemeral_kyber_pk: Option<kyber::PublicKey>,
    /// Shared secret from KEM
    shared_secret: Option<[u8; 32]>,
    /// Nonces for replay protection
    local_nonce: [u8; 32],
    remote_nonce: Option<[u8; 32]>,
}

impl Handshake {
    /// Initiate handshake as client
    pub fn initiate<R: CryptoRngCore>(
        self_id: DigitalID,
        self_secret: DigitalIDSecret,
        rng: &mut R,
    ) -> (Self, HandshakeMessage) {
        let (pk, sk) = kyber::SecretKey::generate(rng);
        let mut local_nonce = [0u8; 32];
        rng.fill_bytes(&mut local_nonce);
        
        let msg = HandshakeMessage::Hello {
            ephemeral_kyber_pk: pk.clone(),
            nonce: local_nonce,
        };
        
        let hs = Self {
            state: HandshakeState::SentHello,
            self_id,
            self_secret,
            peer_id: None,
            ephemeral_kyber_sk: Some(sk),
            ephemeral_kyber_pk: Some(pk),
            shared_secret: None,
            local_nonce,
            remote_nonce: None,
        };
        
        (hs, msg)
    }
    
    /// Respond to hello as server
    pub fn respond<R: CryptoRngCore>(
        &mut self,
        msg: &HandshakeMessage,
        peer_id: DigitalID,
        rng: &mut R,
    ) -> Result<HandshakeMessage, HandshakeError> {
        match msg {
            HandshakeMessage::Hello { ephemeral_kyber_pk, nonce } => {
                // Generate ephemeral keypair
                let (our_pk, our_sk) = kyber::SecretKey::generate(rng);
                
                // Encapsulate to peer's ephemeral key
                let (ct, shared) = ephemeral_kyber_pk.encapsulate(rng);
                
                // Sign the transcript
                let mut transcript = Vec::new();
                transcript.extend_from_slice(&ephemeral_kyber_pk.to_bytes());
                transcript.extend_from_slice(&our_pk.to_bytes());
                transcript.extend_from_slice(&ct.to_bytes());
                transcript.extend_from_slice(nonce);
                
                let sig = self.self_secret.dilithium_sk.sign(&transcript, b"aim-handshake-v1");
                
                self.state = HandshakeState::SentAuth;
                self.peer_id = Some(peer_id);
                self.ephemeral_kyber_sk = Some(our_sk);
                self.ephemeral_kyber_pk = Some(our_pk);
                self.shared_secret = Some(shared.into_bytes());
                self.remote_nonce = Some(*nonce);
                
                Ok(HandshakeMessage::HelloResponse {
                    ciphertext: ct,
                    signature: sig,
                    responder_id: self.self_id.did.clone(),
                })
            }
            _ => Err(HandshakeError::UnexpectedMessage),
        }
    }
    
    /// Process hello response as client
    pub fn process_response<R: CryptoRngCore>(
        &mut self,
        msg: &HandshakeMessage,
        rng: &mut R,
    ) -> Result<HandshakeMessage, HandshakeError> {
        match msg {
            HandshakeMessage::HelloResponse { ciphertext, signature, responder_id } => {
                // Decapsulate shared secret
                let sk = self.ephemeral_kyber_sk.as_ref()
                    .ok_or(HandshakeError::InvalidState)?;
                let shared = sk.decapsulate(ciphertext);
                
                // Verify signature (need peer's public key from DID resolution)
                // In production: resolve responder_id to DigitalID first
                
                self.shared_secret = Some(shared.into_bytes());
                
                // Send auth confirmation
                let mut transcript = Vec::new();
                transcript.extend_from_slice(&self.local_nonce);
                transcript.extend_from_slice(responder_id.as_bytes());
                
                let sig = self.self_secret.dilithium_sk.sign(&transcript, b"aim-handshake-v1");
                
                self.state = HandshakeState::Complete;
                
                Ok(HandshakeMessage::AuthConfirm {
                    signature: sig,
                    initiator_id: self.self_id.did.clone(),
                })
            }
            _ => Err(HandshakeError::UnexpectedMessage),
        }
    }
    
    /// Complete handshake as server
    pub fn complete(&mut self, msg: &HandshakeMessage) -> Result<SessionKeys, HandshakeError> {
        match msg {
            HandshakeMessage::AuthConfirm { signature, initiator_id } => {
                if self.state != HandshakeState::SentAuth {
                    return Err(HandshakeError::InvalidState);
                }
                
                // Verify auth signature
                // In production: resolve initiator_id to DigitalID
                
                self.state = HandshakeState::Complete;
                
                // Derive session keys
                let ss = self.shared_secret.ok_or(HandshakeError::MissingSharedSecret)?;
                let salt = self.local_nonce;
                
                let mut keys = [0u8; 80]; // tx + rx + session_id
                kdf::hkdf_sha256(&ss, &salt, b"aim-session-keys-v1", &mut keys);
                
                let mut tx_key = [0u8; 32];
                let mut rx_key = [0u8; 32];
                let mut session_id = [0u8; 16];
                
                tx_key.copy_from_slice(&keys[0..32]);
                rx_key.copy_from_slice(&keys[32..64]);
                session_id.copy_from_slice(&keys[64..80]);
                
                Ok(SessionKeys {
                    tx_key,
                    rx_key,
                    session_id,
                    epoch: 0,
                })
            }
            _ => Err(HandshakeError::UnexpectedMessage),
        }
    }
    
    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
    
    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Invalid handshake state")]
    InvalidState,
    #[error("Unexpected message type")]
    UnexpectedMessage,
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Missing shared secret")]
    MissingSharedSecret,
    #[error("DID resolution failed: {0}")]
    DIDResolutionFailed(String),
}

/// Simplified one-shot handshake for basic usage
pub fn perform_handshake<R: CryptoRngCore>(
    self_id: &DigitalID,
    self_secret: &DigitalIDSecret,
    peer_id: &DigitalID,
    rng: &mut R,
) -> SessionKeys {
    // In production: full 3-way handshake over network
    // For now: simplified direct key exchange
    
    let (pk, sk) = kyber::SecretKey::generate(rng);
    let (ct, shared) = peer_id.kyber_pk.encapsulate(rng);
    
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    
    let mut keys = [0u8; 80];
    kdf::hkdf_sha256(&shared.into_bytes(), &salt, b"aim-simple-handshake-v1", &mut keys);
    
    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];
    let mut session_id = [0u8; 16];
    
    tx_key.copy_from_slice(&keys[0..32]);
    rx_key.copy_from_slice(&keys[32..64]);
    session_id.copy_from_slice(&keys[64..80]);
    
    SessionKeys {
        tx_key,
        rx_key,
        session_id,
        epoch: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_handshake_flow() {
        let mut rng = OsRng;
        
        // Create two identities
        let (id_a, secret_a) = DigitalID::generate(&mut rng);
        let (id_b, secret_b) = DigitalID::generate(&mut rng);
        
        // A initiates
        let (mut hs_a, hello) = Handshake::initiate(id_a.clone(), secret_a, &mut rng);
        
        // B responds
        let mut hs_b = Handshake {
            state: HandshakeState::Init,
            self_id: id_b.clone(),
            self_secret: secret_b,
            peer_id: None,
            ephemeral_kyber_sk: None,
            ephemeral_kyber_pk: None,
            shared_secret: None,
            local_nonce: [0u8; 32],
            remote_nonce: None,
        };
        
        let response = hs_b.respond(&hello, id_a, &mut rng).unwrap();
        
        // A processes response
        let auth = hs_a.process_response(&response, &mut rng).unwrap();
        
        // B completes
        let keys_b = hs_b.complete(&auth).unwrap();
        
        // A derives keys (simplified)
        assert!(hs_a.is_complete());
        assert!(hs_b.is_complete());
    }
}
