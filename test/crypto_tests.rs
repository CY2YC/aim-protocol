//! Cryptographic primitive tests

use aim_core::crypto::{dilithium, kyber, kdf, hybrid};
use rand::rngs::OsRng;

#[test]
fn test_ml_dsa_key_generation() {
    let mut rng = OsRng;
    let sk = dilithium::SecretKey::generate(&mut rng);
    let pk = sk.verifying_key();
    
    // Verify public key is valid
    let pk_bytes = pk.to_bytes();
    assert_eq!(pk_bytes.len(), dilithium::PUBLIC_KEY_LENGTH);
    
    // Verify roundtrip serialization
    let pk2 = dilithium::PublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk.to_bytes(), pk2.to_bytes());
}

#[test]
fn test_ml_dsa_sign_verify() {
    let mut rng = OsRng;
    let sk = dilithium::SecretKey::generate(&mut rng);
    let pk = sk.verifying_key();
    
    let msg = b"test message for signing";
    let ctx = b"test-context-v1";
    
    let sig = sk.sign(msg, ctx);
    
    // Valid signature should verify
    assert!(pk.verify(msg, ctx, &sig));
    
    // Wrong message should fail
    assert!(!pk.verify(b"wrong message", ctx, &sig));
    
    // Wrong context should fail
    assert!(!pk.verify(msg, b"wrong-context", &sig));
}

#[test]
fn test_ml_kem_encaps_decaps() {
    let mut rng = OsRng;
    let (pk, sk) = kyber::SecretKey::generate(&mut rng);
    
    let (ct, ss1) = pk.encapsulate(&mut rng);
    let ss2 = sk.decapsulate(&ct);
    
    // Shared secrets should match
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    
    // Ciphertext should be valid size
    assert_eq!(ct.to_bytes().len(), kyber::CIPHERTEXT_LENGTH);
}

#[test]
fn test_hkdf_key_derivation() {
    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"application info";
    
    let key1 = kdf::derive_key(ikm, salt, info);
    let key2 = kdf::derive_key(ikm, salt, info);
    
    // Deterministic derivation
    assert_eq!(key1, key2);
    
    // Different info should produce different key
    let key3 = kdf::derive_key(ikm, salt, b"different info");
    assert_ne!(key1, key3);
}

#[test]
fn test_hybrid_kem() {
    let mut rng = OsRng;
    
    let (pk, sk) = hybrid::HybridKem::generate(&mut rng);
    let (ct, ss1) = hybrid::HybridKem::encapsulate(&pk, &mut rng);
    
    // Note: In real usage, the secret would be used for key derivation
    // This test just verifies the encapsulation works
    assert_eq!(ss1.len(), 32);
}

#[test]
fn test_key_serialization_roundtrip() {
    let mut rng = OsRng;
    
    // ML-DSA
    let sk = dilithium::SecretKey::generate(&mut rng);
    let pk = sk.verifying_key();
    let sig = sk.sign(b"test", b"ctx");
    
    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();
    
    let pk2 = dilithium::PublicKey::from_bytes(&pk_bytes).unwrap();
    let sig2 = dilithium::SignatureBytes::from_bytes(&sig_bytes).unwrap();
    
    assert!(pk2.verify(b"test", b"ctx", &sig2));
    
    // ML-KEM
    let (pk_kem, sk_kem) = kyber::SecretKey::generate(&mut rng);
    let pk_kem_bytes = pk_kem.to_bytes();
    let pk_kem2 = kyber::PublicKey::from_bytes(&pk_kem_bytes).unwrap();
    
    let (ct, ss1) = pk_kem2.encapsulate(&mut rng);
    let ss2 = sk_kem.decapsulate(&ct);
    
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
}

#[test]
fn test_signature_malleability_resistance() {
    let mut rng = OsRng;
    let sk = dilithium::SecretKey::generate(&mut rng);
    let pk = sk.verifying_key();
    
    let msg = b"important message";
    let sig = sk.sign(msg, b"ctx");
    
    // Attempt to mutate signature (should fail verification)
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0xFF; // Flip bits
    let mutated_sig = dilithium::SignatureBytes::from_bytes(&sig_bytes).unwrap();
    
    assert!(!pk.verify(msg, b"ctx", &mutated_sig));
}
