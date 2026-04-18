# AIM Protocol Cryptographic Specification

## Overview

This document specifies the cryptographic primitives and protocols used in the AIM (Authenticated Identity Mesh) Protocol. All algorithms are NIST-standardized and implemented using formally verified or production-ready Rust crates.

## Post-Quantum Primitives

### ML-KEM-768 (FIPS 203) [^79^]

**Purpose**: Key Encapsulation Mechanism (KEM) for secure key exchange

**Parameters**:
- Security Level: NIST Category 3 (AES-192 equivalent)
- Public Key Size: 1,184 bytes
- Secret Key Size: 2,400 bytes
- Ciphertext Size: 1,088 bytes
- Shared Secret: 32 bytes

**Implementation**: `ml-kem` crate (RustCrypto) [^19^]

**Usage**:
```rust
// Key generation
let (pk, sk) = ml_kem::SecretKey::generate(&mut rng);

// Encapsulation
let (ct, ss) = pk.encapsulate(&mut rng);

// Decapsulation
let ss = sk.decapsulate(&ct);
```

**Security Basis**: Module Learning With Errors (MLWE) problem - no known quantum or classical polynomial-time algorithm [^79^]

### ML-DSA-65 (FIPS 204) [^83^]

**Purpose**: Digital signatures for authentication and non-repudiation

**Parameters**:
- Security Level: NIST Category 3 (~192-bit security)
- Public Key Size: 1,952 bytes
- Secret Key Size: 4,032 bytes
- Signature Size: 3,293 bytes

**Implementation**: `ml-dsa` crate (RustCrypto) [^19^]

**Usage**:
```rust
// Key generation
let sk = ml_dsa::SecretKey::generate(&mut rng);
let pk = sk.verifying_key();

// Signing
let sig = sk.sign(msg, context);

// Verification
assert!(pk.verify(msg, context, &sig));
```

**Security Basis**: Module-Lattice-based hardness assumptions [^83^]

## Hybrid Constructions

### X25519 + ML-KEM-768

**Purpose**: Defense-in-depth combining classical and post-quantum security

**Algorithm**:
1. Generate ephemeral X25519 keypair
2. Generate ephemeral ML-KEM keypair
3. X25519 ECDH: `ss_x = X25519(eph_sk, peer_pk)`
4. ML-KEM encaps: `(ct, ss_k) = ML-KEM.encaps(peer_pk)`
5. Combined: `ss = HKDF(ss_x || ss_k, salt, "aim-hybrid-v1")`

**Rationale**: If either X25519 or ML-KEM is broken, the other provides security

## Key Derivation

### HKDF-SHA256

**Purpose**: Derive multiple keys from shared secret

**Parameters**:
- Hash Function: SHA2-256
- Salt: Random or context-specific
- Info: Application-specific context string

**Usage**:
```rust
let mut keys = [0u8; 80]; // tx + rx + session_id
hkdf::hkdf_sha256(&shared_secret, &salt, b"aim-session-v1", &mut keys);
```

## Identity Binding

### DID Generation

**Format**: `did:aim:<fingerprint>`

**Fingerprint Computation**:
```
fingerprint = SHA256("did:aim:v1:" || ML-DSA-PK || ML-KEM-PK)
did = "did:aim:" || hex(fingerprint[0..16])
```

**Verification**: Recompute fingerprint from public keys and compare

## Session Protocol

### Handshake (Noise-inspired)

**Messages**:
1. **Hello**: `eph_kyber_pk || nonce`
2. **HelloResponse**: `ciphertext || sig || responder_did`
3. **AuthConfirm**: `sig || initiator_did`

**Key Derivation**:
```
shared_secret = ML-KEM.decaps(sk, ct)
session_keys = HKDF(shared_secret, transcript_hash, "aim-handshake-v1")
```

## Revocation

### Sparse Merkle Tree (SMT)

**Purpose**: Cryptographically verifiable revocation proofs

**Parameters**:
- Hash Function: BLAKE3
- Tree Height: 256
- Key: SHA256(DID)
- Value: BLAKE3(serialized revocation entry)

**Operations**:
- Insert: O(1) amortized
- Proof generation: O(log n)
- Verification: O(log n)

### Bloom Filter

**Purpose**: Fast-path rejection of revoked identities

**Parameters**:
- Capacity: 1,000,000 entries
- False Positive Rate: 0.1%
- Hash Functions: 7 (optimal for given capacity/FP rate)

## Security Parameters Summary

| Component | Algorithm | Security Level | Status |
|-----------|-----------|----------------|--------|
| Key Exchange | ML-KEM-768 | NIST Cat 3 | FIPS 203 [^79^] |
| Signatures | ML-DSA-65 | NIST Cat 3 | FIPS 204 [^83^] |
| Hashing | BLAKE3 | 256-bit | Standard |
| KDF | HKDF-SHA256 | 256-bit | RFC 5869 |
| Symmetric | AES-256-GCM | 256-bit | Standard |
| SMT | BLAKE3 | 256-bit | Custom |

## Implementation Notes

### Constant-Time Operations
All cryptographic operations must be constant-time to prevent timing attacks. The `ml-kem` and `ml-dsa` crates use constant-time implementations.

### Memory Safety
- Secret keys use `zeroize` for secure memory clearing
- Heap allocations minimized in hot paths
- Stack allocations preferred for small arrays

### Randomness
- Cryptographically secure RNG required (`OsRng` or equivalent)
- No user-provided entropy without whitening

## References

- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard [^79^]
- FIPS 204: Module-Lattice-Based Digital Signature Standard [^83^]
- ml-kem crate documentation [^19^]
- ml-dsa crate documentation [^19^]
- BLAKE3 specification
- HKDF RFC 5869
