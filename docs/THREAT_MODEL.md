# AIM Protocol Threat Model

## Adversary Model

### Capabilities
- **Quantum Computing**: Adversary with access to cryptographically-relevant quantum computer (CRQC)
- **Network Control**: Ability to intercept, modify, and inject network traffic
- **Resource Abundance**: Can deploy multiple nodes (Sybil attack) [^85^]
- **Long-term Storage**: Store now, decrypt later (HNDL) attacks

### Limitations
- Cannot break NIST PQC algorithms (ML-KEM, ML-DSA) [^79^][^83^]
- Cannot forge signatures without private keys
- Cannot reverse hash functions (BLAKE3, SHA3-256)

## Attack Vectors and Mitigations

### 1. Quantum Attacks

**Threat**: Harvest now, decrypt later attacks on classical cryptography

**Mitigation**:
- ML-KEM-768 (FIPS 203) for key exchange [^79^]
- ML-DSA-65 (FIPS 204) for signatures [^83^]
- Hybrid X25519+ML-KEM for defense-in-depth

### 2. Sybil Attacks

**Threat**: Single adversary creates multiple fake identities to gain disproportionate influence [^85^]

**Mitigation**:
- Proof-of-bandwidth: Reputation requires sustained contribution
- Slashing: 50% reputation reduction for misbehavior
- Decay: 1% hourly decay prevents stale reputation accumulation

### 3. Eclipse Attacks

**Threat**: Isolate target node by monopolizing peer connections [^85^]

**Mitigation**:
- Multi-AP bootstrap: 2-of-3 consensus on peer lists
- Diverse peer selection across multiple bootstrap nodes
- Randomized peer rotation
- Kademlia DHT for decentralized routing [^48^]

### 4. Replay Attacks

**Threat**: Reuse captured packets to impersonate or disrupt

**Mitigation**:
- 64-bit sliding window replay detection
- Per-session unique nonces
- Session key rotation every 1M packets

### 5. DoS/DDoS Attacks

**Threat**: Overwhelm nodes with traffic

**Mitigation**:
- XDP kernel-mode filtering (10+ Mpps capacity) [^69^]
- LRU rate limiting per IP
- Reputation-based packet dropping
- Connection limits per peer

### 6. Key Compromise

**Threat**: Theft or exposure of private keys

**Mitigation**:
- Epoch-based key rotation
- Shamir secret sharing (3-of-5) for recovery [^32^]
- Zeroize-on-drop for memory protection
- TEE attestation (Intel TDX / AMD SEV-SNP)

### 7. Supply Chain Attacks

**Threat**: Compromised dependencies or build system

**Mitigation**:
- cargo-deny for dependency auditing
- Reproducible builds
- Minimal dependency tree (pure Rust where possible)
- NIST PQC implementations from verified crates (ml-kem, ml-dsa) [^19^]

## Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk Level | Status |
|--------|-----------|--------|------------|--------|
| Quantum HNDL | High | Critical | High | Mitigated |
| Sybil Attack | Medium | High | Medium | Mitigated |
| Eclipse Attack | Medium | High | Medium | Mitigated |
| Replay Attack | Low | Medium | Low | Mitigated |
| DDoS Attack | High | Medium | Medium | Mitigated |
| Key Compromise | Low | Critical | Medium | Mitigated |
| Supply Chain | Low | Critical | Medium | Mitigated |

## TCB (Trusted Computing Base)

### Hardware
- CPU with constant-time multiplication
- Secure memory (no DMA attacks)
- Optional: TEE (Intel TDX / AMD SEV-SNP)

### Software
- Linux kernel 5.15+ (XDP support)
- Rust standard library
- ml-kem, ml-dsa crates (RustCrypto)
- libp2p networking stack

### Excluded from TCB
- Application layer code
- User interface
- Logging and monitoring
- Non-critical utilities

## Verification Requirements

### Cryptographic Verification
- [x] NIST test vectors for ML-KEM [^19^]
- [x] NIST test vectors for ML-DSA [^19^]
- [x] Constant-time verification (dudect/dalek)
- [x] Memory safety (Rust borrow checker)

### Network Verification
- [x] 2-of-3 bootstrap consensus
- [x] XDP filter correctness
- [x] Rate limiting effectiveness
- [x] Peer diversity metrics

### Formal Verification (Future)
- [ ] Handshake protocol (Tamarin/ProVerif)
- [ ] SMT correctness proofs
- [ ] Reputation system game theory

## References

- NIST FIPS 203, 204, 205 [^79^][^83^]
- Sybil/Eclipse Attack Analysis [^85^]
- XDP Performance and Security [^69^][^86^]
- libp2p Security [^48^]
