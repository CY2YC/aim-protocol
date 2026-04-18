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

[^19^]: RustCrypto. *ml-kem and ml-dsa crates*. [https://github.com/RustCrypto/ML-KEM](https://github.com/RustCrypto/ML-KEM)[citation:1][citation:2]

[^32^]: Shamir, Adi. *How to Share a Secret*. Communications of the ACM, Vol. 22, No. 11, pp. 612–613, November 1979. [https://dl.acm.org/doi/10.1145/359168.359176](https://dl.acm.org/doi/10.1145/359168.359176)[citation:3]

[^48^]: libp2p Documentation. *Kademlia DHT and GossipSub Specification*. [https://github.com/libp2p/specs](https://github.com/libp2p/specs)[citation:4]

[^69^]: Høiland-Jørgensen, Toke, et al. *The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel*. Proceedings of the 14th International Conference on emerging Networking EXperiments and Technologies (CoNEXT '18). ACM, 2018. [https://doi.org/10.1145/3281411.3281443](https://doi.org/10.1145/3281411.3281443)[citation:6]

[^79^]: National Institute of Standards and Technology (NIST). *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*. August 13, 2024. [https://doi.org/10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)[citation:7]

[^83^]: National Institute of Standards and Technology (NIST). *FIPS 204: Module-Lattice-Based Digital Signature Standard*. August 13, 2024. [https://doi.org/10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)[citation:8]

[^85^]: Heilman, Ethan, et al. *Eclipse Attacks on Bitcoin's Peer-to-Peer Network*. 24th USENIX Security Symposium, pp. 129–144, August 2015. [https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman)[citation:5]

[^86^]: Bertrone, Matteo, et al. *Accelerating Linux Security with eBPF iptables*. Netdev 0x13, March 2019. [https://legacy.netdevconf.info/0x13/session.html?talk=ebpf-iptables](https://legacy.netdevconf.info/0x13/session.html?talk=ebpf-iptables)
