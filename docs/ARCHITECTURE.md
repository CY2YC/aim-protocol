# AIM Protocol Architecture

## System Overview

The AIM (Authenticated Identity Mesh) Protocol is a production-grade, zero-trust mesh networking system implementing NIST-standardized post-quantum cryptography (PQC) for quantum-resistant secure communications.

## Core Components

### 1. Cryptographic Layer (`aim-core`)

**Post-Quantum Primitives:**
- **ML-KEM-768** (FIPS 203) [^79^]: Module-Lattice-based Key Encapsulation Mechanism for secure key exchange
- **ML-DSA-65** (FIPS 204) [^83^]: Module-Lattice-based Digital Signature Algorithm for authentication
- **Hybrid X25519+ML-KEM**: Defense-in-depth combining classical and PQC algorithms

**Key Features:**
- Constant-time implementations to prevent timing attacks
- Zeroize-on-drop for secret key protection
- NIST test vector validation

### 2. Identity Layer (`aim-core`)

**DigitalID System:**
- Decentralized Identifiers (DIDs) using `did:aim` method
- Post-quantum cryptographic binding (ML-DSA + ML-KEM)
- Shamir Secret Sharing (3-of-5) for key recovery [^32^]
- Epoch-based key rotation for post-compromise security

### 3. Session Layer (`aim-core`)

**Secure Handshake:**
- Noise-protocol inspired 3-way handshake
- Ephemeral ML-KEM for forward secrecy
- HKDF-SHA256 for key derivation

**Replay Protection:**
- 64-bit sliding window for sequence tracking
- Automatic key rotation every 1M packets or max epochs

### 4. Network Layer (`aim-mesh`)

**Mesh Networking:**
- libp2p-based peer discovery with Kademlia DHT [^48^]
- GossipSub for message propagation [^48^]
- Multi-AP bootstrap with 2-of-3 consensus for eclipse resistance [^85^]

**XDP Firewall:**
- Kernel-mode packet filtering at NIC driver level
- 10+ Mpps packet processing capability [^69^]
- Reputation-based filtering with LRU rate limiting

### 5. Governance Layer (`aim-core`)

**Reputation System:**
- Bandwidth contribution rewards (0.1 rep/KB)
- Slashing (50% reduction) for misbehavior
- Time decay (1%/hour) to prevent stale reputation

**Revocation:**
- Sparse Merkle Tree (SMT) for cryptographic proofs [^66^]
- Bloom filter for fast-path rejection [^65^]
- BFT threshold signatures for governance

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Application │────▶│  AIM Core   │────▶│   libp2p    │
│    Layer     │     │  (Crypto)   │     │   Network   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │   XDP FW    │     │   P2P Mesh  │
                    │  (Kernel)   │     │  (Userspace)│
                    └─────────────┘     └─────────────┘
```

## Security Properties

| Property | Implementation |
|----------|---------------|
| Confidentiality | ML-KEM-768 + AES-256-GCM |
| Authentication | ML-DSA-65 signatures |
| Integrity | SHA3-256 / BLAKE3 |
| Forward Secrecy | Ephemeral ML-KEM per session |
| Post-Compromise | Epoch-based key rotation |
| Replay Protection | 64-bit sliding window |
| DoS Resistance | XDP rate limiting + reputation |

## Performance Characteristics

Based on benchmarks and research [^69^][^86^]:

| Operation | Latency | Throughput |
|-----------|---------|------------|
| ML-KEM Encaps | ~0.5ms | 2,000 ops/s |
| ML-DSA Sign | ~0.3ms | 3,000 ops/s |
| XDP Filtering | ~50ns | 10-24 Mpps |
| Handshake | ~2ms | 500 handshakes/s |

## References

- FIPS 203: ML-KEM Standard [^79^]
- FIPS 204: ML-DSA Standard [^83^]
- XDP Performance Analysis [^86^]
- Sybil/Eclipse Attack Defenses [^85^]
