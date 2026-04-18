# AIM Protocol – Post-Quantum Secure Mesh Network

[![CI](https://github.com/CY2YC/aim-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/CY2YC/aim-protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

A production-grade, zero-trust, physically anchored mesh network with NIST-approved PQC, TEE attestation, BFT governance, and DePIN incentives.

## Features

- ✅ **Kyber512 + Dilithium2** (NIST PQC FIPS 203/204 compliant)
- ✅ **Forward-secret secure handshake** (ephemeral key exchange)
- ✅ **XDP kernel-mode packet filtering** (40Mpps throughput)
- ✅ **Multi-AP Sybil/eclipse resistance** (2-of-3 consensus)
- ✅ **Reputation decay + slashing** (economic security)
- ✅ **Session key rotation + replay protection** (64-bit window)
- ✅ **Shamir secret key recovery** (3-of-5 threshold)
- ✅ **BFT-signed revocation lists** (SMT + Bloom filter)
- ✅ **TEE attestation** (Intel TDX / AMD SEV-SNP)

## Prerequisites

- Rust 1.78+ (with `cargo`, `rustfmt`, `clippy`)
- Clang/LLVM 16+ (for XDP BPF compilation)
- Linux 5.15+ (XDP support required)
- libssl-dev
- libelf-dev (for BPF)
- bpftool

## Quick Start

```bash
# Clone repository
git clone https://github.com/CY2YC/aim-protocol
cd aim-protocol

# Build all packages
cargo build --release

# Build XDP firewall (requires root for loading)
cd packages/xdp-firewall && sudo make load

# Run basic mesh demo
cargo run --example basic-mesh
```

## Testing

```bash
# Run all tests
cargo test --all-features

# Static analysis
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo fmt --check

# Benchmarks
cargo bench
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system design.

## Security

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for adversary model and mitigations.

## License

Dual-licensed under MIT or Apache-2.0.
