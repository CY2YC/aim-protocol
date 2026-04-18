# AIM Protocol Wire Format Specification

## Overview

This document specifies the byte-level packet format for AIM Protocol network communications. All multi-byte values are transmitted in network byte order (big-endian).

## Packet Structure

### AIM Protocol Header

All AIM packets begin with a fixed 32-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic (4 bytes) "AIM\x00"                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (1)   | Type (1)      | Flags (1)   | Reserved (1)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Payload Length (4 bytes)                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Sequence Number (8 bytes)                                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Session ID (8 bytes)                                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Epoch (4 bytes)                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reserved (4 bytes)                                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Field Descriptions:**

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | Protocol identifier: `0x41494D00` ("AIM\0") |
| Version | 1 byte | Protocol version (current: 1) |
| Type | 1 byte | Packet type (see below) |
| Flags | 1 byte | Bit flags (encrypted, compressed, etc.) |
| Reserved | 1 byte | Reserved for future use |
| Payload Length | 4 bytes | Length of payload in bytes (max 2^32-1) |
| Sequence Number | 8 bytes | Anti-replay sequence number |
| Session ID | 8 bytes | Session identifier (truncated from 16 bytes) |
| Epoch | 4 bytes | Current key epoch |
| Reserved | 4 bytes | Reserved for future use |

### Packet Types

| Value | Type | Description |
|-------|------|-------------|
| 0x01 | HANDSHAKE_HELLO | Initial handshake message |
| 0x02 | HANDSHAKE_RESPONSE | Handshake response |
| 0x03 | HANDSHAKE_AUTH | Handshake authentication |
| 0x10 | DATA_ENCRYPTED | Encrypted application data |
| 0x11 | DATA_PLAINTEXT | Unencrypted data (emergency) |
| 0x20 | CONTROL_PING | Keep-alive ping |
| 0x21 | CONTROL_PONG | Keep-alive response |
| 0x30 | REVOCATION_QUERY | Check revocation status |
| 0x31 | REVOCATION_PROOF | Revocation proof response |

### Flags

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | ENCRYPTED | Payload is encrypted |
| 1 | COMPRESSED | Payload is compressed (zstd) |
| 2 | FRAGMENTED | Packet is a fragment |
| 3 | ACK_REQUIRED | Requires acknowledgment |
| 4-7 | Reserved | Reserved for future use |

## Handshake Messages

### Hello Message (Type 0x01)

**Payload Format:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                   Ephemeral ML-KEM Public Key                 +
|                      (1,184 bytes)                            |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                        Nonce (32 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total Payload Size:** 1,216 bytes

### Hello Response (Type 0x02)

**Payload Format:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     ML-KEM Ciphertext                         +
|                      (1,088 bytes)                            |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      ML-DSA Signature                       +
|                      (3,293 bytes)                            |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Responder DID Length (2 bytes)                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Responder DID (variable)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total Payload Size:** 4,383 + DID length bytes

### Authentication Confirm (Type 0x03)

**Payload Format:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      ML-DSA Signature                       +
|                      (3,293 bytes)                            |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Initiator DID Length (2 bytes)                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Initiator DID (variable)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Encrypted Data Messages

### Data Packet (Type 0x10)

**Payload Format:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Nonce (12 bytes for AES-GCM)                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Encrypted Payload                         +
|                   (variable length)                           |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Authentication Tag                        |
|                     (16 bytes for AES-GCM)                    |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## XDP Trusted Header

For kernel-mode filtering, packets carry an additional trusted header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Zone ID (4 bytes)                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reputation Score (4 bytes)                                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Session ID (8 bytes)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Nonce (8 bytes)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total Size:** 24 bytes

This header is placed immediately after the transport header (TCP/UDP) and before the AIM protocol header.

## Serialization

### Integer Encoding
- All integers use network byte order (big-endian)
- Fixed-width fields are zero-padded

### Variable-Length Data
- Length prefix: 2 bytes (u16), big-endian
- Maximum length: 65,535 bytes

### DID Encoding
- UTF-8 string representation
- Example: `did:aim:a1b2c3d4...`
- Maximum length: 64 bytes

## Cryptographic Binding

### Packet Authentication
All packets include implicit authentication through:
1. Session keys derived from authenticated handshake
2. Sequence numbers preventing replay
3. Epoch-based key rotation

### Integrity Protection
Encrypted packets use AES-256-GCM with:
- 96-bit nonce (derived from sequence number)
- 128-bit authentication tag
- Additional data: AIM header (unencrypted portion)

## Size Limits

| Component | Maximum Size |
|-----------|--------------|
| AIM Header | 32 bytes |
| Handshake Hello | 1,216 bytes |
| Handshake Response | 4,400 bytes |
| Handshake Auth | 3,300 bytes |
| Encrypted Payload | 65,535 bytes |
| Total Packet | 65,599 bytes |

## Implementation Notes

### Memory Alignment
- All structures are packed (no padding)
- Use `#[repr(C, packed)]` in Rust
- Beware of unaligned access penalties on some architectures

### Validation
- Reject packets with invalid magic
- Reject packets with version > supported
- Reject oversized payloads
- Validate all length fields

### Extensibility
- Reserved fields must be zero
- Unknown packet types should be ignored
- New flags should be opt-in
