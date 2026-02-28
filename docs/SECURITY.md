# GordianNet Security

## Threat Model

GordianNet provides **confidential, authenticated, reliable** peer-to-peer
communication between two endpoints. The security model assumes:

- **Trusted endpoints**: both peers run unmodified GordianNet code.
- **Untrusted network**: all traffic traverses hostile networks (NAT, ISP, etc.).
- **Authenticated bundle exchange**: the out-of-band channel used to exchange
  bundles provides **integrity and authenticity** (e.g., encrypted messaging,
  in-person QR scan). See [Known Limitations](#known-limitations).

### Assets Protected

| Asset                | Protection Mechanism                      |
|---------------------|-------------------------------------------|
| Message content      | DTLS 1.2 AES-GCM encryption              |
| Message integrity    | DTLS 1.2 AEAD authentication tag          |
| Peer identity        | ECDSA P-256 certificate fingerprint       |
| Message ordering     | KCP reliable ordered delivery             |
| NAT traversal        | ICE/STUN (libjuice)                       |

### Threat Actors Considered

| Actor                   | Capability                              | Mitigated? |
|------------------------|----------------------------------------|------------|
| Passive network eavesdropper | Intercepts UDP traffic            | Yes (DTLS)  |
| Active network attacker | Injects/modifies/replays UDP packets   | Yes (DTLS AEAD) |
| MITM during bundle exchange | Substitutes fingerprint in bundle | **Only if bundle channel is authenticated** |
| Denial of service       | Floods UDP packets                     | Partial (queue limits) |

## Security Properties

### Encryption (DTLS 1.2)

- **Cipher suites restricted** (H-4): Only ECDHE-ECDSA with AEAD:
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- No CBC, no 3DES, no RSA key exchange, no export ciphers.
- **Minimum protocol version**: DTLS 1.2 enforced; no fallback to older versions.
- **Forward secrecy**: ECDHE key exchange provides perfect forward secrecy.

### Authentication

- Each node generates an **ephemeral ECDSA P-256** keypair and self-signed
  certificate at `gordian_start()`.
- The certificate's **SHA-256 fingerprint** is embedded in the bundle.
- After DTLS handshake, the peer's certificate fingerprint is verified against
  the expected value from the bundle using **constant-time comparison** (C-2)
  to prevent timing side-channel attacks.

### Anti-Replay & Renegotiation

- **Renegotiation disabled** (H-3): Prevents certificate swap attacks after
  handshake.
- **Session tickets disabled** (M-1): Prevents bypassing fingerprint
  verification on session resumption.
- **Session cache disabled**: No session reuse across connections.
- DTLS 1.2's built-in sequence number and epoch provide replay protection.

### Key Material Handling

- PRNG seeded with **32 bytes of OS entropy** per instance (H-1), ensuring
  unique PRNG state even for simultaneously-started nodes.
- Certificate validity window is **24 hours** (H-2) — ephemeral by design.
- **Random 64-bit serial numbers** (H-7) with MSB cleared (RFC 5280 compliance).
- All sensitive byte arrays (`local_fingerprint_raw`, `remote_fingerprint_raw`)
  are **zeroized** in the destructor via `mbedtls_platform_zeroize()` (C-6).
- Fingerprint strings are also zeroized before destruction (C-6).

### Resource Limits (DoS Mitigation)

| Resource              | Limit               | Guard    |
|-----------------------|---------------------|----------|
| Incoming UDP queue    | 256 packets         | H-5      |
| Send queue            | 64 MiB (default)    | configurable |
| Single message        | 16 MiB (default)    | C-5, configurable |
| Recv accumulation buf | 32 MiB              | C-7      |
| DTLS handshake        | 30 s timeout        | configurable |
| Bundle input          | 65536 bytes max     | API layer |

### Compiler & Linker Hardening

- `-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security`
- `-fstack-protector-strong`
- `_FORTIFY_SOURCE=2` (Release/RelWithDebInfo)
- Full RELRO: `-z,relro,-z,now`
- Hidden symbol visibility by default

## Hardening Reference Codes

The codebase uses inline reference codes for security-relevant decisions:

| Code | Description                                                |
|------|------------------------------------------------------------|
| C-1  | Bundle not signed — requires authenticated OOB channel     |
| C-2  | Constant-time fingerprint comparison                       |
| C-3  | DTLS cookie verification handling (HelloVerifyRequest)     |
| C-4  | Oversized DTLS packet rejection (prevents truncation)      |
| C-5  | Frame length validation (rejects oversized frames)         |
| C-6  | Sensitive material zeroization in destructor               |
| C-7  | recv_accum size cap to prevent OOM                         |
| H-1  | 32-byte OS entropy for PRNG seeding                        |
| H-2  | 24-hour certificate validity window                        |
| H-3  | DTLS renegotiation disabled                                |
| H-4  | ECDHE-ECDSA + AEAD cipher suite restriction                |
| H-5  | Incoming queue packet count limit                          |
| H-6  | kcp_output_cb error propagation via dtls_error flag        |
| H-7  | Random certificate serial number                           |
| L-7  | KCP uint32 timestamp wrap-around note (~49.7 days)         |
| L-8  | recv_accum offset-based compaction (amortised O(1))        |
| M-1  | Session tickets & cache disabled                           |
| M-2  | Fingerprint collision detection                            |
| M-4  | Fingerprint format validation (95 chars, hex pairs)        |

## Known Limitations

### 1. Bundle MITM (C-1) — Architectural

The bundle (SDP + fingerprint) is transmitted as an opaque base64 blob. It is
**not cryptographically signed**. If an attacker can intercept and modify the
bundle during out-of-band exchange, they can substitute their own fingerprint
and perform a man-in-the-middle attack.

**Mitigation**: Applications MUST exchange bundles over an authenticated
channel. Examples:
- End-to-end encrypted messaging (Signal, WhatsApp)
- In-person QR code scan
- A signalling server with pre-shared identity keys

A future enhancement could sign bundles with a long-term identity key, but
this introduces key management complexity that is outside the current scope.

### 2. No Post-Quantum Cryptography

The ECDSA P-256 signatures and ECDHE key exchange are vulnerable to
quantum computers. This is a limitation of mbedTLS 2.28, which does not
support post-quantum algorithms. A future migration to mbedTLS 3.x or
a different TLS library could address this.

### 3. KCP Timestamp Wrap (L-7)

KCP uses uint32 millisecond timestamps that wrap at ~49.7 days. The signed
subtraction in ikcp handles intervals up to ~24.8 days correctly. Nodes with
uptimes exceeding this should be restarted or a local epoch offset should be
introduced.

### 4. Single Peer Per Node

Each `GordianNode` supports exactly one peer connection. Multi-peer topologies
require multiple node instances (one per peer). This is by design for
simplicity and security isolation.

## Security Audit Changelog

### 2026-03-12

- **Fixed**: Use-after-free in destructor — worker thread could call
  `juice_send()` on a destroyed agent via `kcp_output_cb`. Destruction
  order changed to: stop worker → join → destroy agent.
- **Fixed**: `recv_accum` unbounded growth — added 32 MiB cap (C-7) to
  prevent OOM from peer flooding small valid frames.
- **Fixed**: Sensitive fingerprint strings not zeroized in destructor (C-6).
- **Fixed**: Missing `fire_error()` calls on DTLS handshake timeout,
  fingerprint mismatch, fatal handshake error, and oversized frame rejection.
