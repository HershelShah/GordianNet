# GordianNet

Lightweight bare-metal P2P link-layer library. Establishes direct, encrypted,
reliable peer-to-peer connections over UDP with NAT traversal — no signalling
server required.

## Protocol Stack

```
Application  (gordian_send / recv_cb)
     ↕
KCP          reliable, ordered, low-latency delivery
     ↕
DTLS 1.2     AES-GCM encryption, ECDSA P-256 fingerprint auth
     ↕
ICE / UDP    NAT traversal via STUN (libjuice)
```

## Features

- **Pure C99 public API** — opaque handle, callbacks, zero-init config (SQLite-style)
- **NAT traversal** — ICE/STUN via [libjuice](https://github.com/paullouisageneau/libjuice) (no GLib dependency)
- **Encryption** — DTLS 1.2 with ECDHE-ECDSA + AES-GCM (mbedTLS), forward secrecy
- **Authentication** — mutual ECDSA P-256 certificate fingerprint verification
- **Reliability** — KCP protocol for ordered, low-latency delivery over UDP
- **No external signalling** — peers exchange opaque bundles out-of-band (copy/paste, QR, etc.)

## Quick Start

### Build

```bash
# Dependencies: cmake >= 3.16, mbedTLS 2.28.x (system package)
sudo apt install libmbedtls-dev   # Debian/Ubuntu

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
```

### Run the Chat Demo

Open two terminals:

```bash
# Terminal A
LD_LIBRARY_PATH=build ./build/gordian_chat

# Terminal B
LD_LIBRARY_PATH=build ./build/gordian_chat
```

1. Each terminal prints a base64 bundle
2. Copy Terminal A's bundle → paste into Terminal B
3. Copy Terminal B's bundle → paste into Terminal A
4. Both show `[READY]` — type messages and hit Enter

### Run Tests

```bash
cd build && LD_LIBRARY_PATH=. ctest --output-on-failure -V
```

## API Usage

```c
#include "gordian_net.h"

// 1. Create with defaults
GordianConfig cfg = {0};
GordianNode* node = gordian_create(&cfg);

// 2. Set callbacks
gordian_set_callbacks(node, on_creds, on_state, on_recv, on_error, user_data);

// 3. Start ICE gathering (triggers on_creds with your bundle)
gordian_start(node);

// 4. Feed remote peer's bundle (from out-of-band exchange)
gordian_connect(node, remote_bundle_base64);

// 5. Wait for GORDIAN_STATE_READY, then send messages
gordian_send(node, data, len);

// 6. Clean up
gordian_disconnect(node, 1000);
gordian_destroy(node);
```

### Callbacks

| Callback | Purpose |
|----------|---------|
| `GordianCredsCallback` | Delivers your base64 bundle — send it to the remote peer |
| `GordianStateCallback` | State transitions: `GATHERING` → `READY` → `DISCONNECTED` |
| `GordianRecvCallback` | Complete message received from peer |
| `GordianErrorCallback` | Async errors (defaults to stderr if not set) |

### Configuration

All fields zero-initialize to sensible defaults:

| Field | Default | Description |
|-------|---------|-------------|
| `stun_server_host` | `stun.l.google.com` | STUN server hostname |
| `stun_server_port` | `19302` | STUN server port |
| `handshake_timeout_ms` | `30000` | DTLS handshake timeout |
| `max_message_size` | `16 MiB` | Max single message size |
| `max_send_queue_bytes` | `64 MiB` | Send queue backpressure limit |

## How It Works

1. **Identity**: Each node generates an ephemeral ECDSA P-256 keypair and
   self-signed certificate at startup
2. **Bundle**: The local SDP (ICE candidates) + certificate SHA-256 fingerprint
   are base64-encoded into a single opaque string
3. **Exchange**: Peers exchange bundles out-of-band (the library doesn't
   prescribe how — any channel works)
4. **ICE**: libjuice performs STUN binding and ICE connectivity checks to
   establish a direct UDP path through NATs
5. **DTLS**: A DTLS 1.2 handshake authenticates both peers (fingerprint
   verification) and establishes an encrypted channel
6. **KCP**: The KCP protocol runs over the DTLS channel, providing reliable
   ordered delivery with low latency

### DTLS Role Determination

No negotiation needed — the peer with the lexicographically larger certificate
fingerprint becomes the DTLS client. Both sides compute the same result
independently.

## Security

- **Encryption**: DTLS 1.2 with ECDHE-ECDSA + AES-GCM (forward secrecy)
- **Authentication**: Constant-time SHA-256 fingerprint verification
- **Hardening**: Renegotiation disabled, session tickets disabled, AEAD-only
  cipher suites, 24-hour cert validity
- **Compiler**: `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO

**Important**: Bundles must be exchanged over an authenticated channel (e.g.,
encrypted messaging, in-person QR scan). If an attacker can modify bundles in
transit, they can MITM the connection.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

## Project Structure

```
include/gordian_net.h       Public C99 API
src/gordian_node.hpp        Internal C++ class
src/gordian_node.cpp         Implementation + C bridge
cli/main.cpp                Interactive chat demo
tests/                      Integration test suite
vendor/ikcp.{c,h}           KCP (vendored)
docs/ARCHITECTURE.md        Architecture & Mermaid diagrams
docs/SECURITY.md            Threat model & hardening notes
Doxyfile                    Doxygen configuration
```

## Documentation

Generate API documentation with [Doxygen](https://www.doxygen.nl/):

```bash
doxygen Doxyfile
# Open docs/doxygen/html/index.html
```

Architecture diagrams are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
(viewable directly on GitHub with Mermaid rendering).

## Dependencies

| Library | Version | Source | Purpose |
|---------|---------|--------|---------|
| [libjuice](https://github.com/paullouisageneau/libjuice) | 1.7.0 | CMake FetchContent | ICE/STUN NAT traversal |
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) | 2.28.x | System package | DTLS 1.2 encryption |
| [ikcp](https://github.com/skywind3000/kcp) | — | Vendored | Reliable UDP delivery |

## CI

GitHub Actions runs on every push/PR to `master`:
- **Debug** + **Release** builds
- **AddressSanitizer**, **ThreadSanitizer**, **UndefinedBehaviorSanitizer**
- `-Werror` enabled
- Full test suite

## License

See [LICENSE](LICENSE) for details.
