# GordianNet Architecture

## Overview

GordianNet is a lightweight bare-metal P2P link-layer library that establishes
direct, encrypted, reliable connections between two peers over UDP. It requires
no signalling server beyond a STUN service for NAT traversal; peers exchange
opaque "bundles" out-of-band (copy/paste, QR code, etc.).

## Protocol Stack

```
+---------------------------------------------------+
|              Application (gordian_send / recv_cb)  |
+---------------------------------------------------+
|  KCP  (ikcp)                                      |
|  Reliable, ordered, low-latency stream delivery   |
|  Conv=0, stream mode, 5ms tick, 256-window        |
+---------------------------------------------------+
|  DTLS 1.2  (mbedTLS 2.28)                         |
|  AES-128/256-GCM, ECDHE-ECDSA, P-256 certs       |
|  Fingerprint-based mutual authentication          |
+---------------------------------------------------+
|  ICE / UDP  (libjuice 1.7)                        |
|  STUN NAT traversal, candidate gathering          |
|  No GLib dependency, thread-per-agent model       |
+---------------------------------------------------+
|              UDP Socket (kernel)                   |
+---------------------------------------------------+
```

```mermaid
graph TB
    subgraph Application Layer
        APP[Application<br>gordian_send / recv_cb]
    end

    subgraph Reliability Layer
        KCP[KCP - ikcp<br>Reliable ordered delivery<br>5ms tick, 256 window]
    end

    subgraph Encryption Layer
        DTLS[DTLS 1.2 - mbedTLS<br>AES-GCM + ECDHE-ECDSA<br>Fingerprint auth]
    end

    subgraph Transport Layer
        ICE[ICE/UDP - libjuice<br>STUN NAT traversal]
    end

    subgraph OS
        UDP[UDP Socket]
    end

    APP <--> KCP
    KCP <--> DTLS
    DTLS <--> ICE
    ICE <--> UDP

    style APP fill:#4a9eff,color:#fff
    style KCP fill:#ff9f43,color:#fff
    style DTLS fill:#ee5a24,color:#fff
    style ICE fill:#6ab04c,color:#fff
    style UDP fill:#666,color:#fff
```

## Connection Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created : gordian_create()

    Created --> Gathering : gordian_start()
    note right of Gathering
        Generates ECDSA P-256 keypair
        Creates ICE agent
        Begins STUN candidate gathering
    end note

    Gathering --> Connecting : gordian_connect(remote_bundle)
    note right of Connecting
        Decodes remote SDP + fingerprint
        Determines DTLS role
        Starts worker thread
    end note

    Connecting --> ICE_Wait : Worker thread started
    ICE_Wait --> DTLS_Handshake : ICE CONNECTED/COMPLETED
    DTLS_Handshake --> Verify_Fingerprint : Handshake success
    Verify_Fingerprint --> KCP_Init : Fingerprint matches
    KCP_Init --> Ready : KCP configured

    Ready --> Disconnected : close_notify / peer disconnect
    Ready --> Disconnected : gordian_disconnect()

    Gathering --> Failed : ICE failure
    ICE_Wait --> Failed : ICE FAILED
    DTLS_Handshake --> Failed : Handshake timeout / error
    Verify_Fingerprint --> Failed : Fingerprint mismatch (ERR_AUTH)
    Ready --> Failed : DTLS transport error

    Failed --> [*] : gordian_destroy()
    Disconnected --> [*] : gordian_destroy()
    Ready --> [*] : gordian_destroy()
```

## Threading Model

```mermaid
sequenceDiagram
    participant App as Application Thread
    participant Juice as libjuice Thread
    participant Worker as Worker Thread

    Note over App: gordian_start()
    App->>Juice: juice_create() + juice_gather_candidates()

    Juice-->>Juice: STUN binding
    Juice->>App: cb_gathering_done() → cred_cb(bundle)

    Note over App: gordian_connect(remote_bundle)
    App->>Worker: spawn worker_thread

    Juice->>Juice: ICE connectivity checks
    Juice->>Worker: cb_state_changed(CONNECTED)
    Juice->>Worker: cb_recv(UDP datagram) → incoming_queue

    Note over Worker: Phase 1: Wait for ICE

    Worker->>Worker: Phase 2: DTLS Handshake
    Worker->>Juice: dtls_send() → juice_send()
    Juice->>Worker: cb_recv() → incoming_queue → dtls_recv()
    Worker->>Worker: verify_peer_fingerprint()
    Worker->>Worker: Phase 2 complete → KCP init

    Worker->>App: fire_state(READY)

    Note over Worker: Phase 3: Data Loop

    loop Every 5ms or on incoming data
        Juice->>Worker: cb_recv() → incoming_queue
        Worker->>Worker: ssl_read → ikcp_input
        Worker->>Worker: ikcp_update (tick clock)
        Worker->>Worker: drain send_queue → ikcp_send
        Worker->>Worker: ikcp_flush → kcp_output_cb → ssl_write
        Worker->>Juice: juice_send(encrypted KCP segment)
        Worker->>Worker: ikcp_recv → parse frames
        Worker->>App: recv_cb(complete message)
    end

    App->>Worker: send_queue.push(message)

    Note over App: gordian_disconnect()
    App->>Worker: disconnect_requested = true
    Worker->>Juice: ssl_close_notify → juice_send
    Worker->>App: fire_state(DISCONNECTED)
```

## Data Flow (Send Path)

```mermaid
flowchart LR
    A[Application<br>gordian_send] -->|"push under<br>send_mtx"| B[send_queue]
    B -->|"worker drains"| C[4-byte length<br>prefix framing]
    C -->|"chunked ≤127×MSS"| D[ikcp_send]
    D -->|ikcp_flush| E[kcp_output_cb]
    E -->|mbedtls_ssl_write| F[DTLS encrypt]
    F -->|dtls_send| G[juice_send]
    G -->|"UDP socket"| H((Network))

    style A fill:#4a9eff,color:#fff
    style H fill:#666,color:#fff
```

## Data Flow (Receive Path)

```mermaid
flowchart RL
    H((Network)) -->|"UDP socket"| G[juice internal]
    G -->|cb_recv| F["incoming_queue<br>(mutex+cv)"]
    F -->|"worker pops"| E[mbedtls_ssl_read]
    E -->|"DTLS decrypt"| D[ikcp_input]
    D -->|ikcp_recv| C["recv_accum<br>(byte accumulator)"]
    C -->|"parse 4-byte<br>length frames"| B[Complete message]
    B -->|recv_cb| A[Application]

    style A fill:#4a9eff,color:#fff
    style H fill:#666,color:#fff
```

## Bundle Format

The "bundle" is the opaque credential blob exchanged out-of-band between peers.

```
Bundle = Base64( SDP_text + "\na=fingerprint:sha-256 " + fingerprint_hex + "\n" )
```

```mermaid
flowchart TD
    subgraph "Bundle Construction (cb_gathering_done)"
        SDP["juice_get_local_description()<br>→ SDP text (ufrag, pwd, candidates)"]
        FP["local_fingerprint<br>SHA-256 of DER cert<br>XX:YY:ZZ:... (95 chars)"]
        CAT["Concatenate:<br>SDP + \\na=fingerprint:sha-256  + FP + \\n"]
        B64["Base64 encode → single-line string"]

        SDP --> CAT
        FP --> CAT
        CAT --> B64
    end

    subgraph "Bundle Parsing (connect)"
        DEC["Base64 decode"]
        SPLIT["Split on \\na=fingerprint:sha-256 "]
        RSDP["Remote SDP<br>→ juice_set_remote_description"]
        RFP["Remote fingerprint<br>→ validate format (95 chars, hex:hex)"]
        ROLE["DTLS role: local_fp > remote_fp → client"]

        DEC --> SPLIT
        SPLIT --> RSDP
        SPLIT --> RFP
        RFP --> ROLE
    end

    B64 -.->|"out-of-band<br>copy/paste"| DEC
```

## DTLS Role Determination

Both peers generate ephemeral ECDSA P-256 certificates at startup. The DTLS
client/server role is deterministic and requires no negotiation:

```
if (local_fingerprint > remote_fingerprint)  →  DTLS client
if (local_fingerprint < remote_fingerprint)  →  DTLS server
if (local_fingerprint == remote_fingerprint) →  ERROR (collision)
```

The lexicographic comparison of the SHA-256 hex strings ("XX:YY:...") provides
a stable, symmetric tie-breaker. Both peers independently arrive at the same
role assignment without any additional signalling.

## KCP Framing

Messages are framed with a 4-byte big-endian length prefix before entering KCP:

```
+----------+-------------------+
| len (4B) | payload (len B)   |
+----------+-------------------+
  BE uint32   application data
```

KCP operates in stream mode (`kcp->stream = 1`), which means multiple
`ikcp_send` calls are concatenated into a continuous byte stream. The
length-prefix framing allows the receiver to reconstruct message boundaries.

### Large Message Chunking

`ikcp_send` rejects calls where `ceil(len / mss) >= 128` (hardcoded
`IKCP_WND_RCV` in ikcp.c), even in stream mode. Messages are chunked into
at most `127 * kcp->mss` bytes per `ikcp_send` call. KCP's stream mode
reassembles them transparently on the receive side.

## File Layout

```
GordianNet/
├── include/
│   └── gordian_net.h          # Public C99 API (opaque GordianNode*)
├── src/
│   ├── gordian_node.hpp       # Internal C++ class definition
│   └── gordian_node.cpp       # Full implementation + extern "C" bridge
├── cli/
│   └── main.cpp               # Interactive P2P chat demo
├── tests/
│   ├── loopback_test.cpp      # Two-node in-process round-trip test
│   ├── framing_test.cpp       # Large message framing test
│   ├── error_path_test.cpp    # Invalid input / error path coverage
│   ├── concurrent_send_test.cpp # Multi-threaded send stress test
│   └── shutdown_test.cpp      # Graceful shutdown test
├── vendor/
│   ├── ikcp.c                 # KCP vendored source
│   └── ikcp.h                 # KCP vendored header
├── docs/
│   ├── ARCHITECTURE.md        # This file
│   └── SECURITY.md            # Threat model and hardening notes
├── CMakeLists.txt             # Build system
├── Doxyfile                   # Doxygen configuration
└── gordian_net.pc.in          # pkg-config template
```

## Build Dependencies

| Dependency | Version | Source       | Purpose              |
|------------|---------|-------------|----------------------|
| libjuice   | 1.7.0   | FetchContent | ICE/STUN             |
| mbedTLS    | 2.28.x  | System pkg   | DTLS 1.2 encryption  |
| ikcp       | vendored| vendor/      | Reliable delivery    |
| CMake      | >= 3.16 | System       | Build system         |
