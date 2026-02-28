/**
 * @file gordian_net.h
 * @brief GordianNet — lightweight bare-metal P2P link-layer library.
 *
 * Pure C99 public API providing NAT-traversed, encrypted, reliable
 * peer-to-peer messaging over UDP.
 *
 * @par Protocol Stack (bottom-up)
 * | Layer   | Library        | Purpose                                |
 * |---------|----------------|----------------------------------------|
 * | ICE/UDP | libjuice 1.7   | NAT traversal via STUN                 |
 * | DTLS    | mbedTLS 2.28   | AES-GCM encryption, ECDSA fingerprints |
 * | KCP     | ikcp (vendored)| Reliable, low-latency ordered delivery |
 *
 * @par Typical Usage
 * @code
 *   GordianConfig cfg = {0};
 *   GordianNode* node = gordian_create(&cfg);
 *   gordian_set_callbacks(node, on_creds, on_state, on_recv, on_error, NULL);
 *   gordian_start(node);
 *   // ... exchange bundles out-of-band ...
 *   gordian_connect(node, remote_bundle_b64);
 *   // ... wait for GORDIAN_STATE_READY, then send/recv ...
 *   gordian_send(node, data, len);
 *   gordian_disconnect(node, 1000);
 *   gordian_destroy(node);
 * @endcode
 *
 * @par Thread Safety
 * - gordian_send() may be called from any thread once READY.
 * - All callbacks fire from an internal worker thread; do not call
 *   gordian_destroy() from within a callback.
 * - gordian_create(), gordian_start(), gordian_connect(), and
 *   gordian_destroy() must be called from the application thread.
 *
 * @see docs/ARCHITECTURE.md for diagrams and threading model.
 * @see docs/SECURITY.md for threat model and hardening notes.
 */

#ifndef GORDIAN_NET_H
#define GORDIAN_NET_H

#include <stdint.h>
#include <stddef.h>

/** @cond INTERNAL */
/* --- Symbol visibility -------------------------------------------------- */
#ifdef GORDIAN_NET_BUILDING
  #if defined(_WIN32) || defined(__CYGWIN__)
    #define GORDIAN_API __declspec(dllexport)
  #elif defined(__GNUC__) || defined(__clang__)
    #define GORDIAN_API __attribute__((visibility("default")))
  #else
    #define GORDIAN_API
  #endif
#else
  #if defined(_WIN32) || defined(__CYGWIN__)
    #define GORDIAN_API __declspec(dllimport)
  #else
    #define GORDIAN_API
  #endif
#endif
/** @endcond */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle to a GordianNet node.
 *
 * All API functions accept a pointer to this type. Created by
 * gordian_create() and freed by gordian_destroy().
 */
typedef struct GordianNode GordianNode;

/* =========================================================================
   Connection State
   ========================================================================= */

/**
 * @brief Connection lifecycle states.
 *
 * The state machine progresses as follows:
 * @verbatim
 *   GATHERING ──→ READY ──→ DISCONNECTED
 *       │                        ↑
 *       └──→ FAILED              │
 *              ↑                 │
 *              └─── (any) ───────┘
 * @endverbatim
 */
typedef enum {
    GORDIAN_STATE_GATHERING,     /**< ICE candidate gathering in progress.   */
    GORDIAN_STATE_READY,         /**< P2P connection fully established.      */
    GORDIAN_STATE_DISCONNECTED,  /**< Remote peer disconnected gracefully.   */
    GORDIAN_STATE_FAILED         /**< ICE, DTLS, or auth failure (terminal). */
} GordianState;

/* =========================================================================
   Error Codes
   ========================================================================= */

/**
 * @brief Error codes returned by API functions and passed to the error callback.
 */
typedef enum {
    GORDIAN_OK = 0,              /**< Success.                               */
    GORDIAN_ERR_MISUSE,          /**< NULL parameter or wrong call order.    */
    GORDIAN_ERR_INVALID_BUNDLE,  /**< Malformed base64 or fingerprint data.  */
    GORDIAN_ERR_CRYPTO,          /**< Entropy, keygen, or DTLS failure.      */
    GORDIAN_ERR_ICE,             /**< STUN/ICE negotiation failure.          */
    GORDIAN_ERR_AUTH,            /**< Peer certificate fingerprint mismatch. */
    GORDIAN_ERR_QUEUE_FULL,      /**< Send queue backpressure limit reached. */
    GORDIAN_ERR_MSG_TOO_LARGE,   /**< Message exceeds max_message_size.      */
    GORDIAN_ERR_INTERNAL         /**< Unexpected internal error.             */
} GordianError;

/* =========================================================================
   Configuration
   ========================================================================= */

/**
 * @brief Node configuration. Zero-initialize for all defaults.
 *
 * @code
 *   GordianConfig cfg = {0};  // all defaults
 *   cfg.stun_server_host = "stun.example.com";
 *   cfg.stun_server_port = 3478;
 * @endcode
 */
typedef struct {
    const char* stun_server_host;      /**< STUN server hostname.
                                            NULL = "stun.l.google.com". */
    uint16_t    stun_server_port;      /**< STUN server port. 0 = 19302. */
    uint32_t    handshake_timeout_ms;  /**< DTLS handshake timeout.
                                            0 = 30000 ms (30 s).        */
    uint32_t    max_message_size;      /**< Max single message size in bytes.
                                            0 = 16 MiB.                 */
    size_t      max_send_queue_bytes;  /**< Send queue backpressure limit.
                                            0 = 64 MiB.                 */
} GordianConfig;

/* =========================================================================
   Callback Signatures
   ========================================================================= */

/**
 * @brief Called when local ICE credentials are ready.
 *
 * The @p base64_bundle string encodes the SDP + DTLS fingerprint.
 * The application must transmit this to the remote peer out-of-band
 * (copy/paste, QR code, signalling server, etc.).
 *
 * @param base64_bundle  Null-terminated base64-encoded bundle string.
 * @param user_data      User pointer from gordian_set_callbacks().
 *
 * @warning The bundle is NOT authenticated. It must be exchanged over
 *          an authenticated channel to prevent MITM substitution.
 */
typedef void (*GordianCredsCallback)(const char* base64_bundle,
                                     void* user_data);

/**
 * @brief Called on connection state transitions.
 *
 * @param state     The new connection state.
 * @param user_data User pointer from gordian_set_callbacks().
 *
 * @note Fires from the internal worker thread. Keep handler fast.
 */
typedef void (*GordianStateCallback)(GordianState state, void* user_data);

/**
 * @brief Called when a complete message is received from the peer.
 *
 * @param data      Pointer to the received message bytes.
 * @param len       Length of the message in bytes.
 * @param user_data User pointer from gordian_set_callbacks().
 *
 * @note The @p data pointer is valid only for the duration of the callback.
 *       Copy the data if you need it beyond the callback scope.
 * @note Fires from the internal worker thread.
 */
typedef void (*GordianRecvCallback)(const uint8_t* data, size_t len,
                                    void* user_data);

/**
 * @brief Called when an error occurs asynchronously.
 *
 * @param err       The error code.
 * @param msg       Human-readable error description (null-terminated).
 * @param user_data User pointer from gordian_set_callbacks().
 *
 * @note If no error callback is set, errors are printed to stderr.
 */
typedef void (*GordianErrorCallback)(GordianError err, const char* msg,
                                     void* user_data);

/* =========================================================================
   API Functions
   ========================================================================= */

/**
 * @brief Create a new GordianNet node.
 *
 * @param cfg  Configuration struct, or NULL for all defaults.
 * @return     Opaque node handle. Never returns NULL.
 *
 * @note The returned node must be freed with gordian_destroy().
 */
GORDIAN_API GordianNode* gordian_create(const GordianConfig* cfg);

/**
 * @brief Destroy a node and free all resources.
 *
 * Stops the worker thread, sends DTLS close_notify if connected,
 * and zeroizes all cryptographic material.
 *
 * @param node  Node handle from gordian_create(). NULL is a no-op.
 *
 * @warning Must NOT be called from within a GordianNet callback.
 */
GORDIAN_API void gordian_destroy(GordianNode* node);

/**
 * @brief Register event callbacks.
 *
 * Must be called before gordian_start(). Callbacks fire from the
 * internal worker thread; the application must not call
 * gordian_destroy() from within any callback.
 *
 * @param node      Node handle.
 * @param cred_cb   Credentials-ready callback (may be NULL).
 * @param state_cb  State-change callback (may be NULL).
 * @param recv_cb   Message-received callback (may be NULL).
 * @param error_cb  Error callback (may be NULL; errors go to stderr).
 * @param user_data Opaque pointer passed through to all callbacks.
 */
GORDIAN_API void gordian_set_callbacks(GordianNode*         node,
                                       GordianCredsCallback cred_cb,
                                       GordianStateCallback state_cb,
                                       GordianRecvCallback  recv_cb,
                                       GordianErrorCallback error_cb,
                                       void*                user_data);

/**
 * @brief Generate identity and begin ICE candidate gathering.
 *
 * Generates an ECDSA P-256 keypair and self-signed certificate,
 * then starts ICE/STUN candidate gathering. When gathering completes,
 * the @ref GordianCredsCallback fires with the base64-encoded bundle.
 *
 * @param node  Node handle.
 * @return GORDIAN_OK on success, or an error code.
 *
 * @pre  gordian_set_callbacks() has been called.
 * @post State transitions to GORDIAN_STATE_GATHERING.
 *
 * @note May only be called once per node.
 */
GORDIAN_API GordianError gordian_start(GordianNode* node);

/**
 * @brief Accept a remote peer's bundle and begin the connection.
 *
 * Decodes the base64 bundle, extracts the remote SDP and DTLS
 * fingerprint, configures the DTLS session, and starts the worker
 * thread which drives ICE → DTLS handshake → KCP setup.
 *
 * @param node           Node handle.
 * @param remote_bundle  Base64-encoded bundle from the remote peer.
 * @return GORDIAN_OK on success, or an error code.
 *
 * @pre  gordian_start() has been called.
 * @post On success, the worker thread begins. State transitions to
 *       GORDIAN_STATE_READY once ICE + DTLS + KCP are established.
 *
 * @note May only be called once per node.
 * @note The bundle must be at most 65536 bytes.
 */
GORDIAN_API GordianError gordian_connect(GordianNode* node,
                                         const char* remote_bundle);

/**
 * @brief Send a message to the connected peer.
 *
 * The message is framed with a 4-byte big-endian length prefix,
 * passed through KCP for reliable delivery, encrypted via DTLS,
 * and sent over the ICE-established UDP path.
 *
 * @param node  Node handle.
 * @param data  Pointer to message bytes. Must not be NULL.
 * @param len   Length in bytes. Must be > 0 and < max_message_size.
 * @return GORDIAN_OK on success, or an error code.
 *
 * @par Thread Safety
 * This function is safe to call from any thread once the node has
 * reached GORDIAN_STATE_READY.
 *
 * @retval GORDIAN_ERR_MISUSE       Node not ready, or data/len invalid.
 * @retval GORDIAN_ERR_MSG_TOO_LARGE Message exceeds max_message_size.
 * @retval GORDIAN_ERR_QUEUE_FULL   Send queue backpressure limit hit.
 */
GORDIAN_API GordianError gordian_send(GordianNode* node,
                                      const uint8_t* data, size_t len);

/**
 * @brief Initiate graceful disconnection.
 *
 * Sends a DTLS close_notify to the peer and waits up to
 * @p timeout_ms milliseconds for the worker thread to finish.
 *
 * @param node        Node handle.
 * @param timeout_ms  Maximum wait time in ms. 0 = no wait (fire-and-forget).
 * @return GORDIAN_OK on success, or GORDIAN_ERR_MISUSE.
 */
GORDIAN_API GordianError gordian_disconnect(GordianNode* node,
                                            uint32_t timeout_ms);

/**
 * @brief Query the current connection state.
 *
 * @param node  Node handle.
 * @return Current GordianState, or GORDIAN_STATE_FAILED if node is NULL.
 *
 * @note This performs an atomic load and is safe to call from any thread.
 */
GORDIAN_API GordianState gordian_state(const GordianNode* node);

/**
 * @brief Get a human-readable error description.
 *
 * @param err  Error code.
 * @return Static null-terminated string describing the error.
 */
GORDIAN_API const char*  gordian_errstr(GordianError err);

#ifdef __cplusplus
}
#endif
#endif /* GORDIAN_NET_H */
