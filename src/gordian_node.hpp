/**
 * @file gordian_node.hpp
 * @brief Internal C++ implementation header — never included by public consumers.
 * @internal
 *
 * @par Threading Model
 *
 * Three threads interact during a connection's lifetime:
 *
 * 1. **libjuice internal thread** — fires ICE callbacks:
 *    - cb_recv() pushes raw UDP datagrams into @c incoming_queue (mutex + cv).
 *    - cb_state_changed() sets @c ice_connected and notifies @c incoming_cv.
 *    - cb_gathering_done() builds and delivers the base64 bundle.
 *
 * 2. **worker_thread** — sole owner of DTLS + KCP contexts. Wakes on
 *    @c incoming_cv (5 ms timeout) and:
 *    - Drives the DTLS handshake once @c ice_connected is set.
 *    - After handshake: decrypts incoming → @c ikcp_input.
 *    - Ticks KCP clock via @c ikcp_update every loop iteration.
 *    - Drains @c send_queue → ikcp_send → ikcp_flush → kcp_output → DTLS → juice.
 *    - Delivers complete messages: @c ikcp_recv → @c recv_cb.
 *
 * 3. **Application thread** — calls send() which pushes to @c send_queue
 *    under @c send_mtx. No GMainLoop, no GLib.
 *
 * @par Security Notes
 *
 * - **C-1**: The bundle (SDP + fingerprint) is not signed. A MITM who can
 *   intercept the out-of-band exchange can substitute their own fingerprint.
 *   Callers must use an authenticated channel for bundle exchange.
 * - **C-2**: Fingerprint verification uses constant-time comparison to
 *   prevent timing side-channel attacks.
 * - **C-6**: All sensitive strings (fingerprints) and byte arrays are
 *   zeroized in the destructor using mbedtls_platform_zeroize().
 * - **C-7**: recv_accum is capped at kMaxRecvAccumBytes (32 MiB) to
 *   prevent OOM from a malicious peer flooding small valid frames.
 */

#pragma once
#ifndef GORDIAN_NODE_HPP
#define GORDIAN_NODE_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

/* libjuice */
#include <juice/juice.h>

/* mbedTLS */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509_crt.h>

/* KCP reliability */
#include "ikcp.h"

/* Public C API */
#include "gordian_net.h"

/**
 * @brief Internal implementation of a GordianNet node.
 * @internal
 *
 * Manages the full lifecycle: ICE negotiation (libjuice), DTLS 1.2
 * encryption (mbedTLS), and KCP reliable delivery (ikcp). The struct
 * is not copyable or movable; it is always heap-allocated behind
 * the opaque @ref GordianNode handle.
 */
struct GordianNodeImpl {

    /** @name User Callbacks
     *  Set before start(), read-only from the worker thread.
     *  @{ */
    GordianCredsCallback   cred_cb   = nullptr; /**< Credentials ready.     */
    GordianStateCallback   state_cb  = nullptr; /**< State transition.      */
    GordianRecvCallback    recv_cb   = nullptr; /**< Message received.      */
    GordianErrorCallback   error_cb  = nullptr; /**< Async error.           */
    void*                  user_data = nullptr;  /**< Opaque callback data.  */
    /** @} */

    /** @name Configuration
     *  Populated from GordianConfig in gordian_create(); immutable after start().
     *  @{ */
    std::string cfg_stun_host     = "stun.l.google.com"; /**< STUN hostname.   */
    uint16_t    cfg_stun_port     = 19302;               /**< STUN port.       */
    uint32_t    cfg_handshake_ms  = 30000;               /**< DTLS timeout ms. */
    uint32_t    cfg_max_msg_size  = 16u * 1024u * 1024u; /**< Max msg (16 MiB).*/
    size_t      cfg_max_send_q    = 64u * 1024u * 1024u; /**< Queue cap (64 MiB).*/
    /** @} */

    /** @name ICE Agent
     *  @{ */
    juice_agent_t* agent = nullptr; /**< libjuice ICE agent handle. */
    /** @} */

    /** @name DTLS Identity
     *  Generated in start(), used for role determination and peer verification.
     *  @{ */
    std::string local_fingerprint;           /**< SHA-256 hex "XX:YY:..." of our cert.  */
    std::string remote_fingerprint;          /**< SHA-256 hex from the remote bundle.   */
    uint8_t     local_fingerprint_raw[32];   /**< Raw SHA-256 bytes of local cert.      */
    uint8_t     remote_fingerprint_raw[32];  /**< Raw SHA-256 bytes of remote cert.     */
    /** @} */

    /** @name mbedTLS Contexts
     *  Cert + key live for the node's lifetime; ssl/ssl_conf are worker-owned.
     *  @{ */
    mbedtls_entropy_context      entropy;    /**< OS entropy source.          */
    mbedtls_ctr_drbg_context     ctr_drbg;   /**< CTR-DRBG PRNG instance.    */
    mbedtls_pk_context           pk_key;     /**< ECDSA P-256 private key.    */
    mbedtls_x509_crt             cert;       /**< Self-signed X.509 cert.     */
    mbedtls_ssl_context          ssl;        /**< DTLS session (worker-owned).*/
    mbedtls_ssl_config           ssl_conf;   /**< DTLS configuration.         */
    mbedtls_timing_delay_context dtls_timer; /**< DTLS retransmit timer.      */
    /** @} */

    /** @name KCP State
     *  Created after DTLS handshake completes; exclusively worker-owned.
     *  @{ */
    ikcpcb*              kcp         = nullptr; /**< KCP control block.            */
    size_t               recv_offset = 0;       /**< Consumed prefix of recv_accum.*/
    std::vector<uint8_t> recv_accum;            /**< Incoming byte accumulator.    */
    /** @} */

    /** @name Queue Limits
     *  @{ */
    static constexpr size_t kMaxIncomingQueue  = 256;                  /**< Max queued UDP packets.  */
    static constexpr size_t kMaxRecvAccumBytes = 32u * 1024u * 1024u;  /**< Max recv_accum (32 MiB). */
    /** @} */

    /** @name Inter-thread Queues
     *  @{ */
    std::mutex                        incoming_mtx;   /**< Guards incoming_queue.       */
    std::condition_variable           incoming_cv;    /**< Signals new incoming data.   */
    std::queue<std::vector<uint8_t>>  incoming_queue; /**< libjuice → worker datagrams. */

    std::mutex                        send_mtx;       /**< Guards send_queue.           */
    std::queue<std::vector<uint8_t>>  send_queue;     /**< App → worker messages.       */
    size_t                            send_queue_bytes = 0; /**< Total queued send bytes.*/
    /** @} */

    /** @name Worker Thread & Atomic State
     *  @{ */
    std::thread       worker_thread;                                    /**< Worker thread handle.    */
    std::mutex        state_mtx;                                        /**< Serialises state_cb.     */
    std::atomic<bool> stop_worker           { false };                  /**< Shutdown signal.         */
    std::atomic<bool> ice_connected         { false };                  /**< ICE path established.    */
    std::atomic<bool> ready                 { false };                  /**< Full stack is up.        */
    std::atomic<bool> dtls_flight_sent      { false };                  /**< First DTLS send done.    */
    std::atomic<bool> dtls_error            { false };                  /**< ssl_write failure flag.  */
    std::atomic<bool> started               { false };                  /**< Guards start() re-entry. */
    std::atomic<bool> connected             { false };                  /**< Guards connect() re-entry.*/
    std::atomic<bool> disconnect_requested  { false };                  /**< Graceful shutdown flag.  */
    std::atomic<GordianState> current_state { GORDIAN_STATE_GATHERING }; /**< Current lifecycle state.*/
    /** @} */

    /** @name Lifecycle Methods
     *  @{ */
    GordianNodeImpl();
    ~GordianNodeImpl();

    /** @brief Generate identity, create ICE agent, begin gathering. */
    GordianError start();
    /** @brief Decode remote bundle, configure DTLS, start worker thread. */
    GordianError connect(const std::string& base64_bundle);
    /** @brief Enqueue a message for sending (thread-safe). */
    GordianError send(const uint8_t* data, size_t size);
    /** @brief Request graceful DTLS teardown. */
    GordianError disconnect(uint32_t timeout_ms);
    /** @} */

    /** @name Internal Helpers
     *  @{ */
    /** @brief Emit a state transition and invoke state_cb (serialised). */
    void fire_state(GordianState s);
    /** @brief Invoke error_cb, or print to stderr if none is set. */
    void fire_error(GordianError e, const char* msg);
    /** @brief Main worker loop: ICE wait → DTLS handshake → KCP data loop. */
    void worker_loop();
    /** @brief Generate ECDSA P-256 self-signed cert; set local_fingerprint. */
    bool gen_cert_and_key();
    /** @brief Verify peer cert fingerprint after DTLS handshake (constant-time). */
    bool verify_peer_fingerprint();
    /** @brief RFC 4648 base64 encode. */
    static std::string base64_encode(const std::string& input);
    /** @brief RFC 4648 base64 decode; returns empty on invalid input. */
    static std::string base64_decode(const std::string& input);
    /** @} */

    /** @name mbedTLS BIO Callbacks
     *  Static functions passed to mbedtls_ssl_set_bio().
     *  @{ */
    /** @brief Send one DTLS record as a UDP datagram via libjuice. */
    static int dtls_send(void* ctx, const unsigned char* buf, size_t len);
    /** @brief Non-blocking receive: pop from incoming_queue or return WANT_READ. */
    static int dtls_recv(void* ctx, unsigned char* buf, size_t len);
    /**
     * @brief Blocking receive with timeout for DTLS handshake retransmit.
     *
     * Contains two guards to prevent the mbedtls_ssl_flight_transmit crash:
     * 1. dtls_flight_sent == false → return WANT_READ (no flight exists).
     * 2. Timer not expired → return WANT_READ (retransmit premature).
     */
    static int dtls_recv_timeout(void* ctx, unsigned char* buf,
                                 size_t len, uint32_t timeout_ms);
    /** @} */

    /** @name KCP Output Callback
     *  @{ */
    /** @brief Encrypt KCP segment via DTLS and send through libjuice. */
    static int kcp_output_cb(const char* buf, int len,
                             ikcpcb* kcp, void* user);
    /** @} */

    /** @name libjuice Callbacks
     *  Static functions fired from libjuice's internal thread.
     *  @{ */
    static void cb_state_changed(juice_agent_t* agent, juice_state_t state,
                                 void* user_ptr);
    static void cb_candidate(juice_agent_t* agent, const char* sdp,
                             void* user_ptr);
    static void cb_gathering_done(juice_agent_t* agent, void* user_ptr);
    static void cb_recv(juice_agent_t* agent, const char* data,
                        size_t size, void* user_ptr);
    /** @} */
};

/**
 * @brief Public-facing wrapper; the C API's opaque GordianNode* points here.
 */
struct GordianNode {
    GordianNodeImpl impl; /**< The actual implementation. */
};

#endif /* GORDIAN_NODE_HPP */
