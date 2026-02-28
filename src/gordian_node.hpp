#pragma once
#ifndef GORDIAN_NODE_HPP
#define GORDIAN_NODE_HPP

/*
 * Internal C++ header — never included by public consumers.
 *
 * Threading model
 * ---------------
 *  libjuice runs its own internal thread and fires callbacks from it.
 *  cb_recv pushes raw UDP datagrams into incoming_queue (mutex + cv).
 *  cb_state_changed sets ice_connected atomic and notifies incoming_cv.
 *
 *  worker_thread is the sole owner of the DTLS context (mbedTLS) and the
 *  KCP instance.  It wakes on incoming_cv (5 ms timeout) and:
 *    - Drives the DTLS handshake once ice_connected is set
 *    - After handshake: decrypts incoming records → ikcp_input
 *    - Ticks the KCP clock (ikcp_update) every loop iteration
 *    - Drains send_queue → ikcp_send → ikcp_flush → kcp_output → DTLS → juice
 *    - Delivers data: ikcp_recv → recv_cb
 *
 *  Application thread may call send() at any time; it just pushes to
 *  send_queue under send_mtx.  No GMainLoop, no GLib, no PseudoTCP.
 */

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

/* =========================================================================
   GordianNodeImpl
   ========================================================================= */
struct GordianNodeImpl {

    /* ---- user callbacks (set before start(), read-only in worker) ------- */
    GordianCredsCallback   cred_cb   = nullptr;
    GordianStateCallback   state_cb  = nullptr;
    GordianReceiveCallback recv_cb   = nullptr;
    void*                  user_data = nullptr;

    /* ---- libjuice ICE agent -------------------------------------------- */
    juice_agent_t* agent = nullptr;

    /* ---- DTLS identity (set in start()) --------------------------------- */
    std::string local_fingerprint;   /* SHA-256 hex of our DER cert          */
    std::string remote_fingerprint;  /* parsed from remote bundle            */

    /* ---- mbedTLS (cert+key live for node lifetime) ---------------------- */
    mbedtls_entropy_context      entropy;
    mbedtls_ctr_drbg_context     ctr_drbg;
    mbedtls_pk_context           pk_key;   /* ECDSA P-256 private key        */
    mbedtls_x509_crt             cert;     /* self-signed DER certificate    */
    mbedtls_ssl_context          ssl;      /* DTLS session (worker-owned)    */
    mbedtls_ssl_config           ssl_conf; /* DTLS config (worker-owned)     */
    mbedtls_timing_delay_context dtls_timer;

    /* ---- KCP (created after DTLS handshake, worker-owned) -------------- */
    ikcpcb* kcp = nullptr;

    /* ---- Queues --------------------------------------------------------- */
    std::mutex                        incoming_mtx;
    std::condition_variable           incoming_cv;
    std::queue<std::vector<uint8_t>>  incoming_queue; /* libjuice → worker  */

    std::mutex                        send_mtx;
    std::queue<std::vector<uint8_t>>  send_queue;     /* app → worker       */

    /* ---- Worker + state ------------------------------------------------ */
    std::thread       worker_thread;
    std::atomic<bool> stop_worker   { false };
    std::atomic<bool> ice_connected { false };
    std::atomic<bool> ready         { false };
    std::atomic<GordianState> current_state { GORDIAN_STATE_GATHERING };

    /* ---- Methods -------------------------------------------------------- */
    GordianNodeImpl();
    ~GordianNodeImpl();

    void start();
    void connect_remote(const std::string& base64_bundle);
    bool send(const uint8_t* data, size_t size);

    void fire_state(GordianState s);         /* thread-safe               */
    void worker_loop();

    bool gen_cert_and_key();                 /* call from start()         */
    bool verify_peer_fingerprint();          /* call from worker after hs */

    static std::string base64_encode(const std::string& input);
    static std::string base64_decode(const std::string& input);

    /* ---- mbedTLS BIO callbacks (static, called by mbedTLS) ------------ */
    static int dtls_send(void* ctx, const unsigned char* buf, size_t len);
    static int dtls_recv(void* ctx, unsigned char* buf, size_t len);
    static int dtls_recv_timeout(void* ctx, unsigned char* buf,
                                 size_t len, uint32_t timeout_ms);

    /* ---- KCP output callback (static, called by ikcp_flush) ----------- */
    static int kcp_output_cb(const char* buf, int len,
                             ikcpcb* kcp, void* user);

    /* ---- libjuice callbacks (static, called from juice internal thread) */
    static void cb_state_changed(juice_agent_t* agent, juice_state_t state,
                                 void* user_ptr);
    static void cb_candidate(juice_agent_t* agent, const char* sdp,
                             void* user_ptr);
    static void cb_gathering_done(juice_agent_t* agent, void* user_ptr);
    static void cb_recv(juice_agent_t* agent, const char* data,
                        size_t size, void* user_ptr);
};

/* The public typedef maps to this struct (C sees an opaque pointer) */
struct GordianNode {
    GordianNodeImpl impl;
};

#endif /* GORDIAN_NODE_HPP */
