/*
 * gordian_node.cpp
 * GordianNet implementation — libjuice ICE + mbedTLS DTLS 1.2 + KCP
 *
 * Stack layers (bottom-up)
 * -------------------------
 *   libjuice   — ICE/STUN, no GLib dependency
 *   mbedTLS    — DTLS 1.2, AES-GCM, ECDSA self-signed cert + fingerprint auth
 *   KCP (ikcp) — reliable, low-latency delivery (replaces PseudoTCP)
 *
 * Threading
 * ---------
 *   libjuice internal thread  → pushes raw UDP to incoming_queue (mutex+cv)
 *   worker_thread             → owns DTLS context + KCP instance
 *   application thread        → pushes to send_queue, reads ready atomic
 */

#include "gordian_node.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>

/* mbedTLS extras needed in the .cpp */
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
/* x509write functions are in x509_crt.h (same header as x509_crt types) */


/* DTLS record buffer: must fit the largest possible DTLS plaintext record.
   MBEDTLS_SSL_MAX_CONTENT_LEN is typically 16384 bytes; add overhead margin. */
static constexpr size_t kDtlsBufSize = 16384 + 512;

/* Allowed DTLS 1.2 cipher suites: ECDHE-ECDSA + AEAD only (H-4).
   No CBC, no 3DES, no RSA key-exchange, no export ciphers.               */
static const int kAllowedCiphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    0
};

/* =========================================================================
   Time helper — millisecond clock for KCP
   NOTE (L-7): KCP uses uint32 ms timestamps; wraps at ~49.7 days of uptime.
   ikcp uses signed subtraction internally so wrap-around is handled for
   intervals < 2^31 ms (~24.8 days).  Long-lived nodes should be restarted
   within that window, or this should be replaced with a local epoch offset.
   ========================================================================= */
static uint32_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
            .count() & 0xFFFFFFFFu);
}

/* =========================================================================
   Constant-time memory comparison (C-2)
   Uses volatile reads and accumulates differences so the compiler cannot
   short-circuit the loop.
   ========================================================================= */
static int ct_memcmp(const uint8_t* a, const uint8_t* b, size_t n)
{
    const volatile uint8_t* va = a;
    const volatile uint8_t* vb = b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= va[i] ^ vb[i];
    return static_cast<int>(diff);
}

/* =========================================================================
   Base64 (RFC 4648) — no external dependency
   ========================================================================= */
static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string GordianNodeImpl::base64_encode(const std::string& in)
{
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kB64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(kB64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

/* Fixed base64_decode (M-3): rejects invalid characters rather than silently
   truncating; properly handles '=' padding without treating it as a break.  */
std::string GordianNodeImpl::base64_decode(const std::string& in)
{
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)kB64Chars[i]] = i;

    int val = 0, valb = -8;
    bool in_padding = false;
    for (unsigned char c : in) {
        if (c == '=') {
            in_padding = true;
            continue;
        }
        if (in_padding || T[c] == -1) {
            /* Data after padding or an invalid character: reject entirely. */
            return {};
        }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

/* =========================================================================
   Constructor / Destructor
   ========================================================================= */
GordianNodeImpl::GordianNodeImpl()
{
    /* Suppress libjuice WARN noise (benign ENETUNREACH on first STUN
       attempt and ICE role-conflict resolution in loopback scenarios). */
    juice_set_log_level(JUICE_LOG_LEVEL_ERROR);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_key);
    mbedtls_x509_crt_init(&cert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
    std::memset(local_fingerprint_raw,  0, sizeof(local_fingerprint_raw));
    std::memset(remote_fingerprint_raw, 0, sizeof(remote_fingerprint_raw));
}

GordianNodeImpl::~GordianNodeImpl()
{
    /* 1. Signal worker to stop and wait for it FIRST.
          The worker thread calls juice_send() via kcp_output_cb → dtls_send,
          so the juice agent must remain alive until the worker exits.
          FIX (CVE-like): previous order destroyed the agent before stopping
          the worker, causing a use-after-free on the juice_agent_t pointer.  */
    stop_worker.store(true);
    incoming_cv.notify_all();
    if (worker_thread.joinable())
        worker_thread.join();

    /* 2. Now that the worker is stopped, destroy the juice agent.
          libjuice callbacks (cb_recv, cb_state_changed) check stop_worker
          and will no-op, so no more incoming_queue pushes after this.        */
    if (agent) {
        juice_destroy(agent);
        agent = nullptr;
    }

    /* 3. Release KCP (worker is done — no more concurrent access) */
    if (kcp) {
        ikcp_release(kcp);
        kcp = nullptr;
    }

    /* 4. Clear sensitive buffers and free mbedTLS resources */
    mbedtls_platform_zeroize(local_fingerprint_raw, sizeof(local_fingerprint_raw));
    mbedtls_platform_zeroize(remote_fingerprint_raw, sizeof(remote_fingerprint_raw));

    /* Zeroize fingerprint strings before they are freed (C-6) */
    if (!local_fingerprint.empty()) {
        mbedtls_platform_zeroize(&local_fingerprint[0], local_fingerprint.size());
        local_fingerprint.clear();
    }
    if (!remote_fingerprint.empty()) {
        mbedtls_platform_zeroize(&remote_fingerprint[0], remote_fingerprint.size());
        remote_fingerprint.clear();
    }

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&pk_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

/* =========================================================================
   fire_state — serialised via state_mtx so state_cb is never called
   concurrently from the worker thread and the libjuice thread (L-10).
   ========================================================================= */
void GordianNodeImpl::fire_state(GordianState s)
{
    current_state.store(s);
    std::lock_guard<std::mutex> lk(state_mtx);
    if (state_cb) state_cb(s, user_data);
}

void GordianNodeImpl::fire_error(GordianError e, const char* msg)
{
    if (error_cb)
        error_cb(e, msg, user_data);
    else
        fprintf(stderr, "[gordian] %s\n", msg);
}

/* =========================================================================
   mbedTLS BIO callbacks
   ========================================================================= */

/* Send one DTLS record → one UDP datagram via libjuice */
int GordianNodeImpl::dtls_send(void* ctx, const unsigned char* buf, size_t len)
{
    auto* self = static_cast<GordianNodeImpl*>(ctx);
    int ret = juice_send(self->agent, reinterpret_cast<const char*>(buf), len);
    if (ret < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    /* Mark that a flight has been sent so dtls_recv_timeout may later
       trigger retransmit (ssl->handshake->flight is guaranteed non-null). */
    self->dtls_flight_sent.store(true);
    return static_cast<int>(len);
}

/* Non-blocking recv: pop one datagram from incoming_queue or return WANT_READ.
   NOTE (C-4): if the queued packet is larger than len, drop it rather than
   silently truncating a DTLS record, which would corrupt the session.        */
int GordianNodeImpl::dtls_recv(void* ctx, unsigned char* buf, size_t len)
{
    auto* self = static_cast<GordianNodeImpl*>(ctx);
    std::lock_guard<std::mutex> lk(self->incoming_mtx);
    if (self->incoming_queue.empty())
        return MBEDTLS_ERR_SSL_WANT_READ;
    auto pkt = std::move(self->incoming_queue.front());
    self->incoming_queue.pop();
    if (pkt.size() > len) {
        fprintf(stderr, "[gordian] dtls_recv: oversized packet (%zu > %zu), dropped\n",
                pkt.size(), len);
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    std::memcpy(buf, pkt.data(), pkt.size());
    return static_cast<int>(pkt.size());
}

/* Blocking recv with timeout — called by mbedTLS during DTLS handshake.
 *
 * Two guards prevent the mbedtls_ssl_flight_transmit crash:
 *
 *  1. dtls_flight_sent == false  (we are the DTLS server waiting for the
 *     first ClientHello, or our first send has not landed yet).
 *     → Return WANT_READ.  mbedtls_ssl_resend must NOT be called because
 *       ssl->handshake->flight is still NULL.
 *
 *  2. dtls_flight_sent == true but the retransmit timer has not expired
 *     (mbedtls_timing_get_delay returns 0 or 1).
 *     → Return WANT_READ.  It is too early to retransmit; the peer may
 *       simply be slow.
 *
 * Only when both guards pass (flight exists AND timer expired == 2) do we
 * return SSL_TIMEOUT, which causes mbedTLS to retransmit the last flight.
 *
 * NOTE (C-4): oversized packets are dropped, same as dtls_recv.
 */
int GordianNodeImpl::dtls_recv_timeout(void* ctx, unsigned char* buf,
                                       size_t len, uint32_t timeout_ms)
{
    auto* self = static_cast<GordianNodeImpl*>(ctx);
    std::unique_lock<std::mutex> lk(self->incoming_mtx);

    if (self->incoming_queue.empty() && timeout_ms > 0) {
        self->incoming_cv.wait_for(
            lk, std::chrono::milliseconds(timeout_ms),
            [self] {
                return !self->incoming_queue.empty()
                    || self->stop_worker.load();
            });
    }

    if (self->incoming_queue.empty()) {
        /* Guard 1: no flight sent yet — never trigger retransmit. */
        if (!self->dtls_flight_sent.load())
            return MBEDTLS_ERR_SSL_WANT_READ;

        /* Guard 2: timer not yet expired — retransmit would be premature. */
        if (mbedtls_timing_get_delay(&self->dtls_timer) != 2)
            return MBEDTLS_ERR_SSL_WANT_READ;

        /* Both guards pass: real timeout, retransmit the last flight. */
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    auto pkt = std::move(self->incoming_queue.front());
    self->incoming_queue.pop();
    if (pkt.size() > len) {
        fprintf(stderr, "[gordian] dtls_recv_timeout: oversized packet (%zu > %zu), dropped\n",
                pkt.size(), len);
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    std::memcpy(buf, pkt.data(), pkt.size());
    return static_cast<int>(pkt.size());
}

/* =========================================================================
   KCP output callback — encrypts via DTLS → sends via libjuice (H-6)
   Handles ssl_write errors by setting dtls_error flag for the worker loop.
   ========================================================================= */
int GordianNodeImpl::kcp_output_cb(const char* buf, int len,
                                   ikcpcb* /*kcp*/, void* user)
{
    auto* self = static_cast<GordianNodeImpl*>(user);
    /* For DTLS/UDP, ssl_write is atomic: it either writes the whole record
       or returns an error — partial writes do not occur on datagram transports.
       We still loop to handle WANT_WRITE correctly.                          */
    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(buf);
    int remaining = len;
    while (remaining > 0) {
        int wr = mbedtls_ssl_write(&self->ssl, ptr,
                                   static_cast<size_t>(remaining));
        if (wr == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (wr <= 0) {
            self->dtls_error.store(true);
            self->incoming_cv.notify_all();
            break;
        }
        ptr       += wr;
        remaining -= wr;
    }
    return 0;
}

/* =========================================================================
   libjuice callbacks — fire from juice's internal thread
   ========================================================================= */

void GordianNodeImpl::cb_state_changed(juice_agent_t* /*agent*/,
                                       juice_state_t  state,
                                       void*          user_ptr)
{
    auto* self = static_cast<GordianNodeImpl*>(user_ptr);
    if (self->stop_worker.load()) return;

    if (state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED) {
        self->ice_connected.store(true);
        self->incoming_cv.notify_all();
    } else if (state == JUICE_STATE_FAILED) {
        self->fire_state(GORDIAN_STATE_FAILED);
        self->stop_worker.store(true);
        self->incoming_cv.notify_all();
    }
}

void GordianNodeImpl::cb_candidate(juice_agent_t* /*agent*/,
                                   const char*    /*sdp*/,
                                   void*          /*user_ptr*/)
{
    /* Individual candidates are bundled via gathering_done below. */
}

void GordianNodeImpl::cb_gathering_done(juice_agent_t* agent, void* user_ptr)
{
    auto* self = static_cast<GordianNodeImpl*>(user_ptr);
    if (self->stop_worker.load()) return;

    /* Get the full local SDP (ufrag + pwd + all candidates).
       NOTE (L-12): JUICE_MAX_SDP_STRING_LEN can be large; heap-allocate to
       avoid overflowing the libjuice callback's stack.                      */
    std::vector<char> sdp_buf(JUICE_MAX_SDP_STRING_LEN);
    if (juice_get_local_description(agent, sdp_buf.data(), sdp_buf.size()) < 0) {
        fprintf(stderr, "[gordian] juice_get_local_description failed\n");
        self->fire_state(GORDIAN_STATE_FAILED);
        self->stop_worker.store(true);
        self->incoming_cv.notify_all();
        return;
    }

    /* Bundle = SDP + fingerprint attribute + base64 */
    std::string bundle_text = sdp_buf.data();
    bundle_text += "\na=fingerprint:sha-256 ";
    bundle_text += self->local_fingerprint;
    bundle_text += "\n";

    std::string b64 = base64_encode(bundle_text);
    if (self->cred_cb)
        self->cred_cb(b64.c_str(), self->user_data);
}

void GordianNodeImpl::cb_recv(juice_agent_t* /*agent*/, const char* data,
                              size_t size, void* user_ptr)
{
    auto* self = static_cast<GordianNodeImpl*>(user_ptr);
    if (self->stop_worker.load()) return;
    {
        std::lock_guard<std::mutex> lk(self->incoming_mtx);
        /* NOTE (H-5): drop incoming packets when queue is full to prevent OOM. */
        if (self->incoming_queue.size() >= kMaxIncomingQueue) return;
        self->incoming_queue.emplace(data, data + size);
    }
    self->incoming_cv.notify_one();
}

/* =========================================================================
   gen_cert_and_key — generate ECDSA P-256 self-signed cert, set
   local_fingerprint.  Called from start().
   ========================================================================= */
bool GordianNodeImpl::gen_cert_and_key()
{
    int ret;

    /* Seed the PRNG with per-instance entropy (H-1).
       We draw 32 bytes directly from the OS entropy source before seeding
       the DRBG so that two nodes started simultaneously on the same machine
       cannot share PRNG state even if the system clock is identical.        */
    unsigned char pers[32];
    if (mbedtls_entropy_func(&entropy, pers, sizeof(pers)) != 0) {
        fprintf(stderr, "[gordian] entropy failure — cannot generate key\n");
        return false;
    }
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 pers, sizeof(pers));
    mbedtls_platform_zeroize(pers, sizeof(pers));
    if (ret != 0) return false;

    /* Generate ECDSA P-256 key */
    ret = mbedtls_pk_setup(&pk_key,
                           mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return false;

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_pk_ec(pk_key),
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) return false;

    /* Write self-signed certificate */
    mbedtls_x509write_cert crt_write;
    mbedtls_x509write_crt_init(&crt_write);
    mbedtls_x509write_crt_set_subject_key(&crt_write, &pk_key);
    mbedtls_x509write_crt_set_issuer_key(&crt_write, &pk_key);
    mbedtls_x509write_crt_set_subject_name(&crt_write, "CN=GordianNet");
    mbedtls_x509write_crt_set_issuer_name(&crt_write, "CN=GordianNet");
    mbedtls_x509write_crt_set_version(&crt_write, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt_write, MBEDTLS_MD_SHA256);

    /* Random 64-bit serial number (H-7), MSB cleared for positive integer
       per RFC 5280 §4.1.2.2, LSB set to guarantee non-zero.               */
    uint8_t serial_bytes[8];
    mbedtls_ctr_drbg_random(&ctr_drbg, serial_bytes, sizeof(serial_bytes));
    serial_bytes[0] &= 0x7F;
    serial_bytes[0] |= 0x01;
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_read_binary(&serial, serial_bytes, sizeof(serial_bytes));
    mbedtls_x509write_crt_set_serial(&crt_write, &serial);
    mbedtls_mpi_free(&serial);
    mbedtls_platform_zeroize(serial_bytes, sizeof(serial_bytes));

    /* Short validity window: 1 minute in the past to now + 24 hours (H-2).
       The past offset handles minor clock skew between peers.              */
    {
        time_t t_before = std::time(nullptr) - 60;
        time_t t_after  = std::time(nullptr) + 86400;
        struct tm tm_buf;
        char not_before[16], not_after[16];
        gmtime_r(&t_before, &tm_buf);
        std::strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", &tm_buf);
        gmtime_r(&t_after, &tm_buf);
        std::strftime(not_after,  sizeof(not_after),  "%Y%m%d%H%M%S", &tm_buf);
        mbedtls_x509write_crt_set_validity(&crt_write, not_before, not_after);
    }

    /* DER-encode: data is at tail of the buffer */
    unsigned char cert_der[4096];
    ret = mbedtls_x509write_crt_der(&crt_write, cert_der, sizeof(cert_der),
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&crt_write);
    if (ret <= 0) {
        mbedtls_platform_zeroize(cert_der, sizeof(cert_der));
        return false;
    }

    int cert_len = ret;
    const unsigned char* cert_ptr = cert_der + sizeof(cert_der) - cert_len;

    /* Parse it back so we have an mbedtls_x509_crt to hand to ssl_conf */
    ret = mbedtls_x509_crt_parse_der(&cert, cert_ptr, cert_len);
    mbedtls_platform_zeroize(cert_der, sizeof(cert_der));
    if (ret != 0) return false;

    /* Compute SHA-256 fingerprint of the DER cert */
    ret = mbedtls_sha256_ret(cert.raw.p, cert.raw.len, local_fingerprint_raw, 0);
    if (ret != 0) return false;

    /* Format as "XX:YY:ZZ:..." for the bundle and role comparison */
    local_fingerprint.clear();
    char hex[4];
    for (int i = 0; i < 32; i++) {
        if (i > 0) local_fingerprint += ':';
        snprintf(hex, sizeof(hex), "%02X", local_fingerprint_raw[i]);
        local_fingerprint += hex;
    }

    return true;
}

/* =========================================================================
   verify_peer_fingerprint — call after DTLS handshake completes (C-2)
   Uses constant-time comparison of raw SHA-256 bytes to prevent
   timing side-channel attacks.
   ========================================================================= */
bool GordianNodeImpl::verify_peer_fingerprint()
{
    const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(&ssl);
    if (!peer_cert) {
        fprintf(stderr, "[gordian] no peer certificate presented\n");
        return false;
    }

    uint8_t hash[32];
    if (mbedtls_sha256_ret(peer_cert->raw.p, peer_cert->raw.len, hash, 0) != 0)
        return false;

    /* Constant-time comparison against expected remote fingerprint bytes */
    if (ct_memcmp(hash, remote_fingerprint_raw, 32) != 0) {
        /* Build human-readable form only in the error path — timing here
           does not matter since we are already going to fail.             */
        char computed[96] = {};
        for (int i = 0; i < 32; i++)
            snprintf(computed + i * 3, 4, "%02X%c", hash[i], i < 31 ? ':' : '\0');
        fprintf(stderr, "[gordian] fingerprint mismatch!\n"
                        "  expected: %s\n  got:      %s\n",
                remote_fingerprint.c_str(), computed);
        return false;
    }
    return true;
}

/* =========================================================================
   worker_loop — owns DTLS + KCP lifecycle
   ========================================================================= */
void GordianNodeImpl::worker_loop()
{
    /* ---- Phase 1: wait for ICE to establish a path -------------------- */
    {
        std::unique_lock<std::mutex> lk(incoming_mtx);
        incoming_cv.wait(lk, [this] {
            return ice_connected.load() || stop_worker.load();
        });
    }
    if (stop_worker.load()) return;

    /* ---- Phase 2: DTLS handshake ---------------------------------------- */
    bool dtls_ready = false;
    auto hs_deadline = std::chrono::steady_clock::now()
                     + std::chrono::milliseconds(cfg_handshake_ms);

    while (!stop_worker.load() && !dtls_ready) {
        if (std::chrono::steady_clock::now() > hs_deadline) {
            fire_error(GORDIAN_ERR_CRYPTO, "DTLS handshake timeout");
            fire_state(GORDIAN_STATE_FAILED);
            return;
        }

        int ret = mbedtls_ssl_handshake(&ssl);
        if (ret == 0) {
            /* Verify the remote cert fingerprint from the bundle */
            if (!verify_peer_fingerprint()) {
                fire_error(GORDIAN_ERR_AUTH,
                           "peer certificate fingerprint mismatch");
                fire_state(GORDIAN_STATE_FAILED);
                return;
            }

            /* Initialise KCP over the established DTLS channel */
            kcp = ikcp_create(0, this);
            if (!kcp) {
                fire_state(GORDIAN_STATE_FAILED);
                return;
            }
            kcp->output = kcp_output_cb;
            kcp->stream = 1;                  /* stream mode: no fragment limit   */
            ikcp_nodelay(kcp, 1, 5, 2, 1);   /* nodelay, 5ms, fast resend, no cc */
            ikcp_wndsize(kcp, 256, 256);
            ikcp_setmtu(kcp, 1200);

            dtls_ready = true;
            ready.store(true);
            fire_state(GORDIAN_STATE_READY);

        } else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
            /* DTLS cookie verification (C-3): server sent HelloVerifyRequest,
               client must reset and retry with the cookie.                  */
            mbedtls_ssl_session_reset(&ssl);

        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ
                || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* No data yet — wait up to 5 ms for incoming packets, then
               retry (which acts as implicit DTLS retransmit on the next
               call to mbedtls_ssl_handshake). */
            std::unique_lock<std::mutex> lk(incoming_mtx);
            incoming_cv.wait_for(lk, std::chrono::milliseconds(5), [this] {
                return !incoming_queue.empty() || stop_worker.load();
            });
        } else {
            /* Fatal handshake error */
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fire_error(GORDIAN_ERR_CRYPTO, errbuf);
            fire_state(GORDIAN_STATE_FAILED);
            return;
        }
    }

    /* ---- Phase 3: data loop ------------------------------------------- */
    /* Heap-allocate the DTLS scratch buffer (C-4): must fit the largest
       DTLS plaintext record (up to 16 KB + overhead).                     */
    std::vector<uint8_t> dtls_buf(kDtlsBufSize);
    std::vector<uint8_t> frame_buf;        /* send-side framing scratch      */

    while (!stop_worker.load()) {
        /* Check for DTLS transport errors from kcp_output_cb (H-6) */
        if (dtls_error.load()) {
            ready.store(false);
            fire_state(GORDIAN_STATE_DISCONNECTED);
            return;
        }

        /* Graceful disconnect: send close_notify from the worker thread
           (which owns the SSL context), then exit cleanly. */
        if (disconnect_requested.load()) {
            mbedtls_ssl_close_notify(&ssl);
            ready.store(false);
            fire_state(GORDIAN_STATE_DISCONNECTED);
            return;
        }

        /* Wait for incoming data or a 5 ms KCP tick */
        {
            std::unique_lock<std::mutex> lk(incoming_mtx);
            incoming_cv.wait_for(lk, std::chrono::milliseconds(5), [this] {
                return !incoming_queue.empty() || stop_worker.load()
                    || dtls_error.load() || disconnect_requested.load();
            });
        }
        if (stop_worker.load()) break;

        /* Decrypt incoming DTLS records and feed into KCP */
        while (true) {
            int n = mbedtls_ssl_read(&ssl, dtls_buf.data(), dtls_buf.size());
            if (n > 0) {
                ikcp_input(kcp, reinterpret_cast<const char*>(dtls_buf.data()), n);
            } else if (n == MBEDTLS_ERR_SSL_WANT_READ
                    || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                break;
            } else if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ready.store(false);
                fire_state(GORDIAN_STATE_DISCONNECTED);
                return;
            } else {
                char errbuf[128];
                mbedtls_strerror(n, errbuf, sizeof(errbuf));
                fprintf(stderr, "[gordian] DTLS read error: %s\n", errbuf);
                ready.store(false);
                fire_state(GORDIAN_STATE_DISCONNECTED);
                return;
            }
        }

        /* Tick the KCP clock */
        ikcp_update(kcp, now_ms());

        /* Drain send_queue → KCP with 4-byte length-prefix framing.
           Frame layout: [ uint32_t BE length ][ payload bytes ]      */
        {
            std::lock_guard<std::mutex> lk(send_mtx);
            while (!send_queue.empty()) {
                auto& pkt = send_queue.front();
                uint32_t n = static_cast<uint32_t>(pkt.size());
                frame_buf.resize(4 + pkt.size());
                frame_buf[0] = uint8_t(n >> 24);
                frame_buf[1] = uint8_t(n >> 16);
                frame_buf[2] = uint8_t(n >>  8);
                frame_buf[3] = uint8_t(n);
                std::memcpy(frame_buf.data() + 4, pkt.data(), pkt.size());
                /* ikcp_send rejects calls where ceil(len/mss) >= 128 (IKCP_WND_RCV,
                   hardcoded in ikcp.c) even in stream mode.  Chunk to stay under. */
                const int max_chunk = 127 * static_cast<int>(kcp->mss);
                const char* ptr = reinterpret_cast<const char*>(frame_buf.data());
                int remaining   = static_cast<int>(frame_buf.size());
                while (remaining > 0) {
                    int chunk = std::min(remaining, max_chunk);
                    int sr = ikcp_send(kcp, ptr, chunk);
                    if (sr < 0) {
                        fprintf(stderr, "[gordian] ikcp_send failed: %d\n", sr);
                        dtls_error.store(true);
                        break;
                    }
                    ptr       += chunk;
                    remaining -= chunk;
                }
                send_queue_bytes -= pkt.size();
                send_queue.pop();
            }
        }

        /* Flush KCP → kcp_output_cb → mbedtls_ssl_write → juice_send */
        ikcp_flush(kcp);

        /* Accumulate incoming KCP bytes into recv_accum (offset-based to
           avoid O(N) front-erase, L-8).  ikcp_recv in stream mode returns
           however many bytes are ready, so we collect and parse frames.   */
        while (true) {
            int n = ikcp_recv(kcp,
                              reinterpret_cast<char*>(dtls_buf.data()),
                              static_cast<int>(dtls_buf.size()));
            if (n <= 0) break;
            recv_accum.insert(recv_accum.end(),
                              dtls_buf.data(), dtls_buf.data() + n);
            /* Guard (C-7): cap recv_accum to prevent OOM from a peer
               flooding small valid frames faster than we can deliver.  */
            if (recv_accum.size() > kMaxRecvAccumBytes) {
                fire_error(GORDIAN_ERR_INTERNAL,
                           "recv accumulation buffer exceeded limit");
                ready.store(false);
                fire_state(GORDIAN_STATE_FAILED);
                return;
            }
        }

        /* Parse and deliver complete frames from recv_accum[recv_offset..] */
        while (recv_accum.size() - recv_offset >= 4) {
            const uint8_t* hdr = recv_accum.data() + recv_offset;
            uint32_t msg_len = (uint32_t(hdr[0]) << 24)
                             | (uint32_t(hdr[1]) << 16)
                             | (uint32_t(hdr[2]) <<  8)
                             |  uint32_t(hdr[3]);

            /* NOTE (C-5): reject msg_len >= cap immediately so recv_accum
               cannot grow unboundedly while waiting for a huge fake frame. */
            if (msg_len >= cfg_max_msg_size) {
                fire_error(GORDIAN_ERR_MSG_TOO_LARGE,
                           "peer sent frame exceeding max_message_size");
                ready.store(false);
                fire_state(GORDIAN_STATE_FAILED);
                return;
            }

            if (recv_accum.size() - recv_offset < 4 + msg_len)
                break; /* incomplete frame — wait for more data */

            if (recv_cb)
                recv_cb(recv_accum.data() + recv_offset + 4, msg_len, user_data);

            recv_offset += 4 + msg_len;

            /* Compact recv_accum when the consumed prefix exceeds 64 KB and
               is at least half the buffer — amortises the erase cost (L-8). */
            if (recv_offset > 65536 && recv_offset >= recv_accum.size() / 2) {
                recv_accum.erase(recv_accum.begin(),
                                 recv_accum.begin() + recv_offset);
                recv_accum.shrink_to_fit();
                recv_offset = 0;
            }
        }
    }
}

/* =========================================================================
   start() — generate identity, create juice agent, begin ICE gathering
   ========================================================================= */
GordianError GordianNodeImpl::start()
{
    if (started.exchange(true)) return GORDIAN_ERR_MISUSE;

    if (!gen_cert_and_key()) {
        fire_error(GORDIAN_ERR_CRYPTO, "certificate generation failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_CRYPTO;
    }

    juice_config_t jcfg = {};
    jcfg.concurrency_mode  = JUICE_CONCURRENCY_MODE_THREAD;
    jcfg.stun_server_host  = cfg_stun_host.c_str();
    jcfg.stun_server_port  = cfg_stun_port;
    jcfg.cb_state_changed  = cb_state_changed;
    jcfg.cb_candidate      = cb_candidate;
    jcfg.cb_gathering_done = cb_gathering_done;
    jcfg.cb_recv           = cb_recv;
    jcfg.user_ptr          = this;

    agent = juice_create(&jcfg);
    if (!agent) {
        fire_error(GORDIAN_ERR_ICE, "juice_create failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_ICE;
    }

    if (juice_gather_candidates(agent) < 0) {
        fire_error(GORDIAN_ERR_ICE, "juice_gather_candidates failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_ICE;
    }

    return GORDIAN_OK;
}


/* =========================================================================
   connect() — decode bundle, configure DTLS, start worker
   ========================================================================= */
GordianError GordianNodeImpl::connect(const std::string& b64)
{
    if (!agent) {
        fire_error(GORDIAN_ERR_MISUSE, "connect called before start()");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_MISUSE;
    }

    if (connected.exchange(true)) return GORDIAN_ERR_MISUSE;

    std::string bundle_text = base64_decode(b64);
    if (bundle_text.empty()) {
        fire_error(GORDIAN_ERR_INVALID_BUNDLE, "base64 decode failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_INVALID_BUNDLE;
    }

    /* Split on fingerprint line */
    const std::string fp_marker = "\na=fingerprint:sha-256 ";
    size_t fp_pos = bundle_text.find(fp_marker);
    if (fp_pos == std::string::npos) {
        fire_error(GORDIAN_ERR_INVALID_BUNDLE, "bundle missing fingerprint");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_INVALID_BUNDLE;
    }

    std::string remote_sdp = bundle_text.substr(0, fp_pos);
    std::string fp_tail    = bundle_text.substr(fp_pos + fp_marker.size());

    /* Extract fingerprint up to the next newline (M-4 validation below) */
    size_t nl = fp_tail.find('\n');
    remote_fingerprint = (nl != std::string::npos)
                       ? fp_tail.substr(0, nl)
                       : fp_tail;

    /* Validate fingerprint format: exactly "XX:YY:..." × 32 (M-4) */
    auto valid_fp = [](const std::string& fp) -> bool {
        if (fp.size() != 95) return false;
        for (int i = 0; i < 32; i++) {
            int base = i * 3;
            if (!isxdigit((unsigned char)fp[base  ]) ||
                !isxdigit((unsigned char)fp[base+1])) return false;
            if (i < 31 && fp[base+2] != ':') return false;
        }
        return true;
    };
    if (!valid_fp(remote_fingerprint)) {
        fire_error(GORDIAN_ERR_INVALID_BUNDLE, "invalid fingerprint format");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_INVALID_BUNDLE;
    }

    /* Decode hex fingerprint string to raw bytes for constant-time compare */
    for (int i = 0; i < 32; i++) {
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            return 0;
        };
        remote_fingerprint_raw[i] =
            static_cast<uint8_t>((nib(remote_fingerprint[i*3]) << 4) |
                                  nib(remote_fingerprint[i*3+1]));
    }

    /* Detect equal fingerprints early — cannot determine DTLS role (M-2) */
    if (local_fingerprint == remote_fingerprint) {
        fire_error(GORDIAN_ERR_AUTH, "fingerprint collision");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_AUTH;
    }

    /* Feed ICE description to libjuice */
    if (juice_set_remote_description(agent, remote_sdp.c_str()) < 0) {
        fire_error(GORDIAN_ERR_ICE, "juice_set_remote_description failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_ICE;
    }
    /* Signal that all remote candidates are already bundled */
    juice_set_remote_gathering_done(agent);

    /* Determine DTLS role: lexicographically larger fingerprint → client */
    bool is_client = (local_fingerprint > remote_fingerprint);
    int  endpoint  = is_client ? MBEDTLS_SSL_IS_CLIENT
                               : MBEDTLS_SSL_IS_SERVER;

    /* Configure DTLS 1.2 */
    int ret = mbedtls_ssl_config_defaults(&ssl_conf, endpoint,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        fire_error(GORDIAN_ERR_CRYPTO, "mbedtls_ssl_config_defaults failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_CRYPTO;
    }

    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* Restrict to ECDHE-ECDSA + AEAD cipher suites only (H-4) */
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, kAllowedCiphersuites);

    /* Enforce DTLS 1.2 minimum — no fallback to older versions (H-4) */
    mbedtls_ssl_conf_min_version(&ssl_conf,
                                  MBEDTLS_SSL_MAJOR_VERSION_3,
                                  MBEDTLS_SSL_MINOR_VERSION_3);

    /* Disable renegotiation — prevents cert swap after handshake (H-3) */
    mbedtls_ssl_conf_renegotiation(&ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);

    /* Disable session resumption and tickets — would bypass fingerprint
       verification on a resumed session (M-1)                           */
    mbedtls_ssl_conf_session_tickets(&ssl_conf,
                                      MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    mbedtls_ssl_conf_session_cache(&ssl_conf, nullptr, nullptr, nullptr);

    /* OPTIONAL: request peer cert (needed so server gets client cert),
       but don't abort on chain-verification failure (self-signed).
       We verify the fingerprint ourselves after handshake.             */
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    /* Our own certificate + private key */
    ret = mbedtls_ssl_conf_own_cert(&ssl_conf, &cert, &pk_key);
    if (ret != 0) {
        fire_error(GORDIAN_ERR_CRYPTO, "mbedtls_ssl_conf_own_cert failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_CRYPTO;
    }

    /* No CA chain — we authenticate via DTLS fingerprint, not PKI */
    mbedtls_ssl_conf_ca_chain(&ssl_conf, nullptr, nullptr);

    /* DTLS cookies disabled: the ICE layer already establishes a verified
       peer-to-peer path, making cookie-based DoS protection redundant.
       mbedtls_ssl_cookie requires mbedtls_ssl_set_client_transport_id()
       which cannot be meaningfully provided through the ICE tunnel.     */
    mbedtls_ssl_conf_dtls_cookies(&ssl_conf, nullptr, nullptr, nullptr);

    /* Retransmit: start at 100 ms, cap at 2 s */
    mbedtls_ssl_conf_handshake_timeout(&ssl_conf, 100, 2000);

    /* Set up the DTLS session */
    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    if (ret != 0) {
        fire_error(GORDIAN_ERR_CRYPTO, "mbedtls_ssl_setup failed");
        fire_state(GORDIAN_STATE_FAILED);
        return GORDIAN_ERR_CRYPTO;
    }

    /* DTLS requires a monotonic timer for retransmit state */
    mbedtls_ssl_set_timer_cb(&ssl, &dtls_timer,
                              mbedtls_timing_set_delay,
                              mbedtls_timing_get_delay);

    /* Hook up our BIO callbacks.  dtls_recv_timeout drives DTLS retransmit;
       it only returns SSL_TIMEOUT when a flight exists AND the timer has
       expired, preventing the NULL-flight crash on the server side.        */
    mbedtls_ssl_set_bio(&ssl, this,
                         dtls_send, dtls_recv, dtls_recv_timeout);

    /* Launch the worker thread (it will wait for ICE first) */
    worker_thread = std::thread([this]() { worker_loop(); });
    return GORDIAN_OK;
}


/* =========================================================================
   send() — callable from any thread, enqueues to send_queue
   ========================================================================= */
GordianError GordianNodeImpl::send(const uint8_t* data, size_t size)
{
    if (!data || size == 0) return GORDIAN_ERR_MISUSE;
    if (size >= cfg_max_msg_size) return GORDIAN_ERR_MSG_TOO_LARGE;
    std::lock_guard<std::mutex> lk(send_mtx);
    if (!ready.load()) return GORDIAN_ERR_MISUSE;
    if (send_queue_bytes + size > cfg_max_send_q) return GORDIAN_ERR_QUEUE_FULL;
    send_queue.emplace(data, data + size);
    send_queue_bytes += size;
    return GORDIAN_OK;
}


/* =========================================================================
   disconnect() — graceful DTLS teardown from application thread
   ========================================================================= */
GordianError GordianNodeImpl::disconnect(uint32_t timeout_ms)
{
    if (!ready.load() && !worker_thread.joinable())
        return GORDIAN_ERR_MISUSE;

    disconnect_requested.store(true);
    incoming_cv.notify_all();

    if (timeout_ms > 0 && worker_thread.joinable()) {
        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::milliseconds(timeout_ms);
        /* Spin-wait with short sleeps for the worker to finish its
           close_notify and exit cleanly. */
        while (worker_thread.joinable() && ready.load()) {
            if (std::chrono::steady_clock::now() >= deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    return GORDIAN_OK;
}

/* =========================================================================
   C API bridge
   ========================================================================= */
extern "C" {

GordianNode* gordian_create(const GordianConfig* cfg)
{
    auto* node = new GordianNode{};
    if (cfg) {
        auto& impl = node->impl;
        if (cfg->stun_server_host)     impl.cfg_stun_host    = cfg->stun_server_host;
        if (cfg->stun_server_port)     impl.cfg_stun_port    = cfg->stun_server_port;
        if (cfg->handshake_timeout_ms) impl.cfg_handshake_ms = cfg->handshake_timeout_ms;
        if (cfg->max_message_size)     impl.cfg_max_msg_size = cfg->max_message_size;
        if (cfg->max_send_queue_bytes) impl.cfg_max_send_q   = cfg->max_send_queue_bytes;
    }
    return node;
}

void gordian_destroy(GordianNode* node)
{
    delete node;
}

void gordian_set_callbacks(GordianNode*         node,
                           GordianCredsCallback cred_cb,
                           GordianStateCallback state_cb,
                           GordianRecvCallback  recv_cb,
                           GordianErrorCallback error_cb,
                           void*                user_data)
{
    if (!node) return;
    node->impl.cred_cb   = cred_cb;
    node->impl.state_cb  = state_cb;
    node->impl.recv_cb   = recv_cb;
    node->impl.error_cb  = error_cb;
    node->impl.user_data = user_data;
}

GordianError gordian_start(GordianNode* node)
{
    if (!node) return GORDIAN_ERR_MISUSE;
    return node->impl.start();
}

GordianError gordian_connect(GordianNode* node, const char* bundle)
{
    if (!node || !bundle) return GORDIAN_ERR_MISUSE;
    if (std::strlen(bundle) > 65536) return GORDIAN_ERR_INVALID_BUNDLE;
    return node->impl.connect(bundle);
}

GordianError gordian_send(GordianNode* node, const uint8_t* data, size_t len)
{
    if (!node) return GORDIAN_ERR_MISUSE;
    return node->impl.send(data, len);
}

GordianError gordian_disconnect(GordianNode* node, uint32_t timeout_ms)
{
    if (!node) return GORDIAN_ERR_MISUSE;
    return node->impl.disconnect(timeout_ms);
}

GordianState gordian_state(const GordianNode* node)
{
    if (!node) return GORDIAN_STATE_FAILED;
    return node->impl.current_state.load();
}

const char* gordian_errstr(GordianError err)
{
    switch (err) {
    case GORDIAN_OK:                return "ok";
    case GORDIAN_ERR_MISUSE:        return "misuse (NULL param or wrong call order)";
    case GORDIAN_ERR_INVALID_BUNDLE:return "invalid bundle";
    case GORDIAN_ERR_CRYPTO:        return "cryptographic failure";
    case GORDIAN_ERR_ICE:           return "ICE/STUN failure";
    case GORDIAN_ERR_AUTH:          return "peer authentication failed";
    case GORDIAN_ERR_QUEUE_FULL:    return "send queue full";
    case GORDIAN_ERR_MSG_TOO_LARGE: return "message too large";
    case GORDIAN_ERR_INTERNAL:      return "internal error";
    }
    return "unknown error";
}

} /* extern "C" */
