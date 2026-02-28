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
#include <algorithm>

/* mbedTLS extras needed in the .cpp */
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
/* x509write functions are in x509_crt.h (same header as x509_crt types) */

/* =========================================================================
   Time helper — millisecond clock for KCP
   ========================================================================= */
static uint32_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
            .count() & 0xFFFFFFFFu);
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

std::string GordianNodeImpl::base64_decode(const std::string& in)
{
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)kB64Chars[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
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
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_key);
    mbedtls_x509_crt_init(&cert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
}

GordianNodeImpl::~GordianNodeImpl()
{
    /* 1. Signal worker to stop and wait for it */
    stop_worker.store(true);
    incoming_cv.notify_all();
    if (worker_thread.joinable())
        worker_thread.join();

    /* 2. Release KCP (worker is done — no more concurrent access) */
    if (kcp) {
        ikcp_release(kcp);
        kcp = nullptr;
    }

    /* 3. Free mbedTLS resources */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&pk_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    /* 4. Destroy juice agent (stops its internal thread + callbacks) */
    if (agent) {
        juice_destroy(agent);
        agent = nullptr;
    }
}

/* =========================================================================
   fire_state — thread-safe
   ========================================================================= */
void GordianNodeImpl::fire_state(GordianState s)
{
    current_state.store(s);
    if (state_cb) state_cb(s, user_data);
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
    return static_cast<int>(len);
}

/* Non-blocking recv: pop one datagram from incoming_queue or return WANT_READ */
int GordianNodeImpl::dtls_recv(void* ctx, unsigned char* buf, size_t len)
{
    auto* self = static_cast<GordianNodeImpl*>(ctx);
    std::lock_guard<std::mutex> lk(self->incoming_mtx);
    if (self->incoming_queue.empty())
        return MBEDTLS_ERR_SSL_WANT_READ;
    auto pkt = std::move(self->incoming_queue.front());
    self->incoming_queue.pop();
    size_t n = std::min(len, pkt.size());
    std::memcpy(buf, pkt.data(), n);
    return static_cast<int>(n);
}

/* Blocking recv with timeout (used by DTLS handshake for retransmit logic).
   We cap the wait at 5 ms so the worker loop stays responsive. */
int GordianNodeImpl::dtls_recv_timeout(void* ctx, unsigned char* buf,
                                       size_t len, uint32_t timeout_ms)
{
    auto* self = static_cast<GordianNodeImpl*>(ctx);
    std::unique_lock<std::mutex> lk(self->incoming_mtx);
    if (self->incoming_queue.empty()) {
        /* Cap wait to 5 ms regardless of what mbedTLS asks for */
        uint32_t wait = std::min(timeout_ms, uint32_t{5});
        if (wait > 0) {
            self->incoming_cv.wait_for(
                lk, std::chrono::milliseconds(wait),
                [self] {
                    return !self->incoming_queue.empty()
                        || self->stop_worker.load();
                });
        }
    }
    if (self->incoming_queue.empty())
        return MBEDTLS_ERR_SSL_TIMEOUT;
    auto pkt = std::move(self->incoming_queue.front());
    self->incoming_queue.pop();
    size_t n = std::min(len, pkt.size());
    std::memcpy(buf, pkt.data(), n);
    return static_cast<int>(n);
}

/* =========================================================================
   KCP output callback — encrypts via DTLS → sends via libjuice
   ========================================================================= */
int GordianNodeImpl::kcp_output_cb(const char* buf, int len,
                                   ikcpcb* /*kcp*/, void* user)
{
    auto* self = static_cast<GordianNodeImpl*>(user);
    mbedtls_ssl_write(&self->ssl,
                      reinterpret_cast<const unsigned char*>(buf),
                      static_cast<size_t>(len));
    return 0;  /* return value is ignored by ikcp internal code */
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

    /* Get the full local SDP (ufrag + pwd + all candidates) */
    char sdp_buf[JUICE_MAX_SDP_STRING_LEN];
    if (juice_get_local_description(agent, sdp_buf, sizeof(sdp_buf)) < 0)
        return;

    /* Bundle = SDP + fingerprint attribute + base64 */
    std::string bundle_text = sdp_buf;
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

    /* Seed the PRNG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 reinterpret_cast<const unsigned char*>("gordiannet"),
                                 10);
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

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 1);
    mbedtls_x509write_crt_set_serial(&crt_write, &serial);
    mbedtls_mpi_free(&serial);

    mbedtls_x509write_crt_set_validity(&crt_write,
                                        "20200101000000", "20990101000000");

    /* DER-encode: data is at tail of the buffer */
    unsigned char cert_der[4096];
    ret = mbedtls_x509write_crt_der(&crt_write, cert_der, sizeof(cert_der),
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&crt_write);
    if (ret <= 0) return false;

    int cert_len = ret;
    const unsigned char* cert_ptr = cert_der + sizeof(cert_der) - cert_len;

    /* Parse it back so we have an mbedtls_x509_crt to hand to ssl_conf */
    ret = mbedtls_x509_crt_parse_der(&cert, cert_ptr, cert_len);
    if (ret != 0) return false;

    /* Compute SHA-256 fingerprint of the DER cert */
    unsigned char hash[32];
    ret = mbedtls_sha256_ret(cert.raw.p, cert.raw.len, hash, 0 /*is224=false*/);
    if (ret != 0) return false;

    /* Format as "XX:YY:ZZ:..." */
    local_fingerprint.clear();
    char hex[4];
    for (int i = 0; i < 32; i++) {
        if (i > 0) local_fingerprint += ':';
        snprintf(hex, sizeof(hex), "%02X", hash[i]);
        local_fingerprint += hex;
    }

    return true;
}

/* =========================================================================
   verify_peer_fingerprint — call after DTLS handshake completes
   ========================================================================= */
bool GordianNodeImpl::verify_peer_fingerprint()
{
    const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(&ssl);
    if (!peer_cert) {
        fprintf(stderr, "[gordian] no peer certificate presented\n");
        return false;
    }

    unsigned char hash[32];
    if (mbedtls_sha256_ret(peer_cert->raw.p, peer_cert->raw.len, hash, 0) != 0)
        return false;

    std::string computed;
    char hex[4];
    for (int i = 0; i < 32; i++) {
        if (i > 0) computed += ':';
        snprintf(hex, sizeof(hex), "%02X", hash[i]);
        computed += hex;
    }

    if (computed != remote_fingerprint) {
        fprintf(stderr, "[gordian] fingerprint mismatch!\n"
                        "  expected: %s\n  got:      %s\n",
                remote_fingerprint.c_str(), computed.c_str());
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

    /* ---- Phase 2: DTLS handshake -------------------------------------- */
    bool dtls_ready = false;
    while (!stop_worker.load() && !dtls_ready) {
        int ret = mbedtls_ssl_handshake(&ssl);
        if (ret == 0) {
            /* Verify the remote cert fingerprint from the bundle */
            if (!verify_peer_fingerprint()) {
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
            ikcp_nodelay(kcp, 1, 5, 2, 1);   /* nodelay, 5ms, fast resend, no cc */
            ikcp_wndsize(kcp, 256, 256);
            ikcp_setmtu(kcp, 1200);

            dtls_ready = true;
            ready.store(true);
            fire_state(GORDIAN_STATE_READY);

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
            fprintf(stderr, "[gordian] DTLS handshake error: %s\n", errbuf);
            fire_state(GORDIAN_STATE_FAILED);
            return;
        }
    }

    /* ---- Phase 3: data loop ------------------------------------------- */
    uint8_t dtls_buf[4096];

    while (!stop_worker.load()) {
        /* Wait for incoming data or a 5 ms KCP tick */
        {
            std::unique_lock<std::mutex> lk(incoming_mtx);
            incoming_cv.wait_for(lk, std::chrono::milliseconds(5), [this] {
                return !incoming_queue.empty() || stop_worker.load();
            });
        }
        if (stop_worker.load()) break;

        /* Decrypt incoming DTLS records and feed into KCP */
        while (true) {
            int n = mbedtls_ssl_read(&ssl, dtls_buf, sizeof(dtls_buf));
            if (n > 0) {
                ikcp_input(kcp, reinterpret_cast<const char*>(dtls_buf), n);
            } else if (n == MBEDTLS_ERR_SSL_WANT_READ
                    || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                break;  /* no more records available right now */
            } else if (n == 0
                    || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ready.store(false);
                fire_state(GORDIAN_STATE_DISCONNECTED);
                return;
            } else {
                /* Other errors (e.g. record MAC failure) — keep going */
                break;
            }
        }

        /* Tick the KCP clock */
        ikcp_update(kcp, now_ms());

        /* Drain send_queue → KCP */
        {
            std::lock_guard<std::mutex> lk(send_mtx);
            while (!send_queue.empty()) {
                auto& pkt = send_queue.front();
                ikcp_send(kcp, reinterpret_cast<const char*>(pkt.data()),
                          static_cast<int>(pkt.size()));
                send_queue.pop();
            }
        }

        /* Flush KCP → calls kcp_output_cb → mbedtls_ssl_write → juice_send */
        ikcp_flush(kcp);

        /* Deliver reassembled application data to the caller */
        while (true) {
            int n = ikcp_recv(kcp, reinterpret_cast<char*>(dtls_buf),
                              static_cast<int>(sizeof(dtls_buf)));
            if (n <= 0) break;
            if (recv_cb)
                recv_cb(dtls_buf, static_cast<size_t>(n), user_data);
        }
    }
}

/* =========================================================================
   start() — generate identity, create juice agent, begin ICE gathering
   ========================================================================= */
void GordianNodeImpl::start()
{
    if (!gen_cert_and_key()) {
        fire_state(GORDIAN_STATE_FAILED);
        return;
    }

    juice_config_t cfg = {};
    cfg.concurrency_mode  = JUICE_CONCURRENCY_MODE_THREAD;
    cfg.stun_server_host  = "stun.l.google.com";
    cfg.stun_server_port  = 19302;
    cfg.cb_state_changed  = cb_state_changed;
    cfg.cb_candidate      = cb_candidate;
    cfg.cb_gathering_done = cb_gathering_done;
    cfg.cb_recv           = cb_recv;
    cfg.user_ptr          = this;

    agent = juice_create(&cfg);
    if (!agent) {
        fire_state(GORDIAN_STATE_FAILED);
        return;
    }

    juice_gather_candidates(agent);
}

/* =========================================================================
   connect_remote() — decode bundle, configure DTLS, start worker
   ========================================================================= */
void GordianNodeImpl::connect_remote(const std::string& b64)
{
    std::string bundle_text = base64_decode(b64);

    /* Split on fingerprint line */
    const std::string fp_marker = "\na=fingerprint:sha-256 ";
    size_t fp_pos = bundle_text.find(fp_marker);
    if (fp_pos == std::string::npos) {
        fprintf(stderr, "[gordian] bundle missing fingerprint\n");
        fire_state(GORDIAN_STATE_FAILED);
        return;
    }

    std::string remote_sdp  = bundle_text.substr(0, fp_pos);
    std::string fp_tail     = bundle_text.substr(fp_pos + fp_marker.size());
    remote_fingerprint      = fp_tail.substr(0, fp_tail.find('\n'));

    /* Feed ICE description to libjuice */
    if (juice_set_remote_description(agent, remote_sdp.c_str()) < 0) {
        fprintf(stderr, "[gordian] juice_set_remote_description failed\n");
        fire_state(GORDIAN_STATE_FAILED);
        return;
    }
    /* Signal that all remote candidates are already bundled */
    juice_set_remote_gathering_done(agent);

    /* Determine DTLS role: lexicographically larger fingerprint → client */
    bool is_client = (local_fingerprint > remote_fingerprint);
    int  endpoint  = is_client ? MBEDTLS_SSL_IS_CLIENT
                               : MBEDTLS_SSL_IS_SERVER;

    /* Configure DTLS 1.2 */
    mbedtls_ssl_config_defaults(&ssl_conf, endpoint,
                                 MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* OPTIONAL: request peer cert (needed so server gets client cert),
       but don't abort on chain-verification failure (self-signed).
       We verify the fingerprint ourselves after handshake. */
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    /* Our own certificate + private key */
    mbedtls_ssl_conf_own_cert(&ssl_conf, &cert, &pk_key);

    /* No CA chain — we authenticate via DTLS fingerprint, not PKI */
    mbedtls_ssl_conf_ca_chain(&ssl_conf, nullptr, nullptr);

    /* Disable DTLS cookies (P2P, no DoS concern) */
    mbedtls_ssl_conf_dtls_cookies(&ssl_conf, nullptr, nullptr, nullptr);

    /* Retransmit: start at 100 ms, cap at 2 s (our BIO caps wait at 5 ms
       anyway, so effective retransmit is driven by the BIO timeout). */
    mbedtls_ssl_conf_handshake_timeout(&ssl_conf, 100, 2000);

    /* Set up the DTLS session */
    mbedtls_ssl_setup(&ssl, &ssl_conf);

    /* DTLS requires a monotonic timer for retransmit state */
    mbedtls_ssl_set_timer_cb(&ssl, &dtls_timer,
                              mbedtls_timing_set_delay,
                              mbedtls_timing_get_delay);

    /* Hook up our BIO callbacks.
       We omit f_recv_timeout (pass NULL) to prevent mbedTLS from triggering
       automatic retransmit via mbedtls_ssl_resend.  The worker loop calls
       mbedtls_ssl_handshake in a tight 5-ms loop, so retransmit is implicit:
       the next iteration re-sends the flight when data doesn't arrive. */
    mbedtls_ssl_set_bio(&ssl, this,
                         dtls_send, dtls_recv, nullptr);

    /* Launch the worker thread (it will wait for ICE first) */
    worker_thread = std::thread([this]() { worker_loop(); });
}

/* =========================================================================
   send() — callable from any thread
   ========================================================================= */
bool GordianNodeImpl::send(const uint8_t* data, size_t size)
{
    if (!ready.load()) return false;
    std::lock_guard<std::mutex> lk(send_mtx);
    send_queue.emplace(data, data + size);
    return true;
}

/* =========================================================================
   C API bridge
   ========================================================================= */
extern "C" {

GordianNode* gordian_node_create(void)
{
    return new GordianNode{};
}

void gordian_node_destroy(GordianNode* node)
{
    delete node;
}

void gordian_node_set_callbacks(GordianNode*           node,
                                GordianCredsCallback   cred_cb,
                                GordianStateCallback   state_cb,
                                GordianReceiveCallback recv_cb,
                                void*                  user_data)
{
    if (!node) return;
    node->impl.cred_cb   = cred_cb;
    node->impl.state_cb  = state_cb;
    node->impl.recv_cb   = recv_cb;
    node->impl.user_data = user_data;
}

void gordian_node_start(GordianNode* node)
{
    if (!node) return;
    node->impl.start();
}

void gordian_node_connect(GordianNode* node, const char* remote_candidates)
{
    if (!node || !remote_candidates) return;
    node->impl.connect_remote(remote_candidates);
}

bool gordian_node_send(GordianNode* node, const uint8_t* data, size_t size)
{
    if (!node) return false;
    return node->impl.send(data, size);
}

} /* extern "C" */
