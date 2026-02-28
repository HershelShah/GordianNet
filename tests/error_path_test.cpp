/*
 * tests/error_path_test.cpp
 *
 * Error-path coverage: exercises invalid inputs, wrong-state calls, and
 * boundary conditions through the public C99 API.
 *
 * Exit 0 on all-pass, 1 on any failure.
 */

#include "gordian_net.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <vector>

/* ---- per-node helper state ---------------------------------------------- */

struct NodeCtx {
    GordianNode*            node         = nullptr;
    std::string             bundle;
    std::mutex              mtx;
    std::condition_variable cv;
    bool                    bundle_ready = false;
    std::atomic<bool>       ready{false};
    std::atomic<bool>       failed{false};
};

static void ctx_cred_cb(const char* b64, void* ud)
{
    auto* c = static_cast<NodeCtx*>(ud);
    std::lock_guard<std::mutex> lk(c->mtx);
    c->bundle       = b64;
    c->bundle_ready = true;
    c->cv.notify_all();
}

static void ctx_state_cb(GordianState st, void* ud)
{
    auto* c = static_cast<NodeCtx*>(ud);
    if (st == GORDIAN_STATE_READY)        c->ready.store(true);
    if (st == GORDIAN_STATE_FAILED)       c->failed.store(true);
    if (st == GORDIAN_STATE_DISCONNECTED) c->failed.store(true);
}

static void ctx_recv_cb(const uint8_t*, size_t, void*) { /* unused */ }

static bool wait_bundle(NodeCtx& c, int timeout_s)
{
    std::unique_lock<std::mutex> lk(c.mtx);
    return c.cv.wait_for(lk, std::chrono::seconds(timeout_s),
                         [&]{ return c.bundle_ready; });
}

/* Start a node and wait for its bundle. Returns true on success. */
static bool start_and_get_bundle(NodeCtx& c)
{
    c.node = gordian_create(NULL);
    if (!c.node) return false;
    gordian_set_callbacks(c.node, ctx_cred_cb, ctx_state_cb,
                          ctx_recv_cb, NULL, &c);
    GordianError e = gordian_start(c.node);
    if (e != GORDIAN_OK) return false;
    return wait_bundle(c, 15);
}

/* ---- test harness ------------------------------------------------------- */

static int g_pass = 0;
static int g_fail = 0;

static void check(const char* name, bool cond)
{
    if (cond) {
        printf("  PASS  %s\n", name);
        ++g_pass;
    } else {
        printf("  FAIL  %s\n", name);
        ++g_fail;
    }
}

/* ---- helpers for bundle manipulation ------------------------------------ */

/* Minimal base64 encode/decode (sufficient for bundle twiddling). */
static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_encode(const std::string& in)
{
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string b64_decode(const std::string& in)
{
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)b64_chars[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

/* Strip the fingerprint portion from a decoded bundle, returning just SDP. */
static std::string strip_fingerprint(const std::string& decoded)
{
    auto pos = decoded.find("\na=fingerprint:sha-256 ");
    if (pos == std::string::npos) return decoded;
    return decoded.substr(0, pos);
}

/* Extract the fingerprint hex string from a decoded bundle. */
static std::string extract_fingerprint(const std::string& decoded)
{
    const std::string tag = "\na=fingerprint:sha-256 ";
    auto pos = decoded.find(tag);
    if (pos == std::string::npos) return {};
    auto start = pos + tag.size();
    auto end   = decoded.find('\n', start);
    if (end == std::string::npos) end = decoded.size();
    return decoded.substr(start, end - start);
}

/* ---- tests -------------------------------------------------------------- */

int main()
{
    printf("=== GordianNet error-path tests ===\n\n");

    /* -- Spin up a node whose bundle we can reuse for connect_ex tests -- */
    NodeCtx src;
    if (!start_and_get_bundle(src)) {
        fprintf(stderr, "FATAL: could not start source node\n");
        return 1;
    }
    std::string decoded_bundle = b64_decode(src.bundle);
    std::string sdp_only       = strip_fingerprint(decoded_bundle);
    std::string real_fp        = extract_fingerprint(decoded_bundle);

    /* ================================================================== */
    printf("[1] Garbage base64 → INVALID_BUNDLE\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        GordianError e = gordian_connect(n.node, "~~~not-base64!!!");
        check("connect_ex returns INVALID_BUNDLE", e == GORDIAN_ERR_INVALID_BUNDLE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[2] Valid base64 but no fingerprint → INVALID_BUNDLE\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        std::string no_fp = b64_encode(sdp_only);
        GordianError e = gordian_connect(n.node, no_fp.c_str());
        check("connect_ex returns INVALID_BUNDLE", e == GORDIAN_ERR_INVALID_BUNDLE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[3] Malformed fingerprint (wrong length) → INVALID_BUNDLE\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        std::string bad = sdp_only + "\na=fingerprint:sha-256 AA:BB:CC\n";
        std::string enc = b64_encode(bad);
        GordianError e = gordian_connect(n.node, enc.c_str());
        check("connect_ex returns INVALID_BUNDLE", e == GORDIAN_ERR_INVALID_BUNDLE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[4] Double-start → ALREADY_STARTED\n");
    {
        NodeCtx n;
        n.node = gordian_create(NULL);
        gordian_set_callbacks(n.node, ctx_cred_cb, ctx_state_cb,
                              ctx_recv_cb, NULL, &n);
        GordianError e1 = gordian_start(n.node);
        GordianError e2 = gordian_start(n.node);
        check("first start OK",            e1 == GORDIAN_OK);
        check("second start ALREADY_STARTED", e2 == GORDIAN_ERR_MISUSE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[5] Send before READY → send returns error\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        const uint8_t msg[] = "hello";
        GordianError e = gordian_send(n.node, msg, sizeof(msg) - 1);
        check("send returns error", e != GORDIAN_OK);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[6] Send NULL data → send returns error, no crash\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        GordianError e = gordian_send(n.node, nullptr, 10);
        check("send(NULL) returns error", e != GORDIAN_OK);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[7] Send zero length → send returns error\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        const uint8_t msg[] = "x";
        GordianError e = gordian_send(n.node, msg, 0);
        check("send(len=0) returns error", e != GORDIAN_OK);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[8] Send oversized (17 MiB) → MESSAGE_TOO_LARGE\n");
    {
        NodeCtx n;
        start_and_get_bundle(n);
        size_t big = 17u * 1024u * 1024u;
        std::vector<uint8_t> buf(big, 0x41);
        GordianError e = gordian_send(n.node, buf.data(), buf.size());
        check("send returns MSG_TOO_LARGE",
              e == GORDIAN_ERR_MSG_TOO_LARGE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[9] Connect before start → NOT_STARTED\n");
    {
        NodeCtx n;
        n.node = gordian_create(NULL);
        gordian_set_callbacks(n.node, ctx_cred_cb, ctx_state_cb,
                              ctx_recv_cb, NULL, &n);
        GordianError e = gordian_connect(n.node, src.bundle.c_str());
        check("connect returns MISUSE (not started)", e == GORDIAN_ERR_MISUSE);
        gordian_destroy(n.node);
    }

    /* ================================================================== */
    printf("[10] Destroy without start → no crash\n");
    {
        GordianNode* n = gordian_create(NULL);
        gordian_destroy(n);
        check("destroy-only did not crash", true);
    }

    /* ================================================================== */
    printf("[11] Tampered fingerprint → INVALID_BUNDLE\n");
    {
        /* Start a second node to get a structurally valid bundle. */
        NodeCtx donor;
        start_and_get_bundle(donor);
        std::string raw = b64_decode(donor.bundle);
        std::string fp  = extract_fingerprint(raw);

        /* Replace the first hex char with 'Z' (non-hex) to break format. */
        std::string bad_fp = fp;
        if (!bad_fp.empty()) {
            bad_fp[0] = 'Z';
        }

        /* Rebuild the bundle with the tampered fingerprint. */
        std::string tampered = strip_fingerprint(raw)
                             + "\na=fingerprint:sha-256 " + bad_fp + "\n";
        std::string enc = b64_encode(tampered);

        NodeCtx n;
        start_and_get_bundle(n);
        GordianError e = gordian_connect(n.node, enc.c_str());
        check("connect_ex returns INVALID_BUNDLE", e == GORDIAN_ERR_INVALID_BUNDLE);
        gordian_destroy(n.node);
        gordian_destroy(donor.node);
    }

    /* ---- cleanup source node -------------------------------------------- */
    gordian_destroy(src.node);

    /* ---- summary -------------------------------------------------------- */
    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
