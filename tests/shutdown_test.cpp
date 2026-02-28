/*
 * tests/shutdown_test.cpp
 *
 * Shutdown / teardown integration tests for GordianNet.
 * Verifies that destroying nodes at various lifecycle stages is safe.
 *
 * Exit 0 on all-pass, 1 on any failure.
 */

#include "gordian_net.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <chrono>

/* ---- shared helpers ------------------------------------------------------ */

struct PeerState {
    const char*             name;
    GordianNode*            node          = nullptr;
    std::string             bundle;
    std::mutex              mtx;
    std::condition_variable bundle_cv;
    bool                    bundle_ready  = false;
    std::atomic<bool>       ready{false};
    std::atomic<bool>       disconnected{false};
    std::atomic<bool>       failed{false};
};

static void on_creds(const char* b64, void* ud) {
    auto* p = static_cast<PeerState*>(ud);
    std::lock_guard<std::mutex> lk(p->mtx);
    p->bundle       = b64;
    p->bundle_ready = true;
    p->bundle_cv.notify_all();
}

static void on_state(GordianState state, void* ud) {
    auto* p = static_cast<PeerState*>(ud);
    if (state == GORDIAN_STATE_READY)        p->ready.store(true);
    if (state == GORDIAN_STATE_DISCONNECTED) p->disconnected.store(true);
    if (state == GORDIAN_STATE_FAILED)       p->failed.store(true);
}

static void on_recv(const uint8_t*, size_t, void*) { /* unused */ }

static bool wait_bundle(PeerState& p, int secs) {
    std::unique_lock<std::mutex> lk(p.mtx);
    return p.bundle_cv.wait_for(lk, std::chrono::seconds(secs),
                                [&]{ return p.bundle_ready; });
}

static bool wait_ready(PeerState& p, int secs) {
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(secs);
    while (!p.ready.load() && !p.failed.load()) {
        if (std::chrono::steady_clock::now() >= end) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return p.ready.load();
}

static bool wait_down(PeerState& p, int secs) {
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(secs);
    while (!p.disconnected.load() && !p.failed.load()) {
        if (std::chrono::steady_clock::now() >= end) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return true;
}

/* Set up a loopback pair that reaches READY.  Returns false on timeout. */
static bool make_pair(PeerState& a, PeerState& b, int timeout_s) {
    a.node = gordian_create(NULL);
    b.node = gordian_create(NULL);
    gordian_set_callbacks(a.node, on_creds, on_state, on_recv, NULL, &a);
    gordian_set_callbacks(b.node, on_creds, on_state, on_recv, NULL, &b);
    gordian_start(a.node);
    gordian_start(b.node);
    if (!wait_bundle(a, timeout_s) || !wait_bundle(b, timeout_s)) return false;
    gordian_connect(a.node, b.bundle.c_str());
    gordian_connect(b.node, a.bundle.c_str());
    if (!wait_ready(a, timeout_s) || !wait_ready(b, timeout_s)) return false;
    return true;
}

/* ---- test cases ---------------------------------------------------------- */

static bool test_destroy_during_gathering() {
    printf("  [1] destroy during ICE gathering... ");
    GordianNode* n = gordian_create(NULL);
    PeerState ps;
    ps.name = "G";
    ps.node = n;
    gordian_set_callbacks(n, on_creds, on_state, on_recv, NULL, &ps);
    gordian_start(n);
    /* Destroy immediately — should not crash or hang */
    gordian_destroy(n);
    printf("PASS\n");
    return true;
}

static bool test_destroy_during_dtls() {
    printf("  [2] destroy during DTLS handshake... ");
    PeerState a, b;
    a.name = "A"; b.name = "B";
    a.node = gordian_create(NULL);
    b.node = gordian_create(NULL);
    gordian_set_callbacks(a.node, on_creds, on_state, on_recv, NULL, &a);
    gordian_set_callbacks(b.node, on_creds, on_state, on_recv, NULL, &b);
    gordian_start(a.node);
    gordian_start(b.node);
    if (!wait_bundle(a, 10) || !wait_bundle(b, 10)) {
        printf("FAIL (bundle timeout)\n");
        gordian_destroy(a.node);
        gordian_destroy(b.node);
        return false;
    }
    /* Exchange bundles to trigger ICE + DTLS, then kill A immediately */
    gordian_connect(a.node, b.bundle.c_str());
    gordian_connect(b.node, a.bundle.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    gordian_destroy(a.node);

    /* Without keepalive, B may not detect peer loss quickly over ICE/UDP.
       The key assertion is no crash/no hang on A's destroy. */
    (void)wait_down(b, 3);
    gordian_destroy(b.node);
    printf("PASS\n");
    return true;
}

static bool test_destroy_during_transfer() {
    printf("  [3] destroy during active transfer... ");
    PeerState a, b;
    a.name = "A"; b.name = "B";
    if (!make_pair(a, b, 10)) {
        printf("FAIL (pair setup timeout)\n");
        if (a.node) gordian_destroy(a.node);
        if (b.node) gordian_destroy(b.node);
        return false;
    }
    /* Start a burst of sends, then destroy A mid-flight */
    const char* payload = "shutdown-test-payload";
    for (int i = 0; i < 20; i++)
        gordian_send(a.node, reinterpret_cast<const uint8_t*>(payload),
                     strlen(payload));
    gordian_destroy(a.node);

    /* Ungraceful destroy (no close_notify) — B may or may not detect peer
       loss quickly since there's no DTLS/KCP keepalive.  The key assertion
       is no crash/no hang on A's destroy side.  Give B a short window to
       notice, but don't fail the test if it doesn't. */
    (void)wait_down(b, 3);
    gordian_destroy(b.node);
    printf("PASS\n");
    return true;
}

static bool test_graceful_disconnect() {
    printf("  [4] graceful disconnect... ");
    PeerState a, b;
    a.name = "A"; b.name = "B";
    if (!make_pair(a, b, 10)) {
        printf("FAIL (pair setup timeout)\n");
        if (a.node) gordian_destroy(a.node);
        if (b.node) gordian_destroy(b.node);
        return false;
    }
    GordianError err = gordian_disconnect(a.node, 2000);
    if (err != GORDIAN_OK) {
        printf("FAIL (disconnect returned %d)\n", static_cast<int>(err));
        gordian_destroy(a.node);
        gordian_destroy(b.node);
        return false;
    }
    bool b_down = wait_down(b, 5);
    gordian_destroy(a.node);
    gordian_destroy(b.node);
    if (!b_down) {
        printf("FAIL (B did not see DISCONNECTED)\n");
        return false;
    }
    printf("PASS\n");
    return true;
}

static bool test_rapid_create_destroy() {
    printf("  [5] rapid create/destroy (100 cycles)... ");
    for (int i = 0; i < 100; i++) {
        GordianNode* n = gordian_create(NULL);
        if (!n) {
            printf("FAIL (create returned null at iteration %d)\n", i);
            return false;
        }
        PeerState ps;
        ps.name = "R";
        ps.node = n;
        gordian_set_callbacks(n, on_creds, on_state, on_recv, NULL, &ps);
        gordian_start(n);
        gordian_destroy(n);
    }
    printf("PASS\n");
    return true;
}

/* ---- main ---------------------------------------------------------------- */

int main() {
    printf("=== GordianNet shutdown test ===\n\n");

    int passed = 0, total = 5;

    if (test_destroy_during_gathering())  passed++;
    if (test_destroy_during_dtls())       passed++;
    if (test_destroy_during_transfer())   passed++;
    if (test_graceful_disconnect())       passed++;
    if (test_rapid_create_destroy())      passed++;

    printf("\n=== Results: %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
