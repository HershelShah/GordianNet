/*
 * tests/loopback_test.cpp
 *
 * Integration test: spins up two GordianNode instances in the same process.
 * Node A and Node B exchange bundles in-process (simulating the copy/paste),
 * then verify that a message sent by A arrives at B and vice-versa.
 *
 * Pass criteria (exit 0):
 *   - Both nodes reach GORDIAN_STATE_READY
 *   - Message from A received verbatim by B
 *   - Message from B received verbatim by A
 *
 * Failure: exit 1 (or timeout after 30 s → exit 2)
 */

#include "gordian_net.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <chrono>

/* ---- shared state -------------------------------------------------------- */

struct PeerState {
    const char*             name;
    GordianNode*            node      = nullptr;

    /* filled by cred_cb — protected by mtx */
    std::string             bundle;
    std::mutex              mtx;
    std::condition_variable bundle_cv;
    bool                    bundle_ready = false;

    /* connection readiness */
    std::atomic<bool>       ready { false };
    std::atomic<bool>       failed { false };

    /* received message */
    std::string             received_msg;
    std::mutex              recv_mtx;
    std::condition_variable recv_cv;
    bool                    recv_ready = false;
};

/* ---- callbacks ----------------------------------------------------------- */

static void on_creds(const char* b64, void* ud)
{
    auto* p = static_cast<PeerState*>(ud);
    std::lock_guard<std::mutex> lk(p->mtx);
    p->bundle       = b64;
    p->bundle_ready = true;
    printf("[%s] bundle ready (%zu chars)\n", p->name, p->bundle.size());
    p->bundle_cv.notify_all();
}

static void on_state(GordianState state, void* ud)
{
    auto* p = static_cast<PeerState*>(ud);
    const char* names[] = { "GATHERING", "READY", "DISCONNECTED", "FAILED" };
    printf("[%s] state → %s\n", p->name, names[(int)state]);

    if (state == GORDIAN_STATE_READY) {
        p->ready.store(true);
    } else if (state == GORDIAN_STATE_FAILED || state == GORDIAN_STATE_DISCONNECTED) {
        p->failed.store(true);
        /* wake any waiter so the test can exit promptly */
        p->ready.store(false);
        {
            std::lock_guard<std::mutex> lk(p->recv_mtx);
            p->recv_ready = true;
        }
        p->recv_cv.notify_all();
    }
}

static void on_recv(const uint8_t* data, size_t size, void* ud)
{
    auto* p = static_cast<PeerState*>(ud);
    std::string msg(reinterpret_cast<const char*>(data), size);
    printf("[%s] received: \"%s\"\n", p->name, msg.c_str());
    std::lock_guard<std::mutex> lk(p->recv_mtx);
    p->received_msg = msg;
    p->recv_ready   = true;
    p->recv_cv.notify_all();
}

/* ---- helpers ------------------------------------------------------------- */

static bool wait_bundle(PeerState& p, int timeout_s)
{
    std::unique_lock<std::mutex> lk(p.mtx);
    return p.bundle_cv.wait_for(lk,
                                std::chrono::seconds(timeout_s),
                                [&]{ return p.bundle_ready; });
}

static bool wait_ready(PeerState& p, int timeout_s)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    while (!p.ready.load() && !p.failed.load()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return p.ready.load();
}

static bool wait_recv(PeerState& p, int timeout_s)
{
    std::unique_lock<std::mutex> lk(p.recv_mtx);
    return p.recv_cv.wait_for(lk,
                              std::chrono::seconds(timeout_s),
                              [&]{ return p.recv_ready; });
}

/* ---- main ---------------------------------------------------------------- */

int main()
{
    printf("=== GordianNet loopback integration test ===\n\n");

    PeerState a, b;
    a.name = "A";
    b.name = "B";

    /* Create nodes */
    a.node = gordian_node_create();
    b.node = gordian_node_create();

    gordian_node_set_callbacks(a.node, on_creds, on_state, on_recv, &a);
    gordian_node_set_callbacks(b.node, on_creds, on_state, on_recv, &b);

    /* Start ICE gathering on both */
    printf("[test] starting both nodes…\n");
    gordian_node_start(a.node);
    gordian_node_start(b.node);

    /* Wait for both bundles (up to 15 s — STUN round-trip can be slow) */
    printf("[test] waiting for ICE bundles…\n");
    if (!wait_bundle(a, 15)) { fprintf(stderr, "FAIL: A bundle timeout\n"); return 2; }
    if (!wait_bundle(b, 15)) { fprintf(stderr, "FAIL: B bundle timeout\n"); return 2; }

    /* Cross-feed bundles (simulates the user copy/paste) */
    printf("[test] exchanging bundles…\n");
    gordian_node_connect(a.node, b.bundle.c_str());
    gordian_node_connect(b.node, a.bundle.c_str());

    /* Wait for both to reach READY (up to 20 s — ICE checks + PseudoTCP SYN) */
    printf("[test] waiting for READY…\n");
    if (!wait_ready(a, 20)) {
        fprintf(stderr, "FAIL: A did not reach READY (failed=%d)\n", a.failed.load());
        return a.failed.load() ? 1 : 2;
    }
    if (!wait_ready(b, 20)) {
        fprintf(stderr, "FAIL: B did not reach READY (failed=%d)\n", b.failed.load());
        return b.failed.load() ? 1 : 2;
    }

    printf("[test] both READY — sending test messages\n");

    /* Small delay to let PseudoTCP settle before writing */
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    /* A → B */
    const char* msg_a = "hello from A";
    bool ok = gordian_node_send(a.node,
                                reinterpret_cast<const uint8_t*>(msg_a),
                                strlen(msg_a));
    if (!ok) { fprintf(stderr, "FAIL: A send returned false\n"); return 1; }

    /* B → A */
    const char* msg_b = "hello from B";
    ok = gordian_node_send(b.node,
                           reinterpret_cast<const uint8_t*>(msg_b),
                           strlen(msg_b));
    if (!ok) { fprintf(stderr, "FAIL: B send returned false\n"); return 1; }

    /* Wait for each side to receive */
    printf("[test] waiting for messages to arrive…\n");
    if (!wait_recv(b, 10)) { fprintf(stderr, "FAIL: B recv timeout\n"); return 2; }
    if (!wait_recv(a, 10)) { fprintf(stderr, "FAIL: A recv timeout\n"); return 2; }

    /* Verify contents */
    int result = 0;
    if (b.received_msg != msg_a) {
        fprintf(stderr, "FAIL: B got \"%s\", expected \"%s\"\n",
                b.received_msg.c_str(), msg_a);
        result = 1;
    }
    if (a.received_msg != msg_b) {
        fprintf(stderr, "FAIL: A got \"%s\", expected \"%s\"\n",
                a.received_msg.c_str(), msg_b);
        result = 1;
    }

    if (result == 0) {
        printf("\n=== PASS: full round-trip verified ===\n");
    }

    gordian_node_destroy(a.node);
    gordian_node_destroy(b.node);
    return result;
}
