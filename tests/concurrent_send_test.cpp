/*
 * tests/concurrent_send_test.cpp
 *
 * Concurrency test: two loopback nodes, 4 threads each sending 50 messages
 * from A to B (200 total). Verifies all messages arrive intact.
 *
 * Exit 0 = PASS, 1 = FAIL, 2 = timeout.
 */

#include "gordian_net.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <chrono>
#include <set>

static constexpr int NUM_THREADS    = 4;
static constexpr int MSGS_PER_THREAD = 50;
static constexpr int TOTAL_MSGS     = NUM_THREADS * MSGS_PER_THREAD;

/* ---- shared state -------------------------------------------------------- */

struct PeerState {
    const char*             name;
    GordianNode*            node = nullptr;

    std::string             bundle;
    std::mutex              mtx;
    std::condition_variable bundle_cv;
    bool                    bundle_ready = false;

    std::atomic<bool>       ready  { false };
    std::atomic<bool>       failed { false };

    std::vector<std::string> received;
    std::mutex               recv_mtx;
    std::condition_variable  recv_cv;
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
    printf("[%s] state -> %s\n", p->name, names[(int)state]);

    if (state == GORDIAN_STATE_READY) {
        p->ready.store(true);
    } else if (state == GORDIAN_STATE_FAILED || state == GORDIAN_STATE_DISCONNECTED) {
        p->failed.store(true);
        p->recv_cv.notify_all();
    }
}

static void on_recv(const uint8_t* data, size_t size, void* ud)
{
    auto* p = static_cast<PeerState*>(ud);
    std::string msg(reinterpret_cast<const char*>(data), size);
    std::lock_guard<std::mutex> lk(p->recv_mtx);
    p->received.push_back(std::move(msg));
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

static bool wait_recv_count(PeerState& p, int count, int timeout_s)
{
    std::unique_lock<std::mutex> lk(p.recv_mtx);
    return p.recv_cv.wait_for(lk,
                              std::chrono::seconds(timeout_s),
                              [&]{
                                  return (int)p.received.size() >= count
                                         || p.failed.load();
                              });
}

/* ---- main ---------------------------------------------------------------- */

int main()
{
    printf("=== GordianNet concurrent send test ===\n\n");

    PeerState a, b;
    a.name = "A";
    b.name = "B";

    a.node = gordian_create(NULL);
    b.node = gordian_create(NULL);

    gordian_set_callbacks(a.node, on_creds, on_state, on_recv, NULL, &a);
    gordian_set_callbacks(b.node, on_creds, on_state, on_recv, NULL, &b);

    gordian_start(a.node);
    gordian_start(b.node);

    if (!wait_bundle(a, 15)) { fprintf(stderr, "FAIL: A bundle timeout\n"); return 2; }
    if (!wait_bundle(b, 15)) { fprintf(stderr, "FAIL: B bundle timeout\n"); return 2; }

    gordian_connect(a.node, b.bundle.c_str());
    gordian_connect(b.node, a.bundle.c_str());

    if (!wait_ready(a, 20)) {
        fprintf(stderr, "FAIL: A not READY (failed=%d)\n", a.failed.load());
        return a.failed.load() ? 1 : 2;
    }
    if (!wait_ready(b, 20)) {
        fprintf(stderr, "FAIL: B not READY (failed=%d)\n", b.failed.load());
        return b.failed.load() ? 1 : 2;
    }

    printf("[test] both READY — spawning %d sender threads (%d msgs each)\n",
           NUM_THREADS, MSGS_PER_THREAD);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    /* Spawn sender threads: each sends 50 messages from A to B */
    std::vector<std::thread> senders;
    for (int t = 0; t < NUM_THREADS; ++t) {
        senders.emplace_back([&a, t]() {
            for (int i = 0; i < MSGS_PER_THREAD; ++i) {
                char buf[64];
                snprintf(buf, sizeof(buf), "thread-%d-msg-%d", t, i);
                gordian_send(a.node,
                             reinterpret_cast<const uint8_t*>(buf),
                             strlen(buf));
            }
        });
    }

    for (auto& th : senders) th.join();
    printf("[test] all sends queued — waiting for %d messages at B\n", TOTAL_MSGS);

    /* Wait for all messages to arrive at B */
    if (!wait_recv_count(b, TOTAL_MSGS, 60)) {
        std::lock_guard<std::mutex> lk(b.recv_mtx);
        fprintf(stderr, "FAIL: timeout — received %d/%d messages\n",
                (int)b.received.size(), TOTAL_MSGS);
        gordian_destroy(a.node);
        gordian_destroy(b.node);
        return 2;
    }

    /* Verify */
    int result = 0;

    /* Check count */
    {
        std::lock_guard<std::mutex> lk(b.recv_mtx);
        if ((int)b.received.size() != TOTAL_MSGS) {
            fprintf(stderr, "FAIL: count mismatch — got %d, expected %d\n",
                    (int)b.received.size(), TOTAL_MSGS);
            result = 1;
        }
    }

    /* Check each message matches "thread-T-msg-N" and build a set */
    std::set<std::string> seen;
    {
        std::lock_guard<std::mutex> lk(b.recv_mtx);
        for (const auto& msg : b.received) {
            int t, n;
            if (sscanf(msg.c_str(), "thread-%d-msg-%d", &t, &n) != 2
                || t < 0 || t >= NUM_THREADS
                || n < 0 || n >= MSGS_PER_THREAD) {
                fprintf(stderr, "FAIL: corrupt message \"%s\"\n", msg.c_str());
                result = 1;
            }
            seen.insert(msg);
        }
    }

    /* Check completeness — every expected message present */
    for (int t = 0; t < NUM_THREADS && result == 0; ++t) {
        for (int i = 0; i < MSGS_PER_THREAD; ++i) {
            char buf[64];
            snprintf(buf, sizeof(buf), "thread-%d-msg-%d", t, i);
            if (seen.find(buf) == seen.end()) {
                fprintf(stderr, "FAIL: missing message \"%s\"\n", buf);
                result = 1;
            }
        }
    }

    if (result == 0) {
        printf("\n=== PASS: all %d messages received intact ===\n", TOTAL_MSGS);
    }

    gordian_destroy(a.node);
    gordian_destroy(b.node);
    return result;
}
