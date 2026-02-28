/*
 * framing_test — exercises the 4-byte length-prefix framing layer:
 *   1. Multi-message burst: 100 small messages from A → B, verify order + content
 *   2. Large payload: single 256 KB message from B → A, verify exact bytes
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

struct PeerState {
    const char*  name;
    GordianNode* node     = nullptr;
    std::string  bundle;
    std::mutex   mtx;
    std::condition_variable bundle_cv;
    bool         bundle_ready = false;
    std::atomic<bool> ready  { false };
    std::atomic<bool> failed { false };

    std::vector<std::vector<uint8_t>> msgs;
    std::mutex   msg_mtx;
    std::condition_variable msg_cv;
};

static void on_creds(const char* b64, void* ud) {
    auto* p = static_cast<PeerState*>(ud);
    std::lock_guard<std::mutex> lk(p->mtx);
    p->bundle = b64;
    p->bundle_ready = true;
    p->bundle_cv.notify_all();
}
static void on_state(GordianState state, void* ud) {
    auto* p = static_cast<PeerState*>(ud);
    if (state == GORDIAN_STATE_READY)        p->ready.store(true);
    else if (state == GORDIAN_STATE_FAILED || state == GORDIAN_STATE_DISCONNECTED)
        p->failed.store(true);
}
static void on_recv(const uint8_t* data, size_t size, void* ud) {
    auto* p = static_cast<PeerState*>(ud);
    std::lock_guard<std::mutex> lk(p->msg_mtx);
    p->msgs.push_back(std::vector<uint8_t>(data, data + size));
    p->msg_cv.notify_all();
}

static bool wait_bundle(PeerState& p, int s) {
    std::unique_lock<std::mutex> lk(p.mtx);
    return p.bundle_cv.wait_for(lk, std::chrono::seconds(s), [&]{ return p.bundle_ready; });
}
static bool wait_ready(PeerState& p, int s) {
    auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(s);
    while (!p.ready && !p.failed)
        if (std::chrono::steady_clock::now() >= dl) return false;
        else std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return p.ready.load();
}
static bool wait_msgs(PeerState& p, size_t count, int s) {
    std::unique_lock<std::mutex> lk(p.msg_mtx);
    return p.msg_cv.wait_for(lk, std::chrono::seconds(s),
                             [&]{ return p.msgs.size() >= count || p.failed.load(); });
}

int main() {
    printf("=== GordianNet framing test ===\n\n");

    PeerState a, b;
    a.name = "A"; b.name = "B";
    a.node = gordian_create(NULL);
    b.node = gordian_create(NULL);
    gordian_set_callbacks(a.node, on_creds, on_state, on_recv, NULL, &a);
    gordian_set_callbacks(b.node, on_creds, on_state, on_recv, NULL, &b);
    gordian_start(a.node);
    gordian_start(b.node);

    if (!wait_bundle(a, 15) || !wait_bundle(b, 15)) { fprintf(stderr, "FAIL: bundle timeout\n"); return 2; }
    gordian_connect(a.node, b.bundle.c_str());
    gordian_connect(b.node, a.bundle.c_str());
    if (!wait_ready(a, 20) || !wait_ready(b, 20)) { fprintf(stderr, "FAIL: ready timeout\n"); return 2; }

    printf("[test] READY — running framing tests\n");

    /* ---- Test 1: 100 small messages A → B -------------------------------- */
    const int N = 100;
    for (int i = 0; i < N; i++) {
        std::string msg = "msg-" + std::to_string(i);
        gordian_send(a.node, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    }
    if (!wait_msgs(b, N, 10)) {
        fprintf(stderr, "FAIL: only received %zu/%d small messages\n", b.msgs.size(), N);
        return 1;
    }
    for (int i = 0; i < N; i++) {
        std::string expected = "msg-" + std::to_string(i);
        std::string got(b.msgs[i].begin(), b.msgs[i].end());
        if (got != expected) {
            fprintf(stderr, "FAIL: msg[%d] expected \"%s\" got \"%s\"\n",
                    i, expected.c_str(), got.c_str());
            return 1;
        }
    }
    printf("[test] PASS: %d small messages received in order\n", N);

    /* ---- Test 2: 256 KB payload B → A ------------------------------------ */
    const size_t BIG = 256 * 1024;
    std::vector<uint8_t> big_payload(BIG);
    for (size_t i = 0; i < BIG; i++) big_payload[i] = uint8_t(i & 0xFF);
    gordian_send(b.node, big_payload.data(), big_payload.size());

    if (!wait_msgs(a, 1, 15)) { fprintf(stderr, "FAIL: large message timeout\n"); return 2; }
    if (a.msgs[0].size() != BIG || a.msgs[0] != big_payload) {
        fprintf(stderr, "FAIL: large message corrupted (got %zu bytes, expected %zu)\n",
                a.msgs[0].size(), BIG);
        return 1;
    }
    printf("[test] PASS: %zu-byte message received intact\n", BIG);

    gordian_destroy(a.node);
    gordian_destroy(b.node);
    printf("\n=== PASS: all framing tests ===\n");
    return 0;
}
