/*
 * cli/main.cpp  —  GordianNet interactive P2P chat demo
 *
 * Usage
 * -----
 *   Terminal A:  ./gordian_chat
 *   Terminal B:  ./gordian_chat
 *
 * Workflow
 * --------
 *   1. Both peers launch the binary. Each prints its own Base64 bundle.
 *   2. Copy Terminal A's bundle, paste into Terminal B when prompted.
 *   3. Copy Terminal B's bundle, paste into Terminal A when prompted.
 *   4. ICE negotiation runs. When both show "[READY]", type and hit Enter.
 *
 * Environment
 * -----------
 *   GORDIAN_STUN  — custom STUN server (host:port, default stun.l.google.com:19302)
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>

#include "gordian_net.h"

/* ---- shared state -------------------------------------------------------- */
static std::atomic<bool>  g_ready { false };
static std::mutex         g_cv_mutex;
static std::condition_variable g_cv;

/* ---- callbacks ----------------------------------------------------------- */

static void on_creds(const char* b64, void* /*ud*/)
{
    printf("\n"
           "╔══════════════════════════════════════════════════════════════╗\n"
           "║              YOUR LOCAL ICE BUNDLE (copy this)              ║\n"
           "╚══════════════════════════════════════════════════════════════╝\n"
           "%s\n\n", b64);
    fflush(stdout);
}

static void on_state(GordianState state, void* /*ud*/)
{
    switch (state) {
    case GORDIAN_STATE_GATHERING:
        printf("[INFO] Gathering ICE candidates…\n");
        break;
    case GORDIAN_STATE_READY:
        printf("\n[READY] P2P link established! Start typing.\n> ");
        fflush(stdout);
        g_ready.store(true);
        g_cv.notify_all();
        break;
    case GORDIAN_STATE_DISCONNECTED:
        printf("\n[WARN] Remote peer disconnected.\n");
        g_ready.store(false);
        g_cv.notify_all();
        break;
    case GORDIAN_STATE_FAILED:
        printf("\n[ERROR] Connection failed. Check firewall / STUN reachability.\n");
        g_ready.store(false);
        g_cv.notify_all();
        break;
    }
    fflush(stdout);
}

static void on_recv(const uint8_t* data, size_t size, void* /*ud*/)
{
    printf("\r\033[K");
    printf("[PEER] %.*s\n> ", (int)size, reinterpret_cast<const char*>(data));
    fflush(stdout);
}

static void on_error(GordianError error, const char* message, void* /*ud*/)
{
    fprintf(stderr, "[ERROR %d] %s\n", (int)error, message);
}

/* ---- main ---------------------------------------------------------------- */
int main()
{
    printf("GordianNet P2P Chat  —  ICE + DTLS 1.2 + KCP\n");
    printf("==============================================\n\n");

    /* Parse optional STUN server from environment */
    GordianConfig cfg = {};
    const char* stun_env = std::getenv("GORDIAN_STUN");
    std::string stun_host_buf;
    if (stun_env) {
        std::string s = stun_env;
        auto colon = s.rfind(':');
        if (colon != std::string::npos) {
            stun_host_buf = s.substr(0, colon);
            cfg.stun_server_host = stun_host_buf.c_str();
            cfg.stun_server_port = (uint16_t)std::atoi(s.substr(colon + 1).c_str());
        } else {
            stun_host_buf = s;
            cfg.stun_server_host = stun_host_buf.c_str();
        }
        printf("[INFO] Using custom STUN: %s:%d\n",
               cfg.stun_server_host, cfg.stun_server_port ? cfg.stun_server_port : 19302);
    }

    GordianNode* node = gordian_create(&cfg);
    gordian_set_callbacks(node, on_creds, on_state, on_recv, on_error, nullptr);

    GordianError err = gordian_start(node);
    if (err != GORDIAN_OK) {
        fprintf(stderr, "[FATAL] Start failed: %s\n", gordian_errstr(err));
        gordian_destroy(node);
        return 1;
    }

    printf("[INFO] Starting ICE candidate gathering…\n");
    fflush(stdout);

    printf("Paste the REMOTE peer's bundle below, then press Enter twice:\n> ");
    fflush(stdout);

    std::string remote_bundle;
    {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.empty()) {
                if (!remote_bundle.empty()) break;
                continue;
            }
            remote_bundle = line;
            break;
        }
    }

    if (remote_bundle.empty()) {
        fprintf(stderr, "[ERROR] No remote bundle provided. Exiting.\n");
        gordian_destroy(node);
        return 1;
    }

    printf("[INFO] Remote bundle accepted. Starting ICE negotiation…\n");
    fflush(stdout);
    err = gordian_connect(node, remote_bundle.c_str());
    if (err != GORDIAN_OK) {
        fprintf(stderr, "[FATAL] Connect failed: %s\n", gordian_errstr(err));
        gordian_destroy(node);
        return 1;
    }

    {
        std::unique_lock<std::mutex> lk(g_cv_mutex);
        g_cv.wait(lk, [] { return g_ready.load(); });
    }

    if (!g_ready.load()) {
        fprintf(stderr, "[ERROR] Connection failed. Exiting.\n");
        gordian_destroy(node);
        return 1;
    }

    printf("\n[CHAT] Type a message and press Enter. Ctrl+D to quit.\n");
    printf("> ");
    fflush(stdout);

    std::string msg;
    while (g_ready.load() && std::getline(std::cin, msg)) {
        if (msg.empty()) {
            printf("> ");
            fflush(stdout);
            continue;
        }
        GordianError se = gordian_send(node,
                                        reinterpret_cast<const uint8_t*>(msg.c_str()),
                                        msg.size());
        if (se != GORDIAN_OK) {
            printf("[WARN] Send failed: %s\n", gordian_errstr(se));
        }
        printf("> ");
        fflush(stdout);
    }

    printf("\n[INFO] Shutting down.\n");
    gordian_disconnect(node, 1000);
    gordian_destroy(node);
    return 0;
}
