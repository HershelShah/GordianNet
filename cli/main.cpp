/*
 * cli/main.cpp  —  GordianNet interactive P2P chat demo
 *
 * Usage
 * -----
 *   Terminal A (passive, waits for remote bundle):
 *       ./gordian_chat
 *
 *   Terminal B (active, feeds the bundle from Terminal A):
 *       ./gordian_chat
 *
 * Workflow
 * --------
 *   1. Both peers launch the binary. Each prints its own Base64 bundle.
 *   2. Copy Terminal A's bundle, paste into Terminal B when prompted.
 *   3. Copy Terminal B's bundle, paste into Terminal A when prompted.
 *   4. ICE negotiation runs. When both show "[READY]", type and hit Enter.
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
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              YOUR LOCAL ICE BUNDLE (copy this)              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("%s\n\n", b64);
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
        break;
    case GORDIAN_STATE_FAILED:
        printf("\n[ERROR] ICE negotiation failed. Check firewall / STUN reachability.\n");
        g_ready.store(false);
        g_cv.notify_all();
        break;
    }
    fflush(stdout);
}

static void on_recv(const uint8_t* data, size_t size, void* /*ud*/)
{
    /* Print received message, then re-draw the prompt */
    printf("\r\033[K");           /* erase current input line */
    printf("[PEER] %.*s\n> ", (int)size, reinterpret_cast<const char*>(data));
    fflush(stdout);
}

/* ---- main ---------------------------------------------------------------- */
int main()
{
    printf("GordianNet P2P Chat  —  libnice ICE + PseudoTCP\n");
    printf("================================================\n\n");

    /* Create and configure node */
    GordianNode* node = gordian_node_create();
    gordian_node_set_callbacks(node, on_creds, on_state, on_recv, nullptr);

    /* Kick off ICE gathering */
    gordian_node_start(node);

    /* Wait for the creds callback to print before prompting */
    printf("[INFO] Starting ICE candidate gathering…\n");
    fflush(stdout);

    /* Prompt user to paste remote bundle */
    printf("Paste the REMOTE peer's bundle below, then press Enter twice:\n> ");
    fflush(stdout);

    std::string remote_bundle;
    {
        /* Read until we get a non-empty line (the Base64 blob may be long
           but fits on one line). Also handle multi-line input by stopping
           at the first empty line after content.                           */
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
        gordian_node_destroy(node);
        return 1;
    }

    printf("[INFO] Remote bundle accepted. Starting ICE negotiation…\n");
    fflush(stdout);
    gordian_node_connect(node, remote_bundle.c_str());

    /* Block until READY or FAILED */
    {
        std::unique_lock<std::mutex> lk(g_cv_mutex);
        g_cv.wait(lk, [] { return g_ready.load(); });
    }

    if (!g_ready.load()) {
        fprintf(stderr, "[ERROR] Connection failed. Exiting.\n");
        gordian_node_destroy(node);
        return 1;
    }

    /* ---- Interactive chat loop ----------------------------------------- */
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
        bool ok = gordian_node_send(node,
                                    reinterpret_cast<const uint8_t*>(msg.c_str()),
                                    msg.size());
        if (!ok) {
            printf("[WARN] Send failed (not connected?)\n");
        }
        printf("> ");
        fflush(stdout);
    }

    printf("\n[INFO] Shutting down.\n");
    gordian_node_destroy(node);
    return 0;
}
