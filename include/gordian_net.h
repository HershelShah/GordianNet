#ifndef GORDIAN_NET_H
#define GORDIAN_NET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle — never expose internals to C callers */
typedef struct GordianNode GordianNode;

typedef enum {
    GORDIAN_STATE_GATHERING,     /* ICE candidate gathering in progress   */
    GORDIAN_STATE_READY,         /* PseudoTCP connection established       */
    GORDIAN_STATE_DISCONNECTED,  /* Remote peer disconnected               */
    GORDIAN_STATE_FAILED         /* ICE negotiation or connect failed      */
} GordianState;

/* --- Callback signatures ------------------------------------------------ */

/* Fired once when local ICE bundle is ready for out-of-band exchange.
   base64_candidates is a NUL-terminated Base64 string owned by the library;
   copy it before returning from the callback.                               */
typedef void (*GordianCredsCallback)(const char* base64_candidates, void* user_data);

/* Fired whenever the connection state changes.                              */
typedef void (*GordianStateCallback)(GordianState state, void* user_data);

/* Fired for every application-level message received over PseudoTCP.
   data points to an internal buffer valid only for the duration of the call.*/
typedef void (*GordianReceiveCallback)(const uint8_t* data, size_t size, void* user_data);

/* --- Lifecycle ----------------------------------------------------------- */

GordianNode* gordian_node_create(void);
void         gordian_node_destroy(GordianNode* node);

/* Register all three callbacks before calling gordian_node_start().
   user_data is forwarded verbatim to every callback invocation.            */
void gordian_node_set_callbacks(GordianNode*          node,
                                GordianCredsCallback  cred_cb,
                                GordianStateCallback  state_cb,
                                GordianReceiveCallback recv_cb,
                                void*                 user_data);

/* Begin ICE gathering. GordianCredsCallback fires when bundle is ready.    */
void gordian_node_start(GordianNode* node);

/* Feed the remote peer's Base64 bundle and start ICE negotiation.          */
void gordian_node_connect(GordianNode* node, const char* remote_candidates);

/* Send application data over the PseudoTCP stream.
   Returns true on success, false if not yet connected or send failed.      */
bool gordian_node_send(GordianNode* node, const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif
#endif /* GORDIAN_NET_H */
