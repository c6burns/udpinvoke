#ifndef UDP_CONTEXT_H
#define UDP_CONTEXT_H

#include <stdint.h>

#include "uv.h"

#define SAFE_UDP_CTX(ctx) (ctx && ctx->config)

typedef struct udp_ctx_config_s {
	uv_loop_t *uv_loop;
} udp_ctx_config_t;

typedef struct udp_ctx_s {
	udp_ctx_config_t *config;
	uint64_t recv_msgs;
	uint64_t recv_bytes;
	uint64_t send_msgs;
	uint64_t send_bytes;
} udp_ctx_t;

udp_ctx_t *udp_context_new();
void udp_context_delete(udp_ctx_t **ctx);
int udp_context_set_config(udp_ctx_t *ctx, udp_ctx_config_t *cfg);
uv_loop_t *udp_context_get_loop(udp_ctx_t *ctx);

#endif