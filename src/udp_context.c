#include "udp/udp_context.h"

#include <string.h>

#include "udp/allocator.h"


// --------------------------------------------------------------------------------------------------------------
udp_ctx_t *udp_context_new()
{
	udp_ctx_t *ctx;

	if (!(ctx = HB_MEM_ACQUIRE(sizeof(udp_ctx_t)))) {
		return NULL;
	}
	memset(ctx, 0, sizeof(udp_ctx_t));
	if (!(ctx->config = HB_MEM_ACQUIRE(sizeof(udp_ctx_config_t)))) {
		udp_context_delete(&ctx);
		return NULL;
	}

	return ctx;
}

// --------------------------------------------------------------------------------------------------------------
void udp_context_delete(udp_ctx_t **pctx)
{
	if (!pctx) return;

	udp_ctx_t *ctx = *pctx;
	if (!ctx) return;

	if (ctx->config) {
		HB_MEM_RELEASE(ctx->config);
	}

	HB_MEM_RELEASE(ctx);
	ctx = NULL;
}

// --------------------------------------------------------------------------------------------------------------
int udp_context_set_config(udp_ctx_t *ctx, udp_ctx_config_t *cfg)
{
	if (!SAFE_UDP_CTX(ctx)) return EINVAL;
	if (!cfg) return EINVAL;

	memcpy(ctx->config, cfg, sizeof(udp_ctx_config_t));

	return 0;
}

// --------------------------------------------------------------------------------------------------------------
uv_loop_t *udp_context_get_loop(udp_ctx_t *ctx)
{
	if (!SAFE_UDP_CTX(ctx)) return NULL;
	return ctx->config->uv_loop;
}