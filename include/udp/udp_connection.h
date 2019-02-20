#ifndef UDP_CONNECTION_H
#define UDP_CONNECTION_H

#include <stdint.h>

#include "uv.h"

#include "udp/allocator.h"
#include "udp/udp_context.h"

#if _MSC_VER
#	define UV_BUFLEN_CAST(x) (ULONG)x
#else
#	define UV_BUFLEN_CAST(x) x
#endif

typedef enum connection_state_e {
	CS_NEW = 0,
	CS_CONNECTING,
	CS_CONNECTED,
	CS_DISCONNECTING,
	CS_DISCONNECTED,
} connection_state_t;

typedef struct udp_conn_s {
	udp_ctx_t *ctx;
	uv_stream_t *stream;
	int32_t read_err;
	int32_t write_err;
	int32_t state;
	uint8_t pad[4]; // 64 bit align
} udp_conn_t;



/* uv callbacks */
void on_udp_close_cb(uv_handle_t *handle);
static void on_udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void on_udp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void on_udp_connect_cb(uv_connect_t *connection, int status);
void on_udp_write_cb(uv_write_t *req, int status);

/* uv interface functions */
void udp_write_begin(uv_stream_t *stream, char *data, int len);
int udp_connect_begin(udp_conn_t *conn, const char *host, int port);

/* connection and state management */
udp_conn_t *udp_conn_new(udp_ctx_t *ctx);
void udp_conn_delete(udp_conn_t **conn);
int udp_conn_init(udp_ctx_t *ctx, udp_conn_t *conn);
void udp_conn_disconnect(udp_conn_t *conn);
void udp_conn_close(udp_conn_t *conn);
void udp_get_conns(udp_conn_t *conns, int count);

#endif