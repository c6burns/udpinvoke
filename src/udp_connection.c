#include "udp/udp_connection.h"

#include "aws/common/byte_buf.h"

#include "udp/error.h"
#include "udp/allocator.h"
#include "udp/log.h"


typedef struct udp_write_data_s {
	udp_conn_t *conn;
	uv_buf_t *buf;
} udp_write_data_t;


// lib uv async callbacks
// all callbacks take the form on_****_cb
// (on_ prefix and _cb suffix)
// none of these should ever be called directly

// this callback is registered by uv_close
// --------------------------------------------------------------------------------------------------------------
void on_udp_close_cb(uv_handle_t *handle)
{
#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- handle: %p\n", __FUNCTION__, uv_thread_self(), handle);
#endif

	udp_conn_t *conn = (udp_conn_t *)handle->data;
	HB_MEM_RELEASE(handle);
	conn->state = CS_DISCONNECTED;
	conn->udp = NULL;
}

// this callback is registered by uv_start_read
// flow: udp_connect_begin:uv_udp_connect -> on_connect_cb:uv_start_read -> on_read_cb
// --------------------------------------------------------------------------------------------------------------
static void on_udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- handle: %p\n", __FUNCTION__, uv_thread_self(), handle);
#endif

	buf->base = HB_MEM_ACQUIRE(suggested_size);
	if (!buf->base) {
		return;
	}
	buf->len = UV_BUFLEN_CAST(suggested_size);
}

// this callback is registered by uv_start_read
// flow: udp_connect_begin:uv_udp_connect -> on_connect_cb:uv_start_read -> on_read_cb
// --------------------------------------------------------------------------------------------------------------
void on_udp_read_cb(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags)
{
#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- handle: %p -- buf: %p\n", __FUNCTION__, uv_thread_self(), tcp, buf->base);
#endif

	int should_close = 0;
	udp_conn_t *conn = (udp_conn_t *)req->data;

	// TODO: determine if 0 bytes is a graceful close which is usually standard
	if (nread >= 0) {
		conn->ctx->recv_msgs++;
		conn->ctx->recv_bytes += nread;
	} else {
		hb_log_uv_error((int)nread);
		should_close = 1;
	}

	HB_MEM_RELEASE(buf->base);

	if (conn->state != CS_CONNECTED) should_close = 1;
	if (should_close) udp_conn_disconnect(conn);
}

//// this callback is registered by uv_udp_connect
//// flow: udp_connect_begin:uv_udp_connect -> on_connect_cb
//// --------------------------------------------------------------------------------------------------------------
//void on_udp_connect_cb(uv_connect_t *connection, int status)
//{
//#ifdef UV_THREAD_HANDLE_DEBUG
//	printf("%s -- %lu -- uv_connect_t: %p -- handle: %p\n", __FUNCTION__, uv_thread_self(), connection, connection->handle);
//#endif
//
//	int ret;
//	udp_conn_t *conn = (udp_conn_t *)connection->data;
//
//	if (status < 0) {
//		conn->state = CS_DISCONNECTED;
//		hb_log_uv_error(status);
//		HB_MEM_RELEASE(connection);
//		return;
//	}
//
//	//int nlen;
//	//struct sockaddr_storage local;
//	//struct sockaddr_in *plocal = (struct sockaddr_in *)&local;
//	//nlen = sizeof(local);
//	//if ((ret = uv_udp_getsockname((uv_udp_t *)connection->handle, (struct sockaddr *)plocal, &nlen))) {
//	//	PRINTERRCODE(ret);
//	//	udp_conn_disconnect(conn);
//	//}
//
//	//struct sockaddr_storage peer;
//	//struct sockaddr_in *ppeer = (struct sockaddr_in *)&peer;
//	//nlen = sizeof(peer);
//	//if ((ret = uv_udp_getpeername((uv_udp_t *)connection->handle, (struct sockaddr *)ppeer, &nlen))) {
//	//	PRINTERRCODE(ret);
//	//	udp_conn_disconnect(conn);
//	//}
//
//	conn->state = CS_CONNECTED;
//	conn->udp = connection->handle;
//	conn->udp->data = (void *)conn;
//	//memcpy(&conn->local_ip, &plocal->sin_addr, sizeof(uint32_t));
//	//conn->local_port = ntohs(plocal->sin_port);
//	//memcpy(&conn->peer_ip, &ppeer->sin_addr, sizeof(uint32_t));
//	//conn->peer_port = ntohs(ppeer->sin_port);
//	HB_MEM_RELEASE(connection);
//	if ((ret = uv_read_start(conn->udp, on_udp_alloc_cb, on_udp_read_cb))) {
//		hb_log_uv_error(ret);
//		udp_conn_disconnect(conn);
//	}
//}

// this callback is registered by uv_write
// flow: udp_write_begin:uv_write -> on_write_cb
// --------------------------------------------------------------------------------------------------------------
void on_udp_write_cb(uv_udp_send_t *req, int status)
{
	int should_close = 0;
	udp_write_data_t *wdata = (udp_write_data_t *)req->data;
	udp_conn_t *conn = wdata->conn;
	uv_buf_t *wbuf = wdata->buf;

#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- uv_write_t: %p -- handle: %p -- buf: %p\n", __FUNCTION__, uv_thread_self(), req, req->handle, wbuf->base);
#endif

	if (status) {
		hb_log_uv_error(status);
		should_close = 1;
	} else {
		conn->ctx->send_msgs++;
		conn->ctx->send_bytes += wbuf->len;
	}

	HB_MEM_RELEASE(wbuf->base);
	HB_MEM_RELEASE(wbuf);
	HB_MEM_RELEASE(req);
	HB_MEM_RELEASE(wdata);

	if (conn->state != CS_CONNECTED) should_close = 1;
	if (should_close) udp_conn_disconnect(conn);
}


// async initiator methods 
// all initiators take the form ****_begin (suffixed with _begin)
// any method named like this will initiate an async operation
// and install the appropriate callbacks
// TODO: return int status code
// TODO: cleanup memory on error
// --------------------------------------------------------------------------------------------------------------
void udp_write_begin(uv_udp_t *udp, char *data, int len, unsigned flags)
{
	int ret;
	// TODO: return error codes for all of the critical failures below
	if (!udp) return;
	if (!udp->data) return;
	if (!data) return;
	if (!len) return;

	udp_conn_t *conn = (udp_conn_t *)udp->data;
	if (conn->state == CS_CONNECTING) {
		conn->state = CS_CONNECTED;
	} else if (conn->state != CS_CONNECTED) {
		return;
	}

	// max we could prepend would be 8 bytes for 64 bit int
	struct aws_byte_buf bb_data;
	if (aws_byte_buf_init(&bb_data, &hb_aws_default_allocator, len + 8) != AWS_OP_SUCCESS) {
		hb_log_error("aws_byte_buf_init failed");
		return;
	}

	// hard code BE 32 bit int prefix for protocol message length
	if (!aws_byte_buf_write_be32(&bb_data, (uint32_t)len)) {
		hb_log_error("aws_byte_buf_write_be32 failed");
		return;
	}

	// TODO: remove all prefixing and pass the responsibility to a higher level
	//if (cmdline_args.prefix == 8) {
	//	if (len <= UCHAR_MAX) {
	//		if (!aws_byte_buf_write_u8(&bb_data, (uint8_t)len)) {
	//			PRINTERR("aws_byte_buf_write_u8 failed");
	//		}
	//	} else {
	//		cmdline_args.prefix *= 2;
	//	}
	//}
	//if (cmdline_args.prefix == 16) {
	//	if (len <= USHRT_MAX) {
	//		if (!aws_byte_buf_write_be16(&bb_data, (uint16_t)len)) {
	//			PRINTERR("aws_byte_buf_write_be16 failed");
	//		}
	//	} else {
	//		cmdline_args.prefix *= 2;
	//	}
	//}
	//if (cmdline_args.prefix == 32) {
	//	if (len <= UINT_MAX) {
	//		if (!aws_byte_buf_write_be32(&bb_data, (uint32_t)len)) {
	//			PRINTERR("aws_byte_buf_write_be32 failed");
	//		}
	//	} else {
	//		cmdline_args.prefix *= 2;
	//	}
	//}
	//if (cmdline_args.prefix == 64) {
	//	if (!aws_byte_buf_write_be64(&bb_data, (uint64_t)len)) {
	//		PRINTERR("aws_byte_buf_write_be64 failed");
	//	}
	//}

	if (!aws_byte_buf_write(&bb_data, (uint8_t *)data, len)) {
		hb_log_error("aws_byte_buf_write failed");
	}

	udp_write_data_t *wdata = HB_MEM_ACQUIRE(sizeof(udp_write_data_t));
	if (!wdata) {
		hb_log_uv_error(ENOMEM);
		return;
	}
	wdata->conn = conn;

	wdata->buf = HB_MEM_ACQUIRE(sizeof(uv_buf_t));
	if (!wdata->buf) {
		hb_log_error("failed to allocate uv_buf_t");
		return;
	}
	wdata->buf->base = (char *)bb_data.buffer;
	wdata->buf->len = UV_BUFLEN_CAST(bb_data.len);

	// write_req_t *wr = (write_req_t *)HB_MEM_ACQUIRE(sizeof(write_req_t *));
	uv_udp_send_t *send_req = HB_MEM_ACQUIRE(sizeof(*send_req));
	//uv_write_t *wreq = HB_MEM_ACQUIRE(sizeof(uv_write_t));
	if (!send_req) {
		hb_log_error("failed to allocate uv_write_t");
		return;
	}
	send_req->data = (void *)wdata;
	//wreq->send_handle

#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- uv_write_t: %p -- handle: %p -- buf: %p\n", __FUNCTION__, uv_thread_self(), wreq, stream, wbuf->base);
#endif

	if ((ret = uv_udp_send(send_req, udp, wdata->buf, 1, (const struct sockaddr *)&conn->sockstr, on_udp_write_cb))) {
		hb_log_uv_error(ret);
		udp_conn_disconnect((udp_conn_t *)udp->data);
		return;
	}
}


// TODO: memory cleanup on failure
// --------------------------------------------------------------------------------------------------------------
int udp_connect_begin(udp_conn_t *conn, const char *host, int port)
{
	int ret;
	uv_loop_t *loop;

	if (!conn) return EINVAL;
	if (conn->state != CS_NEW && conn->state != CS_DISCONNECTED) return EINVAL;
	if (!SAFE_UDP_CTX(conn->ctx)) return EINVAL;
	if (!(loop = udp_context_get_loop(conn->ctx))) return EINVAL;

	conn->udp = HB_MEM_ACQUIRE(sizeof(*conn->udp));
	if (!conn->udp) {
		hb_log_error("failed to allocate uv_udp_t");
		return ENOMEM;
	}

	if ((ret = uv_udp_init(loop, conn->udp))) {
		hb_log_uv_error(ret);
		return ret;
	}
	conn->udp->data = conn;

	if ((ret = uv_ip6_addr(host, port, (struct sockaddr_in6 *)&conn->sockstr))) {
		if ((ret = uv_ip4_addr(host, port, (struct sockaddr_in *)&conn->sockstr))) {
			hb_log_uv_error(ret);
			return ret;
		}
	}

	struct sockaddr_storage localaddr;
	if ((ret = uv_ip4_addr(host, port, (struct sockaddr_in *)&localaddr))) {
		hb_log_uv_error(ret);
		return ret;
	}

	if ((ret = uv_udp_bind(conn->udp, (const struct sockaddr *)&localaddr, 0))) {
		hb_log_uv_error(ret);
		return HB_ERROR;
	}

	if ((ret = uv_udp_recv_start(conn->udp, on_udp_alloc_cb, on_udp_read_cb))) {
		hb_log_uv_error(UV_ENOMEM);
		return HB_ERROR;
	}

	struct sockaddr_storage dest;
	if ((ret = uv_ip6_addr(host, port, (struct sockaddr_in6 *)&dest))) {
		if ((ret = uv_ip4_addr(host, port, (struct sockaddr_in *)&dest))) {
			hb_log_uv_error(ret);
			return ret;
		}
	}

	char addr_peer[255], addr_local[255];
	memset(&addr_peer, 0, 255);
	memset(&addr_local, 0, 255);
	if (dest.ss_family == AF_INET6) {
		uv_ip6_name((struct sockaddr_in6 *)&dest, addr_peer, sizeof(addr_peer));
	} else if (dest.ss_family == AF_INET) {
		uv_ip4_name((struct sockaddr_in *)&dest, addr_peer, sizeof(addr_peer));
	} else {
		return HB_ERROR;
	}
	//printf("Conecting to %s:%d\n", ipbuf, port);

	uv_connect_t *connection = HB_MEM_ACQUIRE(sizeof(uv_connect_t));
	if (!connection) {
		hb_log_error("failed to allocate uv_connect_t");
		return HB_ERROR;
	}

#ifdef UV_THREAD_HANDLE_DEBUG
	printf("%s -- %lu -- uv_connect_t: %p -- handle: %p\n", __FUNCTION__, uv_thread_self(), connection, socket);
#endif

	connection->data = (void *)conn;
	conn->state = CS_CONNECTING;
	//if ((ret = uv_udp_connect(connection, socket, (const struct sockaddr *)&dest, on_udp_connect_cb))) {
	//	hb_log_uv_error(ret);
	//	conn->state = CS_DISCONNECTED;
	//	return ret;
	//}

	return HB_SUCCESS;
}

// --------------------------------------------------------------------------------------------------------------
udp_conn_t *udp_conn_new(udp_ctx_t *ctx)
{
	udp_conn_t *conn;

	if (!ctx) return NULL;

	if (!(conn = HB_MEM_ACQUIRE(sizeof(udp_conn_t)))) {
		return NULL;
	}

	memset(conn, 0, sizeof(udp_conn_t));

	conn->ctx = ctx;

	return conn;
}

// --------------------------------------------------------------------------------------------------------------
void udp_conn_delete(udp_conn_t **pconn)
{
	if (!pconn) return;

	udp_conn_t *conn = *pconn;
	if (!conn) return;

	HB_MEM_RELEASE(conn);
	conn = NULL;
}

// --------------------------------------------------------------------------------------------------------------
int udp_conn_init(udp_ctx_t *ctx, udp_conn_t *conn)
{
	if (!conn) return EINVAL;
	
	memset(conn, 0, sizeof(udp_conn_t));
	conn->ctx = ctx;

	return 0;
}

// --------------------------------------------------------------------------------------------------------------
void udp_conn_disconnect(udp_conn_t *conn)
{
	if (!conn) return;
	if (conn->state == CS_DISCONNECTED || conn->state == CS_DISCONNECTING) return;
	if (!conn->udp) return;

	if (!uv_is_closing((uv_handle_t *)conn->udp)) {
		conn->state = CS_DISCONNECTING;
		uv_close((uv_handle_t *)conn->udp, on_udp_close_cb);
	}
}

// --------------------------------------------------------------------------------------------------------------
void udp_conn_close(udp_conn_t *conn)
{
	udp_conn_disconnect(conn);
}

// --------------------------------------------------------------------------------------------------------------
void udp_get_conns(udp_conn_t *conns, int count)
{
	udp_ctx_t *ctx = udp_context_new();
	for (int i = 0; i < count; i++) {
		udp_conn_init(ctx, &conns[i]);
		//conns[i].stream = NULL;
		conns[i].read_err = 1;
		conns[i].write_err = 2;
		conns[i].state = CS_DISCONNECTED;
	}
}