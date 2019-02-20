#include "udpserv/udpserv.h"

#include <stdlib.h>

#include "udp/error.h"
#include "udp/log.h"
#include "udp/udp_connection.h"
#include "udp/bufferpool.h"



hb_buffer_pool_t *uvu_pool = NULL;
uint8_t *uvu_pool_backing_store;

//debug_memlist_t g_debug_memlist;
//uvu_allocator_t g_debug_allocator;
uvu_thread_private_t *uvu_thread_priv = NULL;
uv_thread_t uvu_thread = (uv_thread_t)NULL;
uv_loop_t *uvu_loop = NULL;
uv_udp_t *uvu_udp_server = NULL;
static uv_timer_t *uvu_accept_timer = NULL;
int uvu_closing = 0;

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req)
{
	write_req_t *wr = (write_req_t*)req;
	HB_MEM_RELEASE(wr->buf.base);
	HB_MEM_RELEASE(wr);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = (char*)HB_MEM_ACQUIRE(suggested_size);
	buf->len = UV_BUFLEN_CAST(suggested_size);
}

void on_close(uv_handle_t* handle)
{
	HB_MEM_RELEASE(handle);
}

void echo_write(uv_write_t *req, int status)
{
	if (status) {
		fprintf(stderr, "Write error %s\n", uv_strerror(status));
	}
	free_write_req(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
	if (nread > 0) {
		write_req_t *req = (write_req_t*)HB_MEM_ACQUIRE(sizeof(write_req_t));
		req->buf = uv_buf_init(buf->base, (unsigned int)nread);
		uv_write((uv_write_t*)req, client, &req->buf, 1, echo_write);
		return;
	}
	if (nread < 0) {
		if (nread != UV_EOF)
			fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
		uv_close((uv_handle_t*)client, on_close);
	}

	HB_MEM_RELEASE(buf->base);
}

void on_new_connection(uv_stream_t *server, int status)
{
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		// error!
		return;
	}

	uv_udp_t *client = (uv_udp_t*)HB_MEM_ACQUIRE(sizeof(uv_udp_t));
	uv_udp_init(uvu_loop, client);
	if (uv_accept(server, (uv_stream_t*)client) == 0) {
		uv_read_start((uv_stream_t*)client, alloc_buffer, echo_read);
	} else {
		uv_close((uv_handle_t*)client, on_close);
	}
}

int uvu_server_start(const char *ipstr, uint16_t port)
{
	uvu_closing = 0;

	int uvret;
	if (uvu_thread_priv) {
		return UV_UNKNOWN;
	}

	uvu_thread_priv = (uvu_thread_private_t *)HB_MEM_ACQUIRE(sizeof(uvu_thread_private_t));
	if (!uvu_thread_priv) {
		return UV_ENOMEM;
	}
	memset(uvu_thread_priv, 0, sizeof(uvu_thread_priv));

	if ((uvret = uv_ip6_addr(ipstr, port, (struct sockaddr_in6 *)&uvu_thread_priv->listen_addr))) {
		if ((uvret = uv_ip4_addr(ipstr, port, (struct sockaddr_in *)&uvu_thread_priv->listen_addr))) {
			return uvret;
		}
	}

	char ipbuf[255];
	memset(&ipbuf, 0, sizeof(ipbuf));
	if (uvu_thread_priv->listen_addr.ss_family == AF_INET6) {
		uv_ip6_name((struct sockaddr_in6 *)&uvu_thread_priv->listen_addr, ipbuf, sizeof(ipbuf));
	} else if (uvu_thread_priv->listen_addr.ss_family == AF_INET) {
		uv_ip4_name((struct sockaddr_in *)&uvu_thread_priv->listen_addr, ipbuf, sizeof(ipbuf));
	} else {
		return 1;
	}
	printf("Listening on %s\n", ipbuf);

	if ((uvret = uv_thread_create(&uvu_thread, uvu_server_run, (void *)uvu_thread_priv))) {
		return uvret;
	}

	return 0;
}


static void close_cb(uv_handle_t *handle)
{
	// if (!handle) return;

	// HB_MEM_RELEASE(handle);
	// handle = NULL;
}

static void timer_cb(uv_timer_t *handle)
{
	if (handle != uvu_accept_timer)
		return;

	if (uvu_closing) {
		if (!uv_is_closing((uv_handle_t *)uvu_udp_server)) uv_close((uv_handle_t *)uvu_udp_server, close_cb);
		if (!uv_is_closing((uv_handle_t *)uvu_accept_timer)) uv_close((uv_handle_t *)uvu_accept_timer, close_cb);
	}
}

void walk_cb(uv_handle_t *handle, void *arg)
{
	if (uv_is_closing(handle)) return;

	uv_close(handle, close_cb);
}

void async_cb(uv_async_t *handle)
{
	//uv_close((uv_handle_t *)uvu_accept_timer, close_cb);
	//uv_close((uv_handle_t *)uvu_udp_server, close_cb);
	uv_close((uv_handle_t *)handle, close_cb);
	uvu_closing = 1;
	//uv_stop(uvu_loop);
}

int uvu_server_stop()
{
	if (uvu_closing) return -1;

	int uvret;

	uv_async_t *async = HB_MEM_ACQUIRE(sizeof(async));
	uv_async_init(uvu_loop, async, async_cb);
	uv_async_send(async);

	uvret = uv_thread_join(&uvu_thread);
	if (uvret) {
		hb_log_uv_error(uvret);
	}

	if (uvu_thread_priv) {
		HB_MEM_RELEASE(uvu_thread_priv);
	}

	return 0;
}

void shutdown_walk_cb(uv_handle_t* handle, void* arg)
{
	if (!uv_is_closing(handle)) {
		printf("Manually closing handle: %p -- %s\n", handle, uv_handle_type_name(uv_handle_get_type(handle)));
		uv_close(handle, on_close);
	}
}


void uvu_server_run_cleanup()
{
	//if (uvu_accept_timer) HB_MEM_RELEASE(uvu_accept_timer);
	//if (uvu_udp_server) HB_MEM_RELEASE(uvu_udp_server);
	if (uvu_loop) HB_MEM_RELEASE(uvu_loop);
	if (uvu_pool) {
		hb_buffer_pool_cleanup(uvu_pool);
		hb_buffer_pool_delete(&uvu_pool);
	}
	if (uvu_pool_backing_store) HB_MEM_RELEASE(uvu_pool_backing_store);
}


// TODO : CLEANUP ON ERROR
void uvu_server_run(void *priv_data)
{
	int uvret = 0;
	size_t blocks = 10;
	size_t block_size = 512;
	uvu_thread_private_t *thread_priv = (uvu_thread_private_t *)priv_data;

	uvu_loop = NULL;
	uvu_udp_server = NULL;
	uvu_accept_timer = NULL;
	uvu_pool = NULL;
	uvu_pool_backing_store = NULL;


	if (!(uvu_pool_backing_store = (uint8_t *)HB_MEM_ACQUIRE(blocks * block_size))) {
		hb_log_uv_error(UV_ENOMEM);
		goto error;
	}

	if (!(uvu_loop = (uv_loop_t *)HB_MEM_ACQUIRE(sizeof(uv_loop_t)))) {
		hb_log_uv_error(UV_ENOMEM);
		goto error;
	}

	if (!(uvu_udp_server = (uv_udp_t *)HB_MEM_ACQUIRE(sizeof(uv_udp_t)))) {
		hb_log_uv_error(UV_ENOMEM);
		goto error;
	}

	if (!(uvu_accept_timer = (uv_timer_t *)HB_MEM_ACQUIRE(sizeof(uv_timer_t)))) {
		hb_log_uv_error(UV_ENOMEM);
		goto error;
	}

	if (!(uvu_pool = hb_buffer_pool_new())) {
		hb_log_uv_error(UV_ENOMEM);
		goto error;
	}

	if ((uvret = hb_buffer_pool_setup(uvu_pool, uvu_pool_backing_store, block_size, blocks))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_loop_init(uvu_loop))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_timer_init(uvu_loop, uvu_accept_timer))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_timer_start(uvu_accept_timer, timer_cb, 500, 500))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_udp_init(uvu_loop, uvu_udp_server))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	//if ((uvret = uv_udp_nodelay(uvu_udp_server, 1))) {
	//	hb_log_uv_error(uvret);
	//	goto error;
	//}

	if ((uvret = uv_udp_bind(uvu_udp_server, (const struct sockaddr *)&thread_priv->listen_addr, 0))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_listen((uv_stream_t *)uvu_udp_server, 1024, on_new_connection))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_run(uvu_loop, UV_RUN_DEFAULT))) {
		hb_log_uv_error(uvret);
		goto error;
	}

	if ((uvret = uv_loop_close(uvu_loop))) {
		uv_walk(uvu_loop, shutdown_walk_cb, NULL);
		if ((uvret = uv_loop_close(uvu_loop))) {
			hb_log_uv_error(uvret);
			goto error;
		}
		hb_log_error("Walked loop and shutdown cleanly\n");
	}

	//if ((uvret = hb_buffer_pool_debug_print(uvu_pool))) {
	//	hb_log_uv_error(uvret);
	//	goto error;
	//}

	uvu_server_run_cleanup();
	return;

error:
	uvu_server_run_cleanup();
	return;
}

int main(void)
{
	uvu_server_start("0.0.0.0", 7777);

	getchar();

	uvu_server_stop();

	return 0;
}