#ifndef LIBUV_SERVER_H
#define LIBUV_SERVER_H

#include <stdint.h>
#include "uv.h"


typedef struct uvu_thread_private_s {
	struct sockaddr_storage listen_addr;
} uvu_thread_private_t;

int uvu_server_start(const char *ipstr, uint16_t port);
int uvu_server_stop();
void uvu_server_run(void *priv_data);

#endif