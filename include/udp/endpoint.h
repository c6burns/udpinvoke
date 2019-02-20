#ifndef HB_ENDPOINT_H
#define HB_ENDPOINT_H

#include <stdint.h>

#define HB_ENDPOINT_MAX_SIZE 256
#define HB_ENDPOINT_SOCKADDR_STORAGE_SIZE 128

typedef struct hb_sockaddr_storage_s {
	uint16_t family;
	uint8_t pad0[HB_ENDPOINT_SOCKADDR_STORAGE_SIZE - sizeof(uint16_t)];
} hb_sockaddr_storage_t;

typedef struct hb_sockaddr4_s {
	uint16_t family;
	uint16_t port;
	uint32_t addr;
	uint8_t pad0[HB_ENDPOINT_SOCKADDR_STORAGE_SIZE - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t)];
} hb_sockaddr4_t;

typedef struct hb_sockaddr6_s {
	uint16_t family;
	uint16_t port;
	uint32_t  flowinfo;
	uint8_t addr[16];
	uint32_t scope;
	uint8_t pad0[HB_ENDPOINT_SOCKADDR_STORAGE_SIZE - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t) - (sizeof(uint8_t) * 16)];
} hb_sockaddr6_t;


typedef enum hb_endpoint_type_e {
	HB_ENDPOINT_TYPE_NONE,
	HB_ENDPOINT_TYPE_IPV4,
	HB_ENDPOINT_TYPE_IPV6,
	HB_ENDPOINT_TYPE_PIPE,
	HB_ENDPOINT_TYPE_FILE,
} hb_endpoint_type_t;

typedef struct hb_endpoint_s {
	uint64_t type; // 64 bit (vs anything lower) won't mess up alignment of structs coming after (eg. sockaddr)
	uint8_t padding[HB_ENDPOINT_MAX_SIZE - sizeof(uint64_t)];
} hb_endpoint_t;

typedef struct hb_endpoint_ipv4_s {
	uint64_t type;
	hb_sockaddr4_t sockaddr;
} hb_endpoint_ip4_t;

typedef struct hb_endpoint_ipv6_s {
	uint64_t type;
	hb_sockaddr6_t sockaddr;
} hb_endpoint_ip6_t;

typedef struct hb_endpoint_file_s {
	uint64_t type;
	char file_name[HB_ENDPOINT_MAX_SIZE - sizeof(uint64_t)];
} hb_endpoint_file_t;


int hb_endpoint_set_ip4(hb_endpoint_t *endpoint, const char *ip, uint16_t port);
int hb_endpoint_set_ip6(hb_endpoint_t *endpoint, const char *ip, uint16_t port);

#endif