#include "udp/endpoint.h"

#include "uv.h"

#include "udp/error.h"

// --------------------------------------------------------------------------------------------------------------
int hb_endpoint_set_ip4(hb_endpoint_t *endpoint, const char *ip, uint16_t port)
{
	int ret;

	if (!endpoint) return HB_ERROR;
	if (!ip) return HB_ERROR;

	hb_endpoint_ip4_t *endpoint4 = (hb_endpoint_ip4_t *)endpoint;
	if ((ret = uv_ip4_addr(ip, port, (struct sockaddr_in *)&endpoint4->sockaddr))) return HB_ERROR;
	endpoint4->type = HB_ENDPOINT_TYPE_IPV4;

	return HB_SUCCESS;
}

// --------------------------------------------------------------------------------------------------------------
int hb_endpoint_set_ip6(hb_endpoint_t *endpoint, const char *ip, uint16_t port)
{
	int ret;

	if (!endpoint) return HB_ERROR;
	if (!ip) return HB_ERROR;

	hb_endpoint_ip6_t *endpoint6 = (hb_endpoint_ip6_t *)endpoint;
	if ((ret = uv_ip6_addr(ip, port, (struct sockaddr_in6 *)&endpoint6->sockaddr))) return HB_ERROR;
	endpoint6->type = HB_ENDPOINT_TYPE_IPV6;

	return HB_SUCCESS;
}
