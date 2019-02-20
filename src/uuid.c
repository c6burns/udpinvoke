#include "udp/uuid.h"

#include "aws/common/uuid.h"

#include "udp/error.h"
#include "udp/allocator.h"
#include "udp/log.h"

// --------------------------------------------------------------------------------------------------------------
hb_uuid_t *hb_uuid_new(void)
{
	return HB_MEM_ACQUIRE(sizeof(hb_uuid_t));
}

// --------------------------------------------------------------------------------------------------------------
void hb_uuid_delete(hb_uuid_t **ptr_uuid)
{
	HB_MEM_RELEASE_PTR((void **)ptr_uuid);
}

// --------------------------------------------------------------------------------------------------------------
int hb_uuid_generate(hb_uuid_t *uuid)
{
	int ret;
	if (!uuid) return HB_ERROR;
	if ((ret = aws_uuid_init((struct aws_uuid *)uuid))) hb_log_error("failed to generate uuid");
	return ret;
}

// --------------------------------------------------------------------------------------------------------------
int hb_uuid_clear(hb_uuid_t *uuid)
{
	if (!uuid) return HB_ERROR;
	memset(uuid, 0, sizeof(hb_uuid_t));
	return HB_SUCCESS;
}

// --------------------------------------------------------------------------------------------------------------
int hb_uuid_compare(hb_uuid_t *uuid1, hb_uuid_t *uuid2)
{
	if (!uuid1 && !uuid2) return HB_SUCCESS;
	if (!uuid1 || !uuid2) return HB_ERROR;

	return aws_uuid_equals((struct aws_uuid *)uuid1, (struct aws_uuid *)uuid2);
}