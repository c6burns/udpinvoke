#include "PluginAPI-2018.3.2f1/IUnityInterface.h"

#include "aws/common/byte_buf.h"
#include "aws/common/device_random.h"

#include "udp/error.h"
#include "udp/allocator.h"

// ----------------------------------------------------------------------------------------------------------------------------------
//void UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API UnityPluginLoad(IUnityInterfaces* unityInterfaces)
//{
//}

// ----------------------------------------------------------------------------------------------------------------------------------
//void UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API UnityPluginUnload(void)
//{
//}

#define HB_BLOCK_SIZE 512

struct hb_mem_block {
	uint64_t size;
	uint64_t len;
	uint64_t type;
	uint8_t *buf;
};

static uint8_t *hb_buffer = NULL;
static struct hb_mem_block *hb_blocks = NULL;
int hb_block_count = 8192;
int hb_block_size = HB_BLOCK_SIZE;



int UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API hb_unity_memtest_alloc()
{
	HB_GUARD(hb_blocks);
	HB_GUARD(hb_buffer);

	int buffer_len = hb_block_count * hb_block_size;
	hb_blocks = HB_MEM_ACQUIRE(sizeof(*hb_blocks) * hb_block_count);
	hb_buffer = HB_MEM_ACQUIRE(hb_block_count * hb_block_size);
	
	struct aws_byte_buf buffer = {
		.len = buffer_len,
		.buffer = hb_buffer,
		.capacity = buffer_len,
		.allocator = NULL,
	};
	HB_GUARD(aws_device_random_buffer(&buffer));

	uint8_t *buf = hb_buffer;
	for (int i = 0; i < hb_block_count; i++) {
		hb_blocks[i].size = 512;
		hb_blocks[i].len = 512;
		hb_blocks[i].type = 123;
		hb_blocks[i].buf = buf;

		buf += hb_block_size;
	}

	return HB_SUCCESS;
}

int UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API hb_unity_memtest_randomize()
{
	HB_GUARD_NULL(hb_blocks);
	struct aws_byte_buf buffer = {
		.len = hb_block_count * hb_block_size,
		.buffer = hb_buffer,
		.capacity = hb_block_count * hb_block_size,
		.allocator = NULL,
	};
	HB_GUARD(aws_device_random_buffer(&buffer));
	return HB_SUCCESS;
}

int UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API hb_unity_memtest_ptr(void **out_blocks, void **out_buffer, int *block_count, int *block_size)
{
	HB_GUARD_NULL(hb_blocks);
	HB_GUARD_NULL(hb_buffer);
	HB_GUARD_NULL(out_buffer);
	HB_GUARD_NULL(out_blocks);

	*out_blocks = hb_blocks;
	*out_buffer = hb_buffer;
	*block_count = hb_block_count;
	*block_size = hb_block_size;

	return HB_SUCCESS;
}

int UNITY_INTERFACE_EXPORT UNITY_INTERFACE_API hb_unity_memtest_dealloc()
{
	HB_GUARD(hb_blocks);
	HB_GUARD(hb_buffer);

	HB_MEM_RELEASE_PTR(&hb_blocks);
	HB_MEM_RELEASE_PTR(&hb_buffer);

	return HB_SUCCESS;
}
