#ifndef HB_BUFFER_POOL_H
#define HB_BUFFER_POOL_H


#include "aws/common/array_list.h"
#include "aws/common/linked_list.h"
#include "aws/common/hash_table.h"
#include "aws/common/mutex.h"
#include "aws/common/atomics.h"


typedef struct aws_hash_table aws_hash_table_t;
typedef struct aws_array_list aws_array_list_t;
typedef struct aws_linked_list aws_linked_list_t;
typedef struct aws_linked_list_node aws_linked_list_node_t;
typedef struct aws_mutex aws_mutex_t;
typedef volatile struct aws_atomic_var aws_atomic_t;

enum hb_buffer_pool_state {
	HB_BUFFER_POOL_NEW = 0,
	HB_BUFFER_POOL_READY,
	HB_BUFFER_POOL_RESET
};

typedef struct {
	aws_linked_list_node_t node;
	uint64_t id;
	uint64_t type;
	uint64_t len;
	uint8_t *data;
} hb_buffer_t;

typedef struct {
	aws_linked_list_t *available;
	aws_hash_table_t *reserved;
	aws_mutex_t mtx;
	size_t blocks;
	size_t block_size;
	aws_atomic_t state;
	hb_buffer_t *buffers;
} hb_buffer_pool_t;


hb_buffer_pool_t *hb_buffer_pool_new();
void hb_buffer_pool_delete(hb_buffer_pool_t **p_pool);

int hb_buffer_pool_setup(hb_buffer_pool_t *pool, void *rawmem, size_t block_size, size_t blocks);
void hb_buffer_pool_cleanup(hb_buffer_pool_t *pool);

uint8_t *hb_buffer_pool_acquire(hb_buffer_pool_t *pool, uint64_t type);
int hb_buffer_pool_release(hb_buffer_pool_t *pool, uint8_t *bufferdata);

int hb_buffer_pool_debug_print(hb_buffer_pool_t *pool);

#endif