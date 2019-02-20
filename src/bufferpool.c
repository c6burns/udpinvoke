#include "udp/bufferpool.h"

#include <stdio.h>

#include "udp/error.h"
#include "udp/allocator.h"

uint64_t hb_buffer_hash_key_fn(const void *key)
{
	return (uint64_t)key;
}

bool hb_buffer_hash_eq_fn(const void *a, const void *b)
{
	return (uint64_t)a == (uint64_t)b;
}

void hb_buffer_hash_destroy_fn(void *value)
{
	if (!value) return;
	HB_MEM_RELEASE(value);
}

// --------------------------------------------------------------------------------------------------------------
hb_buffer_pool_t *hb_buffer_pool_new()
{
	hb_buffer_pool_t *pool;

	if (!(pool = HB_MEM_ACQUIRE(sizeof(hb_buffer_pool_t)))) {
		return NULL;
	}
	memset(pool, 0, sizeof(hb_buffer_pool_t));

	if (!(pool->available = HB_MEM_ACQUIRE(sizeof(aws_linked_list_t)))) {
		hb_buffer_pool_delete(&pool);
		return NULL;
	}

	if (!(pool->reserved = HB_MEM_ACQUIRE(sizeof(aws_hash_table_t)))) {
		hb_buffer_pool_delete(&pool);
		return NULL;
	}

	aws_mutex_init(&pool->mtx);

	aws_atomic_init_int(&pool->state, HB_BUFFER_POOL_NEW);

	return pool;
}

// --------------------------------------------------------------------------------------------------------------
void hb_buffer_pool_delete(hb_buffer_pool_t **p_pool)
{
	if (!p_pool) return;

	hb_buffer_pool_t *pool = *p_pool;
	if (!pool) return;

	aws_mutex_lock(&pool->mtx);
	aws_atomic_store_int(&pool->state, HB_BUFFER_POOL_RESET);

	if (pool->available) {
		HB_MEM_RELEASE_PTR(&pool->available);
	}

	if (pool->reserved) {
		HB_MEM_RELEASE_PTR(&pool->reserved);
	}

	aws_mutex_unlock(&pool->mtx);
	aws_mutex_clean_up(&pool->mtx);

	HB_MEM_RELEASE_PTR(&pool);
}

// --------------------------------------------------------------------------------------------------------------
int hb_buffer_pool_populate(hb_buffer_pool_t *pool, void *rawmem, size_t block_size, size_t blocks)
{
	uint8_t *p = rawmem;

	for (int b = 0; b < blocks; b++) {
		pool->buffers[b].id = b;
		pool->buffers[b].type = 0;
		pool->buffers[b].len = block_size;
		pool->buffers[b].data = p;
		aws_linked_list_push_back(pool->available, &pool->buffers[b].node);
		
		p += block_size;
	}

	return 0;
}

// --------------------------------------------------------------------------------------------------------------
int hb_buffer_pool_setup(hb_buffer_pool_t *pool, void *rawmem, size_t block_size, size_t blocks)
{
	if (!pool) return HB_ERROR_INVAL;
	if (!pool->available) return HB_ERROR_INVAL;
	if (!pool->reserved) return HB_ERROR_INVAL;
	if (block_size <= 0) return HB_ERROR_INVAL;
	if (blocks <= 0) return HB_ERROR_INVAL;
	if (!rawmem) return HB_ERROR_INVAL;

	if (aws_atomic_load_int(&pool->state) != HB_BUFFER_POOL_NEW) return HB_ERROR_INVAL;
	aws_mutex_lock(&pool->mtx);
	aws_atomic_store_int(&pool->state, HB_BUFFER_POOL_READY);

	if (!(pool->buffers = HB_MEM_ACQUIRE(sizeof(hb_buffer_t) * blocks))) {
		aws_mutex_unlock(&pool->mtx);
		return HB_ERROR_NOMEM;
	}

	aws_linked_list_init(pool->available);

	if (aws_hash_table_init(pool->reserved, hb_default_allocator.priv, blocks, hb_buffer_hash_key_fn, hb_buffer_hash_eq_fn, NULL, NULL)) {
		aws_mutex_unlock(&pool->mtx);
		return HB_ERROR_NOMEM;
	}

	if (hb_buffer_pool_populate(pool, rawmem, block_size, blocks)) {
		aws_mutex_unlock(&pool->mtx);
		return HB_ERROR_NOMEM;
	}

	aws_mutex_unlock(&pool->mtx);

	return 0;
}

// --------------------------------------------------------------------------------------------------------------
void hb_buffer_pool_cleanup(hb_buffer_pool_t *pool)
{
	if (!pool) return;

	if (aws_atomic_load_int(&pool->state) != HB_BUFFER_POOL_READY) return;
	aws_mutex_lock(&pool->mtx);
	aws_atomic_store_int(&pool->state, HB_BUFFER_POOL_RESET);

	if (pool->buffers) {
		HB_MEM_RELEASE_PTR(&pool->buffers);
	}

	if (pool->reserved) {
		aws_hash_table_clean_up(pool->reserved);
	}

	aws_mutex_unlock(&pool->mtx);
}

// --------------------------------------------------------------------------------------------------------------
int hb_buffer_pool_mark_reserved(hb_buffer_pool_t *pool, hb_buffer_t *buffer)
{
	int ret, created;
	ret = aws_hash_table_put(pool->reserved, buffer->data, buffer, &created);
	return (ret || !created);
}

// --------------------------------------------------------------------------------------------------------------
hb_buffer_t *hb_buffer_pool_unmark_reserved(hb_buffer_pool_t *pool, uint8_t *bufferdata)
{
	int ret, removed;
	hb_buffer_t *buffer = NULL;
	struct aws_hash_element elem;
	ret = aws_hash_table_remove(pool->reserved, (void *)bufferdata, &elem, &removed);

	if (!ret && removed) return elem.value;
	return NULL;
}

// --------------------------------------------------------------------------------------------------------------
hb_buffer_t *hb_buffer_pool_pop_available(hb_buffer_pool_t *pool)
{
	int ret;

	hb_buffer_t *buffer;
	aws_linked_list_node_t *node;

	if (aws_linked_list_empty(pool->available)) return NULL;
	if (!(node = aws_linked_list_pop_front(pool->available))) return NULL;

	buffer = AWS_CONTAINER_OF(node, hb_buffer_t, node);
	if ((ret = hb_buffer_pool_mark_reserved(pool, buffer))) {
		aws_linked_list_push_front(pool->available, node);
		return NULL;
	}

	return buffer;
}

// --------------------------------------------------------------------------------------------------------------
hb_buffer_t *hb_buffer_pool_push_available(hb_buffer_pool_t *pool, uint8_t *bufferdata)
{
	hb_buffer_t *buffer;
	if (!(buffer = hb_buffer_pool_unmark_reserved(pool, bufferdata))) return NULL;

	aws_linked_list_push_back(pool->available, &buffer->node);

	return buffer;
}

// --------------------------------------------------------------------------------------------------------------
uint8_t *hb_buffer_pool_acquire(hb_buffer_pool_t *pool, uint64_t type)
{
	if (!pool) return NULL;
	if (aws_atomic_load_int(&pool->state) != HB_BUFFER_POOL_READY) return NULL;

	aws_mutex_lock(&pool->mtx);

	hb_buffer_t *buffer = hb_buffer_pool_pop_available(pool);

	aws_mutex_unlock(&pool->mtx);

	if (!buffer) return NULL;
	
	buffer->type = type;
	return buffer->data;
}

// --------------------------------------------------------------------------------------------------------------
int hb_buffer_pool_release(hb_buffer_pool_t *pool, uint8_t *bufferdata)
{
	if (!pool) return HB_ERROR_INVAL;
	if (aws_atomic_load_int(&pool->state) != HB_BUFFER_POOL_READY) return HB_ERROR_INVAL;
	if (!bufferdata) return HB_ERROR_INVAL;

	hb_buffer_t *buffer;

	aws_mutex_lock(&pool->mtx);

	buffer = hb_buffer_pool_push_available(pool, bufferdata);

	aws_mutex_unlock(&pool->mtx);

	return 0;
}

// --------------------------------------------------------------------------------------------------------------
int hb_buffer_pool_debug_print(hb_buffer_pool_t *pool)
{
	if (!pool) return HB_ERROR_INVAL;
	if (aws_atomic_load_int(&pool->state) != HB_BUFFER_POOL_READY) return HB_ERROR_INVAL;

	aws_mutex_lock(&pool->mtx);

	printf("------------------------------------------------------------\nReservations:\n");
	struct aws_hash_iter hit;
	for (hit = aws_hash_iter_begin(pool->reserved); !aws_hash_iter_done(&hit); aws_hash_iter_next(&hit)) {
		hb_buffer_t *buffer = (hb_buffer_t *)hit.element.value;
		printf("Addr: %p -> id: %zu, type: %zu, len: %zu\n", buffer->data, buffer->id, buffer->type, buffer->len);
	}

	//printf("\n\nAvailable:\n");
	//struct aws_linked_list_node *node;
	//for (node = aws_linked_list_begin(pool->available); node != aws_linked_list_end(pool->available); node = aws_linked_list_next(node)) {
	//	hb_buffer_t *buffer = AWS_CONTAINER_OF(node, hb_buffer_t, node);
	//	printf("Addr: %p -> id: %zu, type: %zu, len: %zu\n", buffer->data, buffer->id, buffer->type, buffer->len);
	//}
	//printf("\n\n");

	aws_mutex_unlock(&pool->mtx);

	return 0;
}
