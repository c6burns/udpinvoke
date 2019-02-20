#include "udp/allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "udp/error.h"


// private ------------------------------------------------------------------------------------------------------
void *hb_aws_default_acquire(struct aws_allocator *allocator, size_t size)
{
	return malloc(size);
}

// private ------------------------------------------------------------------------------------------------------
void *hb_aws_default_realloc(struct aws_allocator *allocator, void **ptr, size_t oldsize, size_t newsize)
{
	if (!ptr) return NULL;
	if (!*ptr) return NULL;
	return realloc(*ptr, newsize);
}

// private ------------------------------------------------------------------------------------------------------
void hb_aws_default_release(struct aws_allocator *allocator, void *ptr)
{
	if (!ptr) return;
	free(ptr);
}

aws_allocator_t hb_aws_default_allocator = {
	.mem_acquire = hb_aws_default_acquire,
	.mem_release = hb_aws_default_release,
	.mem_realloc = hb_aws_default_realloc,
	.impl = NULL,
};


// private ------------------------------------------------------------------------------------------------------
void *hb_allocator_default_acquire(const struct hb_allocator_s *allocator, size_t sz)
{
	uint8_t *mem;
	if (!(mem = aws_mem_acquire(&hb_aws_default_allocator, sz))) return NULL;

	return (void *)mem;
}

// private ------------------------------------------------------------------------------------------------------
void hb_allocator_default_release(const struct hb_allocator_s *allocator, void *ptr)
{
	if (!ptr) return;

	aws_mem_release(&hb_aws_default_allocator, ptr);
}

// private ------------------------------------------------------------------------------------------------------
void hb_allocator_default_release_ptr(const struct hb_allocator_s *allocator, void **ptr)
{
	if (!ptr) return;
	if (!*ptr) return;

	aws_mem_release(&hb_aws_default_allocator, *ptr);

	*ptr = NULL;
}

hb_allocator_t hb_default_allocator = {
	.acquire_fn = hb_allocator_default_acquire,
	.release_fn = hb_allocator_default_release,
	.release_ptr_fn = hb_allocator_default_release_ptr,
	.config = {
		.priv = NULL,
	},
	.priv = &hb_aws_default_allocator,
};


// --------------------------------------------------------------------------------------------------------------
hb_allocator_t *hb_allocator_new(void)
{
	hb_allocator_t *allocator;
	if (!(allocator = aws_mem_acquire(&hb_aws_default_allocator, sizeof(hb_allocator_t)))) return NULL;
	return allocator;
}

// --------------------------------------------------------------------------------------------------------------
void hb_allocator_delete(hb_allocator_t **ptr_allocator)
{
	if (!ptr_allocator) return;
	if (!*ptr_allocator) return;
	aws_mem_release(&hb_aws_default_allocator, *ptr_allocator);
	*ptr_allocator = NULL;
}

// --------------------------------------------------------------------------------------------------------------
int hb_allocator_setup(hb_allocator_t *allocator, const hb_allocator_config_t *config, hb_allocator_aquire_fn acquire_fn, hb_allocator_release_fn release_fn)
{
	if (!allocator) return HB_ERROR;

	if (config) {
		memcpy(&allocator->config, config, sizeof(hb_allocator_config_t));
	}

	if (acquire_fn) allocator->acquire_fn = acquire_fn;
	else allocator->acquire_fn = hb_allocator_default_acquire;

	if (release_fn) allocator->release_fn = release_fn;
	else allocator->release_fn = hb_allocator_default_release;

	return HB_SUCCESS;
}

// --------------------------------------------------------------------------------------------------------------
int hb_allocator_cleanup(hb_allocator_t *allocator)
{
	return HB_SUCCESS;
}

// --------------------------------------------------------------------------------------------------------------
void *hb_allocator_acquire(const hb_allocator_t *allocator, size_t sz)
{
	if (!allocator) return NULL;
	if (!allocator->acquire_fn) return NULL;

	return allocator->acquire_fn(allocator, sz);
}

// --------------------------------------------------------------------------------------------------------------
void hb_allocator_release(const hb_allocator_t *allocator, void *ptr)
{
	if (!allocator) return;
	if (!allocator->release_fn) return;

	allocator->release_fn(allocator, ptr);
}

// --------------------------------------------------------------------------------------------------------------
void hb_allocator_release_ptr(const hb_allocator_t *allocator, void **ptr)
{
	if (!allocator) return;
	if (!allocator->release_fn) return;

	allocator->release_ptr_fn(allocator, ptr);
}