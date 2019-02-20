#ifndef HB_ALLOCATOR_H
#define HB_ALLOCATOR_H

#include <stdlib.h>

#include "aws/common/common.h"

#define HB_MEM_DEBUG 0
#define HB_MEM_1K 1024
#define HB_MEM_1M HB_MEM_1K * 1024
#define HB_MEM_1G HB_MEM_1M * 1024

#if HB_MEM_DEBUG
#	define HB_MEM_ACQUIRE(sz) aws_mem_acquire(&hb_aws_default_allocator, sz, __FILENAME__, __LINE__, __FUNCTION__); 
#	define HB_MEM_RELEASE(ptr) aws_mem_release(&hb_aws_default_allocator, ptr, __FILENAME__, __LINE__, __FUNCTION__);
#else
#	define HB_MEM_ACQUIRE(sz) hb_allocator_acquire(&hb_default_allocator, sz)
#	define HB_MEM_RELEASE(ptr) hb_allocator_release(&hb_default_allocator, ptr)
#	define HB_MEM_RELEASE_PTR(ptr) hb_allocator_release_ptr(&hb_default_allocator, ptr)
#endif


typedef struct hb_allocator_config_s {
	void *priv;
} hb_allocator_config_t;

struct hb_allocator_s;
#if HB_MEM_DEBUG
typedef void *(*hb_allocator_aquire_fn)(const struct hb_allocator_s *allocator, size_t sz, const char *file_name, const int line, const char *function_name);
typedef void(*hb_allocator_release_fn)(const struct hb_allocator_s *allocator, void *ptr, const char *file_name, const int line, const char *function_name);
typedef void(*hb_allocator_release_ptr_fn)(const struct hb_allocator_s *allocator, void **ptr, const char *file_name, const int line, const char *function_name);
#else
typedef void *(*hb_allocator_aquire_fn)(const struct hb_allocator_s *allocator, size_t sz);
typedef void(*hb_allocator_release_fn)(const struct hb_allocator_s *allocator, void *ptr);
typedef void(*hb_allocator_release_ptr_fn)(const struct hb_allocator_s *allocator, void **ptr);
#endif

typedef struct aws_allocator aws_allocator_t;
typedef struct hb_allocator_s {
	hb_allocator_aquire_fn acquire_fn;
	hb_allocator_release_fn release_fn;
	hb_allocator_release_ptr_fn release_ptr_fn;
	hb_allocator_config_t config;
	void *priv;
} hb_allocator_t;


hb_allocator_t *hb_allocator_new(void);
void hb_allocator_delete(hb_allocator_t **ptr_allocator);
int hb_allocator_setup(hb_allocator_t *allocator, const hb_allocator_config_t *config, hb_allocator_aquire_fn acquire_fn, hb_allocator_release_fn release_fn);
int hb_allocator_cleanup(hb_allocator_t *allocator);

#if HB_MEM_DEBUG
void *hb_allocator_acquire(const hb_allocator_t *allocator, size_t sz, const char *file_name, const int line, const char *function_name);
void hb_allocator_release(const hb_allocator_t *allocator, void *ptr, const char *file_name, const int line, const char *function_name);
void hb_allocator_release_ptr(const hb_allocator_t *allocator, void **ptr, const char *file_name, const int line, const char *function_name);
#else
void *hb_allocator_acquire(const hb_allocator_t *allocator, size_t sz);
void hb_allocator_release(const hb_allocator_t *allocator, void *ptr);
void hb_allocator_release_ptr(const hb_allocator_t *allocator, void **ptr);
#endif

// these are now private within the translation unit
//void *hb_aws_default_acquire(struct aws_allocator *allocator, size_t size);
//void *hb_aws_default_realloc(struct aws_allocator *allocator, void **ptr, size_t oldsize, size_t newsize);
//void hb_aws_default_release(struct aws_allocator *allocator, void *ptr);

// this provides a default allocator we can use right away without creating anything custom
hb_allocator_t hb_default_allocator;

aws_allocator_t hb_aws_default_allocator;

#endif
