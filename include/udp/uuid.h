#ifndef HB_UUID_H
#define HB_UUID_H

#include <stdint.h>

typedef struct hb_uuid_s {
	uint8_t uuid_data[16];
} hb_uuid_t;

hb_uuid_t *hb_uuid_new(void);
void hb_uuid_delete(hb_uuid_t **ptr_uuid);
int hb_uuid_generate(hb_uuid_t *uuid);
int hb_uuid_clear(hb_uuid_t *uuid);
int hb_uuid_compare(hb_uuid_t *uuid1, hb_uuid_t *uuid2);
#define hb_uuid_cmp(uuid1, uuid2) hb_uuid_compare(uuid1, uuid2)

#endif