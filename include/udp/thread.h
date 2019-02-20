#ifndef HB_THREAD_H
#define HB_THREAD_H

#define HB_TIME_MS_PER_S 1000
#define HB_TIME_US_PER_S 1000000
#define HB_TIME_NS_PER_S 1000000000

#define HB_TIME_US_PER_MS 1000
#define HB_TIME_NS_PER_MS 1000000

#define HB_TIME_NS_PER_US 1000

#define HB_THREAD_SLEEP_S(s) aws_thread_current_sleep(ms * HB_TIME_NS_PER_S)
#define HB_THREAD_SLEEP_MS(ms) aws_thread_current_sleep(ms * HB_TIME_NS_PER_MS)

#include <stdint.h>

typedef enum hb_tstamp_unit_e {
	HB_TSTAMP_S = 1,
	HB_TSTAMP_MS = 1000,
	HB_TSTAMP_US = 1000000,
	HB_TSTAMP_NS = 1000000000,
} hb_tstamp_unit_t;

uint64_t hb_tstamp_convert(uint64_t tstamp, hb_tstamp_unit_t from, hb_tstamp_unit_t to, uint64_t *remainder);

void hb_thread_sleep(uint64_t ns);
#define hb_thread_sleep_s(tstamp) hb_thread_sleep(hb_tstamp_convert(tstamp, HB_TSTAMP_S, HB_TSTAMP_NS, NULL))
#define hb_thread_sleep_ms(tstamp) hb_thread_sleep(hb_tstamp_convert(tstamp, HB_TSTAMP_MS, HB_TSTAMP_NS, NULL))

uint64_t hb_thread_id(void);

#endif