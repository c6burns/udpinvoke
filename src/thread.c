#include "udp/thread.h"

#include "aws/common/thread.h"
#include "aws/common/clock.h"

// --------------------------------------------------------------------------------------------------------------
uint64_t hb_tstamp_convert(uint64_t tstamp, hb_tstamp_unit_t from, hb_tstamp_unit_t to, uint64_t *remainder)
{
	return aws_timestamp_convert(tstamp, from, to, remainder);
}

// --------------------------------------------------------------------------------------------------------------
void hb_thread_sleep(uint64_t ns)
{
	aws_thread_current_sleep(ns);
}

// --------------------------------------------------------------------------------------------------------------
uint64_t hb_thread_id(void)
{
	return aws_thread_current_thread_id();
}