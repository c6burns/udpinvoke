#ifndef HB_LOG_H
#define HB_LOG_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "udp/thread.h"


#if _MSC_VER
#	define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#	define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define HB_LOG_FILENAME "hubbub.log"
//#define HB_LOG_DISABLE
#define HB_LOG_USE_COLOR
#define HB_THREAD_ID hb_thread_id()

typedef void(*hb_log_lock_fn)(void *udata, int lock);

typedef enum hb_log_level_e { 
	HB_LOG_LEVEL_TRACE,
	HB_LOG_LEVEL_DEBUG,
	HB_LOG_LEVEL_INFO,
	HB_LOG_LEVEL_WARN,
	HB_LOG_LEVEL_ERROR,
	HB_LOG_LEVEL_FATAL,
} hb_log_level_t;

#ifdef HB_LOG_DISABLE
#	define hb_log_uv_error(...)

#	define hb_log(...) 
#	define hb_log_trace(...) 
#	define hb_log_debug(...) 
#	define hb_log_info(...) 
#	define hb_log_warn(...) 
#	define hb_log_error(...) 
#	define hb_log_fatal(...) 

#	define hb_log_enable(b) 
#	define hb_log_disable(b) 
#	define hb_log_level(l) 
#	define hb_log_file(f) 
#else
#	define hb_log_uv_error(code) hb_log_error("uv error code: %d -- %s -- %s", code, uv_err_name(code), uv_strerror(code))
#	define hb_log(...) hb_log_log(HB_LOG_LEVEL_DEBUG, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_trace(...) hb_log_log(HB_LOG_LEVEL_TRACE, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_debug(...) hb_log_log(HB_LOG_LEVEL_DEBUG, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_info(...) hb_log_log(HB_LOG_LEVEL_INFO, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_warn(...) hb_log_log(HB_LOG_LEVEL_WARN, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_warning(...) hb_log_log(HB_LOG_LEVEL_WARN, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_error(...) hb_log_log(HB_LOG_LEVEL_ERROR, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)
#	define hb_log_fatal(...) hb_log_log(HB_LOG_LEVEL_FATAL, __FUNCTION__, __FILENAME__, __LINE__, HB_THREAD_ID, __VA_ARGS__)

#	define hb_log_enable(b) hb_log_set_quiet(0);
#	define hb_log_disable(b) hb_log_set_quiet(1);
#	define hb_log_level(l) hb_log_set_level(l);
#	define hb_log_file(f) hb_log_set_fp(f);
#endif


void hb_log_setup();
void hb_log_cleanup();

// TODO: udata and locking should probably be private
void hb_log_color(int enable);
void hb_log_set_udata(void *udata);
void hb_log_set_lock(hb_log_lock_fn fn);
void hb_log_set_fp(FILE *fp);
void hb_log_set_level(int level);
void hb_log_set_quiet(int enable);

void hb_log_log(int level, const char *func, const char *file, int line, uint64_t thread_id, const char *fmt, ...);

#endif