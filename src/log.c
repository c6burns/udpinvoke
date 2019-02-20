/*
 * Copyright (c) 2017 rxi -- this is the original copyright holder. Thanks guy!
 * Additional Copyright (c) 2019 c6burns -- many a modification
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define _CRT_SECURE_NO_WARNINGS
#if _MSC_VER
#	include <windows.h>
#endif

#include "udp/log.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "aws/common/mutex.h"
#include "aws/common/thread.h"
#include "aws/common/condition_variable.h"


static const char *level_names[] = {
	"TRACE",
	"DEBUG",
	"INFO",
	"WARN",
	"ERROR",
	"FATAL",
};

#ifdef HB_LOG_USE_COLOR
static const char *level_colors[] = {
	"\x1b[90m",
	"\x1b[36m",
	"\x1b[32m",
	"\x1b[33m",
	"\x1b[31m",
	"\x1b[35m",
};
#endif

typedef struct aws_mutex aws_mutex_t;
aws_mutex_t hb_log_mtx;
FILE *hb_log_fp = NULL;
int hb_log_ready = 0;

typedef struct hb_log_s {
	void *udata;
	hb_log_lock_fn lock;
	FILE *fp;
	int level;
	int quiet;
	int color;
} hb_log_t;

static hb_log_t hb_log_ctx;

//typedef struct aws_thread hb_thread_t;
//typedef struct aws_condition_variable hb_condition_t;
//
//typedef struct hb_log_thread_private_s {
//	hb_condition_t cond;
//} hb_log_thread_private_t;
//hb_thread_t hb_log_thread;


// private ------------------------------------------------------------------------------------------------------
void hb_log_lock_impl(void *udata, int lock)
{
	aws_mutex_t *mtx = (aws_mutex_t *)udata;
	if (lock) aws_mutex_lock(mtx);
	else aws_mutex_unlock(mtx);
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_setup()
{
#ifndef HB_LOG_DISABLE
	if (hb_log_ready) return;
	hb_log_ready = 1;

	memset(&hb_log_ctx, 0, sizeof(hb_log_ctx));

	hb_log_color(1);

	aws_mutex_init(&hb_log_mtx);
	hb_log_set_udata(&hb_log_mtx);
	hb_log_set_lock(hb_log_lock_impl);

#	ifdef HB_LOG_FILENAME
	hb_log_fp = fopen(HB_LOG_FILENAME, "a+");
	if (hb_log_fp) hb_log_set_fp(hb_log_fp);
#	endif

	hb_log_trace("Application logging started ... ");
#endif
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_cleanup()
{
#ifndef HB_LOG_DISABLE
	hb_log_trace("Application logging completed");
	
	if (!hb_log_ready) return;
	hb_log_ready = 0;
	aws_mutex_clean_up(&hb_log_mtx);
	if (hb_log_fp) fclose(hb_log_fp);
#endif
}

void hb_log_color(int enable)
{
#ifdef HB_LOG_USE_COLOR
	if (enable) {
#	if _MSC_VER
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hOut == INVALID_HANDLE_VALUE) {
			enable = 0;
		}

		DWORD dwMode = 0;
		if (!GetConsoleMode(hOut, &dwMode)) {
			enable = 0;
		}

		dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		if (!SetConsoleMode(hOut, dwMode)) {
			enable = 0;
		}
#	endif
	}

	hb_log_ctx.color = enable;
#endif
}

// --------------------------------------------------------------------------------------------------------------
static void hb_log_lock(void)
{
	if (hb_log_ctx.lock) {
		hb_log_ctx.lock(hb_log_ctx.udata, 1);
	}
}

// --------------------------------------------------------------------------------------------------------------
static void hb_log_unlock(void)
{
	if (hb_log_ctx.lock) {
		hb_log_ctx.lock(hb_log_ctx.udata, 0);
	}
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_set_udata(void *udata)
{
	hb_log_ctx.udata = udata;
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_set_lock(hb_log_lock_fn fn)
{
	hb_log_ctx.lock = fn;
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_set_fp(FILE *fp)
{
	hb_log_ctx.fp = fp;
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_set_level(int level)
{
	hb_log_ctx.level = level;
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_set_quiet(int enable)
{
	hb_log_ctx.quiet = enable ? 1 : 0;
}

// --------------------------------------------------------------------------------------------------------------
void hb_log_log(int level, const char *func, const char *file, int line, uint64_t thread_id, const char *fmt, ...)
{
	if (!hb_log_ready) hb_log_setup();

	if (level < hb_log_ctx.level) return;

	hb_log_lock();

	time_t tstamp = time(NULL);
	struct tm *local_time = localtime(&tstamp);

	if (!hb_log_ctx.quiet) {
		va_list args;
		char time_buf[32];
		time_buf[strftime(time_buf, sizeof(time_buf), "%H:%M:%S", local_time)] = '\0';

		if (hb_log_ctx.color) {
			fprintf(stderr, "%s %s%-5s\x1b[0m \x1b[90m%zu:%s:%d - %s: \x1b[0m ", time_buf, level_colors[level], level_names[level], thread_id, file, line, func);
		} else {
			fprintf(stderr, "%s %-5s %zu:%s:%d - %s: ", time_buf, level_names[level], thread_id, file, line, func);
		}

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	if (hb_log_ctx.fp) {
		va_list args;
		char time_buf[64];
		time_buf[strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", local_time)] = '\0';
		fprintf(hb_log_ctx.fp, "%s %-5s %zu:%s:%d - %s: ", time_buf, level_names[level], thread_id, file, line, func);
		va_start(args, fmt);
		vfprintf(hb_log_ctx.fp, fmt, args);
		va_end(args);
		fprintf(hb_log_ctx.fp, "\n");
		fflush(hb_log_ctx.fp);
	}

	hb_log_unlock();
}
