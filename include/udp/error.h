#ifndef HB_ERROR_H
#define HB_ERROR_H

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define HB_SUCCESS 0
#define HB_ERROR -1
#define HB_ERROR_AGAIN -EAGAIN
#define HB_ERROR_NOMEM -ENOMEM
#define HB_ERROR_INVAL -EINVAL

#define HB_ASSERT(expr) assert(expr)
#define HB_GUARD(expr) if ((expr)) return HB_ERROR
#define HB_GUARD_LOG(expr, errstr) if ((expr)) { hb_log_error(errstr); return HB_ERROR; }
#define HB_GUARD_PTR(expr) if (!(expr)) return HB_ERROR
#define HB_GUARD_NULL(expr) HB_GUARD_PTR(expr)
#define HB_GUARD_RET(expr, ret) { if ((ret = (expr))) return ret; }
#define HB_GUARD_GOTO(expr, lbl) { if ((expr)) goto lbl; }
#define HB_GUARD_RET_GOTO(expr, ret, lbl) if ((ret = (expr))) goto lbl; }
#define HB_GUARD_BREAK(expr) if ((expr)) break
#define HB_GUARD_RET_BREAK(expr, ret) if ((ret = (expr))) break

#ifdef _WIN32
#	define HB_PLATFORM_WINDOWS 1

#	ifdef _WIN64
#	else
#	endif
#elif __APPLE__
#	include <TargetConditionals.h>
#	if TARGET_IPHONE_SIMULATOR
#		define HB_PLATFORM_IOS 1
#	elif TARGET_OS_IPHONE
#		define HB_PLATFORM_IOS 1
#	elif TARGET_OS_MAC
#		define HB_PLATFORM_OSX 1
#	else
#   	error "Unknown Apple platform"
#	endif
#elif __ANDROID__
#	define HB_PLATFORM_ANDROID 1
#elif __linux__
#	define HB_PLATFORM_POSIX 1
#elif __unix__ // all unices not caught above
#	define HB_PLATFORM_POSIX 1
#elif defined(_POSIX_VERSION)
#	define HB_PLATFORM_POSIX 1
#else
#   error "Unknown compiler"
#endif

#endif