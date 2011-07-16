#pragma once

/*
 * logging.h
 * A simple and reasonably flexible logging mechanism.
 *
 * Copyright (c) 2011 Drew Hess <dhess-src@bothan.net>
 *
 * Thanks to Kevin Bowling for the idea of wrapping syslog for
 * interactive output, described here:
 * http://www.kev009.com/wp/2010/12/no-nonsense-logging-in-c-and-cpp/
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <syslog.h>
#include <stdarg.h>

/*
 * Convenient typedefs:
 *
 * syslog_fun is a function prototype for a function like syslog(3).
 *
 * vsyslog_fun is a function prototype for a function like vsyslog(3).
 *
 * setlogmask_fun is a function prototype for a function like setlogmask(3).
 *
 * level_prefix_fun is a function prototype for a function like
 * level_prefix() (see below).
 */
typedef void (*syslog_fun)(int priority, const char *format, ...);
typedef void (*vsyslog_fun)(int priority, const char *format, va_list args);
typedef int (*setlogmask_fun)(int mask);
typedef const char * (*level_prefix_fun)(int priority);

/*
 * These functions return pointers to functions that log to syslog, or
 * to stderr. Upon return, the logger, vlogger, and setmask parameters
 * point to functions that behave like syslog, vsyslog, and
 * setlogmask, respectively; use them as you would those functions. If
 * any of the pointer arguments is NULL, then its value is not set
 * upon return.
 *
 * Note that you can obtain these logging functions at any time, and
 * freely switch between them, if you wish.
 */

/*
 * Returns the standard C library syslog, vsyslog, and setlogmask
 * functions.
 *
 * If you plan to use the syslog logging functions, you can still call
 * openlog(3) and closelog() in your program.
 */
void get_syslog_logger(syslog_fun *logger,
                       vsyslog_fun *vlogger,
                       setlogmask_fun *setmask);

/*
 * Returns versions of syslog, vsyslog, and setlogmask that log to
 * stderr rather than syslog.
 *
 * Note that some syslog concepts, e.g., the facility, don't have any
 * meaning for stderr logging, and are therefore ignored by these
 * functions.
 *
 * Like its syslog counterpart, the default stderr log mask permits
 * all log priorities to be logged.
 *
 * NOTE: this stderr logger is neither thread-safe nor reentrant,
 * though it would probably be trivial to make it so.
 */
void get_stderr_logger(syslog_fun *logger,
                       vsyslog_fun *vlogger,
                       setlogmask_fun *setmask);

/*
 * By default, the stderr logger uses the included level_prefix()
 * function to display the logging level when logging messages, but
 * you can override it with this function. The function returns a
 * pointer to the previously-installed level prefix function.
 *
 * NOTE: this function modifies global state, and is neither
 * thread-safe nor reentrant.
 */
level_prefix_fun
set_stderr_level_prefix_fun(level_prefix_fun new_fn);

/*
 * Convenience functions for writing your own loggers.
 */

/*
 * For a given syslog priority, return a const, null-terminated string
 * that corresponds to the priority's logging level, formatted for use
 * as a logging prefix. (e.g., returns "DEBUG: " for level LOG_DEBUG)
 */
const char *
level_prefix(int priority);
