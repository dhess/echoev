#ifndef INCLUDED_LOGGING_H
#define INCLUDED_LOGGING_H

/*
 * logging.h
 * A syslog(3)-compatible logging mechanism.
 *
 * Written in 2011 by Drew Hess <dhess-src@bothan.net>.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/*
 * Supports logging to stderr using the syslog(3) interface. Includes
 * support for the special syslog(3) "%m" format sequence. Could be
 * easily extended to support other forms of logging (stdout, file,
 * network, etc.).
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
 * For a given syslog priority, return a const, null-terminated string
 * that corresponds to the priority's logging level, formatted for use
 * as a logging prefix. (e.g., returns "DEBUG: " for level LOG_DEBUG)
 */
const char *
logging_level_prefix(int priority);

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
void
get_syslog_logger(syslog_fun *logger,
                  vsyslog_fun *vlogger,
                  setlogmask_fun *setmask);

/*
 * stderr logging.
 */

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
 * NOTE: the stderr setmask function is neither thread-safe nor
 * reentrant. It modifies global state. Call it only from one thread
 * at a time.
 */
void
get_stderr_logger(syslog_fun *logger,
                  vsyslog_fun *vlogger,
                  setlogmask_fun *setmask);

/*
 * By default, the stderr logger uses the included
 * logging_level_prefix() function to display the logging level when
 * logging messages, but you can override it with this function. The
 * function returns a pointer to the previously-installed level prefix
 * function.
 *
 * You can change this function at any time, and freely switch between
 * functions.
 *
 * NOTE: this function modifies global state, and is neither
 * thread-safe nor reentrant. Call it only from one thread at a time.
 */
level_prefix_fun
set_stderr_level_prefix_fun(level_prefix_fun new_fn);

#endif /* INCLUDED_LOGGING_H */
