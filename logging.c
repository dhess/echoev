/*
 * logging.c
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

#include "logging.h"

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

void get_syslog_logger(syslog_fun *logger,
                       vsyslog_fun *vlogger,
                       setlogmask_fun *setmask)
{
    if (logger)
        *logger = syslog;
    if (vlogger)
        *vlogger = vsyslog;
    if (setmask)
        *setmask = setlogmask;
}

/*
 * XXX dhess - to make this thread-safe/reentrant, need to make
 * stderr_logmask per-thread/per-context.
 */

static int stderr_logmask = LOG_UPTO(LOG_DEBUG);

static int
stderr_setlogmask(int mask)
{
    if (mask == 0)
        return stderr_logmask;
    int prev = stderr_logmask;
    stderr_logmask = mask;
    return prev;
}

static void
stderr_vsyslog(int priority, const char *format, va_list args)
{
    if (!(LOG_MASK(priority) & stderr_logmask))
        return;

    /*
     * Using LOG_PRI probably isn't standard, but I don't know a more
     * portable way to determine the log level from priority, since
     * it's perfectly legal for the user to OR the level with the
     * facility when forming priority.
     */
    const char *levelstr = 0;
    switch (LOG_PRI(priority)) {
    case LOG_DEBUG:
        levelstr = "DEBUG: ";
        break;
    case LOG_INFO:
        levelstr = "INFO: ";
        break;
    case LOG_NOTICE:
        levelstr = "NOTICE: ";
        break;
    case LOG_WARNING:
        levelstr = "WARNING: ";
        break;
    case LOG_ERR:
        levelstr = "ERR: ";
        break;
    case LOG_CRIT:
        levelstr = "CRIT: ";
        break;
    case LOG_ALERT:
        levelstr = "ALERT: ";
        break;
    case LOG_EMERG:
        levelstr = "EMERG: ";
        break;
    default:
        levelstr = "UNKNOWN: ";
    }

    fprintf(stderr, "%s", levelstr);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

static void
stderr_syslog(int priority, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    stderr_vsyslog(priority, format, ap);
    va_end(ap);
}

void get_stderr_logger(syslog_fun *logger,
                       vsyslog_fun *vlogger,
                       setlogmask_fun *setmask)
{
    if (logger)
        *logger = stderr_syslog;
    if (vlogger)
        *vlogger = stderr_vsyslog;
    if (setmask)
        *setmask = stderr_setlogmask;
}
