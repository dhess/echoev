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
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>

/*
 * This function returns string s1 if string s2 is an empty string, or
 * if s2 is not found in s1. If s2 is found in s1, the function
 * returns a new null-terminated string whose contents are identical
 * to s1, except that all occurrences of s2 in the original string s1
 * are, in the new string, replaced by the string s3. The caller owns
 * the new string.
 *
 * Strings s1, s2, and s3 must all be null-terminated strings.
 *
 * If any of s1, s2, or s3 are NULL, the function returns NULL. If an
 * error occurs, the function returns NULL, though unfortunately there
 * is no way to determine the nature of the error from the call site.
 */

char *
strrep(const char *s1, const char *s2, const char *s3)
{
    if (!s1 || !s2 || !s3)
        return 0;
    size_t s1_len = strlen(s1);
    if (!s1_len)
        return (char *)s1;
    size_t s2_len = strlen(s2);
    if (!s2_len)
        return (char *)s1;

    /*
     * Two-pass approach: figure out how much space to allocate for
     * the new string, pre-allocate it, then perform replacement(s).
     */

    size_t count = 0;
    const char *p = s1;
    do {
        p = strstr(p, s2);
        if (p) {
            p += s2_len;
            ++count;
        }
    } while (p);

    if (!count)
        return (char *)s1;

    /*
     * The following size arithmetic is extremely cautious, to guard
     * against size_t overflows.
     */
    size_t s1_without_s2_len = s1_len - count * s2_len;
    size_t s3_len = strlen(s3);
    size_t s1_with_s3_len = s1_without_s2_len + count * s3_len;
    if (s3_len &&
        ((s1_with_s3_len <= s1_without_s2_len) || (s1_with_s3_len + 1 == 0)))
        /* Overflow. */
        return 0;
    
    char *s1_with_s3 = (char *)malloc(s1_with_s3_len + 1); /* w/ terminator */
    if (!s1_with_s3)
        /* ENOMEM, but no good way to signal it. */
        return 0;
    
    char *dst = s1_with_s3;
    const char *start_substr = s1;
    size_t i;
    for (i = 0; i != count; ++i) {
        const char *end_substr = strstr(start_substr, s2);
        size_t substr_len = end_substr - start_substr;
        memcpy(dst, start_substr, substr_len);
        dst += substr_len;
        memcpy(dst, s3, s3_len);
        dst += s3_len;
        start_substr = end_substr + s2_len;
    }

    /* copy remainder of s1, including trailing '\0' */
    size_t remains = s1_len - (start_substr - s1) + 1;
    memcpy(dst, start_substr, remains);
    return s1_with_s3;
}

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

const char *
level_prefix(int priority)
{
    /*
     * Using LOG_PRI probably isn't standard, but I don't know a more
     * portable way to determine the log level from priority, since
     * it's perfectly legal for the user to OR the level with the
     * facility when forming priority.
     */
    switch (LOG_PRI(priority)) {
    case LOG_DEBUG:
        return "DEBUG: ";
    case LOG_INFO:
        return "INFO: ";
    case LOG_NOTICE:
        return "NOTICE: ";
    case LOG_WARNING:
        return "WARNING: ";
    case LOG_ERR:
        return "ERR: ";
    case LOG_CRIT:
        return "CRIT: ";
    case LOG_ALERT:
        return "ALERT: ";
    case LOG_EMERG:
        return "EMERG: ";
    default:
        return "UNKNOWN: ";
    }
}

/* XXX dhess - not thread-safe. */
static level_prefix_fun stderr_level_prefix_fn = level_prefix;

level_prefix_fun
set_stderr_level_prefix_fun(level_prefix_fun new_fn)
{
    level_prefix_fun prev_fn = stderr_level_prefix_fn;
    stderr_level_prefix_fn = new_fn;
    return prev_fn;
}

static void
_stderr_vsyslog(int perrno, int priority, const char *format, va_list args)
{
    if (!(LOG_MASK(priority) & stderr_logmask))
        return;

    const char *levelstr = stderr_level_prefix_fn(priority);
    fprintf(stderr, "%s", levelstr);
    char *eformat = strrep(format, "%m", strerror(perrno));
    vfprintf(stderr, eformat, args);
    if (eformat != format)
        free(eformat);
    fprintf(stderr, "\n");
}

static void
stderr_vsyslog(int priority, const char *format, va_list args)
{
    /* Preserving errno isn't strictly required, but it's nice. */
    int perrno = errno;
    _stderr_vsyslog(perrno, perrno, format, args);
    errno = perrno;
}

static void
stderr_syslog(int priority, const char *format, ...)
{
    /* Preserving errno isn't strictly required, but it's nice. */
    int perrno = errno;
    va_list ap;
    va_start(ap, format);
    _stderr_vsyslog(perrno, priority, format, ap);
    va_end(ap);
    errno = perrno;
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
