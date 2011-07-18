#pragma once

/*
 * echo-common.h
 * Common functions for echoev and echoevc.
 *
 * Copyright (c) 2011 Drew Hess <dhess-src@bothan.net>
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

#include <stddef.h>
#include "ringbuf.h"

/*
 * The echo protocol message/line delimiter.
 */
static const char MSG_DELIMITER = '\n';

/*
 * struct msg_buf associates a ringbuf_t object with a search offset
 * (to be used with ringbuf_findchr) and a message length, which
 * indicates how many bytes remain to be written in the ring buffer's
 * first complete FIFO message (terminated by MSG_DELIMITER).
 */
typedef struct msg_buf
{
    ringbuf_t rb;
    size_t search_offset;
    size_t msg_len;
} msg_buf;

/*
 * Initialize a msg_buf by creating a new msg_buf and its associated
 * ring buffer. capacity is the capacity of the ring buffer.
 */
void
msg_buf_init(msg_buf *buf, size_t capacity);
 
/*
 * Make an existing socket non-blocking.
 *
 * Return 0 if successful, otherwise -1, in which case the error code
 * is left in errno.
 */
int
set_nonblocking(int fd);

/*
 * Set the process's signal mask to ignore SIGPIPE signals. Returns 0
 * if success, -1 if error, in which case the errno code is left in
 * errno.
 */
int
ignore_sigpipe();
