/*
 * echoev.c
 * A simple echo server, implemented with libev.
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

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <signal.h>
#include <assert.h>
#include <ev.h>

/*
 * An address family-agnostic wrapper around inet_ntop. dst is the
 * character string to which the presentation format string will be
 * written, and size is the length of that string.
 *
 * Returns a pointer to dst if successful, 0 if not, in which case
 * errno is set.
 */
const char *
inet_ntop_any(const struct sockaddr_storage *addr, char *dst, socklen_t size)
{
    const void *src;
    if (addr->ss_family == AF_INET)
        src = &((const struct sockaddr_in *) addr)->sin_addr;
    else
        src = &((const struct sockaddr_in6 *) addr)->sin6_addr;
    return inet_ntop(addr->ss_family, src, dst, size);
}

#define MAX_LOG 256

void log_msg(const char *msg)
{
    puts(msg);
}

void log_err(const char *errmsg)
{
    perror(errmsg);
}

void
log_warn(const char *msg)
{
    log_msg(msg);
}

void log_notice(const char *msg)
{
    log_msg(msg);
}

static void
log_notice_with_addr(const char *fmt, const struct sockaddr_storage *addr)
{
    char ip[INET6_ADDRSTRLEN];
    if (!inet_ntop_any(addr, ip, INET6_ADDRSTRLEN))
        log_err("log_notice_with_addr inet_ntop");
    else {
        char msg[MAX_LOG];
        snprintf(msg, sizeof(msg), fmt, ip);
        log_notice(msg);
    }
}

void log_debug(const char *msg)
{
    log_msg(msg);
}

#define MAX_MSG 4096

/*
 * Naive ring buffer FIFO implementation, with a sentinel element used
 * to indicate the "full" condition.
 *
 * The ring buffer's head pointer points to the starting location
 * where data should be written when copying data *into* the buffer
 * (e.g., with ringbuf_read). The ring buffer's tail pointer points to
 * the starting location where data should be read when copying data
 * *from* the buffer (e.g., with ringbuf_write).
 */

typedef struct ringbuf_t
{
    char *head, *tail;
    char buf[MAX_MSG];
} ringbuf_t;

void
ringbuf_init(ringbuf_t *rb)
{
    rb->head = rb->tail = rb->buf;
}

size_t
ringbuf_size(ringbuf_t *rb)
{
    /* There's always one unused element */
    return MAX_MSG - 1;
}

size_t
ringbuf_bytes_free(ringbuf_t *rb)
{
    if (rb->head >= rb->tail)
        return ringbuf_size(rb) - (rb->head - rb->tail);
    else
        return rb->tail - rb->head - 1;
}

bool
ringbuf_full(ringbuf_t *rb)
{
    return ringbuf_bytes_free(rb) == 0;
}

char *
ringbuf_tail(ringbuf_t *rb)
{
    return rb->tail;
}

char *
ringbuf_head(ringbuf_t *rb)
{
    return rb->head;
}

/*
 * This function calls read(2) and returns its value. It will only
 * call read(2) once, and may return a short count. If you get a short
 * count and want to keep reading from the file descriptor, simply
 * call the function again.
 *
 * The primary purpose of this function is to properly handle the case
 * where the ring buffer must wrap around the end of the allocated
 * contiguous buffer space.
 *
 * This function will happily overflow the ring buffer without
 * complaint. This permits the user to, e.g., discard data from a
 * pipe/socket that she doesn't care about in order to advance the
 * stream. When an overflow occurs, the state of the ring buffer is
 * guaranteed to be consistent, including the head and tail pointers.
 */

#define MIN(a,b) ((a) < (b) ? (a) : (b))

ssize_t
ringbuf_read(int fd, ringbuf_t *rb, size_t count)
{
    char *bufend = rb->buf + MAX_MSG;
    size_t nfree = ringbuf_bytes_free(rb);

    /* don't read beyond the end of the buffer */
    count = MIN(bufend - rb->head, count);
    ssize_t n = read(fd, (void *) rb->head, count);
    if (n > 0) {
        assert(rb->head + n <= bufend);
        rb->head += n;

        /* wrap? */
        if (rb->head == bufend)
            rb->head = rb->buf;

        /* fix up the tail pointer if an overflow occurred */
        if (n > nfree) {
            if (rb->head + 1 == bufend)
                rb->tail = rb->buf;
            else
                rb->tail = rb->head + 1;
            assert(ringbuf_full(rb));
        }
    }

    return n;
}

typedef struct echo_io
{
    ev_io io;
    ringbuf_t rb;
} echo_io;
    
/*
 * Make an existing socket non-blocking.
 *
 * Return 0 if successful, otherwise -1, in which case the error is
 * logged, and the error code is left in errno.
 */
int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        log_err("fcntl");
        return -1;
    }
    return 0;
}

void
stop_echo_watcher(EV_P_ echo_io *w)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(w->io.fd, (struct sockaddr *) &addr, &addr_len) == -1)
        log_err("stop_echo_watcher getpeername");
    else
        log_notice_with_addr("closed connection from %s", &addr);
    ev_io_stop(EV_A_ &w->io);
    close(w->io.fd);
    free(w);
}

void read_cb(EV_P_ ev_io *w_, int revents)
{
    log_debug("read_cb called");

    echo_io *w = (echo_io *) w_;
    while (ringbuf_bytes_free(&w->rb)) {
        ssize_t n = ringbuf_read(w->io.fd, &w->rb, ringbuf_bytes_free(&w->rb));
        if (n == 0) {
            /* eof */
            stop_echo_watcher(EV_A_ w);
            return;
        }
        else if (n == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
                return;  /* no more data for now */
            else {
                log_err("recv");
                stop_echo_watcher(EV_A_ w);
                return;
            }
        }
    }

    /* overflow */
    log_warn("read buffer full");
    stop_echo_watcher(EV_A_ w);
}

echo_io *make_watcher(int wfd)
{
    if (set_nonblocking(wfd) == -1)
        return 0;

    echo_io *watcher = malloc(sizeof(echo_io));
    if (watcher) {
        ringbuf_init(&watcher->rb);
        ev_io_init(&watcher->io, read_cb, wfd, EV_READ);
    }
    return watcher;
}

void listen_cb(EV_P_ ev_io *w, int revents)
{
    log_debug("listen_cb called");

    /*
     * libev recommends calling accept() in a loop for best
     * performance when using the select or poll back ends. The ev_io
     * watcher's file descriptor had better be non-blocking!
     */
    while (true) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);

        int fd = accept(w->fd, (struct sockaddr *) &addr, &addr_len);
        if (fd == -1) {

            /*
             * EWOULDBLOCK and EAGAIN mean no more connections to
             * accept.  ECONNABORTED and EPROTO mean the client has
             * aborted the connection, so just ignore it. EINTR means
             * we were interrupted by a signal. (We could re-try the
             * accept in case of EINTR, but we choose not to, in the
             * interest of making forward progress.)
             */
            if ((errno == EWOULDBLOCK) ||
                (errno == ECONNABORTED) ||
#ifndef ECHOEV_PLATFORM_BSD
                (errno == EPROTO) ||
#endif
                (errno == EINTR))
                break;
            else {
                log_err("accept");
                break;
            }
        }

        log_notice_with_addr("accepted connection from %s", &addr);
        echo_io *reader = make_watcher(fd);
        if (!reader) {
            log_err("make_watcher");
            close(fd);
        } else
            ev_io_start(EV_A_ &reader->io);
    }
}

/*
 * Create, bind, and listen on a non-blocking socket using the given
 * socket address.
 *
 * Return the socket's file descriptor, or -1 if an error occured, in
 * which case the error is logged, the error code is left in errno,
 * and -1 is returned.
 */
int listen_on(const struct sockaddr *addr, socklen_t addr_len)
{
    int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        log_err("socket");
        return -1;
    }
    if (set_nonblocking(fd) == -1)
        goto err;
    const int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        log_err("setsockopt");
        return -1;
    }
    if (bind(fd, addr, addr_len) == -1) {
        log_err("bind");
        goto err;
    }
    if (listen(fd, 8) == -1) {
        log_err("listen");
        goto err;
    }
    return fd;

  err:
    close(fd);
    return -1;
}

ev_io *make_listener(const struct sockaddr *addr, socklen_t addr_len)
{
    int listen_fd = listen_on(addr, addr_len);
    if (listen_fd == -1)
        return NULL;

    ev_io *watcher = malloc(sizeof(ev_io));
    if (watcher)
        ev_io_init(watcher, listen_cb, listen_fd, EV_READ);
    return watcher;
}
                     
const uint16_t port = 7777;

int main(int argc, char *argv[])
{
    /* Ignore SIGPIPE. */
    struct sigaction sa, osa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &osa) == -1) {
        log_err("sigaction");
        exit(errno);
    }
    
    struct ev_loop *loop = EV_DEFAULT;

    /*
     * Regarding IPv4 and IPv6 wildcard binds on the same port:
     *
     * The Linux kernel maps both IPv4 and IPv6 wildcard binds to the
     * same local port space, in which case only one family can be
     * bound to a given port. An IPv6 wildcard bind will see both IPv4
     * and IPv6 traffic. BSD-based platforms (e.g., Mac OS X)
     * recommend listening on two sockets for the same port, one for
     * IPv4 and one for IPv6, when you want to accept traffic for both
     * transports, especially when access control (firewalling) is in
     * effect.
     *
     * OpenBSD simply won't route IPv4 traffic to IPv6 sockets.
     */

    struct sockaddr_in6 saddr6;
    memset(&saddr6, 0, sizeof(saddr6));
    saddr6.sin6_family = AF_INET6;
    saddr6.sin6_addr = in6addr_any;
    saddr6.sin6_port = htons(port);

    ev_io *listen6_watcher = make_listener((const struct sockaddr *)&saddr6,
                                           sizeof(saddr6));
    if (listen6_watcher)
        ev_io_start(loop, listen6_watcher);
    else
        exit(errno);

#ifndef ECHOEV_PLATFORM_LINUX
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(port);

    ev_io *listen_watcher = make_listener((const struct sockaddr *)&saddr,
                                          sizeof(saddr));
    if (listen_watcher)
        ev_io_start(loop, listen_watcher);
    else
        exit(errno);
#endif
    
    log_debug("entering ev_run");
    ev_run(loop, 0);

    log_debug("ev_run exited");
    return 0;
}
