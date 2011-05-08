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
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <sys/param.h>
#include <getopt.h>
#include <libgen.h>
#include <assert.h>
#include <ev.h>

const char *version = "0.9";

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

void
log_msg(const char *msg)
{
    puts(msg);
}

void
log_err(const char *errmsg)
{
    perror(errmsg);
}

void
log_warn(const char *msg)
{
    log_msg(msg);
}

void
log_notice(const char *msg)
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

void
log_debug(const char *msg)
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
ringbuf_capacity(ringbuf_t *rb)
{
    /* There's always one unused element */
    return sizeof(rb->buf) - 1;
}

const char *
ringbuf_end(ringbuf_t *rb)
{
    return rb->buf + sizeof(rb->buf);
}

size_t
ringbuf_bytes_free(ringbuf_t *rb)
{
    if (rb->head >= rb->tail)
        return ringbuf_capacity(rb) - (rb->head - rb->tail);
    else
        return rb->tail - rb->head - 1;
}

size_t
ringbuf_bytes_used(ringbuf_t *rb)
{
    return ringbuf_capacity(rb) - ringbuf_bytes_free(rb);
}

bool
ringbuf_full(ringbuf_t *rb)
{
    return ringbuf_bytes_free(rb) == 0;
}

bool
ringbuf_empty(ringbuf_t *rb)
{
    return ringbuf_bytes_free(rb) == ringbuf_capacity(rb);
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

ssize_t
ringbuf_read(int fd, ringbuf_t *rb, size_t count)
{
    const char *bufend = ringbuf_end(rb);
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

/*
 * This function calls write(2) and returns its value. It will only
 * call write(2) once, and may return a short count. If you get a
 * short count and want to keep writing to the file descriptor, simply
 * call the function again.
 *
 * The primary purpose of this function is to properly handle the case
 * where the ring buffer must wrap around the end of the allocated
 * contiguous buffer space.
 *
 * This function will not allow the ring buffer to underflow. If the
 * user requests to write more bytes than are currently used in the
 * ring buffer, the function will return 0.
 */
ssize_t
ringbuf_write(int fd, ringbuf_t *rb, size_t count)
{
    if (count > ringbuf_bytes_used(rb))
        return 0;

    const char *bufend = ringbuf_end(rb);
    count = MIN(bufend - rb->tail, count);
    ssize_t n = write(fd, (const void *) rb->tail, count);
    if (n > 0) {
        assert(rb->tail + n <= bufend);
        rb->tail += n;

        /* wrap? */
        if (rb->tail == bufend)
            rb->tail = rb->buf;
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
int
set_nonblocking(int fd)
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

void
reset_echo_watcher(EV_P_ ev_io *w, int revents);

void
echo_cb(EV_P_ ev_io *w_, int revents)
{
    log_debug("echo_cb called");

    echo_io *w = (echo_io *) w_;

    if (revents & EV_WRITE) {
        log_debug("echo_cb write event");
        while (!ringbuf_empty(&w->rb)) {
            ssize_t n = ringbuf_write(w->io.fd,
                                      &w->rb,
                                      ringbuf_bytes_used(&w->rb));
            if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR))
                    break;
                else {
                    log_err("write");
                    stop_echo_watcher(EV_A_ w);
                    return;
                }
            }
        }
        if (ringbuf_empty(&w->rb))
            reset_echo_watcher(EV_A_ &w->io, EV_READ);
    }
    
    if (revents & EV_READ) {
        log_debug("echo_cb read event");
        size_t nread = 0;
        while (ringbuf_bytes_free(&w->rb)) {
            ssize_t n = ringbuf_read(w->io.fd,
                                     &w->rb,
                                     ringbuf_bytes_free(&w->rb));
            if (n == 0) {
                /* eof */
                stop_echo_watcher(EV_A_ w);
                return;
            }
            else if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR)) {
                    if (nread)
                        reset_echo_watcher(EV_A_ &w->io, EV_READ | EV_WRITE);
                    return;
                } else {
                    log_err("read");
                    stop_echo_watcher(EV_A_ w);
                    return;
                }
            } else
                nread += n;
        }

        /* overflow */
        log_warn("read buffer full");
        stop_echo_watcher(EV_A_ w);
    }
}

void
reset_echo_watcher(EV_P_ ev_io *w, int revents)
{
    ev_io_stop(EV_A_ w);
    ev_io_init(w, echo_cb, w->fd, revents);
    ev_io_start(EV_A_ w);
}

echo_io *
make_echo_watcher(int wfd)
{
    if (set_nonblocking(wfd) == -1)
        return 0;

    echo_io *watcher = malloc(sizeof(echo_io));
    if (watcher) {
        ringbuf_init(&watcher->rb);
        ev_io *io = &watcher->io;
        ev_io_init(io, echo_cb, wfd, EV_READ);
    }
    return watcher;
}

void
listen_cb(EV_P_ ev_io *w, int revents)
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
        echo_io *watcher = make_echo_watcher(fd);
        if (!watcher) {
            log_err("make_echo_watcher");
            close(fd);
        } else
            ev_io_start(EV_A_ &watcher->io);
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
int
listen_on(const struct sockaddr *addr, socklen_t addr_len)
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

ev_io *
make_listener(const struct sockaddr *addr, socklen_t addr_len)
{
    int listen_fd = listen_on(addr, addr_len);
    if (listen_fd == -1)
        return NULL;

    ev_io *watcher = malloc(sizeof(ev_io));
    if (watcher)
        ev_io_init(watcher, listen_cb, listen_fd, EV_READ);
    return watcher;
}
                     
const char *default_portstr = "7777";

void
usage(const char *name)
{
    printf("usage: %s [OPTIONS]\n\n", name);
    printf("Options:\n");
    printf("  -p, --port       Port number to listen on [0-65535].\n");
    printf("                   The default is 7777. Service names are\n");
    printf("                   also acceptable.\n");
    printf("  -h, --help       Show this message and exit\n");
    printf("  -V, --version    Print the program version and exit\n");
}

void
print_version(const char *name)
{
    printf("%s version %s\n", name, version);
}

int
main(int argc, char *argv[])
{
    static struct option longopts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'V' },
        { "port",    required_argument, 0, 'p' },
        { 0,         0,                 0,  0  }
    };

    char *portstr = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, "hVp:", longopts, 0)) != -1) {
        switch (ch) {
        case 'V':
            print_version(basename(argv[0]));
            exit(0);
            break;
        case 'p':
            portstr = strdup(optarg);
            if (!portstr) {
                log_err("strdup");
                exit(errno);
            }
            break;
        case 'h':
        default:
            usage(basename(argv[0]));
            exit(0);
        }
    }

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

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_PASSIVE;

    int err = getaddrinfo(0, portstr ? portstr : default_portstr, &hints, &res);
    if (err) {
        log_err(gai_strerror(err));
        exit(err);
    }
    assert(res);
    assert(!res->ai_next);
    ev_io *listen6_watcher = make_listener(res->ai_addr, res->ai_addrlen);
    if (listen6_watcher)
        ev_io_start(loop, listen6_watcher);
    else
        exit(errno);
    freeaddrinfo(res);

#ifndef ECHOEV_PLATFORM_LINUX
    hints.ai_family = AF_INET;
    err = getaddrinfo(0, portstr ? portstr : default_portstr, &hints, &res);
    if (err) {
        log_err(gai_strerror(err));
        exit(err);
    }
    assert(res);
    assert(!res->ai_next);
    ev_io *listen_watcher = make_listener(res->ai_addr, res->ai_addrlen);
    if (listen_watcher)
        ev_io_start(loop, listen_watcher);
    else
        exit(errno);
    freeaddrinfo(res);
#endif

    /* Cleanup before entering ev_run loop */
    if (portstr)
        free(portstr);
    
    log_debug("entering ev_run");
    ev_run(loop, 0);

    log_debug("ev_run exited");
    return 0;
}
