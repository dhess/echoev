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

#include "logging.h"
#include "ringbuf.h"

const char *version = "0.9";

const char MSG_DELIMITER = '\n';

static syslog_fun log;
static setlogmask_fun logmask;

static void
log_with_addr(int priority,
              const char *fmt,
              const struct sockaddr *addr,
              socklen_t size)
{
    char host[NI_MAXHOST];
    int err = getnameinfo((const struct sockaddr *) addr,
                          size,
                          host,
                          sizeof(host),
                          0,
                          0,
                          NI_NUMERICHOST);
    if (err)
        log(LOG_ERR, "log_with_addr getnameinfo: %s", gai_strerror(err));
    else
        log(priority, fmt, host);
}

typedef struct echo_io
{
    ev_io io;
    ringbuf_t rb;
    bool half_closed;

    /* Bytes remaining to be written in a response message. */
    size_t msg_len;
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
        log(LOG_ERR, "fcntl: %m");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        log(LOG_ERR, "fcntl: %m");
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
        log(LOG_ERR, "stop_echo_watcher getpeername: %m");
    else
        log_with_addr(LOG_NOTICE,
                      "closed connection from %s",
                      (const struct sockaddr *) &addr,
                      addr_len);
    ev_io_stop(EV_A_ &w->io);
    close(w->io.fd);
    free(w);
}

/*
 * Returns 0 if no full message yet received.
 */
size_t
next_msg_len(const ringbuf_t *rb, char delimiter)
{
    size_t delim_location = ringbuf_findchr(rb, delimiter, 0);
    if (delim_location < ringbuf_bytes_used(rb))
        return delim_location + 1;
    else
        return 0;
}

void
reset_echo_watcher(EV_P_ ev_io *w, int revents);

void
echo_cb(EV_P_ ev_io *w_, int revents)
{
    log(LOG_DEBUG, "echo_cb called");

    echo_io *w = (echo_io *) w_;

    if (revents & EV_WRITE) {
        log(LOG_DEBUG, "echo_cb write event");
        while (w->msg_len) {
            ssize_t n = ringbuf_write(w->io.fd,
                                      &w->rb,
                                      w->msg_len);
            if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR))
                    break;
                else {
                    log(LOG_ERR, "write: %m");
                    stop_echo_watcher(EV_A_ w);
                    return;
                }
            } else {
                w->msg_len -= n;
                log(LOG_DEBUG, "echo_cb %zd bytes written", n);
            }
        }
        if (w->msg_len == 0) {

            /* Look for more messages */
            w->msg_len = next_msg_len(&w->rb, MSG_DELIMITER);
            if (w->msg_len == 0) {
                if (w->half_closed)
                    stop_echo_watcher(EV_A_ w);
                else
                    reset_echo_watcher(EV_A_ &w->io, EV_READ);
            }
        }
    }
    
    if (revents & EV_READ) {
        log(LOG_DEBUG, "echo_cb read event");
        size_t nread = 0;
        while (ringbuf_bytes_free(&w->rb)) {
            ssize_t n = ringbuf_read(w->io.fd,
                                     &w->rb,
                                     ringbuf_bytes_free(&w->rb));
            if (n == 0) {

                /* EOF: drain remaining writes or close connection */
                log(LOG_DEBUG, "echo_cb EOF received");
                if (nread && w->msg_len == 0)
                    w->msg_len = next_msg_len(&w->rb, MSG_DELIMITER);
                if (w->msg_len) {
                    w->half_closed = true;
                    reset_echo_watcher(EV_A_ &w->io, EV_WRITE);
                }
                else
                    stop_echo_watcher(EV_A_ w);
                return;
            }
            else if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR)) {

                    /*
                     * Nothing more to read for now; schedule a write
                     * if we've received a full message and there's
                     * not already another message to be written.
                     */
                    if (nread && (w->msg_len == 0)) {
                        w->msg_len = next_msg_len(&w->rb, MSG_DELIMITER);
                        if (w->msg_len)
                            reset_echo_watcher(EV_A_ &w->io,
                                               EV_READ | EV_WRITE);
                    }
                    return;
                } else {
                    log(LOG_ERR, "read: %m");
                    stop_echo_watcher(EV_A_ w);
                    return;
                }
            } else {
                nread += n;
                log(LOG_DEBUG, "echo_cb %zd bytes read", n);
            }
        }

        /* overflow */
        log(LOG_WARNING, "read buffer full");
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
        watcher->half_closed = false;
        watcher->msg_len = 0;
        ev_io *io = &watcher->io;
        ev_io_init(io, echo_cb, wfd, EV_READ);
    }
    return watcher;
}

void
listen_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "listen_cb called");

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
                log(LOG_ERR, "accept: %m");
                break;
            }
        }

        log_with_addr(LOG_NOTICE,
                      "accepted connection from %s",
                      (const struct sockaddr *) &addr,
                      addr_len);
        echo_io *watcher = make_echo_watcher(fd);
        if (!watcher) {
            log(LOG_ERR, "make_echo_watcher: %m");
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
        log(LOG_ERR, "socket: %m");
        return -1;
    }
    if (set_nonblocking(fd) == -1)
        goto err;
    const int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        log(LOG_ERR, "setsockopt: %m");
        return -1;
    }
    if (bind(fd, addr, addr_len) == -1) {
        log(LOG_ERR, "bind: %m");
        goto err;
    }
    if (listen(fd, 8) == -1) {
        log(LOG_ERR, "listen: %m");
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
    printf("  -i, --interface  Interface to listen on, specified by IP\n");
    printf("                   address. May be specified multiple times.\n");
    printf("                   The default is all interfaces.\n");
    printf("  -l, --loglevel   Set the logging level (0-7, 0 is emergency,\n");
    printf("                   7 is debug). The default is 5 (notice).\n");
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
    typedef struct ip_list_t {
        char *addr;
        int family;
        struct ip_list_t *next;
    } ip_list_t;
    
    static struct option longopts[] = {
        { "help",      no_argument,       0, 'h' },
        { "version",   no_argument,       0, 'V' },
        { "port",      required_argument, 0, 'p' },
        { "loglevel",  required_argument, 0, 'l' },
        { "interface", required_argument, 0, 'i' },
        { 0,           0,                 0,  0  }
    };

    long loglevel = LOG_NOTICE;
    char *portstr = 0;
    ip_list_t *ip = 0, *listen_ips = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, "hVl:p:i:", longopts, 0)) != -1) {
        switch (ch) {
        case 'V':
            print_version(basename(argv[0]));
            exit(0);
            break;
        case 'l':
            errno = 0;
            loglevel = strtol(optarg, 0, 10);
            if (errno || loglevel < 0 || loglevel > 7) {
                fprintf(stderr, "Log level must be between 0 and 7, inclusive.\n");
                exit(errno);
            }
            break;
        case 'p':
            portstr = strdup(optarg);
            if (!portstr) {
                perror("strdup");
                exit(errno);
            }
            break;
        case 'i':
            if (ip) {
                ip->next = (ip_list_t *) malloc(sizeof(ip_list_t));
                ip = ip->next;
            } else {
                listen_ips = (ip_list_t *) malloc(sizeof(ip_list_t));
                ip = listen_ips;
            }
            ip->addr = strdup(optarg);
            ip->family = AF_UNSPEC;
            ip->next = 0;
            break;
        case 'h':
        default:
            usage(basename(argv[0]));
            exit(0);
        }
    }

    /*
     * If no listen IPs were specified, listen on all interfaces
     * (i.e., the wildcard address).
     *
     * Regarding IPv4 and IPv6 wildcard binds on the same port:
     *
     * The Linux kernel maps both IPv4 and IPv6 wildcard binds to the
     * same local port space, in which case only one family can be
     * bound to a given port. An IPv6 wildcard bind on a GNU/Linux
     * system will see both IPv4 and IPv6 traffic.
     *
     * BSD-based platforms (e.g., Mac OS X) recommend listening on two
     * sockets for the same port, one for IPv4 and one for IPv6, when
     * you want to accept traffic for both transports, especially when
     * access control (firewalling) is in effect.
     *
     * OpenBSD simply won't route IPv4 traffic to IPv6 sockets; on
     * that platform, an application must bind to both of the IPv4 and
     * IPv6 wildcard addresses to receive both types of traffic.
     */
    
    if (!listen_ips) {
        ip = (ip_list_t *) malloc(sizeof(ip_list_t));
        if (!ip) {
            perror("malloc");
            exit(errno);
        }
        listen_ips = ip;
        ip->addr = 0;
        ip->family = AF_INET6;
#ifndef ECHOEV_PLATFORM_LINUX
        ip->next = (ip_list_t *) malloc(sizeof(ip_list_t));
        if (!ip->next) {
            perror("malloc");
            exit(errno);
        }
        ip = ip->next;
        ip->addr = 0;
        ip->family = AF_INET;
#endif
        ip->next = 0;
    }
    
    get_stderr_logger(&log, 0, &logmask);
    logmask(LOG_UPTO(loglevel));
    
    /* Ignore SIGPIPE. */
    struct sigaction sa, osa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &osa) == -1) {
        log(LOG_ERR, "sigaction: %m");
        exit(errno);
    }
    
    struct ev_loop *loop = EV_DEFAULT;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    for (ip = listen_ips; ip != 0; ip = ip->next) {
        hints.ai_family = ip->family;
        int err = getaddrinfo(ip->addr,
                              portstr ? portstr : default_portstr,
                              &hints,
                              &res);
        if (err) {
            log(LOG_ERR, "%s", gai_strerror(err));
            exit(err);
        }
        assert(!res->ai_next);
        ev_io *listen_watcher = make_listener(res->ai_addr, res->ai_addrlen);
        if (listen_watcher) {
            log_with_addr(LOG_NOTICE,
                          "listening on %s",
                          res->ai_addr,
                          res->ai_addrlen);
            ev_io_start(loop, listen_watcher);
        }
        else
            exit(errno);
        freeaddrinfo(res);
    }

    /* Clean up before entering ev_run loop */
    if (portstr)
        free(portstr);
    while (listen_ips) {
        ip = listen_ips;
        listen_ips = ip->next;
        free(ip->addr);
        free(ip);
    }
    listen_ips = 0;
    
    log(LOG_DEBUG, "entering ev_run");
    ev_run(loop, 0);

    log(LOG_DEBUG, "ev_run exited");
    return 0;
}
