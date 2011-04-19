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
#include <ev.h>

void log_msg(const char *msg)
{
    puts(msg);
}

void log_err(const char *errmsg)
{
    perror(errmsg);
}

void log_notice(const char *msg)
{
    log_msg(msg);
}

void log_debug(const char *msg)
{
    log_msg(msg);
}

void log_connection(const struct sockaddr_storage *addr,
                           socklen_t addr_len)
{
    char ip[INET6_ADDRSTRLEN];
    const void *src;
    if (addr->ss_family == AF_INET)
        src = &((const struct sockaddr_in *) addr)->sin_addr;
    else
        src = &((const struct sockaddr_in6 *) addr)->sin6_addr;
    log_notice(inet_ntop(addr->ss_family, src, ip, INET6_ADDRSTRLEN));
}

#define MAX_MSG 4096

typedef struct echo_io
{
    ev_io io;
    size_t nread;
    char buf[MAX_MSG];
} echo_io;
    
void read_cb(EV_P_ ev_io *w_, int revents)
{
    log_debug("read_cb called");

    echo_io *w = (echo_io *) w_;
    while (true) {

        /* save room for terminating '\0' */
        ssize_t n = recv(w->io.fd, &w->buf[w->nread], MAX_MSG - w->nread - 1, 0);
        if (n == 0) {
            /* eof */
            w->buf[w->nread] = '\0';
            goto stop_watcher;
        } else if (n == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                return;  /* no more data for now */
            else {
                log_err("recv");
                goto stop_watcher;
            }
        } else
            w->nread += n;
    }
        
  stop_watcher:
    log_notice("closing connection");
    ev_io_stop(EV_A_ &w->io);
    close(w->io.fd);
    free(w);
}

echo_io *make_reader(int wfd)
{
    fcntl(wfd, F_SETFL, O_NONBLOCK);

    echo_io *watcher = malloc(sizeof(echo_io));
    if (watcher) {
        watcher->nread = 0;
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
            if (errno != EWOULDBLOCK)
                log_err("accept");
            break;
        }

        log_connection(&addr, addr_len);
        echo_io *reader = make_reader(fd);
        if (!reader) {
            log_err("make_reader");
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
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (bind(fd, addr, addr_len) == -1) {
        log_err("bind");
        goto err;
    }
    if (listen(fd, 0) == -1) {
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
    struct ev_loop *loop = EV_DEFAULT;

    /*
     * Regarding IPv4 and IPv6 wildcard binds on the same port:
     *
     * The Linux kernel maps both IPv4 and IPv6 wildcard binds to the
     * same local port space, in which case only one family can be
     * bound to a given port, and the IPv6 wildcard bind will see both
     * IPv4 and IPv6 traffic. BSD-based platforms (e.g., Mac OS X)
     * recommend listening on two sockets for the same port, one for
     * IPv4 and one for IPv6, when you want to accept traffic for both
     * transports, especially when access control (firewalling) is in
     * effect.
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
