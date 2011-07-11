/*
 * echoevc.c
 * A simple echo client, implemented with libev.
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

typedef struct timeout_timer
{
    ev_timer timer;
    ev_tstamp last_activity;
} timeout_timer;

typedef struct msg_buf
{
    ringbuf_t rb;
    size_t msg_len;
} msg_buf;

void
msg_buf_init(msg_buf *buf)
{
    ringbuf_init(&buf->rb);
    buf->msg_len = 0;
}

/*
 * client_session contains the entirety of the connection state to an
 * echo server, including all the libev ev_io watchers needed to
 * interact with the client's stdin, stdout, and the echo server; the
 * timeout trackers; and two msg_buf structures for enforcing the
 * FIFO, message-oriented nature of the echo protocol.
 */
typedef struct client_session
{
    ev_io stdin_io;
    ev_io srv_writer_io;
    msg_buf stdin_buf;

    ev_io srv_reader_io;
    ev_io stdout_io;
    msg_buf stdout_buf;

    /*
     * N.B.: stdout is allowed to block indefinitely and doesn't time
     * out.
     */
    timeout_timer stdin_timeout;
    timeout_timer srv_writer_timeout;
    timeout_timer srv_reader_timeout;
} client_session;

/* Default protocol timeout, in seconds. */
static const ev_tstamp ECHO_PROTO_TIMEOUT = 120.0;

/*
 * This timeout callback implements the timeout solution recommended
 * in the libev documentation. Returns true if an actual timeout
 * occurred, false otherwise.
 */
bool
echo_proto_timeout_cb(EV_P_ timeout_timer *t)
{
    ev_tstamp now = ev_now(EV_A);
    ev_tstamp timeout = t->last_activity + ECHO_PROTO_TIMEOUT;
    if (timeout < now)
        return true;
    else {

        /* False alarm, re-arm timeout. */
        t->timer.repeat = timeout - now;
        ev_timer_again(EV_A_ &t->timer);
        return false;
    }
}

/*
 * Macro to help libev callbacks go from ev_* struct pointers back to
 * their containing client_session.
 */
#define CLIENT_SESSION_OF(p, id)                                        \
    (client_session *) (((void *)(p)) - offsetof(client_session, id));

void
teardown_session(EV_P_ client_session *cs);

#define DEFINE_TIMEOUT_CB(fun_name, timeout_id, timeout_str)     \
    void                                                         \
    fun_name(EV_P_ ev_timer *_t, int _revents)                   \
    {                                                            \
        client_session *_cs = CLIENT_SESSION_OF(_t, timeout_id); \
        if (echo_proto_timeout_cb(EV_A_ &_cs->timeout_id)) {     \
            log(LOG_NOTICE, timeout_str);                        \
            teardown_session(EV_A_ _cs);                         \
        }                                                        \
    }

DEFINE_TIMEOUT_CB(stdin_timeout_cb, \
                  stdin_timeout,    \
                  "Timeout on stdin, closing connection.");

DEFINE_TIMEOUT_CB(srv_writer_timeout_cb, \
                  srv_writer_timeout,    \
                  "Server timed out on write, closing connection.");

DEFINE_TIMEOUT_CB(srv_reader_timeout_cb, \
                  srv_reader_timeout,    \
                  "Server timed out on read, closing connection.");

/*
 * Start an ev_io watcher and its echo protocol timer (if non-NULL).
 * Assumes both have already been initialized.
 */
void
start_watcher(EV_P_ ev_io *w, timeout_timer *t)
{
    ev_io_start(EV_A_ w);
    if (t) {
        t->last_activity = ev_now(EV_A);
        echo_proto_timeout_cb(EV_A_ t);
    }
}

/*
 * Stop an ev_io and its echo protocol timer (if non-NULL).
 */
void
stop_watcher(EV_P_ ev_io *w, timeout_timer *t)
{
    ev_io_stop(EV_A_ w);
    if (t)
        ev_timer_stop(EV_A_ &t->timer);
}

/*
 * Mark a watcher as finished (socket closed/shutdown).
 */
void
mark_as_finished(ev_io *w)
{
    w->fd = -1;
}

bool
is_finished(const ev_io *w)
{
    return w->fd == -1;
}

typedef void (* shutdown_fn)(EV_P_ ev_io *);

/*
 * A special shutdown function for the echo server writer
 * watcher. It's called when there's no more data to be written from
 * stdin. The writer watcher must not close(2) the echo server
 * connection, because the client might still be waiting for data to
 * be echoed back from the echo server.
 */
void
shutdown_srv_writer(EV_P_ ev_io *w)
{
    /* Half-close. */
    if (shutdown(w->fd, SHUT_WR) == -1)
        log(LOG_WARNING, "shutdown_srv_writer shutdown: %m");
    mark_as_finished(w);
}

/*
 * The default shutdown function: just close(2) the watcher's file
 * descriptor, and mark it as finished.
 */
void
close_watcher(EV_P_ ev_io *w)
{
    if (close(w->fd) == -1)
        log(LOG_WARNING, "close_watcher close on fd %d: %m", w->fd);
    mark_as_finished(w);
}

/*
 * Call this function to tear down the entire session immediately:
 * close all file descriptors, cancel all timeouts, and free the
 * client_session structure.
 */
void
teardown_session(EV_P_ client_session *cs)
{
    if (!is_finished(&cs->stdin_io)) {
        stop_watcher(EV_A_ &cs->stdin_io, &cs->stdin_timeout);
        close_watcher(EV_A_ &cs->stdin_io);
    }
    if (!is_finished(&cs->srv_writer_io)) {
        stop_watcher(EV_A_ &cs->srv_writer_io, &cs->srv_writer_timeout);
        shutdown_srv_writer(EV_A_ &cs->srv_writer_io);
    }
    if (!is_finished(&cs->srv_reader_io)) {
        stop_watcher(EV_A_ &cs->srv_reader_io, &cs->srv_reader_timeout);
        close_watcher(EV_A_ &cs->srv_reader_io);
    }
    if (!is_finished(&cs->stdout_io)) {

        /* stdout has no timeout */
        stop_watcher(EV_A_ &cs->stdout_io, 0);
        close_watcher(EV_A_ &cs->stdout_io);
    }
    free(cs);
}
 
/*
 * Reads messages from a watcher's descriptor, and schedules them for
 * writing using its paired ev_io writer.
 *
 * Returns 1 under normal conditions; 0 if an EOF was received; and -1
 * if a serious error occurred (generally meaning that the session
 * should be aborted).
 */
int
read_cb(EV_P_
        ev_io *reader,
        ev_io *writer,
        msg_buf *buf,
        timeout_timer *reader_timeout,
        timeout_timer *writer_timeout,
        shutdown_fn writer_shutdown)
{
    log(LOG_DEBUG, "read_cb called");
    
    size_t nread = 0;
    while (ringbuf_bytes_free(&buf->rb)) {
        ssize_t n = ringbuf_read(reader->fd,
                                 &buf->rb,
                                 ringbuf_bytes_free(&buf->rb));
        if (n == 0) {
            
            /*
             * EOF: shutdown this watcher, but drain any remaining
             * messages through the writer. If there are none,
             * shutdown the writer, too. N.B.: incomplete messages
             * (those without a terminating MSG_DELIMITER) will be
             * discarded, by design.
             */
            log(LOG_DEBUG, "read_cb EOF received on fd %d", reader->fd);

            stop_watcher(EV_A_ reader, reader_timeout);
            close_watcher(EV_A_ reader);

            if (buf->msg_len == 0) {
                assert(!ev_is_active(writer) && !ev_is_pending(writer));
                if (nread &&
                    (buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER))) {
                    
                    start_watcher(EV_A_ writer, writer_timeout);
                } else
                    writer_shutdown(EV_A_ writer);
            }
            return 0;

        } else if (n == -1) {
            if ((errno == EAGAIN) ||
                (errno == EWOULDBLOCK) ||
                (errno == EINTR)) {

                /*
                 * Nothing more to read for now; schedule a write
                 * if we've received a full message and there's
                 * not already another message to be written.
                 */
                if (nread && (buf->msg_len == 0)) {
                    buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
                    if (buf->msg_len)
                        start_watcher(EV_A_ writer, writer_timeout);
                }
                return 1;
            } else {
                log(LOG_ERR, "read_cb read on fd %d: %m", reader->fd);
                return -1;
            }
        } else {
            nread += n;
            if (reader_timeout)
                reader_timeout->last_activity = ev_now(EV_A);
            log(LOG_DEBUG, "read_cb %zd bytes read on fd %d", n, reader->fd);
        }
    }

    /* Overflow. */
    log(LOG_ERR, "read_cb socket overflow on fd %d.", reader->fd);
    return -1;
}

/*
 * This callback is scheduled by reading watchers when they receive
 * messages for writing.
 *
 * Returns 1 under normal conditions, 0 if the reader has finished and
 * the writer has no more messages to write, and -1 if a serious error
 * occurred (generally meaning that the session should be aborted.)
 */
int
write_cb(EV_P_
         const ev_io *reader,
         ev_io *writer,
         msg_buf *buf,
         timeout_timer *writer_timeout,
         shutdown_fn writer_shutdown)
{
    log(LOG_DEBUG, "write_cb called");

    while (buf->msg_len) {
        ssize_t n = ringbuf_write(writer->fd,
                                  &buf->rb,
                                  buf->msg_len);
        if (n == -1) {
            if ((errno == EAGAIN) ||
                (errno == EWOULDBLOCK) ||
                (errno == EINTR)) {

                return 1;
            } else {
                log(LOG_ERR, "write_cb write on fd %d: %m", writer->fd);
                return -1;
            }
        } else {
            buf->msg_len -= n;
            if (writer_timeout)
                writer_timeout->last_activity = ev_now(EV_A);
            log(LOG_DEBUG,
                "write_cb %zd bytes written to fd %d",
                n,
                writer->fd);
        }
    }
    if (buf->msg_len == 0) {

        /* Look for more messages; stop/shutdown if none. */
        buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
        if (buf->msg_len == 0) {
            stop_watcher(EV_A_ writer, writer_timeout);
            if (is_finished(reader)) {

                /* No more work for this reader/writer pair. */
                writer_shutdown(EV_A_ writer);
                return 0;
            }
        }
    }

    return 1;
}

/*
 * These are the libev ev_io callbacks that are installed in the libev
 * event loop, one for each client socket (stdin/stdout) or server
 * stream direction (srv_reader/srv_writer). They simply marshall the
 * required structs and functions and pass them to the common callback
 * routines (read_cb and write_cb).
 */
void
stdin_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "stdin_cb called");

    if (revents & EV_READ) {
        client_session *cs = CLIENT_SESSION_OF(w, stdin_io);
        int status = read_cb(EV_A_
                             &cs->stdin_io,
                             &cs->srv_writer_io,
                             &cs->stdin_buf,
                             &cs->stdin_timeout,
                             &cs->srv_writer_timeout,
                             shutdown_srv_writer);
        if (status == -1)
            teardown_session(EV_A_ cs);
    } else
        log(LOG_WARNING, "stdin_cb spurious callback!");
}

void
srv_writer_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "srv_writer_cb called");

    if (revents & EV_WRITE) {
        client_session *cs = CLIENT_SESSION_OF(w, srv_writer_io);
        int status = write_cb(EV_A_
                              &cs->stdin_io,
                              &cs->srv_writer_io,
                              &cs->stdin_buf,
                              &cs->srv_writer_timeout,
                              shutdown_srv_writer);
        if (status == -1)
            teardown_session(EV_A_ cs);

        /* No need to do anything special for status code 0. */
    } else
        log(LOG_WARNING, "srv_writer_cb spurious callback!");
}

void
srv_reader_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "srv_reader_cb called");

    if (revents & EV_READ) {
        client_session *cs = CLIENT_SESSION_OF(w, srv_reader_io);
        int status = read_cb(EV_A_
                             &cs->srv_reader_io,
                             &cs->stdout_io,
                             &cs->stdout_buf,
                             &cs->srv_reader_timeout,
                             0, /* no stdout timeout */
                             close_watcher);
        if (status == 0) {

            /*
             * If either stdin_io or srv_writer_io has not already
             * finished, the server sent an EOF prematurely.  Shutdown
             * the stdin half of the client so that writes to the
             * server won't fail.
             */
            if (!is_finished(&cs->stdin_io) ||
                !is_finished(&cs->srv_writer_io)) {

                log(LOG_WARNING, "Connection closed by server.");
                if (!is_finished(&cs->stdin_io)) {
                    stop_watcher(EV_A_ &cs->stdin_io, &cs->stdin_timeout);
                    close_watcher(EV_A_ &cs->stdin_io);
                }
                if (!is_finished(&cs->srv_writer_io)) {
                    stop_watcher(EV_A_ &cs->srv_writer_io,
                                 &cs->srv_writer_timeout);

                    /* Server socket was already closed by read_cb. */
                }

                if (is_finished(&cs->stdout_io))
                    free(cs);

            } else if (is_finished(&cs->stdout_io)) {
                log(LOG_NOTICE, "Connection closed.");
                free(cs);
            }

        } else if (status == -1)
            teardown_session(EV_A_ cs);
    } else
        log(LOG_WARNING, "srv_reader_cb spurious callback!");
}

void
stdout_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "stdout_cb called");

    if (revents & EV_WRITE) {
        client_session *cs = CLIENT_SESSION_OF(w, stdout_io);
        int status = write_cb(EV_A_
                              &cs->srv_reader_io,
                              &cs->stdout_io,
                              &cs->stdout_buf,
                              0, /* no stdout timeout */
                              close_watcher);
        if (status == 0) {

            /*
             * Session was terminated cleanly. All watchers should
             * already be marked as finished, as stdout is the last
             * stage of the echo pipeline.
             */
            log(LOG_NOTICE, "Connection closed.");
            assert(is_finished(&cs->stdin_io) &&
                   is_finished(&cs->srv_writer_io) &&
                   is_finished(&cs->srv_reader_io) &&
                   is_finished(&cs->stdout_io));
            free(cs);

        } else if (status == -1)
            teardown_session(EV_A_ cs);
    } else
        log(LOG_WARNING, "srv_writer_cb spurious callback!");
}

/*
 * Create a new client_session struct using the given file
 * descriptors. Note that the client_session ev_io watchers and
 * timeouts are initialized, but not started.
 *
 * N.B.: though two of the file descriptors are named stdin_fd and
 * stdout_fd, they need not strictly be the stdin and stdout
 * descriptors; they could be any non-blocking readable or writable
 * descriptors, respectively.
 */
client_session *
new_client_session(int stdin_fd, int stdout_fd, int server_fd)
{
    client_session *cs = malloc(sizeof(client_session));
    if (!cs)
        return 0;

    msg_buf_init(&cs->stdin_buf);
    msg_buf_init(&cs->stdout_buf);

    ev_io_init(&cs->stdin_io, stdin_cb, stdin_fd, EV_READ);
    ev_io_init(&cs->stdout_io, stdout_cb, stdout_fd, EV_WRITE);
    ev_io_init(&cs->srv_reader_io, srv_reader_cb, server_fd, EV_READ);
    ev_io_init(&cs->srv_writer_io, srv_writer_cb, server_fd, EV_WRITE);

    ev_init(&cs->stdin_timeout.timer, stdin_timeout_cb);
    ev_init(&cs->srv_reader_timeout.timer, srv_reader_timeout_cb);
    ev_init(&cs->srv_writer_timeout.timer, srv_writer_timeout_cb);

    return cs;
}

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

/*
 * This struct makes it possible to attempt a connection to each known
 * address for the echo server (as returned by getaddrinfo) -- one at
 * a time -- from the libev event loop, without blocking on
 * connect(). The eio member is the watcher of the latest connection
 * attempt. If it successfully connects, its file descriptor is the
 * one that should be passed to the client_session constructor as the
 * server file descriptor.
 */
typedef struct connect_watcher
{
    ev_io eio;
    struct addrinfo *addr; /* addrinfo for this connection. */
    struct addrinfo *addr_base; /* The base of the addrinfo list. */
} connect_watcher;

/*
 * Initiate a connection on a non-blocking socket using the given
 * socket address.
 *
 * The function returns the socket's file descriptor. Select (using
 * select(2) or one of its cousins) the socket for writing in order to
 * wait for the connection to complete.
 *
 * If an immediate error occurs, the error is logged, the error code
 * is left in errno, and the function returns -1.
 */
int
initiate_connection(const struct sockaddr *addr, socklen_t addr_len)
{
    int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        log(LOG_ERR, "socket: %m");
        return -1;
    }
    if (set_nonblocking(fd) == -1)
        goto err;

    /*
     * Treat both an immediate connection and EINPROGRESS as success,
     * let the caller sort it out.
     */
    int status = connect(fd, addr, addr_len);
    if ((status == 0) || ((status == -1) && (errno == EINPROGRESS)))
        return fd;
    else
        log(LOG_ERR, "connect: %m");

  err:
    close(fd);
    return -1;
}

/*
 * Called by connect_cb when a serious C standard library-related
 * error occurs that prevents connect_cb from making any more
 * connection attempts. errnum contains the corresponding error number
 * (for use with strerror, etc.).
 *
 * In this implementation, the function simply calls exit(3), but in a
 * more complicated program (e.g., an interactive app), it might do
 * something like display a "connection failed" dialog.
 */
void
abort_connection(int errnum)
{
    exit(errnum);
}
 
connect_watcher *
new_connector(struct addrinfo *addr, struct addrinfo *addr_base);

/*
 * This callback creates a client_session structure and starts the
 * echo protocol callbacks, if the current connection attempt
 * succeeds; or tries the next address in the getaddrinfo sequence, if
 * the current attempt fails.
 *
 * If the current attempt fails and there are no more addresses to
 * try, the callback cleans up any remaining state and gives up.
 */
void
connect_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "connect_cb called");

    connect_watcher *c = (connect_watcher *) w;
    if (revents & EV_WRITE) {

        /*
         * This is how we tell if the asynchronous connect(2) was
         * successful.
         */
        int optval;
        socklen_t optlen;
        optlen = sizeof(optval);
        if (getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
            log(LOG_ERR, "connect_cb getsockopt: %m");
            freeaddrinfo(c->addr_base);
            free(c);
            abort_connection(errno);
        }
        if (optval != 0) {

            /* Connection failed; try the next address in the list. */
            log(LOG_ERR, "Connection failed: %s", strerror(optval));
            ev_io_stop(EV_A_ w);
            close(w->fd);

            if (c->addr->ai_next) {
                connect_watcher *cnext = new_connector(c->addr->ai_next,
                                                       c->addr_base);
                if (cnext) {
                    log_with_addr(LOG_NOTICE,
                                  "Trying connection to %s...",
                                  cnext->addr->ai_addr,
                                  cnext->addr->ai_addrlen);
                    ev_io_start(EV_A_ &cnext->eio);
                    free(c);
                    return;
                } else {
                    log(LOG_ERR, "connect_cb can't create connect_watcher: %m");
                    freeaddrinfo(c->addr_base);
                    free(c);
                    abort_connection(errno);
                }
            } else {

                /* No more addresses to try. Fatal. */
                freeaddrinfo(c->addr_base);
                free(c);
                abort_connection(optval);
            }
        }

        log(LOG_NOTICE, "Connected.");

        /*
         * stdin and stdout *must* be set to non-blocking in order for
         * libev to do its thing.
         */
        if (set_nonblocking(/* stdin */ 0) == -1) {
            log(LOG_ERR, "connect_cb can't make stdin non-blocking: %m");
            abort_connection(errno);
        }
        if (set_nonblocking(/* stdout */ 1) == -1) {
            log(LOG_ERR, "connect_cb can't make stdout non-blocking: %m");
            abort_connection(errno);
        }

        client_session *cs = new_client_session(/* stdin */ 0,
                                                /* stdout */ 1,
                                                w->fd);

        if (!cs) {
            log(LOG_ERR, "connect_cb can't create client_session: %m");
            abort_connection(errno);
        }

        /*
         * Start only the reading watchers; there's nothing to write
         * until we get something from stdin or the echo server.
         */
        start_watcher(EV_A_ &cs->stdin_io, &cs->stdin_timeout);
        start_watcher(EV_A_ &cs->srv_reader_io, &cs->srv_reader_timeout);

        /* Don't need the connect watcher anymore. */
        ev_io_stop(EV_A_ w);
        freeaddrinfo(c->addr_base);
        free(c);
    } else {
        log(LOG_WARNING, "connect_cb spurious callback!");
    }
}

/*
 * Constructor for the connect_watcher struct. Returns the address of
 * the new connector_watcher if success, otherwise 0, in which case
 * the error code is left in errno.
 */
connect_watcher *
new_connector(struct addrinfo *addr,
              struct addrinfo *addr_base)
{
    int fd = initiate_connection(addr->ai_addr, addr->ai_addrlen);
    if (fd == -1)
        return 0;

    connect_watcher *c = malloc(sizeof(connect_watcher));
    if (c) {
        ev_io_init(&c->eio, connect_cb, fd, EV_WRITE);
        c->addr = addr;
        c->addr_base = addr_base;
    }
    return c;
}

const char *default_portstr = "7777";

void
usage(const char *name)
{
    printf("usage: %s [OPTIONS] server\n\n", name);
    printf("server can be either an IPv[46] address, or a domain name.\n\n");
    printf("Options:\n");
    printf("  -n, --numerichost Prevents IP address-to-name lookup when\n");
    printf("                    server is given as an IP address.\n");
    printf("  -p, --port        Remote port number to connect to [0-65535].\n");
    printf("                    The default is 7777. Service names are\n");
    printf("                    also acceptable, unless --numericpport is.\n");
    printf("                    specified.\n");
    printf("  -N, --numericport Prevents service name-to-port number lookup\n");
    printf("                    when remote port is specified as an\n");
    printf("                    integer.\n");
    printf("  -l, --loglevel    Set the logging level (0-7, 0 is emergency,\n");
    printf("                    7 is debug). The default is 5 (notice).\n");
    printf("  -4, --ipv4        Connect only via IPv4.\n");
    printf("  -6, --ipv6        Connect only via IPv6.\n");
    printf("  -h, --help        Show this message and exit\n");
    printf("  -V, --version     Print the program version and exit\n");
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
        { "help",        no_argument,       0, 'h' },
        { "version",     no_argument,       0, 'V' },
        { "numerichost", no_argument,       0, 'n' },
        { "numericport", no_argument,       0, 'N' },
        { "ipv4",        no_argument,       0, '4' },
        { "ipv6",        no_argument,       0, '6' },
        { "port",        required_argument, 0, 'p' },
        { "loglevel",    required_argument, 0, 'l' },
        { 0,             0,                 0,  0  }
    };

    char *progname = strdup(argv[0]);
    if (!progname) {
        perror("strdup");
        exit(errno);
    }
    
    long loglevel = LOG_NOTICE;
    char *portstr = 0;
    int opt_ai_flags = 0;
    int opt_ai_family = AF_UNSPEC;
    int ch;
    while ((ch = getopt_long(argc, argv, "hVnN46p:l:", longopts, 0)) != -1) {
        switch (ch) {
        case 'V':
            print_version(basename(progname));
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
        case 'n':
            opt_ai_flags |= AI_NUMERICHOST;
            break;
        case 'N':
            opt_ai_flags |= AI_NUMERICSERV;
            break;
        case '4':
            if ((opt_ai_family == AF_UNSPEC) || (opt_ai_family == AF_INET))
                opt_ai_family = AF_INET;
            else {
                fprintf(stderr,
                        "IPv4-only and IPv6-only flags are mutually exclusive.\n");
                exit(1);
            }
            break;
        case '6':
            if ((opt_ai_family == AF_UNSPEC) || (opt_ai_family == AF_INET6))
                opt_ai_family = AF_INET6;
            else {
                fprintf(stderr,
                        "IPv4-only and IPv6-only flags are mutually exclusive.\n");
                exit(1);
            }
            break;
        case 'h':
        default:
            usage(basename(progname));
            exit(0);
        }
    }

    argc -= optind;
    argv += optind;
    if (argc != 1) {
        usage(basename(progname));
        exit(1);
    }
    char *hostname = strdup(argv[0]);
    if (!hostname) {
        perror("strdup");
        exit(errno);
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
    hints.ai_flags = AI_ADDRCONFIG | opt_ai_flags;
    hints.ai_family = opt_ai_family;
    int err = getaddrinfo(hostname,
                          portstr ? portstr : default_portstr,
                          &hints,
                          &res);
    if (err) {
        log(LOG_ERR, "%s", gai_strerror(err));
        exit(err);
    }

    connect_watcher *c = new_connector(res, res);
    if (c) {
        log_with_addr(LOG_NOTICE,
                      "Trying connection to %s...",
                      res->ai_addr,
                      res->ai_addrlen);
        ev_io_start(loop, &c->eio);
    }
    else
        exit(errno);

    /* Clean up before entering ev_run loop */
    if (portstr)
        free(portstr);
    free(progname);
    free(hostname);
    
    log(LOG_DEBUG, "entering ev_run");
    ev_run(loop, 0);

    log(LOG_DEBUG, "ev_run exited");
    return 0;
}
