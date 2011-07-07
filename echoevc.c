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

/*
 * Each pair of watchers (stdin/srv_write, stdout/srv_read) share a
 * ring buffer via this structure. The last one out is responsible for
 * deallocating it.
 */
typedef struct msg_buf
{
    ringbuf_t rb;
    size_t msg_len;
} msg_buf;

/*
 * A client_watcher and its libev callback is reponsible for
 * implementing exactly one part of the echo client protocol. For any
 * given connection to an echo server, there will be 4 client_watcher
 * instances: one to read the client's input on stdin, one to write
 * the stdin data to the echo server socket, one to read the echoed
 * data back from the echo server on the echo server socket, and one
 * to write the echoed data on stdout.
 *
 * The 4 client watchers are organized by the client program into 2
 * pairs: one pair for stdin and writing to the echo server, and one
 * pair for reading from the echo server and writing to stdout. Each
 * pair shares a ring buffer via the msg_buf structure; the ring
 * buffer enforces the FIFO nature of the echo protocol. The "partner"
 * member of the client_watcher data structure points to the watcher's
 * pair partner.
 *
 * As the C language has no support for garbage collection or
 * reference counting, the shared msg_buf struct for each pair must be
 * freed (via the free_msg_buf function) when it's no longer
 * needed. Note that it's always the watcher that's performing writes
 * for a given pair that's responsible for freeing the msg_buf.
 */
typedef struct client_watcher *client_watcher_p;

typedef void (* client_watcher_destructor)(EV_P_ client_watcher_p);

typedef struct client_watcher
{
    ev_io eio;
    msg_buf *buf; /* shared with partner */
    timeout_timer *timeout;
    struct client_watcher *partner;
    client_watcher_destructor destructor;
} client_watcher;

/*
 * msg_buf's need a bit of initialization. This function does that,
 * and returns a pointer to the new msg_buf if successful, 0
 * otherwise, in which case errno contains the error.
 */
msg_buf *
new_msg_buf()
{
    msg_buf *buf = malloc(sizeof(msg_buf));
    if (buf)
        ringbuf_init(&buf->rb);
    return buf;
}

void
free_msg_buf(msg_buf *buf)
{
    free(buf);
}

/* Default protocol timeout, in seconds. */
static const ev_tstamp ECHO_PROTO_TIMEOUT = 120.0;

/*
 * Handles timeouts on established connections.
 */
void
echo_proto_timeout_cb(EV_P_ ev_timer *t_, int revents)
{
    timeout_timer *t = (timeout_timer *) t_;

    ev_tstamp now = ev_now(EV_A);
    ev_tstamp timeout = t->last_activity + ECHO_PROTO_TIMEOUT;
    if (timeout < now) {

        /* A real timeout. */
        log(LOG_NOTICE, "Timeout, closing connection");
        exit(1);
    } else {

        /* False alarm, re-arm timeout. */
        t_->repeat = timeout - now;
        ev_timer_again(EV_A_ t_);
    }
}

/*
 * Start an client_watcher and its protocol timer (if
 * applicable). Assumes both have already been initialized.
 */
void
start_watcher(EV_P_ client_watcher *w)
{
    ev_io_start(EV_A_ &w->eio);
    if (w->timeout) {
        w->timeout->last_activity = ev_now(EV_A);
        echo_proto_timeout_cb(EV_A_ &w->timeout->timer, EV_TIMER);
    }
}

/*
 * Stop an client_watcher and its protocol timer (if applicable).
 */
void
stop_watcher(EV_P_ client_watcher *w)
{
    ev_io_stop(EV_A_ &w->eio);
    if (w->timeout)
        ev_timer_stop(EV_A_ &w->timeout->timer);
}

/*
 * Destructor for client read watchers.
 *
 * This function does *not* free the msg_buf that the watcher shares
 * with its client write partner, because the writer may still need
 * it.
 *
 * NB: This function closes the watcher's file descriptor, so if this
 * client watcher shares a file descriptor with another watcher (e.g.,
 * the echo server file descriptor), you may not communicate on that
 * file descriptor after calling this function!
 */
void
free_read_watcher(EV_P_ client_watcher *w)
{
    log(LOG_DEBUG, "Freeing client watcher on fd %d.", w->eio.fd);
    stop_watcher(EV_A_ w);
    close(w->eio.fd);
    free(w);
}

/*
 * Call this function when you're done writing bytes to the echo
 * server, and you want to clean up after the server-writing
 * watcher. This function frees the msg_buf that the watcher shares
 * with the stdin watcher. It also shuts down writes on the echo
 * server socket.
 *
 * NB: once you call this function, you can no longer call stdin_cb;
 * i.e., you must stop the stdin watcher, as well.
 */
void
free_srv_write_watcher(EV_P_ client_watcher *w)
{
    log(LOG_DEBUG, "Freeing server write watcher.");
    stop_watcher(EV_A_ w);

    /* *Don't* close the file descriptor here, just want a half-close. */
    if (shutdown(w->eio.fd, SHUT_WR) == -1) {
        log(LOG_ERR, "free_srv_write_watcher shutdown: %m");
        exit(errno);
    }

    free_msg_buf(w->buf);
    free(w);
}

/*
 * Call this function when you're done writing to stdout, and you want
 * to clean up after the stdout watcher. This function frees the
 * msg_buf that the watcher shares with the echo server read
 * watcher. It also closes stdout.
 *
 * NB: once you call this function, you can no longer call
 * srv_read_cb; i.e., you must stop the echo server read watcher, as
 * well.
 */
void
free_stdout_watcher(EV_P_ client_watcher *w)
{
    log(LOG_DEBUG, "Freeing stdout watcher.");
    stop_watcher(EV_A_ w);
    close(w->eio.fd); /* stdout */
    free_msg_buf(w->buf);
    free(w);
}

/*
 * Reads input from a watcher's descriptor, and schedules it for
 * writing using the watcher's "partner."
 */
void
read_cb(EV_P_ ev_io *w_, int revents)
{
    log(LOG_DEBUG, "read_cb called");

    client_watcher *w = (client_watcher *) w_;
    msg_buf *buf = w->buf;
    
    if (revents & EV_READ) {
        size_t nread = 0;
        while (ringbuf_bytes_free(&buf->rb)) {
            ssize_t n = ringbuf_read(w->eio.fd,
                                     &buf->rb,
                                     ringbuf_bytes_free(&buf->rb));
            if (n == 0) {

                /*
                 * EOF: delete this watcher, but drain any remaining
                 * writes.
                 */
                log(LOG_DEBUG, "read_cb EOF received on fd %d", w_->fd);
                if (nread && (buf->msg_len == 0))
                    buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
                if (buf->msg_len)
                    start_watcher(EV_A_ w->partner);
                else {

                    /*
                     * Nothing left to write, delete the writing
                     * partner, too.
                     *
                     * Note: this will discard any incomplete messages
                     * (those without a terminating MSG_DELIMITER), by
                     * design.
                     */
                    w->partner->destructor(EV_A_ w->partner);
                }
                w->destructor(EV_A_ w);
                return;
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
                            start_watcher(EV_A_ w->partner);
                    }
                    return;
                } else {

                    /* Fatal. */
                    log(LOG_ERR, "read_cb read on fd %d: %m", w_->fd);
                    exit(errno);
                }
            } else {
                nread += n;
                if (w->timeout)
                    w->timeout->last_activity = ev_now(EV_A);
                log(LOG_DEBUG, "read_cb %zd bytes read on fd %d", n, w_->fd);
            }
        }

        /* Overflow - fatal. */
        log(LOG_ERR, "read_cb socket overflow on fd %d.", w_->fd);
        exit(1);

    } else
        log(LOG_WARNING, "read_cb spurious callback on fd %d!", w_->fd);
}

/*
 * This callback is scheduled by reading watchers when they receive
 * data for writing.
 */
void
write_cb(EV_P_ ev_io *w_, int revents)
{
    log(LOG_DEBUG, "write_cb called");

    client_watcher *w = (client_watcher *) w_;
    msg_buf *buf = w->buf;

    if (revents & EV_WRITE) {
        while (buf->msg_len) {
            ssize_t n = ringbuf_write(w->eio.fd,
                                      &buf->rb,
                                      buf->msg_len);
            if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR))
                    break;
                else {

                    /* Fatal. */
                    log(LOG_ERR, "write_cb write on fd %d: %m", w_->fd);
                    exit(errno);
                }
            } else {
                buf->msg_len -= n;
                if (w->timeout)
                    w->timeout->last_activity = ev_now(EV_A);
                log(LOG_DEBUG,
                    "write_cb %zd bytes written to fd %d",
                    n,
                    w_->fd);
            }
        }
        if (buf->msg_len == 0) {

            /* Look for more messages; stop if none. */
            buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
            if (buf->msg_len == 0)
                stop_watcher(EV_A_ w);
        }
    } else
        log(LOG_WARNING, "write_cb spurious callback on fd %d!", w_->fd);
}

typedef void (* ev_io_cb)(EV_P_ ev_io *, int);
typedef void (* ev_timer_cb)(EV_P_ ev_timer *, int);

/*
 * Create and initialize a client_watcher, using the provided file
 * descriptor, libev event mask, libev callback, msg_buf pointer, and
 * destructor. The function will also create and initialize a timeout
 * timer for the watcher, if timeout_callback is non-NULL.
 *
 * Returns 0 if any of the structures cannot be allocated, in which
 * case the error is left in errno.
 *
 * N.B.: This function does not set the client_watcher's partner
 * pointer; because of the circular dependency between a pair of
 * client_watcher structs, it must be set by the caller.
 */
client_watcher *
new_client_watcher(int fd,
                   int revents,
                   ev_io_cb callback,
                   ev_timer_cb timeout_callback,
                   msg_buf *buf,
                   client_watcher_destructor destructor)
{
    client_watcher *w = malloc(sizeof(client_watcher));
    if (!w)
        return 0;
    if (timeout_callback) {
        w->timeout = malloc(sizeof(timeout_timer));
        if (!w->timeout) {
            free(w);
            return 0;
        }
    } else
        w->timeout = 0;
    w->buf = buf;
    w->partner = 0;
    w->destructor = destructor;
        
    ev_io_init(&w->eio, callback, fd, revents);
    if (w->timeout)
        ev_init(&w->timeout->timer, timeout_callback);
    return w;
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
 * This callback exists merely to indicate when the non-blocking
 * connection attempt has succeeded, so that the echo protocol
 * callbacks can be installed.
 */
void
connect_cb(EV_P_ ev_io *w, int revents)
{
    log(LOG_DEBUG, "connect_cb called");

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
            exit(errno);
        }
        if (optval != 0) {
            log(LOG_ERR, "Connection failed: %s", strerror(optval));
            exit(optval);
        }
            
        log(LOG_NOTICE, "Connected.");

        /*
         * Hook up all the watchers, msg_bufs, timeouts, and
         * callbacks.
         */
        if (set_nonblocking(/* stdin */ 0) == -1) {
            log(LOG_ERR, "connect_cb can't make stdin non-blocking: %m");
            exit(errno);
        }
        if (set_nonblocking(/* stdout */ 1) == -1) {
            log(LOG_ERR, "connect_cb can't make stdout non-blocking: %m");
            exit(errno);
        }
        msg_buf *stdin_buf = new_msg_buf();
        msg_buf *stdout_buf = new_msg_buf();
        if (!stdin_buf || !stdout_buf) {
            log(LOG_ERR, "connect_cb can't create message buffers: %m");
            exit(errno);
        }
        client_watcher *stdin_io = new_client_watcher(/* stdin */ 0,
                                                      EV_READ,
                                                      read_cb,
                                                      echo_proto_timeout_cb,
                                                      stdin_buf,
                                                      free_read_watcher);
        client_watcher *srv_write_io = new_client_watcher(w->fd,
                                                          EV_WRITE,
                                                          write_cb,
                                                          echo_proto_timeout_cb,
                                                          stdin_buf,
                                                          free_srv_write_watcher);
        client_watcher *srv_read_io = new_client_watcher(w->fd,
                                                         EV_READ,
                                                         read_cb,
                                                         echo_proto_timeout_cb,
                                                         stdout_buf,
                                                         free_read_watcher);

        /* Note: don't use a timeout on stdout: blocking is OK. */
        client_watcher *stdout_io = new_client_watcher(/* stdout */ 1,
                                                       EV_WRITE,
                                                       write_cb,
                                                       0,
                                                       stdout_buf,
                                                       free_stdout_watcher);
        if (!stdin_io || !srv_write_io || !srv_read_io || !stdout_io) {
            log(LOG_ERR, "connect_cb can't create client watcher: %m");
            exit(errno);
        }

        stdin_io->partner = srv_write_io;
        srv_write_io->partner = stdin_io;

        srv_read_io->partner = stdout_io;
        stdout_io->partner = srv_read_io;
        
        /*
         * Start only the reading watchers; nothing to write until we
         * get something from stdin or the echo server.
         */
        start_watcher(EV_A_ stdin_io);
        start_watcher(EV_A_ srv_read_io);

        /* Don't need the connect watcher anymore. */
        ev_io_stop(EV_A_ w);
        free(w);
    } else {
        log(LOG_WARNING, "connect_cb spurious callback!");
    }
}

ev_io *
make_connector(const struct sockaddr *addr, socklen_t addr_len)
{
    int fd = initiate_connection(addr, addr_len);
    if (fd == -1)
        return NULL;

    ev_io *io = malloc(sizeof(ev_io));
    if (io)
        ev_io_init(io, connect_cb, fd, EV_WRITE);
    return io;
}

const char *default_portstr = "7777";

void
usage(const char *name)
{
    printf("usage: %s [OPTIONS] server\n\n", name);
    printf("server can be either an IPv[46] address, or a domain name.\n\n");
    printf("Options:\n");
    printf("  -p, --port       Remote port number to connect to [0-65535].\n");
    printf("                   The default is 7777. Service names are\n");
    printf("                   also acceptable.\n");
    printf("  -l, --loglevel   Set the logging level (0-7, 0 is emergency,\n");
    printf("                   7 is debug). The default is 3 (error).\n");
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
        { "help",      no_argument,       0, 'h' },
        { "version",   no_argument,       0, 'V' },
        { "port",      required_argument, 0, 'p' },
        { "loglevel",  required_argument, 0, 'l' },
        { 0,           0,                 0,  0  }
    };

    char *progname = strdup(argv[0]);
    if (!progname) {
        perror("strdup");
        exit(errno);
    }
    
    long loglevel = LOG_ERR;
    char *portstr = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, "hVl:p:", longopts, 0)) != -1) {
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
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_UNSPEC;
    int err = getaddrinfo(hostname,
                          portstr ? portstr : default_portstr,
                          &hints,
                          &res);
    if (err) {
        log(LOG_ERR, "%s", gai_strerror(err));
        exit(err);
    }

    /* XXX dhess - cycle through connections until one works. */
    ev_io *io = make_connector(res->ai_addr, res->ai_addrlen);
    if (io) {
        log(LOG_NOTICE, "Trying connection to %s...", hostname);
        ev_io_start(loop, io);
    }
    else
        exit(errno);
    freeaddrinfo(res);

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
