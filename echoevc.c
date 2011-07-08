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

typedef void (* shutdown_fn)(EV_P_ ev_io *w);

/*
 * On the client side of the echo protocol, there are two pairs of
 * ev_io watchers: one pair for reading from stdin and writing that
 * data to the echo server, and one pair for reading the data back
 * from the echo server and writing it to stdout. Therefore, each pair
 * needs one reader, and one writer. The reader and writer share a
 * single ring buffer to enforce the FIFO nature of the echo protocol.
 *
 * The watcher_pair struct combines the paired ev_io reader and writer
 * with a separate timeout mechanism for each ev_io watcher; separate
 * shutdown functions for each watcher's file descriptor; a flag to
 * indicate that the reader half of the pair is finished with its file
 * descriptor; and the ring buffer, plus the length of the first whole
 * message in the ring buffer.

 */
typedef struct watcher_pair
{
    ev_io reader;
    ev_io writer;

    timeout_timer reader_timeout;
    timeout_timer writer_timeout;

    shutdown_fn reader_shutdown;
    shutdown_fn writer_shutdown;

    bool reader_is_finished;

    /* Bytes left to be written in the current outgoing message. */
    size_t msg_len;
    ringbuf_t rb;
} watcher_pair;

/*
 * Macros to help libev callbacks go from ev_io struct pointers back
 * to their containing watcher_pair structs.
 */
#define READER_TO_WATCHER_PAIR(w) \
    (watcher_pair *) (((void *)(w)) - offsetof(watcher_pair, reader));

#define WRITER_TO_WATCHER_PAIR(w) \
    (watcher_pair *) (((void *)(w)) - offsetof(watcher_pair, writer));

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
 * A do-nothing timeout handler (for stdout, which should not time
 * out).
 */
void
null_timeout_cb(EV_P_ ev_timer *t, int revents)
{
}

/*
 * Start an ev_io watcher and its echo protocol timer.  Assumes both
 * have already been initialized.
 */
void
start_watcher(EV_P_ ev_io *w, timeout_timer *t)
{
    ev_io_start(EV_A_ w);
    t->last_activity = ev_now(EV_A);
    echo_proto_timeout_cb(EV_A_ &t->timer, EV_TIMER);
}

/*
 * Stop an ev_io and its echo protocol timer.
 */
void
stop_watcher(EV_P_ ev_io *w, timeout_timer *t)
{
    ev_io_stop(EV_A_ w);
    ev_timer_stop(EV_A_ &t->timer);
}

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
    if (shutdown(w->fd, SHUT_WR) == -1) {
        log(LOG_ERR, "shutdown_srv_writer shutdown: %m");
        exit(errno);
    }
}

/*
 * The default shutdown function: just close(2) the watcher's file
 * descriptor.
 */
void
close_watcher(EV_P_ ev_io *w)
{
    if (close(w->fd) == -1) {
        log(LOG_ERR, "close_watcher close on fd %d: %m", w->fd);
        exit(errno);
    }
}

/*
 * Reads input from a watcher's descriptor, and schedules it for
 * writing using its paired ev_io writer.
 */
void
read_cb(EV_P_ ev_io *reader, int revents)
{
    log(LOG_DEBUG, "read_cb called");

    watcher_pair *p = READER_TO_WATCHER_PAIR(reader);
    assert(reader == &p->reader);
    
    if (revents & EV_READ) {
        size_t nread = 0;
        while (ringbuf_bytes_free(&p->rb)) {
            ssize_t n = ringbuf_read(reader->fd,
                                     &p->rb,
                                     ringbuf_bytes_free(&p->rb));
            if (n == 0) {

                /*
                 * EOF: shutdown this watcher, but drain any remaining
                 * writes.
                 */
                log(LOG_DEBUG, "read_cb EOF received on fd %d", reader->fd);

                stop_watcher(EV_A_ reader, &p->reader_timeout);
                p->reader_shutdown(EV_A_ reader);
                p->reader_is_finished = true;

                if (nread && (p->msg_len == 0))
                    p->msg_len = next_msg_len(&p->rb, MSG_DELIMITER);
                if (p->msg_len)
                    start_watcher(EV_A_ &p->writer, &p->writer_timeout);
                else {

                    /*
                     * Nothing left to write, destroy the entire pair.
                     *
                     * Note: this will discard any incomplete messages
                     * (those without a terminating MSG_DELIMITER), by
                     * design.
                     */
                    stop_watcher(EV_A_ &p->writer, &p->writer_timeout);
                    p->writer_shutdown(EV_A_ &p->writer);
                    free(p);
                }
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
                    if (nread && (p->msg_len == 0)) {
                        p->msg_len = next_msg_len(&p->rb, MSG_DELIMITER);
                        if (p->msg_len)
                            start_watcher(EV_A_ &p->writer, &p->writer_timeout);
                    }
                    return;
                } else {

                    /* Fatal. */
                    log(LOG_ERR, "read_cb read on fd %d: %m", reader->fd);
                    exit(errno);
                }
            } else {
                nread += n;
                p->reader_timeout.last_activity = ev_now(EV_A);
                log(LOG_DEBUG,
                    "read_cb %zd bytes read on fd %d",
                    n,
                    reader->fd);
            }
        }

        /* Overflow - fatal. */
        log(LOG_ERR, "read_cb socket overflow on fd %d.", reader->fd);
        exit(1);

    } else
        log(LOG_WARNING, "read_cb spurious callback on fd %d!", reader->fd);
}

/*
 * This callback is scheduled by reading watchers when they receive
 * data for writing.
 */
void
write_cb(EV_P_ ev_io *writer, int revents)
{
    log(LOG_DEBUG, "write_cb called");

    watcher_pair *p = WRITER_TO_WATCHER_PAIR(writer);
    assert(writer == &p->writer);

    if (revents & EV_WRITE) {
        while (p->msg_len) {
            ssize_t n = ringbuf_write(writer->fd,
                                      &p->rb,
                                      p->msg_len);
            if (n == -1) {
                if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINTR))
                    break;
                else {

                    /* Fatal. */
                    log(LOG_ERR, "write_cb write on fd %d: %m", writer->fd);
                    exit(errno);
                }
            } else {
                p->msg_len -= n;
                p->writer_timeout.last_activity = ev_now(EV_A);
                log(LOG_DEBUG,
                    "write_cb %zd bytes written to fd %d",
                    n,
                    writer->fd);
            }
        }
        if (p->msg_len == 0) {

            /* Look for more messages; stop/shutdown if none. */
            p->msg_len = next_msg_len(&p->rb, MSG_DELIMITER);
            if (p->msg_len == 0) {
                stop_watcher(EV_A_ writer, &p->writer_timeout);
                if (p->reader_is_finished) {

                    /* No more work for this pair; clean it up. */
                    p->writer_shutdown(EV_A_ &p->writer);
                    free(p);
                }
            }
        }
    } else
        log(LOG_WARNING, "write_cb spurious callback on fd %d!", writer->fd);
}

typedef void (* ev_timer_cb)(EV_P_ ev_timer *, int);

watcher_pair *
new_watcher_pair(int reader_fd,
                 ev_timer_cb reader_timeout_callback,
                 shutdown_fn reader_shutdown_fn,
                 int writer_fd,
                 ev_timer_cb writer_timeout_callback,
                 shutdown_fn writer_shutdown_fn)
{
    watcher_pair *pair = malloc(sizeof(watcher_pair));
    if (!pair)
        return 0;

    ringbuf_init(&pair->rb);
    pair->msg_len = 0;

    pair->reader_shutdown = reader_shutdown_fn;
    pair->writer_shutdown = writer_shutdown_fn;
    
    ev_io_init(&pair->reader, read_cb, reader_fd, EV_READ);
    ev_init(&pair->reader_timeout.timer, reader_timeout_callback);

    ev_io_init(&pair->writer, write_cb, writer_fd, EV_WRITE);
    ev_init(&pair->writer_timeout.timer, writer_timeout_callback);

    return pair;
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

connect_watcher *
new_connector(struct addrinfo *addr, struct addrinfo *addr_base);

/*
 * This callback exists merely to indicate when the non-blocking
 * connection attempt has succeeded, so that the echo protocol
 * callbacks can be installed.
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

            /* Fatal. */
            log(LOG_ERR, "connect_cb getsockopt: %m");
            freeaddrinfo(c->addr_base);
            free(c);
            exit(errno);
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

                    /* Fatal. */
                    freeaddrinfo(c->addr_base);
                    free(c);
                    exit(optval);
                }
            } else {

                /* Fatal. */
                freeaddrinfo(c->addr_base);
                free(c);
                exit(optval);
            }
        }

        log(LOG_NOTICE, "Connected.");

        /*
         * stdin and stdout *must* be set to non-blocking in order for
         * libev to do its thing.
         */
        if (set_nonblocking(/* stdin */ 0) == -1) {
            log(LOG_ERR, "connect_cb can't make stdin non-blocking: %m");
            exit(errno);
        }
        if (set_nonblocking(/* stdout */ 1) == -1) {
            log(LOG_ERR, "connect_cb can't make stdout non-blocking: %m");
            exit(errno);
        }

        watcher_pair *stdin_srv_write = new_watcher_pair(/* stdin */ 0,
                                                         echo_proto_timeout_cb,
                                                         close_watcher,
                                                         w->fd,
                                                         echo_proto_timeout_cb,
                                                         shutdown_srv_writer);

        /*
         * N.B.: don't timeout on stdout, it should be allowed to
         * block indefinitely.
         */
        watcher_pair *stdout_srv_read = new_watcher_pair(w->fd,
                                                         echo_proto_timeout_cb,
                                                         close_watcher,
                                                         /* stdout */ 1,
                                                         null_timeout_cb,
                                                         close_watcher);

        if (!stdin_srv_write || !stdout_srv_read) {
            log(LOG_ERR, "connect_cb can't create watcher_pair: %m");
            exit(errno);
        }

        /*
         * Start only the reading watchers; there's nothing to write
         * until we get something from stdin or the echo server.
         */
        start_watcher(EV_A_ &stdin_srv_write->reader,
                      &stdin_srv_write->reader_timeout);
        start_watcher(EV_A_ &stdout_srv_read->reader,
                      &stdout_srv_read->reader_timeout);

        /* Don't need the connect watcher anymore. */
        ev_io_stop(EV_A_ w);
        freeaddrinfo(c->addr_base);
        free(c);
    } else {
        log(LOG_WARNING, "connect_cb spurious callback!");
    }
}

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
