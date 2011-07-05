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

typedef struct io_timer
{
    ev_timer timer;
    ev_tstamp last_activity;
} io_timer;

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

typedef struct client_watcher
{
    ev_io eio;
    msg_buf *buf; /* shared with partner */
    io_timer timeout;
    struct client_watcher *partner;
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
static const ev_tstamp ECHO_PROTO_TIMEOUT = 10.0;

/*
 * Handles timeouts on established connections.
 */
void
echo_proto_timeout_cb(EV_P_ ev_timer *t_, int revents)
{
    io_timer *t = (io_timer *) t_;

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
 * Start an client_watcher and its protocol timer. Assumes both have
 * already been initialized.
 */
void
start_watcher(EV_P_ client_watcher *w)
{
    ev_io_start(EV_A_ &w->eio);
    w->timeout.last_activity = ev_now(EV_A);
    echo_proto_timeout_cb(EV_A_ &w->timeout.timer, EV_TIMER);
}

/*
 * Stop an client_watcher and its protocol timer.
 */
void
stop_watcher(EV_P_ client_watcher *w)
{
    ev_io_stop(EV_A_ &w->eio);
    ev_timer_stop(EV_A_ &w->timeout.timer);
}

/*
 * Call this function when you're done reading from stdin, and you
 * want to clean up after the stdin watcher.
 *
 * This function does *not* free the msg_buf that the stdin watcher
 * shares with its partner, because the partner may still need it.
 */
void
free_stdin_watcher(EV_P_ client_watcher *w)
{
    log(LOG_DEBUG, "Freeing stdin watcher.");
    stop_watcher(EV_A_ w);
    close(w->eio.fd); /* stdin */
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
 * Call this function when you're done reading from the echo server,
 * and you want to clean up after the echo server read watcher. It
 * also closes the echo server socket.
 *
 * This function does *not* free the msg_buf that the echo server read
 * watcher shares with its partner (the stdout writer), because the
 * partner may still need it.
 *
 * NB: once you call this function, you can no longer write to (or
 * read from) the echo server, as it closes the connection; i.e, you
 * can no longer call write_cb.
 */
void
free_srv_read_watcher(EV_P_ client_watcher *w)
{
    log(LOG_DEBUG, "Freeing server read watcher.");
    stop_watcher(EV_A_ w);
    close(w->eio.fd); /* echo server socket */
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
 * Reads input from stdin, and schedules it for writing to the echo
 * server using stdin's "partner" watcher.
 */
void
stdin_cb(EV_P_ ev_io *w_, int revents)
{
    log(LOG_DEBUG, "stdin_cb called");

    client_watcher *w = (client_watcher *) w_;
    msg_buf *buf = w->buf;
    
    if (revents & EV_READ) {
        size_t nread = 0;
        while (ringbuf_bytes_free(&buf->rb)) {
            ssize_t n = ringbuf_read(w->eio.fd,
                                     &buf->rb,
                                     ringbuf_bytes_free(&buf->rb));
            if (n == 0) {

                /* EOF: stop this watcher, but drain any remaining writes. */
                log(LOG_DEBUG, "stdin_cb EOF received");
                if (nread && (buf->msg_len == 0))
                    buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
                if (buf->msg_len)
                    start_watcher(EV_A_ w->partner);
                else {

                    /*
                     * Nothing left to write.
                     *
                     * Note: this will discard any incomplete client
                     * messages (those without a terminating
                     * MSG_DELIMITER), by design.
                     */
                    free_srv_write_watcher(EV_A_ w->partner);
                }
                free_stdin_watcher(EV_A_ w);
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
                    log(LOG_ERR, "srv_read_cb read: %m");
                    exit(errno);
                }
            } else {
                nread += n;
                w->timeout.last_activity = ev_now(EV_A);
                log(LOG_DEBUG, "srv_read_cb %zd bytes read", n);
            }
        }

        /* Overflow - fatal. */
        log(LOG_ERR, "server socket overflow.");
        exit(1);

    } else
        log(LOG_WARNING, "srv_read_cb spurious callback!");
}

/*
 * Reads input from the echo server, and schedules it for writing to
 * stdout using its "partner" stdout watcher.
 */
void
srv_read_cb(EV_P_ ev_io *w_, int revents)
{
    log(LOG_DEBUG, "srv_read_cb called");

    client_watcher *w = (client_watcher *) w_;
    msg_buf *buf = w->buf;
    
    if (revents & EV_READ) {
        size_t nread = 0;
        while (ringbuf_bytes_free(&buf->rb)) {
            ssize_t n = ringbuf_read(w->eio.fd,
                                     &buf->rb,
                                     ringbuf_bytes_free(&buf->rb));
            if (n == 0) {

                /* EOF: stop this watcher, but drain any remaining writes. */
                log(LOG_DEBUG, "srv_read_cb EOF received");
                if (nread && (buf->msg_len == 0))
                    buf->msg_len = next_msg_len(&buf->rb, MSG_DELIMITER);
                if (buf->msg_len)
                    start_watcher(EV_A_ w->partner);
                else {

                    /*
                     * Nothing left to write.
                     *
                     * Note: this will discard any incomplete server
                     * messages (those without a terminating
                     * MSG_DELIMITER), by design.
                     */
                    free_stdout_watcher(EV_A_ w->partner);
                }
                free_srv_read_watcher(EV_A_ w);
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
                    log(LOG_ERR, "stdin_cb read: %m");
                    exit(errno);
                }
            } else {
                nread += n;
                w->timeout.last_activity = ev_now(EV_A);
                log(LOG_DEBUG, "stdin_cb %zd bytes read", n);
            }
        }

        /* Overflow - fatal. */
        log(LOG_ERR, "stdin overflow.");
        exit(1);

    } else
        log(LOG_WARNING, "stdin_cb spurious callback!");
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
                w->timeout.last_activity = ev_now(EV_A);
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

/*
 * Create a pair of libev ev_io watchers and support structures: one
 * is a stdio socket (typically either stdin or stdout), and one is a
 * network socket whose (already connected) remote endpoint is an echo
 * server. The two watchers work in concert, via their callbacks and a
 * shared ring buffer, either to send data from the client to the
 * server by reading from stdin and writing to the network socket; or
 * to read echoed data back from the server by reading from the
 * network socket and writing to stdout.
 *
 * This function creates the new watchers, initializes them, and
 * initializes (but does not start) their protocol timeout timers. It
 * is agnostic about the watchers' behaviors, so it works for either
 * case. It does *not* start either watcher: this is the
 * responsibility of the caller, as which one must be started depends
 * on which pair is being created.
 *
 * The pair of watchers shares a msg_buf structure, which contains a
 * ring buffer and a message length count. As the C language has no
 * support for garbage collection or reference counting, the shared
 * msg_buf struct must be freed (via the free_msg_buf function) when
 * it's no longer needed. Be careful not to free it twice, nor to free
 * it too early -- for example, when stdin receives an EOF (hence, the
 * stdin watcher is stopped) but there are still bytes in the ring
 * buffer to be written to the server.
 *
 * Because the C language lacks support for multiple return values,
 * this function always returns a pointer to the newly created stdio
 * watcher; you can get its network watcher "partner" via the partner
 * pointer.
 *
 * NOTE: assumes that both std_fd and net_fd have been made
 * non-blocking! The echo client won't function properly if either
 * socket is blocking.
 *
 * Returns 0 if one or more of the structures can't be allocated, in
 * which case the error is left in errno.
 */
client_watcher *
make_client_watcher(EV_P_ int std_fd,
                    int std_revents,
                    ev_io_cb std_cb,
                    int net_fd,
                    int net_revents,
                    ev_io_cb net_cb)
{
    client_watcher *std_io = malloc(sizeof(client_watcher));
    if (!std_io)
        return 0;
    client_watcher *net_io = malloc(sizeof(client_watcher));
    if (!net_io)
        goto err_net_io;
    msg_buf *buf = new_msg_buf();
    if (!buf)
        goto err_buf_io;
    std_io->buf = buf;
    std_io->partner = net_io;
    net_io->buf = buf;
    net_io->partner = std_io;
        
    ev_io_init(&std_io->eio, std_cb, std_fd, std_revents);
    ev_init(&std_io->timeout.timer, echo_proto_timeout_cb);
    ev_io_init(&net_io->eio, net_cb, net_fd, net_revents);
    ev_init(&net_io->timeout.timer, echo_proto_timeout_cb);
    return std_io;

  err_buf_io:
    free(net_io);
  err_net_io:
    free(std_io);
    return 0;
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
 * callback can be installed.
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

        if (set_nonblocking(/* stdin */ 0) == -1) {
            log(LOG_ERR, "connect_cb can't make stdin non-blocking: %m");
            exit(errno);
        }
        client_watcher *stdin_io = make_client_watcher(EV_A_ /* stdin */ 0,
                                                       EV_READ,
                                                       stdin_cb,
                                                       w->fd,
                                                       EV_WRITE,
                                                       write_cb);
        if (!stdin_io) {
            log(LOG_ERR, "make_client_watcher: %m");
            exit(errno);
        }

        if (set_nonblocking(/* stdout */ 1) == -1) {
            log(LOG_ERR, "connect_cb can't make stdout non-blocking: %m");
            exit(errno);
        }
        client_watcher *stdout_io = make_client_watcher(EV_A_ /* stdout */ 1,
                                                        EV_WRITE,
                                                        write_cb,
                                                        w->fd,
                                                        EV_READ,
                                                        srv_read_cb);
        if (!stdout_io) {
            log(LOG_ERR, "make_client_watcher: %m");
            exit(errno);
        }

        start_watcher(EV_A_ stdin_io);
        start_watcher(EV_A_ stdout_io->partner); /* read from server */

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
