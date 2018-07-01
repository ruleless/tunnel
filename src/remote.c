#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/event_compat.h>

#include "util.h"
#include "protocol.h"
#include "thread_env.h"

#define DebugLog 1
#define InfoLog  2
#define WarnLog  3
#define ErrLog   4

#define TUN_TIMEOUT    60
#define REMOTE_TIMEOUT 60

#define ENV_TUN       "TUNNEL"
#define ENV_REMOTE    "REMOTE"
#define ENV_TUNFD     "tunfd"
#define ENV_REMOTEFD  "remotefd"

#define LOG(lv, fmt, ...)                                               \
    do {                                                                \
        char env_[1024] = {0};                                          \
        time_t t_ = time(NULL);                                         \
        struct tm *timeinfo_ = localtime(&t_);                          \
        get_logenv(env_, sizeof(env_));                                 \
        if (DebugLog == lv) {                                           \
            fprintf(stderr, "[%04d/%02d/%d %02d:%02d:%02d][" #lv "]"    \
                    "[%s:%d][%s]" fmt "%s\n",                           \
                    timeinfo_->tm_year + 1900, timeinfo_->tm_mon + 1,   \
                    timeinfo_->tm_mday, timeinfo_->tm_hour,             \
                    timeinfo_->tm_min, timeinfo_->tm_sec,               \
                    __FILE__, __LINE__, __FUNCTION__,                   \
                    ##__VA_ARGS__, env_);                               \
        } else {                                                        \
            fprintf(stderr, "[%04d/%02d/%d %02d:%02d:%02d][" #lv "]"    \
                    fmt "%s\n",                                         \
                    timeinfo_->tm_year + 1900, timeinfo_->tm_mon + 1,   \
                    timeinfo_->tm_mday, timeinfo_->tm_hour,             \
                    timeinfo_->tm_min, timeinfo_->tm_sec,               \
                    ##__VA_ARGS__, env_);                               \
        }                                                               \
    } while (0)

#define SNPRINTF(key)                                                   \
    do {                                                                \
        const char *env_ = get_thread_env(key);                         \
        if (env_ && *env_) {                                            \
            int n_ = snprintf(ptr, end_ptr - ptr, key ":%s ", env_);    \
            if (n_ < 0 || n_ >= end_ptr - ptr) {                        \
                return;                                                 \
            }                                                           \
            ptr += n_;                                                  \
        }                                                               \
    } while(0)

typedef struct global_s global_t;
typedef struct server_s server_t;
typedef struct addr_info_s addr_info_t;
typedef struct tunnel_s tunnel_t;
typedef struct remote_s remote_t;

typedef int (*encode_handler_pt)(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);
typedef int (*decode_handler_pt)(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset);

struct global_s
{
    struct event_base *evbase;
    struct evdns_base *evdns;
};

struct addr_info_s
{
    hostname_t listen_addr;
    hostname_t peer_addr;

    struct sockaddr_in listen_inaddr;
    struct sockaddr_in peer_inaddr;
};

struct server_s
{
    int fd;

    struct event ev_accept;

    addr_info_t addr;

    encode_handler_pt encode_handler;
    decode_handler_pt decode_handler;
};

struct tunnel_s
{
    int fd;

    server_t *s;

    remote_t *r;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    char encbuf[BUF_SIZE];
    char *sendptr;
    size_t len;
};

struct remote_s
{
    int fd;

    tunnel_t *tun;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    BOOL connected;

    char encbuf[BUF_SIZE];
    char *recvptr;

    char buf[RECV_SIZE];
    char padding[PADDING_SIZE]; /* prevent from overflow when decoding */
    char *sendptr;
    size_t len;
};

static global_t s_global;

static void signal_cb(evutil_socket_t fd, short event, void *arg);

static server_t *new_server(addr_info_t *addr);
static void free_server(server_t *s);
static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg);
static void accept_cb(evutil_socket_t fd, short event, void *arg);

static tunnel_t *new_tunnel(server_t *s, int fd);
static void free_tunnel(tunnel_t *tun);
static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg);
static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg);

static remote_t *new_remote(tunnel_t *l);
static void free_remote(remote_t *r);
static void remote_recv_cb(evutil_socket_t fd, short event, void *arg);
static void remote_send_cb(evutil_socket_t fd, short event, void *arg);


static void get_logenv(char *env, size_t len)
{
    char *ptr = env + 1, *end_ptr = env + len;

    SNPRINTF(ENV_TUN);
    SNPRINTF(ENV_REMOTE);
    SNPRINTF(ENV_TUNFD);
    SNPRINTF(ENV_REMOTEFD);
    if (ptr > env + 1)
    {
        *env = '<';
        *(ptr - 1) = '>';
    }
}

static void set_logenv(const tunnel_t *tun)
{
    char str_tun[32], str_remote[32], tunfd[8], remotefd[8];

    snprintf(str_tun, sizeof(str_tun), "%p", tun);
    snprintf(str_remote, sizeof(str_remote), "%p", tun->r);
    snprintf(tunfd, sizeof(tunfd), "%d", tun->fd);

    if (tun->r)
        snprintf(remotefd, sizeof(remotefd), "%d", tun->r->fd);
    else
        snprintf(remotefd, sizeof(remotefd), "-1");

    set_thread_env(ENV_TUN, str_tun);
    set_thread_env(ENV_REMOTE, str_remote);
    set_thread_env(ENV_TUNFD, tunfd);
    set_thread_env(ENV_REMOTEFD, remotefd);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *signal = arg;

    LOG(InfoLog, "signal_cb: got signal %d", event_get_signal(signal));
}

static server_t *new_server(addr_info_t *addr)
{
    server_t *s = NULL;
    struct evutil_addrinfo hints;
    int fd = -1;
    int opt;

    s = (server_t *)calloc(sizeof(server_t), 1);
    if (!s)
    {
        LOG(ErrLog, "new server failed, no enough memory");
        goto err_1;
    }
    memcpy(&s->addr, addr, sizeof(s->addr));
    s->encode_handler = aes_encode;
    s->decode_handler = aes_decode;

    /* create socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG(WarnLog, "create server failed, reason:%s", strerror(errno));
        goto err_1;
    }
    if (set_nonblock(fd) < 0)
    {
        LOG(WarnLog, "create server failed, reason:%s", strerror(errno));
        goto err_2;
    }

    opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* bind address */
    s->addr.listen_inaddr.sin_family = AF_INET;
    s->addr.listen_inaddr.sin_port = htons(s->addr.listen_addr.port);
    if (*s->addr.listen_addr.hostname)
    {
        if (inet_pton(AF_INET, s->addr.listen_addr.hostname, &s->addr.listen_inaddr.sin_addr) < 0)
        {
            LOG(ErrLog, "create server failed, invalid listen address:%s", strerror(errno));
            goto err_2;
        }
    }
    else
    {
        s->addr.listen_inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(fd, (const struct sockaddr *)&s->addr.listen_inaddr, sizeof(s->addr.listen_inaddr)) < 0)
    {
        LOG(ErrLog, "create server failed, bind failed, reason:%s", strerror(errno));
        goto err_2;
    }
    if (listen(fd, 5) < 0)
    {
        LOG(ErrLog, "create server failed, listen failed, reason:%s", strerror(errno));
        goto err_2;
    }

    s->fd = fd;

    event_assign(&s->ev_accept, s_global.evbase, fd, EV_READ|EV_PERSIST, accept_cb, s);

    /* resolve peer hostname */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    evdns_getaddrinfo(s_global.evdns, s->addr.peer_addr.hostname, NULL, &hints, resolv_cb, s);

    return s;

err_2:
    if (fd >= 0)
        close(fd);
err_1:
    if (s)
        free(s);
    return NULL;
}

static void free_server(server_t *s)
{
    event_del(&s->ev_accept);
    free(s);
}

static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg)
{
    int i;
    server_t *s = (server_t *)arg;

    if (err)
    {
        goto err_1;
    }

    for (i = 0; ai; ai = ai->ai_next, ++i)
    {
        char buf[128];

        if (ai->ai_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;

            evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            s->addr.peer_inaddr.sin_family = AF_INET;
            s->addr.peer_inaddr.sin_port = htons(s->addr.peer_addr.port);
            s->addr.peer_inaddr.sin_addr.s_addr = sin->sin_addr.s_addr;

            event_add(&s->ev_accept, NULL);

            LOG(DebugLog, "reolve %s -> %s, we can accept tunnel now",
                s->addr.peer_addr.hostname, buf);

            return;
        }
    }

err_1:
    LOG(DebugLog, "resolve '%s' failed, now exit, reason:%s",
        s->addr.peer_addr.hostname, evutil_gai_strerror(err));
    event_base_loopexit(s_global.evbase, NULL);
}

static void accept_cb(evutil_socket_t fd, short event, void *arg)
{
    server_t *s = (server_t *)arg;
    int tunfd = accept(s->fd, NULL, NULL);
    tunnel_t *tun = NULL;

    if (tunfd < 0)
    {
        LOG(WarnLog, "accept tunnel failed, reason:%s", strerror(errno));
        goto end;
    }
    if (set_nonblock(tunfd) < 0)
    {
        goto err_1;
    }

    if (!(tun = new_tunnel(s, tunfd)))
    {
        LOG(WarnLog, "accpet tunnel failed, create tunnel error");
        goto err_1;
    }

    LOG(DebugLog, "step 1. accept tunnel");

    return;

err_1:
    if (tunfd >= 0)
        close(tunfd);

end:
    clear_thread_env();
}

static tunnel_t *new_tunnel(server_t *s, int fd)
{
    tunnel_t *tun = NULL;
    remote_t *r = NULL;

    tun = calloc(sizeof(*tun), 1);
    if (!tun)
    {
        LOG(WarnLog, "new tunnel failed, no enough memory");
        return NULL;
    }

    tun->fd = fd;
    tun->s = s;

    tun->timeout.tv_sec = TUN_TIMEOUT;
    tun->timeout.tv_usec = 0;
    event_assign(&tun->ev_read, s_global.evbase, fd, EV_READ|EV_PERSIST, tunnel_recv_cb, tun);
    event_assign(&tun->ev_write, s_global.evbase, fd, EV_WRITE|EV_PERSIST, tunnel_send_cb, tun);

    set_logenv(tun);

    r = new_remote(tun);
    if (!r)
    {
        LOG(WarnLog, "create remote failed");
        goto err_1;
    }
    tun->r = r;

    return tun;

err_1:
    if (tun)
        free(tun);

    return NULL;
}

static void free_tunnel(tunnel_t *tun)
{
    if (tun)
    {
        LOG(DebugLog, "free tunnel");

        event_del(&tun->ev_read);
        event_del(&tun->ev_write);
        close(tun->fd);

        free(tun);
    }
}

static int decode_buffer(remote_t *r, server_t *s)
{
    int n, offset;

    n = s->decode_handler(r->encbuf, r->recvptr - r->encbuf, r->buf, sizeof(r->buf), &offset);
    if (n <= 0)
    {
        if (-Proto_Again == n)
        {
            return -Proto_Again;
        }

        LOG(WarnLog, "decode data failed, reason:%s", proto_strerror(n));
        return n;
    }

    assert(offset <= r->recvptr - r->encbuf && "offset <= r->recvptr - r->encbuf");
    if (offset < r->recvptr - r->encbuf)
    {
        memmove(r->encbuf, r->encbuf + offset, r->recvptr - r->encbuf - offset);
    }
    r->recvptr -= offset;
    r->len = n;

    return r->len;
}

static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    tunnel_t *tun = (tunnel_t *)arg;
    remote_t *r = tun->r;
    server_t *s = tun->s;
    int n, len;

    assert(r && "tunnel_recv_cb: remote != NULL");
    assert(r->connected && "tunnel_recv_cb: remote is connected");

    set_logenv(tun);

    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "connection with tunnel timeout");
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    /* recv from tunnel */
again_1:
    assert((!r->sendptr || r->sendptr == r->buf) && "tunnel_recv_cb: has data to send to remote");
    if (!r->recvptr)
        r->recvptr = r->encbuf;
    n = recv(tun->fd, r->recvptr, r->encbuf + sizeof(r->encbuf) - r->recvptr, 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_1;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(InfoLog, "read from tunnel error, %s", strerror(errno));
            free_remote(r);
            free_tunnel(tun);
            goto end;
        }

        goto end;
    }
    if (n == 0)
    {
        LOG(DebugLog, "connection with tunnel closed");
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    /* decode */
    r->recvptr += n;
decode:
    if ((n = decode_buffer(r, s)) <= 0)
    {
        if (n != -Proto_Again)
        {
            free_remote(r);
            free_tunnel(tun);
        }

        goto end;
    }

    /* translate data to remote */
again_2:
    len = r->len;
    n = send(r->fd, r->buf, len, 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_2;
        }
        else if (EAGAIN == errno || EWOULDBLOCK == errno)
        {
            /* send buffer is full */
            event_del(&tun->ev_read);
            event_add(&r->ev_write, NULL);

            r->sendptr = r->buf;
            goto end;
        }

        LOG(WarnLog, "translate data to remote failed, %s", strerror(errno));
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    if (n != len)
    {
        event_del(&tun->ev_read);
        event_add(&r->ev_write, NULL);

        r->sendptr = r->buf + n;
        goto end;
    }

    r->len = 0;
    if (r->recvptr > r->encbuf)
    {
        goto decode;
    }
end:
    clear_thread_env();
}

static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg)
{
    tunnel_t *tun = (tunnel_t *)arg;
    remote_t *r = tun->r;
    int n, len;

    assert(event != EV_TIMEOUT && "tunnel_send_cb: event != EV_TIMEOUT");
    assert(r && "tunnel_send_cb: r != NULL");
    assert(tun->sendptr && "tunnel_send_cb: tun->sendptr != NULL");

    set_logenv(tun);

again:
    len = tun->encbuf + tun->len - tun->sendptr;
    n = send(tun->fd, tun->sendptr, len, 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again;
        }
        else if (EAGAIN == errno || EWOULDBLOCK == errno)
        {
            goto end;
        }

        LOG(WarnLog, "translate to tunnel failed(in callback), reason: %s", strerror(errno));
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    if (n != len)
    {
        tun->sendptr += n;
        goto end;
    }

    event_del(&tun->ev_write);
    event_add(&r->ev_read, &r->timeout);
    tun->sendptr = NULL;
    tun->len = 0;

end:
    clear_thread_env();
}

static remote_t *new_remote(tunnel_t *tun)
{
    server_t *s = tun->s;
    remote_t *r = NULL;

    r = calloc(sizeof(*r), 1);
    if (!r)
    {
        LOG(WarnLog, "new remote failed, no enough memory");
        return NULL;
    }

    r->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (r->fd < 0)
    {
        LOG(WarnLog, "create remote socket faild, reason:%s", strerror(errno));
        goto err_1;
    }
    if (set_nonblock(r->fd) < 0)
    {
        LOG(WarnLog, "create remote socket failed, set nonblock failed");
        goto err_2;
    }

    r->tun = tun;
    r->connected = FALSE;
    r->timeout.tv_sec = REMOTE_TIMEOUT;
    r->timeout.tv_usec = 0;

    event_assign(&r->ev_read, s_global.evbase, r->fd, EV_READ|EV_PERSIST, remote_recv_cb, r);
    event_assign(&r->ev_write, s_global.evbase, r->fd, EV_WRITE|EV_PERSIST, remote_send_cb, r);

    set_logenv(tun);

    /* connect remote server */
again:
    if (connect(r->fd, (struct sockaddr *)&s->addr.peer_inaddr, sizeof(s->addr.peer_inaddr)) < 0)
    {
        if (EINTR == errno)
        {
            goto again;
        }
        else if (EINPROGRESS == errno)
        {
            event_add(&r->ev_write, NULL);
        }
        else
        {
            LOG(ErrLog, "create remote error, connect failed, reason:%s", strerror(errno));
            goto err_2;
        }
    }
    else
    {
        event_add(&tun->ev_read, &tun->timeout);
        event_add(&r->ev_read, &r->timeout);
        r->connected = TRUE;
    }

    return r;

err_2:
    if (r->fd >= 0)
        close(r->fd);

err_1:
    if (r)
        free(r);

    return NULL;
}

static void free_remote(remote_t *r)
{
    if (r)
    {
        LOG(DebugLog, "free remote");

        event_del(&r->ev_read);
        event_del(&r->ev_write);
        close(r->fd);

        free(r);
    }
}

static void remote_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    remote_t *r = (remote_t *)arg;
    tunnel_t *tun = r->tun;
    server_t *s = tun->s;
    char buf[RECV_SIZE];
    int n, len;

    set_logenv(tun);

    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "connection with remote timeout");
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    /* recv data from remote */
again_1:
    n = recv(r->fd, buf, sizeof(buf), 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_1;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(WarnLog, "read from remote failed, %s", strerror(errno));
            free_remote(r);
            free_tunnel(tun);
            goto end;
        }

        goto end;
    }
    if (n == 0)
    {
        LOG(DebugLog, "connection with remote closed");
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    /* encode the data */
    assert((!tun->sendptr || tun->sendptr == tun->encbuf) && "remote_recv_cb: has data to send");
    n = s->encode_handler(buf, n, tun->encbuf, sizeof(tun->encbuf));
    if (n <= 0)
    {
        LOG(ErrLog, "encode error, reason:%s", proto_strerror(n));
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }
    tun->len = n;

    /* translate to tunnel */
again_2:
    len = tun->len;
    n = send(tun->fd, tun->encbuf, len, 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_2;
        }
        else if (EAGAIN == errno || EWOULDBLOCK == errno)
        {
            /* send buffer is full */
            event_del(&r->ev_read);
            event_add(&tun->ev_write, NULL);

            tun->sendptr = tun->encbuf;
            goto end;
        }

        LOG(WarnLog, "tranlate to tunnel error, %s", strerror(errno));
        free_remote(r);
        free_tunnel(tun);
        goto end;
    }

    if (n != len)
    {
        event_del(&r->ev_read);
        event_add(&tun->ev_write, NULL);

        tun->sendptr = tun->encbuf + n;
        goto end;
    }

    tun->len = 0;
end:
    clear_thread_env();
}

static void remote_send_cb(evutil_socket_t fd, short event, void *arg)
{
    remote_t *r = (remote_t *)arg;
    tunnel_t *tun = r->tun;
    server_t *s = tun->s;

    set_logenv(tun);

    if (r->connected)
    {
        int len, n;

        assert(r->sendptr && "remote_send_cb: r->sendptr != NULL");
  again:
        len = r->buf + r->len - r->sendptr;
        n = send(r->fd, r->sendptr, len, 0);
        if (n < 0)
        {
            if (EINTR == errno)
            {
                goto again;
            }
            else if (EAGAIN == errno || EWOULDBLOCK == errno)
            {
                goto end;
            }

            LOG(WarnLog, "translate data to remote error(in callback), reason:%s", strerror(errno));
            free_remote(r);
            free_tunnel(tun);
            goto end;
        }

        if (n != len)
        {
            r->sendptr += n;
            goto end;
        }

        /* has data left to decode */
        if (r->recvptr > r->encbuf)
        {
            if ((n = decode_buffer(r, s)) <= 0)
            {
                if (n != -Proto_Again)
                {
                    free_remote(r);
                    free_tunnel(tun);
                    goto end;
                }
            }
            else
            {
                r->sendptr = r->buf;
                goto again;
            }
        }

        event_del(&r->ev_write);
        event_add(&tun->ev_read, &tun->timeout);
        r->sendptr = NULL;
        r->len = 0;
    }
    else
    {
        int err = 0;
        socklen_t errlen = sizeof(int);

        if (EV_TIMEOUT == event)
        {
            LOG(InfoLog, "connect to %s:%d timeout, shutdown",
                s->addr.peer_addr.hostname, s->addr.peer_addr.port);
            free_remote(r);
            free_tunnel(tun);
            goto end;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
        {
            LOG(InfoLog, "connect to %s:%d error, reason:%s",
                s->addr.peer_addr.hostname, s->addr.peer_addr.port, strerror(err));
            free_remote(r);
            free_tunnel(tun);
            goto end;
        }

        r->connected = TRUE;
        event_del(&r->ev_write);
        event_add(&tun->ev_read, &tun->timeout);
        event_add(&r->ev_read, &r->timeout);

        LOG(DebugLog, "async connected to %s:%d",
            s->addr.peer_addr.hostname, s->addr.peer_addr.port);
    }

end:
    clear_thread_env();
}

static addr_info_t *parse_addr(int argc, char *argv[])
{
    int opt = 0;
    int listen_port = 0, peer_port = 0;
    const char *listen_addr = NULL, *peer_addr = NULL;
    const char *ptr = NULL;
    addr_info_t *addr;

    while ((opt = getopt(argc, argv, "l:r:p:")) != -1)
    {
        switch (opt)
        {
        case 'l':
            listen_addr = optarg;
            break;
        case 'r':
            peer_addr = optarg;
            break;
        case 'p':
            peer_port = atoi(optarg);
            break;
        }
    }

    addr = calloc(sizeof(addr_info_t), 1);
    assert(addr && "calloc addr failed, no enough memory");

    /* parse listen address */
    if (!listen_addr)
    {
        fprintf(stderr, "no listen address, use '-l' to assign it(like 0.0.0.0:8081 or 8081)\n");
        goto err;
    }
    if ((ptr = strchr(listen_addr, ':')))
    {
        listen_port = atoi(ptr + 1);
        if (ptr > listen_addr)
        {
            strncpy(addr->listen_addr.hostname, listen_addr,
                    MIN(ptr - listen_addr, sizeof(addr->listen_addr.hostname) - 1));
        }
    }
    else
    {
        listen_port = atoi(listen_addr);
    }
    if (!valid_port(listen_port))
    {
        fprintf(stderr, "invalid listen port\n");
        goto err;
    }
    addr->listen_addr.port = listen_port;

    /* parse peer address */
    if (!peer_addr)
    {
        fprintf(stderr, "no peer address, use '-r' to assign it\n");
        goto err;
    }
    if (!valid_port(peer_port))
    {
        fprintf(stderr, "invalid peer port, use '-p' to assign it\n");
        goto err;
    }
    snprintf(addr->peer_addr.hostname, sizeof(addr->peer_addr.hostname), "%s", peer_addr);
    addr->peer_addr.port = peer_port;

    return addr;

  err:
    if (addr)
        free(addr);
    return NULL;
}

int main(int argc, char *argv[])
{
    struct event evsig;
    addr_info_t *addr;
    server_t *s;
    int r;

    addr = parse_addr(argc, argv);
    if (!addr)
    {
        fprintf(stderr, "parse address failed, exit\n");
        exit(1);
    }

    aes_proto_init("123456");

    s_global.evbase = event_base_new();
    s_global.evdns = evdns_base_new(s_global.evbase, 0);

    evsignal_assign(&evsig, s_global.evbase, SIGPIPE, signal_cb, &evsig);
    evsignal_add(&evsig, NULL);

    r = evdns_base_resolv_conf_parse(s_global.evdns, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
    if (r < 0)
    {
        LOG(ErrLog, "Couldn't configure nameservers");
        goto err;
    }

    s = new_server(addr);
    if (!s)
    {
        LOG(ErrLog, "new server failed");
        goto err;
    }

    event_base_dispatch(s_global.evbase);

    free_server(s);

err:
    evdns_base_free(s_global.evdns, 0);
    event_base_free(s_global.evbase);

    exit(0);
}
