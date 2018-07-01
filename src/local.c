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

#define TUN_TIMEOUT   60
#define LOCAL_TIMEOUT 60
#define NOBODY_UID    99

#define ENV_LOCAL   "LOCAL"
#define ENV_TUN     "TUNNEL"
#define ENV_LOCALFD "localfd"
#define ENV_TUNFD   "tunfd"

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
typedef struct client_s client_t;
typedef struct addr_info_s addr_info_t;
typedef struct local_s local_t;
typedef struct tunnel_s tunnel_t;

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

struct client_s
{
    int fd;

    struct event ev_accept;

    addr_info_t addr;

    encode_handler_pt encode_handler;
    decode_handler_pt decode_handler;
};

struct local_s
{
    int fd;

    client_t *c;

    tunnel_t *tun;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    char encbuf[BUF_SIZE];
    char *recvptr;

    char buf[RECV_SIZE];
    char padding[PADDING_SIZE]; /* prevent from overflow when decoding */
    char *sendptr;
    size_t len;
};

struct tunnel_s
{
    int fd;

    local_t *l;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    BOOL connected;

    char encbuf[BUF_SIZE];
    char *sendptr;
    size_t len;
};

static global_t s_global;

static void signal_cb(evutil_socket_t fd, short event, void *arg);

static int decode_buffer(local_t *l, client_t *c);

static client_t *new_client(addr_info_t *addr);
static void free_client(client_t *c);
static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg);
static void accept_cb(evutil_socket_t fd, short event, void *arg);

static local_t *new_local(client_t *c, int fd);
static void free_local(local_t *l);
static void local_recv_cb(evutil_socket_t fd, short event, void *arg);
static void local_send_cb(evutil_socket_t fd, short event, void *arg);

static tunnel_t *new_tunnel(local_t *l);
static void free_tunnel(tunnel_t *tun);
static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg);
static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg);


static void get_logenv(char *env, size_t len)
{
    char *ptr = env + 1, *end_ptr = env + len;

    SNPRINTF(ENV_LOCAL);
    SNPRINTF(ENV_TUN);
    SNPRINTF(ENV_LOCALFD);
    SNPRINTF(ENV_TUNFD);
    if (ptr > env + 1)
    {
        *env = '<';
        *(ptr - 1) = '>';
    }
}

static void set_logenv(const local_t *l)
{
    char str_local[32], str_tun[32], localfd[8], tunfd[8];

    snprintf(str_local, sizeof(str_local), "%p", l);
    snprintf(str_tun, sizeof(str_tun), "%p", l->tun);
    snprintf(localfd, sizeof(localfd), "%d", l->fd);

    if (l->tun)
        snprintf(tunfd, sizeof(tunfd), "%d", l->tun->fd);
    else
        snprintf(tunfd, sizeof(tunfd), "-1");

    set_thread_env(ENV_LOCAL, str_local);
    set_thread_env(ENV_TUN, str_tun);
    set_thread_env(ENV_LOCALFD, localfd);
    set_thread_env(ENV_TUNFD, tunfd);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *signal = arg;

    LOG(InfoLog, "signal_cb: got signal %d", event_get_signal(signal));
}

static client_t *new_client(addr_info_t *addr)
{
    client_t *c = NULL;
    struct evutil_addrinfo hints;
    int fd = -1;
    int opt;

    c = (client_t *)calloc(sizeof(client_t), 1);
    if (!c)
    {
        LOG(ErrLog, "new client failed, no enough memory");
        goto err_1;
    }
    memcpy(&c->addr, addr, sizeof(c->addr));
    c->encode_handler = aes_encode;
    c->decode_handler = aes_decode;

    /* create socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG(WarnLog, "create client failed, reason:%s", strerror(errno));
        goto err_1;
    }
    if (set_nonblock(fd) < 0)
    {
        LOG(WarnLog, "create client failed, reason:%s", strerror(errno));
        goto err_2;
    }

    opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* bind address */
    c->addr.listen_inaddr.sin_family =  AF_INET;
    c->addr.listen_inaddr.sin_port = htons(c->addr.listen_addr.port);
    if (*c->addr.listen_addr.hostname)
    {
        if (inet_pton(AF_INET, c->addr.listen_addr.hostname, &c->addr.listen_inaddr.sin_addr) < 0)
        {
            LOG(ErrLog, "create client failed, invalid listen address:%s", strerror(errno));
            goto err_2;
        }
    }
    else
    {
        c->addr.listen_inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(fd, (const struct sockaddr *)&c->addr.listen_inaddr, sizeof(c->addr.listen_inaddr)) < 0)
    {
        LOG(ErrLog, "create client failed, bind failed, reason:%s", strerror(errno));
        goto err_2;
    }
    if (listen(fd, 5) < 0)
    {
        LOG(ErrLog, "create client failed, listen failed, reason:%s", strerror(errno));
        goto err_2;
    }

    c->fd = fd;

    event_assign(&c->ev_accept, s_global.evbase, fd, EV_READ|EV_PERSIST, accept_cb, c);

    /* resolve peer hostname */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    evdns_getaddrinfo(s_global.evdns, c->addr.peer_addr.hostname, NULL, &hints, resolv_cb, c);

    return c;

err_2:
    if (fd >= 0)
        close(fd);
err_1:
    if (c)
        free(c);
    return NULL;
}

static void free_client(client_t *c)
{
    event_del(&c->ev_accept);
    free(c);
}

static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg)
{
    int i;
    client_t *c = (client_t *)arg;

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
            c->addr.peer_inaddr.sin_family = AF_INET;
            c->addr.peer_inaddr.sin_port = htons(c->addr.peer_addr.port);
            c->addr.peer_inaddr.sin_addr.s_addr = sin->sin_addr.s_addr;

            event_add(&c->ev_accept, NULL);

            LOG(DebugLog, "reolve %s -> %s, we can accept client now",
                c->addr.peer_addr.hostname, buf);

            return;
        }
    }

err_1:
    LOG(DebugLog, "resolve '%s' failed, now exit, reason:%s",
        c->addr.peer_addr.hostname, evutil_gai_strerror(err));
    event_base_loopexit(s_global.evbase, NULL);
}

static void accept_cb(evutil_socket_t fd, short event, void *arg)
{
    client_t *c = (client_t *)arg;
    int clifd = accept(c->fd, NULL, NULL);
    local_t *l = NULL;

    if (clifd < 0)
    {
        LOG(WarnLog, "accept client failed, reason:%s", strerror(errno));
        goto end;
    }
    if (set_nonblock(clifd) < 0)
    {
        goto err_1;
    }

    if (!(l = new_local(c, clifd)))
    {
        LOG(WarnLog, "accpet client failed, create local error");
        goto err_1;
    }

    LOG(DebugLog, "step 1. accept client");

    return;

err_1:
    if (clifd >= 0)
        close(clifd);

end:
    clear_thread_env();
}

static local_t *new_local(client_t *c, int fd)
{
    local_t *l = NULL;
    tunnel_t *tun = NULL;

    l = calloc(sizeof(local_t), 1);
    if (!l)
    {
        LOG(WarnLog, "new local failed, no enough memory");
        return NULL;
    }

    l->fd = fd;
    l->c = c;

    l->timeout.tv_sec = LOCAL_TIMEOUT;
    l->timeout.tv_usec = 0;
    event_assign(&l->ev_read, s_global.evbase, fd, EV_READ|EV_PERSIST, local_recv_cb, l);
    event_assign(&l->ev_write, s_global.evbase, fd, EV_WRITE|EV_PERSIST, local_send_cb, l);

    set_logenv(l);

    tun = new_tunnel(l);
    if (!tun)
    {
        LOG(WarnLog, "create tunnel failed");
        goto err_1;
    }
    l->tun = tun;

    return l;

err_1:
    if (l)
        free(l);

    return NULL;
}

static void free_local(local_t *l)
{
    if (l)
    {
        LOG(DebugLog, "free local");

        event_del(&l->ev_read);
        event_del(&l->ev_write);
        close(l->fd);

        free(l);
    }
}

static void local_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    local_t *l = (local_t *)arg;
    tunnel_t *tun = l->tun;
    client_t *c = l->c;
    char buf[RECV_SIZE];
    int len;
    int n, r;

    assert(tun && "local_recv_cb: tun != NULL");
    assert(tun->connected && "local_recv_cb: tunnel is connected");

    set_logenv(l);

    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "connection with client timeout");
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    /* recv from client */
again_1:
    n = recv(l->fd, buf, sizeof(buf), 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_1;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(WarnLog, "read from client failed, %s", strerror(errno));
            free_tunnel(tun);
            free_local(l);
            goto end;
        }

        goto end;
    }
    if (n == 0)
    {
        LOG(DebugLog, "connection with client closed");
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    /* encode the data */
    assert((!tun->sendptr || tun->sendptr == tun->encbuf) && "local_recv_cb: has data to send");
    r = c->encode_handler(buf, n, tun->encbuf, sizeof(tun->encbuf));
    if (r <= 0)
    {
        LOG(ErrLog, "encode error, reason:%s", proto_strerror(r));
        free_tunnel(tun);
        free_local(l);
        goto end;
    }
    tun->len = r;

    /* translate to server */
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
            event_del(&l->ev_read);
            event_add(&tun->ev_write, NULL);

            tun->sendptr = tun->encbuf;
            goto end;
        }

        LOG(WarnLog, "tranlate to server error, %s", strerror(errno));
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    if (n != len)
    {
        event_del(&l->ev_read);
        event_add(&tun->ev_write, NULL);

        tun->sendptr = tun->encbuf + n;
        goto end;
    }

    tun->len = 0;
end:
    clear_thread_env();
}

static void local_send_cb(evutil_socket_t fd, short event, void *arg)
{
    local_t *l = (local_t *)arg;
    tunnel_t *tun = l->tun;
    client_t *c = l->c;
    int n, len;

    assert(event != EV_TIMEOUT && "local_send_cb: event != EV_TIMEOUT");
    assert(tun && "local_send_cb: tun != NULL");
    assert(l->sendptr && "local_send_cb: l->sendptr != NULL");

    set_logenv(l);

again:
    len = l->buf + l->len - l->sendptr;
    n = send(l->fd, l->sendptr, len, 0);
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

        LOG(WarnLog, "translate data to client error(in callback), reason:%s", strerror(errno));
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    if (n != len)
    {
        l->sendptr += n;
        goto end;
    }

    /* has data left to decode */
    if (l->recvptr > l->encbuf)
    {
        if ((n = decode_buffer(l, c)) <= 0)
        {
            if (n != -Proto_Again)
            {
                free_tunnel(tun);
                free_local(l);
                goto end;
            }
        }
        else
        {
            l->sendptr = l->buf;
            goto again;
        }
    }

    event_del(&l->ev_write);
    event_add(&tun->ev_read, &tun->timeout);
    l->sendptr = NULL;
    l->len = 0;

end:
    clear_thread_env();
}

static tunnel_t *new_tunnel(local_t *l)
{
    client_t *c = l->c;
    tunnel_t *tun = NULL;

    tun = calloc(sizeof(tunnel_t), 1);
    if (!tun)
    {
        LOG(WarnLog, "new tunnel failed, no enough memory");
        return NULL;
    }

    tun->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (l->fd < 0)
    {
        LOG(WarnLog, "create tunnel socket faild, reason:%s", strerror(errno));
        goto err_1;
    }
    if (set_nonblock(tun->fd) < 0)
    {
        LOG(WarnLog, "create tunnel socket failed, set nonblock failed");
        goto err_2;
    }

    tun->l = l;
    tun->connected = FALSE;
    tun->timeout.tv_sec = TUN_TIMEOUT;
    tun->timeout.tv_usec = 0;

    event_assign(&tun->ev_read, s_global.evbase, tun->fd, EV_READ|EV_PERSIST, tunnel_recv_cb, tun);
    event_assign(&tun->ev_write, s_global.evbase, tun->fd, EV_WRITE|EV_PERSIST, tunnel_send_cb, tun);

    set_logenv(l);

    /* connect tunnel server */
again:
    if (connect(tun->fd, (struct sockaddr *)&c->addr.peer_inaddr, sizeof(c->addr.peer_inaddr)) < 0)
    {
        if (EINTR == errno)
        {
            goto again;
        }
        else if (EINPROGRESS == errno)
        {
            event_add(&tun->ev_write, NULL);
        }
        else
        {
            LOG(ErrLog, "create tunnel error, connect failed, reason:%s", strerror(errno));
            goto err_2;
        }
    }
    else
    {
        event_add(&l->ev_read, &l->timeout);
        event_add(&tun->ev_read, &tun->timeout);
        tun->connected = TRUE;
    }

    return tun;

err_2:
    if (tun->fd >= 0)
        close(tun->fd);

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

static int decode_buffer(local_t *l, client_t *c)
{
    int n, offset;

    n = c->decode_handler(l->encbuf, l->recvptr - l->encbuf, l->buf, sizeof(l->buf), &offset);
    if (n <= 0)
    {
        if (-Proto_Again == n)
        {
            return -Proto_Again;
        }

        LOG(WarnLog, "decode data failed, reason:%s", proto_strerror(n));
        return n;
    }

    assert(offset <= l->recvptr - l->encbuf && "offset <= l->recvptr - l->encbuf");
    if (offset < l->recvptr - l->encbuf)
    {
        memmove(l->encbuf, l->encbuf + offset, l->recvptr - l->encbuf - offset);
    }
    l->recvptr -= offset;
    l->len = n;

    return l->len;
}

static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    tunnel_t *tun = (tunnel_t *)arg;
    local_t *l = tun->l;
    client_t *c = l->c;
    int n, len;

    set_logenv(l);

    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "connection with server timeout");
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    /* recv data from server */
again_1:
    assert((!l->sendptr || l->sendptr == l->buf) && "tunnel_recv_cb: has data to send to client");
    if (!l->recvptr)
        l->recvptr = l->encbuf;
    n = recv(tun->fd, l->recvptr, l->encbuf + sizeof(l->encbuf) - l->recvptr, 0);
    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_1;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(InfoLog, "read from server error, %s", strerror(errno));
            free_tunnel(tun);
            free_local(l);
            goto end;
        }

        goto end;
    }
    if (n == 0)
    {
        LOG(DebugLog, "connection with server closed");
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    /* decode */
    l->recvptr += n;
decode:
    if ((n = decode_buffer(l, c)) <= 0)
    {
        if (n != -Proto_Again)
        {
            free_tunnel(tun);
            free_local(l);
        }

        goto end;
    }

    /* translate data to client */
again_2:
    len = l->len;
    n = send(l->fd, l->buf, len, 0);
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
            event_add(&l->ev_write, NULL);

            LOG(InfoLog, "l->recvptr - l->encbuf=%d len=%d", (int)(l->recvptr - l->encbuf), (int)l->len);

            l->sendptr = l->buf;
            goto end;
        }

        LOG(WarnLog, "translate data to client failed, %s", strerror(errno));
        free_tunnel(tun);
        free_local(l);
        goto end;
    }

    if (n != len)
    {
        event_del(&tun->ev_read);
        event_add(&l->ev_write, NULL);

        LOG(InfoLog, "l->recvptr - l->encbuf=%d len=%d", (int)(l->recvptr - l->encbuf), (int)l->len);
        l->sendptr = l->buf + n;
        goto end;
    }

    l->len = 0;
    if (l->recvptr > l->encbuf)
    {
        goto decode;
    }
end:
    clear_thread_env();
}

static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg)
{
    tunnel_t *tun = (tunnel_t *)arg;
    local_t *l = tun->l;
    client_t *c = l->c;

    set_logenv(l);

    if (tun->connected)
    {
        int len, n;

        assert(tun->sendptr && "tunnel_send_cb: tun->sendptr != NULL");
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

            LOG(WarnLog, "translate to server failed(in callback), reason: %s", strerror(errno));
            free_tunnel(tun);
            free_local(l);
            goto end;
        }

        if (n != len)
        {
            tun->sendptr += n;
            goto end;
        }

        event_del(&tun->ev_write);
        event_add(&l->ev_read, &l->timeout);
        tun->sendptr = NULL;
        tun->len = 0;
    }
    else
    {
        int err = 0;
        socklen_t errlen = sizeof(int);

        if (EV_TIMEOUT == event)
        {
            LOG(InfoLog, "connect to %s:%d timeout, shutdown",
                c->addr.peer_addr.hostname, c->addr.peer_addr.port);
            free_tunnel(tun);
            free_local(l);
            goto end;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
        {
            LOG(InfoLog, "connect to %s:%d error, reason:%s",
                c->addr.peer_addr.hostname, c->addr.peer_addr.port, strerror(err));
            free_tunnel(tun);
            free_local(l);
            goto end;
        }

        tun->connected = TRUE;
        event_del(&tun->ev_write);
        event_add(&l->ev_read, &l->timeout);
        event_add(&tun->ev_read, &tun->timeout);

        LOG(DebugLog, "async connected to %s:%d",
            c->addr.peer_addr.hostname, c->addr.peer_addr.port);
    }

end:
    clear_thread_env();
}

static addr_info_t *parse_arg(int argc, char *argv[])
{
    int opt = 0;
    int listen_port = 0, peer_port = 0;
    const char *listen_addr = NULL, *peer_addr = NULL;
    const char *ptr = NULL;
    addr_info_t *addr;

    while ((opt = getopt(argc, argv, "l:r:p:f:")) != -1)
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
        case 'f':
            daemonize(optarg);
            setgid(NOBODY_UID);
            setuid(NOBODY_UID);
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
    client_t *c;
    int r;

    addr = parse_arg(argc, argv);
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
        exit(1);
    }

    c = new_client(addr);
    if (!c)
    {
        LOG(ErrLog, "new client failed");
        exit(1);
    }

    event_base_dispatch(s_global.evbase);

    free_client(c);

    evdns_base_free(s_global.evdns, 0);
    event_base_free(s_global.evbase);

    exit(0);
}
