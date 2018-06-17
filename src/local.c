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
#include "thread_env.h"

#define DebugLog 1
#define InfoLog  2
#define WarnLog  3
#define ErrLog   4

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

#define BUF_SIZE  4096
#define RECV_SIZE 2048

#define BOOL  int
#define TRUE  1
#define FALSE 0

typedef struct global_s global_t;
typedef struct client_s client_t;
typedef struct local_s local_t;
typedef struct tunnel_s tunnel_t;

typedef int (*encode_handler_pt)(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);
typedef int (*decode_handler_pt)(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);

struct global_s
{
    struct event_base *s_evbase;
    struct evdns_base *s_evdns;
};

struct client_s
{
    int fd;    

    struct event ev_accept;

    encode_handler_pt encode_handler;
    decode_handler_pt decode_handler;
};

struct local_s
{
    int fd;

    client_t *client;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    char decbuf[BUF_SIZE];
    size_t len;
};

struct tunnel_s
{
    int fd;

    local_t *local;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    char encbuf[BUF_SIZE];
    size_t len;
};

static void accept_cb(evutil_socket_t fd, short event, void *arg);

static void signal_cb(evutil_socket_t fd, short event, void *arg);

static local_t *new_local(client_t *client, int fd);
static void free_local(local_t *local);
static void local_recv_cb(evutil_socket_t fd, short event, void *arg);
static void local_send_cb(evutil_socket_t fd, short event, void *arg);

static tunnel_t *new_tunnel(tunnel_t *tun, const struct sockaddr *addr, socklen_t addrlen);
static void free_tunnel(tunnel_t *tun);
static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg);
static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg);
