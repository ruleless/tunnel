#ifndef __UTIL_H__
#define __UTIL_H__

#define HOSTNAME_SIZE 256

#ifndef MIN
# define MIN(a, b) ((b) < (a) ? (b) : (a))
#endif
#ifndef MAX
# define MAX(a, b) ((b) > (a) ? (b) : (a))
#endif

#ifndef BOOL
# define BOOL int
#endif
#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hostname_s hostname_t;
struct hostname_s {
    char hostname[HOSTNAME_SIZE];
    int port;
};

int set_nonblock(int fd);

BOOL valid_port(int port);
BOOL valid_hostname(const char *h);

void daemonize(const char *path);

void print_stack_frames(void (*print)(const char *sym));

int aes_encrypt(const unsigned char *plaintext,
                int plaintext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext);

int aes_decrypt(const unsigned char *ciphertext,
                int ciphertext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* __UTIL_H__ */
