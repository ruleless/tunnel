#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#define PADDING_SIZE 256
#define RECV_SIZE    2048
#define BUF_SIZE     (RECV_SIZE + PADDING_SIZE)

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

enum EProtoCode {
    Proto_Unknown = 1,
    Proto_DataErr,
    Proto_Again,
    Proto_NoSpace,
};

const char *proto_strerror(int code);

BOOL aes_proto_init(const char *key);

int fake_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);
int fake_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset);

int aes_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);
int aes_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset);

#ifdef __cplusplus
}
#endif

#endif /* __PROTOCOL_H__ */
