#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#ifdef __cplusplus
extern "C" {
#endif

enum EProtoCode
{
    Proto_Success = 0,

    Proto_Unknown,
    Proto_DataErr,
    Proto_Again,
    Proto_NoSpace,
};

const char *proto_strerror(int code);

int fake_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen);
int fake_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset);

#ifdef __cplusplus
}
#endif

#endif /* __PROTOCOL_H__ */
