#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "protocol.h"

#define FAKE_MAGIC 0x46454B45
#define AES_MAGIC  0x4655434B

#define AES_KEY_BYTES 256
#define AES_IV_BYTES  128

typedef struct header_s header_t;

struct header_s
{
    int len;
    unsigned magic;
};

struct
{
    unsigned char iv[AES_IV_BYTES];
    unsigned char key[AES_KEY_BYTES];
} s_aes_ctx;

const char *proto_strerror(int code)
{
#define RETURN_ERR(r)                           \
    do {                                        \
        if ((r == code) || (r == -code)) {      \
            return #r;                          \
        }                                       \
    } while (0)

    RETURN_ERR(Proto_Unknown);
    RETURN_ERR(Proto_DataErr);
    RETURN_ERR(Proto_Again);
    RETURN_ERR(Proto_NoSpace);

    return "unknown";

#undef RETURN_ERR
}

BOOL aes_proto_init(const char *key)
{
    int i = 0;

    for (i = 0; i < sizeof(s_aes_ctx.iv); i++)
    {
        s_aes_ctx.iv[i] = ((314259 ^ i) * (i + 13) % 256);
    }
    snprintf((char *)s_aes_ctx.key, sizeof(s_aes_ctx.key), "%s", key);

    return TRUE;
}

int fake_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    header_t h;

    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(outlen >= inlen + sizeof(header_t) && "outlen >= inlen");

    h.len = inlen;
    h.magic = FAKE_MAGIC;

    memcpy(outbuf, &h, sizeof(h));
    memcpy(outbuf + sizeof(h), inbuf, inlen);
    return inlen + sizeof(h);
}

int fake_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset)
{
    header_t *h;

    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(offset && "offset != NULL");

    if (inlen < sizeof(*h))
    {
        return -Proto_Again;
    }
    h = (header_t *)inbuf;
    if (h->magic != FAKE_MAGIC)
    {
        return -Proto_DataErr;
    }
    if (inlen < h->len + sizeof(*h))
    {
        return -Proto_Again;
    }

    memcpy(outbuf, inbuf + sizeof(*h), h->len);
    *offset = sizeof(*h) + h->len;
    return h->len;
}

int aes_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    header_t h;
    int cipherlen = 0;

    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(outlen >= inlen + PADDING_SIZE && "outlen >= inlen + PADDING_SIZE");

    cipherlen = aes_encrypt((const unsigned char *)inbuf, inlen, s_aes_ctx.key, s_aes_ctx.iv,
                            (unsigned char *)outbuf + sizeof(h));
    if (cipherlen < 0)
    {
        return -Proto_DataErr;
    }
    assert(outlen >= cipherlen + sizeof(h) && "outlen >= cipherlen + sizeof(h)");

    h.magic = AES_MAGIC;
    h.len = cipherlen;
    memcpy(outbuf, &h, sizeof(h));
    return sizeof(h) + cipherlen;
}

int aes_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset)
{
    header_t *h;
    int plainlen = 0;

    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(offset && "offset != NULL");
    assert(outlen + PADDING_SIZE >= inlen && "outlen + PADDING_SIZE >= inlen");

    if (inlen < sizeof(*h))
    {
        return -Proto_Again;
    }
    h = (header_t *)inbuf;
    if (h->magic != AES_MAGIC)
    {
        return -Proto_DataErr;
    }
    if (inlen < h->len + sizeof(*h))
    {
        return -Proto_Again;
    }

    plainlen = aes_decrypt((const unsigned char *)inbuf + sizeof(*h), h->len, s_aes_ctx.key, s_aes_ctx.iv,
                           (unsigned char *)outbuf);
    if (plainlen < 0)
    {
        return -Proto_DataErr;
    }
    assert(outlen >= plainlen && "outlen >= plainlen");

    *offset = sizeof(*h) + h->len;
    return plainlen;
}
