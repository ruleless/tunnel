#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "protocol.h"

#define FAKE_MAGIC 0x46454B45

typedef struct header_s header_t;

struct header_s
{
    int len;
    unsigned magic;
};

const char *proto_strerror(int code)
{
#define RETURN_ERR(r) if ((r == code) || (r == -code)) { return #r; }

    RETURN_ERR(Proto_Success);
    RETURN_ERR(Proto_Unknown);
    RETURN_ERR(Proto_Again);
    RETURN_ERR(Proto_NoSpace);

    return "unknown";

#undef RETURN_ERR
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
