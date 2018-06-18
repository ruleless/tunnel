#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "protocol.h"

const char *proto_strerror(int code)
{
#define RETURN_ERR(r) if (r == code) { return #r; }

    RETURN_ERR(Proto_Success);
    RETURN_ERR(Proto_Unknown);
    RETURN_ERR(Proto_Again);
    RETURN_ERR(Proto_NoSpace);

    return "unknown";

#undef RETURN_ERR
}

int fake_encode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(outlen >= inlen && "outlen >= inlen");

    memcpy(outbuf, inbuf, inlen);
    return inlen;
}

int fake_decode(const char *inbuf, size_t inlen, char *outbuf, size_t outlen, int *offset)
{
    assert(inbuf && outbuf && "inbuf && outbuf");
    assert(outlen >= inlen && "outlen >= inlen");
    assert(offset && "offset != NULL");

    memcpy(outbuf, inbuf, inlen);
    *offset = inlen;
    return inlen;
}
