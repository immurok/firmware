/*
 * SHA-1 Implementation
 * Public domain implementation based on FIPS 180-1
 */

#include "sha1.h"
#include <string.h>

// Initial hash values
static const uint32_t H0[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

// Rotate left
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t *block)
{
    uint32_t W[80];
    uint32_t a, b, c, d, e;
    uint32_t temp;
    int i;

    // Prepare message schedule
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        W[i] = ROTL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            temp = ROTL(a, 5) + ((b & c) ^ (~b & d)) + e + W[i] + 0x5A827999;
        } else if (i < 40) {
            temp = ROTL(a, 5) + (b ^ c ^ d) + e + W[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = ROTL(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + W[i] + 0x8F1BBCDC;
        } else {
            temp = ROTL(a, 5) + (b ^ c ^ d) + e + W[i] + 0xCA62C1D6;
        }
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(sha1_ctx_t *ctx)
{
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->count = 0;
}

void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = SHA1_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        sha1_transform(ctx, ctx->buffer);
        data += left;
        len -= left;
    }

    while (len >= SHA1_BLOCK_SIZE) {
        sha1_transform(ctx, data);
        data += SHA1_BLOCK_SIZE;
        len -= SHA1_BLOCK_SIZE;
    }

    if (len) {
        memcpy(ctx->buffer, data, len);
    }
}

void sha1_final(sha1_ctx_t *ctx, uint8_t *digest)
{
    uint64_t bits = ctx->count * 8;

    // Padding
    sha1_update(ctx, (const uint8_t *)"\x80", 1);

    while ((ctx->count & 0x3F) != 56) {
        uint8_t zero = 0;
        sha1_update(ctx, &zero, 1);
    }

    // Append length (big-endian)
    uint8_t length[8];
    length[0] = (uint8_t)(bits >> 56);
    length[1] = (uint8_t)(bits >> 48);
    length[2] = (uint8_t)(bits >> 40);
    length[3] = (uint8_t)(bits >> 32);
    length[4] = (uint8_t)(bits >> 24);
    length[5] = (uint8_t)(bits >> 16);
    length[6] = (uint8_t)(bits >> 8);
    length[7] = (uint8_t)(bits);
    sha1_update(ctx, length, 8);

    // Output digest (big-endian)
    for (int i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void sha1(const uint8_t *data, size_t len, uint8_t *digest)
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}
