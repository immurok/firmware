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

/* 消息调度表 W[80] 曾在 sha1_transform 栈上（320B），是 TOTP 那条链 1024B
 * 栈的最大单块（M12）。改为调用方提供，指向 work_buf 的 OTP 分区。
 * sha1 全仓库只服务 TOTP（hmac_sha1→totp），totp_compute 入口设、出口清；
 * 见 docs/superpowers/specs/2026-09-20-otp-stack-workbuf.md 与 totp_core.c。 */
static uint32_t *s_sha1_w;
void sha1_set_w(uint32_t *w80) { s_sha1_w = w80; }

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t *block)
{
    uint32_t *W = s_sha1_w;   /* 必须已由 sha1_set_w 设好（TOTP 独占契约） */
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
    /* M12：内联补位，直接调 sha1_transform，不经 sha1_update —— 省掉最深
     * 那条链上 final→update→transform 的 update 层，长度也写进 ctx->buffer
     * 而非栈上 length[8]。sha1 只服务 TOTP，行为由 test_totp 的 KAT 守着。 */
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);

    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        while (index < SHA1_BLOCK_SIZE) ctx->buffer[index++] = 0;
        sha1_transform(ctx, ctx->buffer);
        index = 0;
    }
    while (index < 56) ctx->buffer[index++] = 0;
    for (int i = 0; i < 8; i++)
        ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_transform(ctx, ctx->buffer);

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
