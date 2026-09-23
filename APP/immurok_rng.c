/*
 * SHA-256 池式 DRBG。设计说明见 immurok_rng.h。
 * 不引 SDK 头：主机测试直接编（test/test_rng.c）。
 */
#include "immurok_rng.h"
#include "sha256.h"
#include <string.h>

static uint8_t  s_pool[SHA256_DIGEST_SIZE];
static uint32_t s_ctr;
static uint8_t  s_seeded;

/* pool = SHA256(tag || pool || extra) */
static void pool_absorb(uint8_t tag, const uint8_t *extra, unsigned len)
{
    sha256_ctx_t *ctx = &sha256_scratch_ctx;
    sha256_init(ctx);
    sha256_update(ctx, &tag, 1);
    sha256_update(ctx, s_pool, sizeof s_pool);
    if (len) sha256_update(ctx, extra, len);
    sha256_final(ctx, s_pool);
}

void immurok_rng_add(const uint8_t *data, unsigned len)
{
    pool_absorb(0x00, data, len);
    s_seeded = 1;
}

int immurok_rng_fill(uint8_t *dest, unsigned size)
{
    if (!s_seeded) return 0;

    uint8_t blk[SHA256_DIGEST_SIZE];   /* 32B 栈：fill 在 uECC 内部是叶函数 */
    while (size) {
        sha256_ctx_t *ctx = &sha256_scratch_ctx;
        uint8_t tag = 0x01;
        sha256_init(ctx);
        sha256_update(ctx, &tag, 1);
        sha256_update(ctx, s_pool, sizeof s_pool);
        sha256_update(ctx, (const uint8_t *)&s_ctr, sizeof s_ctr);
        sha256_final(ctx, blk);
        s_ctr++;

        unsigned n = size < sizeof blk ? size : sizeof blk;
        memcpy(dest, blk, n);
        dest += n;
        size -= n;
    }
    memset(blk, 0, sizeof blk);

    /* 棘轮：发出去的块不能从之后的池状态倒推 */
    pool_absorb(0x02, NULL, 0);
    return 1;
}

#ifdef IMMUROK_HOST_TEST
void immurok_rng_reset_for_test(void)
{
    memset(s_pool, 0, sizeof s_pool);
    s_ctr = 0;
    s_seeded = 0;
}
#endif
