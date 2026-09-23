/*
 * H4（2026-09-19 审计）：uECC 的随机源原来只有 tmos_rand()（种子 SysTick，
 * 开机几乎相同）。换成 SHA-256 池式 DRBG：硬件侧把 tmos_rand、时钟抖动、ADC
 * 噪声、RTC/SysTick、MAC 混进池；这里只测生成器本身的性质：
 *   - 没播种就拒绝出数（fail closed：uECC_make_key 会失败而不是用零）
 *   - 播种后输出非退化、连续两次不同（计数器）
 *   - 同样的播种序列 → 同样的输出（可复现，说明输出完全由池决定）
 *   - 不同播种 / 追加播种 → 输出改变（池真的吸收了输入）
 *   - 任意长度（非 32 倍数）都填满
 */
#include "immurok_rng.h"
#include "test_main.h"
#include <string.h>

static int all_same(const uint8_t *p, unsigned n)
{
    for (unsigned i = 1; i < n; i++) if (p[i] != p[0]) return 0;
    return 1;
}

static void test_unseeded_refuses(void)
{
    uint8_t out[32]; memset(out, 0xEE, 32);
    immurok_rng_reset_for_test();
    CHECK(immurok_rng_fill(out, 32) == 0, "fill before any seed -> 0 (failure)");
    CHECK(all_same(out, 32) && out[0] == 0xEE, "dest untouched when refused");
}

static void test_seeded_output_nondegenerate(void)
{
    uint8_t a[32], b[32];
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    CHECK(immurok_rng_fill(a, 32) == 1, "fill after seed -> 1");
    CHECK(!all_same(a, 32), "output is not a constant byte");
    CHECK(immurok_rng_fill(b, 32) == 1, "second fill");
    CHECK(memcmp(a, b, 32) != 0, "consecutive fills differ");
}

static void test_reproducible_from_same_seed(void)
{
    uint8_t a[64], b[64];
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    immurok_rng_add((const uint8_t *)"\x01\x02\x03", 3);
    CHECK(immurok_rng_fill(a, 64) == 1, "fill A");
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    immurok_rng_add((const uint8_t *)"\x01\x02\x03", 3);
    CHECK(immurok_rng_fill(b, 64) == 1, "fill B");
    CHECK(memcmp(a, b, 64) == 0, "same seeds -> same stream (output is a pure function of the pool)");
}

static void test_seed_changes_output(void)
{
    uint8_t a[32], b[32], c[32];
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    immurok_rng_fill(a, 32);
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-B", 6);
    immurok_rng_fill(b, 32);
    CHECK(memcmp(a, b, 32) != 0, "different seed -> different output");
    /* 追加播种要影响后续输出 */
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    immurok_rng_add((const uint8_t *)"more", 4);
    immurok_rng_fill(c, 32);
    CHECK(memcmp(a, c, 32) != 0, "extra seed material changes output");
}

static void test_fill_arbitrary_length(void)
{
    uint8_t out[100]; memset(out, 0, 100);
    immurok_rng_reset_for_test();
    immurok_rng_add((const uint8_t *)"seed-A", 6);
    CHECK(immurok_rng_fill(out, 100) == 1, "fill 100 bytes");
    CHECK(!(out[96] == 0 && out[97] == 0 && out[98] == 0 && out[99] == 0), "tail block written");
    CHECK(memcmp(out, out + 96, 4) != 0, "tail is not a copy of the head");
    uint8_t one[1] = {0};
    CHECK(immurok_rng_fill(one, 1) == 1, "fill 1 byte");
    CHECK(immurok_rng_fill(one, 0) == 1, "fill 0 bytes is a no-op success");
}

int main(void)
{
    RUN(test_unseeded_refuses);
    RUN(test_seeded_output_nondegenerate);
    RUN(test_reproducible_from_same_seed);
    RUN(test_seed_changes_output);
    RUN(test_fill_arbitrary_length);
    TEST_MAIN_END;
}
