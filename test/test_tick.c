/*
 * H1（2026-09-19 审计）：tick→ms 换算的 uint32 溢出。
 *
 * 旧写法 (ticks * 625) / 1000 在 ticks >= 6,871,948（约 71.6 分钟）时乘积回绕，
 * 结果落回 0..10000，指纹门把陈旧冷却当成新鲜的放行。这里锁定新换算函数：
 * 对全部 uint32 输入都精确（floor(ticks*5/8)）且永不回绕。
 */
#include "immurok_tick.h"
#include "test_main.h"

static void test_small_values_exact(void)
{
    CHECK(immurok_ticks_to_ms(0) == 0, "0 tick = 0 ms");
    CHECK(immurok_ticks_to_ms(1) == 0, "1 tick = 0.625 ms -> 0");
    CHECK(immurok_ticks_to_ms(7) == 4, "7 tick = 4.375 ms -> 4");
    CHECK(immurok_ticks_to_ms(8) == 5, "8 tick = 5 ms");
    CHECK(immurok_ticks_to_ms(1600) == 1000, "1600 tick = 1 s");
    CHECK(immurok_ticks_to_ms(16000) == 10000, "16000 tick = 10 s (gate cooldown)");
    CHECK(immurok_ticks_to_ms(48000) == 30000, "48000 tick = 30 s");
}

/* 旧算式在这个点回绕：6871964*625 mod 2^32 = 10204 -> 10 ms。
 * 新算式必须给出真实值 4294977 ms（约 71.6 分钟），远大于 10 s 冷却。 */
static void test_no_wrap_at_71_minutes(void)
{
    uint32_t t = 6871948u + 16u;
    uint32_t old_formula = (t * 625u) / 1000u;   /* 复现旧 bug 的数值 */
    CHECK(old_formula < 10000u, "old formula really wraps here (test premise)");
    CHECK(immurok_ticks_to_ms(t) == 4294977u, "new formula: exact, no wrap");
    CHECK(immurok_ticks_to_ms(t) > 10000u, "new formula: gate sees expired cooldown");
}

static void test_full_range(void)
{
    /* floor(4294967295 * 5 / 8) = 2684354559 */
    CHECK(immurok_ticks_to_ms(0xFFFFFFFFu) == 2684354559u, "max uint32 exact");
    /* 逐段抽样与 64 位参考值比对 */
    int bad = 0;
    for (uint64_t t = 0; t <= 0xFFFFFFFFull; t += 0x01234567ull) {
        uint32_t ref = (uint32_t)((t * 5ull) / 8ull);
        if (immurok_ticks_to_ms((uint32_t)t) != ref) bad++;
    }
    CHECK(bad == 0, "matches 64-bit reference across the range");
}

int main(void)
{
    RUN(test_small_values_exact);
    RUN(test_no_wrap_at_71_minutes);
    RUN(test_full_range);
    TEST_MAIN_END;
}
