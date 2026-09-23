/*
 * TMOS tick（625 µs）与毫秒的换算。
 *
 * 2026-09-19 审计 H1：hidkbd.c 里 (now - t0) * 625 / 1000 两侧都是 uint32，
 * tick 差值到 6,871,948（约 71.6 分钟）乘积就回绕，指纹门冷却把 71 分钟前
 * 的一次通过读成「10 秒内」，之后每 71.6 分钟有 10 秒免指纹窗口，并且一旦
 * 命中就被续成 rolling 冷却。同型算式全文件约 40 处。
 *
 * 625/1000 = 5/8。把 ticks 拆成 8q + r 后算 5q + floor(5r/8)：
 *   5q     <= 5 * 0x1FFFFFFF = 0x9FFFFFFB，不溢出
 *   5r/8   <= 4
 * 对每一个 uint32 输入都等于 floor(ticks * 5 / 8)，见 test/test_tick.c。
 * 不引 SDK 头，主机测试可直接编。
 */
#ifndef IMMUROK_TICK_H
#define IMMUROK_TICK_H

#include <stdint.h>

static inline uint32_t immurok_ticks_to_ms(uint32_t ticks)
{
    return (ticks >> 3) * 5u + (((ticks & 7u) * 5u) >> 3);
}

#endif /* IMMUROK_TICK_H */
