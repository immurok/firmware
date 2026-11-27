/*
 * ECC 标量乘搬进 RAM 执行前的判定（纯函数，主机可测：test/test_ecc_ram_policy.c）。
 *
 * 背景：CH592 从 Flash 取指很慢，P-256 标量乘在 Flash 上约 2 s，搬进 RAM 执行约 0.37 s
 * （2026-11-26 真机实测）。RAM 没有常驻空间，做法是运算前把热点代码拷进
 * immurok_keystore_work_buf 的低端，算完即弃（见 immurok_ecc_fast.c）。
 *
 * 这样做有两个会让固件跑飞的前提，都在这里把关，不成立就退回「留在 Flash 上跑」：
 *   1. 链接器给出的热点代码范围是合理的，要跳进去的两个入口都在范围内
 *      （ecc_ram_layout_check）。
 *   2. 搬进去之后，栈往下长不会碰到代码（ecc_ram_stack_ok）。work_buf 的高端本来就是
 *      栈溢出缓冲带，代码占了低端，留给栈的就只剩中间那一截。
 *
 * work_buf 里的布局（低 → 高）：
 *   [代码][曲线表副本 + 借给调用方的临时空间][保护带] …… 栈从上面往下长
 */
#ifndef ECC_RAM_POLICY_H
#define ECC_RAM_POLICY_H

#include <stdint.h>

typedef struct {
    uintptr_t start;   /* 热点代码范围 [start, end)，链接脚本的 _ecc_hot_start / _ecc_hot_end */
    uintptr_t end;
    uintptr_t mult;    /* EccPoint_mult：搬过去之后从这里进入 */
    uintptr_t mmod;    /* 曲线表里的 mmod_fast：副本里要改指到 RAM */
} ecc_ram_layout_t;

enum {
    ECC_RAM_OK = 0,
    ECC_RAM_BAD_RANGE,       /* 范围为空或倒置 */
    ECC_RAM_TOO_BIG,         /* 代码超过上限 */
    ECC_RAM_ENTRY_OUTSIDE,   /* 入口不在范围内：跳过去执行的会是没搬的东西 */
};

static inline uint32_t ecc_ram_code_size(const ecc_ram_layout_t *l)
{
    return (uint32_t)(l->end - l->start);
}

static inline uint8_t ecc_ram_layout_check(const ecc_ram_layout_t *l, uint32_t max_code)
{
    if (l->end <= l->start)
        return ECC_RAM_BAD_RANGE;
    if (ecc_ram_code_size(l) > max_code)
        return ECC_RAM_TOO_BIG;
    if (l->mult < l->start || l->mult >= l->end || l->mmod < l->start || l->mmod >= l->end)
        return ECC_RAM_ENTRY_OUTSIDE;
    return ECC_RAM_OK;
}

/* 数据区（曲线表副本等）在 work_buf 里的偏移：紧跟代码，向上取 4 对齐。 */
static inline uint32_t ecc_ram_data_offset(const ecc_ram_layout_t *l)
{
    return (ecc_ram_code_size(l) + 3u) & ~3u;
}

/* 代码 + 数据区一共占 work_buf 低端多少字节。 */
static inline uint32_t ecc_ram_extent(const ecc_ram_layout_t *l, uint32_t data_len)
{
    return ecc_ram_data_offset(l) + data_len;
}

/* 当前栈指针到「占用区顶 + 保护带」之间还剩多少字节可用。 */
static inline uint32_t ecc_ram_stack_room(uintptr_t sp, uintptr_t work_base, uint32_t extent,
                                          uint32_t guard)
{
    /* 不做 work_base + extent + guard 这样的加法：32 位上 extent 很大时和会绕回去，
       反而算出一大截「余量」。只做减法和比较。 */
    uintptr_t above;   /* sp 比 work_buf 起点高出多少 */
    if (sp <= work_base)
        return 0;
    above = sp - work_base;
    if (extent >= above || guard >= above - extent)
        return 0;
    return (uint32_t)(above - extent - guard);
}

/* 标量乘还要往下用 need 字节（调用链 + 中断余量），够不够。 */
static inline int ecc_ram_stack_ok(uintptr_t sp, uintptr_t work_base, uint32_t extent,
                                   uint32_t guard, uint32_t need)
{
    return ecc_ram_stack_room(sp, work_base, extent, guard) >= need;
}

#endif /* ECC_RAM_POLICY_H */
