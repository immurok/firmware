/*
 * ECC 标量乘搬进 RAM 执行前的两道判定（ecc_ram_policy.h）。
 *
 * 搬运的前提是热点代码范围合理、要跳进去的入口确实被搬了、搬进去之后栈够用。任何一条
 * 不成立都必须退回「留在 Flash 上跑」，不能赌——跳到没搬的地方是跑飞，栈撞上代码也是跑飞。
 */
#include "ecc_ram_policy.h"
#include "test_main.h"

/* 一份合法布局：代码 [0x4000, 0x4B82)（2946 字节），标量乘在开头，mmod_fast 在中间。 */
static ecc_ram_layout_t good(void)
{
    ecc_ram_layout_t l = { .start = 0x4000, .end = 0x4B82, .mult = 0x4000, .mmod = 0x4400 };
    return l;
}

#define MAX_CODE 3072u

static void test_good_layout_passes(void)
{
    ecc_ram_layout_t l = good();
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_OK, "合法布局应通过");
    CHECK(ecc_ram_code_size(&l) == 2946, "代码大小 = end - start");
}

static void test_bad_range_rejected(void)
{
    ecc_ram_layout_t l = good();
    l.end = l.start;                  /* 链接脚本里那一段没匹配到任何函数 */
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_BAD_RANGE, "空范围");
    l = good(); l.end = l.start - 4;
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_BAD_RANGE, "范围倒置");
}

static void test_size_limit(void)
{
    ecc_ram_layout_t l = good();
    CHECK(ecc_ram_layout_check(&l, 2946) == ECC_RAM_OK, "恰好等于上限");
    CHECK(ecc_ram_layout_check(&l, 2945) == ECC_RAM_TOO_BIG, "超上限 1 字节");
}

static void test_entries_must_be_inside(void)
{
    ecc_ram_layout_t l = good();
    l.mult = l.end;                   /* EccPoint_mult 没被排进热点段 */
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_ENTRY_OUTSIDE, "mult == end");
    l = good(); l.mult = l.start - 2;
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_ENTRY_OUTSIDE, "mult 在范围前");
    l = good(); l.mmod = l.end + 0x100;
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_ENTRY_OUTSIDE, "mmod 在范围后");
    l = good(); l.mmod = l.start;     /* 边界：范围内第一个字节算在内 */
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_OK, "mmod == start");
    l = good(); l.mult = l.end - 2;   /* 边界：范围内最后一条指令算在内 */
    CHECK(ecc_ram_layout_check(&l, MAX_CODE) == ECC_RAM_OK, "mult == end - 2");
}

static void test_data_area_follows_code_aligned(void)
{
    ecc_ram_layout_t l = good();      /* 2946 → 数据区从 2948 开始 */
    CHECK(ecc_ram_data_offset(&l) == 2948, "数据区偏移向上取 4 对齐");
    CHECK(ecc_ram_extent(&l, 344) == 2948 + 344, "占用 = 数据区偏移 + 数据区长度");
    l.end = l.start + 2948;
    CHECK(ecc_ram_data_offset(&l) == 2948, "已对齐时不再多占");
}

static void test_stack_room(void)
{
    /* work_buf 在 0x200055C8，代码 + 数据占 3292，保护带 32，标量乘还要 656。
       栈指针最低只能到 0x200055C8 + 3292 + 32 = 0x200062C4，所以 sp 至少 0x20006554。 */
    const uintptr_t wb = 0x200055C8u;
    CHECK(ecc_ram_stack_ok(0x20006554u, wb, 3292, 32, 656), "恰好够");
    CHECK(!ecc_ram_stack_ok(0x20006553u, wb, 3292, 32, 656), "差 1 字节");
    CHECK(ecc_ram_stack_ok(0x20006700u, wb, 3292, 32, 656), "有余量");
    CHECK(!ecc_ram_stack_ok(0x20005000u, wb, 3292, 32, 656), "sp 在缓冲区下面：不是我们认识的栈");
    CHECK(!ecc_ram_stack_ok(0x20006700u, wb, 0xFFFFFFF0u, 32, 656), "extent 溢出不能绕过检查");
    /* 这几条在 64 位主机上也能真正考到：判断里没有会绕回的加法，只有减法和比较。
       32 位目标上原来的写法（work_base + extent + guard）会让第一条算出 4392 字节余量。 */
    CHECK(ecc_ram_stack_room(0x20006700u, wb, 0xFFFFFFF0u, 32) == 0, "extent 超过 sp 到缓冲区起点的距离：余量 0");
    CHECK(ecc_ram_stack_room(0x20006700u, wb, 0x20006700u - wb, 32) == 0, "extent 恰好顶到 sp：余量 0");
    CHECK(ecc_ram_stack_room(0x20006700u, wb, 3292, 0xFFFFFFFFu) == 0, "guard 溢出也不能绕过");
    CHECK(ecc_ram_stack_room(0x20006700u, wb, 0x20006700u - wb - 40, 32) == 8, "紧贴边界：还剩 8 字节");
    CHECK(ecc_ram_stack_room(0x20006700u, wb, 3292, 32) == 0x20006700u - 0x200062C4u, "余量 = sp - 占用区顶 - 保护带");
    CHECK(ecc_ram_stack_room(0x20006000u, wb, 3292, 32) == 0, "sp 已经在占用区里：余量为 0");
}

int main(void)
{
    RUN(test_good_layout_passes);
    RUN(test_bad_range_rejected);
    RUN(test_size_limit);
    RUN(test_entries_must_be_inside);
    RUN(test_data_area_follows_code_aligned);
    RUN(test_stack_room);
    TEST_MAIN_END;
}
