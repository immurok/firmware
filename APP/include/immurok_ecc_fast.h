/*
 * P-256 标量乘从 RAM 执行（约 0.37 s，从 Flash 约 2 s）。
 *
 * 调用方不直接用这里的东西算 ECC：照常调 uECC_make_key / uECC_shared_secret / uECC_sign。
 * 固件里的 micro-ecc 由 immurok_ecc_fast.c 包含编译，那三个函数里的标量乘会先把热点代码
 * 拷进 RAM 再执行。uECC_verify（OTA 验签）有自己的循环，不经过这条路径。
 *
 * 机制与前提见 immurok_ecc_fast.c 和 ecc_ram_policy.h。
 */
#ifndef IMMUROK_ECC_FAST_H
#define IMMUROK_ECC_FAST_H

#include <stdint.h>

/*
 * RAM 执行是否可用：代码段布局通过检查，且没有发生过保护带故障（发生过就锁存到重启）。
 * 可用时一次运算只阻塞几百毫秒，调用方不必先把 supervision timeout 谈长；不可用时运算
 * 退回 Flash（约 2s），调用方要保留原来的门。
 *
 * 它不保证某一次运算一定走 RAM：栈余量是进入时按当前 sp 现算的。所以调用方必须在非
 * 嵌套派发时才发起 ECC（见 immurok_scratch.h 的 immurok_tmos_nested()），那样栈深
 * 与构建检查建模的一致，余量是够的。
 */
uint8_t immurok_ecc_fast_available(void);

/*
 * 上一次运算后，代码上方的保护带是否被栈写穿过。读取即清零。
 * 为真说明栈余量估错了，这次的结果不可信，调用方必须当作运算失败处理。
 */
uint8_t immurok_ecc_fast_take_fault(void);

/*
 * 借一块 IMMUROK_ECC_FAST_SCRATCH_LEN 字节、4 字节对齐的临时空间，标量乘期间不会被动到。
 * 给 ECC 调用方放大块的局部缓冲用：栈和搬进 work_buf 的代码共用一段空间，栈深的入口
 * 把缓冲放这里比放栈上安全。它在 immurok_keystore_work_buf 里，遵守那边的借用约定：
 * 生命期不得跨越一次向分发器的返回，期间不得做 keystore / security-save。
 */
#define IMMUROK_ECC_FAST_SCRATCH_LEN 160u
uint8_t *immurok_ecc_fast_scratch(void);

#ifdef ECC_FAST_DIAG
/* 测试构建的统计，经 GET_CONN_PARAMS 载荷 [0xEC] 读出，用来确认真机上走的是哪条路径。 */
typedef struct {
    uint8_t  ram_runs;      /* 从 RAM 执行的标量乘次数 */
    uint8_t  flash_runs;    /* 退回 Flash 执行的次数 */
    uint8_t  faults;        /* 保护带被写穿的次数 */
    uint8_t  last_reason;   /* 最近一次退回的原因：1 曲线 2 布局 3 缓冲区被占 4 栈余量不够 5 故障后锁存 */
    uint16_t min_room;      /* 进入标量乘时栈余量的最小值（字节） */
    uint16_t max_used;      /* 标量乘实际往下用掉的栈（含中断）的最大值 */
} immurok_ecc_fast_diag_t;
const immurok_ecc_fast_diag_t *immurok_ecc_fast_diag(void);
#endif

#endif /* IMMUROK_ECC_FAST_H */
