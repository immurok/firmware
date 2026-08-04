/*
 * 双主机功能对 immurok_keystore_work_buf[4096] 的借用分区。
 *
 * 背景：CH592F 只有 26KB RAM，release-debug 的 .highcode 比 debug 大
 * ~1.3KB，.bss 每多几百字节就会让 .stack 撞上 .stack_guard 链接不过。
 * 双主机需要约 300B 的临时缓冲，直接放 .bss 装不下。
 *
 * work_buf 是既有的跨模块 scratch（immurok_security.c:495 早就在裸
 * extern 借用），它同时充当 .stack_guard。这里把这个惯例正规化。
 *
 * === 唯一的安全前提 ===
 * keystore 的块读改写（KEY_* 命令、keystore_reset）与
 * save_security_data() 会用掉**整个** 4096 字节。因此：
 *
 *   任何 keystore / security-save 操作在飞行中时，不得有双主机缓冲存活。
 *
 * 这个前提当前成立，因为两类操作都由 GATT 分发器串行驱动，双主机的缓冲
 * 生命期从不跨越一次向分发器的返回。DEBUG 构建下有运行时断言兜底
 * （见 immurok_keystore.c 的 immurok_scratch_assert_free）。
 *
 * 各分区偏移互不重叠，所以模块的缓冲可以同时存活。
 */
#ifndef IMMUROK_SCRATCH_H
#define IMMUROK_SCRATCH_H

#include <stdint.h>

extern uint8_t immurok_keystore_work_buf[4096];

/* 分区偏移。取自 4096B 的头部。
 * 曾有 SCRATCH_PIN_OFF / SCRATCH_HIDKBD_OFF 两个分区，服务临时 PIN 的
 * 登记流程；2026-08-03 该流程移除后一并删除。 */
#define SCRATCH_SLOTS_OFF   0     /* 64B  — immurok_slots 的页缓冲 */
#define SCRATCH_TOTAL       64

#define SCRATCH_AT(off)  (&immurok_keystore_work_buf[(off)])

/* DEBUG 构建下：进入 keystore 块操作前断言没有双主机缓冲存活。 */
void immurok_scratch_mark_busy(uint8_t busy);
void immurok_scratch_assert_free(const char *who);

#endif /* IMMUROK_SCRATCH_H */
