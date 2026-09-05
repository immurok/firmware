/*
 * immurok Case-Open Hold (VER6+, HAS_TAMPER_DETECT)
 *
 * 开盖期间永不广播：
 *   已配对开盖 → 防拆清除（tamper.c，不经此模块）
 *   未配对开盖 → 停广播、红灯慢闪，数据不动；合盖自动恢复广播
 *
 * 物理自检（簧片+BTN 触发）与 im-k1-test 测试广播态已删除（2026-08-31，
 * 提案 qc/ik1-selftest-proposal.md v2）。量产检测唯一入口是 BLE QC 命令
 * （qc_test.c），且仅在组装完成（合盖）后进行。
 */
#ifndef IMMUROK_FACTORY_TEST_H
#define IMMUROK_FACTORY_TEST_H

#include <stdint.h>
#include "CONFIG.h"
#include "hardware_pins.h"

#define HAS_FACTORY_TEST    HAS_TAMPER_DETECT   // 现仅指开盖保持

#if HAS_FACTORY_TEST

// 1 while an unpaired device sits with the case open (adv off, red slow
// blink). Cleared when the switch reads low again.
extern volatile uint8_t  g_factory_case_open;

// Unpaired device saw ANTI_OPEN high: enter the hold state (idempotent).
void factory_case_open_enter(void);
// Called by the poll timer: leave the hold state, resume normal advertising.
void factory_case_open_exit(void);

// ---- provided by hidkbd.c ----
void HidEmu_CaseOpenHold(void);        // adv off, red slow blink, start switch poll
void HidEmu_CaseOpenResume(void);      // stop poll, normal fast adv cycle

#endif // HAS_FACTORY_TEST
#endif // IMMUROK_FACTORY_TEST_H
