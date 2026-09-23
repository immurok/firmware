/*
 * immurok QC 自检（BLE 触发，qc/ik1-selftest-proposal.md v3）
 *
 * 写 0x40（未配对才接受；已过检的不重测，直接进 DONE 绿灯让 QC 板确认）
 * → 白闪 3 次 → 依次跑 6 项自动检测（fp 模块/
 * batt/empty/flash/gpio/lse，fail-fast：任一项失败立即停测进 DONE，fail_code=
 * 首个失败项，红灯持续闪）→ 全过则 fp 进触摸待机，进人工阶段：常亮白灯=等触摸，
 * 触摸到了变常亮青灯=等按键（两者顺序不限，总窗口 ≤30s）→ 都到了=绿灯 /
 * 超时=fail_code=TOUCH 或 BTN 红灯闪；等 QC 板读走后收尾。
 * 人工阶段的触摸/按键 IRQ 标志由 main.c 直接交给 qc_test_tick 消费，
 * 不再进 hidkbd 的正常流程（否则触摸会起一次搜索、长按会触发出厂重置）。
 * 判定看电平不看边沿：DETECT 高 / BTN 低持续 ≥40ms，且进入人工阶段后
 * 先见过未操作电平（1.7.13；1.7.11 只看 IRQ 边沿，产线出现未操作自动过）。
 *
 * 结果传递靠「QC 板轮询 QC_GET」而非通知（自检期间 fp 操作会打断 BLE，
 * 通知不可靠；读取始终可靠）。QC_GET 回 phase + bitmap + mv，phase=DONE
 * 时结果有效。设备保持结果可读到关机/BLE 关。
 * 1.8.0 起 bitmap 在 RUNNING / WAIT_TOUCH 期间也实时反映「已过项」
 * （人工阶段 bit5=已触摸、bit7=已按键），供 QC 板把进度转发给上位机的
 * 设备演示窗口；最终判定仍只看 phase=DONE 时的 bitmap + fail_code。
 */
#ifndef IMMUROK_QC_TEST_H
#define IMMUROK_QC_TEST_H

#include <stdint.h>
#include "CONFIG.h"

#define HAS_QC_TEST 1

// 结果位图（1 = 通过）。与 qc/qc-firmware/main/qc_proto.h 保持一致。
#define QC_BIT_FP     (1u << 0)   // 指纹模块（红）
#define QC_BIT_BATT   (1u << 1)   // 电池 ADC（蓝）
#define QC_BIT_EMPTY  (1u << 2)   // 出厂数据为空：模板数 0 + 无绑定（绿）
#define QC_BIT_FLASH  (1u << 3)   // DataFlash 擦写回读，scratch 页 0x6C00（黄）
#define QC_BIT_GPIO   (1u << 4)   // BTN 高 / ANTI_OPEN 低（青）
#define QC_BIT_TOUCH  (1u << 5)   // 用户触摸指纹传感器（DETECT 电平确认）
#define QC_BIT_LSE    (1u << 6)   // 32.768kHz 外部晶振起振且频率正常（品红）
#define QC_BIT_BTN    (1u << 7)   // 用户按下物理按键（BTN 真实按压，1.7.11+）
#define QC_BITS_ALL   0xFF        // 8 项全过

// fail-fast 失败码（QC_GET 响应第 8 字节；0 = 无失败）。数值 = 检测执行顺序。
// 与 qc/qc-firmware/main/qc_proto.h 保持一致。
#define QC_FAIL_NONE   0
#define QC_FAIL_FP     1
#define QC_FAIL_BATT   2
#define QC_FAIL_EMPTY  3
#define QC_FAIL_FLASH  4
#define QC_FAIL_GPIO   5
#define QC_FAIL_LSE    6   // 32k 晶振停振/频偏
#define QC_FAIL_TOUCH  7   // 人工阶段 30s 超时且触摸未到
#define QC_FAIL_BTN    8   // 人工阶段 30s 超时，触摸到了但按键未按

// QC_GET 里报告的自检阶段
#define QC_PHASE_IDLE       0   // 本次上电未跑自检
#define QC_PHASE_RUNNING    1   // 自动检测项进行中
#define QC_PHASE_WAIT_TOUCH 2   // 人工阶段：等用户触摸 + 按键
#define QC_PHASE_DONE       3   // 完成，bitmap/mv 有效

// GATT 回调置位，主循环消费（自检必须在主循环上下文跑）
extern volatile uint8_t g_qc_start_req;
// 自检运行中（拒后续 0x40 = busy，拒 OTA 写，断链时保住 sleep_inhibit）
extern volatile uint8_t g_qc_running;
// QC_GET 用：当前阶段与最终结果（phase=DONE 时 bitmap/mv 有效）
extern volatile uint8_t  g_qc_phase;
extern volatile uint8_t  g_qc_result_bitmap;
extern volatile uint16_t g_qc_result_mv;
extern volatile uint8_t  g_qc_fail_code;   // 首个失败项（fail-fast），0=无
// QC 板已读到 DONE 结果（QC_GET 在 phase=DONE 时被处理）
extern volatile uint8_t  g_qc_read_done;
// QC 板发 QC_SHUTDOWN(0x44) 请求收尾关机
extern volatile uint8_t  g_qc_shutdown_req;
// 收尾后置 1：门住断链后的重广播（qc_complete 已关 BLE，进 LED 保持态）
extern volatile uint8_t  g_qc_finished;

uint8_t qc_done_read(void);    // 1 = 已通过量产质检（DataFlash 0x6D00）
void    qc_done_clear(void);   // 0x43 QC_CLEAR（返修复测）

// 触发自检：跑自动项后进人工阶段（等触摸+按键）并返回主循环。
// 已过检（qc_done=1）的设备不重跑：直接置 DONE/全过，绿灯等 QC 板读走后收尾
void qc_test_run(void);
// 主循环每轮调用：等触摸+按键 → DONE → 等 QC 板读取+关机命令 → 收尾（不返回）
void qc_test_tick(void);

// ---- provided by hidkbd.c ----
int      HidEmu_IsConnected(void);
uint16_t HidEmu_LastBattMv(void);
void     HidEmu_QcAdvFlagUpdate(uint8_t qc_done);   // 刷新广播 mfr data 标志位
void     HidEmu_QcBleOff(void);                     // 断链 + 停广播（失败停机前）

#endif // IMMUROK_QC_TEST_H
