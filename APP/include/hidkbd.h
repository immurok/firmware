/********************************** (C) COPYRIGHT *******************************
 * File Name          : hidkbd.h
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/10
 * Description        :
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

#ifndef HIDKBD_H
#define HIDKBD_H

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************
 * INCLUDES
 */
#include "hardware_pins.h"

/*********************************************************************
 * CONSTANTS
 */

// Task Events
#define START_DEVICE_EVT          0x0001
#define START_REPORT_EVT          0x0002
#define START_PARAM_UPDATE_EVT    0x0004
#define START_PHY_UPDATE_EVT      0x0008
#define BUTTON_SCAN_EVT           0x0010
#define TOUCH_SCAN_EVT            0x0020
#define FP_AUTH_EVT               0x0040
#define FP_ENROLL_EVT             0x0080
#define FP_POWER_OFF_EVT          0x0100
#define FP_WAKE_DONE_EVT          0x0200
#define FP_SEARCH_EVT             0x0400
#define OTA_FLASH_ERASE_EVT       0x0800
#define FP_NOTIFY_RETRY_EVT       0x1000
#define SLOW_ADV_EVT              0x2000
#define HID_KEY_RELEASE_EVT       0x4000
// 0x8000 reserved by SYS_EVENT_MSG

/*********************************************************************
 * DESIRED CONNECTION PARAMETERS (what we ask the central for)
 *
 * Shared with hiddev.c, which compares the granted params against these to
 * decide whether the central honoured the request or overrode it.
 *********************************************************************/

// Minimum connection interval (units of 1.25ms). 24 = 30ms
#define DEFAULT_DESIRED_MIN_CONN_INTERVAL    24

// Maximum connection interval (units of 1.25ms). 48 = 60ms
#define DEFAULT_DESIRED_MAX_CONN_INTERVAL    48

// Slave latency to request. 20 = skip up to 20 intervals; effective idle
// interval = 60ms * 21 = 1.26s. Keystrokes wake immediately, latency drops
// back to 30-60ms.
#define DEFAULT_DESIRED_SLAVE_LATENCY        20

// Supervision timeout (units of 10ms).
// Apple requires: timeout > intervalMax * (latency + 1) * 3 = 60ms*21*3 = 3780ms
// Apple's current guideline range is 6s-18s; 600 = 6s is the low end.
#define DEFAULT_DESIRED_CONN_TIMEOUT         600

/*********************************************************************
 * BLE SUPERVISION TIMEOUT THRESHOLDS (units of 10ms)
 *
 * Two thresholds, shared between hidkbd.c (the ECC gate) and hiddev.c (the
 * param negotiation loop). They MUST satisfy:
 *
 *     PARAM_OK_CONN_TIMEOUT >= LONG_OP_MIN_CONN_TIMEOUT
 *
 * If hiddev.c stops re-requesting at a value the ECC gate still rejects, the
 * device deadlocks: no further param requests go out, and every ECC operation
 * fails forever. That is exactly the macOS 27 Secure Pair bug — hiddev.c was
 * satisfied at 200 (2000ms) while the gate demanded 500 (5000ms).
 *********************************************************************/

// Minimum supervision timeout required to start a blocking ECC operation
// (ECDH make_key / shared_secret, ECDSA sign — each ~1.8-1.9s measured).
//
// This is NOT sized against the ECC duration. The link is serviced throughout:
// uECC kicks its watchdog callback every 8 point-mult iterations
// (LIB/uECC.c:897) and that callback pumps TMOS_SystemProcess()
// (immurok_keystore.c:71-80, registered globally at keystore init). Measured
// on VER=6 / 1.6.2: make_key 1783ms over ~32 kicks = one link service per
// ~56ms. What must fit inside the supervision timeout is that ~56ms gap, not
// the 1.8s total.
//
// 100 (1000ms) is ~18x the observed kick interval, and leaves 2x headroom
// under the 2000ms macOS 27 imposes on HID keyboards. The historical value was
// 500 (5000ms), sized against the ECC total — wrong reference, and
// unreachable on macOS 27, which ignores both our param request and the PPCP.
#define LONG_OP_MIN_CONN_TIMEOUT  100

// Absolute floor. Below this the link is too fragile to be worth attempting a
// long op even after waiting for a param update; the request is rejected with
// 0xE1. Still ~5x the kick interval, so this only rejects genuinely broken
// links (e.g. the 720ms macOS uses before any param update lands).
#define LONG_OP_FLOOR_CONN_TIMEOUT 30

// Supervision timeout at which hiddev.c stops re-requesting param updates.
// Apple is explicit that the central may override at any time and that
// continuous renegotiation is harmful, so once we are above the ECC gate we
// stop asking rather than fight macOS for the 6s we would prefer.
#define PARAM_OK_CONN_TIMEOUT     200

// ECDH 偏好的 supervision timeout。**不是闸门** —— 达不到照样跑（闸门是
// LONG_OP_MIN_CONN_TIMEOUT，1000ms）。它的作用是让 PAIR_INIT **提早发出**
// 参数更新请求：配对要人按指纹再按按钮，中间有好几秒人类时间，足够 macOS
// 把 6000ms 谈下来，ECDH 就能跑在宽裕的链路上。
//
// 2026-08-04 实机：链路停在 2000ms 时 make_key 耗时 1746ms「勉强活下来」，
// 随后 220ms 内就 Reason:8（supervision timeout）断开 —— 余量薄到最后一个
// 锚点刚好落在边界外。而 hiddev.c 在 >= PARAM_OK_CONN_TIMEOUT(2000ms) 后
// 就不再请求了，没人会把它推到 6000ms，PAIR_INIT 原来也只在 < 1000ms 时才
// 请求，于是 2000ms 成了一个没人管的稳定坑。
//
// 只在配对路径用。KEY_SIGN 不能照搬 —— 那会给每次 sudo/ssh 加上等待。
#define PAIR_PREFERRED_CONN_TIMEOUT  600

// How long a long op waits for a requested param update to land before either
// proceeding anyway (>= LONG_OP_FLOOR_CONN_TIMEOUT) or rejecting with 0xE1.
#define LONG_OP_PARAM_WAIT_MS     3000
// Re-check interval while waiting (TMOS ticks; 625us each → ~500ms)
#define LONG_OP_PARAM_POLL_TICKS  800

// KEY_SIGN(ECDSA ~2s)专用:等待长 supervision timeout 落地的上限。
// macOS 27 重连后强制 latency=22/timeout=2000ms(override 窗口),比 2s 签名短 →
// 签名阻塞期 LL 不发包 → supervision 超时断链,签名 100% 失败。故 KEY_SIGN 也
// 必须先把 timeout 谈到 6000ms 再签 —— 这推翻了上面 PAIR_PREFERRED 注释
// "KEY_SIGN 不能加等待"的旧结论:实测不加就必断,~1s 等待是签名可用的必要代价。
// 2026-08-04 实机:签名当下主动申请 latency=20/timeout=6000ms,macOS 在 override
// 窗口内也接受,~1s grant(且 latency=20 本身省电,签名全程低功耗、无需事后恢复)。
// 5000ms 上限留足余量;超时则按操作类型回错误(签名 0xE1/配对 SEC_ERR)。
#define KEY_SIGN_PARAM_WAIT_MS    5000

// 长 ECC 门等待期内**最多**发几次参数请求(含首发)。BLE central 对短时间内
// 反复的 conn param update 请求会 ban(Apple 明确"不应持续重协商")。实测 ~1s
// grant,首发 + 2 次重发(共 3 次,间隔 ~500ms 覆盖到 ~1s)足够;之后只 poll 等
// grant,不再发。
#define LONG_OP_MAX_PARAM_REQ     3

// 认为 slave latency"够省电"的下限。低于此(尤其被 central 压成 0)虽不影响功能
// (timeout 够就能跑),但唤醒频率高、费电,应继续在后台把 latency 谈回
// DEFAULT_DESIRED_SLAVE_LATENCY。判据从"latency>0 即满意"收紧到">=5",让
// latency=1..4 也继续协商(latency=0 现有代码已会继续谈)。
#define MIN_ACCEPTABLE_SLAVE_LATENCY  5

/*********************************************************************
 * POST-OVERRIDE PARAM RE-REQUEST
 *
 * macOS 27 grants our param request during service discovery and then, ~1.7s
 * later, overrides it with its own HID keyboard params (interval 15ms,
 * latency 22, timeout 2000ms). The shorter effective wake period (345ms vs the
 * 1260ms we ask for) is 3.65x the connection events, measured as a standby
 * regression from 44uA to 90uA.
 *
 * hiddev.c used to stop the retry task the moment latency was accepted, so we
 * never once asked again after the override. Measured 2026-07-30 on macOS 27
 * beta 4: re-requesting 30s later is ACCEPTED — the central grants the full
 * interval=60ms / latency=20 / timeout=6000ms and held it for 17+ minutes.
 * So the rule is not "macOS 27 refuses our params", it is "macOS 27 refuses
 * them during service discovery and accepts them afterwards".
 *
 * Bounded, not unlimited: Apple objects to *continuous* renegotiation. We
 * re-arm on each detected override, at most POST_OVERRIDE_RETRY_MAX times per
 * connection, spaced by POST_OVERRIDE_RETRY_DELAY. Counters reset on
 * disconnect, so a reconnect gets a fresh budget. In the observed macOS 27
 * case exactly one attempt is ever used; the budget covers the periodic
 * central-initiated resets referenced in the START_PARAM_UPDATE_EVT handler,
 * which were not observed within the 17-minute window and so remain a
 * possibility rather than a measured behaviour.
 *********************************************************************/
// Current connection params, cached on link establishment and on every param
// update. Defined in hidkbd.c, written by hiddev.c's param callback.
extern uint16_t s_conn_timeout;   // units of 10ms
extern uint16_t s_conn_interval;  // units of 1.25ms
extern uint16_t s_conn_latency;
extern uint8_t  s_latency_accepted;
extern uint8_t  s_post_discovery;
extern uint8_t  s_post_override_retry_count;
extern uint8_t  s_post_override_retry_armed;

// Notify the App of the current connection params ([0xF0] frame). Defined in
// hidkbd.c; called by hiddev.c on every param change.
extern void ImmurokNotify_ConnParams(void);

// Delay before each re-request (TMOS ticks, 625us each → 30s)
#define POST_OVERRIDE_RETRY_DELAY 48000
// Max re-requests per connection. Beyond this we accept whatever the central
// insists on rather than keep fighting it.
#define POST_OVERRIDE_RETRY_MAX   5

// 常规参数更新请求的上限：**连续没有任何回应**的请求次数（主机一旦回调、
// 计数清零）。原来两个阶段都无上限，主机侧栈卡住不回 L2CAP 响应时固件每
// 5s/30s 无休止地请求，与 Apple「持续重协商有害」的要求相悖。超过上限就停，
// 等下一次断连重连或长操作（ECDH/签名）显式再要一次。
#define PARAM_UPDATE_PHASE1_MAX   6      // ×5s  = 30s
#define PARAM_UPDATE_PHASE2_MAX   3      // ×30s = 90s
// 主机明确拒绝（GAP_LINK_PARAM_UPDATE_EVENT status != SUCCESS）：直接停，
// 不再等到上限。主机之后自己改参数（回调进来）会清零重新开放。
#define PARAM_UPDATE_GIVEN_UP     0xFF
#define FP_GATE_EXEC_EVT          OTA_FLASH_ERASE_EVT  // reuse: signing and OTA are mutually exclusive

/*********************************************************************
 * MACROS
 */

/*********************************************************************
 * FUNCTIONS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */

/*
 * Task Initialization for the BLE Application
 */
extern void HidEmu_Init(void);

/*
 * Task Event Processor for the BLE Application
 */
extern uint16_t HidEmu_ProcessEvent(uint8_t task_id, uint16_t events);

/*
 * GPIO interrupt flags (set in ISR, consumed in TMOS event loop)
 */
extern volatile uint8_t g_touch_irq_flag;
extern volatile uint8_t g_btn_irq_flag;
#if HAS_TAMPER_DETECT
extern volatile uint8_t g_tamper_irq_flag;
extern void tamper_run_cleanup(void) __attribute__((noreturn));   // implemented in hidkbd.c
// True when a tamper event must wipe: any slot paired. Unpaired devices
// (production line, assembly, flashing) ignore both the rising edge and a
// static-high ANTI_OPEN at boot.
extern int tamper_should_wipe(void);   // bool; hidkbd.h is included before stdbool in main.c
#endif

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif
