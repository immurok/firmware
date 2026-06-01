
/********************************** (C) COPYRIGHT *******************************
 * File Name          : hidkbd.c
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/10
 * Description        : ��������Ӧ�ó��򣬳�ʼ���㲥���Ӳ�����Ȼ��㲥��ֱ�����������󣬶�ʱ�ϴ���ֵ
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

/*********************************************************************
 * INCLUDES
 */
#include "CONFIG.h"
#include "devinfoservice.h"
#include "battservice.h"
#include "hidkbdservice.h"
#include "hiddev.h"
#include "hidkbd.h"
#include "immurokservice.h"
#include "fingerprint.h"
#include "immurok_security.h"
#include "immurok_keystore.h"
#include "otaprofile.h"
#include "ota.h"
#include "hardware_pins.h"
#include "version.h"
#if HAS_VBAT_ADC
#include "CH59x_adc.h"
#endif

/*********************************************************************
 * MACROS
 */
// HID keyboard input report length
#define HID_KEYBOARD_IN_RPT_LEN              8

// HID LED output report length
#define HID_LED_OUT_RPT_LEN                  1

/*********************************************************************
 * CONSTANTS
 */
// Initial delay after connection before the first param update request.
// Phase 1 asks only for extended supervision timeout (latency=0), which macOS
// accepts even during service discovery — 1s lets the link settle first.
#define START_PARAM_UPDATE_EVT_DELAY         1600

// Phase 1 retry (latency=0, timeout extension only) — 5s. macOS rarely
// rejects this form of request, so retry quickly if it's ignored.
#define PARAM_UPDATE_PHASE1_RETRY            8000

// Phase 2 retry (full params with slave latency) — 30s. macOS rejects high
// latency during early service discovery; long retry avoids spamming.
#define PARAM_UPDATE_RETRY_DELAY             48000

// Param update delay
#define START_PHY_UPDATE_DELAY               1600

// HID idle timeout in msec; set to zero to disable timeout
#define DEFAULT_HID_IDLE_TIMEOUT             60000

// Minimum connection interval (units of 1.25ms)
// 24 = 30ms
#define DEFAULT_DESIRED_MIN_CONN_INTERVAL    24

// Maximum connection interval (units of 1.25ms)
// 48 = 60ms
#define DEFAULT_DESIRED_MAX_CONN_INTERVAL    48

// Slave latency to use if parameter update request
// 20 = skip up to 20 intervals; effective idle interval = 60ms * 21 = 1.26s
// Keystroke wakes immediately, latency drops back to 30-60ms
#define DEFAULT_DESIRED_SLAVE_LATENCY        20

// Supervision timeout value (units of 10ms)
// Apple requires: timeout > intervalMax * (latency + 1) * 3 = 60ms * 21 * 3 = 3780ms
// 600 = 6s (Apple max = 6s)
#define DEFAULT_DESIRED_CONN_TIMEOUT         600

// Default passcode
#define DEFAULT_PASSCODE                     0

// Default GAP pairing mode
#define DEFAULT_PAIRING_MODE                 GAPBOND_PAIRING_MODE_WAIT_FOR_REQ

// Default MITM mode (TRUE to require passcode or OOB when pairing)
#define DEFAULT_MITM_MODE                    FALSE

// Default bonding mode, TRUE to bond
#define DEFAULT_BONDING_MODE                 TRUE

// Default GAP bonding I/O capabilities
#define DEFAULT_IO_CAPABILITIES              GAPBOND_IO_CAP_NO_INPUT_NO_OUTPUT

// Battery level is critical when it is less than this %
#define DEFAULT_BATT_CRITICAL_LEVEL          6

// Pin definitions from hardware_pins.h: PIN_BTN, PIN_TOUCH

// Button scan interval (in 625us units, 160 = 100ms)
#define BUTTON_SCAN_INTERVAL    160

// Fingerprint power off delay (in 625us units)
// 500ms: idle-watchdog fallback. The state machine actively extends this
// timer on every iteration (FP_SEARCH_EVT, FP_AUTH_EVT, etc.) and powers off
// explicitly on finger lift, so this only fires when no other path will.
#define FP_POWER_OFF_DELAY        800     // 500ms (was 10s warm-hold)
// 25s watchdog when a gate command is pending but FP is NOT preheated.
// Cleared by FP_POWER_OFF_EVT if user never touches; matches App's 30s timeout.
#define FP_GATE_PENDING_TIMEOUT  40000    // 25s gate-pending watchdog
// 10s OTA inactivity timeout. When s_ota_active is set, FP_POWER_OFF_EVT is
// repurposed as the OTA watchdog (FP itself is off during OTA, so the FP
// idle path is unused). Each OTA cmd refreshes the timer; firing without a
// cmd for 10s aborts OTA mode and restores the device to idle state. Covers
// the ota-update.py Ctrl+C case: client disconnects mid-OTA, daemon never
// sends an abort, BLE link stays up — without this the device would blink
// fast-blue forever until BLE supervision actually drops.
#define OTA_IDLE_TIMEOUT_TICKS   16000    // 10s

// Advertising intervals (units of 0.625ms)
#define ADV_FAST_INT             160    // 100ms - fast reconnection after disconnect
#define ADV_SLOW_INT             800    // 500ms - power saving when host is off

// FAST → SLOW transition delay: 60s in 0.625ms units = 60000 / 0.625 = 96000
#define SLOW_ADV_DELAY           96000

// SLOW phase sub-tick (60s) × count (60) = 60min before SLOW → DEEP_SLEEP
#define SLOW_TICK_DELAY          96000   // 60s per sub-tick (0.625ms units)
#define SLOW_PHASE_TICK_COUNT    60      // 60 × 60s = 1 hour

// Advertising phase state machine
#define ADV_PHASE_OFF         0   // Not advertising (connected / unconfigured)
#define ADV_PHASE_FAST        1   // 100ms ADV, 60s, LED 0.5s/0.5s
#define ADV_PHASE_SLOW        2   // 500ms ADV, 60min, LED 0.5s/10s
#define ADV_PHASE_DEEP_SLEEP  3   // no ADV, LED off — BTN/TOUCH wakes back to FAST

/*********************************************************************
 * TYPEDEFS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */

// Task ID (non-static: main loop checks GPIO flags and fires events)
uint8_t hidEmuTaskId = INVALID_TASK_ID;

// Fingerprint enrollment state
static uint8_t s_enroll_active = 0;
static uint16_t s_enroll_page_id = 0;   // User finger ID (0 to FP_USER_MAX-1)
static uint8_t s_enroll_step = 0;       // 0=init, 1=get_image, 2=gen_char, 3=wait_lift, 4=merge, 5=store
static uint8_t s_enroll_substate = 0;   // 0=send command, 1=poll response
static uint32_t s_enroll_substate_start = 0;
static uint32_t s_enroll_start = 0;     // Timeout tracking
static uint8_t s_enroll_capture = 0;    // Current capture count (0 to FP_ENROLL_CAPTURES-1)

static uint8_t s_gate_preheat = 0;        // FP gate preheat: module powered, waiting for touch
static uint8_t s_gate_fail_count = 0;      // FP match failure count in current gate session
#define FP_GATE_MAX_RETRIES  3             // Max fingerprint attempts before gate failure
// Firmware-side defense-in-depth: even with sensor ScoreLevel=5 (set in
// fp_init), require MatchScore above this floor before trusting an ack=0x00
// from SEARCH. R559S returns scores in roughly 0..400 range; a legitimate
// match at level 5 typically scores 200+, a thin-feature false accept on a
// short tap scores ~50-100. Bumped 100→150 after a user report (2026-05-19)
// of false-accept passing the 100 floor on the lock-screen path while
// gate-mode rejected the same finger — strongly suggests ScoreLevel write
// silently failed on that boot and the chip stayed at default 3, where
// false-match scores can land in 100-150 range. fp_set_score_level now also
// verifies the write; the bumped MIN_SCORE is belt-and-suspenders.
#define FP_MIN_MATCH_SCORE   150
static uint32_t s_fp_power_on_tick = 0;  // RTC tick when fp_power_on() called

// Factory reset: deferred bond erase + system reset (after OK response sent)
static uint8_t s_factory_reset_pending = 0;

// Set when the short-button-press touch-reset path should follow up with a
// battery measurement once the FP module finishes powering off. Battery ADC
// reads are more accurate after VBAT-MCU has settled (FP off), so we defer
// rather than measure inline with the press.
static uint8_t s_pending_batt_check = 0;

// Use PSAutoIdentify (0x32) for single-command fingerprint search.
// Comment out to use manual 3-step search (GET_IMAGE+GEN_CHAR+SEARCH).
// #define FP_USE_AUTO_IDENTIFY

// Fingerprint search state machine
static uint8_t s_search_active = 0;
// WAIT_LIFT debounce: count consecutive GET_IMAGE ack=0x02 ("no finger")
// before declaring lift. R599S can briefly report 0x02 mid-press while the
// sensor's image-capture circuit re-arms — acting on a single 0x02 fires
// fp_power_off while the finger is still on, leaving DETECT latched.
// 2 consecutive (~40ms apart) is enough to filter the spurious blip.
#define FP_WAIT_LIFT_CONFIRM_NEEDED  2
static uint8_t s_lift_confirm = 0;
// WAIT_LIFT (case 3) was originally only entered after a successful match,
// where the user typically lifts within a second or two. The 1.4.5 change
// reuses it for no-match (so the user sees a persistent red LED while the
// long-press lock window counts down, and a quick lift before 1s cancels
// the lock). Long unregistered holds (10s+) on the same path were the
// 1.4.0 fix's "100% reproducible" DETECT-latch failure mode — to keep
// that mitigated, this flag triggers an early bail to fp_async_off_start
// once the lock window has comfortably passed.
static uint8_t s_wait_lift_no_match = 0;
#define FP_WAIT_LIFT_NOMATCH_SOFT_TMO_MS  2000
// Async substate for manual 3-step search: 0=need-send, 1=awaiting-response.
// Each case of the state machine issues its UART command in substate 0 and
// polls the ring-buffer parser in substate 1. Reset on state transition.
static uint8_t  s_search_substate = 0;
static uint32_t s_search_substate_start = 0;
// Poll interval while awaiting an FP response (625us units; 8 = 5ms).
// Short enough to catch short responses promptly, long enough that the main
// loop yields repeatedly to TMOS/BLE.
#define FP_SEARCH_POLL_TICKS        8

// Per-state response timeouts (ms). These must match the REAL R599S latency,
// not the nominal values in the old `fp_recv_ack(..., X)` calls. The old
// busy-polling loop's `timeout_ms * 6000` iterations plus periodic
// TMOS_SystemProcess() stretched every advertised wait to 3-6× its nominal
// value, which is how the old code gave R599S enough time. Our tick-based
// timeout is precise wall-clock, so sizes must be chosen empirically:
//   GET_IMAGE  — first cold-wake ack seen at ~286ms on c0c574e
//   GEN_CHAR   — feature extraction on R599S, measured at 300-500ms
//   SEARCH     — library scan over ≤5 templates, 100-300ms
// Single long poll; do NOT re-send on timeout (resending resets the sensor).
#define FP_STATE_GET_IMAGE_TMO_MS   400
#define FP_STATE_GEN_CHAR_TMO_MS    600
#define FP_STATE_SEARCH_TMO_MS      500
// WAIT_LIFT polls GET_IMAGE looking for ack=0x02 (no finger). On a fresh
// sensor 20ms is plenty; but after extended polling with finger held, the
// R599S response time creeps up — we've seen it miss a 20ms window. Each
// missed window triggers a re-send whose uart_flush() wipes any in-flight
// ack bytes, so the loop never converges. 200ms gives the sensor enough
// slack while still keeping lift-to-power-off latency under a quarter
// second in the common case.
#define FP_STATE_WAIT_LIFT_TMO_MS   200

// Enrollment uses the same non-blocking UART parser as fingerprint search.
// Do not call fp_recv_ack() from FP_ENROLL_EVT: it pumps TMOS_SystemProcess()
// while already inside a TMOS event, and repeated enroll captures can overflow
// the tiny CH592F stack / trip WWDG.
#define FP_ENROLL_POLL_TICKS        FP_SEARCH_POLL_TICKS
#define FP_ENROLL_GET_IMAGE_TMO_MS  400
#define FP_ENROLL_GEN_CHAR_TMO_MS   1000
#define FP_ENROLL_WAIT_LIFT_TMO_MS  300
#define FP_ENROLL_REG_MODEL_TMO_MS  1000
#define FP_ENROLL_STORE_TMO_MS      1000
#ifndef FP_USE_AUTO_IDENTIFY
// Manual 3-step: each state does send+recv in one call to avoid UART FIFO overflow
static uint8_t s_search_state = 0;   // 0=GET_IMAGE, 1=GEN_CHAR, 2=SEARCH
#endif
static uint32_t s_search_start_time = 0;
static uint8_t s_wait_finger_lift = 0;  // Block new search until finger lifted
// Long-press lock: 1 between TOUCH rising edge and either LOCK_HOLD_EVT firing
// or the user lifting before 2s elapse. Cleared by the LED task's lock
// handler (after the notify or the touch-released no-op) and on disconnect.
static uint8_t s_lock_pending = 0;

// Async PS_Sleep retry state (driven by FP_SLEEP_RETRY_EVT in LED task).
static uint32_t s_sleep_retry_start_tick = 0;
static uint32_t s_sleep_retry_send_tick  = 0;
// 0 = need send (fresh CMD_SLEEP with flush)
// 1 = polling parser (re-send every 1s)
// 2 = post power-cycle, waiting for sensor 0x55 ready
static uint8_t  s_sleep_retry_substate   = 0;
static uint8_t  s_sleep_retry_active     = 0;
static uint8_t  s_sleep_retry_send_count = 0;  // sends in current power cycle
static uint8_t  s_sleep_retry_cycle_count = 0; // power cycles so far
static uint32_t s_sleep_retry_cycle_tick = 0;  // tick when current cycle started

// Overall search budget. Single attempt worst case is GET_IMAGE(400) +
// GEN_CHAR(600) + SEARCH(500) = 1500ms, so a 2000ms budget leaves room for
// one retry or a slow sensor variant.
#define FP_SEARCH_TIMEOUT_MS    2000

// Fingerprint notify retry state (HID wake + ACK mechanism)
static uint8_t s_fp_notify_pending = 0;     // Has pending notification awaiting ACK
static uint32_t s_fp_notify_start_time = 0; // Start time for 15s timeout
static uint8_t s_fp_notify_data[64];        // Cached notification data (0x21 + page_id + pwd)
static uint8_t s_fp_notify_len = 0;         // Length of cached data

// Fingerprint-gated write state machine
static uint8_t s_pending_cmd = 0;           // Pending command waiting for FP verification
static uint8_t s_pending_payload[64];       // Cached payload for pending command
static uint8_t s_pending_payload_len = 0;   // Length of cached payload
static uint32_t s_pending_cmd_start = 0;    // TMOS tick when gate started
// Deferred delete: separate from s_pending_cmd to avoid race with concurrent FP match
static uint8_t s_deferred_delete_id = 0xFF; // 0xFF = no deferred delete
#define FP_GATE_TIMEOUT_MS  25000           // 25s overall gate timeout (App has 30s)
// FP gate cooldown is split by command category so that one type of recent
// FP verify doesn't unintentionally free up a different sensitive operation.
//   AUTH:     AUTH_REQUEST (PAM/sudo) — must NOT ride a keystore cooldown
//   KEYSTORE: KEY_READ/WRITE/DELETE/COMMIT/SIGN/GEN/OTP_GET — bulk ops
//   ADMIN:    ENROLL_START/DELETE_FP/FACTORY_RESET — privileged FP mgmt
typedef enum { FP_CAT_AUTH = 0, FP_CAT_KEYSTORE = 1, FP_CAT_ADMIN = 2 } fp_gate_cat_t;
static uint32_t s_fp_gate_last[3] = {0, 0, 0};
#define FP_GATE_COOLDOWN_MS 10000           // 10s idle timeout — rolling, refreshed on each pass
static fp_gate_cat_t fp_gate_cat_for_cmd(uint8_t cmd);  // forward decl (used at FP pass-through)

// Cached fingerprint bitmap (updated at init/enroll/delete, used by GET_STATUS)
// Extern: set from main.c after fp_init, avoids blocking in GATT callback
uint16_t g_cached_fp_bitmap = 0;

// Convert raw physical bitmap to user-visible bitmap
// Single-slot: bitmap bit = finger enrolled
static uint16_t fp_user_bitmap(void)
{
    return g_cached_fp_bitmap & ((1 << FP_USER_MAX) - 1);
}

// Apply BLE bond-manager pairing mode based on whether the device is already
// claimed (has a stored ECDH shared_key). Once claimed, refuse new BLE bond
// requests so a thief who carries the device away from host A can't bond it
// to host B. Combined with GATT_PERMIT_ENCRYPT_WRITE on the immurok command
// + OTA characteristics, only the originally bonded peer (with stored LTK)
// can drive the device — a fresh BLE central can't write commands at all.
//
// Called: once from init (after immurok_security_init), and from
// EEPROM_SAVE_EVT after PAIR_CONFIRM saves the new shared_key. After
// FACTORY_RESET we reboot, so init re-applies the (now-unpaired) state.
static void apply_ble_pairing_mode(void)
{
    uint8_t mode = immurok_security_is_paired()
        ? GAPBOND_PAIRING_MODE_NO_PAIRING
        : GAPBOND_PAIRING_MODE_WAIT_FOR_REQ;
    GAPBondMgr_SetParameter(GAPBOND_PERI_PAIRING_MODE, sizeof(uint8_t), &mode);
    PRINT("BLE pairing mode: %s\n",
          mode == GAPBOND_PAIRING_MODE_NO_PAIRING ? "NO_PAIRING" : "WAIT_FOR_REQ");
}

// GPIO interrupt flags (set in ISR, consumed in TMOS event loop)
volatile uint8_t g_touch_irq_flag = 0;
volatile uint8_t g_btn_irq_flag = 0;

// BLE connection state (set/cleared in GAP state callback)
static uint8_t s_ble_connected = 0;
// App/daemon GATT subscription state (set by first GATT cmd, cleared on CCCD disable / disconnect)
static uint8_t s_app_connected = 0;
// Touch-reset: power cycle FP module just to send sleep and reset touch GPIO
static uint8_t s_touch_reset = 0;

// PAIR_INIT received, waiting for the user to physically press the button to
// confirm. ECDH key generation does NOT start until the button is pressed or
// a 30s timeout fires (whichever comes first). Set by the GATT handler,
// cleared by the button handler / timeout / disconnect / factory reset.
static uint8_t s_pair_wait_button = 0;

// Advertising phase tracking
static uint8_t s_adv_phase = ADV_PHASE_OFF;
static uint8_t s_adv_slow_count = 0;  // counts SLOW_ADV_EVT ticks toward deep-sleep

// OTA IAP state
static OTA_IAP_CMD_t s_ota_iap_data;
static uint32_t s_ota_erase_addr = 0;
static uint32_t s_ota_erase_blocks = 0;
static uint32_t s_ota_erase_count = 0;
static uint8_t s_ota_verify_status = 0;
uint8_t s_ota_active = 0;  // OTA mode: suppress all non-OTA functionality (non-static: extern'd by hiddev.c)
static uint8_t s_ota_reboot_pending = 0;  // Deferred reboot after OTA verification

// OTA secure context (for encrypted .imfw upgrades)
#include "ota_keys.h"
static ota_secure_ctx_t s_ota_sec = {0};

/*********************************************************************
 * RGB LED Indicator (VER2 board)
 */
#if HAS_RGB_LED
static uint8_t s_led_task_id;
#define LED_BLINK_EVT       0x0001
#define LED_OFF_EVT         0x0002
// LOCK_HOLD_EVT: scheduled on TOUCH rising edge; fires LOCK_HOLD_TICKS later.
// If touch is still active and the timer wasn't cancelled, sends a long-press
// lock notification to the App. Independent of the FP search state machine —
// match success and lock request can both fire in the same press cycle.
//
// 1s timer (not 2s): BLE slave latency = 20 × interval up to 60ms means the
// notification queues for up to ~1200ms after GATT_Notification before macOS
// actually receives it. Total user-perceived "press → lock" lands at ~2s.
#define LOCK_HOLD_EVT       0x0004
#define LOCK_HOLD_TICKS     1600    // 1s @ 625us/tick
// EEPROM_SAVE_EVT: deferred ECDH pairing data save. EEPROM_READ called
// inline immediately after pair_compute_secret crashes the chip — see
// immurok_security_pair_save_pending. Scheduled by the EXEC handler 200ms
// after sending the PAIR_CONFIRM response.
#define EEPROM_SAVE_EVT     0x0010
// KEYSTORE_COMMIT_EVT: deferred SSH keystore commit after KEY_GENERATE.
// Same hazard as EEPROM_SAVE_EVT — calling EEPROM_ERASE/WRITE inline right
// after uECC_make_key on the same call stack faults into the IAP bootloader,
// causing a silent reboot and a BLE supervision timeout (~6s). The EXEC
// handler stages the new entry and schedules this event 200ms later; this
// handler does the flash commit + sends the response in a fresh TMOS context.
#define KEYSTORE_COMMIT_EVT 0x0040
// PAIR_BTN_TIMEOUT_EVT: 30s window after PAIR_INIT for the user to physically
// press the device button to confirm pairing. Started in the PAIR_INIT GATT
// handler, cleared on button press / long-press cancel / disconnect.
#define PAIR_BTN_TIMEOUT_EVT    0x0020
#define PAIR_BTN_TIMEOUT_TICKS  48000   // 30s @ 625us/tick

// FP_SLEEP_RETRY_EVT: async PS_Sleep + VCC-cut state machine.
//
// Design notes — there are two race-prone scenarios when the finger is still
// on the sensor at WAIT_LIFT timeout:
//   (1) sensor takes >150ms to ack PS_Sleep — the ack arrives between our
//       attempts, so each retry's uart_flush() wipes it before we see it.
//   (2) sensor refuses PS_Sleep while finger is on; we need to re-send
//       AFTER the user lifts so the sensor processes it from a fresh state.
// Both fail with a "send once, poll forever" model: (1) needs to not flush,
// (2) needs to re-send. So: first send uses flush (clear stale WAIT_LIFT
// bytes), subsequent re-sends every 1s use fp_send_cmd_noflush so any late
// ack from an earlier send still wins. Polls every 50ms. 5-min cap is a
// safety net for a truly broken sensor.
#define FP_SLEEP_RETRY_EVT          0x0008
// LED_ACCESS_OFF_EVT: deferred yellow-LED off for the keystore-read access
// indicator. Each qualifying GATT cmd (KEY_COUNT/READ/GETPUB/RESULT) drives
// R+G high inline AND restarts this task with ~100ms delay. Subsequent
// commands within the window keep restarting it, so during a batch read
// the LED stays continuously on; the trailing 100ms after the last
// response is what makes a single command visible.
#define LED_ACCESS_OFF_EVT          0x0020
#define LED_ACCESS_HOLD_TICKS       800   // 500ms (× 625µs) — bridges multi-chunk KEY_RESULT BLE round-trips so a single batch reads as one solid yellow rather than two flickers
#define FP_SLEEP_POLL_TICKS         80      // 50ms parser poll
#define FP_SLEEP_RESEND_MS          1000    // re-send PS_Sleep every 1s (no flush)
// Hardware reset escalation: after this many sends in a single power cycle
// without ack, power-cycle the sensor (VCC off → on → wait ready → retry).
// The user-observed pattern was 2 retries → sensor still stuck → eventual
// 5-min hard cap with unsafe VCC cut. With 3 sends per cycle (initial +
// 2 re-sends ≈ 2s) and 3 cycles, recovery typically lands within ~7s.
#define FP_SLEEP_SENDS_PER_CYCLE    3
#define FP_SLEEP_MAX_CYCLES         3
#define FP_SLEEP_POWER_READY_TMO_MS 300     // wait for 0x55 after fp_power_on
#define FP_SLEEP_RETRY_TOTAL_MS     300000  // 5min — broken-sensor escape hatch
#define LED_BLINK_TICKS     800     // 500ms (default on & off)
#define LED_FLASH_TICKS     320     // 200ms
#define LED_SOLID_2S_TICKS  3200    // 2s

// Advertising phase LED patterns (on/off in 625us units)
// FAST uses default LED_BLINK_TICKS (500ms / 500ms) via led_blink_start()
#define LED_ADV_SLOW_ON     800     // 500ms on
#define LED_ADV_SLOW_OFF    16000   // 10s off
// DEEP_SLEEP: LED fully off, no constants needed

static uint8_t s_led_color = 0;   // 'R', 'G', 'B', or 0
static uint8_t s_led_blink = 0;
static uint8_t s_led_toggle = 0;
static uint16_t s_led_on_ticks = LED_BLINK_TICKS;   // on duration
static uint16_t s_led_off_ticks = LED_BLINK_TICKS;  // off duration
// Busy flag: set during ECC/ECDH computation to reject concurrent commands.
// Defined here (not with other long-op state below) because the LED task's
// KEYSTORE_COMMIT_EVT handler clears it after the deferred flash commit.
static volatile uint8_t s_long_op_busy = 0;

// FP search/auth visual indicator: green normally, yellow (R+G) when battery
// is below LOW_BATT_PCT — gives the user a visible "charge me" hint on every
// touch without changing the success (blue) / failure (red) outcomes.
#define FP_LOW_BATT_PCT 15
static uint8_t fp_indicator_color(void)
{
#if HAS_VBAT_ADC
    uint8_t lvl = 100;
    Batt_GetParameter(BATT_PARAM_LEVEL, &lvl);
    return (lvl < FP_LOW_BATT_PCT) ? 'Y' : 'G';
#else
    return 'G';
#endif
}

static void led_all_off(void)
{
    LED_RED_Off(); LED_GREEN_Off(); LED_BLUE_Off();
}

static void led_on(uint8_t c)
{
    led_all_off();
    if(c == 'R') LED_RED_On();
    else if(c == 'G') LED_GREEN_On();
    else if(c == 'B') LED_BLUE_On();
    else if(c == 'Y') { LED_RED_On(); LED_GREEN_On(); }
    else if(c == 'W') { LED_RED_On(); LED_GREEN_On(); LED_BLUE_On(); }
}

static void led_stop(void)
{
    tmos_stop_task(s_led_task_id, LED_BLINK_EVT);
    tmos_stop_task(s_led_task_id, LED_OFF_EVT);
    led_all_off();
    s_led_blink = 0;
    s_led_color = 0;
}

// Solid on; auto-off after `ticks` (0 = stay on until next led_* call)
static void led_solid(uint8_t c, uint16_t ticks)
{
    led_stop();
    s_led_color = c;
    led_on(c);
    if(ticks) tmos_start_task(s_led_task_id, LED_OFF_EVT, ticks);
}

// Blink with custom on/off durations (625us units)
static void led_blink_start_ex(uint8_t c, uint16_t on_ticks, uint16_t off_ticks)
{
    led_stop();
    s_led_color = c;
    s_led_blink = 1;
    s_led_toggle = 1;
    s_led_on_ticks = on_ticks;
    s_led_off_ticks = off_ticks;
    led_on(c);
    tmos_start_task(s_led_task_id, LED_BLINK_EVT, on_ticks);
}

// Default symmetric blink (~1 Hz, 500ms on / 500ms off)
// Skips restart if already blinking the same color to avoid uneven timing.
static void led_blink_start(uint8_t c)
{
    if(s_led_blink && s_led_color == c) return;
    led_blink_start_ex(c, LED_BLINK_TICKS, LED_BLINK_TICKS);
}

// Kick the async PS_Sleep + VCC-cut state machine. Use instead of fp_power_off
// when the finger may still be on the sensor (sleep would NACK or hang).
// Cancels the idle FP_POWER_OFF_EVT timer too — otherwise it would fire
// later and call the synchronous fp_power_off, which blocks 4s and cuts
// VCC unconditionally. That's exactly the failure mode this path avoids.
static void fp_async_off_start(void)
{
    if(!fp_is_powered() || s_sleep_retry_active) return;
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    s_sleep_retry_active = 1;
    s_sleep_retry_substate = 0;
    s_sleep_retry_send_count = 0;
    s_sleep_retry_cycle_count = 0;
    s_sleep_retry_start_tick = TMOS_GetSystemClock();
    s_sleep_retry_cycle_tick = s_sleep_retry_start_tick;
    tmos_set_event(s_led_task_id, FP_SLEEP_RETRY_EVT);
}

// Forward decls — ota_abort_to_idle and ota_kick_timeout are defined later
// (after hidEmuConnHandle is in scope) but referenced from FP_POWER_OFF_EVT
// handler and the disconnect cleanup path.
static void ota_kick_timeout(void);
static void ota_abort_to_idle(void);

static uint16_t LED_ProcessEvent(uint8_t task_id, uint16_t events)
{
    if(events & LED_BLINK_EVT)
    {
        if(s_led_blink)
        {
            s_led_toggle ^= 1;
            if(s_led_toggle) {
                led_on(s_led_color);
                tmos_start_task(s_led_task_id, LED_BLINK_EVT, s_led_on_ticks);
            } else {
                led_all_off();
                tmos_start_task(s_led_task_id, LED_BLINK_EVT, s_led_off_ticks);
            }
        }
        return events ^ LED_BLINK_EVT;
    }
    if(events & LED_OFF_EVT)
    {
        led_all_off();
        s_led_color = 0;
        return events ^ LED_OFF_EVT;
    }
    if(events & LED_ACCESS_OFF_EVT)
    {
        // Bulk-read access indicator's trailing-edge off. Touches only R+G
        // so it doesn't interfere with whatever the BLINK state machine has
        // assigned to BLUE (advertising etc.).
        LED_RED_Off();
        LED_GREEN_Off();
        return events ^ LED_ACCESS_OFF_EVT;
    }
    if(events & FP_SLEEP_RETRY_EVT)
    {
        // Async PS_Sleep + VCC cut. Used after WAIT_LIFT timeout, where the
        // finger may still be on the sensor and a synchronous fp_power_off
        // would block ~4s (fp_recv_ack busy-loop calibration).
        //
        // Substates:
        //   0 = need send (fresh CMD_SLEEP with flush)
        //   1 = polling for ack + periodic re-send every 1s
        //   2 = post power-cycle, polling for sensor 0x55 ready
        //
        // Escalation: if sensor is silent after FP_SLEEP_SENDS_PER_CYCLE
        // sends (~2s wall time), fp_finish_off → fp_power_on → wait 0x55 →
        // back to substate 0 for fresh send. Repeats up to
        // FP_SLEEP_MAX_CYCLES before giving up.
        extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int fp_send_cmd_noflush(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int uart_rx_pop(void);
        extern void uart_flush(void);
        if(!s_sleep_retry_active) {
            return events ^ FP_SLEEP_RETRY_EVT;
        }
        if(!fp_is_powered() && s_sleep_retry_substate != 2) {
            // Someone else cut VCC out from under us — bail.
            s_sleep_retry_active = 0;
            s_sleep_retry_substate = 0;
            return events ^ FP_SLEEP_RETRY_EVT;
        }

        // Substate 2: post power-cycle, waiting for sensor's boot 0x55.
        if(s_sleep_retry_substate == 2) {
            int b;
            int got_ready = 0;
            while ((b = uart_rx_pop()) >= 0) {
                if ((uint8_t)b == 0x55) { got_ready = 1; break; }
            }
            uint32_t wait_ms = (TMOS_GetSystemClock() - s_sleep_retry_cycle_tick) * 625 / 1000;
            if(got_ready) {
                PRINT("Sleep cycle %d: sensor ready in %ums\n",
                      s_sleep_retry_cycle_count, (unsigned)wait_ms);
                uart_flush();
                s_sleep_retry_substate = 0;
                s_sleep_retry_send_count = 0;
                tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, 1);
                return events ^ FP_SLEEP_RETRY_EVT;
            }
            if(wait_ms < FP_SLEEP_POWER_READY_TMO_MS) {
                tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, FP_SLEEP_POLL_TICKS);
                return events ^ FP_SLEEP_RETRY_EVT;
            }
            // No 0x55 received within timeout — proceed anyway. Old sensors
            // may not emit 0x55 reliably on warm boot; CMD_SLEEP attempt
            // will tell us if it's responsive.
            PRINT("Sleep cycle %d: no 0x55 in %ums, proceeding\n",
                  s_sleep_retry_cycle_count, (unsigned)wait_ms);
            uart_flush();
            s_sleep_retry_substate = 0;
            s_sleep_retry_send_count = 0;
            tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, 1);
            return events ^ FP_SLEEP_RETRY_EVT;
        }

        if(s_sleep_retry_substate == 0) {
            // First send of this cycle: flush stale residue, fresh PS_Sleep.
            PRINT("Sleep retry: cycle %d first send\n", s_sleep_retry_cycle_count);
            fp_parser_reset();
            fp_send_cmd(0x33, NULL, 0);  // CMD_SLEEP, with flush
            s_sleep_retry_substate = 1;
            s_sleep_retry_send_count = 1;
            s_sleep_retry_send_tick = TMOS_GetSystemClock();
            tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, FP_SLEEP_POLL_TICKS);
            return events ^ FP_SLEEP_RETRY_EVT;
        }
        // substate == 1: poll parser; re-send PS_Sleep every 1s (no flush)
        uint8_t ack;
        int ret = fp_try_parse_packet(&ack, NULL, NULL);
        WWDG_SetCounter(0);
        uint32_t since_send = (TMOS_GetSystemClock() - s_sleep_retry_send_tick) * 625 / 1000;
        if(ret == FP_OK && ack == 0x00) {
            PRINT("R599S sleep OK (cycle %d, %ums after last send), cutting VCC\n",
                  s_sleep_retry_cycle_count, (unsigned)since_send);
            fp_finish_off();
            s_sleep_retry_active = 0;
            s_sleep_retry_substate = 0;
            // Sensor only acks PS_Sleep after the finger lifts (it stays
            // silent while touched). Receiving the ack here is the most
            // reliable lift signal we have — release the touch gate so
            // the next press can start a fresh search. The TOUCH_SCAN_EVT
            // touch=0 branch wouldn't fire on its own without a new IRQ.
            s_wait_finger_lift = 0;
            return events ^ FP_SLEEP_RETRY_EVT;
        }
        if(ret == FP_OK) {
            // Non-zero ack — sensor refused. Log; the next noflush re-send
            // will let the sensor retry from its current state (post-lift).
            PRINT("Sleep retry: NACK ack=0x%02X (%ums)\n", ack, (unsigned)since_send);
        } else if(ret == FP_ERR_FAIL) {
            PRINT("Sleep retry: parse fail (%ums)\n", (unsigned)since_send);
        }

        // Hard cap: 5min for truly stuck sensor.
        uint32_t total_elapsed = (TMOS_GetSystemClock() - s_sleep_retry_start_tick) * 625 / 1000;
        if(total_elapsed > FP_SLEEP_RETRY_TOTAL_MS) {
            PRINT("Sleep retry timed out (%ums total), forcing VCC cut\n",
                  (unsigned)total_elapsed);
            fp_finish_off();
            s_sleep_retry_active = 0;
            s_sleep_retry_substate = 0;
            return events ^ FP_SLEEP_RETRY_EVT;
        }

        // Re-send PS_Sleep every 1s without flushing — preserves a late ack
        // from a prior send. If the user just lifted, this re-send will be
        // accepted by the now-idle sensor.
        if(since_send >= FP_SLEEP_RESEND_MS) {
            if(s_sleep_retry_send_count < FP_SLEEP_SENDS_PER_CYCLE) {
                PRINT("Sleep retry: re-send (no flush, %ums since prev, count %d)\n",
                      (unsigned)since_send, s_sleep_retry_send_count);
                fp_send_cmd_noflush(0x33, NULL, 0);
                s_sleep_retry_send_count++;
                s_sleep_retry_send_tick = TMOS_GetSystemClock();
            } else {
                // Sensor is stuck. Power-cycle and retry.
                if(s_sleep_retry_cycle_count + 1 >= FP_SLEEP_MAX_CYCLES) {
                    PRINT("Sleep retry: %d cycles exhausted, forcing VCC cut\n",
                          s_sleep_retry_cycle_count + 1);
                    fp_finish_off();
                    s_sleep_retry_active = 0;
                    s_sleep_retry_substate = 0;
                    return events ^ FP_SLEEP_RETRY_EVT;
                }
                s_sleep_retry_cycle_count++;
                PRINT("Sleep retry: %d sends silent, power-cycling sensor (cycle %d)\n",
                      FP_SLEEP_SENDS_PER_CYCLE, s_sleep_retry_cycle_count);
                fp_finish_off();
                // Brief settle then re-power. fp_power_on does the GPIO +
                // UART setup; sensor takes ~150-200ms to boot and emit 0x55.
                fp_power_on();
                s_sleep_retry_substate = 2;
                s_sleep_retry_cycle_tick = TMOS_GetSystemClock();
                tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, FP_SLEEP_POLL_TICKS);
                return events ^ FP_SLEEP_RETRY_EVT;
            }
        }
        tmos_start_task(s_led_task_id, FP_SLEEP_RETRY_EVT, FP_SLEEP_POLL_TICKS);
        return events ^ FP_SLEEP_RETRY_EVT;
    }

    if(events & EEPROM_SAVE_EVT)
    {
        // Deferred save of pairing data. Runs in fresh TMOS context after
        // the ECC compute call stack has fully unwound — calling
        // EEPROM_READ inline right after compute_secret crashes the chip.
        if(immurok_security_pair_save_pending) {
            immurok_security_pair_save_pending = 0;
            int ret = immurok_security_pair_save();
            PRINT("Deferred EEPROM save: ret=%d\n", ret);
            // Pair just claimed the device — flip pairing mode to NO_PAIRING
            // so a fresh BLE central can no longer bond. Existing peer's LTK
            // (saved at the BLE bonding step that preceded ECDH) survives.
            if(ret == 0) {
                apply_ble_pairing_mode();
            }
        }
        return events ^ EEPROM_SAVE_EVT;
    }

    if(events & KEYSTORE_COMMIT_EVT)
    {
        // Deferred SSH keystore commit — runs in fresh TMOS context so the
        // ECC call stack from KEY_GENERATE is fully unwound before any
        // EEPROM_ERASE/WRITE. See note on KEYSTORE_COMMIT_EVT define above.
        // Gate on (pending_cmd == KEY_GENERATE && busy): only the EXEC
        // handler's stage path schedules this event, and disconnect
        // cleanup clears both flags + the timer, so this is a robust
        // "stage done, awaiting commit" signal.
        if(s_pending_cmd == IMMUROK_CMD_KEY_GENERATE && s_long_op_busy) {
            uint8_t new_idx = s_pending_payload[17];
            int ret = immurok_keystore_commit(KEYSTORE_CAT_SSH, 0xFF);
            if(ret == 0) {
                uint8_t rsp3[3] = { IMMUROK_RSP_OK, 64, new_idx };
                PRINT("KEY_GENERATE commit done: idx=%d\n", new_idx);
                ImmurokService_SendResponse(rsp3, 3);
            } else {
                uint8_t rspErr[1] = { SEC_ERR_INTERNAL };
                PRINT("KEY_GENERATE commit failed\n");
                ImmurokService_SendResponse(rspErr, 1);
            }
            // Now release the long-op lock that the EXEC handler held
            // through stage→commit so concurrent KEY_SIGN/KEY_GENERATE
            // wouldn't race the partially-staged buffer.
            s_pending_cmd = 0;
            s_long_op_busy = 0;
#if HAS_RGB_LED
            led_stop();
#endif
        }
        return events ^ KEYSTORE_COMMIT_EVT;
    }

    if(events & PAIR_BTN_TIMEOUT_EVT)
    {
        // 30s elapsed without the user pressing the button — abort pairing.
        if(s_pair_wait_button)
        {
            s_pair_wait_button = 0;
            led_stop();
            if(s_app_connected)
            {
                uint8_t notif[2] = { IMMUROK_NTF_PAIR_BUTTON, 0x00 };  // timeout
                ImmurokService_SendResponse(notif, 2);
            }
            PRINT("Pair button timeout (30s)\n");
        }
        return events ^ PAIR_BTN_TIMEOUT_EVT;
    }

    if(events & LOCK_HOLD_EVT)
    {
        // Fires LOCK_HOLD_TICKS after TOUCH rising edge. We do NOT gate on
        // TOUCH_ReadPin()
        // here: R599S resets its DETECT line during/after match, so the GPIO
        // reads LOW even when the finger is still on the sensor. Instead the
        // schedule is treated as "armed", and reliable-lift signals clear
        // s_lock_pending elsewhere (WAIT_LIFT lift detected, GET_IMAGE ack=0x02
        // standby, fp_power_off paths). When the timer fires with pending=1,
        // the user has not lifted — fire the lock notify regardless of FP
        // match outcome (App arbitrates based on screen state).
        //
        // Suppress during a gated command (KEY_SIGN/DELETE_FP/KEY_GENERATE/
        // ENROLL etc.), AUTH_REQUEST, or active fingerprint enrollment:
        // the user is holding *for* one of those flows; firing LOCK_REQUEST
        // in parallel pops a "lock screen?" dialog over the active sudo /
        // unlock / enroll guidance and is always wrong.
        {
            uint8_t in_gate = (s_pending_cmd != 0
                               || immurok_security_has_pending_auth()
                               || s_enroll_active);
            if(s_lock_pending && s_app_connected && !in_gate)
            {
                uint8_t buf[1] = { IMMUROK_CMD_LOCK_REQUEST };
                ImmurokService_SendResponse(buf, 1);
                led_solid('W', LED_FLASH_TICKS);  // brief white flash as feedback
                PRINT("Long-press lock request sent\n");
            }
            else if(s_lock_pending && !in_gate)
            {
                // Non-gate but app not subscribed — clear the persistent
                // blue (match) / red (no-match) indicator the search
                // result handler armed; otherwise the LED stays stuck.
                PRINT("Long-press lock suppressed (no app)\n");
                led_stop();
            }
            else if(s_lock_pending)
            {
                // Gate/auth in flight — LED is owned by the gate handler
                // (green/yellow blink); do not touch it.
                PRINT("Long-press lock suppressed (gate/auth pending)\n");
            }
        }
        s_lock_pending = 0;
        return events ^ LOCK_HOLD_EVT;
    }
    return 0;
}
#endif // HAS_RGB_LED

/*********************************************************************
 * LOCAL FUNCTIONS
 */

// Reset fingerprint power-off timer (call after any FP operation while module
// is powered). State machine iterations refresh this on every step; once the
// last step stops calling it, the 500ms fallback fires and powers FP off.
// Note: gate-pending watchdog uses a separate longer arm in fp_gate_enter().
static void fp_reset_power_timer(void)
{
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, FP_POWER_OFF_DELAY);
}

// Ensure fingerprint module is ready for operation
static int fp_ensure_ready(void)
{
    int ret = fp_wake();
    if (ret == FP_OK) {
        fp_reset_power_timer();
    }
    return ret;
}

// Restart fast advertising cycle (FAST 60s → SLOW 60min → DEEP_SLEEP).
// Called when user touches sensor or presses button during SLOW/DEEP_SLEEP phase.
// Also handles waking from DEEP_SLEEP where ADVERT_ENABLED was set to FALSE.
static void adv_restart_fast_cycle(void)
{
    if(s_adv_phase == ADV_PHASE_FAST) return;  // already fast
    PRINT("ADV: restart fast cycle (was phase %d)\n", s_adv_phase);
    s_adv_phase = ADV_PHASE_FAST;
    s_adv_slow_count = 0;
    tmos_stop_task(hidEmuTaskId, SLOW_ADV_EVT);
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
    GAP_SetParamValue(TGAP_LIM_ADV_TIMEOUT, 0);  // no timeout (we manage via SLOW_ADV_EVT)
    uint8_t adv_enable = TRUE;
    GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
    tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_ADV_DELAY);
#if HAS_RGB_LED
    led_blink_start('B');
#endif
}

/*********************************************************************
 * EXTERNAL VARIABLES
 */

/*********************************************************************
 * EXTERNAL FUNCTIONS
 */

/*********************************************************************
 * LOCAL FUNCTION PROTOTYPES
 */
static void HidEmu_ImmurokCommandCB(uint16_t connHandle, uint8_t *pData, uint8_t len);
static void HidEmu_ImmurokCccChangeCB(uint8_t enabled);
static void hidEmuSendCtrlKey(void);

// OTA callback functions
static void OTA_IAPReadDataComplete(uint8_t paramID);
static void OTA_IAPWriteData(uint8_t paramID, uint8_t *pData, uint8_t len);
static void OTA_IAP_DataDeal(void);
static void OTA_IAP_SendStatus(uint8_t status);


/*********************************************************************
 * LOCAL VARIABLES
 */

// GAP Profile - Name attribute for SCAN RSP data
static uint8_t scanRspData[] = {
    0x0D,                           // length of this data (12 + 1)
    GAP_ADTYPE_LOCAL_NAME_COMPLETE, // AD Type = Complete local name
    'i',
    'm',
    'm',
    'u',
    'r',
    'o',
    'k',
    ' ',
    'I',
    'K',
    '-',
    '1',  // connection interval range
    0x05, // length of this data
    GAP_ADTYPE_SLAVE_CONN_INTERVAL_RANGE,
    LO_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL), // 100ms
    HI_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL),
    LO_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL), // 1s
    HI_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL),

    // service UUIDs
    0x05, // length of this data
    GAP_ADTYPE_16BIT_MORE,
    LO_UINT16(HID_SERV_UUID),
    HI_UINT16(HID_SERV_UUID),
    LO_UINT16(BATT_SERV_UUID),
    HI_UINT16(BATT_SERV_UUID),

    // Tx power level
    0x02, // length of this data
    GAP_ADTYPE_POWER_LEVEL,
    0 // 0dBm
};

// Advertising data
static uint8_t advertData[] = {
    // flags
    0x02, // length of this data
    GAP_ADTYPE_FLAGS,
    GAP_ADTYPE_FLAGS_GENERAL | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED,

    // appearance
    0x03, // length of this data
    GAP_ADTYPE_APPEARANCE,
    LO_UINT16(GAP_APPEARE_HID_KEYBOARD),
    HI_UINT16(GAP_APPEARE_HID_KEYBOARD)};

// Device name attribute value
static CONST uint8_t attDeviceName[GAP_DEVICE_NAME_LEN] = "immurok IK-1";

// HID Dev configuration
static hidDevCfg_t hidEmuCfg = {
    DEFAULT_HID_IDLE_TIMEOUT, // Idle timeout
    HID_FEATURE_FLAGS         // HID feature flags
};

static uint16_t hidEmuConnHandle = GAP_CONNHANDLE_INIT;

// Param update retry counter
uint8_t s_param_update_retries = 0;
// Whether our desired latency has been accepted (extern'd by hiddev.c)
uint8_t s_latency_accepted = 0;
// Current supervision timeout in units of 10ms (extern'd by hiddev.c, updated on every param change)
uint16_t s_conn_timeout = 0;
// Sticky: set once Phase 2 (slave latency + timeout ≥ 2s) has been accepted.
// Signals discovery is done, so degradation recovery can skip Phase 1 and
// request full params directly. Cleared on disconnect. Extern'd by hiddev.c.
uint8_t s_post_discovery = 0;
// Long op param wait state (reset on disconnect)
static uint8_t s_long_op_param_requested = 0;
static uint32_t s_long_op_wait_start = 0;
// s_long_op_busy / s_keygen_commit_pending / s_keygen_new_idx are defined
// near the LED task so its KEYSTORE_COMMIT_EVT handler can see them.

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static void    hidEmu_ProcessTMOSMsg(tmos_event_hdr_t *pMsg);
static void    hidEmuSendKbdReport(uint8_t keycode);
static uint8_t hidEmuRcvReport(uint8_t len, uint8_t *pData);
static uint8_t hidEmuRptCB(uint8_t id, uint8_t type, uint16_t uuid,
                           uint8_t oper, uint16_t *pLen, uint8_t *pData);
static void    hidEmuEvtCB(uint8_t evt);
static void    hidEmuStateCB(gapRole_States_t newState, gapRoleEvent_t *pEvent);

/*********************************************************************
 * PROFILE CALLBACKS
 */

static hidDevCB_t hidEmuHidCBs = {
    hidEmuRptCB,
    hidEmuEvtCB,
    NULL,
    hidEmuStateCB};

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

/*********************************************************************
 * BATTERY ADC CALLBACKS (VER1/VER2/VER3/VER5 — anything with HAS_VBAT_ADC)
 */
#if HAS_VBAT_ADC

// Reentrancy guard for nested TMOS_SystemProcess() during VBAT settle.
static volatile uint8_t s_in_vbat_tmos_kick = 0;

// Last VBAT measurement raw values — exposed via GET_BATT_RAW for calibration.
// Updated by battCalcCB at every periodic measurement.
static uint16_t s_last_batt_mv = 0;
static uint16_t s_last_batt_adc = 0;

// First-measurement-after-boot flag: C7 may need 6.7τ to charge from its
// pre-init state. Subsequent measurements skip the wait because C7 stays
// charged via R2/R3 (PA14 left in IN_Floating between cycles — see
// battTeardownCB rationale).
static bool s_vbat_first_meas = true;

// Yield-aware delay: the RC divider needs 5τ to settle (250ms VER2/3, 375ms
// VER5), longer than several BLE connection intervals (30–50ms). A straight
// DelayMs() busy-loop would starve the TMOS event queue and risk supervision
// timeout. Chunk the wait into ≈15ms slices and pump TMOS between slices so
// LL and ATT keep running.
static void vbat_settle_delay(uint32_t ms)
{
    const uint32_t slice = 15;  // ≈ half a connection interval
    while (ms)
    {
        uint32_t chunk = ms > slice ? slice : ms;
        DelayMs(chunk);
        ms -= chunk;
        if (!s_in_vbat_tmos_kick)
        {
            s_in_vbat_tmos_kick = 1;
            WWDG_SetCounter(0);
            TMOS_SystemProcess();
            s_in_vbat_tmos_kick = 0;
        }
    }
}

static void battSetupCB(void)
{
    // PA14 stays in IN_Floating from boot to teardown. C7 (100nF) is
    // permanently charged via the R2/R3 divider, so no settle wait is needed
    // on subsequent measurements — only the first one after power-on pays the
    // cost (handled by `s_vbat_first_meas`).
    GPIOA_ModeCfg(PIN_VBAT, GPIO_ModeIN_Floating);
    if (s_vbat_first_meas) {
        // First-ever measurement: C7 may not yet be charged (depending on
        // pre-init state). Wait 6.7τ once to fill it.
        vbat_settle_delay(VBAT_SETTLE_MS);
        s_vbat_first_meas = false;
    }
    ADC_ExtSingleChSampInit(SampleFreq_3_2, ADC_PGA_0);
    ADC_ChannelCfg(VBAT_ADC_CH);
}

static void battTeardownCB(void)
{
    ADC_DisablePower();
    // Don't switch PA14 to IN_PD between measurements. Per CH592 datasheet
    // V1.7 §7.2: GPIO wake requires BOTH the per-pin R16_Px_INT_EN *and* the
    // master RB_SLP_GPIO_WAKE bit. PA14 has neither set (pure ADC input),
    // so the previous comment about "floating PA14 at VCC/2 triggers GPIO
    // wake" was incorrect. Plus CH592 GPIO inputs are Schmitt triggers
    // (datasheet pin-type note "I=TTL/CMOS Schmitt input"), so VCC/2-level
    // input doesn't cause buffer oscillation either. Keeping PA14 in
    // IN_Floating leaves C7 charged via the R2/R3 divider — next measurement
    // is <1ms instead of 500ms (verified 2026-05-16 against datasheet).
}

// Li-ion discharge curve: voltage (mV) → percentage
static uint8_t battCalcCB(uint16_t adc)
{
    // PGA_0 (1x), Vref≈1.05V, full-scale≈2.1V → 4096 counts
    // raw_mv = adc * (2100 * VBAT_DIV_RATIO) / 4096
    uint32_t raw_mv = (uint32_t)adc * (2100 * VBAT_DIV_RATIO) / 4096;

    // Bench calibration vs. lab DMM (resources/batt.csv, 2026-05-11 HW Rev.3).
    // Raw chain (CH59x Vref + 1% divider) reads ~10 mV low and has a tiny
    // -0.27% gain error. Linear least-squares fit: real = 0.997297 * raw + 20.224.
    // Integer-shift form below tracks the fit to ±5 mV over 3300-4200 mV.
    //   real_mv = (raw_mv * 1021 + 512) / 1024 + 20
    uint32_t mv = (raw_mv * 1021U + 512U) / 1024U + 20U;

    s_last_batt_adc = adc;
    s_last_batt_mv = (mv > 0xFFFF) ? 0xFFFF : (uint16_t)mv;

    // Top anchor is 4150 mV (not 4200) to absorb measurement headroom: charger
    // float voltage tolerance (±1-2%), CH59x Vref tolerance (±2-3%), 1% resistor
    // tolerance, and remaining C7 settling undershoot (~5 mV at 6.7τ). Real
    // batteries that actually charge to 4.15-4.20 V will read 100% reliably
    // instead of capping at ~96%.
    static const uint16_t curve_mv[]  = {4150, 4100, 4000, 3900, 3800, 3700, 3600, 3500, 3300, 3000};
    static const uint8_t  curve_pct[] = { 100,   90,   80,   60,   40,   30,   20,   10,    5,    0};
    #define CURVE_LEN 10

    if(mv >= curve_mv[0]) return 100;
    if(mv <= curve_mv[CURVE_LEN - 1]) return 0;

    for(int i = 0; i < CURVE_LEN - 1; i++)
    {
        if(mv >= curve_mv[i + 1])
        {
            uint32_t dv = curve_mv[i] - curve_mv[i + 1];
            uint32_t dp = curve_pct[i] - curve_pct[i + 1];
            return curve_pct[i + 1] + (uint8_t)((mv - curve_mv[i + 1]) * dp / dv);
        }
    }
    return 0;
}

#endif // HAS_VBAT_ADC

/*********************************************************************
 * @fn      HidEmu_Init
 *
 * @brief   Initialization function for the HidEmuKbd App Task.
 *          This is called during initialization and should contain
 *          any application specific initialization (ie. hardware
 *          initialization/setup, table initialization, power up
 *          notificaiton ... ).
 *
 * @param   task_id - the ID assigned by TMOS.  This ID should be
 *                    used to send messages and set timers.
 *
 * @return  none
 */
void HidEmu_Init()
{
    hidEmuTaskId = TMOS_ProcessEventRegister(HidEmu_ProcessEvent);

    // Initialize button GPIO (pull-up, active low)
    BTN_SetMode(GPIO_ModeIN_PU);

    // Initialize touch detection GPIO (active high). Idle = IN_PD;
    // fp_power_on() toggles to Floating for R599S during active sensor use.
    TOUCH_SetMode(GPIO_ModeIN_PD);

    // Configure GPIO interrupts for fast wake detection
    // Touch: rising edge (finger down), Button: falling edge (press)
    TOUCH_SetITMode(GPIO_ITMode_RiseEdge);
    BTN_SetITMode(GPIO_ITMode_FallEdge);
    PFIC_EnableIRQ(BTN_TOUCH_IRQn);
    PRINT("GPIO interrupts enabled\n");

#if HAS_RGB_LED
    s_led_task_id = TMOS_ProcessEventRegister(LED_ProcessEvent);
    led_blink_start('B');  // Blue blink = advertising
#endif

    // Initialize security module
    immurok_security_init();

    // Initialize keystore module
    immurok_keystore_init();

    // Setup the GAP Peripheral Role Profile
    {
        uint8_t initial_advertising_enable = TRUE;

        // Set the GAP Role Parameters
        GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &initial_advertising_enable);

        GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);
        GAPRole_SetParameter(GAPROLE_SCAN_RSP_DATA, sizeof(scanRspData), scanRspData);
    }

    // Set the GAP Characteristics
    GGS_SetParameter(GGS_DEVICE_NAME_ATT, GAP_DEVICE_NAME_LEN, (void *)attDeviceName);

    // Setup the GAP Bond Manager
    {
        uint32_t passkey = DEFAULT_PASSCODE;
        uint8_t  mitm = DEFAULT_MITM_MODE;
        uint8_t  ioCap = DEFAULT_IO_CAPABILITIES;
        uint8_t  bonding = DEFAULT_BONDING_MODE;
        GAPBondMgr_SetParameter(GAPBOND_PERI_DEFAULT_PASSCODE, sizeof(uint32_t), &passkey);
        GAPBondMgr_SetParameter(GAPBOND_PERI_MITM_PROTECTION, sizeof(uint8_t), &mitm);
        GAPBondMgr_SetParameter(GAPBOND_PERI_IO_CAPABILITIES, sizeof(uint8_t), &ioCap);
        GAPBondMgr_SetParameter(GAPBOND_PERI_BONDING_ENABLED, sizeof(uint8_t), &bonding);
        // Pairing mode is set by apply_ble_pairing_mode() based on whether
        // the device already has a saved ECDH shared_key — once claimed, new
        // BLE bond requests are refused so a thief can't bond it elsewhere.
        apply_ble_pairing_mode();
    }
    {
        // Preferred connection parameters (advertised to central)
        gapPeriConnectParams_t ConnectParams;
        ConnectParams.intervalMin = DEFAULT_DESIRED_MIN_CONN_INTERVAL;  // 100ms
        ConnectParams.intervalMax = DEFAULT_DESIRED_MAX_CONN_INTERVAL;  // 200ms
        ConnectParams.latency = DEFAULT_DESIRED_SLAVE_LATENCY;          // 20
        ConnectParams.timeout = DEFAULT_DESIRED_CONN_TIMEOUT;           // 5000ms
        GGS_SetParameter(GGS_PERI_CONN_PARAM_ATT, sizeof(gapPeriConnectParams_t), &ConnectParams);
    }
    // Setup Battery Characteristic Values
    {
        uint8_t critical = DEFAULT_BATT_CRITICAL_LEVEL;
        Batt_SetParameter(BATT_PARAM_CRITICAL_LEVEL, sizeof(uint8_t), &critical);

#if HAS_VBAT_ADC
        // Register ADC battery measurement callbacks
        Batt_Setup(VBAT_ADC_CH, 0, 0, battSetupCB, battTeardownCB, battCalcCB);
        // Initial battery measurement at boot
        Batt_MeasLevel();
#else
        // No battery ADC — fixed 20%
        uint8_t fixedLevel = 20;
        Batt_SetParameter(BATT_PARAM_LEVEL, sizeof(uint8_t), &fixedLevel);
#endif
    }

    // Set serial number from chip MAC address
    {
        __attribute__((aligned(4))) uint8_t mac[6];
        GetMACAddress(mac);
        char sn[13];
        for(int i = 0; i < 6; i++) {
            uint8_t hi = mac[i] >> 4;
            uint8_t lo = mac[i] & 0x0F;
            sn[i * 2]     = hi < 10 ? '0' + hi : 'A' + hi - 10;
            sn[i * 2 + 1] = lo < 10 ? '0' + lo : 'A' + lo - 10;
        }
        sn[12] = '\0';
        DevInfo_SetParameter(DEVINFO_SERIAL_NUMBER, 12, sn);
        PRINT("Serial: %s\n", sn);
    }

    // Set up HID keyboard service
    Hid_AddService();

    // Set up immurok custom service
    ImmurokService_AddService();

    // Register immurok command + CCCD callbacks
    static immurokServiceCBs_t immurokCBs = {
        .pfnCommandCB = HidEmu_ImmurokCommandCB,
        .pfnCccChangeCB = HidEmu_ImmurokCccChangeCB
    };
    ImmurokService_RegisterAppCBs(&immurokCBs);

    // Set up OTA service
    OTAProfile_AddService(OTAPROFILE_SERVICE);

    // Register OTA callbacks
    static OTAProfileCBs_t otaCBs = {
        .pfnOTAProfileRead = OTA_IAPReadDataComplete,
        .pfnOTAProfileWrite = OTA_IAPWriteData
    };
    OTAProfile_RegisterAppCBs(&otaCBs);

    // Register for HID Dev callback
    HidDev_Register(&hidEmuCfg, &hidEmuHidCBs);

    // Set initial advertising interval (fast for first connection)
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);

    // Setup a delayed profile startup
    tmos_set_event(hidEmuTaskId, START_DEVICE_EVT);
}

/*********************************************************************
 * @fn      HidEmu_ProcessEvent
 *
 * @brief   HidEmuKbd Application Task event processor.  This function
 *          is called to process all events for the task.  Events
 *          include timers, messages and any other user defined events.
 *
 * @param   task_id  - The TMOS assigned task ID.
 * @param   events - events to process.  This is a bit map and can
 *                   contain more than one event.
 *
 * @return  events not processed
 */

uint16_t HidEmu_ProcessEvent(uint8_t task_id, uint16_t events)
{
    if(events & SYS_EVENT_MSG)
    {
        uint8_t *pMsg;

        if((pMsg = tmos_msg_receive(hidEmuTaskId)) != NULL)
        {
            hidEmu_ProcessTMOSMsg((tmos_event_hdr_t *)pMsg);

            // Release the TMOS message
            tmos_msg_deallocate(pMsg);
        }

        // return unprocessed events
        return (events ^ SYS_EVENT_MSG);
    }

    if(events & START_DEVICE_EVT)
    {
        // GPIO interrupts + main loop flag check handle detection.
        // No periodic polling needed - events fired from Main_Circulation.
        return (events ^ START_DEVICE_EVT);
    }

    if(events & START_PARAM_UPDATE_EVT)
    {
        if(s_ota_active)
        {
            return (events ^ START_PARAM_UPDATE_EVT);
        }
        // Fully done: current params are both latency-accepted AND timeout-adequate.
        // Must check both — macOS periodic resets can push (timeout<200, latency>0)
        // which keeps s_latency_accepted=1 but still needs re-request.
        if(s_latency_accepted && s_conn_timeout >= 200)
        {
            return (events ^ START_PARAM_UPDATE_EVT);
        }
        // Initial connection uses two-phase update so FP auth survives from
        // the moment we connect:
        //   Phase 1 (timeout < 2s, pre-discovery): request latency=0, timeout=6s
        //     — macOS accepts this even during service discovery, lifting
        //     supervision timeout from its 720ms default.
        //   Phase 2 (timeout ≥ 2s, latency=0): request latency=N, timeout=6s
        //     for power savings — macOS only accepts this after discovery.
        // After first Phase 2 acceptance (s_post_discovery=1), macOS periodic
        // resets can be recovered in one round trip — skip Phase 1.
        uint16_t req_latency;
        uint32_t retry_delay;
        if(!s_post_discovery && s_conn_timeout < 200)
        {
            req_latency = 0;
            retry_delay = PARAM_UPDATE_PHASE1_RETRY;
        }
        else
        {
            req_latency = DEFAULT_DESIRED_SLAVE_LATENCY;
            retry_delay = PARAM_UPDATE_RETRY_DELAY;
        }
        s_param_update_retries++;
        PRINT("Requesting param update (attempt %d): interval=%d-%d, latency=%d, timeout=%d\n",
              s_param_update_retries,
              DEFAULT_DESIRED_MIN_CONN_INTERVAL, DEFAULT_DESIRED_MAX_CONN_INTERVAL,
              req_latency, DEFAULT_DESIRED_CONN_TIMEOUT);
        GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                                             DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                                             DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                                             req_latency,
                                             DEFAULT_DESIRED_CONN_TIMEOUT,
                                             hidEmuTaskId);

        tmos_start_task(hidEmuTaskId, START_PARAM_UPDATE_EVT, retry_delay);

        return (events ^ START_PARAM_UPDATE_EVT);
    }

    if(events & START_PHY_UPDATE_EVT)
    {
        // start phy update
        PRINT("Send Phy Update %x...\n", GAPRole_UpdatePHY(hidEmuConnHandle, 0,
                    GAP_PHY_BIT_LE_2M, GAP_PHY_BIT_LE_2M, 0));

        return (events ^ START_PHY_UPDATE_EVT);
    }

    if(events & SLOW_ADV_EVT)
    {
        if(s_adv_phase == ADV_PHASE_FAST)
        {
            // FAST → SLOW: 500ms ADV interval, LED 0.5s on / 10s off
            PRINT("ADV: fast→slow (500ms)\n");
            s_adv_phase = ADV_PHASE_SLOW;
            s_adv_slow_count = 0;
            GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_SLOW_INT);
            GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_SLOW_INT);
            uint8_t adv_enable = TRUE;
            GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
#if HAS_RGB_LED
            led_blink_start_ex('B', LED_ADV_SLOW_ON, LED_ADV_SLOW_OFF);
#endif
            // Schedule next sub-tick (60s) to count toward 60min
            tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_TICK_DELAY);
        }
        else if(s_adv_phase == ADV_PHASE_SLOW)
        {
            s_adv_slow_count++;
            if(s_adv_slow_count >= SLOW_PHASE_TICK_COUNT)
            {
                // SLOW → DEEP_SLEEP: stop advertising entirely, turn LED off.
                // Only BTN press or fingerprint touch can wake us back to FAST
                // (via adv_restart_fast_cycle which re-enables ADVERT_ENABLED).
                // FP sensor is already in wait-for-interrupt standby from the
                // last fp_power_off() — DEEP_SLEEP must not touch FP power; the
                // R559S wake-on-touch path depends on CMD_SLEEP+SENSOR_EN=LOW
                // having been done cleanly at the prior fp_power_off.
                PRINT("ADV: slow→deep-sleep (radio off, led off)\n");
                s_adv_phase = ADV_PHASE_DEEP_SLEEP;
                uint8_t adv_enable = FALSE;
                GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
#if HAS_RGB_LED
                led_stop();
#endif
            }
            else
            {
                // Still in slow phase, keep counting
                tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_TICK_DELAY);
            }
        }
        // ADV_PHASE_DEEP_SLEEP: no more timers, stay until BTN/TOUCH wake
        return (events ^ SLOW_ADV_EVT);
    }

    if(events & START_REPORT_EVT)
    {
        // No longer used for auto-send
        return (events ^ START_REPORT_EVT);
    }

    if(events & BUTTON_SCAN_EVT)
    {
        if(s_ota_active) return (events ^ BUTTON_SCAN_EVT);

        uint8_t btn = (BTN_ReadPin() == 0);  // Active low

        static uint8_t lastBtn = 0;
        static uint32_t pressStart = 0;
        // 0=idle/no-warning, 1=≥1s yellow warning, 2=≥3s red triggered (reboot pending)
        static uint8_t btnStage = 0;

        if(btn && !lastBtn)
        {
            // Press start
            pressStart = TMOS_GetSystemClock();
            btnStage = 0;
            // Restart fast advertising if in slow/deep-sleep phase
            if(s_adv_phase >= ADV_PHASE_SLOW) {
                adv_restart_fast_cycle();
            }
            // Fast polling while pressed (stage transitions)
            tmos_start_task(hidEmuTaskId, BUTTON_SCAN_EVT, BUTTON_SCAN_INTERVAL);
        }
        else if(btn && lastBtn && pressStart && btnStage < 2)
        {
            uint32_t elapsed = (TMOS_GetSystemClock() - pressStart) * 625 / 1000;
#if HAS_RGB_LED
            if(btnStage == 0 && elapsed >= 1000) {
                // Enter warning zone — yellow solid until release or 3s
                led_solid('Y', 0);
                btnStage = 1;
            }
#endif
            if(elapsed >= 3000)
            {
                btnStage = 2;
                PRINT("*** FACTORY RESET (long press) ***\n");
#if HAS_RGB_LED
                led_solid('R', 0);
#endif

                // Order requested: keys → bonds → fingerprints, then reboot.
                PRINT("Stage 1: clearing keys (password + ECDH + keystore)\n");
                immurok_security_factory_reset();

                PRINT("Stage 2: clearing BLE bonds\n");
                HidDev_SetParameter(HIDDEV_ERASE_ALLBONDS, 0, NULL);
                DelayMs(50);  // let GAP process the link drop

                PRINT("Stage 3: clearing fingerprint templates\n");
                if(fp_wake() == FP_OK) {
                    fp_clear_all();
                    fp_power_off();
                }

#if HAS_RGB_LED
                led_stop();  // turn off red before reboot
#endif
                DelayMs(50);
                SYS_ResetExecute();
                // never returns
            }
            tmos_start_task(hidEmuTaskId, BUTTON_SCAN_EVT, BUTTON_SCAN_INTERVAL);
        }
        else if(!btn && lastBtn && pressStart)
        {
            // Release
            uint32_t elapsed = (TMOS_GetSystemClock() - pressStart) * 625 / 1000;

            if(btnStage == 1) {
                // Released during 1-3s warning — cancel
                PRINT("Long-press cancelled (%dms)\n", (int)elapsed);
#if HAS_RGB_LED
                led_stop();
#endif
                if(s_pair_wait_button) {
                    // Pair-wait was active: long press abandons the pair.
                    s_pair_wait_button = 0;
                    tmos_stop_task(s_led_task_id, PAIR_BTN_TIMEOUT_EVT);
                    if(s_app_connected) {
                        uint8_t notif[2] = { IMMUROK_NTF_PAIR_BUTTON, 0x02 };  // cancel
                        ImmurokService_SendResponse(notif, 2);
                    }
                    PRINT("Pair button cancelled by long press\n");
                }
            } else if(elapsed < 1000 && s_pair_wait_button) {
                // PAIR_INIT is waiting for the user to confirm — short press
                // is the confirmation. Notify the App immediately so it can
                // update UI ("button pressed, key exchange running") then
                // start the ECDH key generation that PAIR_INIT skipped.
                PRINT("Short press: PAIR confirm\n");
                s_pair_wait_button = 0;
                tmos_stop_task(s_led_task_id, PAIR_BTN_TIMEOUT_EVT);
#if HAS_RGB_LED
                led_stop();
#endif
                uint8_t notif[2] = { IMMUROK_NTF_PAIR_BUTTON, 0x01 };  // confirmed
                ImmurokService_SendResponse(notif, 2);
                if(immurok_security_pair_init() == 0) {
                    tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                } else {
                    uint8_t err[2] = { IMMUROK_CMD_PAIR_INIT, SEC_ERR_INTERNAL };
                    ImmurokService_SendResponse(err, 2);
                }
            } else if(elapsed < 1000) {
                // Short press: full FP sensor reset to recover from stuck
                // states (e.g., previous power-off skipped PS_Sleep so the
                // sensor's touch-detect logic is latched). Sequence:
                //   1. If currently powered, force-cut VCC (fp_finish_off
                //      avoids the ~4s PS_Sleep block when sensor is hung).
                //   2. Reuse the existing s_touch_reset flow: power on,
                //      wait for 0x55 ready, send PS_Sleep, power off
                //      properly. That clean cycle un-latches touch detect.
                //   3. ADV restart from slow phase already handled at
                //      press-start.
                PRINT("Short press: FP touch reset + batt refresh\n");
                if(fp_is_powered()) {
                    fp_finish_off();
                }
                s_touch_reset = 1;
                s_pending_batt_check = 1;
                fp_power_on();
                s_fp_power_on_tick = RTC_GetCycle32k();
                tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);  // 30ms
#if HAS_RGB_LED
                led_solid('B', LED_FLASH_TICKS);  // brief blue confirm
#endif
            }
            pressStart = 0;
            btnStage = 0;
        }
        // else: idle, no timer needed — GPIO IRQ will trigger next event

        lastBtn = btn;
        return (events ^ BUTTON_SCAN_EVT);
    }

    if(events & TOUCH_SCAN_EVT)
    {
        if(s_ota_active) return (events ^ TOUCH_SCAN_EVT);
        // Ignore TOUCH events while a touch-reset is in flight: fp_power_on()
        // there briefly re-energizes the R599S DETECT line, generating a
        // spurious rising-edge IRQ. Without this guard the IRQ would steal
        // the FP_WAKE_DONE_EVT chain and start a fingerprint search before
        // the sensor's 0x55 ready, leaving everything in a broken state.
        if(s_touch_reset) return (events ^ TOUCH_SCAN_EVT);

        uint8_t touch = TOUCH_ReadPin() ? 1 : 0;

        if(touch)
        {
            // Restart fast advertising if in slow/deep-sleep phase
            if(s_adv_phase >= ADV_PHASE_SLOW)
            {
                adv_restart_fast_cycle();
            }

            if(s_enroll_active) {
                // Skip - enrollment handles touch internally
            }
            else if(s_search_active) {
                // Skip - search already in progress
            }
            else if(s_sleep_retry_active) {
                // Async PS_Sleep retry is in flight (after a no-match search
                // the user is still holding for). Don't start a new search —
                // we'd send GET_IMAGE while another task is sending PS_Sleep
                // on the same UART, corrupting both. Wait until the sleep
                // path finishes (cuts VCC, clears flag) and the user touches
                // again — that touch will refire the IRQ via the always-on
                // VCC rail. Re-poll touch GPIO in 30ms so we don't lose the
                // IRQ if the sleep completes mid-window.
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
            }
            else if(s_gate_preheat) {
                // Gate preheat in progress — FP_WAKE_DONE_EVT will start search
            }
            else if(s_wait_finger_lift) {
                // Wait for finger to be lifted before allowing new search
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);  // poll 30ms
            }
            else if(!s_ble_connected) {
                PRINT("Touch ignored: BLE not connected\n");
                s_wait_finger_lift = 1;
#if HAS_RGB_LED
                // Brief yellow, then restore blue advertising blink
                led_stop();
                led_on('Y');
                s_led_color = 'B';
                s_led_blink = 1;
                s_led_toggle = 0;
                s_led_on_ticks = LED_BLINK_TICKS;
                s_led_off_ticks = LED_BLINK_TICKS;
                tmos_start_task(s_led_task_id, LED_BLINK_EVT, LED_FLASH_TICKS);
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                // Power cycle FP module to reset latched touch GPIO
                s_touch_reset = 1;
                if(!fp_is_powered()) {
                    fp_power_on();
                    s_fp_power_on_tick = RTC_GetCycle32k();
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);
                } else {
                    // fp_power_off() internally handles CMD_SLEEP + ACK + GPIO cleanup.
                    // Calling fp_sleep() first sends a redundant CMD_SLEEP, and the
                    // second one blocks fp_recv_ack inside a nested TMOS_SystemProcess
                    // — risks stack overflow on CH592F's 512B stack.
                    fp_power_off();
                    s_touch_reset = 0;
                    tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 160);
                }
            }
            else if(!s_app_connected && s_pending_cmd == 0 && !immurok_security_has_pending_auth()) {
                // BLE connected but daemon/app has not subscribed to GATT
                // notifications — FP result cannot be delivered.
                PRINT("Touch ignored: app not connected\n");
                s_wait_finger_lift = 1;
#if HAS_RGB_LED
                led_solid('Y', LED_FLASH_TICKS);  // brief yellow flash
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                // Power on → wait ready → send sleep → power off.
                // The sensor latches touch HIGH until the module receives
                // a sleep command; without this reset, subsequent touches
                // won't generate a rising-edge IRQ.
                s_touch_reset = 1;
                if(!fp_is_powered()) {
                    fp_power_on();
                    s_fp_power_on_tick = RTC_GetCycle32k();
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);  // 30ms
                } else {
                    // Already powered — fp_power_off handles CMD_SLEEP+ACK+cleanup.
                    // Do NOT precede with fp_sleep — double CMD_SLEEP inside nested
                    // TMOS_SystemProcess overflows the 512B stack and reboots via WDT.
                    fp_power_off();
                    s_touch_reset = 0;
                    tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 160);
                }
            }
            else
            {
                // Block further touch events until finger is lifted
                s_wait_finger_lift = 1;
#if HAS_RGB_LED
                if(s_pending_cmd != 0 || immurok_security_has_pending_auth()) {
                    led_blink_start(fp_indicator_color());  // restore blink for gate mode (yellow if low batt)
                } else {
                    led_solid(fp_indicator_color(), 0);     // yellow if low batt, else green
                }
                // Arm 2s long-press lock-screen detector. The handler runs on
                // the LED task and re-checks TOUCH_ReadPin() before sending,
                // so a release before 2s naturally cancels (no explicit stop
                // needed except on disconnect, where the timer is purged).
                s_lock_pending = 1;
                tmos_start_task(s_led_task_id, LOCK_HOLD_EVT, LOCK_HOLD_TICKS);
#endif

                // Send CTRL key to wake host screen, but only when no
                // gated command is pending (KEY_SIGN, OTP, etc. don't need it)
                if(s_pending_cmd == 0 && !immurok_security_has_pending_auth()) {
                    hidEmuSendCtrlKey();
                    PRINT("CTRL sent (early wake)\n");
                }

                if(!fp_is_powered())
                {
                    PRINT("Waking FP module (async)...\n");
                    fp_power_on();
                    s_fp_power_on_tick = RTC_GetCycle32k();
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);  // 30ms (poll for 0x55)
                }
                else
                {
                    // Cancel stale WAKE_DONE from a prior touch's power-on to prevent
                    // it from firing on a module that this search may power off.
                    tmos_stop_task(hidEmuTaskId, FP_WAKE_DONE_EVT);
                    if(immurok_security_has_pending_auth()) {
                        PRINT("Starting FP auth...\n");
                    } else {
                        PRINT("Test FP search...\n");
                    }
                    tmos_set_event(hidEmuTaskId, FP_AUTH_EVT);
                }
            }
            // Done - next touch detected by GPIO IRQ
        }
        else
        {
            // No touch (IRQ was noise or finger already lifted).
            // Guard against R599S DETECT momentarily dipping LOW during
            // the sensor's internal processing while the finger is still
            // pressed: a stale touch=0 reading here would clear the lift
            // flag, then the next rising edge spawns a fresh FP_SEARCH —
            // observed as the green→blue→red cycling on long-hold
            // unregistered finger. While async PS_Sleep retry is in
            // flight the finger is provably still pressed (the sensor
            // hasn't acked PS_Sleep yet); keep the flag armed and let
            // the sleep-retry completion path drive the next state.
            if(!s_sleep_retry_active) {
                s_wait_finger_lift = 0;
            }
        }

        return (events ^ TOUCH_SCAN_EVT);
    }

    if(events & FP_WAKE_DONE_EVT)
    {
        if(s_ota_active) return (events ^ FP_WAKE_DONE_EVT);

        // Touch-reset path: module was powered only to send sleep and
        // reset the touch GPIO.  Wait for 0x55, send sleep, power off.
        if(s_touch_reset) {
            bool got_ready = false;
            int b;
            while((b = uart_rx_pop()) >= 0) {
                if((uint8_t)b == 0x55) { got_ready = true; break; }
            }
            if(!got_ready) {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                if(elapsed < 200) {
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 16);
                    return (events ^ FP_WAKE_DONE_EVT);
                }
                PRINT("Touch reset: 0x55 timeout (%dms)\n", (int)elapsed);
            }
            // fp_power_off handles CMD_SLEEP + ACK + GPIO cleanup atomically.
            // Calling fp_sleep first sends a redundant CMD_SLEEP whose ACK wait
            // runs uart_recv inside a nested TMOS_SystemProcess — the recursive
            // dispatch overflows CH592F's 512B stack and reboots the device
            // (observed 2026-05-11: PRINT output garbled mid-line, WDT reset).
            PRINT("Touch reset: power off\n");
            fp_power_off();
            s_touch_reset = 0;
            s_wait_finger_lift = 0;
            if(s_pending_batt_check) {
                s_pending_batt_check = 0;
                HidDev_BattForceUpdate();
            }
            tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 160);  // 100ms settle
            return (events ^ FP_WAKE_DONE_EVT);
        }

        if(s_gate_preheat) {
            // Gate preheat (AUTH_REQUEST etc.): time is available before user
            // touches sensor, so do full wake (0x55 + password verify).
            bool got_ready = false;
            int b;
            while((b = uart_rx_pop()) >= 0) {
                if((uint8_t)b == 0x55) { got_ready = true; break; }
            }
            if(!got_ready && !fp_is_password_verified()) {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                if(elapsed < 200) {
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 16);  // 10ms retry
                    return (events ^ FP_WAKE_DONE_EVT);
                }
                PRINT("FP 0x55 timeout (%dms), proceeding anyway\n", (int)elapsed);
                (void)elapsed;
            } else if(got_ready) {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                PRINT("FP 0x55 at %dms\n", (int)elapsed);
                (void)elapsed;
            }

            PRINT("FP_WAKE (gate): verifying password...\n");
            int ret = fp_start_verify();
            if(ret != FP_OK) {
                PRINT("FP wake failed: %d\n", ret);
                fp_power_off();
                return (events ^ FP_WAKE_DONE_EVT);
            }
            fp_reset_power_timer();

            s_gate_preheat = 0;
#if HAS_RGB_LED
            led_blink_start(fp_indicator_color());  // green / yellow on low batt
#elif HAS_FP_LED
            fp_led_flash(FP_LED_GREEN, 20, 0);  // continuous flash
#endif
#if HAS_R599S
            // R599S: DSP holds Touch IRQ in reset while VCC-MCU is on,
            // so GPIO touch interrupt won't fire. Start search immediately.
            PRINT("FP ready, starting search (R599S)\n");
            tmos_set_event(hidEmuTaskId, FP_AUTH_EVT);
#else
            // Wait for GPIO touch interrupt, then search.
            // Search timeout auto-retries (no GPIO wait between retries).
            PRINT("FP ready, waiting for touch...\n");
#endif
            return (events ^ FP_WAKE_DONE_EVT);
        }

        // Cold touch: finger is already on sensor — wait for 0x55 (module ready)
        // but skip password verify (~110ms saving). 0x55 typically arrives at 30-80ms.
        if(!fp_is_powered()) {
            // Module was powered off by a concurrent search (e.g., a second touch
            // fired FP_AUTH_EVT while this WAKE_DONE was pending). Bail out.
            PRINT("FP_WAKE (cold): module already off, skip\n");
            s_wait_finger_lift = 0;
            return (events ^ FP_WAKE_DONE_EVT);
        }
        {
            bool got_ready = false;
            int b;
            while((b = uart_rx_pop()) >= 0) {
                if((uint8_t)b == 0x55) { got_ready = true; break; }
            }
            if(!got_ready) {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                if(elapsed < 200) {
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 16);  // 10ms retry
                    return (events ^ FP_WAKE_DONE_EVT);
                }
                PRINT("FP_WAKE (cold): 0x55 timeout (%dms), proceeding\n", (int)elapsed);
            } else {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                PRINT("FP_WAKE (cold): 0x55 at %dms, skip verify\n", (int)elapsed);
                (void)elapsed;
            }
        }
        // Check if finger is still on sensor before starting search.
        // If user tapped and lifted quickly, skip search to avoid 1.5s blocking wait.
        // R599S: skip this check — DSP resets Touch IRQ on power-up, so pin reads LOW
        // even though finger is still on the sensor.
#if !HAS_R599S
        if(!TOUCH_ReadPin()) {
            PRINT("FP_WAKE (cold): finger already lifted, skip\n");
#if HAS_RGB_LED
            led_stop();
#endif
            s_wait_finger_lift = 0;
            fp_reset_power_timer();
            return (events ^ FP_WAKE_DONE_EVT);
        }
#endif

        fp_reset_power_timer();

        if(immurok_security_has_pending_auth()) {
            PRINT("Starting FP auth...\n");
        } else {
            PRINT("Test FP search...\n");
        }

#ifndef FP_USE_AUTO_IDENTIFY
        // Pipeline: kick off GET_IMAGE async here (saves the one-dispatch round
        // trip through FP_AUTH_EVT → FP_SEARCH_EVT case 0 substate 0) and let
        // FP_SEARCH_EVT case 0 substate 1 poll the parser for the response.
        // Guard: skip if search already active (race with concurrent FP_AUTH_EVT)
        if(s_search_active) {
            PRINT("FP_WAKE_DONE: search already active, skip pipeline\n");
            return (events ^ FP_WAKE_DONE_EVT);
        }
        {
            extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);

            s_search_active = 1;
            s_search_start_time = TMOS_GetSystemClock();
            s_search_state = 0;          // GET_IMAGE
            s_search_substate = 1;       // already sent — go straight to "poll"
            s_search_substate_start = TMOS_GetSystemClock();
            fp_parser_reset();
            fp_send_cmd(0x01, NULL, 0);  // CMD_GET_IMAGE
            tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
        }
#else
        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 1);  // 625us delay
#endif

        return (events ^ FP_WAKE_DONE_EVT);
    }

    if(events & FP_AUTH_EVT)
    {
        if(s_ota_active) return (events ^ FP_AUTH_EVT);

        // Module should already be awake at this point
        if(!fp_is_powered())
        {
            PRINT("FP_AUTH_EVT: module not powered!\n");
            return (events ^ FP_AUTH_EVT);
        }

        // Reset power-off timer
        fp_reset_power_timer();

        // Start non-blocking search state machine
        if(!s_search_active)
        {
            s_search_active = 1;
            s_search_substate = 0;  // fresh search — parser state is clean
            s_search_start_time = TMOS_GetSystemClock();
#ifdef FP_USE_AUTO_IDENTIFY
            PRINT("FP_AUTH_EVT: starting AutoIdentify search...\n");
#else
            PRINT("FP_AUTH_EVT: starting manual 3-step search...\n");
            s_search_state = 0;  // Start from GET_IMAGE
#endif
            // Yield briefly to let TMOS process BLE events.
            // uart_recv already kicks TMOS every ~15ms, so 1.25ms is sufficient.
            tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 2);  // 1.25ms yield
        }

        return (events ^ FP_AUTH_EVT);
    }

    if(events & FP_SEARCH_EVT)
    {
        if(s_ota_active) return (events ^ FP_SEARCH_EVT);
        // Fingerprint search — two modes selected at compile time:
        // FP_USE_AUTO_IDENTIFY: PSAutoIdentify (0x32), single blocking command (~300ms)
        // Manual: 3-step state machine GET_IMAGE→GEN_CHAR→SEARCH with TMOS yields

        extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int fp_recv_ack(uint8_t *ack, uint8_t *data, uint16_t *len, uint32_t timeout_ms);

        if(!s_search_active)
        {
            return (events ^ FP_SEARCH_EVT);
        }

        // Refresh the 500ms idle watchdog on every search iteration. Without
        // this, R599S's worst-case 600ms full identify time (per datasheet)
        // outruns FP_POWER_OFF_DELAY and FP_POWER_OFF_EVT fires mid-SEARCH,
        // triggering fp_async_off_start. PS_Sleep then collides with the
        // in-flight SEARCH response on UART1, parser parses the interleaved
        // bytes as a malformed packet (e.g. raw_slot=96 score=32 observed
        // 2026-05-19). MIN_SCORE catches that garbage, but the sensor is
        // left in a bad state. case 3 (WAIT_LIFT) already does this at its
        // own top; case 0/1/2 were missing the call.
        fp_reset_power_timer();

        uint8_t ack = 0xFF;
        uint16_t raw_page_id = 0;
        uint16_t match_score = 0;
        int search_done = 0;  // 1 = search produced a final result

#ifdef FP_USE_AUTO_IDENTIFY
        // === PSAutoIdentify: single command, module handles entire pipeline ===
        // uart_recv calls TMOS_SystemProcess every ~15ms internally to keep BLE alive.
        {
            fp_search_result_t ai_result;
            int ret = fp_auto_identify(&ai_result);
            WWDG_SetCounter(0);
#if HAS_RGB_LED
            // Gate/auth mode: keep green blink for retry indication
            // (success/failure handlers set their own LED state)
            if(!(s_pending_cmd != 0 || immurok_security_has_pending_auth())) {
                led_stop();  // Non-gate: turn off green LED
            }
#endif
            uint32_t search_ms = (TMOS_GetSystemClock() - s_search_start_time) * 625 / 1000;

            if(ret == FP_OK) {
                ack = 0x00;
                raw_page_id = ai_result.page_id;
                match_score = ai_result.match_score;
                search_done = 1;
                PRINT("AutoIdentify matched in %dms\n", (int)search_ms);
                // Same firmware-side score floor as the manual SEARCH path.
                if(match_score < FP_MIN_MATCH_SCORE) {
                    PRINT("AutoIdentify score %d < %d, rejecting\n",
                          match_score, FP_MIN_MATCH_SCORE);
                    ack = FP_ACK_NOT_FOUND;
                    raw_page_id = 0;
                }
            } else if(ret == FP_ERR_NOT_FOUND) {
                ack = FP_ACK_NOT_FOUND;
                search_done = 1;
                PRINT("AutoIdentify no match (%dms)\n", (int)search_ms);
            } else {
                // Timeout / error — same handling as manual search timeout
                PRINT("AutoIdentify timeout (%dms)\n", (int)search_ms);
                s_search_active = 0;
                s_wait_finger_lift = 1;
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
                if(s_pending_cmd != 0)
                {
                    uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                    {
                        PRINT("AutoIdentify timeout + gate expired (%dms)\n", (int)gate_elapsed);
#if HAS_RGB_LED
                        led_blink_start('R');
                        tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#elif HAS_FP_LED
                        fp_led_flash(FP_LED_RED, 15, 3);
#endif
                        s_pending_cmd = 0;
                        s_pending_payload_len = 0;
                        s_gate_fail_count = 0;
                        uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                        ImmurokService_SendResponse(rspBuf, 1);
                        fp_power_off();
                    }
                    else
                    {
                        PRINT("AutoIdentify timeout (gate pending, retrying)\n");
                        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 480);  // 300ms — see gate-retry note above
                    }
                }
                else if(immurok_security_has_pending_auth())
                {
                    uint32_t auth_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(auth_elapsed > FP_GATE_TIMEOUT_MS) {
                        PRINT("Auth timeout (%dms)\n", (int)auth_elapsed);
#if HAS_RGB_LED
                        led_blink_start('R');
                        tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#endif
                        uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                        ImmurokService_SendResponse(rspBuf, 1);
                        immurok_security_auth_cancel();
                        fp_power_off();
                    } else {
                        PRINT("AutoIdentify timeout (auth pending, retrying)\n");
                        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 480);  // 300ms — see gate-retry note above
                    }
                }
                else
                {
#if HAS_RGB_LED
                    led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 25, 1);
#endif
                }
                fp_reset_power_timer();
                return (events ^ FP_SEARCH_EVT);
            }
        }
#else // !FP_USE_AUTO_IDENTIFY
        // === Manual 3-step search: GET_IMAGE → GEN_CHAR → SEARCH ===
        // Each state does send+recv together (UART FIFO is only 8 bytes)
        // State 3 = post-match finger-lift polling (not subject to search timeout)

        // Check per-search timeout (finger not detected in time)
        // Skip for state 3 (finger lift uses power-off timer)
        // Skip for gate/auth mode — use the gate's own 25s timeout instead of 1.5s
        // to avoid wasteful search restarts that consume BLE supervision budget.
        if(s_search_state <= 2
           && s_pending_cmd == 0 && !immurok_security_has_pending_auth())
        {
            uint32_t elapsed = (TMOS_GetSystemClock() - s_search_start_time) * 625 / 1000;
            if(elapsed > FP_SEARCH_TIMEOUT_MS)
            {
                s_search_active = 0;
                s_wait_finger_lift = 1;
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
                if(s_pending_cmd != 0)
                {
                    uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                    {
                        PRINT("FP search timeout + gate expired (%dms), clearing cmd 0x%02X\n",
                              (int)gate_elapsed, s_pending_cmd);
#if HAS_RGB_LED
                        led_blink_start('R');
                        tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#elif HAS_FP_LED
                        fp_led_flash(FP_LED_RED, 15, 3);
#endif
                        s_pending_cmd = 0;
                        s_pending_payload_len = 0;
                        s_gate_fail_count = 0;
                        uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                        ImmurokService_SendResponse(rspBuf, 1);
                        fp_power_off();
                    }
                    else
                    {
                        PRINT("FP search timeout (gate pending, retrying)\n");
#if HAS_RGB_LED
                        led_blink_start(fp_indicator_color());
#endif
                        // Retry search immediately — GET_IMAGE will detect finger
                        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 480);  // 300ms — see gate-retry note above
                    }
                }
                else if(immurok_security_has_pending_auth())
                {
                    uint32_t auth_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(auth_elapsed > FP_GATE_TIMEOUT_MS) {
                        PRINT("Auth timeout (%dms)\n", (int)auth_elapsed);
#if HAS_RGB_LED
                        led_blink_start('R');
                        tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#endif
                        uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                        ImmurokService_SendResponse(rspBuf, 1);
                        immurok_security_auth_cancel();
                        fp_power_off();
                    } else {
                        PRINT("FP search timeout (auth pending, retrying)\n");
#if HAS_RGB_LED
                        led_blink_start(fp_indicator_color());
#endif
                        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 480);  // 300ms — see gate-retry note above
                    }
                }
                else
                {
                    PRINT("FP search timeout\n");
#if HAS_RGB_LED
                    led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 25, 1);
#endif
#if HAS_R599S
                    // R599S DETECT can latch HIGH after rapid touches: GPIO
                    // reads "still touching" forever, TOUCH_SCAN_EVT polling
                    // never sees the lift, s_wait_finger_lift stays 1, and
                    // the next 100 touches are silently ignored. If the pin
                    // is still high after a search timeout, the user almost
                    // certainly lifted their finger — power-cycle to break
                    // the latch and re-arm the touch path.
                    if(TOUCH_ReadPin())
                    {
                        PRINT("DETECT latched after timeout, power-cycling FP\n");
                        fp_power_off();
                        s_wait_finger_lift = 0;
                    }
#endif
                }
                fp_reset_power_timer();
                return (events ^ FP_SEARCH_EVT);
            }
        }

        {
            int ret;
            switch(s_search_state)
            {
            case 0:  // GET_IMAGE
                if(s_search_substate == 0) {
                    fp_parser_reset();
                    fp_send_cmd(0x01, NULL, 0);
                    s_search_substate = 1;
                    s_search_substate_start = TMOS_GetSystemClock();
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                    return (events ^ FP_SEARCH_EVT);
                }
                ret = fp_try_parse_packet(&ack, NULL, NULL);
                WWDG_SetCounter(0);
                if(ret == FP_ERR_TIMEOUT) {
                    uint32_t elapsed_ms = ((TMOS_GetSystemClock() - s_search_substate_start) * 625) / 1000;
                    if(elapsed_ms < FP_STATE_GET_IMAGE_TMO_MS) {
                        tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                        return (events ^ FP_SEARCH_EVT);
                    }
                    // 400ms with no response — sensor is unresponsive. Do NOT
                    // re-send here: resending resets the sensor's pending
                    // command and makes the next response even later. Treat
                    // as "no finger" — user mode goes to standby, gate/auth
                    // mode retries via the existing ack=0x02 handler.
                    PRINT("GET_IMAGE sensor tmo (%dms)\n", (int)elapsed_ms);
                    ack = 0x02;
                    ret = FP_OK;
                }
                if(ret == FP_ERR_FAIL) {
                    PRINT("GET_IMAGE parse fail (ring=%d)\n", (int)uart_rx_available());
                }
                s_search_substate = 0;
                if(ret == FP_OK && ack == 0x00)
                {
                    // Image captured successfully
#if HAS_RGB_LED
                    // Gate mode: keep green blink during search cycle
                    if(!(s_pending_cmd != 0 || immurok_security_has_pending_auth())) {
                        led_solid('B', 0);  // Processing → blue
                    }
#endif
                    s_search_state = 1;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 2);  // 1.25ms yield
                }
                else if(ret == FP_OK && ack == 0x02)
                {
                    // No finger detected
                    if(s_pending_cmd != 0 || immurok_security_has_pending_auth()) {
                        // Gate/auth mode: check overall gate timeout
                        uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                        if(gate_elapsed > FP_GATE_TIMEOUT_MS) {
                            PRINT("GET_IMAGE: gate timeout (%dms)\n", (int)gate_elapsed);
                            s_search_active = 0;
#if HAS_FP_LED
                            fp_led_flash(FP_LED_RED, 15, 3);
#elif HAS_RGB_LED
                            led_blink_start('R');
                            tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#endif
                            if(s_pending_cmd != 0) {
                                s_pending_cmd = 0;
                                s_pending_payload_len = 0;
                                s_gate_fail_count = 0;
                            }
                            if(immurok_security_has_pending_auth()) {
                                immurok_security_auth_cancel();
                            }
                            uint8_t tmoBuf[1] = { SEC_ERR_TIMEOUT };
                            ImmurokService_SendResponse(tmoBuf, 1);
                            fp_power_off();
                        } else {
                            tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms yield
                        }
                    } else {
                        // User-initiated: 400ms GET_IMAGE window already gave
                        // the sensor time to warm up. ack=0x02 (or the
                        // synthesized-from-timeout 0x02) at this point means
                        // no finger on the pad → standby. Sensor reports
                        // "no finger" → user has lifted, cancel any armed
                        // long-press lock timer.
                        PRINT("GET_IMAGE: no finger (false touch), standby\n");
                        s_search_active = 0;
                        s_wait_finger_lift = 0;
#if HAS_RGB_LED
                        s_lock_pending = 0;
                        tmos_stop_task(s_led_task_id, LOCK_HOLD_EVT);
                        led_solid('R', 400);  // red 0.25s
#endif
                        fp_power_off();
                    }
                }
                else
                {
                    // Read failure (0x01) or comm error — retry
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms yield
                }
                return (events ^ FP_SEARCH_EVT);

            case 1:  // GEN_CHAR: async send + poll (~100ms total wall time)
            {
                if(s_search_substate == 0) {
                    uint8_t params[1] = { 1 };
                    fp_parser_reset();
                    fp_send_cmd(0x02, params, 1);  // CMD_IMAGE2TZ
                    s_search_substate = 1;
                    s_search_substate_start = TMOS_GetSystemClock();
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                    return (events ^ FP_SEARCH_EVT);
                }
                ret = fp_try_parse_packet(&ack, NULL, NULL);
                WWDG_SetCounter(0);
                if(ret == FP_ERR_TIMEOUT) {
                    uint32_t elapsed_ms = ((TMOS_GetSystemClock() - s_search_substate_start) * 625) / 1000;
                    if(elapsed_ms < FP_STATE_GEN_CHAR_TMO_MS) {
                        tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                        return (events ^ FP_SEARCH_EVT);
                    }
                    // Response timed out — treat as failure, retry from GET_IMAGE.
                    PRINT("FP gen_char timeout\n");
                    s_search_substate = 0;
                    s_search_state = 0;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);
                    return (events ^ FP_SEARCH_EVT);
                }
                s_search_substate = 0;
                if(ret == FP_OK && ack == 0x00)
                {
                    s_search_state = 2;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 2);  // 1.25ms yield
                }
                else
                {
                    PRINT("FP gen_char failed\n");
                    s_search_state = 0;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms retry
                }
                return (events ^ FP_SEARCH_EVT);
            }

            case 2:  // SEARCH: async send + poll (~200ms total wall time)
            {
                if(s_search_substate == 0) {
                    uint8_t search_params[5];
                    search_params[0] = 1;
                    search_params[1] = 0;
                    search_params[2] = 0;
                    search_params[3] = 0;
                    search_params[4] = FP_SLOT_MAX;
                    fp_parser_reset();
                    fp_send_cmd(0x04, search_params, 5);  // CMD_SEARCH
                    s_search_substate = 1;
                    s_search_substate_start = TMOS_GetSystemClock();
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                    return (events ^ FP_SEARCH_EVT);
                }
                uint8_t search_result[4];
                uint16_t result_len = 4;
                ret = fp_try_parse_packet(&ack, search_result, &result_len);
                WWDG_SetCounter(0);
                if(ret == FP_ERR_TIMEOUT) {
                    uint32_t elapsed_ms = ((TMOS_GetSystemClock() - s_search_substate_start) * 625) / 1000;
                    if(elapsed_ms < FP_STATE_SEARCH_TMO_MS) {
                        tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                        return (events ^ FP_SEARCH_EVT);
                    }
                    // No response within 200ms — treat as comm error.
                    // ack stays 0xFF → falls through as no-match in shared handler.
                    ack = 0xFF;
                }
                s_search_substate = 0;
                if(ret == FP_OK && ack == 0x00) {
                    raw_page_id = (search_result[0] << 8) | search_result[1];
                    match_score = (search_result[2] << 8) | search_result[3];
                    // Defense-in-depth: sensor said match, but if score is
                    // below the firmware floor, treat as no-match. Catches
                    // chips that defaulted to ScoreLevel < 5 before fp_init
                    // could write the strict level (e.g. on first boot
                    // before the WriteReg lands).
                    if(match_score < FP_MIN_MATCH_SCORE) {
                        PRINT("FP score %d < %d, rejecting (raw_slot=%d)\n",
                              match_score, FP_MIN_MATCH_SCORE, raw_page_id);
                        ack = FP_ACK_NOT_FOUND;
                        raw_page_id = 0;
                    }
                }
                search_done = 1;
                break;  // fall through to shared result handling
            }

            case 3:  // WAIT_LIFT: async poll GET_IMAGE until finger removed
            {
                // Reset the FP idle timer on every WAIT_LIFT iteration. The
                // 10s FP_POWER_OFF_DELAY would otherwise fire mid-hold and
                // call fp_async_off_start with the finger still on, which
                // gets stuck because the sensor is silent to PS_Sleep while
                // touched. Keeping the timer pushed forward means the only
                // way out of WAIT_LIFT is the lift-detected branch (or the
                // 60s hard cap below).
                fp_reset_power_timer();

                // Absolute timeout: prevent infinite loop if sensor truly
                // stuck. 60s is way past any plausible user hold; if we hit
                // it, the sensor isn't responding to GET_IMAGE either.
                uint32_t lift_elapsed = (TMOS_GetSystemClock() - s_search_start_time) * 625 / 1000;
                if(lift_elapsed > 60000) {
                    // 60s hard cap for a genuinely stuck sensor. Use
                    // fp_finish_off (no PS_Sleep) — synchronous fp_power_off
                    // blocks ~4s on no-ack while the BLE supervision window
                    // expires. The sensor is already non-functional at this
                    // point; cutting VCC at least frees our state machine.
                    PRINT("WAIT_LIFT hard timeout (%dms), force off\n",
                          (int)lift_elapsed);
                    s_search_active = 0;
                    s_search_substate = 0;
                    s_wait_finger_lift = 0;
                    s_wait_lift_no_match = 0;
                    fp_finish_off();
                    return (events ^ FP_SEARCH_EVT);
                }
                // No-match soft cap: 1.4.0 commit documented R599S DETECT-
                // latch on long unregistered-finger holds with sustained
                // ~50Hz GET_IMAGE polling. By the time this fires, the
                // long-press lock has already triggered (1s) and the user
                // is no longer waiting on lift detection — switch to the
                // async PS_Sleep path which is quiet on the UART.
                if(s_wait_lift_no_match
                   && lift_elapsed > FP_WAIT_LIFT_NOMATCH_SOFT_TMO_MS) {
                    PRINT("WAIT_LIFT no-match soft cap (%dms), async off\n",
                          (int)lift_elapsed);
                    s_wait_lift_no_match = 0;
                    s_search_active = 0;
                    s_search_substate = 0;
                    s_wait_finger_lift = 1;  // block re-trigger until lift
#if HAS_RGB_LED
                    // LOCK_HOLD has already fired (1s) and either flashed
                    // white-then-off or hit its suppressed-cleanup path —
                    // LED should be off. Defensive clear in case anything
                    // re-armed the persistent red in between.
                    led_stop();
#endif
                    fp_async_off_start();
                    tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
                    return (events ^ FP_SEARCH_EVT);
                }
                if(s_search_substate == 0) {
                    fp_parser_reset();
                    fp_send_cmd(0x01, NULL, 0);
                    s_search_substate = 1;
                    s_search_substate_start = TMOS_GetSystemClock();
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                    return (events ^ FP_SEARCH_EVT);
                }
                ret = fp_try_parse_packet(&ack, NULL, NULL);
                WWDG_SetCounter(0);
                if(ret == FP_ERR_TIMEOUT) {
                    uint32_t elapsed_ms = ((TMOS_GetSystemClock() - s_search_substate_start) * 625) / 1000;
                    if(elapsed_ms < FP_STATE_WAIT_LIFT_TMO_MS) {
                        tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, FP_SEARCH_POLL_TICKS);
                        return (events ^ FP_SEARCH_EVT);
                    }
                    // Response timed out — retry after a longer idle (finger still on).
                    s_search_substate = 0;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms
                    return (events ^ FP_SEARCH_EVT);
                }
                s_search_substate = 0;
                if(ret == FP_OK && ack == 0x02) {
                    s_lift_confirm++;
                    if(s_lift_confirm < FP_WAIT_LIFT_CONFIRM_NEEDED) {
                        // Need another consecutive 0x02 to confirm lift.
                        tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms
                        return (events ^ FP_SEARCH_EVT);
                    }
                    PRINT("Finger lifted (debounced %d)\n", s_lift_confirm);
                    s_lift_confirm = 0;
                    s_search_active = 0;
                    s_wait_finger_lift = 0;
                    s_wait_lift_no_match = 0;
#if HAS_RGB_LED
                    // Reliable lift signal — cancel pending long-press timer
                    // and clear the persistent blue match indicator (set in
                    // the non-gate ack==0x00 branch above).
                    s_lock_pending = 0;
                    tmos_stop_task(s_led_task_id, LOCK_HOLD_EVT);
                    led_stop();
#endif
                    if(!s_enroll_active) {
                        fp_power_off();
#if HAS_R599S
                        // R599S can latch DETECT HIGH if PS_Sleep raced with
                        // the just-completed GET_IMAGE — sensor's MCU state
                        // corrupts on VCC cut and next touch IRQ never fires.
                        // If DETECT is still high after the power-off path
                        // returned, the chip is stuck; trigger the touch-reset
                        // sequence (power on → 0x55 → PS_Sleep → off) used by
                        // the button-recovery path.
                        if(TOUCH_ReadPin()) {
                            PRINT("DETECT latched post lift, touch-reset\n");
                            s_touch_reset = 1;
                            fp_power_on();
                            s_fp_power_on_tick = RTC_GetCycle32k();
                            tmos_start_task(hidEmuTaskId,
                                            FP_WAKE_DONE_EVT, 48);  // 30ms
                        }
#endif
                    } else {
                        fp_reset_power_timer();  // keep module alive for enrollment
                    }
                } else {
                    // Anything other than ack=0x02 → still touching (or comm
                    // error) → reset debounce counter so a spurious 0x02
                    // followed by 0x00 doesn't accidentally count as 2-in-a-row.
                    s_lift_confirm = 0;
                    tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms
                }
                return (events ^ FP_SEARCH_EVT);
            }

            default:
                s_search_active = 0;
                s_wait_finger_lift = 1;
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
                return (events ^ FP_SEARCH_EVT);
            }
        }
#endif // FP_USE_AUTO_IDENTIFY

        // ================================================================
        // Shared result handling (both AUTO_IDENTIFY and manual case 2)
        // do-while(0) preserves break semantics from original switch-case
        // ================================================================
        if(!search_done) {
            return (events ^ FP_SEARCH_EVT);
        }

        do {
            if(ack == 0x00)
            {
                // Ignore duplicate matches while ECC is pending/running
                if(s_long_op_busy) {
                    PRINT("FP match ignored: ECC busy\n");
                    fp_reset_power_timer();
                    break;
                }

                // Defense in depth: if the cached bitmap says no fingerprint
                // is enrolled but the module reported ack=0x00 with some
                // page_id, treat it as a hardware glitch. The downstream
                // proactive-match path would otherwise sign and emit a 0x21
                // unlock notification, letting the App unlock the screen
                // even though no legitimate user fingerprint exists. Drop
                // it; ENROLL/DELETE keep g_cached_fp_bitmap accurate.
                if(g_cached_fp_bitmap == 0) {
                    PRINT("FP match ignored: no fingerprint enrolled (raw_slot=%d)\n", raw_page_id);
                    fp_reset_power_timer();
                    break;
                }

                // Convert physical slot to user finger ID
                uint16_t page_id = FP_FINGER_ID(raw_page_id);
#if HAS_RGB_LED
                // Gate / pending-auth: brief green flash bridges from the
                // pre-match green-blink state to the upcoming blue "computing"
                // (KEY_SIGN/KEY_GENERATE/PAIR_*) — the EXEC dispatch delay is
                // timed to 200ms so the flash completes before blue starts.
                // Non-gate proactive match: hold blue solid so the long-press
                // window has a visible "match recognized, holding" indicator.
                // WAIT_LIFT lift detection clears it on early release;
                // LOCK_HOLD_EVT white-flash overrides it at 1s.
                if(s_pending_cmd != 0 || immurok_security_has_pending_auth()) {
                    led_solid(fp_indicator_color(), LED_FLASH_TICKS);  // green/yellow flash before blue compute
                } else {
                    led_solid('B', 0);  // blue stays until lift or lock white-flash
                }
#elif HAS_FP_LED
                fp_led_off();
#endif
                s_gate_fail_count = 0;
                PRINT("FP matched! raw_slot=%d, finger_id=%d, score=%d\n", raw_page_id, page_id, match_score);

                // Gate 场景的 LOCK_HOLD 抑制: pending_cmd / pending_auth 紧接着
                // 会在 priority 1/2 分支被清零, 1s 后 LOCK_HOLD_EVT fire 时
                // in_gate 检查全 false 会误触发锁屏 (DELETE_FP / KEY_OTP /
                // KEY_DELETE / AUTH_REQUEST 都漏抑制).
                // 仅在确实有 gate 时清, 普通解锁屏幕 (priority 3 proactive
                // match) 的长按是 by design 的锁屏路径, 不在此抑制.
                if(s_pending_cmd != 0 || immurok_security_has_pending_auth()) {
                    s_lock_pending = 0;
                    tmos_stop_task(s_led_task_id, LOCK_HOLD_EVT);
                }

                // Expire stale pending command (gate timeout)
                if(s_pending_cmd != 0)
                {
                    uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                    {
                        PRINT("Pending cmd 0x%02X expired (%dms), clearing\n", s_pending_cmd, (int)gate_elapsed);
                        s_pending_cmd = 0;
                        s_pending_payload_len = 0;
                        fp_power_off();
                    }
                }

                // Priority 1: Execute pending fingerprint-gated command
                // Skip if ECC already deferred (prevents duplicate sign from rapid touches)
                if(s_pending_cmd != 0 && !s_long_op_busy)
                {
                    uint8_t cmd = s_pending_cmd;
                    s_pending_cmd = 0;
                    s_fp_gate_last[fp_gate_cat_for_cmd(cmd)] = TMOS_GetSystemClock();
                    PRINT("Executing pending cmd 0x%02X after FP verify (cooldown set)\n", cmd);

                    uint8_t rspBuf[2];
                    switch(cmd) {
                    case IMMUROK_CMD_ENROLL_START:
                        // Stop search WAIT_LIFT polling — avoid concurrent UART ops
                        s_search_active = 0;
                        tmos_stop_task(hidEmuTaskId, FP_SEARCH_EVT);
                        s_enroll_page_id = s_pending_payload[0];
                        s_enroll_step = 0;
                        s_enroll_substate = 0;
                        s_enroll_capture = 0;
                        s_enroll_active = 1;
                        tmos_set_event(hidEmuTaskId, FP_ENROLL_EVT);
                        rspBuf[0] = IMMUROK_RSP_OK;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    case IMMUROK_CMD_DELETE_FP:
                    {
                        // Send gate-approved RSP_OK so daemon's gate resolves.
                        // Actual delete deferred to FP_GATE_EXEC_EVT (~400ms blocking).
                        // Use s_deferred_delete_id instead of restoring s_pending_cmd
                        // to avoid race with concurrent FP match clearing s_pending_cmd.
                        rspBuf[0] = IMMUROK_RSP_OK;
                        ImmurokService_SendResponse(rspBuf, 1);
                        s_deferred_delete_id = s_pending_payload[0];
                        tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 16);  // 10ms yield
                        break;
                    }
                    case IMMUROK_CMD_FACTORY_RESET:
                    {
                        // Clear all fingerprints
                        if(fp_ensure_ready() == FP_OK) {
                            fp_clear_all();
                        }
                        g_cached_fp_bitmap = 0;
                        // Clear security data (pairing keys, password)
                        immurok_security_factory_reset();
                        // Send OK response FIRST, then defer bond erase + reboot
                        // (ERASE_ALLBONDS terminates link immediately — response would be lost)
                        rspBuf[0] = IMMUROK_RSP_OK;
                        ImmurokService_SendResponse(rspBuf, 1);
                        s_factory_reset_pending = 1;
                        tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, 320);  // 200ms
                        break;
                    }
                    case IMMUROK_CMD_KEY_DELETE:
                    {
                        uint8_t kcat = s_pending_payload[0];
                        uint8_t kidx = s_pending_payload[1];
                        rspBuf[0] = (immurok_keystore_delete(kcat, kidx) == 0)
                                    ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_KEY_COMMIT:
                    {
                        uint8_t kcat = s_pending_payload[0];
                        uint8_t kidx = s_pending_payload[1];
                        rspBuf[0] = (immurok_keystore_commit(kcat, kidx) == 0)
                                    ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_KEY_SIGN:
                    {
                        // Notify App: fingerprint approved, now signing
                        uint8_t fpApproved[1] = { 0x10 };  // FP_APPROVED
                        ImmurokService_SendResponse(fpApproved, 1);
                        // Defer sign to TMOS event (watchdog callback calls
                        // TMOS_SystemProcess during ~2s ECC to keep BLE alive).
                        // 320 ticks = 200ms — matches LED_FLASH_TICKS so the
                        // green "match OK" flash finishes before the blue
                        // "computing" blink starts in the EXEC handler.
                        s_pending_cmd = IMMUROK_CMD_KEY_SIGN;  // restore (cleared above)
                        s_long_op_busy = 1;  // Lock out duplicate FP matches
                        tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 320);
                        break;
                    }
                    case IMMUROK_CMD_KEY_GENERATE:
                    {
                        // Defer keygen to TMOS event (~2s ECC computation)
                        uint8_t fpApproved[1] = { 0x10 };
                        ImmurokService_SendResponse(fpApproved, 1);
                        s_pending_cmd = IMMUROK_CMD_KEY_GENERATE;  // restore
                        s_long_op_busy = 1;  // Lock out duplicate FP matches
                        tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 320);  // 200ms
                        break;
                    }
                    case IMMUROK_CMD_KEY_OTP_GET:
                    {
                        uint8_t kidx = s_pending_payload[0];
                        uint32_t ts = (uint32_t)s_pending_payload[1]
                                    | ((uint32_t)s_pending_payload[2] << 8)
                                    | ((uint32_t)s_pending_payload[3] << 16)
                                    | ((uint32_t)s_pending_payload[4] << 24);
                        // Adjust timestamp by elapsed time since gate started
                        uint32_t elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000000;
                        ts += elapsed;
                        uint8_t code[6];
                        if(immurok_keystore_totp(kidx, ts, code) == 0) {
                            uint8_t rsp7[7];
                            rsp7[0] = IMMUROK_RSP_OK;
                            memcpy(&rsp7[1], code, 6);
                            ImmurokService_SendResponse(rsp7, 7);
                        } else {
                            rspBuf[0] = SEC_ERR_INTERNAL;
                            ImmurokService_SendResponse(rspBuf, 1);
                        }
                        break;
                    }
                    case IMMUROK_CMD_PAIR_INIT:
                    {
                        if(immurok_security_pair_init() == 0) {
                            // Delay matches LED_FLASH_TICKS so green-flash
                            // completes before EXEC starts the blue blink.
                            tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 320);
                            // Response sent from TMOS event handler
                        } else {
                            rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                            rspBuf[1] = SEC_ERR_INTERNAL;
                            ImmurokService_SendResponse(rspBuf, 2);
                        }
                        break;
                    }
                    default:
                        rspBuf[0] = IMMUROK_RSP_UNKNOWN_CMD;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                }
                // Priority 2: Pending auth request
                else if(immurok_security_has_pending_auth())
                {
                    // Refresh ONLY the AUTH cooldown — never KEYSTORE/ADMIN.
                    // Original 1.2.6 design said "do not set cooldown" to
                    // prevent sudo from auto-granting KEY_SIGN access; that
                    // intent is preserved (we only touch FP_CAT_AUTH). But
                    // not setting AUTH's own cooldown made 1.2.12's
                    // "API KEY_READ accepts AUTH or KEYSTORE" useless —
                    // s_fp_gate_last[FP_CAT_AUTH] stayed 0 forever, so a
                    // CLI flow that does AUTH_REQUEST → readKeyEntry(.api)
                    // would still see WAIT_FP on the secret chunk.
                    s_fp_gate_last[FP_CAT_AUTH] = TMOS_GetSystemClock();
                    uint8_t rspBuf[1];
                    rspBuf[0] = SEC_OK;
                    ImmurokService_SendResponse(rspBuf, 1);
                    PRINT("Auth OK response sent (AUTH cooldown set)\n");
                    immurok_security_auth_cancel();
                }
                // Priority 3: Proactive match - send signed 0x21 notification
                else
                {
                    PRINT("FP match OK (no pending auth) - sending signed notify\n");

                    // Build signed notification: [0x21][page_id:2B][hmac:8B] = 11 bytes
                    int notify_len = immurok_security_sign_fp_match(page_id, s_fp_notify_data);
                    if(notify_len < 0) {
                        PRINT("Not paired, cannot send signed notify\n");
                        fp_power_off();
                        break;
                    }
                    s_fp_notify_len = notify_len;

                    // Send notification. Mark pending until App ACKs (0x22).
                    // If GATT is disconnected, notification is lost — device will
                    // re-send on next connection (see GAPROLE_CONNECTED handler).
                    ImmurokService_SendResponse(s_fp_notify_data, s_fp_notify_len);
                    s_fp_notify_pending = 1;
                    s_fp_notify_start_time = TMOS_GetSystemClock();
                    PRINT("FP notify sent (%d bytes), pending ACK\n", s_fp_notify_len);
                }
            }
            else
            {
                PRINT("FP no match (ack=0x%02X)\n", ack);
                uint8_t in_gate = (s_pending_cmd != 0 || immurok_security_has_pending_auth());

                // Red LED for failure indication (0.25s)
#if HAS_RGB_LED
                if(in_gate) {
                    // Gate mode: brief red, then restore green/yellow blink for retry
                    led_stop();
                    led_on('R');
                    s_led_color = fp_indicator_color();  // yellow when battery low, else green
                    s_led_blink = 1;
                    s_led_toggle = 0;
                    tmos_start_task(s_led_task_id, LED_BLINK_EVT, 400);  // 0.25s red then green/yellow blink
                } else {
                    // Hold red solid until LOCK_HOLD_EVT white-flash (or
                    // lift-cleanup via TOUCH_SCAN_EVT / suppressed path) —
                    // the persistent red is the "no match, still holding"
                    // indicator that bridges to the long-press lock.
                    led_solid('R', 0);
                }
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif

                // Track gate failure count
                if(in_gate)
                {
                    s_gate_fail_count++;
                    PRINT("FP gate fail count: %d/%d\n", s_gate_fail_count, FP_GATE_MAX_RETRIES);

                    if(s_gate_fail_count >= FP_GATE_MAX_RETRIES)
                    {
                        // Max retries reached — terminate gate
                        PRINT("FP gate: max retries reached, cancelling\n");
#if HAS_RGB_LED
                        led_blink_start('R');
                        tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);  // 1s
#elif HAS_FP_LED
                        fp_led_flash(FP_LED_RED, 15, 3);  // fast flash 3x
#endif
                        if(s_pending_cmd != 0) {
                            s_pending_cmd = 0;
                            s_pending_payload_len = 0;
                            uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                            ImmurokService_SendResponse(rspBuf, 1);
                        }
                        if(immurok_security_has_pending_auth()) {
                            uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                            ImmurokService_SendResponse(rspBuf, 1);
                            immurok_security_auth_cancel();
                        }
                        s_gate_fail_count = 0;
                        fp_power_off();
                        break;
                    }

                    // Not max retries — notify App + check gate timeout
                    uint8_t notifyBuf[1] = { 0x07 };  // FP_NOT_MATCH
                    ImmurokService_SendResponse(notifyBuf, 1);

                    if(s_pending_cmd != 0)
                    {
                        uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                        if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                        {
                            PRINT("FP gate timeout (%dms), cancelling pending cmd 0x%02X\n",
                                  (int)gate_elapsed, s_pending_cmd);
#if HAS_RGB_LED
                            led_blink_start('R');
                            tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#elif HAS_FP_LED
                            fp_led_flash(FP_LED_RED, 15, 3);
#endif
                            s_pending_cmd = 0;
                            s_pending_payload_len = 0;
                            uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                            ImmurokService_SendResponse(rspBuf, 1);
                            s_gate_fail_count = 0;
                            fp_power_off();
                            break;
                        }
                        else
                        {
                            PRINT("FP gate: retry (%dms/%dms)\n", (int)gate_elapsed, FP_GATE_TIMEOUT_MS);
                        }
                    }
                }

                // Restore green LED for next attempt (VER0 only — VER2 restores in TOUCH_SCAN_EVT)
#if HAS_FP_LED
                if(s_pending_cmd != 0 || immurok_security_has_pending_auth()) {
                    fp_led_flash(FP_LED_GREEN, 20, 0);  // continuous flash
                }
#endif
                // Keep power on for retry via next touch IRQ
                fp_reset_power_timer();
            }
        } while(0);

        // Match success + module still on → poll GET_IMAGE for finger lift
        if(ack == 0x00 && fp_is_powered()) {
            s_search_state = 3;
            s_lift_confirm = 0;
            s_wait_finger_lift = 0;
            s_wait_lift_no_match = 0;  // match path: no soft cap
            fp_reset_power_timer();
            tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms
        } else if(fp_is_powered() && (s_pending_cmd != 0 || immurok_security_has_pending_auth())) {
            // Gate mode no-match: auto-retry search via GET_IMAGE polling.
            // Cannot rely on touch GPIO — R599S DSP holds Touch IRQ in reset
            // while VCC-MCU is on, so GPIO interrupt never fires.
            uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
            if(gate_elapsed > FP_GATE_TIMEOUT_MS) {
                PRINT("Gate/auth timeout on retry (%dms)\n", (int)gate_elapsed);
#if HAS_RGB_LED
                led_blink_start('R');
                tmos_start_task(s_led_task_id, LED_OFF_EVT, 1600);
#endif
                if(s_pending_cmd != 0) {
                    s_pending_cmd = 0;
                    s_pending_payload_len = 0;
                }
                if(immurok_security_has_pending_auth()) {
                    immurok_security_auth_cancel();
                }
                uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                ImmurokService_SendResponse(rspBuf, 1);
                s_gate_fail_count = 0;
                fp_power_off();
            } else {
                s_search_active = 0;
                s_wait_finger_lift = 0;
                // 10ms was too aggressive: in sudo / auth dialog long-press
                // wrong-finger, each retry runs full GET_IMAGE→GEN→SEARCH
                // (~300-600ms), and 10ms between cycles means the sensor
                // barely settles before the next round — same UART-hammer
                // pattern that causes DETECT-latch (commit a922ec0). 480
                // ticks = 300ms gives the sensor a real recovery window.
                // s_gate_fail_count + FP_GATE_MAX_RETRIES still caps the
                // total attempts and FP_GATE_TIMEOUT_MS the wall-clock.
                tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 480);  // 300ms
            }
        } else {
            // Non-gate no-match. Enter WAIT_LIFT (case 3) to poll GET_IMAGE
            // for the user lifting, mirroring the match-success path —
            // this keeps the persistent red LED solid while the long-press
            // lock window counts down, lets a lift before 1s cancel the
            // lock cleanly, and avoids the green→blue→red cycling caused
            // by R599S DETECT toggling under sensor-power-on hold.
            //
            // Safety: 1.4.0 commit 0ddb770 documented this exact path as
            // 100% reproducing R599S DETECT-latch on long holds (10s+,
            // sustained ~50Hz GET_IMAGE). The case 3 handler now bails to
            // fp_async_off_start after FP_WAIT_LIFT_NOMATCH_SOFT_TMO_MS
            // (2s) when entered with s_wait_lift_no_match=1, which is
            // well past the 1s lock fire and bounds the UART hammer to
            // ~100 polls — far below the documented failure threshold.
            if(fp_is_powered()) {
                s_search_state = 3;
                s_search_substate = 0;
                s_lift_confirm = 0;
                s_wait_finger_lift = 0;
                s_wait_lift_no_match = 1;
                fp_reset_power_timer();
                tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 32);  // 20ms
            } else {
                // Already off (e.g., gate-mode bailout above) — fall back to
                // the GPIO-based touch wait used by non-R599S sensors.
                s_search_active = 0;
                s_wait_finger_lift = 1;
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 48);
            }
        }

        return (events ^ FP_SEARCH_EVT);
    }

    if(events & FP_ENROLL_EVT)
    {
        if(s_ota_active) {
            s_enroll_active = 0;
            s_enroll_substate = 0;
            return (events ^ FP_ENROLL_EVT);
        }

        // Manual step-by-step enrollment using individual commands:
        //   PS_GetEnrollImage (0x29) → PS_GenChar (0x02) → PS_RegModel (0x05) → PS_StoreChar (0x06)
        // Each TMOS event does one short UART exchange (~50-200ms), keeping BLE alive.

        extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int fp_recv_ack(uint8_t *ack, uint8_t *data, uint16_t *len, uint32_t timeout_ms);
        extern void uart_flush(void);

        #define ENROLL_TOTAL  FP_ENROLL_CAPTURES
        #define ENROLL_TIMEOUT_MS  20000   // 20s per-step timeout (waiting for finger)

        uint8_t rspBuf[4];
        uint8_t ack = 0xFF;

        if(!s_enroll_active) {
            s_enroll_step = 0;
            s_enroll_substate = 0;
            return (events ^ FP_ENROLL_EVT);
        }

        switch(s_enroll_step) {

        case 0: {
            // ── INIT: wake module, start green blink ──
            PRINT("ENROLL_EVT: manual enroll finger %d (slot %d, %d captures)\n",
                  s_enroll_page_id, FP_SLOT(s_enroll_page_id), ENROLL_TOTAL);
            s_enroll_substate = 0;
            int wake_ret = fp_ensure_ready();
            if(wake_ret != FP_OK) {
                PRINT("ENROLL_EVT: wake failed %d\n", wake_ret);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_FAILED;
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                s_enroll_substate = 0;
                fp_async_off_start();
                return (events ^ FP_ENROLL_EVT);
            }
            uart_flush();
#if HAS_RGB_LED
            led_blink_start_ex('G', 320, 320);  // fast blink 200ms on/off
#elif HAS_FP_LED
            fp_led_flash(FP_LED_GREEN, 10, 0);  // continuous fast flash
#endif

            // Probe whether a finger is currently on the sensor. When we just
            // came through an FP-gate auth (re-enroll when bitmap != 0), the
            // user almost always still has the auth finger pressed when the
            // pending ENROLL_START fires — without this probe, the very next
            // 0x29 in step 1 would capture that same finger as enroll slice 1
            // and effectively re-enroll the OLD finger instead of the NEW
            // one. Use the existing step-3 wait-lift loop in that case so
            // App shows "lift finger, then press again" before capture.
            fp_send_cmd(0x29, NULL, 0);
            int probe = fp_recv_ack(&ack, NULL, NULL, 50);
            uint8_t finger_on = (probe == FP_OK && ack == FP_ACK_SUCCESS);

            rspBuf[0] = 0x11;
            rspBuf[1] = finger_on ? FP_ENROLL_LIFT_FINGER : FP_ENROLL_WAITING;
            rspBuf[2] = 0;
            rspBuf[3] = ENROLL_TOTAL;
            ImmurokService_SendResponse(rspBuf, 4);

            s_enroll_capture = 0;
            s_enroll_step = finger_on ? 3 : 1;
            s_enroll_start = TMOS_GetSystemClock();
            tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 80);  // 50ms yield for BLE
            break;
        }

        case 1: {
            // ── GET_ENROLL_IMAGE (0x29): wait for finger on sensor ──
            // Keep-alive: emit a small notif every ~3s while polling so the
            // BLE link sees fresh app-layer TX. Without this, a >6s pause
            // between captures (user thinking, looking at progress, etc.)
            // triggers BLE supervision timeout in macOS / CH592F LL even
            // though slave is awake (g_sleep_inhibit holds it active).
            // Use 0x11+FP_ENROLL_WAITING (4 bytes) so the frame matches
            // App's existing enrollment-status handler — old [0x12,...]
            // opcode collided with DELETE_FP (0x12), corrupting any
            // concurrent gate / responseCallback (e.g. GET_STATUS run
            // during enroll). App dispatches "waiting" → no UI change.
            static uint32_t s_ka_last_tick = 0;
            uint32_t now = TMOS_GetSystemClock();
            if(now - s_ka_last_tick > 4800) {  // ~3s in 625µs ticks
                s_ka_last_tick = now;
                uint8_t ka[4] = { 0x11, FP_ENROLL_WAITING,
                                  s_enroll_capture, ENROLL_TOTAL };
                ImmurokService_SendResponse(ka, 4);
            }
            if(s_enroll_substate == 0) {
                fp_parser_reset();
                fp_send_cmd(0x29, NULL, 0);
                s_enroll_substate = 1;
                s_enroll_substate_start = TMOS_GetSystemClock();
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                return (events ^ FP_ENROLL_EVT);
            }

            int ret = fp_try_parse_packet(&ack, NULL, NULL);
            WWDG_SetCounter(0);
            if(ret == FP_ERR_TIMEOUT) {
                uint32_t wait_ms = (TMOS_GetSystemClock() - s_enroll_substate_start) * 625 / 1000;
                if(wait_ms < FP_ENROLL_GET_IMAGE_TMO_MS) {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                    return (events ^ FP_ENROLL_EVT);
                }
                // No complete response: treat this poll as "no finger" and
                // retry later. The next send may flush a truly stale partial.
                s_enroll_substate = 0;
                ret = FP_OK;
                ack = FP_ACK_NO_FINGER;
            } else {
                s_enroll_substate = 0;
            }

            if(ret == FP_OK && ack == FP_ACK_SUCCESS) {
                // Finger detected, image captured → generate feature
                PRINT("ENROLL_EVT: image captured (capture %d/%d)\n", s_enroll_capture + 1, ENROLL_TOTAL);
                s_enroll_step = 2;
                s_enroll_substate = 0;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 80);  // 50ms yield for BLE
            }
            else {
                // No finger (0x02), UART timeout, or transient error — retry
                // Only fail on overall 20s timeout, not on individual poll errors
                if(ret == FP_OK && ack != FP_ACK_NO_FINGER) {
                    PRINT("ENROLL_EVT: GetEnrollImage ack=0x%02X, retrying\n", ack);
                }
                uint32_t elapsed = (TMOS_GetSystemClock() - s_enroll_start) * 625 / 1000;
                if(elapsed > ENROLL_TIMEOUT_MS) {
                    PRINT("ENROLL_EVT: timeout waiting for finger (%dms)\n", (int)elapsed);
                    rspBuf[0] = 0x11;
                    rspBuf[1] = FP_ENROLL_FAILED;
                    rspBuf[2] = 0;
                    rspBuf[3] = 0;
                    ImmurokService_SendResponse(rspBuf, 4);
                    s_enroll_active = 0;
                    s_enroll_substate = 0;
#if HAS_RGB_LED
                    led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 25, 1);
#endif
                    fp_async_off_start();
                    return (events ^ FP_ENROLL_EVT);
                }
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // retry 200ms
            }
            break;
        }

        case 2: {
            // ── GEN_CHAR (0x02): generate feature from captured image ──
            uint8_t buffer_id = s_enroll_capture + 1;  // CharBuffer 1..12
            if(s_enroll_substate == 0) {
                fp_parser_reset();
                fp_send_cmd(0x02, &buffer_id, 1);
                s_enroll_substate = 1;
                s_enroll_substate_start = TMOS_GetSystemClock();
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                return (events ^ FP_ENROLL_EVT);
            }

            int ret = fp_try_parse_packet(&ack, NULL, NULL);
            WWDG_SetCounter(0);
            if(ret == FP_ERR_TIMEOUT) {
                uint32_t wait_ms = (TMOS_GetSystemClock() - s_enroll_substate_start) * 625 / 1000;
                if(wait_ms < FP_ENROLL_GEN_CHAR_TMO_MS) {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                    return (events ^ FP_ENROLL_EVT);
                }
                s_enroll_substate = 0;
            } else {
                s_enroll_substate = 0;
            }

            if(ret == FP_OK && ack == FP_ACK_SUCCESS) {
                s_enroll_capture++;
                PRINT("ENROLL_EVT: GenChar OK (capture %d/%d)\n", s_enroll_capture, ENROLL_TOTAL);

                // Notify host: CAPTURED
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_CAPTURED;
                rspBuf[2] = s_enroll_capture;
                rspBuf[3] = ENROLL_TOTAL;
                ImmurokService_SendResponse(rspBuf, 4);

                if(s_enroll_capture < ENROLL_TOTAL) {
                    // More captures needed → wait for finger lift
                    s_enroll_step = 3;
                    s_enroll_substate = 0;
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // 200ms pause
                } else {
                    // All captures done → merge templates
                    // 200ms yield: let BLE transmit the CAPTURED notification
                    // before step 4 sends PROCESSING (60ms BLE interval)
                    s_enroll_step = 4;
                    s_enroll_substate = 0;
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // 200ms
                }
            }
            else if(ret == FP_OK && (ack == FP_ACK_IMAGE_SMALL || ack == FP_ACK_IMAGE_MESS)) {
                // Bad quality — brief red flash, re-capture same buffer
                PRINT("ENROLL_EVT: GenChar quality fail ack=0x%02X, retrying capture %d\n",
                      ack, s_enroll_capture + 1);
#if HAS_RGB_LED
                led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                s_enroll_step = 3;  // wait for lift, then back to step 1
                s_enroll_substate = 0;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 480);  // 300ms pause
            }
            else {
                // Fatal error
                PRINT("ENROLL_EVT: GenChar fatal error ret=%d ack=0x%02X\n", ret, ack);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_FAILED;
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                s_enroll_substate = 0;
#if HAS_RGB_LED
                led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                fp_async_off_start();
                return (events ^ FP_ENROLL_EVT);
            }
            break;
        }

        case 3: {
            // ── WAIT FINGER LIFT: poll until finger removed ──
            if(s_enroll_substate == 0) {
                fp_parser_reset();
                fp_send_cmd(0x29, NULL, 0);
                s_enroll_substate = 1;
                s_enroll_substate_start = TMOS_GetSystemClock();
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                return (events ^ FP_ENROLL_EVT);
            }

            int ret = fp_try_parse_packet(&ack, NULL, NULL);
            WWDG_SetCounter(0);
            if(ret == FP_ERR_TIMEOUT) {
                uint32_t wait_ms = (TMOS_GetSystemClock() - s_enroll_substate_start) * 625 / 1000;
                if(wait_ms < FP_ENROLL_WAIT_LIFT_TMO_MS) {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                    return (events ^ FP_ENROLL_EVT);
                }
                s_enroll_substate = 0;
            } else {
                s_enroll_substate = 0;
            }

            if(ret == FP_OK && ack == FP_ACK_NO_FINGER) {
                // Finger lifted
                PRINT("ENROLL_EVT: finger lifted (capture %d/%d)\n", s_enroll_capture, ENROLL_TOTAL);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_LIFT_FINGER;
                rspBuf[2] = s_enroll_capture;
                rspBuf[3] = ENROLL_TOTAL;
                ImmurokService_SendResponse(rspBuf, 4);
#if HAS_RGB_LED
                led_blink_start_ex('G', 320, 320);  // resume fast green blink
#elif HAS_FP_LED
                fp_led_flash(FP_LED_GREEN, 10, 0);  // continuous fast flash
#endif
                s_enroll_start = TMOS_GetSystemClock();  // reset timeout
                s_enroll_step = 1;  // back to GET_ENROLL_IMAGE
                s_enroll_substate = 0;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 80);  // 50ms yield for BLE
            }
            else if(ret == FP_OK && ack == FP_ACK_SUCCESS) {
                // Finger still on sensor — check timeout and retry
                uint32_t elapsed = (TMOS_GetSystemClock() - s_enroll_start) * 625 / 1000;
                if(elapsed > ENROLL_TIMEOUT_MS) {
                    PRINT("ENROLL_EVT: timeout waiting for finger lift (%dms)\n", (int)elapsed);
                    rspBuf[0] = 0x11;
                    rspBuf[1] = FP_ENROLL_FAILED;
                    rspBuf[2] = 0;
                    rspBuf[3] = 0;
                    ImmurokService_SendResponse(rspBuf, 4);
                    s_enroll_active = 0;
                    s_enroll_substate = 0;
#if HAS_RGB_LED
                    led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 25, 1);
#endif
                    fp_async_off_start();
                    return (events ^ FP_ENROLL_EVT);
                }
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // retry 200ms
            }
            else {
                // Communication error — retry with timeout guard
                uint32_t elapsed = (TMOS_GetSystemClock() - s_enroll_start) * 625 / 1000;
                if(elapsed > ENROLL_TIMEOUT_MS) {
                    PRINT("ENROLL_EVT: comm error timeout (%dms)\n", (int)elapsed);
                    rspBuf[0] = 0x11;
                    rspBuf[1] = FP_ENROLL_FAILED;
                    rspBuf[2] = 0;
                    rspBuf[3] = 0;
                    ImmurokService_SendResponse(rspBuf, 4);
                    s_enroll_active = 0;
                    s_enroll_substate = 0;
#if HAS_RGB_LED
                    led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 25, 1);
#endif
                    fp_async_off_start();
                    return (events ^ FP_ENROLL_EVT);
                }
                PRINT("ENROLL_EVT: finger lift poll error ret=%d ack=0x%02X, retrying\n", ret, ack);
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // retry 200ms
            }
            break;
        }

        case 4: {
            // ── REG_MODEL (0x05): merge all captured features ──
            if(s_enroll_substate == 0) {
                PRINT("ENROLL_EVT: merging %d captures\n", ENROLL_TOTAL);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_PROCESSING;
                rspBuf[2] = ENROLL_TOTAL;
                rspBuf[3] = ENROLL_TOTAL;
                ImmurokService_SendResponse(rspBuf, 4);

                fp_parser_reset();
                fp_send_cmd(0x05, NULL, 0);
                s_enroll_substate = 1;
                s_enroll_substate_start = TMOS_GetSystemClock();
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                return (events ^ FP_ENROLL_EVT);
            }

            int ret = fp_try_parse_packet(&ack, NULL, NULL);
            WWDG_SetCounter(0);
            if(ret == FP_ERR_TIMEOUT) {
                uint32_t wait_ms = (TMOS_GetSystemClock() - s_enroll_substate_start) * 625 / 1000;
                if(wait_ms < FP_ENROLL_REG_MODEL_TMO_MS) {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                    return (events ^ FP_ENROLL_EVT);
                }
                s_enroll_substate = 0;
            } else {
                s_enroll_substate = 0;
            }

            if(ret == FP_OK && ack == FP_ACK_SUCCESS) {
                PRINT("ENROLL_EVT: RegModel OK\n");
                s_enroll_step = 5;
                s_enroll_substate = 0;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 80);  // 50ms yield for BLE
            }
            else {
                PRINT("ENROLL_EVT: RegModel failed ret=%d ack=0x%02X\n", ret, ack);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_FAILED;
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                s_enroll_substate = 0;
#if HAS_RGB_LED
                led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                fp_async_off_start();
                return (events ^ FP_ENROLL_EVT);
            }
            break;
        }

        case 5: {
            // ── STORE_CHAR (0x06): save merged template to flash ──
            uint16_t page = FP_SLOT(s_enroll_page_id);
            uint8_t params[3];
            params[0] = 1;                     // CharBuffer 1
            params[1] = (page >> 8) & 0xFF;    // page_id high
            params[2] = page & 0xFF;            // page_id low

            if(s_enroll_substate == 0) {
                fp_parser_reset();
                fp_send_cmd(0x06, params, 3);
                s_enroll_substate = 1;
                s_enroll_substate_start = TMOS_GetSystemClock();
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                return (events ^ FP_ENROLL_EVT);
            }

            int ret = fp_try_parse_packet(&ack, NULL, NULL);
            WWDG_SetCounter(0);
            if(ret == FP_ERR_TIMEOUT) {
                uint32_t wait_ms = (TMOS_GetSystemClock() - s_enroll_substate_start) * 625 / 1000;
                if(wait_ms < FP_ENROLL_STORE_TMO_MS) {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, FP_ENROLL_POLL_TICKS);
                    return (events ^ FP_ENROLL_EVT);
                }
                s_enroll_substate = 0;
            } else {
                s_enroll_substate = 0;
            }

            if(ret == FP_OK && ack == FP_ACK_SUCCESS) {
                PRINT("ENROLL_EVT: SUCCESS (slot %d)\n", FP_SLOT(s_enroll_page_id));
#if HAS_RGB_LED
                led_stop();
                led_solid('B', 400);  // blue 0.25s
#elif HAS_FP_LED
                fp_led_flash(FP_LED_BLUE, 25, 1);
#endif
                // Update bitmap BEFORE sending COMPLETE — daemon queries
                // FP_LIST immediately after receiving COMPLETE notification
                fp_get_fingerprint_bitmap(&g_cached_fp_bitmap);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_COMPLETE;
                rspBuf[2] = ENROLL_TOTAL;
                rspBuf[3] = ENROLL_TOTAL;
                ImmurokService_SendResponse(rspBuf, 4);
                // No separate RSP_OK needed — COMPLETE notification is sufficient.
                // Sending two notifications back-to-back overflows the GATT queue.
                s_enroll_active = 0;
                s_enroll_substate = 0;
                fp_async_off_start();
            }
            else {
                PRINT("ENROLL_EVT: StoreChar failed ret=%d ack=0x%02X\n", ret, ack);
                rspBuf[0] = 0x11;
                rspBuf[1] = FP_ENROLL_FAILED;
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                s_enroll_substate = 0;
#if HAS_RGB_LED
                led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
                fp_led_flash(FP_LED_RED, 25, 1);
#endif
                fp_async_off_start();
            }
            break;
        }

        default:
            PRINT("ENROLL_EVT: invalid step %d\n", s_enroll_step);
            s_enroll_active = 0;
            s_enroll_substate = 0;
            fp_async_off_start();
            break;
        }  // switch(s_enroll_step)

        return (events ^ FP_ENROLL_EVT);
    }

    if(events & FP_NOTIFY_RETRY_EVT)
    {
        // Re-send pending FP match notification after reconnect.
        // The first send was lost because GATT wasn't connected.
        if(s_fp_notify_pending && s_fp_notify_len > 0)
        {
            // Expire after 30s — don't auto-unlock from a stale match
            uint32_t elapsed = (TMOS_GetSystemClock() - s_fp_notify_start_time) * 625 / 1000;
            if(elapsed > 30000) {
                PRINT("Pending FP notify expired (%dms)\n", (int)elapsed);
                s_fp_notify_pending = 0;
            } else {
                PRINT("Re-sending pending FP notify (%d bytes, %dms old)\n",
                      s_fp_notify_len, (int)elapsed);
                ImmurokService_SendResponse(s_fp_notify_data, s_fp_notify_len);
            }
        }
        return (events ^ FP_NOTIFY_RETRY_EVT);
    }

    if(events & HID_KEY_RELEASE_EVT)
    {
        // Delayed key release — ensures press and release go in separate BLE packets.
        // Retry on failure: if BLE buffer is full, GATT_Notification fails and
        // CTRL stays stuck (macOS interprets click as right-click).
        uint8_t buf[HID_KEYBOARD_IN_RPT_LEN] = {0};
        uint8_t ret = HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                                    HID_KEYBOARD_IN_RPT_LEN, buf);
        if(ret != SUCCESS)
        {
            PRINT("Key release failed (0x%02X), retrying in 10ms\n", ret);
            tmos_start_task(hidEmuTaskId, HID_KEY_RELEASE_EVT, 16);  // 10ms retry
        }
        return (events ^ HID_KEY_RELEASE_EVT);
    }

    if(events & FP_POWER_OFF_EVT)
    {
        // OTA inactivity watchdog: this slot is repurposed during OTA mode
        // since FP is powered off and the FP idle path is dormant. If the
        // client (ota-update.py) was killed mid-session and the daemon never
        // got a chance to clean up, this fires 10s after the last OTA cmd
        // and restores the device to idle. Must be checked before the FP
        // logic — fp_is_powered() is false during OTA so the FP branch
        // would early-out anyway, but the gate-pending re-arm below would
        // mis-fire on s_pending_cmd_start state from before OTA entry.
        if(s_ota_active) {
            ota_abort_to_idle();
            return (events ^ FP_POWER_OFF_EVT);
        }
        // Deferred factory reset: erase bonds + system reset
        // (OK response already sent, 200ms delay for BLE transmission)
        if(s_factory_reset_pending) {
            s_factory_reset_pending = 0;
            PRINT("Factory reset: erasing bonds + reboot\n");
            HidDev_SetParameter(HIDDEV_ERASE_ALLBONDS, 0, NULL);
            DelayMs(100);
            SYS_ResetExecute();
            // Never returns
        }
        // If async sleep retry is already running, the LED task is handling
        // power-off — skip to avoid running the synchronous path in parallel
        // (would issue a duplicate PS_Sleep and block ~4s on no-ack).
        if(s_sleep_retry_active) {
            return (events ^ FP_POWER_OFF_EVT);
        }
        // Two arming paths feed this event:
        //   (a) fp_reset_power_timer() — 500ms after the last FP op; FP is on.
        //       Idle-watchdog: state machine quit without explicit power-off.
        //   (b) fp_gate_enter() — 25s gate-pending watchdog; FP is OFF
        //       (no preheat). User never touched within the gate window.
        // (a) requires async VCC cut. (b) only requires gate cleanup.
        // Both cases share the same gate-cleanup logic, gated on the time
        // elapsed since the gate was opened (s_pending_cmd_start).
        if(fp_is_powered() && !s_enroll_active) {
            PRINT("FP idle timeout - async power off\n");
            fp_async_off_start();
        }

        // Gate-pending decision: re-arm watchdog if still within the window,
        // otherwise time out and emit SEC_ERR_TIMEOUT. Same logic for both
        // arming paths — case (a) typically falls through to re-arm because
        // the gate was just opened, while case (b) usually hits the timeout
        // branch because by definition the 25s window has expired.
        if(!s_enroll_active &&
           (s_pending_cmd != 0 || immurok_security_has_pending_auth()))
        {
            uint32_t elapsed_ms = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
            if(elapsed_ms < FP_GATE_TIMEOUT_MS) {
                uint32_t remaining_ms = FP_GATE_TIMEOUT_MS - elapsed_ms;
                uint32_t ticks = (remaining_ms * 1000) / 625;
                if(ticks < 16)    ticks = 16;     // floor 10ms
                if(ticks > 60000) ticks = 60000;  // 16-bit ceiling
                tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, (uint16_t)ticks);
                return (events ^ FP_POWER_OFF_EVT);
            }
            PRINT("Gate timeout (%dms): clearing pending\n", (int)elapsed_ms);
            if(s_pending_cmd != 0) {
                s_pending_cmd = 0;
                s_pending_payload_len = 0;
                s_gate_fail_count = 0;
                uint8_t rspBuf[1] = { SEC_ERR_TIMEOUT };
                ImmurokService_SendResponse(rspBuf, 1);
            }
            if(immurok_security_has_pending_auth()) {
                immurok_security_auth_cancel();
            }
#if HAS_RGB_LED
            led_solid('R', 1600);
#endif
        }
        return (events ^ FP_POWER_OFF_EVT);
    }

    if(events & OTA_FLASH_ERASE_EVT)
    {
        // Shared event bit: deferred KEY_SIGN or ECDH compute (when not in OTA mode)
        if(!s_ota_active)
        {
            // DELETE_FP: delete the single physical slot for a finger
            // Uses s_deferred_delete_id (not s_pending_cmd) to avoid race
            if(s_deferred_delete_id != 0xFF)
            {
                uint8_t fingerId = s_deferred_delete_id;
                s_deferred_delete_id = 0xFF;
                int del_ret = fp_ensure_ready();
                if(del_ret == FP_OK) {
                    del_ret = fp_delete(FP_SLOT(fingerId), 1);
                    WWDG_SetCounter(0);
                    if(del_ret == FP_OK)
                        fp_get_fingerprint_bitmap(&g_cached_fp_bitmap);
                }
                // No RSP_OK needed — daemon already received gate-approved RSP_OK.
                // Sending another would race with the daemon's FP_LIST query.
                fp_reset_power_timer();
                return (events ^ OTA_FLASH_ERASE_EVT);
            }

            // ECC (~2s) needs supervision timeout >= 5s to avoid disconnect.
            // Reject with 0xE1 if timeout too short — lets App diagnose param issues.
            // s_conn_timeout is in units of 10ms, so 500 = 5000ms = 5s.
            if(s_conn_timeout < 500)
            {
                PRINT("Long op REJECTED: timeout=%dms (need >=5000ms)\n", s_conn_timeout * 10);
                s_long_op_param_requested = 0;
                s_long_op_wait_start = 0;
                uint8_t rspErr[1] = { 0xE1 };
                ImmurokService_SendResponse(rspErr, 1);
                s_pending_cmd = 0;
                // FP-match dispatch (KEY_SIGN/KEY_GENERATE) sets s_long_op_busy=1
                // before scheduling this event to lock out duplicate matches.
                // If we early-return here, that flag stays stuck and every
                // subsequent command gets rejected with 0xFD until disconnect.
                // led_stop() too: gate flow leaves LED in green-flash/blue-solid
                // state that would otherwise persist with no further trigger.
                s_long_op_busy = 0;
#if HAS_RGB_LED
                led_stop();
#endif
                return (events ^ OTA_FLASH_ERASE_EVT);
            }
            s_long_op_param_requested = 0;
            s_long_op_wait_start = 0;
            PRINT("Long op: param accepted, proceeding\n");

            // Lock out concurrent commands during ECC (~2s)
            s_long_op_busy = 1;
            // Suppress FP power-off during ECC — avoid sys_safe_access / PRINT
            // inside TMOS_SystemProcess() called from uECC keepalive
            tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);

#if HAS_RGB_LED
            // Blue solid for the ~2s ECC compute. Match success flashed
            // green for 200ms first; that's now finished, so starting blue
            // here gives a clean green→blue transition. led_stop() at each
            // ECC branch's exit turns it off when the response is sent.
            led_solid('B', 0);
#endif

            // Check if this is an ECDH computation
            immurok_ecdh_state_t ecdh_state = immurok_security_get_ecdh_state();
            if(ecdh_state == ECDH_STATE_MAKE_KEY)
            {
                // ECDH key generation (~2s)
                uint8_t rspBuf[34];
                if(immurok_security_pair_make_key() == 0) {
                    rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                    immurok_security_pair_get_pubkey(&rspBuf[1]);
                    ImmurokService_SendResponse(rspBuf, 34);
                    PRINT("ECDH PAIR_INIT response sent\n");
                } else {
                    rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                    rspBuf[1] = SEC_ERR_INTERNAL;
                    ImmurokService_SendResponse(rspBuf, 2);
                }
                s_long_op_busy = 0;
#if HAS_RGB_LED
                led_stop();
#endif
                return (events ^ OTA_FLASH_ERASE_EVT);
            }
            if(ecdh_state == ECDH_STATE_SHARED_SECRET)
            {
                // ECDH shared secret computation (~2s)
                uint8_t rspBuf[2];
                rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
                if(immurok_security_pair_compute_secret() == 0) {
                    rspBuf[1] = SEC_OK;
                    PRINT("ECDH PAIR_CONFIRM response sent (success)\n");
                } else {
                    rspBuf[1] = SEC_ERR_INTERNAL;
                    PRINT("ECDH PAIR_CONFIRM response sent (failed)\n");
                }
                ImmurokService_SendResponse(rspBuf, 2);
                // Schedule deferred EEPROM save — calling save_security_data
                // inline right after ECC crashes the chip into the IAP
                // bootloader (likely a BootROM flash arbitration issue with
                // the post-ECC instruction-fetch state). See immurok_security.h.
                if(immurok_security_pair_save_pending) {
                    tmos_start_task(s_led_task_id, EEPROM_SAVE_EVT, 320);  // 200ms
                }
                s_long_op_busy = 0;
#if HAS_RGB_LED
                led_stop();
#endif
                return (events ^ OTA_FLASH_ERASE_EVT);
            }

            if(s_pending_cmd == IMMUROK_CMD_KEY_SIGN)
            {
                uint8_t kidx = s_pending_payload[1];
                uint8_t *hash = &s_pending_payload[2];
                uint8_t rspBuf[2];
                if(immurok_keystore_sign(kidx, hash, immurok_keystore_result_buf()) == 0) {
                    immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                    rspBuf[0] = IMMUROK_RSP_OK;
                    rspBuf[1] = 64;
                    PRINT("ECDSA sign done\n");
                    ImmurokService_SendResponse(rspBuf, 2);
                } else {
                    rspBuf[0] = SEC_ERR_INTERNAL;
                    PRINT("ECDSA sign failed\n");
                    ImmurokService_SendResponse(rspBuf, 1);
                }
            }
            else if(s_pending_cmd == IMMUROK_CMD_KEY_GENERATE)
            {
                uint8_t *name = &s_pending_payload[1];  // skip cat byte
                int new_idx = immurok_keystore_generate_stage(name, immurok_keystore_result_buf());
                if(new_idx >= 0) {
                    immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                    PRINT("KEY_GENERATE staged: idx=%d, deferring commit\n", new_idx);
                    // Defer flash commit to KEYSTORE_COMMIT_EVT (LED task,
                    // 200ms later) — calling EEPROM_ERASE/WRITE inline right
                    // after uECC_make_key faults into the IAP bootloader on
                    // this chip, causing a silent reboot and BLE supervision
                    // timeout (~6s no response → host disconnects). Same
                    // hazard as save_security_data after PAIR_CONFIRM.
                    //
                    // Park the index in s_pending_payload past the name (cat
                    // + 16B name = 0..16, [17] free). COMMIT handler reads
                    // it and gates on (pending_cmd == KEY_GENERATE && busy)
                    // to detect "stage done, awaiting commit".
                    s_pending_payload[17] = (uint8_t)new_idx;
                    tmos_start_task(s_led_task_id, KEYSTORE_COMMIT_EVT, 320);  // 200ms
                    // Leave s_pending_cmd / s_long_op_busy set; cleared by
                    // the COMMIT handler. Don't led_stop yet — keep the blue
                    // "computing" indicator on until commit really finishes.
                    return (events ^ OTA_FLASH_ERASE_EVT);
                } else {
                    uint8_t rspErr[1] = { SEC_ERR_INTERNAL };
                    PRINT("KEY_GENERATE stage failed\n");
                    ImmurokService_SendResponse(rspErr, 1);
                }
            }
            s_pending_cmd = 0;
            s_long_op_busy = 0;
#if HAS_RGB_LED
            led_stop();
#endif
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        // Deferred OTA reboot: write IAP flag to DataFlash EEPROM, then reset
        if(s_ota_reboot_pending)
        {
            s_ota_reboot_pending = 0;

            __attribute__((aligned(8))) uint8_t block_buf[16];
            uint8_t ret;
            (void)ret;  // Used only in DEBUG PRINT below

            PRINT("OTA REBOOT: writing ImageFlag to EEPROM @ 0x%x\n", OTA_DATAFLASH_ADD);

            ret = EEPROM_READ(OTA_DATAFLASH_ADD, (uint32_t *)block_buf, 4);
            PRINT("  read: ret=%d, cur=0x%02X\n", ret, block_buf[0]);

            ret = EEPROM_ERASE(OTA_DATAFLASH_ADD, EEPROM_PAGE_SIZE);
            PRINT("  erase: ret=%d\n", ret);

            block_buf[0] = IMAGE_IAP_FLAG;
            ret = EEPROM_WRITE(OTA_DATAFLASH_ADD, (uint32_t *)block_buf, 4);
            PRINT("  write: ret=%d\n", ret);

            // Verify
            block_buf[0] = 0xFF;
            EEPROM_READ(OTA_DATAFLASH_ADD, (uint32_t *)block_buf, 4);
            PRINT("  verify: 0x%02X %s\n", block_buf[0],
                  (block_buf[0] == IMAGE_IAP_FLAG) ? "OK" : "FAIL!");

            PRINT("OTA REBOOT: resetting...\n");
            DelayMs(10);
            SYS_DisableAllIrq(NULL);
            SYS_ResetExecute();
        }

        uint8_t status;

        PRINT("OTA ERASE: %08x block %d/%d\n",
              (int)(s_ota_erase_addr + s_ota_erase_count * FLASH_BLOCK_SIZE),
              (int)s_ota_erase_count, (int)s_ota_erase_blocks);

        status = FLASH_ROM_ERASE(s_ota_erase_addr + s_ota_erase_count * FLASH_BLOCK_SIZE,
                                  FLASH_BLOCK_SIZE);

        if(status != SUCCESS)
        {
            PRINT("OTA ERASE failed: %d\n", status);
            OTA_IAP_SendStatus(status);
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        s_ota_erase_count++;

        if(s_ota_erase_count >= s_ota_erase_blocks)
        {
            PRINT("OTA ERASE complete\n");
            OTA_IAP_SendStatus(SUCCESS);
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        // Continue erasing (return events without XOR to process again)
        return events;
    }

    return 0;
}

/*********************************************************************
 * @fn      hidEmu_ProcessTMOSMsg
 *
 * @brief   Process an incoming task message.
 *
 * @param   pMsg - message to process
 *
 * @return  none
 */
static void hidEmu_ProcessTMOSMsg(tmos_event_hdr_t *pMsg)
{
    switch(pMsg->event)
    {
        default:
            break;
    }
}

/*********************************************************************
 * @fn      hidEmuSendKbdReport
 *
 * @brief   Build and send a HID keyboard report.
 *
 * @param   keycode - HID keycode.
 *
 * @return  none
 */
static void hidEmuSendKbdReport(uint8_t keycode)
{
    uint8_t buf[HID_KEYBOARD_IN_RPT_LEN];

    buf[0] = 0;       // Modifier keys
    buf[1] = 0;       // Reserved
    buf[2] = keycode; // Keycode 1
    buf[3] = 0;       // Keycode 2
    buf[4] = 0;       // Keycode 3
    buf[5] = 0;       // Keycode 4
    buf[6] = 0;       // Keycode 5
    buf[7] = 0;       // Keycode 6

    HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                  HID_KEYBOARD_IN_RPT_LEN, buf);
}

/*********************************************************************
 * @fn      hidEmuSendCtrlKey
 *
 * @brief   Send a CTRL key press and release to wake host from sleep.
 *          Uses LEFT_CTRL modifier only (no keycode) to avoid typing.
 *
 * @return  none
 */
static void hidEmuSendCtrlKey(void)
{
    uint8_t buf[HID_KEYBOARD_IN_RPT_LEN] = {0};

    // Cancel any pending key-release timer and send immediate release first,
    // to prevent Ctrl from "sticking" if called multiple times
    tmos_stop_task(hidEmuTaskId, HID_KEY_RELEASE_EVT);
    HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                  HID_KEYBOARD_IN_RPT_LEN, buf);

    // Press: LEFT_CTRL modifier only
    buf[0] = 0x01;  // LEFT_CTRL
    uint8_t ret = HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                                HID_KEYBOARD_IN_RPT_LEN, buf);

    // Schedule key release only if press succeeded;
    // if press failed (BLE buffer full), no CTRL was sent, no release needed
    if(ret == SUCCESS) {
        tmos_start_task(hidEmuTaskId, HID_KEY_RELEASE_EVT, 128);  // 80ms
    }
}

/*********************************************************************
 * @fn      hidEmuStateCB
 *
 * @brief   GAP state change callback.
 *
 * @param   newState - new state
 *
 * @return  none
 */
static void hidEmuStateCB(gapRole_States_t newState, gapRoleEvent_t *pEvent)
{
    switch(newState & GAPROLE_STATE_ADV_MASK)
    {
        case GAPROLE_STARTED:
        {
            uint8_t ownAddr[6];
            GAPRole_GetParameter(GAPROLE_BD_ADDR, ownAddr);
            GAP_ConfigDeviceAddr(ADDRTYPE_STATIC, ownAddr);
            PRINT("Initialized..\n");
        }
        break;

        case GAPROLE_ADVERTISING:
            if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Advertising (phase %d)..\n", s_adv_phase);
#if HAS_RGB_LED
                // LED is managed by SLOW_ADV_EVT phase transitions;
                // only set default blink if no phase-specific pattern is active
                if(s_adv_phase <= ADV_PHASE_FAST && !s_led_blink)
                {
                    led_blink_start('B');
                }
#endif
            }
            break;

        case GAPROLE_CONNECTED:
            if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                gapEstLinkReqEvent_t *event = (gapEstLinkReqEvent_t *)pEvent;

                // get connection handle
                hidEmuConnHandle = event->connectionHandle;
                ImmurokService_SetConnHandle(event->connectionHandle);
                tmos_start_task(hidEmuTaskId, START_PARAM_UPDATE_EVT, START_PARAM_UPDATE_EVT_DELAY);
                // Cancel advertising cycle timer, mark as connected (not advertising)
                tmos_stop_task(hidEmuTaskId, SLOW_ADV_EVT);
                s_adv_phase = ADV_PHASE_OFF;
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
                s_ble_connected = 1;
                PRINT("Connected..\n");
#if HAS_RGB_LED
                led_solid('B', LED_SOLID_2S_TICKS);
#endif
                // Print connection parameters
                // Interval: unit 1.25ms, Latency: events, Timeout: unit 10ms
                PRINT("Conn params: Interval=%d (%d.%02dms), Latency=%d, Timeout=%d (%dms)\n",
                      event->connInterval,
                      (event->connInterval * 5) / 4, ((event->connInterval * 5) % 4) * 25,
                      event->connLatency,
                      event->connTimeout, event->connTimeout * 10);
                // Save initial connection parameters — Linux may already negotiate
                // adequate params at connection time, so hidDevParamUpdateCB may
                // never fire. Without this, s_conn_timeout stays 0 and PAIR_INIT
                // is rejected with 0xE1.
                s_conn_timeout = event->connTimeout;
                if(event->connLatency > 0)
                {
                    s_latency_accepted = 1;
                }
            }
            break;

        case GAPROLE_CONNECTED_ADV:
            if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Connected Advertising..\n");
            }
            break;

        case GAPROLE_WAITING:
            if(pEvent->gap.opcode == GAP_END_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Advertising timeout (phase %d)\n", s_adv_phase);
                // Initial advertising timed out (no bond) → start fast cycle
                if(s_adv_phase == ADV_PHASE_OFF)
                {
                    s_adv_phase = ADV_PHASE_FAST;
                    s_adv_slow_count = 0;
                    GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
                    GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
                    GAP_SetParamValue(TGAP_LIM_ADV_TIMEOUT, 0);  // no timeout
                    tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_ADV_DELAY);
                }
            }
            else if(pEvent->gap.opcode == GAP_LINK_TERMINATED_EVENT)
            {
                s_ble_connected = 0;
                s_app_connected = 0;
                s_touch_reset = 0;
                PRINT("Disconnected.. Reason:%x\n", pEvent->linkTerminate.reason);
#if HAS_RGB_LED
                led_blink_start('B');
#endif
                // Clear ALL session state for clean reconnect
                s_pending_cmd = 0;
                s_pending_payload_len = 0;
                immurok_security_auth_cancel();
                // Reset param update state
                s_param_update_retries = 0;
                s_latency_accepted = 0;
                s_conn_timeout = 0;
                s_post_discovery = 0;
                extern volatile uint8_t g_sleep_inhibit;
                g_sleep_inhibit = 0;  // Reset all sleep inhibit holds on disconnect
                s_long_op_param_requested = 0;
                s_long_op_wait_start = 0;
                s_long_op_busy = 0;
                // Drop any half-finished KEY_GENERATE: stop the deferred
                // commit timer; the s_pending_cmd clear above + s_long_op_busy=0
                // makes the COMMIT handler's gate fail anyway, but stopping
                // the timer prevents a stale fire on the next session.
                tmos_stop_task(s_led_task_id, KEYSTORE_COMMIT_EVT);
                // Reset fingerprint state
                s_search_active = 0;
                s_search_substate = 0;
                s_enroll_active = 0;
                s_enroll_step = 0;
                s_enroll_substate = 0;
                s_enroll_capture = 0;
                s_gate_fail_count = 0;
                s_gate_preheat = 0;
                s_deferred_delete_id = 0xFF;
                s_wait_finger_lift = 0;
                s_fp_gate_last[0] = 0;  // invalidate all gate cooldowns on disconnect
                s_fp_gate_last[1] = 0;
                s_fp_gate_last[2] = 0;
                // Clear OTA state. Without this, an attacker who completes
                // BLE pairing and sends a single ERASE then disconnects
                // leaves s_ota_active=1 forever — HID/FP/buttons all stay
                // suppressed (see early-return guards in *_EVT handlers)
                // until power cycle. Disconnect always invalidates an
                // in-progress OTA session: incomplete writes can't be
                // resumed safely, and END would have failed the SHA/HMAC
                // check anyway.
                // OTA cleanup (idempotent; clears LED + scratch state + watchdog).
                // Skips conn-param restore inside ota_abort_to_idle since we're
                // already disconnected — s_ble_connected = 0 above.
                ota_abort_to_idle();
                tmos_memset(&s_ota_sec, 0, sizeof(s_ota_sec));
                s_ota_verify_status = 0;
                tmos_stop_task(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                tmos_stop_task(hidEmuTaskId, HID_KEY_RELEASE_EVT);
                tmos_stop_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT);
                tmos_stop_task(hidEmuTaskId, FP_SEARCH_EVT);
                tmos_stop_task(hidEmuTaskId, FP_ENROLL_EVT);
                tmos_stop_task(hidEmuTaskId, FP_WAKE_DONE_EVT);
                tmos_stop_task(hidEmuTaskId, FP_GATE_EXEC_EVT);
                tmos_stop_task(hidEmuTaskId, FP_AUTH_EVT);
#if HAS_RGB_LED
                tmos_stop_task(s_led_task_id, LOCK_HOLD_EVT);
                s_lock_pending = 0;
                tmos_stop_task(s_led_task_id, FP_SLEEP_RETRY_EVT);
                s_sleep_retry_active = 0;
                s_sleep_retry_substate = 0;
                tmos_stop_task(s_led_task_id, PAIR_BTN_TIMEOUT_EVT);
#endif
                s_pair_wait_button = 0;
                // Note: s_fp_notify_pending is NOT cleared here — it survives
                // disconnect so the notification can be re-sent on reconnect.
                // Start fast advertising cycle (FAST 60s → SLOW 60min → DEEP_SLEEP)
                s_adv_phase = ADV_PHASE_FAST;
                s_adv_slow_count = 0;
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
                GAP_SetParamValue(TGAP_LIM_ADV_TIMEOUT, 0);  // no timeout
                tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_ADV_DELAY);
            }
            else if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                PRINT("Advertising timeout..\n");
            }
            // Enable advertising
            {
                uint8_t adv_enable = TRUE;
                GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
            }
            break;

        case GAPROLE_ERROR:
            PRINT("Error %x ..\n", pEvent->gap.opcode);
            break;

        default:
            break;
    }
}

/*********************************************************************
 * @fn      hidEmuRcvReport
 *
 * @brief   Process an incoming HID keyboard report.
 *
 * @param   len - Length of report.
 * @param   pData - Report data.
 *
 * @return  status
 */
static uint8_t hidEmuRcvReport(uint8_t len, uint8_t *pData)
{
    // verify data length
    if(len == HID_LED_OUT_RPT_LEN)
    {
        // set LEDs
        return SUCCESS;
    }
    else
    {
        return ATT_ERR_INVALID_VALUE_SIZE;
    }
}

/*********************************************************************
 * @fn      hidEmuRptCB
 *
 * @brief   HID Dev report callback.
 *
 * @param   id - HID report ID.
 * @param   type - HID report type.
 * @param   uuid - attribute uuid.
 * @param   oper - operation:  read, write, etc.
 * @param   len - Length of report.
 * @param   pData - Report data.
 *
 * @return  GATT status code.
 */
static uint8_t hidEmuRptCB(uint8_t id, uint8_t type, uint16_t uuid,
                           uint8_t oper, uint16_t *pLen, uint8_t *pData)
{
    uint8_t status = SUCCESS;

    // write
    if(oper == HID_DEV_OPER_WRITE)
    {
        if(uuid == REPORT_UUID)
        {
            // process write to LED output report; ignore others
            if(type == HID_REPORT_TYPE_OUTPUT)
            {
                status = hidEmuRcvReport(*pLen, pData);
            }
        }

        if(status == SUCCESS)
        {
            status = Hid_SetParameter(id, type, uuid, *pLen, pData);
        }
    }
    // read
    else if(oper == HID_DEV_OPER_READ)
    {
        status = Hid_GetParameter(id, type, uuid, pLen, pData);
    }
    // notifications enabled
    else if(oper == HID_DEV_OPER_ENABLE)
    {
        tmos_start_task(hidEmuTaskId, START_REPORT_EVT, 500);
    }
    return status;
}

/*********************************************************************
 * @fn      hidEmuEvtCB
 *
 * @brief   HID Dev event callback.
 *
 * @param   evt - event ID.
 *
 * @return  HID response code.
 */
static void hidEmuEvtCB(uint8_t evt)
{
    switch(evt)
    {
    case HID_DEV_SUSPEND_EVT:
        PRINT("HID Suspend\n");
        break;
    case HID_DEV_EXIT_SUSPEND_EVT:
        PRINT("HID Exit Suspend\n");
        break;
    default:
        PRINT("HID evt: %d\n", evt);
        break;
    }
}

/*********************************************************************
 * @fn      HidEmu_ImmurokCommandCB
 *
 * @brief   Process immurok GATT command from host
 *
 * @param   connHandle - connection handle
 * @param   pData - command data [cmd][len][payload...]
 * @param   len - data length
 *
 * @return  none
 */
// Check if fingerprint gate is needed for a category (0 = no, 1 = yes).
// Each category has its own cooldown — verifying for AUTH does NOT free up
// keystore writes, and vice versa. Rolling within a category.
static int fp_gate_needed(fp_gate_cat_t cat)
{
    if(g_cached_fp_bitmap == 0) return 0;
    uint32_t last = s_fp_gate_last[cat];
    if(last == 0) return 1;
    uint32_t now = TMOS_GetSystemClock();
    uint32_t ms_since = (now - last) * 625 / 1000;
    if(ms_since > FP_GATE_COOLDOWN_MS) return 1;
    s_fp_gate_last[cat] = now;  // rolling within category
    return 0;
}

// Map cmd → category (used at FP-verify pass-through to refresh the right
// cooldown). Defaults to KEYSTORE for any unlisted KEY_* command.
static fp_gate_cat_t fp_gate_cat_for_cmd(uint8_t cmd)
{
    switch(cmd) {
    case IMMUROK_CMD_AUTH_REQUEST: return FP_CAT_AUTH;
    case IMMUROK_CMD_ENROLL_START:
    case IMMUROK_CMD_DELETE_FP:
    case IMMUROK_CMD_FACTORY_RESET: return FP_CAT_ADMIN;
    default: return FP_CAT_KEYSTORE;
    }
}

/* Gate enter: light LED + arm gate-pending watchdog. Does NOT power on FP.
 * The fingerprint sensor only powers on when the user actually touches it
 * (TOUCH ISR → cold-path FP_WAKE_DONE). This keeps FP at ~0 µA during the
 * user's reaction-time window instead of 30 mA × 30 s. The 25s watchdog
 * (FP_POWER_OFF_EVT with FP_GATE_PENDING_TIMEOUT) clears s_pending_cmd /
 * pending auth + sends SEC_ERR_TIMEOUT if the user never touches.
 *
 * If FP happens to already be powered (e.g. very fast back-to-back gate ops
 * before idle-off fires), reuse it directly so we don't pointlessly cycle. */
static void fp_gate_enter(void)
{
    s_gate_fail_count = 0;
    s_gate_preheat = 0;  // never preheat — wait for the user's touch

    // Request param update early — ECDSA needs supervision timeout > 2s.
    // Done now (before the touch) so params are likely accepted by the time
    // FP_GATE_EXEC_EVT fires, avoiding a blocking wait there.
    if(!s_latency_accepted) {
        tmos_set_event(hidEmuTaskId, START_PARAM_UPDATE_EVT);
    }

    // LED tells the user we're waiting for their finger.
#if HAS_RGB_LED
    led_blink_start(fp_indicator_color());
#elif HAS_FP_LED
    fp_led_flash(FP_LED_GREEN, 20, 0);
#endif

    if(fp_is_powered()) {
        // Module already on from a previous op — let it serve this gate too.
        fp_reset_power_timer();
#if HAS_R599S
        // R599S: no touch IRQ while powered — start search immediately.
        if(fp_is_ready()) {
            tmos_set_event(hidEmuTaskId, FP_AUTH_EVT);
        }
#endif
        return;
    }

    // Arm gate-pending watchdog. FP_POWER_OFF_EVT handler clears
    // s_pending_cmd / pending auth + emits SEC_ERR_TIMEOUT if it fires
    // with FP still off (i.e. the user never touched).
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, FP_GATE_PENDING_TIMEOUT);
}

static void HidEmu_ImmurokCccChangeCB(uint8_t enabled)
{
    // Only use CCCD disable as a disconnect signal.
    // CCCD enable alone is unreliable — BlueZ restores CCCD for bonded
    // devices on reconnect even without daemon running.  The real
    // "app connected" signal is receiving the first GATT command.
    if(!enabled && s_app_connected) {
        s_app_connected = 0;
        PRINT("App disconnected (CCCD notify disabled)\n");
    }
}

static void HidEmu_ImmurokCommandCB(uint16_t connHandle, uint8_t *pData, uint8_t len)
{
    static uint8_t rspBuf[IMMUROK_RSP_MAX_LEN];  // static: save 64B stack (only 512B total)
    uint8_t rspLen = 1;

    if(len < 2 || len < 2 + pData[1]) {
        rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
        ImmurokService_SendResponse(rspBuf, rspLen);
        return;
    }

    uint8_t cmd = pData[0];
    uint8_t payloadLen = pData[1];

    // First GATT command from daemon marks app as connected.
    // More reliable than CCCD which BlueZ auto-restores for bonded devices.
    if(!s_app_connected) {
        s_app_connected = 1;
        PRINT("App connected (first cmd 0x%02X)\n", cmd);
    }

    PRINT("immurok CMD: 0x%02X, len=%d\n", cmd, payloadLen);

    // Reject all immurok commands during OTA or long ECC operation
    if(s_ota_active || s_long_op_busy) {
        PRINT("  Rejected (%s)\n", s_ota_active ? "OTA" : "ECC busy");
        rspBuf[0] = IMMUROK_RSP_BUSY;
        ImmurokService_SendResponse(rspBuf, rspLen);
        return;
    }

    // Pre-pair gate: an unpaired device only exposes the commands that drive
    // the pairing handshake plus a read-only status query. Without this an
    // attacker who completes BLE Just-Works pairing can enroll fingerprints,
    // write keystore entries, or trigger AUTH_REQUEST / FACTORY_RESET on a
    // device that hasn't been claimed by its legitimate owner yet — leaving
    // persistent state behind that survives the eventual real PAIR_INIT.
    if(!immurok_security_is_paired()) {
        switch(cmd) {
        case IMMUROK_CMD_GET_STATUS:    // App probes "am I paired?"
        case IMMUROK_CMD_GET_BATT_RAW:  // read-only batt calibration data
        case IMMUROK_CMD_PAIR_INIT:     // start ECDH
        case IMMUROK_CMD_PAIR_CONFIRM:  // exchange App pubkey
        case IMMUROK_CMD_PAIR_STATUS:   // read pairing flag
            break;  // allowed pre-pair
        default:
            PRINT("  Rejected (not paired): cmd=0x%02X\n", cmd);
            rspBuf[0] = cmd;
            rspBuf[1] = SEC_ERR_NOT_PAIRED;
            rspLen = 2;
            ImmurokService_SendResponse(rspBuf, rspLen);
            return;
        }
    }

    // Store connection handle for notifications
    ImmurokService_SetConnHandle(connHandle);

    // No-fingerprint gate: a paired device with zero enrolled fingerprints
    // must reject anything that would touch the keystore, run an FP gate,
    // or compute crypto on stored secrets — without an enrolled finger
    // there is no way to authorise such an action, so accepting them on
    // implicit cooldown (the prior fp_gate_needed() returning 0 when
    // bitmap==0) was a hole. App-driven fingerprint-management commands
    // (FP_LIST, ENROLL_START for first enrollment, FACTORY_RESET, etc.)
    // and pure read-only / pubkey paths stay allowed.
    if(g_cached_fp_bitmap == 0) {
        switch(cmd) {
        case IMMUROK_CMD_GET_STATUS:
        case IMMUROK_CMD_GET_BATT_RAW:    // read-only batt data, no FP gate needed
        case IMMUROK_CMD_FP_LIST:
        case IMMUROK_CMD_ENROLL_START:    // first-time enrollment must be allowed
        case IMMUROK_CMD_ENROLL_CANCEL:
        case IMMUROK_CMD_FP_MATCH_ACK:
        case IMMUROK_CMD_PAIR_STATUS:
        case IMMUROK_CMD_PAIR_INIT:       // re-pair (will hit needs_reset gate inside)
        case IMMUROK_CMD_PAIR_CONFIRM:
        case IMMUROK_CMD_FACTORY_RESET:   // recovery escape hatch
        case IMMUROK_CMD_GATE_CANCEL:
        case IMMUROK_CMD_CHALLENGE:       // device authenticity check, no secrets
        case IMMUROK_CMD_KEY_GETPUB:      // public keys are not secret
        case IMMUROK_CMD_KEY_RESULT:      // empty buffer (KEY_SIGN/GENERATE were rejected)
            break;  // allowed without enrolled fingerprint
        default:
            PRINT("  Rejected (no FP enrolled): cmd=0x%02X\n", cmd);
            rspBuf[0] = SEC_ERR_NO_FP_ENROLLED;
            ImmurokService_SendResponse(rspBuf, 1);
            return;
        }
    }

#if HAS_VBAT_ADC
    // Low-battery write protection: block long write/erase operations when
    // the cached battery is below LOW_BATT_REJECT_PCT. A power loss part-way
    // through a 4KB EEPROM erase leaves the keystore corrupted (entries
    // half-erased, headers stale). KEY_SIGN / AUTH / OTP-GET keep working
    // so the user can still authenticate on a dying battery; only the
    // operations that *modify* persistent state are gated.
    {
        #define LOW_BATT_REJECT_PCT 5
        uint8_t batt_lvl = 100;
        Batt_GetParameter(BATT_PARAM_LEVEL, &batt_lvl);
        if(batt_lvl < LOW_BATT_REJECT_PCT) {
            switch(cmd) {
            case IMMUROK_CMD_KEY_WRITE:
            case IMMUROK_CMD_KEY_COMMIT:
            case IMMUROK_CMD_KEY_DELETE:
            case IMMUROK_CMD_KEY_GENERATE:
                PRINT("  Rejected (low batt %d%%): cmd=0x%02X\n", batt_lvl, cmd);
                rspBuf[0] = SEC_ERR_LOW_BATTERY;
                ImmurokService_SendResponse(rspBuf, 1);
                return;
            default:
                break;
            }
        }
    }
#endif

#if HAS_RGB_LED
    // Bulk-read commands light the RGB LED yellow (R+G) so the user can
    // see when the device is being accessed during a batch read. Each
    // qualifying command turns R+G on inline and (re)arms a 100ms off
    // timer; back-to-back commands keep restarting it, so during a batch
    // the LED stays continuously on rather than fluttering with each
    // GATT round-trip (which produced a too-dim PWM-looking effect).
    // After the last command in the batch, the LED dies 100ms later.
    // Limited to fast single-shot reads — long-blocking commands (KEY_SIGN
    // / OTP_GET / etc.) have their own LED feedback already.
    const uint8_t led_indicate =
        (cmd == IMMUROK_CMD_KEY_COUNT  ||
         cmd == IMMUROK_CMD_KEY_READ   ||
         cmd == IMMUROK_CMD_KEY_GETPUB ||
         cmd == IMMUROK_CMD_KEY_RESULT) ? 1 : 0;
    if(led_indicate) {
        LED_RED_On();
        LED_GREEN_On();
        tmos_stop_task(s_led_task_id, LED_ACCESS_OFF_EVT);
        tmos_start_task(s_led_task_id, LED_ACCESS_OFF_EVT, LED_ACCESS_HOLD_TICKS);
    }
#endif

    switch(cmd) {
    case IMMUROK_CMD_GET_STATUS:
        PRINT("  GET_STATUS\n");
        {
            // Use user bitmap — no blocking UART ops in GATT callback
            // (fp_wake blocks ~300ms which overflows the 512B stack in sleep mode)
            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = (uint8_t)fp_user_bitmap();  // 5 slots fit in 1 byte
            rspBuf[2] = immurok_security_is_paired() ? 1 : 0;
            // Read battery from the cache populated by the 5-min periodic
            // measurement (BATT_PERIODIC_EVT in hiddev.c). Inline
            // Batt_MeasLevel() blocks ~250-500ms in vbat_settle_delay (5τ
            // RC settle on the IN_PD↔Floating transition) — that queues
            // every other GATT request behind it, including KEY_SIGN, and
            // combined with the ECDSA ~2s blocking pushes BLE timing to
            // the supervision-timeout edge. The user-initiated refresh
            // button uses HidDev_BattForceUpdate() which is safe (out of
            // band, not stacked behind a sign). Stale cache (up to 5 min)
            // is fine for the status icon.
            uint8_t batt = 0;
            Batt_GetParameter(BATT_PARAM_LEVEL, &batt);
            rspBuf[3] = batt;
            // Firmware version (macOS blocks standard Device Info Service for HID)
            rspBuf[4] = FW_VERSION_MAJOR;
            rspBuf[5] = FW_VERSION_MINOR;
            rspBuf[6] = FW_VERSION_PATCH;
            rspBuf[7] = (FW_BUILD_NUMBER >> 8) & 0xFF;
            rspBuf[8] = FW_BUILD_NUMBER & 0xFF;
            rspLen = 9;

            // If there's a pending FP match (notification lost during disconnect),
            // piggyback the signed data onto GET_STATUS response.
            // App checks byte[9]: 0x21 = pending match, followed by 10 bytes of signed data.
            rspBuf[9] = 0;  // clear separator byte
            if(s_fp_notify_pending && s_fp_notify_len > 0) {
                uint32_t elapsed = (TMOS_GetSystemClock() - s_fp_notify_start_time) * 625 / 1000;
                if(elapsed <= 30000) {
                    memcpy(&rspBuf[10], s_fp_notify_data, s_fp_notify_len);
                    rspLen = 10 + s_fp_notify_len;
                    PRINT("  GET_STATUS: appending pending FP match (%dms old)\n", (int)elapsed);
                } else {
                    PRINT("  GET_STATUS: pending FP match expired (%dms)\n", (int)elapsed);
                }
                s_fp_notify_pending = 0;
            }
        }
        break;

    case IMMUROK_CMD_FP_LIST:
        {
            uint16_t ubm = fp_user_bitmap();
            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = (uint8_t)ubm;  // 5 slots fit in 1 byte
            rspLen = 2;
            PRINT("  FP_LIST: bitmap=0x%02X\n", ubm);
        }
        break;

#if HAS_VBAT_ADC
    case IMMUROK_CMD_GET_BATT_RAW:
        // Optional 1-byte payload flag:
        //   absent / 0x00 → force a fresh Batt_MeasLevel (user-initiated
        //                   refresh — "click to refresh" UX needs immediate
        //                   updates, especially while charging).
        //   0x01          → cached-only — return whatever the most recent
        //                   ADC sample produced. Used by the App's 5-min
        //                   periodic battery-log timer to avoid doubling
        //                   the device's natural BATT_PERIODIC_EVT cadence
        //                   (which already runs every 5 min).
        //
        // SKIP the active measurement when the FP module is powered (touch /
        // search / enroll in progress) — same reasoning as the BATT_PERIODIC
        // path in hiddev.c: vbat_settle's TMOS yields can starve UART1 RX
        // enough to miss a ZW3021 lift ack, leaving R599S with DETECT
        // latched (sensor unresponsive). In that case return the most recent
        // cached values; the App will still see a useful update on next call.
        {
            uint8_t cached_only = (payloadLen >= 1 && pData[2] == 0x01) ? 1 : 0;
            if(!cached_only && !fp_is_powered()) {
                Batt_MeasLevel();
            }
            uint8_t pct = 0;
            Batt_GetParameter(BATT_PARAM_LEVEL, &pct);
            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = s_last_batt_mv & 0xFF;
            rspBuf[2] = (s_last_batt_mv >> 8) & 0xFF;
            rspBuf[3] = pct;
            rspBuf[4] = s_last_batt_adc & 0xFF;
            rspBuf[5] = (s_last_batt_adc >> 8) & 0xFF;
            rspLen = 6;
            PRINT("  GET_BATT_RAW: mv=%u pct=%u adc=%u%s\n",
                  s_last_batt_mv, pct, s_last_batt_adc,
                  cached_only ? " (cached-only)" :
                  (fp_is_powered() ? " (FP busy, cached)" : ""));
        }
        break;
#endif

    case IMMUROK_CMD_ENROLL_START:
        // Payload: [fingerId:1]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t fingerId = pData[2];
            PRINT("  ENROLL_START finger=%d\n", fingerId);

            if(s_enroll_active) {
                rspBuf[0] = IMMUROK_RSP_BUSY;
            } else if(fingerId >= FP_USER_MAX) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            } else {
                uint16_t ubm = fp_user_bitmap();
                if(ubm & (1 << fingerId)) {
                    PRINT("  Finger %d already enrolled (user_bitmap=0x%02X)\n", fingerId, ubm);
                    rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                    break;
                }

                // Fingerprint gate: if any fingerprint exists, require verification
                if(ubm != 0) {
                    PRINT("  FP gate: caching ENROLL_START, waiting for FP verify\n");
                    s_pending_cmd = IMMUROK_CMD_ENROLL_START;
                    s_pending_cmd_start = TMOS_GetSystemClock();
                    s_pending_payload[0] = fingerId;
                    s_pending_payload_len = 1;
                    fp_gate_enter();
                    rspBuf[0] = IMMUROK_RSP_WAIT_FP;
                } else {
                    // No fingerprints yet, allow directly
                    s_enroll_page_id = fingerId;
                    s_enroll_step = 0;
                    s_enroll_substate = 0;
                    s_enroll_capture = 0;
                    s_enroll_active = 1;
                    tmos_set_event(hidEmuTaskId, FP_ENROLL_EVT);
                    rspBuf[0] = IMMUROK_RSP_OK;
                }
            }
        }
        break;

    case IMMUROK_CMD_ENROLL_CANCEL:
        PRINT("  ENROLL_CANCEL active=%d\n", s_enroll_active);
        if(s_enroll_active) {
            // No PS_Cancel needed — manual enrollment has no long-running module command
            s_enroll_active = 0;
            s_enroll_step = 0;
            s_enroll_substate = 0;
            s_enroll_capture = 0;
            tmos_stop_task(hidEmuTaskId, FP_ENROLL_EVT);
#if HAS_RGB_LED
            led_solid('R', LED_FLASH_TICKS);
#elif HAS_FP_LED
            fp_led_flash(FP_LED_RED, 25, 1);
#endif
            fp_reset_power_timer();
        }
        rspBuf[0] = IMMUROK_RSP_OK;
        break;

    case IMMUROK_CMD_DELETE_FP:
        // Payload: [fingerId:1]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t fingerId = pData[2];
            PRINT("  DELETE_FP finger=%d\n", fingerId);

            if(fingerId >= FP_USER_MAX) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                break;
            }

            uint8_t ubm = fp_user_bitmap();
            if(ubm != 0) {
                PRINT("  FP gate: caching DELETE_FP, waiting for FP verify\n");
                s_pending_cmd = IMMUROK_CMD_DELETE_FP;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = fingerId;
                s_pending_payload_len = 1;
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints exist — nothing to delete
                rspBuf[0] = IMMUROK_RSP_OK;
            }
        }
        break;

    case IMMUROK_CMD_AUTH_REQUEST:
        // No payload needed
        PRINT("  AUTH_REQUEST\n");
        {
            immurok_security_set_auth_state(AUTH_STATE_WAIT_FINGERPRINT);
            s_pending_cmd_start = TMOS_GetSystemClock();  // shared gate timer
            fp_gate_enter();
            rspBuf[0] = IMMUROK_RSP_WAIT_FP;
        }
        break;

    case IMMUROK_CMD_PAIR_INIT:
        PRINT("  PAIR_INIT\n");
        {
            // Refuse re-pair while fingerprints are still enrolled. Prevents
            // orphan templates from a previous user surviving into a session
            // with new shared keys. App must factory-reset first.
            // (The pre-pair dispatch gate above prevents an attacker from
            // writing keystore entries on an unpaired device, so the only way
            // to reach this case with non-empty keystore is post-pair user
            // action — re-pair from that state still requires factory_reset
            // because the FP bitmap check below covers the common case.)
            if(fp_user_bitmap() != 0) {
                PRINT("  PAIR_INIT rejected: FP bitmap=0x%02X (need factory reset)\n",
                      fp_user_bitmap());
                rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                rspBuf[1] = SEC_ERR_NEEDS_RESET;
                rspLen = 2;
                break;
            }

            // ECDH needs timeout >= 5s; request param update early
            if(s_conn_timeout < 500) {
                tmos_set_event(hidEmuTaskId, START_PARAM_UPDATE_EVT);
            }

            // Require a physical button press before running ECDH. Tells the
            // App to display "press the device button" and starts a 30s
            // window. ECDH actually kicks off in the BUTTON_SCAN_EVT handler
            // when s_pair_wait_button == 1 and a short press is observed.
            s_pair_wait_button = 1;
#if HAS_RGB_LED
            // Slow white blink to draw attention to the device
            led_blink_start_ex('W', 320, 320);
            tmos_stop_task(s_led_task_id, PAIR_BTN_TIMEOUT_EVT);
            tmos_start_task(s_led_task_id, PAIR_BTN_TIMEOUT_EVT, PAIR_BTN_TIMEOUT_TICKS);
#endif
            rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
            rspBuf[1] = SEC_ERR_WAIT_BUTTON;
            rspLen = 2;
        }
        break;

    case IMMUROK_CMD_PAIR_CONFIRM:
        PRINT("  PAIR_CONFIRM\n");
        if(payloadLen != 33) {
            rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
            rspBuf[1] = SEC_ERR_INVALID_PARAM;
            rspLen = 2;
            break;
        }
        {
            // Receive App compressed pubkey, start shared_secret via TMOS event
            if(immurok_security_pair_confirm(&pData[2]) == 0) {
                tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                // No immediate response — response sent from TMOS event handler
                return;
            } else {
                rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
                rspBuf[1] = SEC_ERR_INVALID_STATE;
                rspLen = 2;
            }
        }
        break;

    case IMMUROK_CMD_PAIR_STATUS:
        PRINT("  PAIR_STATUS\n");
        {
            rspBuf[0] = IMMUROK_CMD_PAIR_STATUS;
            rspBuf[1] = immurok_security_is_paired() ? 0x01 : 0x00;
            rspLen = 2;
        }
        break;

    case IMMUROK_CMD_CHALLENGE:
        PRINT("  CHALLENGE\n");
        if(payloadLen < 8) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            rspBuf[0] = IMMUROK_CMD_CHALLENGE;
            if(immurok_security_challenge_response(&pData[2], &rspBuf[1]) == 0) {
                rspLen = 9;  // [0x38][hmac:8B]
            } else {
                rspBuf[1] = 0xFF;  // not paired
                rspLen = 2;
            }
        }
        break;

    case IMMUROK_CMD_FP_MATCH_ACK:
        PRINT("  FP_MATCH_ACK received\n");
        if(s_fp_notify_pending)
        {
            s_fp_notify_pending = 0;
            tmos_stop_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT);
            PRINT("  Notify retry cancelled (ACK OK)\n");
        }
        rspBuf[0] = IMMUROK_RSP_OK;
        break;

    case IMMUROK_CMD_FACTORY_RESET:
        PRINT("  FACTORY_RESET\n");
        {
            if(fp_user_bitmap() != 0) {
                PRINT("  FP gate: caching FACTORY_RESET, waiting for FP verify\n");
                s_pending_cmd = IMMUROK_CMD_FACTORY_RESET;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload_len = 0;
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints — clear security, send OK, defer bond erase + reboot
                immurok_security_factory_reset();
                rspBuf[0] = IMMUROK_RSP_OK;
                // Response sent below via break; defer bond erase after BLE transmits
                s_factory_reset_pending = 1;
                tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, 320);  // 200ms
            }
        }
        break;

    // ---- Keystore commands ----

    case IMMUROK_CMD_KEY_COUNT:
        // Payload: [cat:1B]
        // Response: [OK][count:1B][checksum:4B LE] = 6 bytes
        // (Old clients reading just the first 2 bytes still work — checksum
        //  is appended; on a checksum-aware client a mismatch with the
        //  cached digest triggers a full list re-fetch.)
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            int cnt = immurok_keystore_count(cat);
            if(cnt < 0) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            } else {
                uint32_t cs = immurok_keystore_checksum(cat);
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = (uint8_t)cnt;
                rspBuf[2] = (uint8_t)(cs & 0xFF);
                rspBuf[3] = (uint8_t)((cs >> 8) & 0xFF);
                rspBuf[4] = (uint8_t)((cs >> 16) & 0xFF);
                rspBuf[5] = (uint8_t)((cs >> 24) & 0xFF);
                rspLen = 6;
            }
            PRINT("  KEY_COUNT cat=%d count=%d cs=0x%08X\n", cat, cnt,
                  (cnt < 0) ? 0 : (unsigned)immurok_keystore_checksum(cat));
        }
        break;

    case IMMUROK_CMD_KEY_READ:
        // Payload: [cat:1B][idx:1B][off:1B]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            uint8_t off = pData[4];

            // Determine readable limit for this category.
            // Secret portions are never exposed via KEY_READ.
            uint16_t readable_size = 0;
            switch(cat) {
            case KEYSTORE_CAT_SSH:
                readable_size = 80;                      // name[16] + pubkey[64], hide privkey
                break;
            case KEYSTORE_CAT_OTP:
                readable_size = 60;                      // name[30] + service[30], hide secret
                break;
            case KEYSTORE_CAT_API:
                readable_size = KEYSTORE_API_ENTRY_SIZE; // full read allowed (FP gate below)
                break;
            default:
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                ImmurokService_SendResponse(rspBuf, rspLen);
                return;  // LED_ACCESS_OFF_EVT handles trailing off
            }

            // API entries (name[32] + key[128]): two-level gate to allow
            // QuickFill / list display to read names without FP, while still
            // protecting secret bytes.
            //   - off >= 32 (pure secret read): must be FP-gated. Either
            //     KEYSTORE or AUTH cooldown satisfies (asymmetric — AUTH
            //     grants secret access, but secret read does NOT grant AUTH).
            //   - off < 32 (name read): always allowed, but chunk is capped
            //     at 32-off below to prevent spilling into secret region.
            // Original 1.2.5 fix gated EVERY API read which broke QuickFill
            // (no way to display names without first triggering FP). This
            // restores name reads while keeping secret protection.
            if(cat == KEYSTORE_CAT_API && off >= 32
               && fp_gate_needed(FP_CAT_KEYSTORE)
               && fp_gate_needed(FP_CAT_AUTH)) {
                rspBuf[0] = SEC_ERR_WAIT_FP;
                break;
            }

            if(off >= readable_size) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                break;
            }

            uint16_t remaining = readable_size - off;
            uint8_t chunk = (remaining > 59) ? 59 : (uint8_t)remaining;

            // API: cap name-region read so it never spills into secret.
            // Caller must do a separate off>=32 request (FP-gated above) to
            // read secret bytes.
            if(cat == KEYSTORE_CAT_API && off < 32 && off + chunk > 32) {
                chunk = 32 - off;
            }

            // Response: [OK][total_lo:1B][off:1B][data...<=59B]
            // Note: total_lo = readable_size & 0xFF (App uses known size)
            if(immurok_keystore_read(cat, idx, off, &rspBuf[3], chunk) == 0) {
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = (uint8_t)(readable_size & 0xFF);
                rspBuf[2] = off;
                rspLen = 3 + chunk;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
            PRINT("  KEY_READ cat=%d idx=%d off=%d chunk=%d\n", cat, idx, off, chunk);
        }
        break;

    case IMMUROK_CMD_KEY_WRITE:
        // Payload: [cat:1B][idx:1B][off:1B][data...<=59B]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            uint8_t off = pData[4];
            uint8_t data_len = payloadLen - 3;

            if(immurok_keystore_stage(cat, idx, off, &pData[5], data_len) == 0) {
                rspBuf[0] = IMMUROK_RSP_OK;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
            PRINT("  KEY_WRITE cat=%d idx=%d off=%d len=%d\n", cat, idx, off, data_len);
        }
        break;

    case IMMUROK_CMD_KEY_DELETE:
        // Payload: [cat:1B][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            PRINT("  KEY_DELETE cat=%d idx=%d\n", cat, idx);

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed(FP_CAT_KEYSTORE)) {
                PRINT("  FP gate: caching KEY_DELETE\n");
                s_pending_cmd = IMMUROK_CMD_KEY_DELETE;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = cat;
                s_pending_payload[1] = idx;
                s_pending_payload_len = 2;
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                rspBuf[0] = (immurok_keystore_delete(cat, idx) == 0)
                            ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
            }
        }
        break;

    case IMMUROK_CMD_KEY_COMMIT:
        // Payload: [cat:1B][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            PRINT("  KEY_COMMIT cat=%d idx=%d\n", cat, idx);

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed(FP_CAT_KEYSTORE)) {
                PRINT("  FP gate: caching KEY_COMMIT\n");
                s_pending_cmd = IMMUROK_CMD_KEY_COMMIT;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = cat;
                s_pending_payload[1] = idx;
                s_pending_payload_len = 2;
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                rspBuf[0] = (immurok_keystore_commit(cat, idx) == 0)
                            ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
            }
        }
        break;

    // ---- SSH crypto commands ----

    case IMMUROK_CMD_KEY_SIGN:
        // Payload: [cat:1B(0)][idx:1B][hash_off:1B][hash_data...]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[3];
            uint8_t hash_off = pData[4];
            uint8_t data_len = payloadLen - 3;
            PRINT("  KEY_SIGN idx=%d off=%d len=%d\n", idx, hash_off, data_len);

            // Store hash fragment into pending_payload
            if(hash_off + data_len <= 32) {
                memcpy(&s_pending_payload[2 + hash_off], &pData[5], data_len);
            }

            // Only proceed when we have the complete hash (off=0 with 32B is single-shot)
            if(hash_off == 0 && data_len >= 32) {
                // Fingerprint gate (with cooldown for batch ops)
                // Always defer ECDSA sign to TMOS event (~2s blocks BLE if done here)
                s_pending_cmd = IMMUROK_CMD_KEY_SIGN;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = 0;  // cat (SSH)
                s_pending_payload[1] = idx;
                memcpy(&s_pending_payload[2], &pData[5], 32);
                s_pending_payload_len = 34;

                // Asymmetric grant: AUTH cooldown also satisfies KEY_SIGN —
                // matches the API secret-read pattern (cat=API off>=32).
                // Lets `imk run --agent` cover ssh-key signing with a single
                // touch: AGENT_APPROVE → AUTH cooldown set → git pull's
                // ssh-sign within 10 s rides the cooldown without re-FP.
                // (Reverse direction stays gated — KEY_SIGN does NOT grant
                // AUTH, so secret access can't escalate to sudo.)
                if(fp_gate_needed(FP_CAT_KEYSTORE) && fp_gate_needed(FP_CAT_AUTH)) {
                    PRINT("  FP gate: caching KEY_SIGN\n");
                    fp_gate_enter();
                    rspBuf[0] = IMMUROK_RSP_WAIT_FP;
                } else {
                    // Cooldown — approved implicitly, defer ECDSA to TMOS
                    // Send 0x10 explicitly + 80ms delay (like FP gate path)
                    // so BLE flushes notification before ECC blocks (~2s)
                    PRINT("  KEY_SIGN cooldown, deferred to TMOS\n");
                    // Pre-request param update if needed (no FP wait to buy time)
                    if(!s_latency_accepted) {
                        tmos_set_event(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                    }
                    uint8_t fpApproved[1] = { 0x10 };
                    ImmurokService_SendResponse(fpApproved, 1);
                    tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 128);  // 80ms
                    return;
                }
            } else {
                // Partial hash received, ACK
                rspBuf[0] = IMMUROK_RSP_OK;
            }
        }
        break;

    case IMMUROK_CMD_KEY_GETPUB:
        // Payload: [cat:1B(0)][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[3];
            PRINT("  KEY_GETPUB idx=%d\n", idx);

            if(immurok_keystore_getpub(idx, immurok_keystore_result_buf()) == 0) {
                immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = 64;
                rspLen = 2;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
        }
        break;

    case IMMUROK_CMD_KEY_GENERATE:
        // Payload: [cat:1B(0)][name_data_16B]
        if(payloadLen < 17) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            PRINT("  KEY_GENERATE\n");

            // Always defer ECC keygen to TMOS event (~2s blocks BLE if done here)
            s_pending_cmd = IMMUROK_CMD_KEY_GENERATE;
            s_pending_cmd_start = TMOS_GetSystemClock();
            memcpy(s_pending_payload, &pData[2], 17);  // cat + 16B name
            s_pending_payload_len = 17;

            if(fp_gate_needed(FP_CAT_KEYSTORE)) {
                PRINT("  FP gate: caching KEY_GENERATE\n");
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                PRINT("  KEY_GENERATE deferred to TMOS\n");
                if(!s_latency_accepted) {
                    tmos_set_event(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                }
                tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                return;  // Response sent from TMOS event handler
            }
        }
        break;

    case IMMUROK_CMD_KEY_RESULT:
        // Payload: [off:1B]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t off = pData[2];
            uint8_t total = immurok_keystore_result_len();
            PRINT("  KEY_RESULT off=%d total=%d\n", off, total);

            if(off >= total) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                break;
            }

            uint8_t remaining = total - off;
            uint8_t chunk = (remaining > 59) ? 59 : remaining;
            uint8_t *rbuf = immurok_keystore_result_buf();

            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = total;
            rspBuf[2] = off;
            memcpy(&rspBuf[3], &rbuf[off], chunk);
            rspLen = 3 + chunk;
        }
        break;

    case IMMUROK_CMD_KEY_OTP_GET:
        // Payload: [idx:1B][timestamp:4B LE]
        if(payloadLen < 5) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[2];
            uint32_t ts = (uint32_t)pData[3]
                        | ((uint32_t)pData[4] << 8)
                        | ((uint32_t)pData[5] << 16)
                        | ((uint32_t)pData[6] << 24);
            PRINT("  KEY_OTP_GET idx=%d ts=%lu\n", idx, ts);

            // Fingerprint gate (with cooldown for batch ops). Same asymmetric
            // grant as KEY_SIGN / API secret read: AUTH cooldown also
            // satisfies — `imk run --agent` covers the whole agent session
            // including OTP code generation without re-FP. Reverse direction
            // stays gated.
            if(fp_gate_needed(FP_CAT_KEYSTORE) && fp_gate_needed(FP_CAT_AUTH)) {
                PRINT("  FP gate: caching KEY_OTP_GET\n");
                s_pending_cmd = IMMUROK_CMD_KEY_OTP_GET;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = idx;
                s_pending_payload[1] = pData[3];
                s_pending_payload[2] = pData[4];
                s_pending_payload[3] = pData[5];
                s_pending_payload[4] = pData[6];
                s_pending_payload_len = 5;
                fp_gate_enter();
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints enrolled, compute directly
                uint8_t code[6];
                if(immurok_keystore_totp(idx, ts, code) == 0) {
                    rspBuf[0] = IMMUROK_RSP_OK;
                    memcpy(&rspBuf[1], code, 6);
                    rspLen = 7;
                } else {
                    rspBuf[0] = SEC_ERR_INTERNAL;
                }
            }
        }
        break;

    case IMMUROK_CMD_GATE_CANCEL:
        PRINT("  GATE_CANCEL\n");
        if(s_pending_cmd != 0) {
            PRINT("  Clearing pending cmd 0x%02X\n", s_pending_cmd);
            s_pending_cmd = 0;
            s_pending_payload_len = 0;
        }
        if(immurok_security_has_pending_auth()) {
            immurok_security_auth_cancel();
        }
        // Stop all gate-related activity
        s_gate_fail_count = 0;
        s_gate_preheat = 0;
        s_search_active = 0;
        s_wait_finger_lift = 0;
        tmos_stop_task(hidEmuTaskId, FP_SEARCH_EVT);
        tmos_stop_task(hidEmuTaskId, FP_AUTH_EVT);
        tmos_stop_task(hidEmuTaskId, FP_WAKE_DONE_EVT);
#if HAS_RGB_LED
        led_solid('R', 1600);  // red 1s
#endif
        fp_reset_power_timer();
        rspBuf[0] = IMMUROK_RSP_OK;
        break;

    default:
        PRINT("  Unknown command\n");
        rspBuf[0] = IMMUROK_RSP_UNKNOWN_CMD;
        break;
    }

    // Send response
    ImmurokService_SendResponse(rspBuf, rspLen);
    // (LED off is handled by LED_ACCESS_OFF_EVT 100ms after the last cmd.)
}

/*********************************************************************
 * OTA IAP Functions
 *********************************************************************/

// Reset the OTA inactivity watchdog. Called at OTA entry and on every OTA
// IAP command. Reuses FP_POWER_OFF_EVT because FP is powered off during OTA
// so the FP idle path is dormant; the same event slot dispatches by
// s_ota_active in HidEmu_ProcessEvent.
static void ota_kick_timeout(void)
{
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, OTA_IDLE_TIMEOUT_TICKS);
}

// Tear down OTA state and restore the device to its pre-OTA appearance.
// Called from (a) disconnect cleanup, (b) OTA inactivity timeout. Idempotent
// — safe to call when s_ota_active is already 0.
static void ota_abort_to_idle(void)
{
    if(!s_ota_active) return;

    PRINT("OTA: abort to idle\n");
    s_ota_active = 0;
    tmos_stop_task(hidEmuTaskId, OTA_FLASH_ERASE_EVT);
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    tmos_memset(&s_ota_sec, 0, sizeof(s_ota_sec));
    s_ota_verify_status = 0;

    // Stop the fast blue progress blink left over from OTA HEADER. The
    // disconnect path takes care of starting advertising blink afterwards;
    // for the inactivity-timeout case (BLE still up), LED-off matches the
    // normal connected-idle state, so no further action needed here.
#if HAS_RGB_LED
    led_stop();
#elif HAS_FP_LED
    fp_led_off();
#endif

    // Restore connection parameters (OTA entry requested latency 0 for
    // throughput; back to the normal power-saving latency).
    if(s_ble_connected) {
        GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
            DEFAULT_DESIRED_MIN_CONN_INTERVAL,
            DEFAULT_DESIRED_MAX_CONN_INTERVAL,
            DEFAULT_DESIRED_SLAVE_LATENCY,
            DEFAULT_DESIRED_CONN_TIMEOUT,
            hidEmuTaskId);
    }
}

/*********************************************************************
 * @fn      OTA_IAP_SendStatus
 * @brief   Send OTA command status response
 */
static void OTA_IAP_SendStatus(uint8_t status)
{
    uint8_t buf[2];
    buf[0] = status;
    buf[1] = 0;
    OTAProfile_SendData(OTAPROFILE_CHAR, buf, 2);
}

/*********************************************************************
 * @fn      OTA_IAP_DataDeal
 * @brief   Process received OTA IAP command
 */
static void OTA_IAP_DataDeal(void)
{
    uint8_t cmd = s_ota_iap_data.other.buf[0];
    uint32_t addr, len;
    uint8_t status;

    // Refresh inactivity watchdog on every OTA cmd received during an
    // active session. The CMD_IAP_ERASE case arms the timer on first entry;
    // subsequent HEADER/PROM/VERIFY/END refresh it here. CMD_IAP_INFO
    // before s_ota_active is set (App probing device info) skips this.
    if(s_ota_active) {
        ota_kick_timeout();
    }

    // OTA does NOT require an enrolled fingerprint:
    // - HMAC-SHA256 over the .imfw header is the actual security gate;
    //   anything not signed by OTA_SIGNING_KEY is rejected at CMD_IAP_END.
    // - Fresh device (just unboxed, no FP enrolled yet) needs to be able to
    //   take a server-pushed firmware update before the user finishes
    //   provisioning — the prior FP gate broke that OOBE flow.
    // - Worst case without signing key: attacker erases Image B (B is the
    //   inactive image; A keeps running) and never finishes — recoverable
    //   by disconnect. Image A is never touched mid-OTA.

#if HAS_VBAT_ADC
    // Low-battery write protection: an OTA mid-write losing power leaves
    // Image B partially erased / partially programmed → JumpIAP picks the
    // wrong image on next boot. INFO read stays allowed (App-side probe).
    if(cmd != CMD_IAP_INFO) {
        uint8_t batt_lvl = 100;
        Batt_GetParameter(BATT_PARAM_LEVEL, &batt_lvl);
        if(batt_lvl < 5) {
            PRINT("OTA rejected: low battery %d%% (cmd=0x%02X)\n", batt_lvl, cmd);
            OTA_IAP_SendStatus(0xF4);  // SEC_ERR_LOW_BATTERY
            return;
        }
    }
#endif

    switch(cmd)
    {
        case CMD_IAP_PROM:
        {
            // Program flash data
            len = s_ota_iap_data.program.len;
            addr = (uint32_t)(s_ota_iap_data.program.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.program.addr[1]) << 8);
            addr = addr * 16;  // Address is 16-byte aligned
            addr += IMAGE_B_START_ADD;  // Offset to Image B

            PRINT("OTA PROM: addr=%08x len=%d\n", (int)addr, (int)len);

            // Reject lengths that don't fit program.buf — caller-controlled
            // attacker can otherwise drive aes128_ctr_xcrypt / sha256_update /
            // FLASH_ROM_WRITE past the 243-byte buffer into adjacent BSS
            // (s_ota_sec, s_pending_payload, shared_key state).
            if(len == 0 || len > sizeof(s_ota_iap_data.program.buf))
            {
                PRINT("OTA PROM: invalid len %d\n", (int)len);
                OTA_IAP_SendStatus(0xFD);
                break;
            }

            // Verify address is within Image B
            if(addr < IMAGE_B_START_ADD || (addr + len) > IMAGE_IAP_START_ADD)
            {
                PRINT("OTA PROM: address out of range\n");
                OTA_IAP_SendStatus(0xFF);
                break;
            }

            // Require HEADER before WRITE (no plaintext OTA)
            if(!s_ota_sec.active)
            {
                PRINT("OTA PROM: rejected - no HEADER\n");
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            {
                // Decrypt in-place, update SHA256
                uint32_t stream_offset = s_ota_sec.bytes_written;
                aes128_ctr_xcrypt(&s_ota_sec.aes_ctx, s_ota_sec.header.iv,
                                  stream_offset,
                                  s_ota_iap_data.program.buf, (size_t)len);
                sha256_update(&s_ota_sec.sha256_ctx,
                              s_ota_iap_data.program.buf, (size_t)len);
                s_ota_sec.bytes_written += len;
            }

            status = FLASH_ROM_WRITE(addr, s_ota_iap_data.program.buf, (uint16_t)len);
            if(status != SUCCESS)
            {
                PRINT("OTA PROM failed: %d\n", status);
            }
            OTA_IAP_SendStatus(status);
            break;
        }

        case CMD_IAP_HEADER:
        {
            // Receive .imfw header (96 bytes in program.buf area)
            // Raw data starts at buf[2] (skip cmd + len)
            uint8_t *hdr_data = &s_ota_iap_data.other.buf[2];
            uint8_t hdr_len = s_ota_iap_data.other.buf[1];

            PRINT("OTA HEADER: len=%d (expected %d)\n", hdr_len, IMFW_HEADER_SIZE);

            if(hdr_len != IMFW_HEADER_SIZE)
            {
                PRINT("OTA HEADER: invalid size\n");
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            // Copy header
            memcpy(&s_ota_sec.header, hdr_data, IMFW_HEADER_SIZE);

            // Validate magic and hardware ID
            if(s_ota_sec.header.magic != IMFW_MAGIC)
            {
                PRINT("OTA HEADER: bad magic 0x%08lx\n", (unsigned long)s_ota_sec.header.magic);
                OTA_IAP_SendStatus(0xFD);
                break;
            }
            if(s_ota_sec.header.hw_id != IMFW_HARDWARE_ID)
            {
                PRINT("OTA HEADER: bad hw_id 0x%04x\n", s_ota_sec.header.hw_id);
                OTA_IAP_SendStatus(0xFC);
                break;
            }
            if(s_ota_sec.header.fw_size > IMAGE_SIZE)
            {
                PRINT("OTA HEADER: fw too large %lu\n", (unsigned long)s_ota_sec.header.fw_size);
                OTA_IAP_SendStatus(0xFB);
                break;
            }

            // Initialize AES and SHA256 contexts
            aes128_init(&s_ota_sec.aes_ctx, OTA_AES_KEY);
            sha256_init(&s_ota_sec.sha256_ctx);
            s_ota_sec.bytes_written = 0;
            s_ota_sec.active = 1;

            PRINT("OTA HEADER: secure OTA initialized, fw_size=%lu\n",
                  (unsigned long)s_ota_sec.header.fw_size);

            // Visible OTA progress indicator: fast blue blink starts at HEADER,
            // runs through all PROM/ERASE writes (~50s), and is replaced by
            // green/red at END based on verify result. Helps the user know
            // "device is busy, do not power off".
#if HAS_RGB_LED
            led_blink_start_ex('B', 80, 80);  // ~12.5 Hz, 50ms on / 50ms off
#elif HAS_FP_LED
            fp_led_flash(FP_LED_BLUE, 5, 0);  // continuous fast blue blink
#endif

            OTA_IAP_SendStatus(SUCCESS);
            break;
        }

        case CMD_IAP_ERASE:
        {
            // Erase flash blocks (async to avoid BLE timeout)
            addr = (uint32_t)(s_ota_iap_data.erase.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.erase.addr[1]) << 8);
            addr = addr * 16;
            addr += IMAGE_B_START_ADD;

            uint32_t block_num = (uint32_t)(s_ota_iap_data.erase.block_num[0]);
            block_num |= ((uint32_t)(s_ota_iap_data.erase.block_num[1]) << 8);

            PRINT("OTA ERASE: addr=%08x blocks=%d\n", (int)addr, (int)block_num);

            // Verify address range
            if(addr < IMAGE_B_START_ADD ||
               (addr + (block_num - 1) * FLASH_BLOCK_SIZE) > IMAGE_IAP_START_ADD)
            {
                PRINT("OTA ERASE: address out of range\n");
                OTA_IAP_SendStatus(0xFF);
                break;
            }

            s_ota_erase_addr = addr;
            s_ota_erase_blocks = block_num;
            s_ota_erase_count = 0;
            s_ota_verify_status = 0;

            // Enter OTA mode: suppress fingerprint, HID, etc.
            if(!s_ota_active)
            {
                s_ota_active = 1;
                ota_kick_timeout();  // arm 10s inactivity watchdog
                PRINT("OTA mode active - all other functions suppressed\n");
                // OTA takes over OTA_FLASH_ERASE_EVT (== FP_GATE_EXEC_EVT).
                // If a KEY_SIGN/KEY_GENERATE FP-match dispatch set busy=1 and
                // scheduled the event in the last 200ms, OTA will consume the
                // event in its own branch — clear the leftover lock here so
                // the post-OTA reboot path doesn't matter and immurok cmds
                // aren't permanently shut out if OTA aborts mid-flow.
                s_long_op_busy = 0;
                s_pending_cmd = 0;
                s_pending_payload_len = 0;
                tmos_stop_task(hidEmuTaskId, FP_GATE_EXEC_EVT);
                // Power off fingerprint if running
                fp_power_off();
                // Stop param update timer so it won't override OTA latency
                tmos_stop_task(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                // Request latency 0 for fast OTA data transfer
                GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                    DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                    DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                    0,  // latency 0 during OTA
                    DEFAULT_DESIRED_CONN_TIMEOUT,
                    hidEmuTaskId);
                PRINT("OTA: requested latency 0\n");
            }

            // Start async erase
            tmos_set_event(hidEmuTaskId, OTA_FLASH_ERASE_EVT);
            break;
        }

        case CMD_IAP_VERIFY:
        {
            // Verify flash data
            len = s_ota_iap_data.verify.len;
            addr = (uint32_t)(s_ota_iap_data.verify.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.verify.addr[1]) << 8);
            addr = addr * 16;
            addr += IMAGE_B_START_ADD;

            PRINT("OTA VERIFY: addr=%08x len=%d\n", (int)addr, (int)len);

            // Same OOB-read defence as PROM: caller-controlled len can drive
            // FLASH_ROM_VERIFY past verify.buf (243B) into adjacent BSS.
            if(len == 0 || len > sizeof(s_ota_iap_data.verify.buf))
            {
                PRINT("OTA VERIFY: invalid len %d\n", (int)len);
                OTA_IAP_SendStatus(0xFD);
                break;
            }

            // Verify address is within Image B (PROM had this; VERIFY did not,
            // letting an attacker turn FLASH_ROM_VERIFY into a 1-bit oracle
            // for arbitrary flash/IAP regions).
            if(addr < IMAGE_B_START_ADD || (addr + len) > IMAGE_IAP_START_ADD)
            {
                PRINT("OTA VERIFY: address out of range\n");
                OTA_IAP_SendStatus(0xFF);
                break;
            }

            status = FLASH_ROM_VERIFY(addr, s_ota_iap_data.verify.buf, len);
            if(status != SUCCESS)
            {
                PRINT("OTA VERIFY failed\n");
            }
            s_ota_verify_status |= status;
            OTA_IAP_SendStatus(s_ota_verify_status);
            break;
        }

        case CMD_IAP_END:
        {
            PRINT("OTA END\n");

            // Require HEADER before END (no plaintext OTA)
            if(!s_ota_sec.active)
            {
                PRINT("OTA END: rejected - no HEADER\n");
                s_ota_active = 0;
                // Restore original latency
                GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                    DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                    DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                    DEFAULT_DESIRED_SLAVE_LATENCY,
                    DEFAULT_DESIRED_CONN_TIMEOUT,
                    hidEmuTaskId);
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            {
                // Verify SHA256 + HMAC before accepting
                // Static to avoid stack overflow (BLE callback chain ~200B + HMAC ~112B = ~500B/512B)
                static uint8_t computed[32];

                // Step 1: Verify SHA256 of decrypted firmware
                sha256_final(&s_ota_sec.sha256_ctx, computed);
                if(memcmp(computed, s_ota_sec.header.fw_sha256, 32) != 0)
                {
                    PRINT("OTA END: SHA256 mismatch!\n");
                    s_ota_sec.active = 0;
                    s_ota_active = 0;
#if HAS_RGB_LED
                    led_solid('R', 1600);  // 1s red — verify failed
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 15, 5);
#endif
                    GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                        DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                        DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                        DEFAULT_DESIRED_SLAVE_LATENCY,
                        DEFAULT_DESIRED_CONN_TIMEOUT,
                        hidEmuTaskId);
                    OTA_IAP_SendStatus(OTA_ERR_SHA256_MISMATCH);
                    break;
                }
                PRINT("OTA END: SHA256 OK\n");

                // Step 2: Verify HMAC-SHA256 of header[0:0x40]
                static uint8_t computed_hmac[32];
                immurok_hmac_sha256(OTA_SIGNING_KEY, sizeof(OTA_SIGNING_KEY),
                                    (const uint8_t *)&s_ota_sec.header, 0x40,
                                    computed_hmac);
                if(memcmp(computed_hmac, s_ota_sec.header.hmac, 32) != 0)
                {
                    PRINT("OTA END: HMAC mismatch!\n");
                    s_ota_sec.active = 0;
                    s_ota_active = 0;
#if HAS_RGB_LED
                    led_solid('R', 1600);  // 1s red — signature failed
#elif HAS_FP_LED
                    fp_led_flash(FP_LED_RED, 15, 5);
#endif
                    GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                        DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                        DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                        DEFAULT_DESIRED_SLAVE_LATENCY,
                        DEFAULT_DESIRED_CONN_TIMEOUT,
                        hidEmuTaskId);
                    OTA_IAP_SendStatus(OTA_ERR_HMAC_MISMATCH);
                    break;
                }
                PRINT("OTA END: HMAC OK - firmware verified!\n");

                s_ota_sec.active = 0;
            }

            PRINT("OTA END - scheduling reboot\n");

            // Cancel the OTA inactivity watchdog. tmos_set_event below schedules
            // the reboot for the next event loop iteration, so 10s is plenty of
            // margin — but explicitly stopping the watchdog removes the race
            // entirely (watchdog would otherwise call ota_abort_to_idle which
            // stops OTA_FLASH_ERASE_EVT and would cancel the pending reboot).
            tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);

            // Verify success — switch from blue progress to solid green so the
            // user sees "done, rebooting" before the actual reset wipes LED.
#if HAS_RGB_LED
            led_solid('G', 0);  // stay on until reboot
#elif HAS_FP_LED
            fp_led_flash(FP_LED_GREEN, 25, 2);
#endif

            // Defer EEPROM write + reset to TMOS event (not safe in GATT callback)
            s_ota_reboot_pending = 1;
            tmos_set_event(hidEmuTaskId, OTA_FLASH_ERASE_EVT);
            break;
        }

        case CMD_IAP_INFO:
        {
            uint8_t info_buf[20];

            PRINT("OTA INFO\n");

            // Image flag (currently running Image A)
            info_buf[0] = IMAGE_B_FLAG;

            // Image size (little-endian)
            info_buf[1] = (uint8_t)(IMAGE_SIZE & 0xFF);
            info_buf[2] = (uint8_t)((IMAGE_SIZE >> 8) & 0xFF);
            info_buf[3] = (uint8_t)((IMAGE_SIZE >> 16) & 0xFF);
            info_buf[4] = (uint8_t)((IMAGE_SIZE >> 24) & 0xFF);

            // Block size
            info_buf[5] = (uint8_t)(FLASH_BLOCK_SIZE & 0xFF);
            info_buf[6] = (uint8_t)((FLASH_BLOCK_SIZE >> 8) & 0xFF);

            // Chip ID
            info_buf[7] = CHIP_ID & 0xFF;
            info_buf[8] = (CHIP_ID >> 8) & 0xFF;

            // Reserved
            for(int i = 9; i < 20; i++) {
                info_buf[i] = 0;
            }

            OTAProfile_SendData(OTAPROFILE_CHAR, info_buf, 20);
            break;
        }

        default:
            PRINT("OTA: unknown cmd 0x%02X\n", cmd);
            OTA_IAP_SendStatus(0xFE);
            break;
    }
}

/*********************************************************************
 * @fn      OTA_IAPReadDataComplete
 * @brief   OTA read complete callback
 */
static void OTA_IAPReadDataComplete(uint8_t paramID)
{
    PRINT("OTA read complete\n");
}

/*********************************************************************
 * @fn      OTA_IAPWriteData
 * @brief   OTA write callback - process received data
 */
static void OTA_IAPWriteData(uint8_t paramID, uint8_t *pData, uint8_t len)
{
    if(len > IAP_LEN)
    {
        PRINT("OTA write: data too long\n");
        return;
    }

    tmos_memcpy((uint8_t *)&s_ota_iap_data, pData, len);
    OTA_IAP_DataDeal();
}

/*********************************************************************
 * @fn      BTN_TOUCH_IRQHandler
 * @brief   GPIO interrupt - set flags for TMOS event loop to consume.
 *          MUST NOT call tmos_set_event() here (race with TMOS_SystemProcess).
 */
__INTERRUPT
__HIGH_CODE
void BTN_TOUCH_IRQHandler(void)
{
    if(TOUCH_ReadITFlag())
    {
        TOUCH_ClearITFlag();
        g_touch_irq_flag = 1;
    }
    if(BTN_ReadITFlag())
    {
        BTN_ClearITFlag();
        g_btn_irq_flag = 1;
    }
}


#if defined(HARDWARE_VER1) || defined(HARDWARE_VER2) || defined(HARDWARE_VER3) || defined(HARDWARE_VER5)
// VER1/VER2/VER3/VER5: BTN/TOUCH on GPIOB - stub GPIOA handler prevents
// stray GPIOA interrupts hitting default infinite-loop -> watchdog reset
__INTERRUPT
__HIGH_CODE
void GPIOA_IRQHandler(void)
{
    R16_PA_INT_IF = R16_PA_INT_IF;  // clear all flags
}
#endif
/*********************************************************************
*********************************************************************/
