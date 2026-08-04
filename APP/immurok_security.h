/*
 * immurok Security Module for CH592F
 * v3.0 - ECDH pairing, HMAC-signed notifications, no password on device
 */

#ifndef IMMUROK_SECURITY_H
#define IMMUROK_SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================================================
// Constants
// ============================================================================

// Auth states
typedef enum {
    AUTH_STATE_IDLE = 0,
    AUTH_STATE_WAIT_FINGERPRINT,
} immurok_auth_state_t;

// Error codes
typedef enum {
    SEC_OK = 0x00,
    SEC_ERR_TIMEOUT = 0x06,
    SEC_ERR_FP_NOT_MATCH = 0x07,
    SEC_ERR_WAIT_FP = 0x11,
    SEC_ERR_WAIT_BUTTON = 0xF0,    // PAIR_INIT 等待用户按设备按钮确认
    SEC_ERR_NEEDS_RESET = 0xF1,    // PAIR_INIT 但设备仍有指纹，需先 factory reset
    SEC_ERR_NOT_PAIRED  = 0xF2,    // 设备未配对，命令被拒（仅 GET_STATUS / PAIR_* 允许）
    SEC_ERR_NO_FP_ENROLLED = 0xF3, // 已配对但未录入指纹，所有 keystore/auth/OTA 命令被拒
    SEC_ERR_LOW_BATTERY = 0xF4,    // 电量过低，拒绝长写操作（KEY_WRITE/COMMIT/GENERATE/OTA），防止半截写损坏 keystore；KEY_SIGN/AUTH 不受限
    SEC_ERR_INVALID_STATE = 0xFD,
    SEC_ERR_INVALID_PARAM = 0xFE,
    SEC_ERR_INTERNAL = 0xFF,
} immurok_sec_err_t;

// ECDH pairing states
typedef enum {
    ECDH_STATE_IDLE = 0,
    ECDH_STATE_MAKE_KEY,       // uECC_make_key pending (TMOS event)
    ECDH_STATE_KEY_READY,      // Device pubkey ready, waiting for App pubkey
    ECDH_STATE_SHARED_SECRET,  // uECC_shared_secret pending (TMOS event)
} immurok_ecdh_state_t;

// ============================================================================
// Public API — Init / Pairing
// ============================================================================

int  immurok_security_init(void);

/* 任一槽已配对即为 true —— 设备全局的「被认领过没有」，用于 BLE bond
 * 模式和未配对命令白名单。回答「跟我说话的这台主机」请用下面那个。 */
bool immurok_security_is_paired(void);

/* 仅活动槽已配对时为 true —— 主机按槽的 BLE 地址连进来，活动槽就是对方
 * 的槽，所以这才是 GET_STATUS / PAIR_STATUS 该报给 app 的那一位。 */
bool immurok_security_active_slot_paired(void);

/* ---- 双主机槽位 ----
 * 对外 HMAC 接口签名不变；内部一律使用「活跃槽」的密钥。
 * 槽 1 的密钥仍在 storage_v3_t 原地（block 0 一字节不改，已出货设备
 * 零迁移），槽 2 在 DataFlash 0x6200。 */
uint8_t immurok_security_active_slot(void);
int     immurok_security_load_active_slot(void);   /* 开机调一次 */
bool    immurok_security_slot_occupied(uint8_t slot);
int     immurok_security_slot_clear(uint8_t slot);

// ECDH pairing state machine (called from GATT handler + TMOS event)
int  immurok_security_pair_init(void);           // Start key generation (returns 0, actual compute in TMOS)
int  immurok_security_pair_make_key(void);       // Called from TMOS event — blocks ~2s
int  immurok_security_pair_get_pubkey(uint8_t *compressed33);  // Get device compressed pubkey (BE)
int  immurok_security_pair_confirm(const uint8_t *app_compressed33); // Receive App pubkey, start shared_secret
int  immurok_security_pair_compute_secret(void); // Called from TMOS event — blocks ~2s

// EEPROM_READ called immediately after pair_compute_secret crashes the chip
// (drops to IAP bootloader). compute_secret now defers the save: caller
// checks immurok_security_pair_save_pending after calling it, sends the
// PAIR_CONFIRM response, then schedules a separate TMOS event later to
// call immurok_security_pair_save() once the call stack has unwound.
extern volatile uint8_t immurok_security_pair_save_pending;

/* 下一次 pair_save() 把密钥写进哪个槽。默认 IMMUROK_SLOT_1。
 * 槽 2 登记前由 hidkbd 设置；save 完自动复位为槽 1。
 * 必须在 PAIR_CONFIRM 之前设置 —— pair_compute_secret() 会把结果写进
 * s_data.shared_key（仅内存），pair_save() 再按目标槽决定落到哪里。 */
void immurok_security_pair_set_target_slot(uint8_t slot);

/* 槽 2 落盘：把内存里刚算出的 ECDH 密钥写进 0x6200，再从 flash 重载
 * 复原槽 1 的内存副本。由 pair_save() 在 target 为槽 2 时调用。
 * （曾是「两段式提交」的后半段，配合临时 PIN 的 proof；2026-08-03 登记
 * 改为指纹 + 按键后，授权在 PAIR_INIT 就完成，不再有扣住的中间态。） */
int  immurok_security_slot2_commit(void);
int  immurok_security_pair_save(void);

immurok_ecdh_state_t immurok_security_get_ecdh_state(void);

// ============================================================================
// Public API — Auth State
// ============================================================================

void immurok_security_set_auth_state(immurok_auth_state_t state);
immurok_auth_state_t immurok_security_get_auth_state(void);
bool immurok_security_has_pending_auth(void);
void immurok_security_auth_cancel(void);

// ============================================================================
// Public API — HMAC Signing (for 0x21 notification)
// ============================================================================

/**
 * Build signed 0x21 notification: [0x21][page_id:2B LE][hmac:8B]
 * @param page_id Fingerprint page ID
 * @param out_buf Output buffer (at least 11 bytes)
 * @return 11 on success, -1 if not paired
 */
int immurok_security_sign_fp_match(uint16_t page_id, uint8_t *out_buf);

/**
 * Compute challenge response: HMAC-SHA256(shared_key, nonce)[0:8]
 * @param nonce 8-byte challenge from App
 * @param out_hmac8 Output buffer (at least 8 bytes)
 * @return 0 on success, -1 if not paired
 */
int immurok_security_challenge_response(const uint8_t *nonce, uint8_t *out_hmac8);

// ============================================================================
// Public API — Reset
// ============================================================================

int immurok_security_factory_reset(void);

// ============================================================================
// Crypto Utility API (used by OTA security)
// ============================================================================

void immurok_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out);

#endif // IMMUROK_SECURITY_H
