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
bool immurok_security_is_paired(void);

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
