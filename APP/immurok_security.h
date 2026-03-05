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
