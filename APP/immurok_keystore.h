/*
 * immurok Keystore Module for CH592F
 * Manages SSH, OTP, and API key storage in DataFlash
 */

#ifndef IMMUROK_KEYSTORE_H
#define IMMUROK_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Constants
// ============================================================================

// Key categories
#define KEYSTORE_CAT_SSH    0
#define KEYSTORE_CAT_OTP    1
#define KEYSTORE_CAT_API    2
#define KEYSTORE_CAT_COUNT  3

// Max entries per category
#define KEYSTORE_SSH_MAX    32
#define KEYSTORE_OTP_MAX    128
#define KEYSTORE_API_MAX    50

// Entry sizes
#define KEYSTORE_SSH_ENTRY_SIZE  112  // 16B name + 64B pubkey_LE + 32B privkey
#define KEYSTORE_OTP_ENTRY_SIZE  92   // 30B name + 30B service + 32B secret
#define KEYSTORE_API_ENTRY_SIZE  160  // 32B name + 128B key

// Section magic numbers
#define KEYSTORE_MAGIC_SSH  0x4B535332  // "KSS2" (v2: includes pubkey fingerprint)
#define KEYSTORE_MAGIC_OTP  0x4B4F5450  // "KOTP"
#define KEYSTORE_MAGIC_API  0x4B415049  // "KAPI"

// ============================================================================
// Data Structures
// ============================================================================

// Section header (12B, at start of each section)
typedef struct __attribute__((aligned(4))) {
    uint32_t magic;       // Section magic number
    uint16_t count;       // Current entry count
    uint16_t reserved;
    uint32_t checksum;    // Checksum over all entries
} keystore_header_t;

// SSH entry (112B)
typedef struct __attribute__((aligned(4))) {
    uint8_t name[16];     // Name (UTF-8, zero-padded)
    uint8_t pubkey[64];   // P-256 public key (x||y, little-endian)
    uint8_t key[32];      // P-256 private key
} ssh_entry_t;

// OTP entry (92B)
typedef struct __attribute__((aligned(4))) {
    uint8_t name[30];     // Account name (UTF-8, zero-padded)
    uint8_t service[30];  // Issuer / service name
    uint8_t secret[32];   // TOTP secret key (raw bytes)
} otp_entry_t;

// API entry (160B)
typedef struct __attribute__((aligned(4))) {
    uint8_t name[32];     // Name (UTF-8, zero-padded)
    uint8_t key[128];     // API key
} api_entry_t;

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize keystore module (read headers from DataFlash)
 */
void immurok_keystore_init(void);

/**
 * Get entry count for a category
 * @param cat Category (KEYSTORE_CAT_SSH/OTP/API)
 * @return Entry count, or -1 on error
 */
int immurok_keystore_count(uint8_t cat);

/**
 * Read an entry
 * @param cat Category
 * @param idx Entry index (0-based)
 * @param offset Byte offset within entry
 * @param buf Output buffer
 * @param len Bytes to read
 * @return 0 on success, -1 on error
 */
int immurok_keystore_read(uint8_t cat, uint8_t idx, uint8_t offset,
                          uint8_t *buf, uint8_t len);

/**
 * Write data to the staging buffer for a pending add/update
 * @param cat Category
 * @param idx Entry index (0xFF = append new)
 * @param offset Byte offset within entry
 * @param data Data to write
 * @param len Data length
 * @return 0 on success, -1 on error
 */
int immurok_keystore_stage(uint8_t cat, uint8_t idx, uint8_t offset,
                           const uint8_t *data, uint8_t len);

/**
 * Commit staged data to DataFlash
 * Call after all KEY_WRITE fragments are received
 * @param cat Category
 * @param idx Entry index (0xFF = append new)
 * @return 0 on success, -1 on error
 */
int immurok_keystore_commit(uint8_t cat, uint8_t idx);

/**
 * Delete an entry (swap-delete: move last entry to deleted position)
 * @param cat Category
 * @param idx Entry index
 * @return 0 on success, -1 on error
 */
int immurok_keystore_delete(uint8_t cat, uint8_t idx);

/**
 * Reset all keystore data (erase blocks 0-5)
 */
void immurok_keystore_reset(void);

/**
 * ECDSA P-256 sign a 32-byte hash using SSH key at idx
 * @param idx SSH key index
 * @param hash32 32-byte SHA-256 hash (little-endian)
 * @param sig64 Output: 64-byte signature r||s (little-endian)
 * @return 0 on success, -1 on error
 */
int immurok_keystore_sign(uint8_t idx, const uint8_t *hash32, uint8_t *sig64);

/**
 * Compute P-256 public key from SSH private key at idx
 * @param idx SSH key index
 * @param pub64 Output: 64-byte public key x||y (little-endian)
 * @return 0 on success, -1 on error
 */
int immurok_keystore_getpub(uint8_t idx, uint8_t *pub64);

/**
 * Generate a new P-256 keypair and store in SSH keystore
 * @param name16 16-byte name (zero-padded)
 * @param pub64 Output: 64-byte public key x||y (little-endian)
 * @return New entry index on success, -1 on error
 */
int immurok_keystore_generate(const uint8_t *name16, uint8_t *pub64);

/**
 * Compute TOTP (RFC 6238) for an OTP entry on-device
 * @param idx OTP entry index
 * @param unix_time Current Unix timestamp
 * @param out6 Output: 6 ASCII digit characters (NOT null-terminated)
 * @return 0 on success, -1 on error
 */
int immurok_keystore_totp(uint8_t idx, uint32_t unix_time, uint8_t *out6);

/**
 * Get pointer to result buffer (for reading crypto results)
 */
uint8_t *immurok_keystore_result_buf(void);

/**
 * Get length of data in result buffer
 */
uint8_t immurok_keystore_result_len(void);

/**
 * Store data in result buffer
 */
void immurok_keystore_set_result(const uint8_t *data, uint8_t len);

#endif // IMMUROK_KEYSTORE_H
