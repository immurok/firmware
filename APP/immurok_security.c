/*
 * immurok Security Module Implementation for CH592F
 * v3.0 - ECDH pairing, HMAC-signed notifications, no password on device
 */

#include "immurok_security.h"
#include "immurok_keystore.h"
#include "CH59x_common.h"
#include "CONFIG.h"
#include "../LIB/sha256.h"
#include "../LIB/uECC.h"
#include <string.h>

// ============================================================================
// HMAC-SHA256 Implementation
// ============================================================================

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out)
{
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_SIZE];
    sha256_ctx_t ctx;

    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }

    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, tk);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, tk, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}

// ============================================================================
// HKDF-SHA256 (Extract + Expand, single output block = 32 bytes)
// ============================================================================

static void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm)
{
    // Extract: PRK = HMAC(salt, IKM)
    uint8_t prk[SHA256_DIGEST_SIZE];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    // Expand: OKM = HMAC(PRK, info || 0x01) — single block (32B)
    uint8_t t_input[64 + 1];  // info max ~20 bytes + 1
    memcpy(t_input, info, info_len);
    t_input[info_len] = 0x01;
    hmac_sha256(prk, SHA256_DIGEST_SIZE, t_input, info_len + 1, okm);
}

// ============================================================================
// Byte-order helpers (uECC LE <-> CryptoKit BE)
// ============================================================================

static void reverse_32(uint8_t *buf)
{
    for (int i = 0; i < 16; i++) {
        uint8_t t = buf[i];
        buf[i] = buf[31 - i];
        buf[31 - i] = t;
    }
}

// ============================================================================
// Configuration
// ============================================================================

#define SECURITY_DATA_ADDR  0
#define STORAGE_MAGIC_V3    0x494D5233  // "IMR3" (little-endian: 0x33 0x52 0x4D 0x49)

// v3.0 storage (112B, 8-byte aligned)
typedef struct __attribute__((aligned(4))) {
    uint32_t magic;           // 4B  "IMR3"
    uint8_t  paired;          // 1B  0x00=unpaired, 0x01=paired
    uint8_t  reserved[3];     // 3B
    uint8_t  shared_key[32];  // 32B HKDF-derived key
    uint8_t  padding[68];     // 68B fill to 108B
    uint32_t checksum;        // 4B
} storage_v3_t;               // 112B total

// ============================================================================
// Static State
// ============================================================================

static storage_v3_t s_data __attribute__((aligned(4))) = {0};
static immurok_auth_state_t s_auth_state = AUTH_STATE_IDLE;
static bool s_initialized = false;

// ECDH state machine
static immurok_ecdh_state_t s_ecdh_state = ECDH_STATE_IDLE;
static uint8_t s_ecdh_priv[32] __attribute__((aligned(4)));
static uint8_t s_ecdh_pub[64] __attribute__((aligned(4)));   // Device public key (LE, uncompressed)
static uint8_t s_ecdh_app_compressed[33];                     // App compressed pubkey (BE from App)

// ============================================================================
// Forward Declarations
// ============================================================================

static int  load_security_data(void);
static int  save_security_data(void);
static uint32_t calc_checksum(const uint8_t *data, uint16_t len);

// ============================================================================
// Initialization
// ============================================================================

int immurok_security_init(void)
{
    if (s_initialized) {
        return 0;
    }

    PRINT("Security module init (v3.0 ECDH)...\n");

    if (load_security_data() != 0) {
        PRINT("No stored data found\n");
        memset(&s_data, 0, sizeof(s_data));
    }

    s_auth_state = AUTH_STATE_IDLE;
    s_ecdh_state = ECDH_STATE_IDLE;
    s_initialized = true;

    PRINT("Security: paired=%d\n", s_data.paired);
    return 0;
}

// ============================================================================
// Pairing Status
// ============================================================================

bool immurok_security_is_paired(void)
{
    return s_data.paired == 0x01;
}

// ============================================================================
// ECDH Pairing State Machine
// ============================================================================

immurok_ecdh_state_t immurok_security_get_ecdh_state(void)
{
    return s_ecdh_state;
}

// Step 1: App sends PAIR_INIT → set state, actual compute in TMOS event
int immurok_security_pair_init(void)
{
    PRINT("ECDH pair_init\n");
    s_ecdh_state = ECDH_STATE_MAKE_KEY;
    memset(s_ecdh_priv, 0, 32);
    memset(s_ecdh_pub, 0, 64);
    return 0;
}

// Step 2: Called from TMOS event — heavy computation (~2s)
int immurok_security_pair_make_key(void)
{
    PRINT("ECDH make_key start...\n");
    uECC_Curve curve = uECC_secp256r1();

    WWDG_SetCounter(0);
    int ret = uECC_make_key(s_ecdh_pub, s_ecdh_priv, curve);
    WWDG_SetCounter(0);

    if (!ret) {
        PRINT("ECDH make_key FAILED\n");
        s_ecdh_state = ECDH_STATE_IDLE;
        return -1;
    }

    PRINT("ECDH make_key done\n");
    s_ecdh_state = ECDH_STATE_KEY_READY;
    return 0;
}

// Step 3: Get device compressed pubkey in BE (for sending to App)
int immurok_security_pair_get_pubkey(uint8_t *compressed33)
{
    if (s_ecdh_state != ECDH_STATE_KEY_READY) {
        return -1;
    }

    uECC_Curve curve = uECC_secp256r1();

    // uECC_compress: input LE pubkey → output [02/03][x_LE:32B]
    uECC_compress(s_ecdh_pub, compressed33, curve);

    // Convert x from LE to BE for CryptoKit compatibility
    reverse_32(&compressed33[1]);

    return 0;
}

// Step 4: Receive App compressed pubkey (BE), prepare for shared_secret
int immurok_security_pair_confirm(const uint8_t *app_compressed33)
{
    if (s_ecdh_state != ECDH_STATE_KEY_READY) {
        PRINT("ECDH pair_confirm: wrong state %d\n", s_ecdh_state);
        return -1;
    }

    memcpy(s_ecdh_app_compressed, app_compressed33, 33);
    s_ecdh_state = ECDH_STATE_SHARED_SECRET;
    PRINT("ECDH pair_confirm: App pubkey received (prefix=0x%02X)\n", app_compressed33[0]);
    return 0;
}

// Step 5: Called from TMOS event — heavy computation (~2s)
int immurok_security_pair_compute_secret(void)
{
    PRINT("ECDH shared_secret start...\n");
    uECC_Curve curve = uECC_secp256r1();

    // Convert App compressed pubkey from BE to LE
    uint8_t compressed_le[33];
    compressed_le[0] = s_ecdh_app_compressed[0];  // prefix byte
    memcpy(&compressed_le[1], &s_ecdh_app_compressed[1], 32);
    reverse_32(&compressed_le[1]);  // x: BE → LE

    // Decompress to full public key (LE)
    uint8_t app_pub[64] __attribute__((aligned(4)));
    uECC_decompress(compressed_le, app_pub, curve);

    // Compute shared secret (LE)
    uint8_t secret[32] __attribute__((aligned(4)));
    WWDG_SetCounter(0);
    int ret = uECC_shared_secret(app_pub, s_ecdh_priv, secret, curve);
    WWDG_SetCounter(0);

    // Clear private key immediately
    memset(s_ecdh_priv, 0, 32);

    if (!ret) {
        PRINT("ECDH shared_secret FAILED\n");
        s_ecdh_state = ECDH_STATE_IDLE;
        return -1;
    }

    // Convert shared secret from LE to BE (match CryptoKit)
    reverse_32(secret);

    // HKDF-SHA256: derive shared_key
    static const uint8_t salt[] = "immurok-pairing-salt";
    static const uint8_t info[] = "immurok-shared-key";
    hkdf_sha256(salt, sizeof(salt) - 1, secret, 32, info, sizeof(info) - 1, s_data.shared_key);
    memset(secret, 0, 32);

    // Mark as paired
    s_data.paired = 0x01;

    // Save to EEPROM
    int save_ret = save_security_data();
    PRINT("ECDH pairing complete, save=%d\n", save_ret);

    s_ecdh_state = ECDH_STATE_IDLE;
    return save_ret;
}

// ============================================================================
// Auth State
// ============================================================================

void immurok_security_set_auth_state(immurok_auth_state_t state)
{
    s_auth_state = state;
}

immurok_auth_state_t immurok_security_get_auth_state(void)
{
    return s_auth_state;
}

bool immurok_security_has_pending_auth(void)
{
    return s_auth_state == AUTH_STATE_WAIT_FINGERPRINT;
}

void immurok_security_auth_cancel(void)
{
    PRINT("Auth cancelled\n");
    s_auth_state = AUTH_STATE_IDLE;
}

// ============================================================================
// HMAC Signed Notification
// ============================================================================

int immurok_security_sign_fp_match(uint16_t page_id, uint8_t *out_buf)
{
    if (!s_data.paired) {
        return -1;
    }

    // Build: [0x21][page_id:2B LE]
    out_buf[0] = 0x21;
    out_buf[1] = page_id & 0xFF;
    out_buf[2] = (page_id >> 8) & 0xFF;

    // HMAC-SHA256(shared_key, 0x21 || page_id), truncate to 8 bytes
    uint8_t hmac_full[32];
    hmac_sha256(s_data.shared_key, 32, out_buf, 3, hmac_full);
    memcpy(&out_buf[3], hmac_full, 8);

    return 11;  // Total notification size
}

// ============================================================================
// Factory Reset
// ============================================================================

int immurok_security_factory_reset(void)
{
    PRINT("Factory reset\n");

    memset(&s_data, 0, sizeof(s_data));
    s_auth_state = AUTH_STATE_IDLE;
    s_ecdh_state = ECDH_STATE_IDLE;

    uint8_t ret = EEPROM_ERASE(SECURITY_DATA_ADDR, EEPROM_BLOCK_SIZE);
    PRINT("Factory reset: EEPROM_ERASE ret=%d\n", ret);

    immurok_keystore_reset();

    return 0;
}

// ============================================================================
// Internal Functions
// ============================================================================

static int load_security_data(void)
{
    uint8_t ret;

    ret = EEPROM_READ(SECURITY_DATA_ADDR, &s_data, sizeof(s_data));
    PRINT("load_security_data: EEPROM_READ ret=%d, size=%d\n", ret, sizeof(s_data));

    if (ret != 0) {
        PRINT("load_security_data: EEPROM_READ failed\n");
        return -1;
    }

    PRINT("load_security_data: magic=0x%08lX (expected 0x%08lX)\n",
          s_data.magic, STORAGE_MAGIC_V3);

    if (s_data.magic != STORAGE_MAGIC_V3) {
        PRINT("load_security_data: magic mismatch (old data auto-invalidated)\n");
        return -1;
    }

    uint32_t expected_cs = calc_checksum((uint8_t *)&s_data,
                                          sizeof(s_data) - sizeof(uint32_t));

    if (s_data.checksum != expected_cs) {
        PRINT("load_security_data: checksum mismatch\n");
        return -1;
    }

    PRINT("load_security_data: paired=%d\n", s_data.paired);
    return 0;
}

// Borrow keystore work buffer for read-modify-write
extern uint8_t immurok_keystore_work_buf[4096];

static int save_security_data(void)
{
    uint8_t ret;

    s_data.magic = STORAGE_MAGIC_V3;
    s_data.checksum = calc_checksum((uint8_t *)&s_data,
                                     sizeof(s_data) - sizeof(uint32_t));

    PRINT("save_security_data: magic=0x%08lX, paired=%d\n",
          s_data.magic, s_data.paired);

    // Read-modify-write: preserve SSH data that shares Block 0
    EEPROM_READ(SECURITY_DATA_ADDR, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
    memcpy(immurok_keystore_work_buf, &s_data, sizeof(s_data));

    WWDG_SetCounter(0);
    ret = EEPROM_ERASE(SECURITY_DATA_ADDR, EEPROM_BLOCK_SIZE);
    if (ret != 0) {
        PRINT("save_security_data: EEPROM_ERASE failed\n");
        return -1;
    }

    WWDG_SetCounter(0);
    ret = EEPROM_WRITE(SECURITY_DATA_ADDR, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
    if (ret != 0) {
        PRINT("save_security_data: EEPROM_WRITE failed\n");
        return -1;
    }

    // Verify
    storage_v3_t verify __attribute__((aligned(4)));
    ret = EEPROM_READ(SECURITY_DATA_ADDR, &verify, sizeof(verify));

    if (verify.magic != s_data.magic || verify.checksum != s_data.checksum) {
        PRINT("save_security_data: VERIFY FAILED!\n");
        return -1;
    }

    PRINT("Security data saved and verified\n");
    return 0;
}

static uint32_t calc_checksum(const uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];
        sum = (sum << 1) | (sum >> 31);
    }
    return sum;
}

// ============================================================================
// Public Crypto Utility
// ============================================================================

void immurok_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out)
{
    hmac_sha256(key, key_len, data, data_len, out);
}
