/*
 * immurok Keystore Module Implementation for CH592F
 * SSH, OTP, and API key storage in DataFlash
 *
 * DataFlash layout (24KB usable: 0x0000-0x5FFF):
 *   Block 0 (0x0000-0x0FFF): Security data (112B) + SSH section
 *   Block 1-3 (0x1000-0x3FFF): OTP section (133 entries)
 *   Block 4-5 (0x4000-0x5FFF): API section (51 entries)
 *   0x6000: OTA ImageFlag (page 0 of block 6, OTA_DATAFLASH_ADD)
 *   0x6F00: tamper case_opened flag (last page of block 6, see tamper.c)
 *   0x7000: BLE SNV (reserved)
 */

#include "immurok_keystore.h"
#include "CH59x_common.h"
#include "CONFIG.h"
#include "../LIB/uECC.h"
extern void uECC_set_watchdog_cb(void (*cb)(void));
#include "../LIB/sha1.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// DataFlash Address Layout
// ============================================================================

// Security data occupies 0x0000-0x006F (112 bytes, storage_v3_t)
#define SSH_HEADER_ADDR     0x0070
#define SSH_ENTRIES_ADDR    0x007C  // SSH_HEADER_ADDR + sizeof(keystore_header_t)

#define OTP_HEADER_ADDR     0x1000
#define OTP_ENTRIES_ADDR    0x100C  // OTP_HEADER_ADDR + sizeof(keystore_header_t)

#define API_HEADER_ADDR     0x4000
#define API_ENTRIES_ADDR    0x400C  // API_HEADER_ADDR + sizeof(keystore_header_t)

// Block boundaries for erase operations
#define SSH_BLOCK_START     0x0000  // Block 0 (shared with security data)
#define OTP_BLOCK_START     0x1000  // Blocks 1-3
#define API_BLOCK_START     0x4000  // Blocks 4-5

// ============================================================================
// Static State
// ============================================================================

// 4KB work buffer for read-modify-write operations (also used by immurok_security.c)
uint8_t immurok_keystore_work_buf[4096] __attribute__((section(".stack_guard"), aligned(4)));

// Staging buffer for incoming entry data (largest entry = 160B for API)
static uint8_t s_stage_buf[160] __attribute__((aligned(4)));
static uint8_t s_stage_cat = 0xFF;   // Category being staged
static uint8_t s_stage_idx = 0xFF;   // Index being staged

// Cached headers (avoid repeated reads)
static keystore_header_t s_headers[KEYSTORE_CAT_COUNT] __attribute__((aligned(4)));
static uint8_t s_initialized = 0;

// Result buffer for SSH crypto operations (signature/public key)
static uint8_t s_result_buf[64];
static uint8_t s_result_len = 0;

// Static buffers for ECC operations (avoid stack overflow in TMOS task)
static uint8_t s_ecc_privkey[32] __attribute__((aligned(4)));
static uint8_t s_ecc_entry[112] __attribute__((aligned(4)));  // 16B name + 64B pubkey + 32B privkey

// Watchdog + TMOS kick during uECC long computations (~2s).
// TMOS_SystemProcess() is required to keep BLE LL alive during blocking ECC.
// Stack guard: immurok_keystore_work_buf[4096] sits between .bss and .stack,
// so any overflow during TMOS processing goes into unused buffer, not BLE state.
static volatile uint8_t s_in_tmos_kick = 0;
static void keystore_watchdog_kick(void)
{
    WWDG_SetCounter(0);
    if(!s_in_tmos_kick)
    {
        s_in_tmos_kick = 1;
        TMOS_SystemProcess();
        s_in_tmos_kick = 0;
    }
}

// RNG function for uECC
static int keystore_rng(uint8_t *dest, unsigned size)
{
    for (unsigned i = 0; i < size; i += 4) {
        uint32_t r = tmos_rand();
        unsigned copy = (size - i) < 4 ? (size - i) : 4;
        tmos_memcpy(dest + i, &r, copy);
    }
    return 1;
}

// ============================================================================
// Internal Helpers
// ============================================================================

static uint32_t calc_checksum(const uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];
        sum = (sum << 1) | (sum >> 31);
    }
    return sum;
}

// Get section parameters by category
static int get_section_params(uint8_t cat,
                              uint32_t *header_addr, uint32_t *entries_addr,
                              uint16_t *entry_size, uint16_t *max_entries,
                              uint32_t *magic)
{
    switch (cat) {
    case KEYSTORE_CAT_SSH:
        *header_addr = SSH_HEADER_ADDR;
        *entries_addr = SSH_ENTRIES_ADDR;
        *entry_size = KEYSTORE_SSH_ENTRY_SIZE;
        *max_entries = KEYSTORE_SSH_MAX;
        *magic = KEYSTORE_MAGIC_SSH;
        return 0;
    case KEYSTORE_CAT_OTP:
        *header_addr = OTP_HEADER_ADDR;
        *entries_addr = OTP_ENTRIES_ADDR;
        *entry_size = KEYSTORE_OTP_ENTRY_SIZE;
        *max_entries = KEYSTORE_OTP_MAX;
        *magic = KEYSTORE_MAGIC_OTP;
        return 0;
    case KEYSTORE_CAT_API:
        *header_addr = API_HEADER_ADDR;
        *entries_addr = API_ENTRIES_ADDR;
        *entry_size = KEYSTORE_API_ENTRY_SIZE;
        *max_entries = KEYSTORE_API_MAX;
        *magic = KEYSTORE_MAGIC_API;
        return 0;
    default:
        return -1;
    }
}

// Compute checksum over all entries in a section
static uint32_t compute_entries_checksum(uint32_t entries_addr, uint16_t count,
                                         uint16_t entry_size)
{
    uint32_t sum = 0;
    uint32_t total_bytes = (uint32_t)count * entry_size;
    uint32_t offset = 0;

    while (offset < total_bytes) {
        uint16_t chunk = (total_bytes - offset > sizeof(immurok_keystore_work_buf))
                         ? sizeof(immurok_keystore_work_buf) : (uint16_t)(total_bytes - offset);
        // IRQ-disable around EEPROM_READ — same defense-in-depth as
        // save_security_data. Inline reads under the wrong execution context
        // can fault into the IAP bootloader on this chip.
        {
            uint32_t saved = __risc_v_disable_irq();
            EEPROM_READ(entries_addr + offset, immurok_keystore_work_buf, chunk);
            __risc_v_enable_irq(saved);
        }
        for (uint16_t i = 0; i < chunk; i++) {
            sum += immurok_keystore_work_buf[i];
            sum = (sum << 1) | (sum >> 31);
        }
        offset += chunk;
    }
    return sum;
}

// Read a header from DataFlash and validate
static int load_header(uint8_t cat)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    keystore_header_t hdr __attribute__((aligned(4)));
    EEPROM_READ(h_addr, &hdr, sizeof(hdr));

    if (hdr.magic != magic || hdr.count > max_e) {
        // Uninitialized or corrupt - treat as empty
        s_headers[cat].magic = magic;
        s_headers[cat].count = 0;
        s_headers[cat].reserved = 0;
        s_headers[cat].checksum = 0;
        return 0;
    }

    // Verify checksum if entries exist
    if (hdr.count > 0) {
        uint32_t cs = compute_entries_checksum(e_addr, hdr.count, e_size);
        if (cs != hdr.checksum) {
            PRINT("Keystore[%d]: checksum mismatch\n", cat);
            s_headers[cat].magic = magic;
            s_headers[cat].count = 0;
            s_headers[cat].reserved = 0;
            s_headers[cat].checksum = 0;
            return 0;
        }
    }

    s_headers[cat] = hdr;
    return 0;
}

// Write header to DataFlash using read-modify-write on its block
static int save_header(uint8_t cat)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    // Determine which block the header lives in
    uint32_t block_base = h_addr & ~0xFFF;

    // Read entire block
    {
        uint32_t saved = __risc_v_disable_irq();
        EEPROM_READ(block_base, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
        __risc_v_enable_irq(saved);
    }

    // Patch header in buffer
    uint16_t offset_in_block = h_addr - block_base;
    memcpy(&immurok_keystore_work_buf[offset_in_block], &s_headers[cat], sizeof(keystore_header_t));

    // Erase and rewrite block
    WWDG_SetCounter(0);
    EEPROM_ERASE(block_base, EEPROM_BLOCK_SIZE);
    WWDG_SetCounter(0);
    EEPROM_WRITE(block_base, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);

    return 0;
}

// Write an entry to DataFlash using read-modify-write on its block(s).
// Handles entries that span a 4KB block boundary (e.g. OTP idx>=44, API idx>=25).
// Also updates header count and checksum if needed.
static int write_entry(uint8_t cat, uint16_t idx, const uint8_t *entry_data)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    uint32_t entry_addr = e_addr + (uint32_t)idx * e_size;
    uint32_t entry_block = entry_addr & ~0xFFF;
    uint32_t header_block = h_addr & ~0xFFF;
    uint16_t off_in_block = entry_addr - entry_block;
    uint16_t first_chunk = EEPROM_BLOCK_SIZE - off_in_block;  // bytes until block end
    uint8_t  crosses_block = (first_chunk < e_size) ? 1 : 0;

    // --- First block (always needed) ---
    {
        uint32_t saved = __risc_v_disable_irq();
        EEPROM_READ(entry_block, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
        __risc_v_enable_irq(saved);
    }
    uint16_t copy1 = crosses_block ? first_chunk : e_size;
    memcpy(&immurok_keystore_work_buf[off_in_block], entry_data, copy1);

    // If header is in the same block, patch it too
    if (entry_block == header_block) {
        uint16_t h_off = h_addr - header_block;
        memcpy(&immurok_keystore_work_buf[h_off], &s_headers[cat], sizeof(keystore_header_t));
    }

    WWDG_SetCounter(0);
    EEPROM_ERASE(entry_block, EEPROM_BLOCK_SIZE);
    WWDG_SetCounter(0);
    EEPROM_WRITE(entry_block, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);

    // --- Second block (only if entry crosses boundary) ---
    if (crosses_block) {
        uint32_t next_block = entry_block + EEPROM_BLOCK_SIZE;
        uint16_t copy2 = e_size - first_chunk;
        {
            uint32_t saved = __risc_v_disable_irq();
            EEPROM_READ(next_block, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
            __risc_v_enable_irq(saved);
        }
        memcpy(&immurok_keystore_work_buf[0], entry_data + first_chunk, copy2);
        WWDG_SetCounter(0);
        EEPROM_ERASE(next_block, EEPROM_BLOCK_SIZE);
        WWDG_SetCounter(0);
        EEPROM_WRITE(next_block, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
    }

    // If header is in a different block, save it separately
    if (entry_block != header_block) {
        save_header(cat);
    }

    return 0;
}

// ============================================================================
// Public API
// ============================================================================

void immurok_keystore_init(void)
{
    if (s_initialized)
        return;

    PRINT("Keystore init...\n");

    uECC_set_rng(keystore_rng);
    uECC_set_watchdog_cb(keystore_watchdog_kick);

    for (uint8_t i = 0; i < KEYSTORE_CAT_COUNT; i++) {
        load_header(i);
        PRINT("  [%d] count=%d\n", i, s_headers[i].count);
    }

    s_stage_cat = 0xFF;
    s_stage_idx = 0xFF;
    s_result_len = 0;
    s_initialized = 1;
}

int immurok_keystore_count(uint8_t cat)
{
    if (cat >= KEYSTORE_CAT_COUNT)
        return -1;
    return s_headers[cat].count;
}

uint32_t immurok_keystore_checksum(uint8_t cat)
{
    if (cat >= KEYSTORE_CAT_COUNT)
        return 0;
    return s_headers[cat].checksum;
}

int immurok_keystore_read(uint8_t cat, uint8_t idx, uint8_t offset,
                          uint8_t *buf, uint8_t len)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    if (idx >= s_headers[cat].count)
        return -1;

    if ((uint16_t)offset + len > e_size)
        return -1;

    uint32_t addr = e_addr + (uint32_t)idx * e_size + offset;
    EEPROM_READ(addr, buf, len);
    return 0;
}

int immurok_keystore_stage(uint8_t cat, uint8_t idx, uint8_t offset,
                           const uint8_t *data, uint8_t len)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    if ((uint16_t)offset + len > e_size)
        return -1;

    // Start new staging if category/index changed.
    // For updates to an existing entry (idx != 0xFF and idx < count): preload
    // current entry from flash so partial writes preserve fields the App
    // can't see (OTP secret[32], SSH privkey[32]). Otherwise the buffer is
    // zeroed and a partial KEY_WRITE chain (e.g. App rewrites only name +
    // service for OTP rename) silently nukes the hidden secret on commit.
    if (s_stage_cat != cat || s_stage_idx != idx) {
        if (idx != 0xFF && idx < s_headers[cat].count) {
            // IRQ-disable around EEPROM_READ — same defense-in-depth as
            // save_security_data / write_entry / save_header / etc. Without
            // it this read can fault into the IAP bootloader on certain
            // execution contexts → silent reboot → FP module left in unknown
            // power state → user sees "FP stuck during enroll/identify".
            // (1.2.8 introduced this read for partial-write rename safety
            // but didn't add the wrapper. 1.2.10 closes the loop.)
            uint32_t saved = __risc_v_disable_irq();
            EEPROM_READ(e_addr + (uint32_t)idx * e_size, s_stage_buf, e_size);
            __risc_v_enable_irq(saved);
            // Zero any tail beyond e_size (s_stage_buf is sized for max entry)
            if (e_size < sizeof(s_stage_buf)) {
                memset(&s_stage_buf[e_size], 0, sizeof(s_stage_buf) - e_size);
            }
        } else {
            memset(s_stage_buf, 0, sizeof(s_stage_buf));
        }
        s_stage_cat = cat;
        s_stage_idx = idx;
    }

    memcpy(&s_stage_buf[offset], data, len);
    return 0;
}

int immurok_keystore_commit(uint8_t cat, uint8_t idx)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    // Verify staging matches
    if (s_stage_cat != cat || s_stage_idx != idx) {
        PRINT("Keystore commit: stage mismatch cat=%d/%d idx=%d/%d\n",
              cat, s_stage_cat, idx, s_stage_idx);
        return -1;
    }

    uint16_t target_idx;

    if (idx == 0xFF) {
        // Append new entry
        if (s_headers[cat].count >= max_e) {
            PRINT("Keystore[%d]: full (%d/%d)\n", cat, s_headers[cat].count, max_e);
            return -1;
        }
        target_idx = s_headers[cat].count;
        s_headers[cat].count++;
    } else {
        // Update existing entry
        if (idx >= s_headers[cat].count) {
            PRINT("Keystore[%d]: idx %d out of range (count=%d)\n",
                  cat, idx, s_headers[cat].count);
            return -1;
        }
        target_idx = idx;
    }

    // Recompute checksum: we need to account for the new/updated entry
    // Write entry first, then recompute full checksum
    int ret = write_entry(cat, target_idx, s_stage_buf);
    if (ret != 0) {
        PRINT("Keystore[%d]: write_entry failed\n", cat);
        return -1;
    }

    // Recompute checksum over all entries
    s_headers[cat].checksum = compute_entries_checksum(
        e_addr, s_headers[cat].count, e_size);

    // Save updated header
    save_header(cat);

    PRINT("Keystore[%d]: committed idx=%d, count=%d\n",
          cat, target_idx, s_headers[cat].count);

    // Clear staging
    s_stage_cat = 0xFF;
    s_stage_idx = 0xFF;

    return 0;
}

int immurok_keystore_delete(uint8_t cat, uint8_t idx)
{
    uint32_t h_addr, e_addr;
    uint16_t e_size, max_e;
    uint32_t magic;

    if (get_section_params(cat, &h_addr, &e_addr, &e_size, &max_e, &magic) != 0)
        return -1;

    if (idx >= s_headers[cat].count)
        return -1;

    uint16_t last_idx = s_headers[cat].count - 1;

    if (idx != last_idx) {
        // Swap-delete: read last entry, write it to deleted position.
        //
        // NOTE: do NOT use a local `uint8_t tmp[160]` here. CH592F has only
        // 512B of CPU stack; this function runs from inside the BLE FP-match
        // priority chain with a deep call stack already. A 160B local plus
        // the rest of the frame can overflow into the .stack_guard region
        // (where immurok_keystore_work_buf lives), and the next EEPROM_READ
        // populating work_buf then writes through stack/return addresses
        // → wild jump → IAP fault → BLE disconnect → user sees red LED then
        // a reset boot. Borrow s_stage_buf (160B, .bss) instead.
        uint32_t last_addr = e_addr + (uint32_t)last_idx * e_size;
        {
            uint32_t saved = __risc_v_disable_irq();
            EEPROM_READ(last_addr, s_stage_buf, e_size);
            __risc_v_enable_irq(saved);
        }

        // Write last entry to deleted position
        s_headers[cat].count--;
        s_headers[cat].checksum = 0;  // Will recompute
        write_entry(cat, idx, s_stage_buf);
        // Trampling s_stage_buf invalidates any in-flight KEY_WRITE staging.
        s_stage_cat = 0xFF;
        s_stage_idx = 0xFF;
    } else {
        // Deleting last entry - just decrement count
        s_headers[cat].count--;
    }

    // Recompute checksum
    if (s_headers[cat].count > 0) {
        s_headers[cat].checksum = compute_entries_checksum(
            e_addr, s_headers[cat].count, e_size);
    } else {
        s_headers[cat].checksum = 0;
    }

    save_header(cat);

    PRINT("Keystore[%d]: deleted idx=%d, count=%d\n",
          cat, idx, s_headers[cat].count);

    return 0;
}

int immurok_keystore_sign(uint8_t idx, const uint8_t *hash32, uint8_t *sig64)
{
    if (idx >= s_headers[KEYSTORE_CAT_SSH].count)
        return -1;

    // Read private key from offset 80 (v2 entry: 16B name + 64B pubkey + 32B key)
    if (immurok_keystore_read(KEYSTORE_CAT_SSH, idx, 80, s_ecc_privkey, 32) != 0)
        return -1;

    // uECC with NATIVE_LITTLE_ENDIAN=1 expects hash in LE byte order,
    // but App sends standard BE SHA-256 hash — reverse it
    static uint8_t hash_le[32];
    for (int i = 0; i < 32; i++)
        hash_le[i] = hash32[31 - i];

    uECC_Curve curve = uECC_secp256r1();
    PRINT("ECDSA sign...\n");
    WWDG_SetCounter(0);
    int ret = uECC_sign(s_ecc_privkey, hash_le, 32, sig64, curve);
    WWDG_SetCounter(0);
    PRINT("ECDSA sign done: %d\n", ret);

    memset(s_ecc_privkey, 0, 32);
    return ret ? 0 : -1;
}

int immurok_keystore_getpub(uint8_t idx, uint8_t *pub64)
{
    if (idx >= s_headers[KEYSTORE_CAT_SSH].count)
        return -1;

    // Public key stored at offset 16 in v2 entry (16B name + 64B pubkey + 32B key)
    // Direct flash read — no ECC computation needed
    return immurok_keystore_read(KEYSTORE_CAT_SSH, idx, 16, pub64, 64);
}

int immurok_keystore_generate_stage(const uint8_t *name16, uint8_t *pub64)
{
    if (s_headers[KEYSTORE_CAT_SSH].count >= KEYSTORE_SSH_MAX)
        return -1;

    uECC_Curve curve = uECC_secp256r1();

    // Entry layout: name[16] + pubkey[64] + privkey[32] = 112B
    memset(s_ecc_entry, 0, 112);
    memcpy(s_ecc_entry, name16, 16);
    PRINT("uECC_make_key...\n");
    WWDG_SetCounter(0);
    // pub64 gets public key (also copied to entry), privkey goes to entry+80
    if (!uECC_make_key(pub64, &s_ecc_entry[80], curve)) {
        PRINT("uECC_make_key failed\n");
        memset(s_ecc_entry, 0, 112);
        return -1;
    }
    WWDG_SetCounter(0);
    PRINT("uECC_make_key done\n");

    // Store public key in entry at offset 16
    memcpy(&s_ecc_entry[16], pub64, 64);

    // Stage but do NOT commit — caller commits in a fresh TMOS context
    // (same hazard as save_security_data: inline EEPROM_ERASE/WRITE right
    // after ECC compute can fault into the IAP bootloader → silent reboot
    // and BLE supervision timeout).
    uint8_t new_idx = s_headers[KEYSTORE_CAT_SSH].count;
    if (immurok_keystore_stage(KEYSTORE_CAT_SSH, 0xFF, 0, s_ecc_entry, 112) != 0) {
        memset(s_ecc_entry, 0, 112);
        return -1;
    }
    memset(s_ecc_entry, 0, 112);
    return new_idx;
}

int immurok_keystore_generate(const uint8_t *name16, uint8_t *pub64)
{
    int new_idx = immurok_keystore_generate_stage(name16, pub64);
    if (new_idx < 0) return -1;
    if (immurok_keystore_commit(KEYSTORE_CAT_SSH, 0xFF) != 0) return -1;
    return new_idx;
}

uint8_t *immurok_keystore_result_buf(void)
{
    return s_result_buf;
}

uint8_t immurok_keystore_result_len(void)
{
    return s_result_len;
}

void immurok_keystore_set_result(const uint8_t *data, uint8_t len)
{
    if (len > 64) len = 64;
    if (data && data != s_result_buf)
        memcpy(s_result_buf, data, len);
    s_result_len = len;
}

// ============================================================================
// HMAC-SHA1 + TOTP
// ============================================================================

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t *out)
{
    sha1_ctx_t ctx;
    uint8_t k_pad[SHA1_BLOCK_SIZE];
    uint8_t tk[SHA1_DIGEST_SIZE];
    int i;

    // If key > block size, hash it first
    if (key_len > SHA1_BLOCK_SIZE) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = SHA1_DIGEST_SIZE;
    }

    // Inner: SHA1(K ^ ipad || data)
    memset(k_pad, 0x36, SHA1_BLOCK_SIZE);
    for (i = 0; i < (int)key_len; i++)
        k_pad[i] ^= key[i];

    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, out);

    // Outer: SHA1(K ^ opad || inner_hash)
    memset(k_pad, 0x5C, SHA1_BLOCK_SIZE);
    for (i = 0; i < (int)key_len; i++)
        k_pad[i] ^= key[i];

    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, out, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, out);
}

int immurok_keystore_totp(uint8_t idx, uint32_t unix_time, uint8_t *out6)
{
    // Read OTP secret (offset 60 = after name[30] + service[30])
    uint8_t secret[32];
    if (immurok_keystore_read(KEYSTORE_CAT_OTP, idx, 60, secret, 32) != 0)
        return -1;

    // Trim trailing zero bytes
    uint8_t sec_len = 32;
    while (sec_len > 0 && secret[sec_len - 1] == 0)
        sec_len--;
    if (sec_len == 0) {
        memset(secret, 0, 32);
        return -1;
    }

    // time_step = unix_time / 30, big-endian 8 bytes
    uint64_t step = (uint64_t)unix_time / 30;
    uint8_t msg[8];
    msg[0] = (uint8_t)(step >> 56);
    msg[1] = (uint8_t)(step >> 48);
    msg[2] = (uint8_t)(step >> 40);
    msg[3] = (uint8_t)(step >> 32);
    msg[4] = (uint8_t)(step >> 24);
    msg[5] = (uint8_t)(step >> 16);
    msg[6] = (uint8_t)(step >> 8);
    msg[7] = (uint8_t)(step);

    // HMAC-SHA1
    uint8_t hmac[SHA1_DIGEST_SIZE];
    hmac_sha1(secret, sec_len, msg, 8, hmac);
    memset(secret, 0, 32);

    // Dynamic truncation (RFC 4226)
    uint8_t offset = hmac[19] & 0x0F;
    uint32_t code = ((uint32_t)(hmac[offset] & 0x7F) << 24)
                  | ((uint32_t)hmac[offset + 1] << 16)
                  | ((uint32_t)hmac[offset + 2] << 8)
                  | ((uint32_t)hmac[offset + 3]);
    code %= 1000000;

    // Format as 6 ASCII digits
    for (int i = 5; i >= 0; i--) {
        out6[i] = '0' + (code % 10);
        code /= 10;
    }

    return 0;
}

void immurok_keystore_reset(void)
{
    PRINT("Keystore: reset all\n");

    // Erase blocks 1-5 (block 0 handled by security module)
    for (uint32_t addr = 0x1000; addr < 0x6000; addr += EEPROM_BLOCK_SIZE) {
        WWDG_SetCounter(0);
        EEPROM_ERASE(addr, EEPROM_BLOCK_SIZE);
    }

    // Clear SSH header in block 0 (read-modify-write to preserve security data)
    EEPROM_READ(0x0000, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
    memset(&immurok_keystore_work_buf[SSH_HEADER_ADDR], 0xFF,
           EEPROM_BLOCK_SIZE - SSH_HEADER_ADDR);
    WWDG_SetCounter(0);
    EEPROM_ERASE(0x0000, EEPROM_BLOCK_SIZE);
    WWDG_SetCounter(0);
    EEPROM_WRITE(0x0000, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);

    // Reset cached headers
    for (uint8_t i = 0; i < KEYSTORE_CAT_COUNT; i++) {
        uint32_t h_addr, e_addr;
        uint16_t e_size, max_e;
        uint32_t magic;
        get_section_params(i, &h_addr, &e_addr, &e_size, &max_e, &magic);
        s_headers[i].magic = magic;
        s_headers[i].count = 0;
        s_headers[i].reserved = 0;
        s_headers[i].checksum = 0;
    }

    s_stage_cat = 0xFF;
    s_stage_idx = 0xFF;
}
