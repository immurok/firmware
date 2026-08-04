/*
 * immurok Security Module Implementation for CH592F
 * v3.0 - ECDH pairing, HMAC-signed notifications, no password on device
 */

#include "immurok_security.h"
#include "immurok_keystore.h"
#include "immurok_slots.h"
#include "slot_meta.h"
#include "CH59x_common.h"
#include "CONFIG.h"
#include "../LIB/sha256.h"
#include "../LIB/uECC.h"
#include <string.h>

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
static uint8_t s_active_slot = IMMUROK_SLOT_1;
static bool    s_active_valid = false;

/* 下一次 pair_save() 把新密钥写进哪个槽。默认槽 1（原有行为）。
 * 槽 2 登记时由 hidkbd 设置，save 完自动复位。 */
static uint8_t s_pair_target_slot = IMMUROK_SLOT_1;

/* 槽 2 登记「扣着待提交」的状态直接由 s_pair_target_slot 表达，不另设
 * 标志位 —— target 停在 SLOT_2 就说明这一轮登记还没提交/放弃。
 * （CH592F 的 RAM 以字节计，一个对齐后占 4B 的 bool 就够让
 * release-debug 链接不过。）
 *
 * 语义：ECDH 算完的密钥先扣在 s_data.shared_key（仅内存），必须等
 * SLOT_PAIR 的 proof 与指纹第二重都通过才真正落盘。不这样做的话，PIN
 * 窗口一开，任何能 bond 上的设备跑一遍正常配对流程，延迟落盘就会把槽 2
 * 直接给它 —— PIN 和指纹形同虚设。
 *
 * 扣着期间禁止 save_security_data()：此刻 s_data.shared_key 装的可能是
 * 槽 2 的新密钥，写下去会覆盖 block 0 里槽 1 的密钥。 */

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

    immurok_security_load_active_slot();

    PRINT("Security: paired=%d, active_slot=%d\n", s_data.paired, s_active_slot);
    return 0;
}

// ============================================================================
// Pairing Status
// ============================================================================

/* 「设备被认领过没有」—— 任一槽有货即为真。
 *
 * 这是**设备全局**的防盗语义，用于 BLE bond 模式和未配对命令白名单：
 * 小偷切到空槽也不该能自由 bond / 走一遍 PAIR_INIT。不要拿它回答
 * 「跟我说话的这台主机配对了没有」—— 那是 active_slot_paired()。 */
bool immurok_security_is_paired(void)
{
    return immurok_security_slot_occupied(IMMUROK_SLOT_1) ||
           immurok_security_slot_occupied(IMMUROK_SLOT_2);
}

/* 「当前连着的这台主机配对了没有」—— 只看活动槽。
 *
 * 主机按槽的 BLE 地址连进来，所以活动槽就是对方的槽。GET_STATUS /
 * PAIR_STATUS 必须报这个：曾经报 is_paired()，结果主机 2 走空的槽 2 连上
 * 来也被告知「已配对」，app 于是按主机 1 视角渲染（绿色 paired + 签发 PIN
 * 按钮），却拿不出共享密钥做验证，红字 Device verification failed，而真正
 * 该出现的「输入配对码」入口反倒不显示。2026-08-03 实机发现。 */
bool immurok_security_active_slot_paired(void)
{
    return immurok_security_slot_occupied(s_active_slot);
}

uint8_t immurok_security_active_slot(void) { return s_active_slot; }

bool immurok_security_slot_occupied(uint8_t slot)
{
    if (slot == IMMUROK_SLOT_1) return (s_data.paired == 0x01);
    if (slot == IMMUROK_SLOT_2) return immurok_slots_slot2_occupied();
    return false;
}

/* 活跃槽的密钥 —— 按需取，不在 RAM 里另存一份副本。
 *
 * 槽 1：s_data.shared_key 开机就已在 RAM（block 0 的内存副本），零成本，
 *       与双主机改造之前的原始路径完全一致。
 * 槽 2：从 flash 0x6200 读进 work_buf 的 SLOTS 分区，用完即弃。
 *
 * 返回的指针只在紧接着的这一次使用中有效（下一次 immurok_slots_* 调用
 * 就会覆盖它），所有调用点都是「取出来立刻喂给 hmac_sha256」。
 *
 * 关于「EEPROM_READ 紧接 ECC 会把芯片打进 IAP」那条既有的坑：不适用。
 * ECC 跑在 FP_GATE_EXEC_EVT 这个独立 TMOS 事件里，本函数的调用者
 * （sign_fp_match / challenge_response）在指纹匹配路径，两者不同事件、
 * 栈已完全展开，不构成「紧接着」。 */
static const uint8_t *active_key(void)
{
    if (!s_active_valid) return 0;
    if (s_active_slot == IMMUROK_SLOT_2) {
        return immurok_slots_slot2_key_ptr();
    }
    return s_data.shared_key;
}

int immurok_security_load_active_slot(void)
{
    uint8_t slot = immurok_slots_active();

    s_active_valid = false;

    /* 槽位只由「按切换指纹」改变。开机照标记页走，不做任何回落 ——
     * 标记页是「当前在哪个槽」的唯一真源。
     *
     * 曾经这里有个「空槽就回落到有效槽」的逻辑，用意是防止卡死。但那会
     * 造成两个真源打架：main.c 选 BLE 地址用的是 immurok_slots_active()
     * 的原值，回落只改了这里的 s_active_slot，结果设备用槽 2 的地址广播
     * 却报告自己在槽 1，LED 也跟着显示错误的颜色。2026-08-03 真机发现。
     *
     * 而防卡死已经由别的机制解决：切换指纹在没有 BLE / app 连接时也能
     * 工作（hidkbd.c 那两道触摸门的双主机例外），它本身就是逃生口。 */
    s_active_slot = slot;

    /* 停在空槽是合法状态（登记中，或用户手动切过去了）：广播照旧，
     * 只是没有密钥可用，所有 HMAC 会干净地失败。 */
    if (slot == IMMUROK_SLOT_2) {
        if (immurok_slots_slot2_key_ptr() == 0) return -1;
    } else {
        if (s_data.paired != 0x01) return -1;
    }
    s_active_valid = true;
    return 0;
}

int immurok_security_slot2_commit(void)
{
    int ret;
    if (s_pair_target_slot != IMMUROK_SLOT_2) return -1;

    /* s_data.shared_key 此刻装的是 ECDH 刚算出的槽 2 密钥（仅内存）。
     * 写进 0x6200 后从 flash 重载 s_data 复原槽 1 —— block 0 全程未被
     * 写入，已出货设备的槽 1 配对完好无损。 */
    ret = immurok_slots_slot2_set_key(s_data.shared_key);
    s_pair_target_slot = IMMUROK_SLOT_1;
    load_security_data();
    immurok_security_load_active_slot();
    return ret;
}

int immurok_security_slot_clear(uint8_t slot)
{
    int i;
    if (slot == IMMUROK_SLOT_2) return immurok_slots_slot2_clear();
    if (slot != IMMUROK_SLOT_1) return -1;
    s_data.paired = 0;
    for (i = 0; i < 32; i++) s_data.shared_key[i] = 0;
    int ret = save_security_data();
    immurok_security_load_active_slot();   /* 同上：状态必须跟着变 */
    return ret;
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
/* 刻意不查 s_ecdh_state。
 *
 * SLOT_PAIR 要用设备公钥算 proof，而那时 pair_compute_secret() 已把状态
 * 清回 IDLE —— 原来那句 `state != KEY_READY → return -1` 让 SLOT_PAIR 一律
 * 回 0xFE，槽 2 永远配不上（2026-08-03 实机）。
 *
 * 判据换成「s_ecdh_pub 还在不在」：pair_init() 把它清零，make_key 填上，
 * 之后只有私钥被擦除。重新压缩一次即可，uECC_compress 只是取坐标，没有
 * make_key 那种秒级标量乘开销。缓存一份压缩结果更直接，但那 34B bss 会把
 * .stack_guard 顶进 .stack，链接不过。 */
int immurok_security_pair_get_pubkey(uint8_t *compressed33)
{
    uint8_t nz = 0;
    int i;
    for (i = 0; i < 64; i++) nz |= s_ecdh_pub[i];
    if (!nz) return -1;

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
// Set when ECC compute completes successfully but save is deferred to a
// later TMOS event. Caller (hidkbd.c EXEC handler) reads this to know it
// must schedule the save.
volatile uint8_t immurok_security_pair_save_pending = 0;

void immurok_security_pair_set_target_slot(uint8_t slot)
{
    s_pair_target_slot = (slot == IMMUROK_SLOT_2) ? IMMUROK_SLOT_2
                                                  : IMMUROK_SLOT_1;
}

int immurok_security_pair_save(void)
{
    PRINT("ECDH deferred save start (target slot %d)\n", s_pair_target_slot);

    if (s_pair_target_slot == IMMUROK_SLOT_2)
    {
        /* 直接落盘。曾经这里只「扣住」，等 SLOT_PAIR 的 PIN proof 才写；
         * 2026-08-03 登记改为指纹 + 按键后，两道门都在 PAIR_INIT 之前过完，
         * 走到这里就已经授权完毕，没有可等的第二阶段了。 */
        return immurok_security_slot2_commit();
    }

    int ret = save_security_data();
    /* 必须刷新活跃槽：所有 HMAC 现在走 active_key()，它的可用性由
     * s_active_valid 决定，而后者只在 load_active_slot() 里置位。
     * 漏掉这一行会让设备「配对成功但认证不了」直到下次重启 ——
     * 2026-08-03 真机实测踩到（challenge-response 失败 → app 报设备
     * 未验证 → AGENT_APPROVE 返回 ERROR）。 */
    immurok_security_load_active_slot();
    return ret;
}

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

    // Save deferred — EEPROM_READ called immediately after ECC (~2s of
    // intensive flash instruction fetch) crashes the chip, regardless of
    // IRQ state or chunk size. Caller schedules a TMOS event to call
    // immurok_security_pair_save() once the call stack has fully unwound
    // and instruction-fetch traffic has settled.
    immurok_security_pair_save_pending = 1;
    PRINT("ECDH compute done, save deferred\n");

    s_ecdh_state = ECDH_STATE_IDLE;
    return 0;
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
    const uint8_t *k = active_key();
    if (k == 0) {
        return -1;
    }

    // Build: [0x21][page_id:2B LE]
    out_buf[0] = 0x21;
    out_buf[1] = page_id & 0xFF;
    out_buf[2] = (page_id >> 8) & 0xFF;

    // HMAC-SHA256(shared_key, 0x21 || page_id), truncate to 8 bytes
    uint8_t hmac_full[32];
    hmac_sha256(k, 32, out_buf, 3, hmac_full);
    memcpy(&out_buf[3], hmac_full, 8);

    return 11;  // Total notification size
}

// ============================================================================
// Challenge-Response Verification
// ============================================================================

int immurok_security_challenge_response(const uint8_t *nonce, uint8_t *out_hmac8)
{
    const uint8_t *k = active_key();
    if (k == 0) {
        return -1;
    }

    // HMAC-SHA256(shared_key, nonce[8]), truncate to 8 bytes
    uint8_t hmac_full[32];
    hmac_sha256(k, 32, nonce, 8, hmac_full);
    memcpy(out_hmac8, hmac_full, 8);

    return 0;
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
    (void)ret;

    /* 双主机的三页在 block 6，不在 keystore 的擦除范围（0x1000-0x6000）
     * 内，也不在上面 block 0 的擦除范围内，必须显式清除 —— 否则恢复出厂
     * 后槽 2 仍持有旧密钥、标记页仍指向槽 2，设备会以槽 2 的 BLE 地址
     * 广播却没有任何主机认识它。 */
    immurok_slots_slot2_clear();
    slot_meta_reset();   /* 0x6300：两槽 gen 回 0、peer 清空 → 地址回出厂 MAC */
    immurok_slots_set_active(IMMUROK_SLOT_1);
    s_active_valid = false;
    s_active_slot = IMMUROK_SLOT_1;

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
    /* 槽 2 登记扣住期间，s_data.shared_key 装的是槽 2 的新密钥。
     * 此时写 block 0 会覆盖槽 1 的密钥 —— 直接拒绝，把脚枪变成可捕获的
     * 错误。正常流程里这一条永不触发（提交/放弃都会先复原 s_data）。 */
    if (s_pair_target_slot == IMMUROK_SLOT_2) {
        PRINT("!! refusing save_security_data: slot 2 enrollment in flight\n");
        return -1;
    }
    uint8_t ret;

    s_data.magic = STORAGE_MAGIC_V3;
    s_data.checksum = calc_checksum((uint8_t *)&s_data,
                                     sizeof(s_data) - sizeof(uint32_t));

    PRINT("save_security_data: magic=0x%08lX, paired=%d\n",
          s_data.magic, s_data.paired);

    // Read-modify-write to preserve keystore data sharing Block 0. Wrap
    // the READ in a global-IRQ disable as defense-in-depth — earlier
    // testing showed inline calls right after ECC could fault into the
    // IAP bootloader. Caller now defers this whole function via a TMOS
    // event 200ms after the PAIR_CONFIRM response, so the call stack is
    // fully unwound; the IRQ wrapper is belt-and-braces.
    {
        uint32_t saved = __risc_v_disable_irq();
        EEPROM_READ(SECURITY_DATA_ADDR, immurok_keystore_work_buf, EEPROM_BLOCK_SIZE);
        __risc_v_enable_irq(saved);
    }
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
