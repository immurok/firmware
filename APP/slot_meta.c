#include "slot_meta.h"
#include <string.h>

#ifdef IMMUROK_HOST_TEST
#include "fake_eeprom.h"
#else
#include "CH59x_common.h"
#include "CONFIG.h"
#endif

#include "../LIB/sha256.h"

#define SLOT_META_ADDR   0x6300
#define SLOT_META_MAGIC  0x4D534D49UL   /* "IMSM",小端 */

typedef struct __attribute__((aligned(4))) {
    uint32_t magic;
    uint8_t  gen[2];            /* [0]=slot1, [1]=slot2 */
    uint8_t  peer_valid[2];
    uint8_t  peer_type[2];
    uint8_t  peer_addr[2][6];
    uint8_t  reserved[6];
    uint32_t checksum;
} slot_meta_page_t;

static uint32_t meta_checksum(const slot_meta_page_t *p)
{
    const uint8_t *b = (const uint8_t *)p;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(*p) - sizeof(uint32_t); i++)
        sum = (sum << 1) ^ (sum >> 31) ^ b[i];   /* rotate-add,与 keystore 同族 */
    return sum ? sum : 1;
}

static int meta_slot_index(uint8_t slot)
{
    if (slot == IMMUROK_SLOT_1) return 0;
    if (slot == IMMUROK_SLOT_2) return 1;
    return -1;
}

/* 读出有效页;空白/坏 magic/坏 checksum → 全 0 结构(gen=0,无 peer)。 */
static void meta_load(slot_meta_page_t *out)
{
    EEPROM_READ(SLOT_META_ADDR, out, sizeof(*out));
    if (out->magic != SLOT_META_MAGIC || out->checksum != meta_checksum(out))
        memset(out, 0, sizeof(*out));
}

static int meta_store(slot_meta_page_t *p)
{
    p->magic = SLOT_META_MAGIC;
    p->checksum = meta_checksum(p);
    WWDG_SetCounter(0);
    if (EEPROM_ERASE(SLOT_META_ADDR, EEPROM_PAGE_SIZE) != 0) return -1;
    WWDG_SetCounter(0);
    if (EEPROM_WRITE(SLOT_META_ADDR, p, sizeof(*p)) != 0) return -1;
    return 0;
}

uint8_t slot_meta_gen(uint8_t slot)
{
    int idx = meta_slot_index(slot);
    if (idx < 0) return 0;
    slot_meta_page_t p;
    meta_load(&p);
    return p.gen[idx];
}

int slot_meta_bump_gen(uint8_t slot)
{
    int idx = meta_slot_index(slot);
    if (idx < 0) return -1;
    slot_meta_page_t p;
    meta_load(&p);
    p.gen[idx]++;
    return meta_store(&p);
}

void slot_meta_reset(void)
{
    /* factory reset：擦整页 → 读回空白（magic 失效）→ 两槽 gen 回 0、peer
     * 全清，广播地址回到 gen=0 的出厂 MAC。0x6300 不在 block 0 / keystore /
     * 0x6200 的擦除范围，必须显式清 —— unpair 地址轮换引入 slot_meta 时漏了，
     * 否则 factory reset 后 gen 残留、地址仍是轮换后的，重配/切槽全乱。 */
    WWDG_SetCounter(0);
    EEPROM_ERASE(SLOT_META_ADDR, EEPROM_PAGE_SIZE);
}

int slot_meta_set_peer(uint8_t slot, uint8_t addr_type, const uint8_t addr[6])
{
    int idx = meta_slot_index(slot);
    if (idx < 0) return -1;
    slot_meta_page_t p;
    meta_load(&p);
    if (p.peer_valid[idx] && p.peer_type[idx] == addr_type &&
        memcmp(p.peer_addr[idx], addr, 6) == 0)
        return 0;                       /* 无变化,不写 */
    p.peer_valid[idx] = 1;
    p.peer_type[idx]  = addr_type;
    memcpy(p.peer_addr[idx], addr, 6);
    return meta_store(&p);
}

int slot_meta_get_peer(uint8_t slot, uint8_t *addr_type, uint8_t addr[6])
{
    int idx = meta_slot_index(slot);
    if (idx < 0) return -1;
    slot_meta_page_t p;
    meta_load(&p);
    if (!p.peer_valid[idx]) return -1;
    if (addr_type) *addr_type = p.peer_type[idx];
    memcpy(addr, p.peer_addr[idx], 6);
    return 0;
}

void slot_mac_derive(const uint8_t factory_mac[6], uint8_t slot,
                     uint8_t gen, uint8_t out[6])
{
    if (gen == 0) {
        memcpy(out, factory_mac, 6);
        if (slot == IMMUROK_SLOT_2) out[5] |= 0x02;
        return;
    }
    for (uint8_t attempt = 0; attempt < 4; attempt++) {
        uint8_t buf[8], digest[32];
        memcpy(buf, factory_mac, 6);
        buf[6] = slot;
        buf[7] = (uint8_t)(gen + attempt);
        sha256(buf, sizeof(buf), digest);
        memcpy(out, digest, 6);
        out[5] |= 0xC0;                 /* static random */
        /* 排除规范禁止的退化值(全 0 / 全 1);高 2 bit 已固定为 1,
         * 只需查其余字节是否全 0 或全 1。 */
        uint8_t all0 = 1, all1 = 1;
        for (int i = 0; i < 6; i++) {
            uint8_t v = (i == 5) ? (uint8_t)(out[5] & 0x3F) : out[i];
            if (v != 0x00) all0 = 0;
            if ((i == 5 && v != 0x3F) || (i != 5 && v != 0xFF)) all1 = 0;
        }
        if (!all0 && !all1) return;
    }
    /* 极不可能:4 次都退化。保底给一个合法值。 */
    memset(out, 0x5A, 6);
    out[5] = (out[5] & 0x3F) | 0xC0;
}
