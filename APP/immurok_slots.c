#include "immurok_slots.h"
#ifndef IMMUROK_HOST_TEST
#include "immurok_scratch.h"
#endif

#ifdef IMMUROK_HOST_TEST
#include "fake_eeprom.h"
#else
#include "CH59x_common.h"
#include "CONFIG.h"
#endif

/* ---------- 活跃槽标记页 0x6100 ----------
 *
 * append-only：每次切换追加一条 4 字节标记（DataFlash 最小写入单位），
 * 一页 64 条，写满才擦一次 → 10k 次擦除 × 64 ≈ 64 万次切换。
 * 这是唯一的高频写入点，故独占一页，绝不与低频的密钥页合并。
 */

#define MARK_ADDR     0x6100
#define MARK_SLOT1    0x31544C53UL   /* "SLT1" */
#define MARK_SLOT2    0x32544C53UL   /* "SLT2" */
#define MARK_BLANK    0xFFFFFFFFUL
#define MARK_ENTRIES  (EEPROM_PAGE_SIZE / 4)

static uint32_t read_word(uint32_t addr)
{
    uint32_t v __attribute__((aligned(4))) = 0;
    /* EEPROM_READ 前后关中断 —— 沿用 tamper.c / immurok_security.c 的
     * 既有写法（"fault-into-IAP war story"）。 */
    uint32_t saved = __risc_v_disable_irq();
    EEPROM_READ(addr, &v, sizeof(v));
    __risc_v_enable_irq(saved);
    return v;
}

uint8_t immurok_slots_active(void)
{
    uint8_t slot = IMMUROK_SLOT_1;
    for (uint16_t i = 0; i < MARK_ENTRIES; i++) {
        uint32_t v = read_word(MARK_ADDR + i * 4);
        if (v == MARK_BLANK) break;             /* 第一个空白即日志末尾 */
        if (v == MARK_SLOT1)      slot = IMMUROK_SLOT_1;
        else if (v == MARK_SLOT2) slot = IMMUROK_SLOT_2;
        /* 其它值 = 损坏条目，跳过继续扫 */
    }
    return slot;
}

int immurok_slots_set_active(uint8_t slot)
{
    uint32_t mark;
    uint16_t free_idx = MARK_ENTRIES;
    uint32_t v __attribute__((aligned(4)));

    if (slot == IMMUROK_SLOT_1)      mark = MARK_SLOT1;
    else if (slot == IMMUROK_SLOT_2) mark = MARK_SLOT2;
    else                             return -1;

    for (uint16_t i = 0; i < MARK_ENTRIES; i++) {
        if (read_word(MARK_ADDR + i * 4) == MARK_BLANK) { free_idx = i; break; }
    }

    WWDG_SetCounter(0);
    if (free_idx == MARK_ENTRIES) {
        EEPROM_ERASE(MARK_ADDR, EEPROM_PAGE_SIZE);   /* 写满，擦页重来 */
        free_idx = 0;
    }

    v = mark;
    EEPROM_WRITE(MARK_ADDR + free_idx * 4, &v, sizeof(v));
    return 0;
}

/* ---------- 槽 2 密钥页 0x6200 ----------
 *
 * 独立成页的动机不是磨损（配对一辈子也就几次），而是**爆炸半径**：
 * save_security_data() 往 block 0 写要做 4KB 整块 read-modify-write，
 * 而 block 0 里住着 32 条 SSH 私钥。槽 2 挪出来后，配对操作永远碰不到
 * SSH 段。
 */

#define SLOT2_ADDR   0x6200
#define SLOT2_MAGIC  0x32534D49UL   /* "IMS2" */

typedef struct __attribute__((aligned(4))) {
    uint32_t magic;
    uint8_t  occupied;
    uint8_t  reserved[3];
    uint8_t  key[32];
    uint32_t checksum;
} slot2_page_t;                      /* 44 B */

/* 页缓冲借用 work_buf 的 SLOTS 分区（64B，够放 48B 的 pin_page_t）。
 * 主机测试里没有 work_buf，退回普通 static。 */
#ifdef IMMUROK_HOST_TEST
static uint8_t s_slots_scratch[64];
#define SLOTS_SCRATCH  s_slots_scratch
#else
#define SLOTS_SCRATCH  SCRATCH_AT(SCRATCH_SLOTS_OFF)
#endif
#define s_slot2_page  (*(slot2_page_t *)SLOTS_SCRATCH)

static uint32_t slot2_checksum(const slot2_page_t *p)
{
    /* 加权加和；目的是拦位翻转，不是防篡改 —— 防篡改靠密钥本身不可读 */
    uint32_t sum = p->magic + p->occupied;
    for (int i = 0; i < 32; i++) sum += p->key[i] * (uint32_t)(i + 1);
    return sum;
}

static int slot2_load(slot2_page_t *out)
{
    uint32_t saved = __risc_v_disable_irq();
    EEPROM_READ(SLOT2_ADDR, out, sizeof(*out));
    __risc_v_enable_irq(saved);
    if (out->magic != SLOT2_MAGIC)            return -1;
    if (out->occupied != 1)                   return -1;
    if (out->checksum != slot2_checksum(out)) return -1;
    return 0;
}

bool immurok_slots_slot2_occupied(void)
{
    return slot2_load(&s_slot2_page) == 0;
}

int immurok_slots_slot2_get_key(uint8_t out_key[32])
{
    if (slot2_load(&s_slot2_page) != 0) return -1;
    for (int i = 0; i < 32; i++) out_key[i] = s_slot2_page.key[i];
    return 0;
}

int immurok_slots_slot2_set_key(const uint8_t key[32])
{
    slot2_page_t *p = &s_slot2_page;
    for (int i = 0; i < (int)sizeof(*p); i++) ((uint8_t *)p)[i] = 0;
    p->magic = SLOT2_MAGIC;
    p->occupied = 1;
    for (int i = 0; i < 32; i++) p->key[i] = key[i];
    p->checksum = slot2_checksum(p);

    WWDG_SetCounter(0);
    EEPROM_ERASE(SLOT2_ADDR, EEPROM_PAGE_SIZE);   /* 覆盖写必须先擦 */
    EEPROM_WRITE(SLOT2_ADDR, p, sizeof(*p));
    return 0;
}

const uint8_t *immurok_slots_slot2_key_ptr(void)
{
    if (slot2_load(&s_slot2_page) != 0) return 0;
    return s_slot2_page.key;
}

int immurok_slots_slot2_clear(void)
{
    WWDG_SetCounter(0);
    EEPROM_ERASE(SLOT2_ADDR, EEPROM_PAGE_SIZE);
    return 0;
}

/* 曾有 PIN 登记状态页 0x6300（k_pin / ttl_boots / attempts_left）。
 * 2026-08-03 第二台主机的登记简化为「指纹 + 设备按键」，临时 PIN 整条
 * 链路移除，这一页不再使用。factory reset 仍显式擦 0x6200 与标记页。 */
