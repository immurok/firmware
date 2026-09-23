#include "immurok_snv.h"
#include "immurok_slots.h"

#ifdef IMMUROK_HOST_TEST
#include "fake_eeprom.h"
#include <string.h>
/* 与固件真正 include 的 SDK/EVT/EXAM/BLE/HAL/include/CONFIG.h 一致：
 * 0x77000 - FLASH_ROM_MAX_SIZE(0x70000) = 0x7000。SDK 里另有一份示例
 * CONFIG.h 写 0x77E00，那不是我们用的，2026-09-19 曾被它误导。 */
#define BLE_SNV_ADDR   0x7000
#define BLE_SNV_BLOCK  256
#define BLE_SNV_NUM    2
#define snv_memcpy     memcpy
#else
#include "CH59x_common.h"
#include "CONFIG.h"
#define snv_memcpy     tmos_memcpy
#endif

#define AREA_SIZE   ((uint32_t)BLE_SNV_BLOCK * (uint32_t)BLE_SNV_NUM)
#define SLOT1_ADDR  ((uint32_t)(BLE_SNV_ADDR))
#define SLOT2_ADDR  ((uint32_t)(BLE_SNV_ADDR) + AREA_SIZE)   /* 紧接槽 1 之后 */

uint32_t immurok_snv_area_size(void)
{
    return AREA_SIZE;
}

uint32_t immurok_snv_area_addr(uint8_t slot)
{
    return (slot == IMMUROK_SLOT_2) ? SLOT2_ADDR : SLOT1_ADDR;
}

void immurok_snv_erase_slot(uint8_t slot)
{
    WWDG_SetCounter(0);
    EEPROM_ERASE(immurok_snv_area_addr(slot), AREA_SIZE);
}

void immurok_snv_erase_all(void)
{
    immurok_snv_erase_slot(IMMUROK_SLOT_1);
    immurok_snv_erase_slot(IMMUROK_SLOT_2);
}

bool immurok_snv_is_blank(uint8_t slot)
{
    uint32_t base = immurok_snv_area_addr(slot);
    /* 16B 一段扫，栈只占 16B（CH592F 栈总共 512B，不能放大缓冲）。
     * EEPROM_READ 前后关中断 —— 沿用 immurok_slots.c 的既有写法。 */
    uint32_t chunk[4] __attribute__((aligned(4)));
    for (uint32_t off = 0; off < AREA_SIZE; off += sizeof(chunk)) {
        uint32_t saved = __risc_v_disable_irq();
        EEPROM_READ(base + off, chunk, sizeof(chunk));
        __risc_v_enable_irq(saved);
        for (int i = 0; i < 4; i++) {
            if (chunk[i] != 0xFFFFFFFFUL) return false;
        }
    }
    return true;
}

int immurok_snv_migrate(bool slot2_paired, uint8_t *buf, uint32_t buf_len)
{
    if (buf_len < AREA_SIZE) return -1;
    if (!slot2_paired) return 0;
    if (!immurok_snv_is_blank(IMMUROK_SLOT_2)) return 0;   /* 已迁移 / 新设备 */
    if (immurok_snv_is_blank(IMMUROK_SLOT_1)) return 0;    /* 没东西可搬 */

    {
        uint32_t saved = __risc_v_disable_irq();
        EEPROM_READ(SLOT1_ADDR, buf, AREA_SIZE);
        __risc_v_enable_irq(saved);
    }
    WWDG_SetCounter(0);
    EEPROM_ERASE(SLOT2_ADDR, AREA_SIZE);     /* 已空白，擦一次只为对称 */
    WWDG_SetCounter(0);
    EEPROM_WRITE(SLOT2_ADDR, buf, AREA_SIZE);
    return 1;
}
