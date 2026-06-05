#include "tamper.h"
#include "CH59x_common.h"
#include "CONFIG.h"

// Block 6 (0x6000-0x6FFF) also holds the OTA ImageFlag at page 0 (0x6000, written
// by hidkbd.c on OTA reboot). Use a SEPARATE 256B page (0x6F00, last page) + 256B
// page-erase so set/clear never touches the OTA flag. Block 6 survives the tamper
// wipe (which erases only keystore 0x0000-0x5FFF and BLE SNV 0x7000).
#define TAMPER_FLAG_ADDR   0x6F00
#define TAMPER_MAGIC       0x4F50454EUL   // "OPEN"

bool tamper_is_flagged(void)
{
    uint32_t v __attribute__((aligned(4))) = 0;
    // Guard EEPROM_READ like immurok_security.c (fault-into-IAP war story).
    uint32_t saved = __risc_v_disable_irq();
    EEPROM_READ(TAMPER_FLAG_ADDR, &v, sizeof(v));
    __risc_v_enable_irq(saved);
    return (v == TAMPER_MAGIC);
}

void tamper_set_flag(void)
{
    uint32_t v __attribute__((aligned(4))) = TAMPER_MAGIC;
    WWDG_SetCounter(0);
    EEPROM_ERASE(TAMPER_FLAG_ADDR, EEPROM_PAGE_SIZE);   // 256B page erase, not 4KB
    EEPROM_WRITE(TAMPER_FLAG_ADDR, &v, sizeof(v));
}

void tamper_clear_flag(void)
{
    WWDG_SetCounter(0);
    EEPROM_ERASE(TAMPER_FLAG_ADDR, EEPROM_PAGE_SIZE);
}
