/*
 * 主机侧固件单元测试用的假 DataFlash。
 *
 * 刻意保留真 flash 的「只能 1→0」语义：写入是 AND 而非覆盖。
 * 这样「没擦就写」的 bug 会在主机测试里被抓到，而不是等烧板子。
 */
#ifndef FAKE_EEPROM_H
#define FAKE_EEPROM_H
#include <stdint.h>
#include <stddef.h>

#define EEPROM_PAGE_SIZE   256
#define EEPROM_BLOCK_SIZE  4096
#define FAKE_EEPROM_BASE   0x6000
#define FAKE_EEPROM_SIZE   0x1000   /* 只模拟 block 6 */

uint8_t fake_EEPROM_READ(uint32_t addr, void *buf, uint32_t len);
uint8_t fake_EEPROM_WRITE(uint32_t addr, void *buf, uint32_t len);
uint8_t fake_EEPROM_ERASE(uint32_t addr, uint32_t len);

void     fake_eeprom_reset(void);
uint32_t fake_eeprom_erase_count(uint32_t addr);

#define EEPROM_READ(a, b, l)   fake_EEPROM_READ((a), (b), (l))
#define EEPROM_WRITE(a, b, l)  fake_EEPROM_WRITE((a), (b), (l))
#define EEPROM_ERASE(a, l)     fake_EEPROM_ERASE((a), (l))

/* 固件里这些由 SDK 提供，主机测试下变成空操作 */
#define WWDG_SetCounter(x)          ((void)0)
#define __risc_v_disable_irq()      (0u)
#define __risc_v_enable_irq(x)      ((void)(x))
#define PRINT(...)                  ((void)0)
#define SYS_ResetExecute()          fake_reset_called()

void fake_reset_called(void);
int  fake_reset_count(void);

#endif
