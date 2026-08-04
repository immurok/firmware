#include "fake_eeprom.h"
#include <string.h>

static uint8_t  s_mem[FAKE_EEPROM_SIZE];
static uint32_t s_erase[FAKE_EEPROM_SIZE / EEPROM_PAGE_SIZE];
static int      s_reset_count;

static uint32_t off(uint32_t addr) { return addr - FAKE_EEPROM_BASE; }

void fake_eeprom_reset(void)
{
    memset(s_mem, 0xFF, sizeof(s_mem));
    memset(s_erase, 0, sizeof(s_erase));
    s_reset_count = 0;
}

uint32_t fake_eeprom_erase_count(uint32_t addr)
{
    return s_erase[off(addr) / EEPROM_PAGE_SIZE];
}

uint8_t fake_EEPROM_READ(uint32_t addr, void *buf, uint32_t len)
{
    memcpy(buf, s_mem + off(addr), len);
    return 0;
}

/* 真 flash 只能把 1 写成 0；假实现照做，好暴露"没擦就写"的 bug */
uint8_t fake_EEPROM_WRITE(uint32_t addr, void *buf, uint32_t len)
{
    uint8_t *src = (uint8_t *)buf;
    uint32_t o = off(addr);
    for (uint32_t i = 0; i < len; i++) {
        s_mem[o + i] &= src[i];
    }
    return 0;
}

uint8_t fake_EEPROM_ERASE(uint32_t addr, uint32_t len)
{
    uint32_t o = off(addr);
    memset(s_mem + o, 0xFF, len);
    for (uint32_t i = 0; i < len / EEPROM_PAGE_SIZE; i++) {
        s_erase[o / EEPROM_PAGE_SIZE + i]++;
    }
    return 0;
}

void fake_reset_called(void) { s_reset_count++; }
int  fake_reset_count(void)  { return s_reset_count; }
