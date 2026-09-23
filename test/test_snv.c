#include "fake_eeprom.h"
#include "test_main.h"
#include "immurok_snv.h"
#include "immurok_slots.h"
#include <string.h>

#define A1 0x7000
#define A2 0x7200
#define SZ 512

static uint8_t buf[SZ];

static void fill_area(uint32_t addr, uint8_t seed)
{
    uint8_t tmp[SZ];
    for (int i = 0; i < SZ; i++) tmp[i] = (uint8_t)(seed + i);
    fake_EEPROM_ERASE(addr, SZ);
    fake_EEPROM_WRITE(addr, tmp, SZ);
}

static int area_equals(uint32_t addr, uint8_t seed)
{
    uint8_t tmp[SZ];
    fake_EEPROM_READ(addr, tmp, SZ);
    for (int i = 0; i < SZ; i++) if (tmp[i] != (uint8_t)(seed + i)) return 0;
    return 1;
}

static void test_layout(void)
{
    CHECK(immurok_snv_area_size() == SZ, "area = 2 x 256");
    CHECK(immurok_snv_area_addr(IMMUROK_SLOT_1) == A1, "slot 1 keeps the shipped address");
    CHECK(immurok_snv_area_addr(IMMUROK_SLOT_2) == A2, "slot 2 directly after slot 1");
    CHECK(immurok_snv_area_addr(0) == A1, "bad slot -> slot 1");
    CHECK(immurok_snv_area_addr(9) == A1, "bad slot -> slot 1");
    /* 两区都在 block 7：不能压到 block 6（0x6E00 SVN floor / 0x6F00 防拆标记），
     * 也不能越过 DataFlash 末尾 0x8000 */
    CHECK(A1 >= 0x7000 && A2 + SZ <= 0x8000, "both areas inside block 7");
}

static void test_blank_detection(void)
{
    fake_eeprom_reset();
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_1), "fresh slot 1 blank");
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "fresh slot 2 blank");
    uint8_t one = 0x7F;
    fake_EEPROM_WRITE(A1 + SZ - 1, &one, 1);       /* 最后一个字节 */
    CHECK(!immurok_snv_is_blank(IMMUROK_SLOT_1), "one bit cleared -> not blank");
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "other slot unaffected");
}

static void test_erase_slot_is_isolated(void)
{
    fake_eeprom_reset();
    fill_area(A1, 0x10);
    fill_area(A2, 0x80);
    immurok_snv_erase_slot(IMMUROK_SLOT_2);
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "slot 2 erased");
    CHECK(area_equals(A1, 0x10), "slot 1 untouched");
    /* block 6 最高一页（防拆标记）和最低一页（OTA 标记）都不能被碰 */
    CHECK(fake_eeprom_erase_count(0x6F00) == 0, "tamper page untouched");
    CHECK(fake_eeprom_erase_count(0x6000) == 0, "OTA flag page untouched");
}

static void test_erase_all(void)
{
    fake_eeprom_reset();
    fill_area(A1, 0x10);
    fill_area(A2, 0x80);
    immurok_snv_erase_all();
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_1), "slot 1 erased");
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "slot 2 erased");
    CHECK(fake_eeprom_erase_count(0x6F00) == 0, "tamper page untouched");
}

static void test_migrate_copies_when_slot2_bond_lives_in_old_area(void)
{
    fake_eeprom_reset();
    fill_area(A1, 0x33);                       /* 老固件：两槽 bond 都在这 */
    CHECK(immurok_snv_migrate(true, buf, sizeof buf) == 1, "migrated");
    CHECK(area_equals(A2, 0x33), "slot 2 area is a copy of slot 1 area");
    CHECK(area_equals(A1, 0x33), "slot 1 area unchanged");
    /* 幂等：第二次开机什么都不做 */
    CHECK(immurok_snv_migrate(true, buf, sizeof buf) == 0, "second boot no-op");
    CHECK(area_equals(A2, 0x33), "still intact");
}

static void test_migrate_noop_cases(void)
{
    fake_eeprom_reset();
    fill_area(A1, 0x33);
    CHECK(immurok_snv_migrate(false, buf, sizeof buf) == 0, "slot 2 unpaired -> no-op");
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "slot 2 area still blank");

    fake_eeprom_reset();
    CHECK(immurok_snv_migrate(true, buf, sizeof buf) == 0, "nothing in slot 1 area -> no-op");

    fake_eeprom_reset();
    fill_area(A1, 0x33);
    fill_area(A2, 0x44);                       /* 槽 2 已有自己的 bond */
    CHECK(immurok_snv_migrate(true, buf, sizeof buf) == 0, "slot 2 area in use -> no-op");
    CHECK(area_equals(A2, 0x44), "slot 2 area not clobbered");

    fake_eeprom_reset();
    fill_area(A1, 0x33);
    CHECK(immurok_snv_migrate(true, buf, 100) == -1, "small buffer rejected");
    CHECK(immurok_snv_is_blank(IMMUROK_SLOT_2), "nothing written on reject");
}

int main(void)
{
    RUN(test_layout);
    RUN(test_blank_detection);
    RUN(test_erase_slot_is_isolated);
    RUN(test_erase_all);
    RUN(test_migrate_copies_when_slot2_bond_lives_in_old_area);
    RUN(test_migrate_noop_cases);
    TEST_MAIN_END;
}
