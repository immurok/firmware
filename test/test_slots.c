#include "fake_eeprom.h"
#include "test_main.h"
#include "immurok_slots.h"
#include <string.h>

#define MARK_ADDR    0x6100
#define MARK_ENTRIES (EEPROM_PAGE_SIZE / 4)

static void test_blank_page_reads_slot1(void)
{
    fake_eeprom_reset();
    CHECK(immurok_slots_active() == IMMUROK_SLOT_1, "blank -> slot 1");
}

static void test_set_then_read(void)
{
    fake_eeprom_reset();
    CHECK(immurok_slots_set_active(IMMUROK_SLOT_2) == 0, "set slot 2 ok");
    CHECK(immurok_slots_active() == IMMUROK_SLOT_2, "reads back slot 2");
    CHECK(immurok_slots_set_active(IMMUROK_SLOT_1) == 0, "set slot 1 ok");
    CHECK(immurok_slots_active() == IMMUROK_SLOT_1, "reads back slot 1");
}

/* 关键性质：连续切换不应每次都擦页 */
static void test_append_does_not_erase_every_time(void)
{
    fake_eeprom_reset();
    for (int i = 0; i < MARK_ENTRIES - 1; i++) {
        immurok_slots_set_active((i % 2) ? IMMUROK_SLOT_1 : IMMUROK_SLOT_2);
    }
    CHECK(fake_eeprom_erase_count(MARK_ADDR) == 0,
          "no erase before the page fills");
}

static void test_page_full_wraps(void)
{
    fake_eeprom_reset();
    for (int i = 0; i < MARK_ENTRIES + 3; i++) {
        immurok_slots_set_active(IMMUROK_SLOT_2);
    }
    CHECK(fake_eeprom_erase_count(MARK_ADDR) == 1, "erased exactly once");
    CHECK(immurok_slots_active() == IMMUROK_SLOT_2, "still correct after wrap");
}

static void test_rejects_bad_slot(void)
{
    fake_eeprom_reset();
    CHECK(immurok_slots_set_active(0) == -1, "slot 0 rejected");
    CHECK(immurok_slots_set_active(3) == -1, "slot 3 rejected");
    CHECK(immurok_slots_active() == IMMUROK_SLOT_1, "unchanged after reject");
}

static void test_slot2_empty_by_default(void)
{
    uint8_t k[32];
    fake_eeprom_reset();
    CHECK(!immurok_slots_slot2_occupied(), "empty by default");
    CHECK(immurok_slots_slot2_get_key(k) == -1, "get on empty fails");
}

static void test_slot2_set_get_clear(void)
{
    uint8_t in[32], out[32];
    for (int i = 0; i < 32; i++) in[i] = (uint8_t)(i * 7 + 1);
    fake_eeprom_reset();
    CHECK(immurok_slots_slot2_set_key(in) == 0, "set ok");
    CHECK(immurok_slots_slot2_occupied(), "now occupied");
    CHECK(immurok_slots_slot2_get_key(out) == 0, "get ok");
    CHECK(memcmp(in, out, 32) == 0, "key round-trips");
    CHECK(immurok_slots_slot2_clear() == 0, "clear ok");
    CHECK(!immurok_slots_slot2_occupied(), "empty after clear");
}

/* 重复写入必须先擦页，否则 flash 的 1->0 语义会把密钥写坏 */
static void test_slot2_overwrite(void)
{
    uint8_t a[32], b[32], out[32];
    memset(a, 0xA5, 32);
    memset(b, 0x5A, 32);
    fake_eeprom_reset();
    immurok_slots_slot2_set_key(a);
    immurok_slots_slot2_set_key(b);
    CHECK(immurok_slots_slot2_get_key(out) == 0, "get after overwrite");
    CHECK(memcmp(b, out, 32) == 0, "second key wins intact");
}

/* 校验和必须拦下位翻转 */
static void test_slot2_rejects_corruption(void)
{
    uint8_t in[32], out[32];
    uint32_t junk = 0x00000000;
    memset(in, 0x11, 32);
    fake_eeprom_reset();
    immurok_slots_slot2_set_key(in);
    fake_EEPROM_WRITE(0x6200 + 8, &junk, sizeof(junk));  /* 破坏密钥字节 */
    CHECK(immurok_slots_slot2_get_key(out) == -1, "corrupt key rejected");
}

/* 槽 2 的写入绝不能碰到标记页 */
static void test_slot2_does_not_touch_marker_page(void)
{
    uint8_t k[32];
    memset(k, 0x99, 32);
    fake_eeprom_reset();
    immurok_slots_set_active(IMMUROK_SLOT_2);
    immurok_slots_slot2_set_key(k);
    CHECK(immurok_slots_active() == IMMUROK_SLOT_2, "marker page intact");
    CHECK(fake_eeprom_erase_count(0x6100) == 0, "marker page not erased");
}

int main(void)
{
    RUN(test_blank_page_reads_slot1);
    RUN(test_set_then_read);
    RUN(test_append_does_not_erase_every_time);
    RUN(test_page_full_wraps);
    RUN(test_rejects_bad_slot);
    RUN(test_slot2_empty_by_default);
    RUN(test_slot2_set_get_clear);
    RUN(test_slot2_overwrite);
    RUN(test_slot2_rejects_corruption);
    RUN(test_slot2_does_not_touch_marker_page);
    TEST_MAIN_END;
}
