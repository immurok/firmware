#include "fake_eeprom.h"
#include "test_main.h"
#include <string.h>

static void test_erase_then_write(void)
{
    uint32_t v = 0xDEADBEEF, r = 0;
    fake_eeprom_reset();
    fake_EEPROM_ERASE(0x6100, EEPROM_PAGE_SIZE);
    fake_EEPROM_WRITE(0x6100, &v, sizeof(v));
    fake_EEPROM_READ(0x6100, &r, sizeof(r));
    CHECK(r == 0xDEADBEEF, "write/read round-trip");
    CHECK(fake_eeprom_erase_count(0x6100) == 1, "erase counted");
}

/* flash 语义：没擦过的位置写不进去（只能 1->0） */
static void test_write_without_erase_is_and(void)
{
    uint32_t a = 0x0000FFFF, b = 0xFFFF0000, r = 0;
    fake_eeprom_reset();
    fake_EEPROM_ERASE(0x6100, EEPROM_PAGE_SIZE);
    fake_EEPROM_WRITE(0x6100, &a, sizeof(a));
    fake_EEPROM_WRITE(0x6100, &b, sizeof(b));
    fake_EEPROM_READ(0x6100, &r, sizeof(r));
    CHECK(r == 0x00000000, "second write ANDs, does not replace");
}

int main(void)
{
    RUN(test_erase_then_write);
    RUN(test_write_without_erase_is_and);
    TEST_MAIN_END;
}
