#include "fake_eeprom.h"
#include "test_main.h"
#include "slot_meta.h"
#include <string.h>

#define SLOT_META_ADDR 0x6300

static void test_blank_gen_is_zero(void)
{
    fake_eeprom_reset();
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 0, "blank -> slot1 gen 0");
    CHECK(slot_meta_gen(IMMUROK_SLOT_2) == 0, "blank -> slot2 gen 0");
}

static void test_bump_persists(void)
{
    fake_eeprom_reset();
    CHECK(slot_meta_bump_gen(IMMUROK_SLOT_1) == 0, "bump ok");
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 1, "slot1 gen now 1");
    CHECK(slot_meta_gen(IMMUROK_SLOT_2) == 0, "slot2 untouched");
    CHECK(slot_meta_bump_gen(IMMUROK_SLOT_1) == 0, "bump again");
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 2, "slot1 gen now 2");
}

static void test_bad_slot_rejected(void)
{
    fake_eeprom_reset();
    CHECK(slot_meta_bump_gen(0) == -1, "slot 0 rejected");
    CHECK(slot_meta_bump_gen(3) == -1, "slot 3 rejected");
    CHECK(slot_meta_gen(0) == 0, "bad slot reads 0");
}

static void test_corrupt_page_reads_zero(void)
{
    uint8_t junk[8] = {1,2,3,4,5,6,7,8};
    fake_eeprom_reset();
    fake_EEPROM_ERASE(SLOT_META_ADDR, EEPROM_PAGE_SIZE);
    fake_EEPROM_WRITE(SLOT_META_ADDR, junk, sizeof(junk)); /* 坏 magic */
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 0, "corrupt -> gen 0");
}

/* 关键:先擦后写。fake_eeprom 的 1→0 语义会让「没擦就写」的位翻转失败,
 * 从而 gen 读不回预期值 —— 这条覆盖 bump 的擦写顺序。 */
static void test_bump_erases_before_write(void)
{
    fake_eeprom_reset();
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    CHECK(slot_meta_gen(IMMUROK_SLOT_2) == 3, "3 bumps survive erase/write");
}

static void test_peer_absent_by_default(void)
{
    uint8_t t, a[6];
    fake_eeprom_reset();
    CHECK(slot_meta_get_peer(IMMUROK_SLOT_1, &t, a) == -1, "no peer by default");
}

static void test_peer_round_trips(void)
{
    uint8_t in[6] = {0xC0,0x11,0x22,0x33,0x44,0x55};
    uint8_t t, out[6];
    fake_eeprom_reset();
    CHECK(slot_meta_set_peer(IMMUROK_SLOT_2, 1, in) == 0, "set peer ok");
    CHECK(slot_meta_get_peer(IMMUROK_SLOT_2, &t, out) == 0, "get peer ok");
    CHECK(t == 1, "addr_type round-trips");
    CHECK(memcmp(in, out, 6) == 0, "addr round-trips");
    CHECK(slot_meta_get_peer(IMMUROK_SLOT_1, &t, out) == -1, "other slot absent");
}

/* 仅变化才写:相同地址重复 set 不得再擦页。 */
static void test_peer_idempotent_no_write(void)
{
    uint8_t in[6] = {0xC0,1,2,3,4,5};
    fake_eeprom_reset();
    slot_meta_set_peer(IMMUROK_SLOT_1, 1, in);
    uint32_t e1 = fake_eeprom_erase_count(0x6300);
    slot_meta_set_peer(IMMUROK_SLOT_1, 1, in);   /* 同值 */
    slot_meta_set_peer(IMMUROK_SLOT_1, 1, in);
    CHECK(fake_eeprom_erase_count(0x6300) == e1, "same peer -> no extra erase");
}

/* gen 与 peer 独立共存:bump gen 不抹掉 peer,反之亦然。 */
static void test_gen_and_peer_coexist(void)
{
    uint8_t in[6] = {0xC0,9,8,7,6,5}, t, out[6];
    fake_eeprom_reset();
    slot_meta_set_peer(IMMUROK_SLOT_1, 1, in);
    slot_meta_bump_gen(IMMUROK_SLOT_1);
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 1, "gen survived peer write");
    CHECK(slot_meta_get_peer(IMMUROK_SLOT_1, &t, out) == 0, "peer survived bump");
    CHECK(memcmp(in, out, 6) == 0, "peer intact after bump");
}

/* gen=0 必须逐字节等于现有派生 —— 升级兼容钉死。 */
static void test_derive_gen0_matches_legacy(void)
{
    uint8_t fm[6] = {0xA1,0xAD,0x5D,0x5E,0x3D,0x0C};  /* 逆序:显示 0C:3D:...:A1 */
    uint8_t s1[6], s2[6];
    slot_mac_derive(fm, IMMUROK_SLOT_1, 0, s1);
    slot_mac_derive(fm, IMMUROK_SLOT_2, 0, s2);
    CHECK(memcmp(s1, fm, 6) == 0, "slot1 gen0 == factory mac");
    CHECK(s2[5] == (uint8_t)(fm[5] | 0x02), "slot2 gen0 sets 0x02 on [5]");
    CHECK(memcmp(s2, fm, 5) == 0, "slot2 gen0 low5 == factory");
}

/* gen>=1 是 static random:out[5] 高 2 bit = 11。 */
static void test_derive_gen1_static_random(void)
{
    uint8_t fm[6] = {1,2,3,4,5,6};
    uint8_t a[6];
    slot_mac_derive(fm, IMMUROK_SLOT_1, 1, a);
    CHECK((a[5] & 0xC0) == 0xC0, "gen1 slot1 static-random bits set");
    slot_mac_derive(fm, IMMUROK_SLOT_2, 1, a);
    CHECK((a[5] & 0xC0) == 0xC0, "gen1 slot2 static-random bits set");
}

/* 两槽同 gen 不撞;同槽跨 gen 不撞。 */
static void test_derive_no_collision(void)
{
    uint8_t fm[6] = {1,2,3,4,5,6};
    uint8_t s1g1[6], s2g1[6], s1g2[6];
    slot_mac_derive(fm, IMMUROK_SLOT_1, 1, s1g1);
    slot_mac_derive(fm, IMMUROK_SLOT_2, 1, s2g1);
    slot_mac_derive(fm, IMMUROK_SLOT_1, 2, s1g2);
    CHECK(memcmp(s1g1, s2g1, 6) != 0, "slot1 != slot2 same gen");
    CHECK(memcmp(s1g1, s1g2, 6) != 0, "gen1 != gen2 same slot");
}

/* 确定性:同输入同输出。 */
static void test_derive_deterministic(void)
{
    uint8_t fm[6] = {9,9,9,9,9,9};
    uint8_t a[6], b[6];
    slot_mac_derive(fm, IMMUROK_SLOT_2, 5, a);
    slot_mac_derive(fm, IMMUROK_SLOT_2, 5, b);
    CHECK(memcmp(a, b, 6) == 0, "same input -> same addr");
}

/* factory reset：slot_meta_reset 擦掉 gen 和 peer，两槽回出厂 gen=0。 */
static void test_reset_clears_gen_and_peer(void)
{
    uint8_t in[6] = {0xC0, 1, 2, 3, 4, 5}, t, out[6];
    fake_eeprom_reset();
    slot_meta_bump_gen(IMMUROK_SLOT_1);
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    slot_meta_bump_gen(IMMUROK_SLOT_2);
    slot_meta_set_peer(IMMUROK_SLOT_1, 1, in);
    CHECK(slot_meta_gen(IMMUROK_SLOT_2) == 3, "precondition slot2 gen 3");
    slot_meta_reset();
    CHECK(slot_meta_gen(IMMUROK_SLOT_1) == 0, "slot1 gen 0 after reset");
    CHECK(slot_meta_gen(IMMUROK_SLOT_2) == 0, "slot2 gen 0 after reset");
    CHECK(slot_meta_get_peer(IMMUROK_SLOT_1, &t, out) == -1, "peer cleared after reset");
}

int main(void)
{
    RUN(test_blank_gen_is_zero);
    RUN(test_bump_persists);
    RUN(test_bad_slot_rejected);
    RUN(test_corrupt_page_reads_zero);
    RUN(test_bump_erases_before_write);
    RUN(test_peer_absent_by_default);
    RUN(test_peer_round_trips);
    RUN(test_peer_idempotent_no_write);
    RUN(test_gen_and_peer_coexist);
    RUN(test_derive_gen0_matches_legacy);
    RUN(test_derive_gen1_static_random);
    RUN(test_derive_no_collision);
    RUN(test_derive_deterministic);
    RUN(test_reset_clears_gen_and_peer);
    TEST_MAIN_END;
}
