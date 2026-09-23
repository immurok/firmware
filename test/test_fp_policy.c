/*
 * M4（2026-09-19 审计）：切换指纹（page 5）计入 fp_user_bitmap()，三个管理命令
 * 按「位图非零」挂门，而切换指纹匹配永远走切槽复位不进门。删掉最后一枚认证
 * 指纹后设备只剩切换指纹，ENROLL/DELETE/FACTORY_RESET 永久 WAIT_FP，只能长按。
 *
 * 用户定的规则（2026-09-19）：
 *   1. 存在切换指纹时，禁止删除最后一枚认证指纹
 *   2. 不存在认证指纹时，禁止录入切换指纹
 */
#include "fp_policy.h"
#include "test_main.h"

#define B(n) ((uint16_t)(1u << (n)))
#define SW   B(FP_SWITCH_SLOT)

static void test_auth_bits_exclude_switch(void)
{
    CHECK(fp_policy_auth_bits(SW) == 0, "only switch finger -> no auth fingers");
    CHECK(fp_policy_auth_bits(B(0) | SW) == B(0), "switch bit masked out");
    CHECK(fp_policy_auth_bits(B(0) | B(3)) == (B(0) | B(3)), "auth bits pass through");
}

static void test_delete_last_auth_with_switch_refused(void)
{
    CHECK(!fp_policy_delete_allowed(B(0) | SW, 0), "0 is the last auth finger and switch exists -> refuse");
    CHECK(!fp_policy_delete_allowed(B(4) | SW, 4), "same for finger 4");
}

static void test_delete_allowed_cases(void)
{
    CHECK(fp_policy_delete_allowed(B(0), 0), "no switch finger: deleting the last auth finger is allowed");
    CHECK(fp_policy_delete_allowed(B(0) | B(1) | SW, 0), "another auth finger remains -> allowed");
    CHECK(fp_policy_delete_allowed(B(0) | SW, FP_SWITCH_SLOT), "deleting the switch finger itself is always allowed");
    CHECK(fp_policy_delete_allowed(SW, FP_SWITCH_SLOT), "only switch finger left, delete it -> allowed");
    CHECK(fp_policy_delete_allowed(B(0) | B(1), 1), "two auth fingers, no switch -> allowed");
}

static void test_enroll_switch_without_auth_refused(void)
{
    CHECK(!fp_policy_enroll_allowed(0, FP_SWITCH_SLOT), "empty device: switch finger first -> refuse");
    CHECK(!fp_policy_enroll_allowed(SW, FP_SWITCH_SLOT), "no auth finger (only switch): refuse");
}

static void test_enroll_allowed_cases(void)
{
    CHECK(fp_policy_enroll_allowed(B(0), FP_SWITCH_SLOT), "one auth finger exists -> switch finger allowed");
    CHECK(fp_policy_enroll_allowed(0, 0), "empty device: auth finger 0 allowed");
    CHECK(fp_policy_enroll_allowed(B(0), 1), "second auth finger allowed");
    CHECK(fp_policy_enroll_allowed(SW, 0), "only switch finger present: enrolling an auth finger allowed");
}

/* 复审补充：三处管理命令的门要看「有没有认证指纹」，不是「位图非零」。
 * 只剩切换指纹的设备（1.8.2 升上来的）否则永远过不了门。 */
static void test_gate_required_only_with_auth_finger(void)
{
    CHECK(!fp_policy_gate_required(0), "empty device: no gate");
    CHECK(!fp_policy_gate_required(SW), "only switch finger: no gate (it can never pass one)");
    CHECK(fp_policy_gate_required(B(0)), "one auth finger: gate");
    CHECK(fp_policy_gate_required(B(2) | SW), "auth + switch: gate");
}

int main(void)
{
    RUN(test_gate_required_only_with_auth_finger);
    RUN(test_auth_bits_exclude_switch);
    RUN(test_delete_last_auth_with_switch_refused);
    RUN(test_delete_allowed_cases);
    RUN(test_enroll_switch_without_auth_refused);
    RUN(test_enroll_allowed_cases);
    TEST_MAIN_END;
}
