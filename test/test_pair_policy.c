/*
 * M2（2026-09-19 审计）：PAIR_INIT 的落盘目标曾是 `slot2_enroll ? 活动槽 : 槽 1`。
 * 活动槽 2 已配对时 slot2_enroll 为假，新密钥写进槽 1，把主机 1 的密钥毁掉
 * （主机 2 自己也对不上）。发 PAIR_INIT 的主机一定是通过活动槽的地址连进来的，
 * 密钥就该落在活动槽。
 *
 * 这张表是审计时逐场景推演的 8 种状态（活动槽 S、槽 1/槽 2 是否配对）：
 * 5 种两版行为相同，3 种旧版写错槽。这里把「目标槽恒等于活动槽」和另外两条
 * 准入规则（第二主机登记判定、NEEDS_RESET）一起锁住。
 */
#include "pair_policy.h"
#include "test_main.h"

typedef struct {
    uint8_t active;
    bool p1, p2;
    bool expect_second_host;
    const char *what;
} row_t;

static const row_t ROWS[] = {
    { 1, false, false, false, "全新设备首次配对" },
    { 1, true,  false, false, "主机 1 重配对" },
    { 1, false, true,  true,  "槽 1 空、槽 2 有货：新主机登记到槽 1" },
    { 1, true,  true,  false, "主机 1 重配对，两槽都满" },
    { 2, true,  false, true,  "登记第二台主机（含双系统装第二个系统）" },
    { 2, true,  true,  false, "M2：主机 2 重配对" },
    { 2, false, true,  false, "主机 1 已解绑，主机 2 独占时重配对" },
    { 2, false, false, false, "停在空槽 2，两槽都空" },
};
#define NROWS (sizeof ROWS / sizeof ROWS[0])

static void test_target_is_always_active_slot(void)
{
    for (unsigned i = 0; i < NROWS; i++) {
        const row_t *r = &ROWS[i];
        bool active_paired = (r->active == 1) ? r->p1 : r->p2;
        bool any_paired = r->p1 || r->p2;
        pair_decision_t d = pair_policy_decide(r->active, active_paired, any_paired, false);
        CHECK(d.target_slot == r->active, r->what);
    }
}

static void test_second_host_enroll_detection(void)
{
    for (unsigned i = 0; i < NROWS; i++) {
        const row_t *r = &ROWS[i];
        bool active_paired = (r->active == 1) ? r->p1 : r->p2;
        bool any_paired = r->p1 || r->p2;
        pair_decision_t d = pair_policy_decide(r->active, active_paired, any_paired, false);
        CHECK(d.second_host == r->expect_second_host, r->what);
    }
}

static void test_needs_reset_rule(void)
{
    /* 有指纹且不是第二主机登记 → 必须先出厂重置 */
    pair_decision_t d = pair_policy_decide(2, true, true, true);
    CHECK(d.needs_reset, "M2 场景且有指纹：拒 NEEDS_RESET");
    d = pair_policy_decide(1, true, false, true);
    CHECK(d.needs_reset, "主机 1 重配对且有指纹：拒");
    /* 第二主机登记的例外：指纹 + 按键两道门代替出厂重置 */
    d = pair_policy_decide(2, false, true, true);
    CHECK(!d.needs_reset, "第二主机登记，有指纹也放行");
    CHECK(d.target_slot == 2, "…且写进槽 2");
    /* 没指纹永远不拒 */
    d = pair_policy_decide(2, true, true, false);
    CHECK(!d.needs_reset, "无指纹不拒");
}

int main(void)
{
    RUN(test_target_is_always_active_slot);
    RUN(test_second_host_enroll_detection);
    RUN(test_needs_reset_rule);
    TEST_MAIN_END;
}
