/*
 * PAIR_INIT 的准入判定（纯函数，主机可测：test/test_pair_policy.c）。
 *
 * 三条规则：
 *   second_host  = 活动槽空 && 别的槽有货 —— 本机是第二台主机，走「指纹 + 按键」
 *                  两道门代替出厂重置（2026-08-03 起）
 *   needs_reset  = 有指纹 && !second_host —— 防前任的模板带进新会话
 *   target_slot  = 活动槽，恒等式
 *
 * 2026-09-19 审计 M2：target 曾是 `second_host ? 活动槽 : 槽 1`。活动槽 2
 * 已配对时 second_host 为假，主机 2 重配对的新密钥写进槽 1，把主机 1 的密钥
 * 毁掉，主机 2 自己也对不上（它存的是新密钥，设备用槽 2 的旧密钥）。发
 * PAIR_INIT 的主机一定是通过活动槽的 BLE 地址连进来的，密钥就该落在活动槽。
 * 逐场景推演见测试文件里的 8 行表：5 种不变，3 种从错变对，没有变差的。
 */
#ifndef PAIR_POLICY_H
#define PAIR_POLICY_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool    second_host;   /* 第二主机登记：PAIR_INIT 先要指纹再要按键 */
    bool    needs_reset;   /* 拒绝，回 SEC_ERR_NEEDS_RESET */
    uint8_t target_slot;   /* pair_save() 把新密钥写进哪个槽 */
} pair_decision_t;

static inline pair_decision_t pair_policy_decide(uint8_t active_slot,
                                                 bool active_paired,
                                                 bool any_paired,
                                                 bool has_fingerprints)
{
    pair_decision_t d;
    d.second_host = !active_paired && any_paired;
    d.needs_reset = has_fingerprints && !d.second_host;
    d.target_slot = active_slot;
    return d;
}

#endif /* PAIR_POLICY_H */
