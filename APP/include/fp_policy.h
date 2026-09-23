/*
 * 指纹槽位管理的策略判定（纯函数，主机可测）。
 *
 * 背景（2026-09-19 审计 M4）：切换指纹（page FP_SWITCH_SLOT）计入
 * fp_user_bitmap()，ENROLL_START / DELETE_FP / FACTORY_RESET 按「位图非零」
 * 挂指纹门，而切换指纹匹配永远走切槽复位、绝不进门。用户删掉最后一枚认证
 * 指纹后设备只剩切换指纹：三个管理命令永久 WAIT_FP，触摸只会重启，只能
 * 硬件长按重置。首次登记也曾允许先登记切换指纹，同样落进这个死角。
 *
 * 规则（用户 2026-09-19 选定）：
 *   1. 存在切换指纹时，禁止删除最后一枚认证指纹
 *   2. 不存在认证指纹时，禁止录入切换指纹
 * 两条合起来保证：只要切换指纹在，至少有一枚认证指纹能过门。
 *
 * 判定在命令收到时就做（回 INVALID_PARAM），不让用户为注定失败的操作摸指纹。
 */
#ifndef FP_POLICY_H
#define FP_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include "fingerprint.h"   /* FP_SWITCH_SLOT */

/* 用户位图去掉切换指纹位 = 认证指纹位图 */
static inline uint16_t fp_policy_auth_bits(uint16_t ubm)
{
    return (uint16_t)(ubm & (uint16_t)~(1u << FP_SWITCH_SLOT));
}

static inline bool fp_policy_delete_allowed(uint16_t ubm, uint8_t fid)
{
    if (fid == FP_SWITCH_SLOT)
        return true;                                   /* 切换指纹随时可删 */
    bool has_switch = (ubm >> FP_SWITCH_SLOT) & 1u;
    bool last_auth  = fp_policy_auth_bits(ubm) == (uint16_t)(1u << fid);
    return !(has_switch && last_auth);
}

/* 管理命令（ENROLL_START / DELETE_FP / FACTORY_RESET）要不要挂指纹门：
 * 有认证指纹才挂。切换指纹永远过不了门，只剩它时挂门等于把设备锁死
 * （1.8.2 升上来的设备可能就停在这个状态，规则 1/2 只防新进入）。
 * 没有认证指纹时门本来就不可能通过，跳过它不降低安全性。 */
static inline bool fp_policy_gate_required(uint16_t ubm)
{
    return fp_policy_auth_bits(ubm) != 0;
}

static inline bool fp_policy_enroll_allowed(uint16_t ubm, uint8_t fid)
{
    if (fid != FP_SWITCH_SLOT)
        return true;                                   /* 认证指纹随时可录 */
    return fp_policy_auth_bits(ubm) != 0;              /* 先有认证指纹才能录切换指纹 */
}

#endif /* FP_POLICY_H */
