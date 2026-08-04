/*
 * immurok 双主机槽位存储。
 *
 * 三个独立的 256B DataFlash 页，动机各不相同，不得合并：
 *   0x6100 槽标记   — 每次切换都写，append-only 摊薄擦除
 *   0x6200 槽 2 密钥 — 极低频；独立成页是为了让配对操作永不重写 block 0
 *                      里的 32 条 SSH 私钥（爆炸半径，不是磨损）
 *   0x6300 PIN 状态  — 独立成页，使失败的登记尝试不可能损坏槽 2 密钥
 *
 * 槽 1 的 shared_key 不在这里 —— 它留在 storage_v3_t 原地，已出货设备零迁移。
 */
#ifndef IMMUROK_SLOTS_H
#define IMMUROK_SLOTS_H

#include <stdint.h>
#include <stdbool.h>

#define IMMUROK_SLOT_1  1
#define IMMUROK_SLOT_2  2

/* 当前活跃槽。空白/损坏页一律返回 IMMUROK_SLOT_1（= 出厂 MAC，
 * 与出货固件行为一致）。 */
uint8_t immurok_slots_active(void);

/* 追加一条活跃槽标记。写满自动擦页重来。返回 0 / -1。 */
int immurok_slots_set_active(uint8_t slot);

/* 槽 2 密钥（0x6200）。槽 1 不经过这里 —— 它在 storage_v3_t 原地。 */
bool immurok_slots_slot2_occupied(void);
int  immurok_slots_slot2_get_key(uint8_t out_key[32]);
int  immurok_slots_slot2_set_key(const uint8_t key[32]);
int  immurok_slots_slot2_clear(void);

/* 返回指向槽 2 密钥的指针（位于 work_buf 的 SLOTS 分区）。
 * 生命期：**仅到下一次 immurok_slots_* 调用为止** —— 用完即弃，
 * 不要存起来。槽 2 未配对或校验失败返回 NULL。
 * 存在的意义是让调用方不必再养一份 32 字节的 RAM 副本。 */
const uint8_t *immurok_slots_slot2_key_ptr(void);

#endif /* IMMUROK_SLOTS_H */
