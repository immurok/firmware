/*
 * immurok 槽元数据页(0x6300)。
 *
 * 复用随 PIN 方案废弃的 0x6300 页,存双主机每槽的:
 *   - address generation(解绑时 +1,驱动 static random 地址轮换)
 *   - 对端(主机)蓝牙地址(解绑时精确 ERASE_SINGLEBOND 回收 SNV 用)
 *
 * 独立成页,与 0x6200 同理:配对/解绑操作永不重写 block 0 的 SSH 私钥。
 */
#ifndef IMMUROK_SLOT_META_H
#define IMMUROK_SLOT_META_H

#include <stdint.h>

#ifndef IMMUROK_SLOT_1
#define IMMUROK_SLOT_1  1
#define IMMUROK_SLOT_2  2
#endif

/* generation:空白/损坏/非法槽 → 0(= 现有地址,升级兼容)。 */
uint8_t slot_meta_gen(uint8_t slot);
int     slot_meta_bump_gen(uint8_t slot);

/* 擦 0x6300：两槽 gen 回 0、peer 全清（factory reset 用，让地址回出厂 MAC）。 */
void    slot_meta_reset(void);

void slot_mac_derive(const uint8_t factory_mac[6], uint8_t slot,
                     uint8_t gen, uint8_t out[6]);

int slot_meta_set_peer(uint8_t slot, uint8_t addr_type, const uint8_t addr[6]);
int slot_meta_get_peer(uint8_t slot, uint8_t *addr_type, uint8_t addr[6]);

#endif /* IMMUROK_SLOT_META_H */
