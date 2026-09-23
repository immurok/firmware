/*
 * immurok 按槽分区的 BLE bond 存储（SNV）。
 *
 * 背景（2026-09-18）：WCH 协议栈的 bond 记录只以对端地址为键，两个槽
 * 原来共用一个 SNV 区。同一台电脑双启动（Windows / Linux 共用一块蓝牙
 * 适配器、同一个公有地址）分别登记到槽 1 / 槽 2 时，第二次配对会把第一
 * 次的 LTK 顶掉，而被顶掉的那个槽又是 NO_PAIRING，用户只能 SLOT_CLEAR。
 *
 * 修法：每个槽一块独立的 SNV 区。协议栈把 SNV 起始地址当运行时参数
 * （bleConfig_t.SNVAddr），开机按活动槽选区即可 —— 库在任何时刻只看得到
 * 本槽的区，同地址的两条记录物理上不在一起，永远撞不上。切换槽本来就
 * 会复位，所以每次开机选一次就够。
 *
 * 布局（DataFlash block 7 = 0x7000-0x7FFF，此前只有 SNV 一个住户）：
 *   槽 1：BLE_SNV_ADDR（0x7000-0x71FF，= 出货固件的位置，升级后槽 1 不搬家）
 *   槽 2：BLE_SNV_ADDR + AREA_SIZE（0x7200-0x73FF）
 * BLE_SNV_ADDR 来自 SDK/EVT/EXAM/BLE/HAL/include/CONFIG.h（0x77000 -
 * FLASH_ROM_MAX_SIZE）。SDK 里另一份示例 CONFIG.h 写 0x77E00，不是我们的。
 *
 * 只对 CH592F 的页级擦写路径成立：SDK 的 Lib_Write_Flash 对芯片 ID 为 9
 * （DEF_CHIP_ID_CH592A）走整块 4KB 读改写，会把同一 block 里另一槽的区
 * 抹掉。启动日志打印 chip id，真机上必须确认不是 9。
 *
 * 随之而来的两条义务，漏一条就是漏洞或死状态：
 *   1. 协议栈的 ERASE_ALLBONDS 只擦它挂载的那个区。出厂重置 / 长按重置 /
 *      防拆擦除之后必须 immurok_snv_erase_all() 把另一个槽的 LTK 也清掉。
 *   2. 老设备两个槽的 bond 都在槽 1 的区里。首次开机 immurok_snv_migrate()
 *      把槽 1 的区整体复制到槽 2 的区，槽 2 的主机才不用重新登记。
 */
#ifndef IMMUROK_SNV_H
#define IMMUROK_SNV_H

#include <stdint.h>
#include <stdbool.h>

/* 一个槽的区大小 = BLE_SNV_BLOCK * BLE_SNV_NUM（当前 256 * 2 = 512B）。 */
uint32_t immurok_snv_area_size(void);

/* 槽的 SNV 区起始地址（DataFlash 偏移）。非法槽按槽 1 处理。 */
uint32_t immurok_snv_area_addr(uint8_t slot);

/* 裸擦一个槽的区 / 两个槽的区。只擦 SNV，不碰 block 6 的任何页。 */
void immurok_snv_erase_slot(uint8_t slot);
void immurok_snv_erase_all(void);

/* 区是否全 0xFF（= 协议栈眼里没有任何 bond）。 */
bool immurok_snv_is_blank(uint8_t slot);

/* 升级迁移。条件全部成立才动手：槽 2 已 app 配对、槽 2 的区空白、
 * 槽 1 的区非空白 —— 即「槽 2 的 bond 还在老的共用区里」。把槽 1 的区
 * 整体复制到槽 2 的区。多带过去的槽 1 主机记录无害：已配对槽拒绝新
 * bond，槽被清时整区一起擦。
 *
 * buf 至少 immurok_snv_area_size() 字节（调用方借 work_buf）。
 * 返回 1 = 复制了，0 = 无事可做，-1 = buf 不够。
 * 必须在 BLE 库初始化**之前**调用。 */
int immurok_snv_migrate(bool slot2_paired, uint8_t *buf, uint32_t buf_len);

#endif /* IMMUROK_SNV_H */
