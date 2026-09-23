/*
 * 硬件熵采集：把板上能拿到的随机性混进 immurok_rng 的池。
 *
 * 2026-09-19 审计 H4。CH592F 没有硬件 TRNG，能用的源：
 *   - tmos_rand()：协议栈 PRNG（原来唯一的源，保留当一路输入）
 *   - LSE（32.768 kHz 晶振）与 HSE（32 MHz 晶振 → PLL → SysTick）两个独立
 *     振荡器的相位抖动：每个 32k 计数边沿采一次 SysTick 低 8 位
 *   - 内部温度传感器 ADC 采样的量化噪声（HAL_GetInterTempValue 自带寄存器
 *     保存/恢复，不影响电池测量的 ADC 配置与电源状态）
 *   - RTC 32k 计数、SysTick、TMOS 时钟：命令到达的时刻由人决定
 *   - 出厂 MAC：不是秘密，只做个性化，让两台设备在其余源都退化时也不同池
 *
 * 每次生成密钥（ECDH 配对、KEY_GENERATE）之前调一次，开机再调一次。
 * 耗时约 1-2 ms，在 TMOS 事件上下文里、ECC 计算之前跑，不需要喂狗。
 * 32k 停振（1.3.11 那类故障）时抖动采样有界退出，不会卡死。
 */
#ifndef IMMUROK_ENTROPY_H
#define IMMUROK_ENTROPY_H

void immurok_entropy_reseed(void);

#endif /* IMMUROK_ENTROPY_H */
