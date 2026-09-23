/*
 * SHA-256 池式 DRBG，给 uECC 当随机源。
 *
 * 2026-09-19 审计 H4：uECC 的唯一熵源曾是闭源库的 tmos_rand()，种子回调
 * SYS_GetSysTickCnt 在同一函数几十条指令前才启动 SysTick，开机几乎相同。
 * ECDH 临时私钥、SSH 私钥生成、ECDSA 的 k 全靠它。签名的 k 已改为确定性
 * （immurok_ecdsa.h）；密钥生成走这里。
 *
 * 结构：
 *   pool[32]  = SHA256(0x00 || pool || 输入)           —— immurok_rng_add
 *   块 i      = SHA256(0x01 || pool || ctr++)           —— immurok_rng_fill
 *   fill 结束  pool = SHA256(0x02 || pool)              —— 棘轮，事后拿到池也
 *                                                        推不出已发出的块
 * 输出完全由池决定（可复现，见 test/test_rng.c）；熵全部来自 add 进来的
 * 东西。硬件侧的采集在 immurok_entropy.c（tmos_rand、LSE/HSE 时钟抖动、
 * 内部温度 ADC 噪声、RTC/SysTick、MAC），每次生成密钥前重新采一轮。
 *
 * 没播种就 fill 返回 0：uECC 会让 make_key 失败（配对 / KEY_GENERATE 报错），
 * 而不是悄悄用零当私钥。
 *
 * RAM：pool 32B + ctr 4B + 标志 1B。SHA-256 上下文用 sha256.h 的共享实例
 * （fill 只在 uECC 内部作为叶函数被调，不会与 hmac_sha256 交错）。
 */
#ifndef IMMUROK_RNG_H
#define IMMUROK_RNG_H

#include <stdint.h>

/* 把任意字节混进池。可反复调用；每次都让后续输出改变。 */
void immurok_rng_add(const uint8_t *data, unsigned len);

/* uECC_RNG_Function 签名：填满 dest[size]，返回 1；未播种返回 0 且不动 dest。 */
int immurok_rng_fill(uint8_t *dest, unsigned size);

#ifdef IMMUROK_HOST_TEST
/* 仅测试：清池、清计数、回到未播种态。固件里不存在这个函数。 */
void immurok_rng_reset_for_test(void);
#endif

#endif /* IMMUROK_RNG_H */
