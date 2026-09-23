/*
 * 硬件熵采集。设计说明见 immurok_entropy.h。固件专用，不进主机测试。
 */
#include "CONFIG.h"
#include "HAL.h"
#include "immurok_entropy.h"
#include "immurok_rng.h"
#include <string.h>

#define JITTER_SAMPLES   32
#define TS_SAMPLES       16
#define JITTER_SPIN_MAX  4000   /* 60 MHz 下远大于一个 32k 周期（30.5 µs） */

void immurok_entropy_reseed(void)
{
    uint8_t  buf[32];
    uint32_t w[3];
    unsigned i;

    /* 1. 设备身份（个性化） */
    GetMACAddress(buf);
    immurok_rng_add(buf, 6);

    /* 2. 协议栈 PRNG */
    for (i = 0; i < 8; i++) {
        uint32_t r = tmos_rand();
        memcpy(&buf[i * 4], &r, 4);
    }
    immurok_rng_add(buf, 32);

    /* 3. 时刻 */
    w[0] = RTC_GetCycle32k();
    w[1] = SYS_GetSysTickCnt();
    w[2] = TMOS_GetSystemClock();
    immurok_rng_add((const uint8_t *)w, sizeof w);

    /* 4. LSE / HSE 相位抖动：每个 32k 边沿采一次 SysTick 低 8 位 */
    for (i = 0; i < JITTER_SAMPLES; i++) {
        uint32_t c = RTC_GetCycle32k();
        unsigned spin = 0;
        while (RTC_GetCycle32k() == c && ++spin < JITTER_SPIN_MAX) { }
        buf[i] = (uint8_t)SYS_GetSysTickCnt();
    }
    immurok_rng_add(buf, JITTER_SAMPLES);

    /* 5. 内部温度传感器 ADC 量化噪声 */
    for (i = 0; i < TS_SAMPLES; i++) {
        uint16_t v = HAL_GetInterTempValue();
        buf[2 * i]     = (uint8_t)v;
        buf[2 * i + 1] = (uint8_t)(v >> 8);
    }
    immurok_rng_add(buf, TS_SAMPLES * 2);

    memset(buf, 0, sizeof buf);
    memset(w, 0, sizeof w);
}
