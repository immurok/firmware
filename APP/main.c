/********************************** (C) COPYRIGHT *******************************
 * File Name          : main.c
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2020/08/06
 * Description        :
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

/******************************************************************************/
#include "CONFIG.h"
#include "HAL.h"
#include <stdarg.h>
#include "hiddev.h"
#include "hidkbd.h"
#include "fingerprint.h"
#include "hardware_pins.h"
#include "ws2812.h"

#ifdef DEBUG
// Lightweight printf replacement — minimal stack usage (~32 bytes vs ~128 for vsnprintf).
// Handles: %d %u %x %X %02X %04X %08X %s %c %% %p and width/zero-pad for integers.
// Stack-critical: called from deep BLE stack callbacks with only 512B total stack.

static void _put(const char *s, int len)
{
    extern int _write(int, char *, int);
    _write(1, (char *)s, len);
}

static void _putc(char c) { _put(&c, 1); }

static void _puts(const char *s)
{
    const char *p = s;
    while(*p) p++;
    _put(s, p - s);
}

static void _putnum(unsigned long v, int base, int width, int zero, int upper)
{
    char tmp[12];  // max 10 digits for 32-bit + sign + null
    int i = 0;
    if(v == 0) { tmp[i++] = '0'; }
    else {
        while(v) {
            int d = v % base;
            tmp[i++] = d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10;
            v /= base;
        }
    }
    while(i < width) tmp[i++] = zero ? '0' : ' ';
    // reverse
    for(int j = i - 1; j >= 0; j--) _putc(tmp[j]);
}

int dbg_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = 0;

    while(*fmt)
    {
        if(*fmt != '%') { _putc(*fmt++); n++; continue; }
        fmt++;  // skip '%'

        // Parse flags and width
        int zero = 0, width = 0;
        if(*fmt == '0') { zero = 1; fmt++; }
        while(*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
        // Skip 'l' modifier
        if(*fmt == 'l') fmt++;

        switch(*fmt)
        {
        case 'd': {
            int v = va_arg(ap, int);
            if(v < 0) { _putc('-'); n++; v = -v; }
            _putnum((unsigned long)v, 10, width, zero, 0);
            break;
        }
        case 'u':
            _putnum(va_arg(ap, unsigned int), 10, width, zero, 0);
            break;
        case 'x':
            _putnum(va_arg(ap, unsigned int), 16, width, zero, 0);
            break;
        case 'X':
            _putnum(va_arg(ap, unsigned int), 16, width, zero, 1);
            break;
        case 'p':
            _puts("0x");
            _putnum(va_arg(ap, unsigned int), 16, 8, 1, 0);
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            _puts(s ? s : "(null)");
            break;
        }
        case 'c':
            _putc((char)va_arg(ap, int));
            break;
        case '%':
            _putc('%');
            break;
        case '\0':
            goto done;
        default:
            _putc('%'); _putc(*fmt);
            break;
        }
        fmt++;
        n++;
    }
done:
    va_end(ap);
    return n;
}
#endif

// GPIO interrupt flags (defined in hidkbd.c, set in BTN_TOUCH_IRQHandler)
extern volatile uint8_t g_touch_irq_flag;
extern volatile uint8_t g_btn_irq_flag;
// hidEmu task ID (needed to fire events from main loop)
extern uint8_t hidEmuTaskId;

/*********************************************************************
 * GLOBAL TYPEDEFS
 */
__attribute__((aligned(4))) uint32_t MEM_BUF[BLE_MEMHEAP_SIZE / 4];

#if(defined(BLE_MAC)) && (BLE_MAC == TRUE)
const uint8_t MacAddr[6] = {0x84, 0xC2, 0xE4, 0x03, 0x02, 0x02};
#endif

/*********************************************************************
 * @fn      Main_Circulation
 *
 * @brief   Main loop
 *
 * @return  none
 */
__HIGH_CODE
__attribute__((noinline))
void Main_Circulation()
{
    while(1)
    {
        TMOS_SystemProcess();

        // Check GPIO interrupt flags and fire TMOS events immediately.
        // Safe to call tmos_set_event here (main context, not ISR).
        if(g_touch_irq_flag)
        {
            g_touch_irq_flag = 0;
            tmos_set_event(hidEmuTaskId, TOUCH_SCAN_EVT);
        }
        if(g_btn_irq_flag)
        {
            g_btn_irq_flag = 0;
            tmos_set_event(hidEmuTaskId, BUTTON_SCAN_EVT);
        }

        WWDG_SetCounter(0);  // 喂狗：计数器清零
    }
}

/*********************************************************************
 * @fn      main
 *
 * @brief   Main function
 *
 * @return  none
 */
int main(void)
{
#if(defined(DCDC_ENABLE)) && (DCDC_ENABLE == TRUE)
    PWR_DCDCCfg(ENABLE);
#endif
    SetSysClock(CLK_SOURCE_PLL_60MHz);
#if(defined(HAL_SLEEP)) && (HAL_SLEEP == TRUE)
    GPIOA_ModeCfg(GPIO_Pin_All, GPIO_ModeIN_PU);
    GPIOB_ModeCfg(GPIO_Pin_All, GPIO_ModeIN_PU);
#endif
#ifdef DEBUG
    // UART3: PA5 TX, PA4 RX, 115200 baud (debug output)
    GPIOA_SetBits(GPIO_Pin_5);
    GPIOA_ModeCfg(GPIO_Pin_5, GPIO_ModeOut_PP_5mA);  // TX
    R32_PA_PU &= ~GPIO_Pin_5;  // Clear pull-up on TX (left over from sleep all-pin-pullup)
    GPIOA_ModeCfg(GPIO_Pin_4, GPIO_ModeIN_PU);       // RX
    UART3_DefInit();

#endif

#if HAS_WS2812
    ws2812_init();
#endif

    // Initialize fingerprint module
    extern uint8_t g_cached_fp_bitmap;
    int fp_ret = fp_init();
    if(fp_ret == FP_OK) {
        PRINT("Fingerprint module OK\n");
        // Cache bitmap before power off (used by GET_STATUS without blocking)
        fp_get_fingerprint_bitmap(&g_cached_fp_bitmap);
        // Power off after init - will be powered on when needed (touch detected)
        fp_power_off();
        PRINT("Fingerprint power management enabled\n");
    } else {
        PRINT("Fingerprint init failed: %d\n", fp_ret);
    }

    // Touch INT input (active high) - for button scan
    TOUCH_SetMode(GPIO_ModeIN_PD);
    PRINT("%s\n", VER_LIB);
    CH59x_BLEInit();
    HAL_Init();
    GAPRole_PeripheralInit();
    HidDev_Init();
    HidEmu_Init();

    // 打印上次复位原因
    PRINT("Reset status: 0x%02X\n", R8_RESET_STATUS & 0x07);

    // 看门狗：初始化并启用
    WWDG_SetCounter(0);
    WWDG_ClearFlag();
    WWDG_ResetCfg(ENABLE);
    PRINT("Watchdog enabled\n");

    Main_Circulation();
}

/******************************** endfile @ main ******************************/
