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
#include "version.h"
#include "fingerprint.h"
#include "immurok_ble_init.h"
#include "immurok_slots.h"
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

// GPIO interrupt flags (defined in hidkbd.c, set in BTN_TOUCH_IRQHandler;
// also declared in hidkbd.h which main.c includes — listed here for clarity)
extern volatile uint8_t g_touch_irq_flag;
extern volatile uint8_t g_btn_irq_flag;
#if HAS_TAMPER_DETECT
extern volatile uint8_t g_tamper_irq_flag;
#endif
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
 * Runs from Flash (.text), NOT __HIGH_CODE. The flash-power-down/wake handling
 * lives inside the BLE lib's LowPower_Sleep (RAM-resident); its caller
 * CH59x_LowPower (SLEEP.c) is itself plain .text and already executes from
 * Flash immediately after wake — proof that Flash is ready before control
 * returns up to this loop. Keeping the loop in Flash frees ~96B of RAM
 * (.highcode) needed by the VER6 tamper feature; the only cost is a few flash
 * wait-states per loop iteration (negligible vs BLE/radio timing).
 *
 * @return  none
 */
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
#if HAS_TAMPER_DETECT
        if(g_tamper_irq_flag)
        {
            g_tamper_irq_flag = 0;
            tamper_run_cleanup();   // never returns (halts blinking red)
        }
#endif

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
#if HAS_VBAT_ADC
    // Pull-down on VBAT divider pin: floating leaves PA14 at ~VCC/2 (near GPIO
    // threshold) causing constant RB_SLP_GPIO_WAKE false wakeups from noise.
    // Pull-down stabilizes at ~0.2V; adds ~1.5uA vs floating but saves ~55uA
    // from eliminated spurious wakeups. ADC settles in <10us after switching
    // to floating in battSetupCB.
    GPIOA_ModeCfg(PIN_VBAT, GPIO_ModeIN_PD);
#endif
#ifdef PIN_ANTI_OPEN
#if HAS_TAMPER_DETECT
    // VER6: ANTI_OPEN is driven by a high-impedance external divider (open≈3V via
    // Q2→R16; closed 0V). FLOAT the pin (undo the blanket GPIOB IN_PU above) so the
    // divider sets the level — IN_PD would collapse the high-Z "open" to ~0.2V and
    // detection would never fire.
    GPIOB_ModeCfg(PIN_ANTI_OPEN, GPIO_ModeIN_Floating);
#else
    // VER5: tamper switch shorts PB10 to GND when closed; the blanket GPIOB IN_PU
    // above would leak ~73µA through the closed switch. Force pull-down so the pin
    // and PD sit at the same potential — no leakage.
    GPIOB_ModeCfg(PIN_ANTI_OPEN, GPIO_ModeIN_PD);
#endif
#endif
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

#if HAS_RGB_LED
    LED_RGB_Init();
    LED_BLUE_On();
    DelayMs(200);   // Blue flash once = system startup（原为红，红留给错误态，
                    // 避免切槽重启时的开机红闪被误当成故障）
    LED_BLUE_Off();
#endif

    // Initialize fingerprint module
    extern uint16_t g_cached_fp_bitmap;
    int fp_ret = fp_init();
    if(fp_ret == FP_OK) {
        PRINT("Fingerprint module OK\n");
        // Cache bitmap before power off (used by GET_STATUS without blocking)
        fp_get_fingerprint_bitmap(&g_cached_fp_bitmap);
        // Single-slot: no orphan cleanup needed (PSAutoEnroll is atomic)
        // Power off after init - will be powered on when needed (touch detected)
        fp_power_off();
        PRINT("Fingerprint power management enabled\n");
    } else {
        // Module returned unexpected info (missing / not responding / bad ack).
        // Blink the red LED rapidly to signal startup failure.
        PRINT("Fingerprint init failed: %d\n", fp_ret);
#if HAS_RGB_LED
        for (int i = 0; i < 6; i++) {
            LED_RED_On();
            DelayMs(120);
            LED_RED_Off();
            DelayMs(120);
            WWDG_SetCounter(0);  // Feed watchdog during blocking blink
        }
#endif
        fp_power_off();
    }

    // Touch INT input (active high). Idle default is IN_PD for all HW revs —
    // fp_power_on() toggles to Floating for R599S during active sensor use.
    TOUCH_SetMode(GPIO_ModeIN_PD);
    PRINT("%s [fw:" FW_VERSION_STRING ".%04X build:%s %s]\n", VER_LIB, FW_BUILD_NUMBER, __DATE__, __TIME__);
    // 双主机：每个槽用不同的 BLE 地址，两台主机各自维护独立 bond。
    // 空白标记页 = 槽 1 = 出厂 MAC，与出货固件行为一致。
    {
        uint8_t slot_mac[6];
        immurok_ble_slot_mac(immurok_slots_active(), slot_mac);
        immurok_BLEInit(slot_mac);
    }
    HAL_Init();
    GAPRole_PeripheralInit();
    HidDev_Init();
    HidEmu_Init();  // LED task registered here → blue blink starts
#ifdef DEBUG
    // BLE library gates UART3 clock during init — restore it for debug output
    sys_safe_access_enable();
    R8_SLP_CLK_OFF0 &= ~RB_SLP_CLK_UART3;
    sys_safe_access_disable();
#endif

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
