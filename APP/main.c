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
#include "hiddev.h"
#include "hidkbd.h"
#include "fingerprint.h"

// GPIO interrupt flags (defined in hidkbd.c, set in GPIOA_IRQHandler)
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
    GPIOA_ModeCfg(GPIO_Pin_4, GPIO_ModeIN_PU);       // RX
    UART3_DefInit();

#endif

    // Initialize fingerprint module (PA12=PWR, PA13=INT, UART1: PA9 TX, PA8 RX)
    int fp_ret = fp_init();
    if(fp_ret == FP_OK) {
        PRINT("Fingerprint module OK\n");
        // Power off after init - will be powered on when needed (touch detected)
        fp_power_off();
        PRINT("Fingerprint power management enabled\n");
    } else {
        PRINT("Fingerprint init failed: %d\n", fp_ret);
    }

    // PA13 = touch INT input (active high) - for button scan
    GPIOA_ModeCfg(GPIO_Pin_13, GPIO_ModeIN_PD);
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
