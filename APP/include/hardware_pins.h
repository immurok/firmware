/*
 * Hardware Pin Definitions for immurok
 *
 * VER0: Original prototype (BTN/Touch/FP_PWR on GPIOA)
 * VER1: Rev.1 board (BTN/Touch/FP_PWR on GPIOB, adds WS2812)
 *
 * Select via Makefile: make VER=0 (default) or make VER=1
 */

#ifndef HARDWARE_PINS_H
#define HARDWARE_PINS_H

// ============================================================================
// Common pins (same for all versions)
// ============================================================================

// Debug UART3
#define PIN_DBG_TX          GPIO_Pin_5      // PA5
#define PIN_DBG_RX          GPIO_Pin_4      // PA4

// Fingerprint UART1 (always GPIOA)
#define PIN_FP_TX           GPIO_Pin_9      // PA9
#define PIN_FP_RX           GPIO_Pin_8      // PA8

// ============================================================================
// Version-specific pins
// ============================================================================

#if defined(HARDWARE_VER1)

// --- VER1 Pin Assignments ---
#define PIN_FP_PWR          GPIO_Pin_7      // PB7  - Fingerprint power (active high)
#define PIN_TOUCH           GPIO_Pin_10     // PB10 - Touch INT (active high)
#define PIN_BTN             GPIO_Pin_4      // PB4  - Button (active low)
#define PIN_WS2812          GPIO_Pin_13     // PB13 - WS2812 DI (power shared with FP)
#define PIN_VBAT            GPIO_Pin_14     // PA14 - Battery voltage (1/2 divider) → AIN4
#define VBAT_ADC_CH         CH_EXTIN_4      // ADC channel 4
#define HAS_VBAT_ADC        1
#define HAS_WS2812          0  // TODO: enable after sleep issue resolved

// FP power (GPIOB)
#define FP_PWR_SetHigh()            GPIOB_SetBits(PIN_FP_PWR)
#define FP_PWR_SetLow()             GPIOB_ResetBits(PIN_FP_PWR)
#define FP_PWR_SetMode(m)           GPIOB_ModeCfg(PIN_FP_PWR, m)

// Touch INT (GPIOB)
#define TOUCH_SetMode(m)            GPIOB_ModeCfg(PIN_TOUCH, m)
#define TOUCH_SetITMode(m)          GPIOB_ITModeCfg(PIN_TOUCH, m)
#define TOUCH_ReadPin()             (GPIOB_ReadPortPin(PIN_TOUCH) & PIN_TOUCH)
#define TOUCH_ReadITFlag()          GPIOB_ReadITFlagBit(PIN_TOUCH)
#define TOUCH_ClearITFlag()         GPIOB_ClearITFlagBit(PIN_TOUCH)

// Button (GPIOB)
#define BTN_SetMode(m)              GPIOB_ModeCfg(PIN_BTN, m)
#define BTN_SetITMode(m)            GPIOB_ITModeCfg(PIN_BTN, m)
#define BTN_ReadPin()               (GPIOB_ReadPortPin(PIN_BTN) & PIN_BTN)
#define BTN_ReadITFlag()            GPIOB_ReadITFlagBit(PIN_BTN)
#define BTN_ClearITFlag()           GPIOB_ClearITFlagBit(PIN_BTN)

// WS2812 (GPIOB)
#define WS2812_SetHigh()            GPIOB_SetBits(PIN_WS2812)
#define WS2812_SetLow()             GPIOB_ResetBits(PIN_WS2812)
#define WS2812_SetMode(m)           GPIOB_ModeCfg(PIN_WS2812, m)

// GPIO IRQ
#define BTN_TOUCH_IRQn              GPIO_B_IRQn
#define BTN_TOUCH_IRQHandler        GPIOB_IRQHandler

#else // HARDWARE_VER0 (default)

// --- VER0 Pin Assignments ---
#define PIN_FP_PWR          GPIO_Pin_12     // PA12 - Fingerprint power (active high)
#define PIN_TOUCH           GPIO_Pin_13     // PA13 - Touch INT (active high)
#define PIN_BTN             GPIO_Pin_14     // PA14 - Button (active low)
#define HAS_WS2812          0

// FP power (GPIOA)
#define FP_PWR_SetHigh()            GPIOA_SetBits(PIN_FP_PWR)
#define FP_PWR_SetLow()             GPIOA_ResetBits(PIN_FP_PWR)
#define FP_PWR_SetMode(m)           GPIOA_ModeCfg(PIN_FP_PWR, m)

// Touch INT (GPIOA)
#define TOUCH_SetMode(m)            GPIOA_ModeCfg(PIN_TOUCH, m)
#define TOUCH_SetITMode(m)          GPIOA_ITModeCfg(PIN_TOUCH, m)
#define TOUCH_ReadPin()             (GPIOA_ReadPortPin(PIN_TOUCH) & PIN_TOUCH)
#define TOUCH_ReadITFlag()          GPIOA_ReadITFlagBit(PIN_TOUCH)
#define TOUCH_ClearITFlag()         GPIOA_ClearITFlagBit(PIN_TOUCH)

// Button (GPIOA)
#define BTN_SetMode(m)              GPIOA_ModeCfg(PIN_BTN, m)
#define BTN_SetITMode(m)            GPIOA_ITModeCfg(PIN_BTN, m)
#define BTN_ReadPin()               (GPIOA_ReadPortPin(PIN_BTN) & PIN_BTN)
#define BTN_ReadITFlag()            GPIOA_ReadITFlagBit(PIN_BTN)
#define BTN_ClearITFlag()           GPIOA_ClearITFlagBit(PIN_BTN)

// GPIO IRQ
#define BTN_TOUCH_IRQn              GPIO_A_IRQn
#define BTN_TOUCH_IRQHandler        GPIOA_IRQHandler

#endif // HARDWARE_VER

#endif // HARDWARE_PINS_H
