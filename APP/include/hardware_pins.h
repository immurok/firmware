/*
 * Hardware Pin Definitions for immurok
 *
 * VER0: Original prototype (BTN/Touch/FP_PWR on GPIOA)
 * VER1: Rev.1 board (BTN/Touch/FP_PWR on GPIOB, adds WS2812)
 * VER2: Rev.2 board (BTN on PB12, RGB LED on PB4/PA12/PA13)
 * VER3: Rev.2 board + R599S fingerprint module
 * VER5: Rev.3 board — all RGB on GPIOB, BATT on PA12 (1/4 divider),
 *       anti-tamper switch on PB10, VCC2 sense on PB12
 *
 * Select via Makefile: make VER=0 / VER=1 / VER=2 / VER=3 / VER=5
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

#if defined(HARDWARE_VER5)

// --- VER5 Pin Assignments (Rev.3 board) ---
// All RGB on GPIOB, BATT stays on PA14 but divider is now 1/4 (R2=3M/R3=1M),
// BTN back to PB4, SENSOR_EN moved to PB12.
// PB10 has an anti-tamper switch wired in HW; detection logic is deferred on
// this revision, but the pin must be clamped to IN_PD at boot so the blanket
// GPIOB pull-up doesn't leak 73µA into the closed switch.
// PB11, PA15, PA13, PA12, PA4 all NC.
// PB14/PB15 go to PCB test points (system debug), not GPIO-usable.
#define PIN_FP_PWR          GPIO_Pin_12     // PB12 - SENSOR_EN (active high)
#define PIN_TOUCH           GPIO_Pin_13     // PB13 - DETECT (active high)
#define PIN_BTN             GPIO_Pin_4      // PB4  - Button (active low, HW RC debounce)
#define PIN_ANTI_OPEN       GPIO_Pin_10     // PB10 - Tamper switch (input-only, no IRQ logic yet)
#define PIN_VBAT            GPIO_Pin_14     // PA14 - Battery voltage (1/4 divider: R2=3M/R3=1M) → AIN4
#define VBAT_ADC_CH         CH_EXTIN_4      // ADC channel 4
#define VBAT_DIV_RATIO      4               // 1/4 resistor divider (VER5 only; VER2/3 use 1/2)
// Divider Thevenin = R2∥R3 = 3M∥1M = 750kΩ, C7 = 100nF → RC=75ms.
// 6.7τ → C7 settles to 99.87% of target (vs 99.33% at 5τ); knocks the
// systematic undershoot at the top end from ~28mV to ~5mV.
#define VBAT_SETTLE_MS      500
#define HAS_VBAT_ADC        1
#define HAS_WS2812          0
#define HAS_FP_LED          0
#define HAS_R599S           1               // Rev.3 ships with R599S-compatible module

// RGB LED (active low) — all three on GPIOB
#define PIN_LED_RED         GPIO_Pin_7      // PB7
#define PIN_LED_GREEN       GPIO_Pin_23     // PB23 (RST function must stay disabled)
#define PIN_LED_BLUE        GPIO_Pin_22     // PB22
#define HAS_RGB_LED         1

#define LED_RED_On()        GPIOB_ResetBits(PIN_LED_RED)
#define LED_RED_Off()       GPIOB_SetBits(PIN_LED_RED)
#define LED_GREEN_On()      GPIOB_ResetBits(PIN_LED_GREEN)
#define LED_GREEN_Off()     GPIOB_SetBits(PIN_LED_GREEN)
#define LED_BLUE_On()       GPIOB_ResetBits(PIN_LED_BLUE)
#define LED_BLUE_Off()      GPIOB_SetBits(PIN_LED_BLUE)

static inline void LED_RGB_Init(void)
{
    GPIOB_SetBits(PIN_LED_RED | PIN_LED_GREEN | PIN_LED_BLUE);
    GPIOB_ModeCfg(PIN_LED_RED | PIN_LED_GREEN | PIN_LED_BLUE, GPIO_ModeOut_PP_5mA);
}

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

// GPIO IRQ (BTN and Touch both on GPIOB)
#define BTN_TOUCH_IRQn              GPIO_B_IRQn
#define BTN_TOUCH_IRQHandler        GPIOB_IRQHandler

#elif defined(HARDWARE_VER2) || defined(HARDWARE_VER3)

// --- VER2/VER3 Pin Assignments ---
// Same as VER1 except: BTN moved to PB12, RGB LED on PB4/PA12/PA13 (active low)
// VER3: same board as VER2 but with R599S fingerprint module
#define PIN_FP_PWR          GPIO_Pin_7      // PB7  - Fingerprint power (active high)
#define PIN_TOUCH           GPIO_Pin_10     // PB10 - Touch INT (active high)
#define PIN_BTN             GPIO_Pin_12     // PB12 - Button (active low)
#define PIN_VBAT            GPIO_Pin_14     // PA14 - Battery voltage (1/2 divider) → AIN4
#define VBAT_ADC_CH         CH_EXTIN_4      // ADC channel 4
#define VBAT_DIV_RATIO      2               // 1/2 resistor divider
// Divider Thevenin = 1M∥1M = 500kΩ, C7 = 100nF → RC=50ms; 5τ=250ms
#define VBAT_SETTLE_MS      250
#define HAS_VBAT_ADC        1
#define HAS_WS2812          0
#define HAS_FP_LED          0  // VER2/3 uses board RGB LED, not FP module LED
#ifdef HARDWARE_VER3
#define HAS_R599S           1  // VER3: R599S module, PS_Sleep before VCC-MCU off
#else
#define HAS_R599S           0
#endif

// RGB LED (active low: set low = ON, set high = OFF)
#define PIN_LED_RED         GPIO_Pin_4      // PB4
#define PIN_LED_GREEN       GPIO_Pin_12     // PA12
#define PIN_LED_BLUE        GPIO_Pin_13     // PA13
#define HAS_RGB_LED         1

#define LED_RED_On()        GPIOB_ResetBits(PIN_LED_RED)
#define LED_RED_Off()       GPIOB_SetBits(PIN_LED_RED)
#define LED_GREEN_On()      GPIOA_ResetBits(PIN_LED_GREEN)
#define LED_GREEN_Off()     GPIOA_SetBits(PIN_LED_GREEN)
#define LED_BLUE_On()       GPIOA_ResetBits(PIN_LED_BLUE)
#define LED_BLUE_Off()      GPIOA_SetBits(PIN_LED_BLUE)

static inline void LED_RGB_Init(void)
{
    // All LEDs off (high = off for active-low)
    GPIOB_SetBits(PIN_LED_RED);
    GPIOA_SetBits(PIN_LED_GREEN);
    GPIOA_SetBits(PIN_LED_BLUE);
    GPIOB_ModeCfg(PIN_LED_RED, GPIO_ModeOut_PP_5mA);
    GPIOA_ModeCfg(PIN_LED_GREEN | PIN_LED_BLUE, GPIO_ModeOut_PP_5mA);
}

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

// GPIO IRQ (BTN and Touch both on GPIOB)
#define BTN_TOUCH_IRQn              GPIO_B_IRQn
#define BTN_TOUCH_IRQHandler        GPIOB_IRQHandler

#elif defined(HARDWARE_VER1)

// --- VER1 Pin Assignments ---
#define PIN_FP_PWR          GPIO_Pin_7      // PB7  - Fingerprint power (active high)
#define PIN_TOUCH           GPIO_Pin_10     // PB10 - Touch INT (active high)
#define PIN_BTN             GPIO_Pin_4      // PB4  - Button (active low)
#define PIN_WS2812          GPIO_Pin_13     // PB13 - WS2812 DI (power shared with FP)
#define PIN_VBAT            GPIO_Pin_14     // PA14 - Battery voltage (1/2 divider) → AIN4
#define VBAT_ADC_CH         CH_EXTIN_4      // ADC channel 4
#define VBAT_DIV_RATIO      2               // 1/2 resistor divider
#define VBAT_SETTLE_MS      250             // 1M∥1M × 100nF, 5τ
#define HAS_VBAT_ADC        1
#define HAS_WS2812          0  // TODO: enable after sleep issue resolved
#define HAS_RGB_LED         0
#define HAS_FP_LED          0  // VER1 fingerprint module does not support AURA LED
#define HAS_R599S           1  // R599S: dual-power, PS_Sleep before VCC-MCU off, CMOS touch input

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
#define HAS_RGB_LED         0
#define HAS_FP_LED          1  // VER0 fingerprint module supports AURA LED
#define HAS_R599S           0

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
