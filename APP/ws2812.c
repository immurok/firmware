/*
 * WS2812 LED Driver for CH592F (60MHz, bit-bang)
 * Single LED, GRB byte order
 */

#include "CH59x_common.h"
#include "ws2812.h"

#if HAS_WS2812

// At 60MHz, 1 NOP ≈ 16.67ns
// WS2812B timing (±150ns tolerance):
//   T0H=400ns  T0L=850ns
//   T1H=800ns  T1L=450ns
#define NOP1  __asm volatile("nop")
#define NOP5  NOP1;NOP1;NOP1;NOP1;NOP1
#define NOP10 NOP5;NOP5

void ws2812_init(void)
{
    WS2812_SetMode(GPIO_ModeOut_PP_5mA);
    WS2812_SetLow();
}

__HIGH_CODE
static void ws2812_send_byte(uint8_t byte)
{
    for (uint8_t i = 0; i < 8; i++) {
        if (byte & 0x80) {
            // '1': T1H ≈ 800ns, T1L ≈ 450ns
            WS2812_SetHigh();
            NOP10; NOP10; NOP10; NOP10;
            WS2812_SetLow();
            NOP10;
        } else {
            // '0': T0H ≈ 400ns, T0L ≈ 850ns
            WS2812_SetHigh();
            NOP10;
            WS2812_SetLow();
            NOP10; NOP10; NOP10; NOP10;
        }
        byte <<= 1;
    }
}

void ws2812_set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    uint32_t irq_status;
    SYS_DisableAllIrq(&irq_status);

    // WS2812 byte order: G, R, B
    ws2812_send_byte(g);
    ws2812_send_byte(r);
    ws2812_send_byte(b);

    SYS_RecoverIrq(irq_status);

    // Reset: hold low >80μs
    DelayUs(80);
}

#endif // HAS_WS2812
