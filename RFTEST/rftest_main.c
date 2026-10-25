/* immurok IK-1 RF test firmware entry point (CH592F VER=5)
 * Fingerprint sensor is powered off; fingerprint UART (UART1, PA8/PA9) used as command port @115200 8N1. */
#include "CH59x_common.h"
#include "CONFIG.h"
#include "HAL.h"
#include "ftm.h"
#include "version.h"

/* VER=5 pins */
#define PIN_SENSOR_EN   GPIO_Pin_12   /* PB12 FP_PWR, set 0 to power off fingerprint sensor */
#define PIN_LED_RED     GPIO_Pin_7    /* PB7  */
#define PIN_LED_BLUE    GPIO_Pin_22   /* PB22 */

__attribute__((aligned(4))) uint32_t MEM_BUF[BLE_MEMHEAP_SIZE / 4];

#if(defined(BLE_MAC)) && (BLE_MAC == TRUE)
const uint8_t MacAddr[6] = {0x84, 0xC2, 0xE4, 0x03, 0x02, 0x02};
#endif

/* UART1 line buffer */
#define LINE_MAX 64
static char  s_line[LINE_MAX];
static int   s_len = 0;

static void board_gpio_init(void) {
    /* Power off fingerprint sensor: PB12 output low */
    GPIOB_ModeCfg(PIN_SENSOR_EN, GPIO_ModeOut_PP_5mA);
    GPIOB_ResetBits(PIN_SENSOR_EN);

    /* Status LEDs (active-high here; adjust if hardware is active-low) */
    GPIOB_ModeCfg(PIN_LED_RED | PIN_LED_BLUE, GPIO_ModeOut_PP_5mA);
    GPIOB_ResetBits(PIN_LED_RED | PIN_LED_BLUE);
}

static void uart1_cmdport_init(void) {
    /* UART1 default pins: PA8 (RXD1) / PA9 (TXD1), no remap needed */
    GPIOA_SetBits(GPIO_Pin_9);
    GPIOA_ModeCfg(GPIO_Pin_8, GPIO_ModeIN_PU);          /* RX */
    GPIOA_ModeCfg(GPIO_Pin_9, GPIO_ModeOut_PP_5mA);     /* TX */
    UART1_DefInit();
    UART1_BaudRateCfg(115200);
}

/* Poll UART1 RX FIFO, assemble lines on \n/\r and hand to ftm_on_line */
static void uart1_poll(void) {
    /* R8_UART1_RFC: RX FIFO byte count register (CH592SFR.h 0x4000340A) */
    while (R8_UART1_RFC) {
        uint8_t c = UART1_RecvByte();
        if (c == '\n' || c == '\r') {
            if (s_len > 0) {
                s_line[s_len] = '\0';
                ftm_on_line(s_line);
                s_len = 0;
            }
        } else if (s_len < LINE_MAX - 1) {
            s_line[s_len++] = (char)c;
        } else {
            /* Line too long: discard and report error */
            s_len = 0;
            ftm_puts("ERR line too long");
        }
    }
}

int main(void) {
#if(defined(DCDC_ENABLE)) && (DCDC_ENABLE == TRUE)
    PWR_DCDCCfg(ENABLE);
#endif
    SetSysClock(CLK_SOURCE_PLL_60MHz);

    board_gpio_init();
    uart1_cmdport_init();

    CH59x_BLEInit();
    HAL_Init();
    RF_RoleInit();
    ftm_init();

    ftm_puts("[FTM] ready");
    ftm_puts("immurok IK-1 RFTEST v" FW_VERSION_STRING " HW=5");

    while (1) {
        TMOS_SystemProcess();
        uart1_poll();
    }
}
