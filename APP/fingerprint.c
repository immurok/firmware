/*
 * ZW3021 Fingerprint Module Driver for CH592F
 * UART1 protocol implementation (PA9 TX, PA8 RX, 57600 8N1)
 * Ported from ESP32H2 implementation
 */

#include "CH59x_common.h"
#include "CONFIG.h"
#include "HAL.h"
#include "fingerprint.h"
#include "hardware_pins.h"
#include "ws2812.h"
#include <string.h>

// Use SDK PRINT macro (requires DEBUG defined)
#ifndef PRINT
#define PRINT(...)
#endif

// Pin definitions from hardware_pins.h:
//   PIN_FP_TX, PIN_FP_RX  — UART1 (always GPIOA)
//   PIN_FP_PWR             — Power control (port varies by HW version)
//   FP_PWR_SetHigh/SetLow/SetMode macros handle port abstraction

// ============================================================================
// Protocol Constants
// ============================================================================

#define FP_HEADER_1             0xEF
#define FP_HEADER_2             0x01
#define FP_DEFAULT_ADDR         0xFFFFFFFF
#define FP_CMD_PACKET           0x01
#define FP_DATA_PACKET          0x02
#define FP_ACK_PACKET           0x07
#define FP_END_PACKET           0x08

// Command codes (per ZW3021 protocol manual)
#define CMD_GET_IMAGE           0x01
#define CMD_IMAGE2TZ            0x02
#define CMD_MATCH               0x03
#define CMD_SEARCH              0x04
#define CMD_REG_MODEL           0x05
#define CMD_STORE               0x06
#define CMD_LOAD_CHAR           0x07
#define CMD_UP_CHAR             0x08
#define CMD_DOWN_CHAR           0x09
#define CMD_DELETE_CHAR         0x0C
#define CMD_EMPTY               0x0D
#define CMD_WRITE_REG           0x0E
#define CMD_READ_SYS_PARA       0x0F
#define CMD_SET_PWD             0x12
#define CMD_VERIFY_PWD          0x13
#define CMD_GET_RANDOM_CODE     0x14
#define CMD_SET_ADDR            0x15
#define CMD_WRITE_NOTEPAD       0x18
#define CMD_READ_NOTEPAD        0x19
#define CMD_HI_SPEED_SEARCH     0x1B
#define CMD_TEMPLATE_NUM        0x1D
#define CMD_READ_INDEX_TAB      0x1F
#define CMD_CANCEL              0x30
#define CMD_AUTO_ENROLL         0x31
#define CMD_AUTO_IDENTIFY       0x32
#define CMD_SLEEP               0x33
#define CMD_GET_CHIP_SN         0x34
#define CMD_HANDSHAKE           0x35
#define CMD_CHECK_SENSOR        0x36
#define CMD_AURA_LED_CONFIG     0x3C
#define CMD_SOFT_RST            0x3D
#define CMD_AUTO_LED_CONTROL    0x60

// Timeouts
#define UART_TIMEOUT_MS         200
#define INIT_TIMEOUT_MS         200
#define HANDSHAKE_TIMEOUT_MS    3000
#define QUICK_READY_TIMEOUT_MS  100

// ============================================================================
// State
// ============================================================================

static bool s_powered_on = false;
volatile uint8_t g_sleep_inhibit = 0;  // Reference count: >0 suppresses HAL_SLEEP. Multiple sources
                                       // (FP module, BLE short timeout) can independently hold it.
static uint32_t s_power_on_tick = 0;  // RTC tick at power-on (for timing measurement)
static bool s_initialized = false;
static bool s_password_verified = false;
static uint32_t s_module_addr = FP_DEFAULT_ADDR;
static uint8_t s_rx_buf[FP_RX_BUF_SIZE];
static uint16_t s_rx_total = 0;      // Total bytes from last uart_recv
static uint16_t s_rx_offset = 0;     // Offset of next unprocessed packet
static uint8_t s_cur_score_level = 0; // 0 = unknown; set by read_module_info

// ============================================================================
// UART1 RX Ring Buffer (ISR-driven; SPSC, power-of-2 size)
// ============================================================================
// 64B: largest FP response packet is ~21B, so this is >3× the max burst.
// Kept small because .bss sits between the BLE stack RAM and the 512B main
// stack — larger ring would collide with .stack_guard.
#define UART_RX_RING_SIZE 64
#define UART_RX_RING_MASK (UART_RX_RING_SIZE - 1)
static volatile uint8_t  s_rx_ring[UART_RX_RING_SIZE];
static volatile uint16_t s_rx_ring_head = 0;  // written by ISR
static volatile uint16_t s_rx_ring_tail = 0;  // written by main

static inline void uart_ring_reset(void)
{
    // Safe from main context when IRQ is masked or when FP is powered off
    s_rx_ring_head = 0;
    s_rx_ring_tail = 0;
}

uint16_t uart_rx_available(void)
{
    uint16_t h = s_rx_ring_head;
    uint16_t t = s_rx_ring_tail;
    return (uint16_t)((h - t) & UART_RX_RING_MASK);
}

// Pop one byte. Returns byte in 0..255, or -1 if empty.
int uart_rx_pop(void)
{
    uint16_t t = s_rx_ring_tail;
    if (t == s_rx_ring_head) return -1;
    uint8_t b = s_rx_ring[t];
    s_rx_ring_tail = (t + 1) & UART_RX_RING_MASK;
    return b;
}

// ============================================================================
// Forward Declarations
// ============================================================================

static int fp_get_image(uint32_t timeout_ms);
static int fp_gen_char(uint8_t buffer_id);
static int fp_reg_model(void);
static int fp_store_char(uint8_t buffer_id, uint16_t page_id);
static int fp_search_lib(uint8_t buffer_id, uint16_t start_page, uint16_t count, fp_search_result_t *result);
static int fp_wait_finger_lift(uint32_t timeout_ms);
static int setup_password_protection(void);
static void check_sensor(void);
static void read_chip_sn(void);
static void read_module_info(void);

// ============================================================================
// UART Functions
// ============================================================================

static void uart_init(void)
{
    // Configure UART1 for fingerprint module (PA9=TX, PA8=RX)
    // 57600 baud, 8N2

    // Ensure UART1 uses PA8/PA9 (not PB12/PB13)
    R16_PIN_ALTERNATE &= ~RB_PIN_UART1;

    // Configure GPIO pins
    GPIOA_SetBits(PIN_FP_TX);
    GPIOA_ModeCfg(PIN_FP_TX, GPIO_ModeOut_PP_5mA);  // TX
    GPIOA_ModeCfg(PIN_FP_RX, GPIO_ModeIN_PU);       // RX

    UART1_DefInit();
    UART1_BaudRateCfg(FP_UART_BAUD);
    // 8N1: 1 start bit, 8 data bits, no parity, 1 stop bit

    // Trigger RX IRQ on every byte (FP packets are small and bursty; 1-byte
    // trigger avoids stale-FIFO edge cases at packet boundaries).
    UART1_ByteTrigCfg(UART_1BYTE_TRIG);
    uart_ring_reset();
    UART1_INTCfg(ENABLE, RB_IER_RECV_RDY | RB_IER_LINE_STAT);
    PFIC_EnableIRQ(UART1_IRQn);

    PRINT("UART1 initialized: %d baud, 8N1\n", FP_UART_BAUD);
}

// UART1 RX ISR: drain FIFO into ring buffer. Kept small to minimize stack use
// (CH592F has only 512B of stack). Runs in WCH-Interrupt-fast context.
__INTERRUPT
__HIGH_CODE
void UART1_IRQHandler(void)
{
    uint8_t iir = R8_UART1_IIR & RB_IIR_INT_MASK;
    if (iir == UART_II_LINE_STAT) {
        (void)R8_UART1_LSR;  // clear line-status flags
        return;
    }
    if (iir == UART_II_RECV_RDY || iir == UART_II_RECV_TOUT) {
        while (R8_UART1_RFC) {
            uint8_t b = R8_UART1_RBR;
            uint16_t next = (s_rx_ring_head + 1) & UART_RX_RING_MASK;
            if (next != s_rx_ring_tail) {
                s_rx_ring[s_rx_ring_head] = b;
                s_rx_ring_head = next;
            }
            // else: overflow — drop the byte. 128B ring is >4× the largest
            // FP packet (~30B), so only possible if main never drains.
        }
    }
}

static void uart_send(const uint8_t *data, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        while ((R8_UART1_LSR & RB_LSR_TX_FIFO_EMP) == 0);
        R8_UART1_THR = data[i];
    }
}

// Reentrancy guard for TMOS keepalive in uart_recv.
// Prevents nested TMOS_SystemProcess() if a TMOS event triggers another UART operation.
static volatile uint8_t s_in_uart_tmos_kick = 0;

static int uart_recv(uint8_t *data, uint16_t max_len, uint32_t timeout_ms)
{
    uint16_t count = 0;
    uint32_t timeout_loops = timeout_ms * 6000;
    uint32_t gap_timeout_loops = 10 * 6000;  // 10ms gap timeout after first byte
    uint32_t idle_count = 0;

    while (count < max_len) {
        int b = uart_rx_pop();
        if (b >= 0) {
            data[count++] = (uint8_t)b;
            idle_count = 0;
        } else {
            idle_count++;
            // Keep BLE alive: call TMOS_SystemProcess() every ~15ms (≈ one connection interval)
            // to prevent supervision timeout during long UART waits (up to 200ms).
            // 15ms ≈ 90000 loops at 60MHz. Use reentrancy guard to prevent nested calls.
            if ((idle_count % 90000) == 0) {
                WWDG_SetCounter(0);
                if(!s_in_uart_tmos_kick) {
                    s_in_uart_tmos_kick = 1;
                    TMOS_SystemProcess();
                    s_in_uart_tmos_kick = 0;
                }
            }
            uint32_t limit = (count > 0) ? gap_timeout_loops : timeout_loops;
            if (idle_count >= limit) {
                break;
            }
        }
    }

    return count;
}

void uart_flush(void)
{
    uart_ring_reset();
    s_rx_total = 0;
    s_rx_offset = 0;
}

// ============================================================================
// Protocol Functions
// ============================================================================

static uint16_t calc_checksum(const uint8_t *data, uint16_t len)
{
    uint16_t sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

// Build + transmit a command packet. When `flush` is true the RX ring is
// reset before sending — the usual case for fresh request/response pairs.
// Set `flush` false in caller-managed retry sequences where a late-arriving
// ack from a previous send should NOT be discarded.
static int fp_send_cmd_impl(uint8_t cmd, const uint8_t *params, uint16_t param_len, int flush)
{
    static uint8_t packet[64];  // static: save 64B stack (only 512B total)
    uint16_t len = 0;

    // Header
    packet[len++] = FP_HEADER_1;
    packet[len++] = FP_HEADER_2;

    // Address (4 bytes)
    packet[len++] = (s_module_addr >> 24) & 0xFF;
    packet[len++] = (s_module_addr >> 16) & 0xFF;
    packet[len++] = (s_module_addr >> 8) & 0xFF;
    packet[len++] = s_module_addr & 0xFF;

    // Packet type
    packet[len++] = FP_CMD_PACKET;

    // Length (command + params + checksum)
    uint16_t pkt_len = 1 + param_len + 2;
    packet[len++] = (pkt_len >> 8) & 0xFF;
    packet[len++] = pkt_len & 0xFF;

    // Command
    packet[len++] = cmd;

    // Parameters
    if (params && param_len > 0) {
        memcpy(&packet[len], params, param_len);
        len += param_len;
    }

    // Checksum (from packet type to end of params)
    uint16_t cs = calc_checksum(&packet[6], len - 6);
    packet[len++] = (cs >> 8) & 0xFF;
    packet[len++] = cs & 0xFF;

    if (flush) uart_flush();
    uart_send(packet, len);

    return FP_OK;
}

int fp_send_cmd(uint8_t cmd, const uint8_t *params, uint16_t param_len)
{
    return fp_send_cmd_impl(cmd, params, param_len, 1);
}

int fp_send_cmd_noflush(uint8_t cmd, const uint8_t *params, uint16_t param_len)
{
    return fp_send_cmd_impl(cmd, params, param_len, 0);
}

int fp_recv_ack(uint8_t *ack_code, uint8_t *params, uint16_t *param_len, uint32_t timeout_ms)
{
    // Check for residual data from a previous uart_recv that contained multiple packets
    uint8_t *buf;
    uint16_t avail;

    if (s_rx_offset < s_rx_total) {
        buf = &s_rx_buf[s_rx_offset];
        avail = s_rx_total - s_rx_offset;

        // Residual too small or invalid header → discard and fall through to fresh read
        if (avail < 12 || buf[0] != FP_HEADER_1 || buf[1] != FP_HEADER_2) {
            s_rx_total = 0;
            s_rx_offset = 0;
            // Fall through to UART read below
        } else {
            goto parse;
        }
    }

    // Read from UART
    {
        int recv_len = uart_recv(s_rx_buf, FP_RX_BUF_SIZE, timeout_ms);
        if (recv_len < 12) {
            s_rx_total = 0;
            s_rx_offset = 0;
            return FP_ERR_TIMEOUT;
        }
        s_rx_total = (uint16_t)recv_len;
        s_rx_offset = 0;
        buf = s_rx_buf;
        avail = s_rx_total;
    }

parse:
    // Verify header
    if (buf[0] != FP_HEADER_1 || buf[1] != FP_HEADER_2) {
        s_rx_total = 0;
        s_rx_offset = 0;
        return FP_ERR_FAIL;
    }

    // Verify packet type
    if (buf[6] != FP_ACK_PACKET) {
        s_rx_total = 0;
        s_rx_offset = 0;
        return FP_ERR_FAIL;
    }

    // Get length field (includes ack + params + checksum)
    uint16_t pkt_len = (buf[7] << 8) | buf[8];
    uint16_t total_pkt = 9 + pkt_len;  // header(9) + pkt_len

    // Bounds check: reject if declared packet length exceeds available data
    if (total_pkt > avail) {
        s_rx_total = 0;
        s_rx_offset = 0;
        return FP_ERR_FAIL;
    }

    // Get ACK code
    *ack_code = buf[9];

    // Get parameters (if any)
    if (param_len && params && pkt_len > 3) {
        uint16_t data_len = pkt_len - 3;  // Subtract ack_code + checksum
        if (data_len > *param_len) {
            data_len = *param_len;
        }
        uint16_t data_avail = (avail > 10) ? (avail - 10) : 0;
        if (data_len > data_avail) {
            data_len = data_avail;
        }
        memcpy(params, &buf[10], data_len);
        *param_len = data_len;
    }

    // Advance offset past this packet for next call
    s_rx_offset += total_pkt;

    return FP_OK;
}

// ============================================================================
// Non-blocking Packet Parser (Phase 2)
// Incremental accumulator — caller pumps fp_try_parse_packet periodically
// via a TMOS event. State persists across calls; reset before each new cmd.
// ============================================================================

static struct {
    uint8_t  buf[32];    // >= header(9) + ack(1) + largest SEARCH/WAIT_LIFT response
    uint16_t pos;        // bytes accumulated so far
    uint16_t total_sz;   // 0 until length field seen, then 9 + pkt_len
} s_parser;

void fp_parser_reset(void)
{
    s_parser.pos = 0;
    s_parser.total_sz = 0;
}

int fp_try_parse_packet(uint8_t *ack_code, uint8_t *params, uint16_t *param_len)
{
    for (;;) {
        // Header resync: while not past position 2, enforce the two magic bytes.
        if (s_parser.pos == 0) {
            int b = uart_rx_pop();
            if (b < 0) return FP_ERR_TIMEOUT;
            if ((uint8_t)b != FP_HEADER_1) continue;
            s_parser.buf[0] = (uint8_t)b;
            s_parser.pos = 1;
        }
        if (s_parser.pos == 1) {
            int b = uart_rx_pop();
            if (b < 0) return FP_ERR_TIMEOUT;
            if ((uint8_t)b != FP_HEADER_2) {
                // Not a valid header — drop the first byte and keep scanning.
                s_parser.pos = 0;
                continue;
            }
            s_parser.buf[1] = (uint8_t)b;
            s_parser.pos = 2;
        }

        // Accumulate fixed-size preamble up to and including the length field.
        while (s_parser.pos < 9) {
            int b = uart_rx_pop();
            if (b < 0) return FP_ERR_TIMEOUT;
            s_parser.buf[s_parser.pos++] = (uint8_t)b;
        }

        // After header(9) we know packet type and length.
        if (s_parser.total_sz == 0) {
            if (s_parser.buf[6] != FP_ACK_PACKET) {
                fp_parser_reset();
                return FP_ERR_FAIL;
            }
            uint16_t pkt_len = ((uint16_t)s_parser.buf[7] << 8) | s_parser.buf[8];
            // pkt_len includes ack(1) + params + checksum(2) — minimum 3 bytes.
            // Bound pkt_len directly. The old form (uint16_t)(9 + pkt_len) truncated
            // the sum: pkt_len in [0xFFF7,0xFFFF] wrapped to 0..8, slipped past the
            // upper bound, and total_sz wrapped below pos so calc_checksum() ran with
            // a ~65528 length → OOB read past s_parser.buf → HardFault/WDT.
            if (pkt_len < 3 || pkt_len > sizeof(s_parser.buf) - 9) {
                fp_parser_reset();
                return FP_ERR_FAIL;
            }
            s_parser.total_sz = 9 + pkt_len;
        }

        // Accumulate payload + checksum.
        while (s_parser.pos < s_parser.total_sz) {
            int b = uart_rx_pop();
            if (b < 0) return FP_ERR_TIMEOUT;
            s_parser.buf[s_parser.pos++] = (uint8_t)b;
        }

        // Complete packet — validate checksum.
        uint16_t cs_expected = calc_checksum(&s_parser.buf[6], s_parser.total_sz - 6 - 2);
        uint16_t cs_recv = ((uint16_t)s_parser.buf[s_parser.total_sz - 2] << 8)
                         | s_parser.buf[s_parser.total_sz - 1];
        if (cs_expected != cs_recv) {
            fp_parser_reset();
            return FP_ERR_FAIL;
        }

        // Extract fields.
        *ack_code = s_parser.buf[9];
        uint16_t pkt_len = ((uint16_t)s_parser.buf[7] << 8) | s_parser.buf[8];
        uint16_t data_len = pkt_len - 3;  // subtract ack + checksum
        if (param_len && params && data_len > 0) {
            uint16_t to_copy = (data_len > *param_len) ? *param_len : data_len;
            memcpy(params, &s_parser.buf[10], to_copy);
            *param_len = to_copy;
        } else if (param_len) {
            *param_len = 0;
        }

        fp_parser_reset();
        return FP_OK;
    }
}

static int send_cmd_recv_ack(uint8_t cmd, const uint8_t *params, uint16_t param_len, uint32_t timeout_ms)
{
    uart_flush();
    fp_send_cmd(cmd, params, param_len);

    uint8_t ack;
    return fp_recv_ack(&ack, NULL, NULL, timeout_ms);
}

// ============================================================================
// Diagnostic Functions
// ============================================================================

static void check_sensor(void)
{
    fp_send_cmd(CMD_CHECK_SENSOR, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        PRINT("Sensor check failed\n");
        return;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Sensor: OK\n");
    } else {
        PRINT("Sensor: Error 0x%02X\n", ack);
    }
}

static void read_chip_sn(void)
{
    fp_send_cmd(CMD_GET_CHIP_SN, NULL, 0);

    uint8_t ack;
    uint8_t sn_buf[32];
    uint16_t sn_len = 32;

    int ret = fp_recv_ack(&ack, sn_buf, &sn_len, UART_TIMEOUT_MS);
    if (ret != FP_OK || ack != FP_ACK_SUCCESS) {
        PRINT("Failed to read chip SN\n");
        return;
    }

    PRINT("Chip SN: ");
    for (int i = 0; i < sn_len && i < 16; i++) {
        if (sn_buf[i] != 0x00 && sn_buf[i] != 0xFF) {
            PRINT("%02X", sn_buf[i]);
        }
    }
    PRINT("\n");
}

static void read_module_info(void)
{
    fp_sys_params_t params;

    fp_send_cmd(CMD_READ_SYS_PARA, NULL, 0);

    uint8_t ack;
    uint8_t buf[16];
    uint16_t len = 16;

    int ret = fp_recv_ack(&ack, buf, &len, UART_TIMEOUT_MS);
    if (ret != FP_OK || ack != FP_ACK_SUCCESS) {
        PRINT("Failed to read system params\n");
        return;
    }

    // Parse parameters (starting at buf[0] which is s_rx_buf[10])
    params.capacity = (s_rx_buf[14] << 8) | s_rx_buf[15];
    params.security_level = (s_rx_buf[16] << 8) | s_rx_buf[17];
    params.device_addr = (s_rx_buf[18] << 24) | (s_rx_buf[19] << 16) |
                         (s_rx_buf[20] << 8) | s_rx_buf[21];

    uint16_t pkt_size_code = (s_rx_buf[22] << 8) | s_rx_buf[23];
    uint16_t pkt_size = 32;
    if (pkt_size_code == 1) pkt_size = 64;
    else if (pkt_size_code == 2) pkt_size = 128;
    else if (pkt_size_code == 3) pkt_size = 256;
    params.packet_size = pkt_size;

    params.baud_setting = (s_rx_buf[24] << 8) | s_rx_buf[25];

    uint16_t template_count = (s_rx_buf[10] << 8) | s_rx_buf[11];

    PRINT("Templates: %d/%d, Security: %d\n",
          template_count, params.capacity, params.security_level);
    PRINT("Address: 0x%08lX, Baud: %d\n",
          (unsigned long)params.device_addr, params.baud_setting * 9600);
    s_cur_score_level = (uint8_t)(params.security_level & 0xFF);
    (void)template_count;
    (void)params;
}

// ============================================================================
// Power Control
// ============================================================================

void fp_power_on(void)
{
    if (s_powered_on) return;

    // Ensure UART RX/TX are LOW before VCC rises to prevent current
    // backflow through the unpowered module's ESD diodes
    GPIOA_ModeCfg(PIN_FP_TX | PIN_FP_RX, GPIO_ModeIN_PD);

#if HAS_R599S
    // R599S wants its DETECT line driven against a CMOS input with no internal
    // pull while the sensor is active. Default idle mode (fp_power_off) is
    // IN_PD — switch to Floating only for the duration of this power cycle.
    TOUCH_SetMode(GPIO_ModeIN_Floating);
#endif

    // Power on VCC, then bring UART pins back up
    FP_PWR_SetMode(GPIO_ModeOut_PP_5mA);
    FP_PWR_SetHigh();

    // Re-enable UART1 clock (was gated in fp_power_off)
    sys_safe_access_enable();
    R8_SLP_CLK_OFF0 &= ~RB_SLP_CLK_UART1;
    sys_safe_access_disable();
    // Now safe to bring UART TX/RX high
    uart_init();
    s_powered_on = true;
    g_sleep_inhibit++;  // Suppress sleep while FP module is active
    s_power_on_tick = RTC_GetCycle32k();
    PRINT("Fingerprint power ON\n");
}

// Internal: GPIO + VCC cut, no PS_Sleep command. Caller is responsible for
// having either successfully issued PS_Sleep or knowingly accepting the
// "VCC cut while finger on → sensor stuck" risk. Exposed via fp_finish_off()
// for the async-retry path in hidkbd.c.
void fp_finish_off(void)
{
    if (!s_powered_on) return;

    // Pull UART RX/TX LOW before VCC drops to prevent current backflow
    // through the module's ESD protection diodes
    GPIOA_ModeCfg(PIN_FP_TX | PIN_FP_RX, GPIO_ModeIN_PD);
    // Disable UART1 IRQ before gating clock — stale interrupts could otherwise
    // fire on floating pins once VCC drops.
    PFIC_DisableIRQ(UART1_IRQn);
    UART1_INTCfg(DISABLE, RB_IER_RECV_RDY | RB_IER_LINE_STAT);
    uart_ring_reset();
    // Gate UART1 clock to eliminate peripheral static power
    sys_safe_access_enable();
    R8_SLP_CLK_OFF0 |= RB_SLP_CLK_UART1;
    sys_safe_access_disable();

    // Now safe to cut VCC
    FP_PWR_SetLow();
    FP_PWR_SetMode(GPIO_ModeIN_PD);

#if HAS_R599S
    // Sensor output stage is losing power — clamp DETECT with internal PD so
    // the pin can't end up floating near the input-buffer threshold and burn
    // 10-100µA in shoot-through current during sleep.
    TOUCH_SetMode(GPIO_ModeIN_PD);
#endif

    s_powered_on = false;
    if(g_sleep_inhibit > 0) g_sleep_inhibit--;  // Release FP hold on sleep inhibit
    s_password_verified = false;  // Need to re-verify after power on
    PRINT("Fingerprint power OFF\n");
}

bool fp_power_off(void)
{
    if (!s_powered_on) return true;

    bool slept = true;  // 非 R599S 无 sleep 步骤,视为已就绪(不触发 touch-reset)
#if HAS_R599S
    // R599S: must send PS_Sleep(0x33) before cutting VCC-MCU power, otherwise
    // sensor stays in mA-level current and touch becomes unresponsive on the
    // next power cycle.
    //
    // Wall-clock-bounded ack wait (~100ms). The old path used fp_recv_ack's
    // busy-loop calibration, which under interrupt pressure (ECC keepalive,
    // BLE bursts) stretched 200ms nominal to ~4s observed — long enough to
    // chew through the BLE supervision window. We now read via the
    // non-blocking parser and bail on wall-clock instead. If the user's
    // finger is still on the sensor when this fires, the sleep won't ack
    // within 100ms; we cut VCC anyway and trust the upstream caller
    // (typically fp_async_off_start) to retry sleep later if needed.
    fp_parser_reset();
    fp_send_cmd(CMD_SLEEP, NULL, 0);

    uint32_t start = RTC_GetCycle32k();
    const uint32_t cap_ticks = 32768 / 10;  // 100ms @ 32.768 kHz
    uint8_t ack = 0xFF;
    int got = FP_ERR_TIMEOUT;
    while ((uint32_t)(RTC_GetCycle32k() - start) < cap_ticks) {
        got = fp_try_parse_packet(&ack, NULL, NULL);
        if (got == FP_OK) break;
        WWDG_SetCounter(0);
        // Keep BLE alive during the wait. Reentrancy guard mirrors uart_recv.
        if (!s_in_uart_tmos_kick) {
            s_in_uart_tmos_kick = 1;
            TMOS_SystemProcess();
            s_in_uart_tmos_kick = 0;
        }
    }
    slept = (got == FP_OK && ack == FP_ACK_SUCCESS);
#ifdef FP_FORCE_SLEEP_NOACK
    /* 测试专用（TEST_DEFS=-DFP_FORCE_SLEEP_NOACK）：把「sleep 没被 ack」这个
     * 概率性 race 变成必现。no-ack 会让调用方走抬指 touch-reset 恢复路径，
     * 而那条路径正是 fp_gate_enter 忙门要保护的窗口 —— 不强制的话跑十遍
     * 也可能一次都没进去，测出来的 PASS 毫无意义。
     * 只影响返回值：CMD_SLEEP 照发、ack 照收，真进了 standby 也当没进，
     * 所以最坏情况只是多跑一次无害的 power-cycle。 */
    if (slept) {
        PRINT("*** FP_FORCE_SLEEP_NOACK: reporting no-ack (TEST BUILD) ***\n");
    }
    slept = false;
#warning "FP_FORCE_SLEEP_NOACK enabled - TEST BUILD ONLY, never ship this"
#endif
    if (slept) {
        PRINT("R599S sleep OK, cutting VCC-MCU\n");
    } else {
        uint32_t waited_ms = ((uint32_t)(RTC_GetCycle32k() - start) * 1000) / 32768;
        PRINT("R599S sleep no-ack (%ums, ack=0x%02X), cutting VCC anyway\n",
              (unsigned)waited_ms, ack);
    }
#endif

    fp_finish_off();
    // slept=false → R599S 没进 standby,touch-wake 会失效。抬指路径据此跑
    // touch-reset 恢复(2-step pair 期间 BLE 高负载挤掉 sleep ack 是高发场景)。
    return slept;
}

bool fp_is_powered(void)
{
    return s_powered_on;
}

int fp_complete_wake(void)
{
    // This function is called after power-on delay has elapsed
    // It completes the wake sequence without blocking delays

    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    // If already verified, nothing to do
    if (s_password_verified) {
        return FP_OK;
    }

    PRINT("Completing wake sequence...\n");

    // Try to read ready signal (0x55) - non-blocking check
    bool got_ready = false;
    for (int i = 0; i < 10; i++) {
        int b;
        while ((b = uart_rx_pop()) >= 0) {
            if ((uint8_t)b == 0x55) {
                got_ready = true;
                break;
            }
        }
        if (got_ready) break;
        // Small delay between checks (not blocking TMOS significantly)
        for(volatile int j = 0; j < 1000; j++);
    }

    // Flush any remaining data
    uart_flush();

    if (got_ready) {
        uint32_t now = RTC_GetCycle32k();
        uint32_t elapsed = now - s_power_on_tick;
        uint32_t ms = elapsed / 33;
        PRINT("Module 0x55 received (complete_wake), %dms after power-on\n", ms);
        (void)ms;
    } else {
        PRINT("Module 0x55 NOT received (complete_wake)\n");
    }

    // Verify the module's default password if not yet verified. Only the
    // default password (0x00000000) is supported — the device never programs
    // a non-default password, so a failure here means the module is missing
    // or not responding as expected.
    if (!s_password_verified) {
        int ret = fp_verify_password(0x00000000);
        if (ret == FP_OK) {
            PRINT("Default password OK (complete_wake)\n");
        } else {
            PRINT("Default password verify failed: %d\n", ret);
            return ret;
        }
    }

    PRINT("Fingerprint module ready\n");
    return FP_OK;
}

bool fp_is_password_verified(void)
{
    return s_password_verified;
}

int fp_start_verify(void)
{
    // Verify password with reduced timeout (safe for watchdog).
    // Send + recv in one call to prevent UART FIFO overflow (8-byte FIFO, 12-byte response).
    // Max blocking: ~110ms (100ms first-byte wait + 10ms gap), well under 557ms watchdog.
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    if (s_password_verified) {
        return FP_OK;
    }

    // 0x55 already consumed by FP_WAKE_DONE_EVT poll in hidkbd.c
    uart_flush();

    // Only the default password (0x00000000) is supported.
    int ret = fp_verify_password(0x00000000);
    if (ret == FP_OK) {
        PRINT("Default password OK\n");
        return FP_OK;
    }

    PRINT("Default password failed in start_verify\n");
    s_password_verified = false;
    return FP_ERR_FAIL;
}

int fp_wake(void)
{
    // If already powered and verified, nothing to do
    if (s_powered_on && s_password_verified) {
        return FP_OK;
    }

    PRINT("Waking up fingerprint module...\n");

    // Power on if needed
    if (!s_powered_on) {
        fp_power_on();

#if HAS_R599S
        DelayMs(200);  // R599S: DSP needs ≥200ms to initialize sensor touch
#else
        // Wait for module initialization (100ms - reduced to avoid BLE timeout)
        DelayMs(100);
#endif
        WWDG_SetCounter(0);  // Feed watchdog after blocking delay

        // Try to read ready signal (0x55)
        bool got_ready = false;
        for (int i = 0; i < 10; i++) {
            int b;
            while ((b = uart_rx_pop()) >= 0) {
                if ((uint8_t)b == 0x55) {
                    got_ready = true;
                    break;
                }
            }
            if (got_ready) break;
            DelayMs(10);
        }

        // Flush any remaining data
        uart_flush();
        WWDG_SetCounter(0);  // Feed watchdog after ready-signal polling

        if (got_ready) {
            PRINT("Module ready signal received\n");
        }
    }

    // Verify the module's default password if not yet verified.
    if (!s_password_verified) {
        int ret = fp_verify_password(0x00000000);
        WWDG_SetCounter(0);  // Feed watchdog after UART command
        if (ret == FP_OK) {
            PRINT("Default password OK (wake)\n");
        } else {
            PRINT("Default password verify failed: %d\n", ret);
            return ret;
        }
    }

    PRINT("Fingerprint module ready\n");
    return FP_OK;
}

// ============================================================================
// Public API - Initialization
// ============================================================================

int fp_init(void)
{
    int ret;

    if (s_initialized) {
        // Fast path: if already powered on and password verified, just return
        if (s_powered_on && s_password_verified) {
            PRINT("Already ready\n");
            return FP_OK;
        }

        // Need to power on and/or verify password
        if (!s_powered_on) {
            fp_power_on();
#if HAS_R599S
            DelayMs(200);  // R599S: DSP needs ≥200ms to initialize sensor touch
#else
            DelayMs(150);  // Minimal boot delay
#endif

            // Read for ready signal FIRST (before any flush)
            bool got_ready = false;

            for (int i = 0; i < 10; i++) {
                int b;
                while ((b = uart_rx_pop()) >= 0) {
                    if ((uint8_t)b == 0x55) {
                        got_ready = true;
                        break;
                    }
                }
                if (got_ready) break;
                DelayMs(10);
            }

            uart_flush();

            if (got_ready) {
                PRINT("Module ready after power on\n");
            }
        }

        // Verify the module's default password if not yet verified.
        if (!s_password_verified) {
            ret = fp_verify_password(0x00000000);
            if (ret == FP_OK) {
                PRINT("Default password OK (init fast path)\n");
            } else {
                PRINT("Default password verify failed\n");
            }
        }
        return FP_OK;
    }

    PRINT("Initializing fingerprint module...\n");

    // Power on module (includes UART init)
    fp_power_on();

    // Wait for module initialization signal (0x55)
    DelayMs(100);

    int total_read = 0;
    bool got_ready = false;

    for (int retry = 0; retry < (INIT_TIMEOUT_MS / 50); retry++) {
        int b;
        while ((b = uart_rx_pop()) >= 0) {
            if ((uint8_t)b == 0x55) {
                got_ready = true;
            }
            total_read++;
        }
        if (got_ready) break;
        DelayMs(50);
    }

    if (got_ready) {
        PRINT("Module ready signal received\n");
    } else {
        PRINT("No ready signal, continuing anyway...\n");
    }

    // Verify the module's default password FIRST (before other commands).
    // This doubles as the module-presence / health check: a healthy module
    // ACKs the VerifyPassword command, while a missing or malfunctioning
    // module times out or returns garbage. Treat that as "unexpected info"
    // and fail init so the caller can signal failure (red LED).
    ret = setup_password_protection();
    if (ret != FP_OK) {
        PRINT("Default password verify failed — module not as expected, init FAILED\n");
        return FP_ERR_FAIL;
    }

    // Now try handshake
    ret = fp_handshake();
    if (ret == FP_OK) {
        PRINT("Handshake OK\n");
        s_initialized = true;
    } else {
        PRINT("Handshake failed, but continuing...\n");
        // Some modules may not support handshake command
        s_initialized = true;
    }

    // Read and display module information
    check_sensor();
    read_chip_sn();
    read_module_info();

    // Force ScoreLevel to strictest (5). read_module_info populates
    // s_cur_score_level; only WriteReg when it differs so we don't wear FLASH
    // on every boot. Factory default is 3 (medium) which can false-accept
    // short-tap low-quality images — see Bug 1 root cause.
    if (s_cur_score_level != FP_TARGET_SCORE_LEVEL) {
        PRINT("ScoreLevel %d != %d, writing\n",
              s_cur_score_level, FP_TARGET_SCORE_LEVEL);
        fp_set_score_level(FP_TARGET_SCORE_LEVEL);
    }

    // Enrollment logic mode (system register 3). Mode 1 = require a different
    // finger area on each capture; GenChar returns 0x28 when overlap is too
    // high, which hidkbd's enroll SM turns into a "shift finger" re-prompt.
    // Register 3 isn't read-back-able, so we write unconditionally once here.
    fp_set_enroll_mode(FP_ENROLL_LOGIC_MODE);

    return FP_OK;
}

void fp_deinit(void)
{
    if (!s_initialized) return;

    fp_power_off();
    s_initialized = false;

    PRINT("Deinitialized\n");
}

bool fp_is_ready(void)
{
    return s_initialized && s_powered_on;
}

int fp_handshake(void)
{
    fp_send_cmd(CMD_HANDSHAKE, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, HANDSHAKE_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        return FP_OK;
    }

    PRINT("Handshake failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// ============================================================================
// Password Protection
// ============================================================================

int fp_set_score_level(uint8_t level)
{
    if (!s_powered_on || level < 1 || level > 5) {
        return FP_ERR_INVALID;
    }

    // PS_WriteReg (0x0E): [reg_id=5 (ScoreLevel)] [value=level]. Re-read
    // sys-params after to confirm — silent write failures here are the
    // exact way the false-accept bug slips back in (chip stays at default
    // level 3 and lets thin features match).
    for (int attempt = 0; attempt < 3; attempt++) {
        uint8_t params[2] = { 5, level };
        fp_send_cmd(CMD_WRITE_REG, params, 2);

        uint8_t ack;
        int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
        if (ret != FP_OK) {
            PRINT("WriteReg ScoreLevel timeout (attempt %d)\n", attempt + 1);
            continue;
        }
        if (ack != FP_ACK_SUCCESS) {
            PRINT("WriteReg ScoreLevel ack=0x%02X (attempt %d)\n",
                  ack, attempt + 1);
            continue;
        }

        // Verify by re-reading. read_module_info refreshes s_cur_score_level.
        s_cur_score_level = 0;  // force refresh
        read_module_info();
        if (s_cur_score_level == level) {
            PRINT("ScoreLevel set to %d (verified)\n", level);
            return FP_OK;
        }
        PRINT("ScoreLevel verify failed: wrote %d, read %d (attempt %d)\n",
              level, s_cur_score_level, attempt + 1);
    }

    PRINT("ScoreLevel write FAILED after 3 attempts — sensor at level %d\n",
          s_cur_score_level);
    return FP_ERR_FAIL;
}

int fp_set_enroll_mode(uint8_t mode)
{
    if (!s_powered_on || mode > 2) {
        return FP_ERR_INVALID;
    }

    // PS_WriteReg (0x0E): [reg_id=3 (enroll logic mode)] [value=mode].
    // Register 3 is NOT returned by ReadSysPara, so unlike ScoreLevel we
    // cannot read-verify — write with retries and trust the ack. Written
    // once per fp_init; mode 1 makes GenChar reject (0x28) captures that
    // overlap the previous one too much, forcing broad-coverage enrollment.
    for (int attempt = 0; attempt < 3; attempt++) {
        uint8_t params[2] = { 3, mode };
        fp_send_cmd(CMD_WRITE_REG, params, 2);

        uint8_t ack;
        int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
        if (ret != FP_OK) {
            PRINT("WriteReg EnrollMode timeout (attempt %d)\n", attempt + 1);
            continue;
        }
        if (ack == FP_ACK_SUCCESS) {
            PRINT("EnrollMode set to %d\n", mode);
            return FP_OK;
        }
        PRINT("WriteReg EnrollMode ack=0x%02X (attempt %d)\n", ack, attempt + 1);
    }

    PRINT("EnrollMode write FAILED after 3 attempts\n");
    return FP_ERR_FAIL;
}

int fp_verify_password(uint32_t password)
{
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    uint8_t params[4];
    params[0] = (password >> 24) & 0xFF;
    params[1] = (password >> 16) & 0xFF;
    params[2] = (password >> 8) & 0xFF;
    params[3] = password & 0xFF;

    fp_send_cmd(CMD_VERIFY_PWD, params, 4);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Password verified\n");
        s_password_verified = true;
        return FP_OK;
    }

    PRINT("Password verification failed: 0x%02X\n", ack);
    s_password_verified = false;
    return FP_ERR_FAIL;
}

// Verify the module's default password (called from fp_init).
// Only the default password (0x00000000) is supported — the device never
// programs a non-default password. A failure here means the module is not
// present or not responding as expected.
static int setup_password_protection(void)
{
    PRINT("Verifying default password...\n");
    int ret = fp_verify_password(0x00000000);
    if (ret == FP_OK) {
        PRINT("Default password OK\n");
        return FP_OK;
    }

    PRINT("Default password verify failed\n");
    s_password_verified = false;
    return FP_ERR_FAIL;
}

// ============================================================================
// Fingerprint Operations
// ============================================================================

int fp_read_sys_params(fp_sys_params_t *params)
{
    if (!fp_is_ready() || !params) {
        return FP_ERR_FAIL;
    }

    fp_send_cmd(CMD_READ_SYS_PARA, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }
    if (ack != FP_ACK_SUCCESS) {
        PRINT("Read params failed: 0x%02X\n", ack);
        return FP_ERR_FAIL;
    }

    // Parse parameters (starting at s_rx_buf[10])
    params->capacity = (s_rx_buf[14] << 8) | s_rx_buf[15];
    params->security_level = (s_rx_buf[16] << 8) | s_rx_buf[17];
    params->device_addr = (s_rx_buf[18] << 24) | (s_rx_buf[19] << 16) |
                          (s_rx_buf[20] << 8) | s_rx_buf[21];
    params->packet_size = (s_rx_buf[22] << 8) | s_rx_buf[23];
    params->baud_setting = (s_rx_buf[24] << 8) | s_rx_buf[25];

    PRINT("Sys params: capacity=%d, security=%d\n",
          params->capacity, params->security_level);

    return FP_OK;
}

int fp_get_template_count(uint16_t *count)
{
    if (!fp_is_ready() || !count) {
        return FP_ERR_FAIL;
    }

    fp_send_cmd(CMD_TEMPLATE_NUM, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }
    if (ack != FP_ACK_SUCCESS) {
        PRINT("Get count failed: 0x%02X\n", ack);
        return FP_ERR_FAIL;
    }

    *count = (s_rx_buf[10] << 8) | s_rx_buf[11];
    PRINT("Template count: %d\n", *count);

    return FP_OK;
}

int fp_get_fingerprint_bitmap(uint16_t *bitmap)
{
    if (!fp_is_ready() || !bitmap) {
        return FP_ERR_FAIL;
    }

    // CMD_READ_INDEX_TAB (0x1F) reads index table
    // Parameter: page number (0-3), each page covers 256 templates
    // For immurok we only need page 0 (slots 0-9 for dual-slot)
    uint8_t params[1] = { 0 };  // Page 0

    fp_send_cmd(CMD_READ_INDEX_TAB, params, 1);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    WWDG_SetCounter(0);  // Feed watchdog after UART command
    if (ret != FP_OK) {
        return ret;
    }
    if (ack != FP_ACK_SUCCESS) {
        PRINT("Read index table failed: 0x%02X\n", ack);
        return FP_ERR_FAIL;
    }

    // Response contains 32 bytes of bitmap (256 bits for 256 templates)
    // Each bit represents whether a template exists at that slot
    // The bitmap is in s_rx_buf[10..41], first byte covers slots 0-7, second byte 8-15
    // For dual-slot we need bits 0-9 (FP_SLOT_MAX=10)
    *bitmap = (uint16_t)(s_rx_buf[10]) | ((uint16_t)(s_rx_buf[11]) << 8);
    *bitmap &= ((1 << FP_SLOT_MAX) - 1);  // Keep only bits 0-9

    PRINT("Fingerprint raw bitmap: 0x%04X\n", *bitmap);

    return FP_OK;
}

// Helper: Search fingerprint in library
static int fp_search_lib(uint8_t buffer_id, uint16_t start_page, uint16_t count, fp_search_result_t *result)
{
    uint8_t params[5];
    params[0] = buffer_id;
    params[1] = (start_page >> 8) & 0xFF;
    params[2] = start_page & 0xFF;
    params[3] = (count >> 8) & 0xFF;
    params[4] = count & 0xFF;

    fp_send_cmd(CMD_SEARCH, params, 5);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        result->page_id = (s_rx_buf[10] << 8) | s_rx_buf[11];
        result->match_score = (s_rx_buf[12] << 8) | s_rx_buf[13];
        return FP_OK;
    } else if (ack == FP_ACK_NOT_FOUND) {
        return FP_ERR_NOT_FOUND;
    }

    PRINT("Search lib failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

int fp_search(fp_search_result_t *result, uint32_t timeout_ms)
{
    if (!fp_is_ready() || !result) {
        return FP_ERR_FAIL;
    }

    int ret;

    // Manual search process:
    // 1. Capture image
    // 2. Generate characteristic to buffer
    // 3. Search in library

    PRINT("Search: waiting for finger...\n");

    // Get image
    ret = fp_get_image(timeout_ms);
    if (ret != FP_OK) {
        PRINT("Search: capture timeout\n");
        return FP_ERR_TIMEOUT;
    }

    // Generate characteristic to buffer 1
    ret = fp_gen_char(1);
    if (ret != FP_OK) {
        PRINT("Search: gen char failed\n");
        return FP_ERR_FAIL;
    }

    // Search in library
    ret = fp_search_lib(1, 0, FP_MAX_TEMPLATES, result);
    if (ret == FP_OK) {
        PRINT("Search found: page=%d, score=%d\n", result->page_id, result->match_score);
        return FP_OK;
    } else if (ret == FP_ERR_NOT_FOUND) {
        PRINT("Search: no match found\n");
        return FP_ERR_NOT_FOUND;
    }

    PRINT("Search: failed\n");
    return FP_ERR_FAIL;
}

int fp_auto_identify(fp_search_result_t *result)
{
    if (!fp_is_ready() || !result) {
        return FP_ERR_FAIL;
    }

    // PSAutoIdentify (0x32) per manual §4.4.2.2:
    //   [security_level:1B][ID:2B][parameter:2B]
    // ID=0xFFFF for 1:N search; parameter bit2=1 suppresses intermediate responses
    uint8_t params[5];
    params[0] = 0x03;                   // Security level (3 = medium)
    params[1] = 0xFF;                   // ID MSB (0xFFFF = 1:N search)
    params[2] = 0xFF;                   // ID LSB
    params[3] = 0x00;                   // Parameter MSB
    params[4] = 0x04;                   // Parameter LSB: bit2=1 (no intermediate responses)

    fp_send_cmd(CMD_AUTO_IDENTIFY, params, 5);

    // Module handles entire pipeline internally (capture + gen_char + search).
    // uart_recv calls TMOS_SystemProcess every ~15ms to keep BLE alive.
    uint8_t ack;
    uint8_t resp[5];  // [param:1B][ID:2B][score:2B]
    uint16_t resp_len = 5;
    int ret = fp_recv_ack(&ack, resp, &resp_len, 1500);
    if (ret != FP_OK) {
        return FP_ERR_TIMEOUT;
    }

    if (ack == FP_ACK_SUCCESS && resp_len >= 5) {
        // resp[0] = step param (0x05 = search), resp[1:2] = ID, resp[3:4] = score
        result->page_id = (resp[1] << 8) | resp[2];
        result->match_score = (resp[3] << 8) | resp[4];
        PRINT("AutoIdentify: page=%d, score=%d\n", result->page_id, result->match_score);
        return FP_OK;
    } else if (ack == FP_ACK_NOT_FOUND || ack == FP_ACK_NOT_MATCH) {
        PRINT("AutoIdentify: no match (0x%02X)\n", ack);
        return FP_ERR_NOT_FOUND;
    } else if (ack == FP_ACK_NO_FINGER || ack == 0x26) {
        PRINT("AutoIdentify: timeout (0x%02X)\n", ack);
        return FP_ERR_TIMEOUT;
    }

    PRINT("AutoIdentify failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// Helper: Get image from sensor
static int fp_get_image(uint32_t timeout_ms)
{
    uint32_t elapsed = 0;

    while (elapsed < timeout_ms) {
        fp_send_cmd(CMD_GET_IMAGE, NULL, 0);

        uint8_t ack;
        int ret = fp_recv_ack(&ack, NULL, NULL, 300);

        if (ret == FP_OK && ack == FP_ACK_SUCCESS) {
            return FP_OK;
        }
        if (ret == FP_OK && ack == FP_ACK_NO_FINGER) {
            // No finger yet, keep trying
            DelayMs(30);
            elapsed += 330;  // 300ms timeout + 30ms delay
            continue;
        }
        if (ret != FP_OK && ret != FP_ERR_TIMEOUT) {
            return ret;
        }
        DelayMs(30);
        elapsed += 330;
    }
    return FP_ERR_TIMEOUT;
}

// Helper: Wait for finger to be lifted from sensor
static int fp_wait_finger_lift(uint32_t timeout_ms)
{
    uint32_t elapsed = 0;

    PRINT("Waiting for finger lift...\n");

    while (elapsed < timeout_ms) {
        fp_send_cmd(CMD_GET_IMAGE, NULL, 0);

        uint8_t ack;
        int ret = fp_recv_ack(&ack, NULL, NULL, 500);

        if (ret == FP_OK && ack == FP_ACK_NO_FINGER) {
            // Finger lifted
            PRINT("Finger lifted\n");
            return FP_OK;
        }
        // Finger still on sensor, keep waiting
        DelayMs(100);
        elapsed += 600;  // 500ms timeout + 100ms delay
    }
    return FP_ERR_TIMEOUT;
}

// Helper: Generate characteristic to buffer
static int fp_gen_char(uint8_t buffer_id)
{
    uint8_t params[1] = { buffer_id };
    fp_send_cmd(CMD_IMAGE2TZ, params, 1);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        return FP_OK;
    }

    PRINT("GenChar failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// Helper: Merge characteristics into template
static int fp_reg_model(void)
{
    fp_send_cmd(CMD_REG_MODEL, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        return FP_OK;
    }

    PRINT("RegModel failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// Helper: Store template to flash
static int fp_store_char(uint8_t buffer_id, uint16_t page_id)
{
    uint8_t params[3];
    params[0] = buffer_id;
    params[1] = (page_id >> 8) & 0xFF;
    params[2] = page_id & 0xFF;

    fp_send_cmd(CMD_STORE, params, 3);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        return FP_OK;
    }

    PRINT("StoreChar failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// Number of captures for enrollment
#define ENROLL_CAPTURE_COUNT    6

int fp_enroll_with_cb(uint16_t page_id, uint32_t timeout_ms, fp_progress_cb_t progress_cb)
{
    if (!fp_is_ready()) {
        return FP_ERR_FAIL;
    }

    if (page_id >= FP_MAX_TEMPLATES) {
        return FP_ERR_FAIL;
    }

    int ret;
    uint32_t per_capture_timeout = 10000;  // 10 seconds per capture
    (void)timeout_ms;

    PRINT("Enroll: %d captures to buffers 1-%d\n", ENROLL_CAPTURE_COUNT, ENROLL_CAPTURE_COUNT);

    for (int i = 1; i <= ENROLL_CAPTURE_COUNT; i++) {
        uint8_t buffer_id = i;  // Use buffers 1, 2, 3, 4, 5, 6

        PRINT("Enroll: waiting for finger (capture %d/%d)...\n", i, ENROLL_CAPTURE_COUNT);

        if (progress_cb) {
            progress_cb(FP_ENROLL_WAITING, i, ENROLL_CAPTURE_COUNT);
        }

        ret = fp_get_image(per_capture_timeout);
        if (ret != FP_OK) {
            PRINT("Enroll: capture %d timeout\n", i);
            return FP_ERR_TIMEOUT;
        }

        ret = fp_gen_char(buffer_id);
        if (ret != FP_OK) {
            PRINT("Enroll: gen char %d failed\n", i);
            return FP_ERR_FAIL;
        }

        PRINT("Enroll: capture %d OK (buffer %d)\n", i, buffer_id);

        if (progress_cb) {
            progress_cb(FP_ENROLL_CAPTURED, i, ENROLL_CAPTURE_COUNT);
        }

        if (i < ENROLL_CAPTURE_COUNT) {
            PRINT("Enroll: lift finger\n");

            if (progress_cb) {
                progress_cb(FP_ENROLL_LIFT_FINGER, i, ENROLL_CAPTURE_COUNT);
            }

            ret = fp_wait_finger_lift(5000);
            if (ret != FP_OK) {
                PRINT("Enroll: finger not lifted, continuing anyway\n");
            }

            DelayMs(200);
        }
    }

    // Merge all characteristics ONCE
    PRINT("Enroll: merging all %d captures...\n", ENROLL_CAPTURE_COUNT);

    if (progress_cb) {
        progress_cb(FP_ENROLL_PROCESSING, ENROLL_CAPTURE_COUNT, ENROLL_CAPTURE_COUNT);
    }

    ret = fp_reg_model();
    if (ret != FP_OK) {
        PRINT("Enroll: merge failed\n");
        return FP_ERR_FAIL;
    }

    // Store to flash
    PRINT("Enroll: storing to page %d...\n", page_id);

    ret = fp_store_char(1, page_id);
    if (ret != FP_OK) {
        PRINT("Enroll: store failed\n");
        return FP_ERR_FAIL;
    }

    PRINT("Enroll: SUCCESS at page %d\n", page_id);
    return FP_OK;
}

int fp_enroll(uint16_t page_id, uint32_t timeout_ms)
{
    return fp_enroll_with_cb(page_id, timeout_ms, NULL);
}

int fp_delete(uint16_t page_id, uint16_t count)
{
    if (!fp_is_ready()) {
        return FP_ERR_FAIL;
    }

    if (page_id >= FP_MAX_TEMPLATES || count == 0 || page_id + count > FP_MAX_TEMPLATES) {
        return FP_ERR_FAIL;
    }

    uint8_t params[4];
    params[0] = (page_id >> 8) & 0xFF;
    params[1] = page_id & 0xFF;
    params[2] = (count >> 8) & 0xFF;
    params[3] = count & 0xFF;

    fp_send_cmd(CMD_DELETE_CHAR, params, 4);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Deleted %d templates starting at %d\n", count, page_id);
        return FP_OK;
    }

    PRINT("Delete failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

int fp_clear_all(void)
{
    if (!fp_is_ready()) {
        return FP_ERR_FAIL;
    }

    fp_send_cmd(CMD_EMPTY, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, 3000);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("All templates cleared\n");
        return FP_OK;
    }

    PRINT("Clear all failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

int fp_cancel(void)
{
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    fp_send_cmd(CMD_CANCEL, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Operation cancelled\n");
        return FP_OK;
    }

    PRINT("Cancel response: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

int fp_sleep(void)
{
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    fp_send_cmd(CMD_SLEEP, NULL, 0);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Module entering sleep mode\n");
        return FP_OK;
    }

    PRINT("Sleep response: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

// ============================================================================
// LED Control
// ============================================================================

int fp_led_control(fp_led_mode_t mode, fp_led_color_t color, uint8_t speed, uint8_t cycles)
{
#if HAS_WS2812
    // Sync WS2812 with FP LED — color bits: bit0=B, bit1=G, bit2=R
    #define WS2812_BRIGHTNESS 51  // 20%
    if (mode == FP_LED_OFF || mode == FP_LED_FADE_OUT) {
        ws2812_set_rgb(0, 0, 0);
    } else {
        uint8_t r = (color & 0x04) ? WS2812_BRIGHTNESS : 0;
        uint8_t g = (color & 0x02) ? WS2812_BRIGHTNESS : 0;
        uint8_t b = (color & 0x01) ? WS2812_BRIGHTNESS : 0;
        ws2812_set_rgb(r, g, b);
    }
#endif

    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    // PS_ControlBLN (0x3C): control + mode + speed + color + cycles
    uint8_t params[4];
    params[0] = (uint8_t)mode;      // Control mode
    params[1] = speed;              // Speed (period, unit ~10ms)
    params[2] = (uint8_t)color;     // Color (bit0=blue, bit1=green, bit2=red)
    params[3] = cycles;             // Number of cycles (0 = infinite)

    fp_send_cmd(CMD_AURA_LED_CONFIG, params, 4);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        return FP_OK;
    }

    PRINT("LED control failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

int fp_led_on(fp_led_color_t color)
{
    return fp_led_control(FP_LED_ON, color, 0, 0);
}

int fp_led_off(void)
{
    return fp_led_control(FP_LED_OFF, FP_LED_WHITE, 0, 0);
}

int fp_led_breathe(fp_led_color_t color, uint8_t speed)
{
    return fp_led_control(FP_LED_BREATHING, color, speed, 0);
}

int fp_led_flash(fp_led_color_t color, uint8_t speed, uint8_t cycles)
{
    return fp_led_control(FP_LED_FLASHING, color, speed, cycles);
}

int fp_led_auto(bool enable)
{
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    uint8_t params[1] = { enable ? 0x01 : 0x00 };

    fp_send_cmd(CMD_AUTO_LED_CONTROL, params, 1);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Auto LED %s\n", enable ? "enabled" : "disabled");
        return FP_OK;
    }

    PRINT("Auto LED config failed: 0x%02X\n", ack);
    return FP_ERR_FAIL;
}

/******************************** endfile @ fingerprint ******************************/
