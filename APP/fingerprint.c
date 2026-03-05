/*
 * ZW3021 Fingerprint Module Driver for CH592F
 * UART1 protocol implementation (PA9 TX, PA8 RX, 57600 8N2)
 * Ported from ESP32H2 implementation
 */

#include "CH59x_common.h"
#include "fingerprint.h"
#include <string.h>

// Use SDK PRINT macro (requires DEBUG defined)
#ifndef PRINT
#define PRINT(...)
#endif

// GPIO pin definitions (direct values to avoid include order issues)
// UART1: PA9 (TXD1), PA8 (RXD1)
#define FP_PIN_TX       (0x00000200)    // PA9 - UART1 TX, GPIO_Pin_9
#define FP_PIN_RX       (0x00000100)    // PA8 - UART1 RX, GPIO_Pin_8
#define FP_PIN_PWR      (0x00001000)    // PA12 - Power control, GPIO_Pin_12
#define FP_PIN_INT      (0x00002000)    // PA13 - Touch INT, GPIO_Pin_13

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

// Password Salt (for device-specific password derivation)
#define FP_SALT_HIGH    0xAAAAAAAAUL
#define FP_SALT_LOW     0x55555555UL

// Timeouts
#define UART_TIMEOUT_MS         200
#define INIT_TIMEOUT_MS         200
#define HANDSHAKE_TIMEOUT_MS    3000
#define QUICK_READY_TIMEOUT_MS  100

// ============================================================================
// State
// ============================================================================

static bool s_powered_on = false;
static uint32_t s_power_on_tick = 0;  // RTC tick at power-on (for timing measurement)
static bool s_initialized = false;
static bool s_password_verified = false;
static uint32_t s_cached_password = 0;
static bool s_password_cached = false;
static uint32_t s_module_addr = FP_DEFAULT_ADDR;
static uint8_t s_rx_buf[FP_RX_BUF_SIZE];

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
    GPIOA_SetBits(FP_PIN_TX);
    GPIOA_ModeCfg(FP_PIN_TX, GPIO_ModeOut_PP_5mA);  // PA9 TX
    GPIOA_ModeCfg(FP_PIN_RX, GPIO_ModeIN_PU);       // PA8 RX

    UART1_DefInit();
    UART1_BaudRateCfg(FP_UART_BAUD);
    // 8N2: 1 start bit, 8 data bits, no parity, 2 stop bits
    R8_UART1_LCR |= RB_LCR_STOP_BIT;

    PRINT("UART1 initialized: %d baud, 8N2\n", FP_UART_BAUD);
}

static void uart_send(const uint8_t *data, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        while ((R8_UART1_LSR & RB_LSR_TX_FIFO_EMP) == 0);
        R8_UART1_THR = data[i];
    }
}

static int uart_recv(uint8_t *data, uint16_t max_len, uint32_t timeout_ms)
{
    uint16_t count = 0;
    uint32_t timeout_loops = timeout_ms * 6000;
    uint32_t gap_timeout_loops = 10 * 6000;  // 10ms gap timeout after first byte
    uint32_t idle_count = 0;

    while (count < max_len) {
        if (R8_UART1_RFC > 0) {
            data[count++] = R8_UART1_RBR;
            idle_count = 0;
        } else {
            idle_count++;
            uint32_t limit = (count > 0) ? gap_timeout_loops : timeout_loops;
            if (idle_count >= limit) {
                break;
            }
        }
    }

    return count;
}

static void uart_flush(void)
{
    while (R8_UART1_RFC > 0) {
        (void)R8_UART1_RBR;
    }
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

int fp_send_cmd(uint8_t cmd, const uint8_t *params, uint16_t param_len)
{
    uint8_t packet[64];
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

    // Flush RX and send
    uart_flush();
    uart_send(packet, len);

    return FP_OK;
}

int fp_recv_ack(uint8_t *ack_code, uint8_t *params, uint16_t *param_len, uint32_t timeout_ms)
{
    // Read packet
    int recv_len = uart_recv(s_rx_buf, FP_RX_BUF_SIZE, timeout_ms);
    if (recv_len < 12) {
        return FP_ERR_TIMEOUT;
    }

    // Verify header
    if (s_rx_buf[0] != FP_HEADER_1 || s_rx_buf[1] != FP_HEADER_2) {
        return FP_ERR_FAIL;
    }

    // Verify packet type
    if (s_rx_buf[6] != FP_ACK_PACKET) {
        return FP_ERR_FAIL;
    }

    // Get length
    uint16_t pkt_len = (s_rx_buf[7] << 8) | s_rx_buf[8];

    // Get ACK code
    *ack_code = s_rx_buf[9];

    // Get parameters (if any)
    if (param_len && params && pkt_len > 3) {
        *param_len = pkt_len - 3;  // Subtract ack_code + checksum
        memcpy(params, &s_rx_buf[10], *param_len);
    }

    return FP_OK;
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
}

// ============================================================================
// Power Control
// ============================================================================

void fp_power_on(void)
{
    if (s_powered_on) return;

    // Re-enable UART1 clock (was gated in fp_power_off)
    sys_safe_access_enable();
    R8_SLP_CLK_OFF0 &= ~RB_SLP_CLK_UART1;
    sys_safe_access_disable();
    // Re-initialize UART1 pins (were set to pull-down in fp_power_off)
    uart_init();
    GPIOA_ModeCfg(FP_PIN_PWR, GPIO_ModeOut_PP_5mA);
    GPIOA_SetBits(FP_PIN_PWR);
    s_powered_on = true;
    s_power_on_tick = RTC_GetCycle32k();
    PRINT("Fingerprint power ON\n");
}

void fp_power_off(void)
{
    if (!s_powered_on) return;

    GPIOA_ResetBits(FP_PIN_PWR);
    // All FP pins to pull-down: prevent current leaking through
    // powered-off module's ESD protection diodes
    GPIOA_ModeCfg(FP_PIN_PWR | FP_PIN_TX | FP_PIN_RX, GPIO_ModeIN_PD);
    // Gate UART1 clock to eliminate peripheral static power
    sys_safe_access_enable();
    R8_SLP_CLK_OFF0 |= RB_SLP_CLK_UART1;
    sys_safe_access_disable();
    s_powered_on = false;
    s_password_verified = false;  // Need to re-verify after power on
    PRINT("Fingerprint power OFF\n");
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
        while (R8_UART1_RFC > 0) {
            uint8_t b = R8_UART1_RBR;
            if (b == 0x55) {
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
    } else {
        PRINT("Module 0x55 NOT received (complete_wake)\n");
    }

    // Verify password if not yet verified
    if (!s_password_verified) {
        // Try default password first
        int ret = fp_verify_password(0x00000000);
        if (ret == FP_OK) {
            PRINT("Default password OK (complete_wake)\n");
            s_password_verified = true;
        } else {
            // Fallback to device-specific password
            if (!s_password_cached) {
                s_cached_password = fp_get_device_password();
                s_password_cached = true;
            }
            ret = fp_verify_password(s_cached_password);
            if (ret == FP_OK) {
                PRINT("Device password OK, resetting to default...\n");
                fp_set_password(0x00000000);
                s_password_verified = true;
            } else {
                PRINT("Password verify failed: %d\n", ret);
                return ret;
            }
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

    // Try default password (0x00000000) first — fastest path
    int ret = fp_verify_password(0x00000000);
    if (ret == FP_OK) {
        PRINT("Default password OK\n");
        s_password_verified = true;
        return FP_OK;
    }

    // Default failed — try device-specific password
    if (!s_password_cached) {
        s_cached_password = fp_get_device_password();
        s_password_cached = true;
    }

    ret = fp_verify_password(s_cached_password);
    if (ret == FP_OK) {
        PRINT("Device password OK, resetting to default...\n");
        fp_set_password(0x00000000);
        s_password_verified = true;
        return FP_OK;
    }

    PRINT("All passwords failed in start_verify\n");
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

        // Wait for module initialization (100ms - reduced to avoid BLE timeout)
        DelayMs(100);

        // Try to read ready signal (0x55)
        bool got_ready = false;
        for (int i = 0; i < 10; i++) {
            while (R8_UART1_RFC > 0) {
                uint8_t b = R8_UART1_RBR;
                if (b == 0x55) {
                    got_ready = true;
                    break;
                }
            }
            if (got_ready) break;
            DelayMs(10);
        }

        // Flush any remaining data
        uart_flush();

        if (got_ready) {
            PRINT("Module ready signal received\n");
        }
    }

    // Verify password if not yet verified
    if (!s_password_verified) {
        int ret = fp_verify_password(0x00000000);
        if (ret == FP_OK) {
            PRINT("Default password OK (wake)\n");
            s_password_verified = true;
        } else {
            if (!s_password_cached) {
                s_cached_password = fp_get_device_password();
                s_password_cached = true;
            }
            ret = fp_verify_password(s_cached_password);
            if (ret == FP_OK) {
                PRINT("Device password OK, resetting to default...\n");
                fp_set_password(0x00000000);
                s_password_verified = true;
            } else {
                PRINT("Password verify failed: %d\n", ret);
                return ret;
            }
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
            DelayMs(150);  // Minimal boot delay

            // Read for ready signal FIRST (before any flush)
            uint8_t init_buf[16];
            bool got_ready = false;

            for (int i = 0; i < 10; i++) {
                while (R8_UART1_RFC > 0) {
                    uint8_t b = R8_UART1_RBR;
                    if (b == 0x55) {
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

        // Verify password if not yet verified
        if (!s_password_verified) {
            ret = fp_verify_password(0x00000000);
            if (ret == FP_OK) {
                PRINT("Default password OK (init fast path)\n");
                s_password_verified = true;
            } else {
                if (!s_password_cached) {
                    s_cached_password = fp_get_device_password();
                    s_password_cached = true;
                }
                ret = fp_verify_password(s_cached_password);
                if (ret == FP_OK) {
                    PRINT("Device password OK, resetting to default...\n");
                    fp_set_password(0x00000000);
                    s_password_verified = true;
                } else {
                    PRINT("Password verify failed\n");
                }
            }
        }
        return FP_OK;
    }

    PRINT("Initializing fingerprint module...\n");

    // Power on module BEFORE configuring UART
    fp_power_on();

    // Initialize UART
    uart_init();

    // Wait for module initialization signal (0x55)
    DelayMs(100);

    uint8_t init_buf[32];
    int total_read = 0;
    bool got_ready = false;

    for (int retry = 0; retry < (INIT_TIMEOUT_MS / 50); retry++) {
        while (R8_UART1_RFC > 0 && total_read < sizeof(init_buf)) {
            init_buf[total_read] = R8_UART1_RBR;
            if (init_buf[total_read] == 0x55) {
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

    // Setup password protection FIRST (before other commands)
    ret = setup_password_protection();
    if (ret != FP_OK) {
        PRINT("Password protection setup failed\n");
        // Don't fail init - module may work without password
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

uint32_t fp_get_device_password(void)
{
    // Get device MAC address (use chip unique ID as substitute)
    uint8_t mac[6];

    // CH592F unique ID is at 0x7F018
    uint8_t *uid = (uint8_t *)0x7F018;
    memcpy(mac, uid, 6);

    // Build password from salt + MAC using simple XOR mixing (same as ESP32)
    uint32_t password = FP_SALT_HIGH ^ FP_SALT_LOW;
    password ^= ((uint32_t)mac[0] << 24) | ((uint32_t)mac[1] << 16) |
                ((uint32_t)mac[2] << 8)  | ((uint32_t)mac[3]);
    password ^= ((uint32_t)mac[4] << 8)  | ((uint32_t)mac[5]);
    password = (password * 0x9E3779B9) ^ (password >> 16);  // Simple hash mixing

    PRINT("Device password derived\n");
    return password;
}

int fp_set_password(uint32_t password)
{
    if (!s_powered_on) {
        return FP_ERR_FAIL;
    }

    uint8_t params[4];
    params[0] = (password >> 24) & 0xFF;
    params[1] = (password >> 16) & 0xFF;
    params[2] = (password >> 8) & 0xFF;
    params[3] = password & 0xFF;

    fp_send_cmd(CMD_SET_PWD, params, 4);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        PRINT("Password set successfully\n");
        return FP_OK;
    }

    PRINT("Set password failed: 0x%02X\n", ack);
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

// Setup password protection (called from fp_init)
// Strategy: use default password (0x00000000) for fast wake-up.
// If module has a non-default password, reset it to default.
static int setup_password_protection(void)
{
    int ret;

    // Try default password first — this is the target state
    PRINT("Verifying default password...\n");
    ret = fp_verify_password(0x00000000);
    if (ret == FP_OK) {
        PRINT("Default password OK\n");
        return FP_OK;
    }

    // Try device-specific password — module may have been set previously
    uint32_t password = fp_get_device_password();
    PRINT("Trying device password...\n");
    ret = fp_verify_password(password);
    if (ret == FP_OK) {
        PRINT("Device password OK, resetting to default...\n");
        fp_set_password(0x00000000);
        return FP_OK;
    }

    // Try some old test passwords
    PRINT("Trying old test passwords...\n");

    // Old algorithm: simple XOR
    uint8_t *uid = (uint8_t *)0x7F018;
    uint32_t old_pwd = ((uint32_t)uid[2] << 24) | ((uint32_t)uid[3] << 16) |
                       ((uint32_t)uid[4] << 8) | (uint32_t)uid[5];
    old_pwd ^= 0xA5A5A5A5;
    old_pwd = ((old_pwd << 13) | (old_pwd >> 19)) ^ 0x5A5A5A5A;

    ret = fp_verify_password(old_pwd);
    if (ret == FP_OK) {
        PRINT("Old password OK, resetting to default...\n");
        fp_set_password(0x00000000);
        return FP_OK;
    }

    // Try passwords from other chips that may have locked this sensor
    {
        static const uint32_t other_chip_passwords[] = {
            0x4C4FBE82,  // legacy chip password (current algo)
            0xD06B3942,  // legacy chip password (old algo)
        };
        int n = sizeof(other_chip_passwords) / sizeof(other_chip_passwords[0]);
        for (int i = 0; i < n; i++) {
            PRINT("Trying other chip password [%d/%d]: 0x%08X\n", i + 1, n, other_chip_passwords[i]);
            ret = fp_verify_password(other_chip_passwords[i]);
            if (ret == FP_OK) {
                PRINT("Other chip password matched! Resetting to default...\n");
                fp_set_password(0x00000000);
                return FP_OK;
            }
        }
    }

    PRINT("All password attempts failed\n");
    // Continue anyway - module may not require password for basic ops
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

int fp_get_fingerprint_bitmap(uint8_t *bitmap)
{
    if (!fp_is_ready() || !bitmap) {
        return FP_ERR_FAIL;
    }

    // CMD_READ_INDEX_TAB (0x1F) reads index table
    // Parameter: page number (0-3), each page covers 256 templates
    // For immurok we only need page 0 (slots 0-4)
    uint8_t params[1] = { 0 };  // Page 0

    fp_send_cmd(CMD_READ_INDEX_TAB, params, 1);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, UART_TIMEOUT_MS);
    if (ret != FP_OK) {
        return ret;
    }
    if (ack != FP_ACK_SUCCESS) {
        PRINT("Read index table failed: 0x%02X\n", ack);
        return FP_ERR_FAIL;
    }

    // Response contains 32 bytes of bitmap (256 bits for 256 templates)
    // Each bit represents whether a template exists at that slot
    // For immurok, we only care about bits 0-4 (slots 0-4)
    // The bitmap is in s_rx_buf[10..41], first byte covers slots 0-7
    *bitmap = s_rx_buf[10] & 0x1F;  // Only keep bits 0-4 (max 5 fingerprints)

    PRINT("Fingerprint bitmap: 0x%02X\n", *bitmap);

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

    // PS_AutoIdentify (0x32): Auto capture + generate + search
    // Parameters: buffer_id(1) + start_page(2) + count(2) + security_level(1) + return_mask(1)
    uint8_t params[7];
    params[0] = 0x01;                   // Buffer ID
    params[1] = 0x00;                   // Start page MSB
    params[2] = 0x00;                   // Start page LSB
    params[3] = 0x00;                   // Search count MSB
    params[4] = FP_MAX_TEMPLATES;       // Search count LSB
    params[5] = 0x03;                   // Security level (3 = medium)
    params[6] = 0x00;                   // Return on match only

    fp_send_cmd(CMD_AUTO_IDENTIFY, params, 7);

    uint8_t ack;
    int ret = fp_recv_ack(&ack, NULL, NULL, 3000);  // 3 second timeout
    if (ret != FP_OK) {
        return ret;
    }

    if (ack == FP_ACK_SUCCESS) {
        result->page_id = (s_rx_buf[10] << 8) | s_rx_buf[11];
        result->match_score = (s_rx_buf[12] << 8) | s_rx_buf[13];
        PRINT("AutoIdentify: page=%d, score=%d\n", result->page_id, result->match_score);
        return FP_OK;
    } else if (ack == FP_ACK_NOT_FOUND || ack == FP_ACK_NOT_MATCH) {
        PRINT("AutoIdentify: no match\n");
        return FP_ERR_NOT_FOUND;
    } else if (ack == FP_ACK_NO_FINGER) {
        PRINT("AutoIdentify: no finger detected\n");
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
