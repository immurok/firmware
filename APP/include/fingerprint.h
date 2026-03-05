/*
 * ZW3021 Fingerprint Module Driver for CH592F
 * UART protocol implementation
 */

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Constants
// ============================================================================

#define FP_MAX_TEMPLATES        29      // Maximum fingerprint templates (0-28)
#define FP_UART_BAUD            57600   // UART baud rate (8N2)

// Response buffer size
#define FP_RX_BUF_SIZE          128

// Confirmation codes (RBF[9])
#define FP_ACK_SUCCESS          0x00    // Command executed successfully
#define FP_ACK_PACKET_ERR       0x01    // Packet receive error
#define FP_ACK_NO_FINGER        0x02    // No finger detected / timeout
#define FP_ACK_ENROLL_FAIL      0x03    // Enrollment failed
#define FP_ACK_IMAGE_MESS       0x06    // Image too messy
#define FP_ACK_IMAGE_SMALL      0x07    // Image too small
#define FP_ACK_NOT_MATCH        0x08    // Finger not match
#define FP_ACK_NOT_FOUND        0x09    // Finger not found in library
#define FP_ACK_ENROLL_COMBINE   0x0A    // Enrollment combine error
#define FP_ACK_BAD_LOCATION     0x0B    // Invalid page ID
#define FP_ACK_DB_ERROR         0x0C    // Database error
#define FP_ACK_EMPTY_DB         0x23    // Database is empty

// Error codes (CH592 style)
#define FP_OK                   0
#define FP_ERR_TIMEOUT          -1
#define FP_ERR_NOT_FOUND        -2
#define FP_ERR_FAIL             -3
#define FP_ERR_INVALID          -4

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    uint16_t template_count;    // Number of stored templates
    uint16_t capacity;          // Maximum capacity
    uint8_t  security_level;    // Security level (1-5)
    uint32_t device_addr;       // Device address
    uint16_t packet_size;       // Data packet size
    uint16_t baud_setting;      // Baud rate setting
} fp_sys_params_t;

typedef struct {
    uint16_t page_id;           // Matched template ID
    uint16_t match_score;       // Match confidence score
} fp_search_result_t;

// Enrollment progress events
typedef enum {
    FP_ENROLL_WAITING = 0,      // Waiting for finger
    FP_ENROLL_CAPTURED = 1,     // Finger captured
    FP_ENROLL_PROCESSING = 2,   // Processing/merging
    FP_ENROLL_LIFT_FINGER = 3,  // Lift finger for next capture
} fp_enroll_event_t;

// LED control modes
typedef enum {
    FP_LED_BREATHING    = 0x01, // Breathing effect
    FP_LED_FLASHING     = 0x02, // Flashing effect
    FP_LED_ON           = 0x03, // Always on
    FP_LED_OFF          = 0x04, // Always off
    FP_LED_FADE_IN      = 0x05, // Gradual on
    FP_LED_FADE_OUT     = 0x06, // Gradual off
} fp_led_mode_t;

// LED colors (bit flags: bit0=blue, bit1=green, bit2=red)
typedef enum {
    FP_LED_BLUE         = 0x01, // Blue
    FP_LED_GREEN        = 0x02, // Green
    FP_LED_CYAN         = 0x03, // Cyan (blue + green)
    FP_LED_RED          = 0x04, // Red
    FP_LED_MAGENTA      = 0x05, // Magenta (red + blue)
    FP_LED_YELLOW       = 0x06, // Yellow (red + green)
    FP_LED_WHITE        = 0x07, // White (all colors)
} fp_led_color_t;

// Progress callback type
typedef void (*fp_progress_cb_t)(fp_enroll_event_t event, int capture, int total);

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize fingerprint module
 * - Configure UART1
 * - Power on module
 * - Wait for module ready
 *
 * @return FP_OK on success, error code otherwise
 */
int fp_init(void);

/**
 * Deinitialize fingerprint module
 */
void fp_deinit(void);

/**
 * Check if module is ready
 */
bool fp_is_ready(void);

/**
 * Send handshake command
 * @return FP_OK if module responds
 */
int fp_handshake(void);

// ============================================================================
// Fingerprint Operations
// ============================================================================

/**
 * Read system parameters
 * @param params Output structure
 * @return FP_OK on success
 */
int fp_read_sys_params(fp_sys_params_t *params);

/**
 * Get number of stored templates
 * @param count Output count
 * @return FP_OK on success
 */
int fp_get_template_count(uint16_t *count);

/**
 * Get fingerprint slot bitmap (which slots have templates)
 * @param bitmap Output bitmap (bit 0-4 for slots 0-4)
 * @return FP_OK on success
 */
int fp_get_fingerprint_bitmap(uint8_t *bitmap);

/**
 * Search for a fingerprint
 * @param result Output result
 * @param timeout_ms Timeout in milliseconds
 * @return FP_OK if found, FP_ERR_NOT_FOUND if not matched
 */
int fp_search(fp_search_result_t *result, uint32_t timeout_ms);

/**
 * Auto-identify fingerprint (single command)
 * @param result Output result
 * @return FP_OK if found
 */
int fp_auto_identify(fp_search_result_t *result);

/**
 * Enroll a new fingerprint
 * @param page_id Template ID to store
 * @param timeout_ms Timeout for each capture
 * @return FP_OK on success
 */
int fp_enroll(uint16_t page_id, uint32_t timeout_ms);

/**
 * Enroll with progress callback
 * @param page_id Template ID to store
 * @param timeout_ms Total timeout
 * @param progress_cb Progress callback
 * @return FP_OK on success
 */
int fp_enroll_with_cb(uint16_t page_id, uint32_t timeout_ms, fp_progress_cb_t progress_cb);

/**
 * Delete fingerprint template(s)
 * @param page_id Starting template ID
 * @param count Number to delete
 * @return FP_OK on success
 */
int fp_delete(uint16_t page_id, uint16_t count);

/**
 * Clear all fingerprint templates
 * @return FP_OK on success
 */
int fp_clear_all(void);

// ============================================================================
// Power Management
// ============================================================================

/**
 * Power on the fingerprint module
 */
void fp_power_on(void);

/**
 * Power off the fingerprint module
 */
void fp_power_off(void);

/**
 * Wake up fingerprint module for operation (blocking)
 * Powers on, waits for initialization, verifies password
 * @return FP_OK if ready, error code otherwise
 */
int fp_wake(void);

/**
 * Complete wake sequence after power-on delay (blocking version)
 * Called after fp_power_on() and delay has elapsed
 * Reads ready signal, verifies password
 * @return FP_OK if ready, error code otherwise
 */
int fp_complete_wake(void);

/**
 * Check if password has been verified
 */
bool fp_is_password_verified(void);

/**
 * Verify password with reduced timeout (watchdog-safe).
 * Reads ready signal, sends verify command, reads response in one call.
 * Max blocking: ~110ms (well under 557ms watchdog).
 * @return FP_OK if verified, error code otherwise
 */
int fp_start_verify(void);

/**
 * Check if module is currently powered on
 */
bool fp_is_powered(void);

/**
 * Cancel ongoing operation
 * @return FP_OK on success
 */
int fp_cancel(void);

/**
 * Put module into sleep mode
 * @return FP_OK on success
 */
int fp_sleep(void);

// ============================================================================
// Security
// ============================================================================

/**
 * Set module password
 * @param password 4-byte password
 * @return FP_OK on success
 */
int fp_set_password(uint32_t password);

/**
 * Verify module password
 * @param password Password to verify
 * @return FP_OK if correct
 */
int fp_verify_password(uint32_t password);

/**
 * Get device-derived password
 * @return Password derived from device MAC
 */
uint32_t fp_get_device_password(void);

// ============================================================================
// LED Control
// ============================================================================

/**
 * Control the RGB LED
 * @param mode LED mode
 * @param color LED color
 * @param speed Speed (0x00-0xFF)
 * @param cycles Number of cycles (0 = infinite)
 * @return FP_OK on success
 */
int fp_led_control(fp_led_mode_t mode, fp_led_color_t color, uint8_t speed, uint8_t cycles);

/**
 * Turn LED on with solid color
 */
int fp_led_on(fp_led_color_t color);

/**
 * Turn LED off
 */
int fp_led_off(void);

/**
 * Set LED to breathing mode
 */
int fp_led_breathe(fp_led_color_t color, uint8_t speed);

/**
 * Set LED to flashing mode
 */
int fp_led_flash(fp_led_color_t color, uint8_t speed, uint8_t cycles);

/**
 * Enable/disable automatic LED indication
 */
int fp_led_auto(bool enable);

#endif // FINGERPRINT_H
