/*
 * immurok Custom GATT Service Header
 * v2.0 - Simplified protocol (no pairing, fingerprint-gated writes)
 */

#ifndef IMMUROKSERVICE_H
#define IMMUROKSERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "CONFIG.h"

// Maximum lengths
#define IMMUROK_CMD_MAX_LEN     64
#define IMMUROK_RSP_MAX_LEN     64

// Attribute indices
#define IMMUROK_SERVICE_IDX     0
#define IMMUROK_CMD_DECL_IDX    1
#define IMMUROK_CMD_VALUE_IDX   2
#define IMMUROK_RSP_DECL_IDX    3
#define IMMUROK_RSP_VALUE_IDX   4
#define IMMUROK_RSP_CCC_IDX     5

// Command codes (v3.0 protocol — ECDH pairing)
#define IMMUROK_CMD_GET_STATUS      0x01
#define IMMUROK_CMD_ENROLL_START    0x10
#define IMMUROK_CMD_DELETE_FP       0x12
#define IMMUROK_CMD_FP_LIST         0x13
#define IMMUROK_CMD_FP_MATCH_ACK    0x22
#define IMMUROK_CMD_PAIR_INIT       0x30
#define IMMUROK_CMD_PAIR_CONFIRM    0x31
#define IMMUROK_CMD_PAIR_STATUS     0x32
#define IMMUROK_CMD_AUTH_REQUEST    0x33
#define IMMUROK_CMD_FACTORY_RESET   0x36

// Keystore commands
#define IMMUROK_CMD_KEY_COUNT      0x60
#define IMMUROK_CMD_KEY_READ       0x61
#define IMMUROK_CMD_KEY_WRITE      0x62
#define IMMUROK_CMD_KEY_DELETE     0x63
#define IMMUROK_CMD_KEY_COMMIT     0x64

// SSH crypto commands
#define IMMUROK_CMD_KEY_SIGN       0x65  // ECDSA sign (FP gated)
#define IMMUROK_CMD_KEY_GETPUB     0x66  // Get public key from private
#define IMMUROK_CMD_KEY_GENERATE   0x67  // Generate keypair (FP gated)
#define IMMUROK_CMD_KEY_RESULT     0x68  // Read result buffer (chunked)
#define IMMUROK_CMD_KEY_OTP_GET   0x69  // TOTP compute on-device (FP gated)

// Response codes
#define IMMUROK_RSP_OK              0x00
#define IMMUROK_RSP_WAIT_FP         0x11
#define IMMUROK_RSP_BUSY            0xFD
#define IMMUROK_RSP_INVALID_PARAM   0xFE
#define IMMUROK_RSP_UNKNOWN_CMD     0xFF

// Callback function types
typedef void (*immurokCommandCB_t)(uint16_t connHandle, uint8_t *pData, uint8_t len);

// Callback structure
typedef struct {
    immurokCommandCB_t pfnCommandCB;    // Command received callback
} immurokServiceCBs_t;

/*********************************************************************
 * API Functions
 */

/**
 * @fn      ImmurokService_AddService
 * @brief   Add the immurok service to GATT server
 * @return  SUCCESS or error code
 */
bStatus_t ImmurokService_AddService(void);

/**
 * @fn      ImmurokService_RegisterAppCBs
 * @brief   Register application callbacks
 * @param   appCBs - pointer to callback structure
 * @return  SUCCESS or FAILURE
 */
bStatus_t ImmurokService_RegisterAppCBs(immurokServiceCBs_t *appCBs);

/**
 * @fn      ImmurokService_SetConnHandle
 * @brief   Set the connection handle for notifications
 * @param   connHandle - connection handle
 */
void ImmurokService_SetConnHandle(uint16_t connHandle);

/**
 * @fn      ImmurokService_SendResponse
 * @brief   Send response notification to host
 * @param   pData - response data
 * @param   len - data length
 * @return  SUCCESS or error code
 */
bStatus_t ImmurokService_SendResponse(uint8_t *pData, uint8_t len);

/**
 * @fn      ImmurokService_HandleConnStatusCB
 * @brief   Handle connection status changes
 * @param   connHandle - connection handle
 * @param   changeType - type of change
 */
void ImmurokService_HandleConnStatusCB(uint16_t connHandle, uint8_t changeType);

#ifdef __cplusplus
}
#endif

#endif /* IMMUROKSERVICE_H */
