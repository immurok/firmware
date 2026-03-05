/*
 * immurok Custom GATT Service for CH592F
 * Service UUID: 12340010-0000-1000-8000-00805f9b34fb
 * Command Characteristic: 12340011 (Write)
 * Response Characteristic: 12340012 (Notify)
 */

#include "CONFIG.h"
#include "immurokservice.h"

// immurok Service UUID: 12340010-0000-1000-8000-00805f9b34fb
static const uint8_t immurokServUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x34, 0x12
};

// Command Characteristic UUID: 12340011
static const uint8_t immurokCmdUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x11, 0x00, 0x34, 0x12
};

// Response Characteristic UUID: 12340012
static const uint8_t immurokRspUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x12, 0x00, 0x34, 0x12
};

// Service declaration
static const gattAttrType_t immurokService = {ATT_UUID_SIZE, immurokServUUID};

// Command characteristic
static uint8_t immurokCmdProps = GATT_PROP_WRITE;
static uint8_t immurokCmdValue[IMMUROK_CMD_MAX_LEN] = {0};

// Response characteristic
static uint8_t immurokRspProps = GATT_PROP_READ | GATT_PROP_NOTIFY;
static uint8_t immurokRspValue[IMMUROK_RSP_MAX_LEN] = {0};
static gattCharCfg_t immurokRspCCC[GATT_MAX_NUM_CONN];

// Attribute table
static gattAttribute_t immurokAttrTbl[] = {
    // immurok Service
    {
        {ATT_BT_UUID_SIZE, primaryServiceUUID},
        GATT_PERMIT_READ,
        0,
        (uint8_t *)&immurokService
    },

    // Command Characteristic Declaration
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &immurokCmdProps
    },
    // Command Characteristic Value
    {
        {ATT_UUID_SIZE, immurokCmdUUID},
        GATT_PERMIT_WRITE,
        0,
        immurokCmdValue
    },

    // Response Characteristic Declaration
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &immurokRspProps
    },
    // Response Characteristic Value
    {
        {ATT_UUID_SIZE, immurokRspUUID},
        GATT_PERMIT_READ,
        0,
        immurokRspValue
    },
    // Response Characteristic CCC
    {
        {ATT_BT_UUID_SIZE, clientCharCfgUUID},
        GATT_PERMIT_READ | GATT_PERMIT_WRITE,
        0,
        (uint8_t *)immurokRspCCC
    },
};

// Service callbacks
static immurokServiceCBs_t *immurokServiceCBs = NULL;

// Connection handle for notifications
static uint16_t immurokConnHandle = INVALID_CONNHANDLE;

/*********************************************************************
 * @fn      immurok_ReadAttrCB
 * @brief   Read an attribute.
 */
static bStatus_t immurok_ReadAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                     uint8_t *pValue, uint16_t *pLen, uint16_t offset,
                                     uint16_t maxLen, uint8_t method)
{
    bStatus_t status = SUCCESS;
    uint16_t uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);

    if(pAttr->type.len == ATT_UUID_SIZE) {
        // 128-bit UUID - Response characteristic
        if(tmos_memcmp(pAttr->type.uuid, immurokRspUUID, ATT_UUID_SIZE)) {
            *pLen = 1;
            pValue[0] = immurokRspValue[0];
        } else {
            *pLen = 0;
            status = ATT_ERR_ATTR_NOT_FOUND;
        }
    } else {
        // 16-bit UUID
        *pLen = 0;
        status = ATT_ERR_ATTR_NOT_FOUND;
    }

    return status;
}

/*********************************************************************
 * @fn      immurok_WriteAttrCB
 * @brief   Validate attribute data prior to a write operation
 */
static bStatus_t immurok_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                      uint8_t *pValue, uint16_t len, uint16_t offset,
                                      uint8_t method)
{
    bStatus_t status = SUCCESS;

    if(pAttr->type.len == ATT_UUID_SIZE) {
        // 128-bit UUID - Command characteristic
        if(tmos_memcmp(pAttr->type.uuid, immurokCmdUUID, ATT_UUID_SIZE)) {
            if(len > IMMUROK_CMD_MAX_LEN) {
                status = ATT_ERR_INVALID_VALUE_SIZE;
            } else {
                // Copy command data
                tmos_memcpy(immurokCmdValue, pValue, len);

                // Notify application
                if(immurokServiceCBs && immurokServiceCBs->pfnCommandCB) {
                    immurokServiceCBs->pfnCommandCB(connHandle, pValue, len);
                }
            }
        } else {
            status = ATT_ERR_ATTR_NOT_FOUND;
        }
    } else if(pAttr->type.len == ATT_BT_UUID_SIZE) {
        uint16_t uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);
        if(uuid == GATT_CLIENT_CHAR_CFG_UUID) {
            // CCC write
            status = GATTServApp_ProcessCCCWriteReq(connHandle, pAttr, pValue, len,
                                                     offset, GATT_CLIENT_CFG_NOTIFY);
        } else {
            status = ATT_ERR_ATTR_NOT_FOUND;
        }
    }

    return status;
}

// GATT Service Callbacks
static gattServiceCBs_t immurokServiceCBsStruct = {
    immurok_ReadAttrCB,
    immurok_WriteAttrCB,
    NULL
};

/*********************************************************************
 * @fn      ImmurokService_AddService
 * @brief   Add the immurok service to GATT
 */
bStatus_t ImmurokService_AddService(void)
{
    uint8_t status;

    // Initialize CCC
    GATTServApp_InitCharCfg(INVALID_CONNHANDLE, immurokRspCCC);

    // Register service
    status = GATTServApp_RegisterService(immurokAttrTbl,
                                          GATT_NUM_ATTRS(immurokAttrTbl),
                                          GATT_MAX_ENCRYPT_KEY_SIZE,
                                          &immurokServiceCBsStruct);

    PRINT("immurok service registered: %d\n", status);
    return status;
}

/*********************************************************************
 * @fn      ImmurokService_RegisterAppCBs
 * @brief   Register application callbacks
 */
bStatus_t ImmurokService_RegisterAppCBs(immurokServiceCBs_t *appCBs)
{
    if(appCBs) {
        immurokServiceCBs = appCBs;
        return SUCCESS;
    }
    return FAILURE;
}

/*********************************************************************
 * @fn      ImmurokService_SetConnHandle
 * @brief   Set the connection handle for notifications
 */
void ImmurokService_SetConnHandle(uint16_t connHandle)
{
    immurokConnHandle = connHandle;
}

/*********************************************************************
 * @fn      ImmurokService_SendResponse
 * @brief   Send response notification
 */
bStatus_t ImmurokService_SendResponse(uint8_t *pData, uint8_t len)
{
    if(immurokConnHandle == INVALID_CONNHANDLE) {
        return FAILURE;
    }

    // Debug: print response data
    PRINT("TX[%d]: ", len);
    for(int i = 0; i < len; i++) {
        PRINT("%02X ", pData[i]);
    }
    PRINT("\n");

    // Check if notifications are enabled
    uint16_t value = GATTServApp_ReadCharCfg(immurokConnHandle, immurokRspCCC);
    if(!(value & GATT_CLIENT_CFG_NOTIFY)) {
        PRINT("TX DROPPED: CCC notify not enabled\n");
        return FAILURE;
    }
    {
        // Copy data to response value
        if(len > IMMUROK_RSP_MAX_LEN) {
            len = IMMUROK_RSP_MAX_LEN;
        }
        tmos_memcpy(immurokRspValue, pData, len);

        // Send notification
        attHandleValueNoti_t noti;
        noti.handle = immurokAttrTbl[IMMUROK_RSP_VALUE_IDX].handle;
        noti.len = len;
        noti.pValue = GATT_bm_alloc(immurokConnHandle, ATT_HANDLE_VALUE_NOTI, len, NULL, 0);
        if(noti.pValue) {
            tmos_memcpy(noti.pValue, pData, len);
            bStatus_t status = GATT_Notification(immurokConnHandle, &noti, FALSE);
            if(status != SUCCESS) {
                PRINT("GATT_Notification FAILED: 0x%02X\n", status);
                GATT_bm_free((gattMsg_t *)&noti, ATT_HANDLE_VALUE_NOTI);
            }
            return status;
        }
        return bleMemAllocError;
    }

    return FAILURE;
}

/*********************************************************************
 * @fn      ImmurokService_HandleConnStatusCB
 * @brief   Handle connection status changes
 */
void ImmurokService_HandleConnStatusCB(uint16_t connHandle, uint8_t changeType)
{
    if(changeType == LINKDB_STATUS_UPDATE_REMOVED ||
       (changeType == LINKDB_STATUS_UPDATE_STATEFLAGS && !linkDB_Up(connHandle))) {
        // Connection terminated
        GATTServApp_InitCharCfg(connHandle, immurokRspCCC);
        if(immurokConnHandle == connHandle) {
            immurokConnHandle = INVALID_CONNHANDLE;
        }
    }
}
