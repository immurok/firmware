/*
 * immurok Custom GATT Service for CH592F
 * Service UUID:  45529919-7668-48f9-b9fe-e4eabe6595d9
 * Command Char:  8a537e1f-3992-4b2c-8b77-8d4e778186e1 (Write)
 * Response Char: 76a1660d-8cf6-44d1-b3fc-70486028e289 (Notify)
 *
 * UUIDs are stored little-endian (BLE wire format).
 */

#include "CONFIG.h"
#include "immurokservice.h"

// immurok Service UUID: 45529919-7668-48f9-b9fe-e4eabe6595d9
static const uint8_t immurokServUUID[ATT_UUID_SIZE] = {
    0xd9, 0x95, 0x65, 0xbe, 0xea, 0xe4, 0xfe, 0xb9,
    0xf9, 0x48, 0x68, 0x76, 0x19, 0x99, 0x52, 0x45
};

// Command Characteristic UUID: 8a537e1f-3992-4b2c-8b77-8d4e778186e1
static const uint8_t immurokCmdUUID[ATT_UUID_SIZE] = {
    0xe1, 0x86, 0x81, 0x77, 0x4e, 0x8d, 0x77, 0x8b,
    0x2c, 0x4b, 0x92, 0x39, 0x1f, 0x7e, 0x53, 0x8a
};

// Response Characteristic UUID: 76a1660d-8cf6-44d1-b3fc-70486028e289
static const uint8_t immurokRspUUID[ATT_UUID_SIZE] = {
    0x89, 0xe2, 0x28, 0x60, 0x48, 0x70, 0xfc, 0xb3,
    0xd1, 0x44, 0xf6, 0x8c, 0x0d, 0x66, 0xa1, 0x76
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
    // ENCRYPT_WRITE: only a peer with a valid bond (and thus an encrypted
    // link) can write commands. Combined with NO_PAIRING after device is
    // claimed, this stops a thief on host B from connecting and driving
    // the immurok service without bonding.
    {
        {ATT_UUID_SIZE, immurokCmdUUID},
        GATT_PERMIT_ENCRYPT_WRITE,
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
    // ENCRYPT_READ: stale response bytes (and any future direct READ payload)
    // shouldn't leak to an unbonded peer.
    {
        {ATT_UUID_SIZE, immurokRspUUID},
        GATT_PERMIT_ENCRYPT_READ,
        0,
        immurokRspValue
    },
    // Response Characteristic CCC
    // ENCRYPT_WRITE on the descriptor stops an unbonded peer from
    // subscribing to notifications (FP match, AUTH OK, etc.).
    {
        {ATT_BT_UUID_SIZE, clientCharCfgUUID},
        GATT_PERMIT_READ | GATT_PERMIT_ENCRYPT_WRITE,
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
            if(status == SUCCESS && immurokServiceCBs && immurokServiceCBs->pfnCccChangeCB) {
                uint16_t cccValue = BUILD_UINT16(pValue[0], (len > 1) ? pValue[1] : 0);
                immurokServiceCBs->pfnCccChangeCB((cccValue & GATT_CLIENT_CFG_NOTIFY) ? 1 : 0);
            }
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
#ifdef TMOS_NESTED_DIAG
#include "immurok_scratch.h"
#define RSP_FAIL(st) do { if(g_nest_diag.rsp_fail != 0xFF) g_nest_diag.rsp_fail++; \
                          g_nest_diag.rsp_fail_status = (uint8_t)(st); } while(0)
#define RSP_COUNT(field) do { if(g_nest_diag.field != 0xFF) g_nest_diag.field++; } while(0)
#else
#define RSP_FAIL(st) do { } while(0)
#define RSP_COUNT(field) do { } while(0)
#endif

/*
 * 待重发的应答（2026-11-26）。
 *
 * 协议栈的发送队列只有 4 条，而且一个事件处理函数里排进去的包要等它返回主循环才发得
 * 出去。「主动触摸」会排进 3 条唤醒按键 + 1 条匹配通知，正好排满；触摸处理期间到达的
 * 命令，应答是第 5 条，GATT_Notification 回 blePending。原来发一次就算，这条应答就丢了：
 * 命令其实已经执行，主机却等到超时（真机压力测试 421 条命令里丢了 14 条）。
 *
 * 现在发不出去就留着：数据本来就在 immurokRspValue 里，只多记一个长度和一个剩余次数。
 * 由应用层的事件每 10ms 调 ImmurokService_FlushPending() 重发，直到发出、次数用完或断连。
 * 只有一个槽位：槽里有东西时新的应答先等它发掉（保证先后顺序），它还发不掉就说明队列
 * 仍是满的，新的这条丢弃。RAM 只剩几十字节，放不下队列；命令是一问一答的，同一时刻
 * 最多一条命令应答待发，一个槽位覆盖得了实测到的情形。
 *
 * 次数上限 2.5s：主机等应答的超时是 5s，再晚到的应答会被主机配给下一条命令。
 */
#define RSP_RETRY_MAX   250
static uint8_t s_rsp_pending_len = 0;   // 非 0：immurokRspValue 里那条还没发出去
static uint8_t s_rsp_retry_left = 0;

static uint8_t rsp_link_ready(void)
{
    if(immurokConnHandle == INVALID_CONNHANDLE)
        return 0;
    return (GATTServApp_ReadCharCfg(immurokConnHandle, immurokRspCCC) & GATT_CLIENT_CFG_NOTIFY) != 0;
}

static uint8_t rsp_retryable(bStatus_t status)
{
    return status == blePending || status == bleNoResources ||
           status == bleMemAllocError || status == MSG_BUFFER_NOT_AVAIL;
}

static bStatus_t rsp_send_raw(const uint8_t *pData, uint8_t len)
{
    attHandleValueNoti_t noti;
    bStatus_t status;

    noti.handle = immurokAttrTbl[IMMUROK_RSP_VALUE_IDX].handle;
    noti.len = len;
    noti.pValue = GATT_bm_alloc(immurokConnHandle, ATT_HANDLE_VALUE_NOTI, len, NULL, 0);
    if(!noti.pValue)
        return bleMemAllocError;
    tmos_memcpy(noti.pValue, pData, len);
    status = GATT_Notification(immurokConnHandle, &noti, FALSE);
    if(status != SUCCESS) {
        PRINT("GATT_Notification FAILED: 0x%02X\n", status);
        GATT_bm_free((gattMsg_t *)&noti, ATT_HANDLE_VALUE_NOTI);
    }
    return status;
}

/*********************************************************************
 * @fn      ImmurokService_FlushPending
 * @brief   重发排着的那条应答。tick 非 0 表示这是定时重试，计入次数上限。
 * @return  1 = 还排着，稍后再来；0 = 没有待发的了（发出去了、放弃了，或本来就没有）
 */
uint8_t ImmurokService_FlushPending(uint8_t tick)
{
    bStatus_t status;

    if(s_rsp_pending_len == 0)
        return 0;
    if(!rsp_link_ready()) {
        s_rsp_pending_len = 0;              // 断连或取消订阅：没人收了
        return 0;
    }
    status = rsp_send_raw(immurokRspValue, s_rsp_pending_len);
    if(status == SUCCESS) {
        s_rsp_pending_len = 0;
        RSP_COUNT(rsp_retry_ok);
        return 0;
    }
    if(tick && s_rsp_retry_left)
        s_rsp_retry_left--;
    if(!rsp_retryable(status) || s_rsp_retry_left == 0) {
        s_rsp_pending_len = 0;
        RSP_COUNT(rsp_dropped);
        return 0;
    }
    return 1;
}

bStatus_t ImmurokService_SendResponse(uint8_t *pData, uint8_t len)
{
    bStatus_t status;

    if(immurokConnHandle == INVALID_CONNHANDLE) {
        RSP_FAIL(0xFD);
        return FAILURE;
    }

    // Debug: print response data
    PRINT("TX[%d]: ", len);
    for(int i = 0; i < len; i++) {
        PRINT("%02X ", pData[i]);
    }
    PRINT("\n");

    // Check if notifications are enabled
    if(!rsp_link_ready()) {
        PRINT("TX DROPPED: CCC notify not enabled\n");
        RSP_FAIL(0xFE);
        return FAILURE;
    }

    if(len > IMMUROK_RSP_MAX_LEN) {
        len = IMMUROK_RSP_MAX_LEN;
    }

    // 前面还排着一条：先把它发掉，不能让后来的插到它前面。它还发不掉，这一条也发不掉。
    if(ImmurokService_FlushPending(0)) {
        PRINT("TX DROPPED: previous response still pending\n");
        RSP_FAIL(blePending);
        RSP_COUNT(rsp_dropped);
        return blePending;
    }

    tmos_memcpy(immurokRspValue, pData, len);
    status = rsp_send_raw(immurokRspValue, len);
    if(status == SUCCESS)
        return SUCCESS;

    RSP_FAIL(status);
    if(rsp_retryable(status) && len != 0) {
        s_rsp_pending_len = len;
        s_rsp_retry_left = RSP_RETRY_MAX;
        RSP_COUNT(rsp_deferred);
        ImmurokApp_RspDeferred();           // 应用层起重试事件
        return SUCCESS;                     // 已接手，稍后发出
    }
    return status;
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
            s_rsp_pending_len = 0;          // 排着的应答随连接作废，不带到下一条连接
        }
    }
}
