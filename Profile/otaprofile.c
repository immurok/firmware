/*
 * OTA Profile Implementation for immurok CH592F
 * Service UUID: 0xFEE0 (BLE OTA Service)
 * Characteristic UUID: 0xFEE1 (OTA Data Channel)
 */

#include "CONFIG.h"
#include "otaprofile.h"
#include "ota.h"

/*********************************************************************
 * CONSTANTS
 */

/*********************************************************************
 * LOCAL VARIABLES
 */

static OTAProfileCBs_t *OTAProfile_AppCBs = NULL;

/* OTA Profile Service UUID: 0xFEE0 */
static const uint8_t OTAProfileServUUID[ATT_BT_UUID_SIZE] = {
    LO_UINT16(OTAPROFILE_SERV_UUID), HI_UINT16(OTAPROFILE_SERV_UUID)
};

/* OTA Characteristic UUID: 0xFEE1 */
static const uint8_t OTAProfileCharUUID[ATT_BT_UUID_SIZE] = {
    LO_UINT16(OTAPROFILE_CHAR_UUID), HI_UINT16(OTAPROFILE_CHAR_UUID)
};

/* Service declaration */
static const gattAttrType_t OTAProfileService = {ATT_BT_UUID_SIZE, OTAProfileServUUID};

/* Characteristic properties: Read + Write + Write Without Response */
static uint8_t OTAProfileCharProps = GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_WRITE_NO_RSP;

/* Characteristic value placeholder */
static uint8_t OTAProfileChar = 0;

/* User description */
static uint8_t OTAProfileCharUserDesp[] = "OTA Channel";

/* Read and write buffers */
static uint8_t OTAProfileReadLen = 0;
static uint8_t OTAProfileReadBuf[IAP_LEN];
static uint8_t OTAProfileWriteLen = 0;
static uint8_t OTAProfileWriteBuf[IAP_LEN];

/*********************************************************************
 * Profile Attributes Table
 */

static gattAttribute_t OTAProfileAttrTbl[] = {
    /* OTA Service Declaration */
    {
        {ATT_BT_UUID_SIZE, primaryServiceUUID},
        GATT_PERMIT_READ,
        0,
        (uint8_t *)&OTAProfileService
    },

    /* OTA Characteristic Declaration */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &OTAProfileCharProps
    },

    /* OTA Characteristic Value */
    {
        {ATT_BT_UUID_SIZE, OTAProfileCharUUID},
        GATT_PERMIT_READ | GATT_PERMIT_WRITE,
        0,
        &OTAProfileChar
    },

    /* OTA Characteristic User Description */
    {
        {ATT_BT_UUID_SIZE, charUserDescUUID},
        GATT_PERMIT_READ,
        0,
        OTAProfileCharUserDesp
    },
};

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static bStatus_t OTAProfile_ReadAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                       uint8_t *pValue, uint16_t *pLen, uint16_t offset,
                                       uint16_t maxLen, uint8_t method);
static bStatus_t OTAProfile_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                        uint8_t *pValue, uint16_t len, uint16_t offset,
                                        uint8_t method);

/*********************************************************************
 * PROFILE CALLBACKS
 */

static gattServiceCBs_t OTAProfileCBs = {
    OTAProfile_ReadAttrCB,
    OTAProfile_WriteAttrCB,
    NULL
};

/*********************************************************************
 * @fn      OTAProfile_AddService
 * @brief   Add OTA Profile service to GATT
 */
bStatus_t OTAProfile_AddService(uint32_t services)
{
    uint8_t status = SUCCESS;

    if(services & OTAPROFILE_SERVICE)
    {
        status = GATTServApp_RegisterService(OTAProfileAttrTbl,
                                             GATT_NUM_ATTRS(OTAProfileAttrTbl),
                                             GATT_MAX_ENCRYPT_KEY_SIZE,
                                             &OTAProfileCBs);
        PRINT("OTA Profile registered: %d\n", status);
    }

    return status;
}

/*********************************************************************
 * @fn      OTAProfile_RegisterAppCBs
 * @brief   Register application callbacks
 */
bStatus_t OTAProfile_RegisterAppCBs(OTAProfileCBs_t *appCallbacks)
{
    if(appCallbacks)
    {
        OTAProfile_AppCBs = appCallbacks;
        return SUCCESS;
    }
    return bleAlreadyInRequestedMode;
}

/*********************************************************************
 * @fn      OTAProfile_ReadAttrCB
 * @brief   Read attribute callback
 */
static bStatus_t OTAProfile_ReadAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                       uint8_t *pValue, uint16_t *pLen, uint16_t offset,
                                       uint16_t maxLen, uint8_t method)
{
    bStatus_t status = SUCCESS;

    if(pAttr->type.len == ATT_BT_UUID_SIZE)
    {
        uint16_t uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);

        switch(uuid)
        {
            case OTAPROFILE_CHAR_UUID:
            {
                *pLen = 0;
                if(OTAProfileReadLen)
                {
                    *pLen = OTAProfileReadLen;
                    tmos_memcpy(pValue, OTAProfileReadBuf, OTAProfileReadLen);
                    OTAProfileReadLen = 0;

                    if(OTAProfile_AppCBs && OTAProfile_AppCBs->pfnOTAProfileRead)
                    {
                        OTAProfile_AppCBs->pfnOTAProfileRead(OTAPROFILE_CHAR);
                    }
                }
                break;
            }
            default:
                *pLen = 0;
                status = ATT_ERR_ATTR_NOT_FOUND;
                break;
        }
    }
    else
    {
        *pLen = 0;
        status = ATT_ERR_INVALID_HANDLE;
    }

    return status;
}

/*********************************************************************
 * @fn      OTAProfile_WriteAttrCB
 * @brief   Write attribute callback
 */
static bStatus_t OTAProfile_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                        uint8_t *pValue, uint16_t len, uint16_t offset,
                                        uint8_t method)
{
    bStatus_t status = SUCCESS;

    if(pAttr->type.len == ATT_BT_UUID_SIZE)
    {
        uint16_t uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);

        switch(uuid)
        {
            case OTAPROFILE_CHAR_UUID:
            {
                if(len > IAP_LEN)
                {
                    status = ATT_ERR_INVALID_VALUE_SIZE;
                }
                else
                {
                    OTAProfileWriteLen = len;
                    tmos_memcpy(OTAProfileWriteBuf, pValue, len);
                }
                break;
            }
            default:
                status = ATT_ERR_ATTR_NOT_FOUND;
                break;
        }
    }
    else
    {
        status = ATT_ERR_INVALID_HANDLE;
    }

    /* Call application callback after successful write */
    if(OTAProfileWriteLen && OTAProfile_AppCBs && OTAProfile_AppCBs->pfnOTAProfileWrite)
    {
        OTAProfile_AppCBs->pfnOTAProfileWrite(OTAPROFILE_CHAR, OTAProfileWriteBuf, OTAProfileWriteLen);
        OTAProfileWriteLen = 0;
    }

    return status;
}

/*********************************************************************
 * @fn      OTAProfile_SendData
 * @brief   Prepare data for read response
 */
bStatus_t OTAProfile_SendData(uint8_t paramID, uint8_t *pData, uint8_t len)
{
    if(len > IAP_LEN)
    {
        return FAILURE;
    }

    OTAProfileReadLen = len;
    tmos_memcpy(OTAProfileReadBuf, pData, len);

    return SUCCESS;
}

/*********************************************************************
*********************************************************************/
