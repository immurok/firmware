/*
 * OTA Profile Implementation for immurok CH592F
 * Service UUID: d29005de-1391-4a54-8168-bf4e3c080430 (BLE OTA Service)
 * Char UUID:    c75f4c30-9a2d-4445-92e0-0e034c53d092 (OTA Data Channel)
 *
 * UUIDs are stored little-endian (BLE wire format).
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

/* OTA Service UUID: d29005de-1391-4a54-8168-bf4e3c080430 */
static const uint8_t OTAProfileServUUID[ATT_UUID_SIZE] = {
    0x30, 0x04, 0x08, 0x3c, 0x4e, 0xbf, 0x68, 0x81,
    0x54, 0x4a, 0x91, 0x13, 0xde, 0x05, 0x90, 0xd2
};

/* OTA Characteristic UUID: c75f4c30-9a2d-4445-92e0-0e034c53d092 */
static const uint8_t OTAProfileCharUUID[ATT_UUID_SIZE] = {
    0x92, 0xd0, 0x53, 0x4c, 0x03, 0x0e, 0xe0, 0x92,
    0x45, 0x44, 0x2d, 0x9a, 0x30, 0x4c, 0x5f, 0xc7
};

/* Service declaration */
static const gattAttrType_t OTAProfileService = {ATT_UUID_SIZE, OTAProfileServUUID};

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
    // ENCRYPT_WRITE: an unbonded peer must not be able to drive OTA (ERASE
    // alone is enough to brick Image B + suppress HID/FP via s_ota_active).
    // ENCRYPT_READ: status bytes back to OTA tool stay in encrypted link.
    {
        {ATT_UUID_SIZE, OTAProfileCharUUID},
        GATT_PERMIT_ENCRYPT_READ | GATT_PERMIT_ENCRYPT_WRITE,
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

    if(pAttr->type.len == ATT_UUID_SIZE &&
       tmos_memcmp(pAttr->type.uuid, OTAProfileCharUUID, ATT_UUID_SIZE))
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
    }
    else
    {
        *pLen = 0;
        status = ATT_ERR_ATTR_NOT_FOUND;
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

    if(pAttr->type.len == ATT_UUID_SIZE &&
       tmos_memcmp(pAttr->type.uuid, OTAProfileCharUUID, ATT_UUID_SIZE))
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
    }
    else
    {
        status = ATT_ERR_ATTR_NOT_FOUND;
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
