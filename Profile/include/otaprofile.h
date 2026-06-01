/*
 * OTA Profile Header for immurok CH592F
 * Service UUID: d29005de-1391-4a54-8168-bf4e3c080430
 * Char UUID:    c75f4c30-9a2d-4445-92e0-0e034c53d092
 */

#ifndef __OTAPROFILE_H
#define __OTAPROFILE_H

#ifdef __cplusplus
extern "C" {
#endif

/* OTA Profile Service bit (for registration) */
#define OTAPROFILE_SERVICE      0x00000001

/* Callback parameter IDs */
#define OTAPROFILE_CHAR         1

/* OTA Profile Callbacks */
typedef struct {
    void (*pfnOTAProfileRead)(uint8_t paramID);
    void (*pfnOTAProfileWrite)(uint8_t paramID, uint8_t *pData, uint8_t len);
} OTAProfileCBs_t;

/* Function Declarations */

/**
 * @brief   Add OTA Profile service to GATT
 * @param   services - Service flags to register
 * @return  Status
 */
bStatus_t OTAProfile_AddService(uint32_t services);

/**
 * @brief   Register application callbacks
 * @param   appCallbacks - Callback function structure
 * @return  Status
 */
bStatus_t OTAProfile_RegisterAppCBs(OTAProfileCBs_t *appCallbacks);

/**
 * @brief   Send data to connected device (for read response)
 * @param   paramID - Parameter ID
 * @param   pData - Data pointer
 * @param   len - Data length
 * @return  Status
 */
bStatus_t OTAProfile_SendData(uint8_t paramID, uint8_t *pData, uint8_t len);

#ifdef __cplusplus
}
#endif

#endif /* __OTAPROFILE_H */
