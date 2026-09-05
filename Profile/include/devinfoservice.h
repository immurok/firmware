/********************************** (C) COPYRIGHT *******************************
 * File Name          : devinfoservice.h
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/11
 * Description        :
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

#ifndef DEVINFOSERVICE_H
#define DEVINFOSERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************
 * INCLUDES
 */

/*********************************************************************
 * CONSTANTS
 */

// Device Information Service Parameters
// (System ID / Hardware Rev / Software Rev 特征已于 2026-08-22 删除——
//  从未维护的占位值，零信息量端点；参数 ID 保号不复用)
#define DEVINFO_MODEL_NUMBER           1
#define DEVINFO_SERIAL_NUMBER          2
#define DEVINFO_FIRMWARE_REV           3
#define DEVINFO_MANUFACTURER_NAME      6
#define DEVINFO_11073_CERT_DATA        7
#define DEVINFO_PNP_ID                 8

// IEEE 11073 authoritative body values
#define DEVINFO_11073_BODY_EMPTY       0
#define DEVINFO_11073_BODY_IEEE        1
#define DEVINFO_11073_BODY_CONTINUA    2
#define DEVINFO_11073_BODY_EXP         254

// PnP ID length
#define DEVINFO_PNP_ID_LEN             7

/*********************************************************************
 * TYPEDEFS
 */

/*********************************************************************
 * MACROS
 */

/*********************************************************************
 * Profile Callbacks
 */

/*********************************************************************
 * API FUNCTIONS
 */

/*
 * DevInfo_AddService- Initializes the Device Information service by registering
 *          GATT attributes with the GATT server.
 *
 */

extern bStatus_t DevInfo_AddService(void);

/*********************************************************************
 * @fn      DevInfo_SetParameter
 *
 * @brief   Set a Device Information parameter.
 *
 * @param   param - Profile parameter ID
 * @param   len - length of data to right
 * @param   value - pointer to data to write.  This is dependent on
 *          the parameter ID and WILL be cast to the appropriate
 *          data type (example: data type of uint16_t will be cast to
 *          uint16_t pointer).
 *
 * @return  bStatus_t
 */
bStatus_t DevInfo_SetParameter(uint8_t param, uint8_t len, void *value);

/*
 * DevInfo_GetParameter - Get a Device Information parameter.
 *
 *    param - Profile parameter ID
 *    value - pointer to data to write.  This is dependent on
 *          the parameter ID and WILL be cast to the appropriate
 *          data type (example: data type of uint16_t will be cast to
 *          uint16_t pointer).
 */
extern bStatus_t DevInfo_GetParameter(uint8_t param, void *value);

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* DEVINFOSERVICE_H */
