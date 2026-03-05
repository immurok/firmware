/********************************** (C) COPYRIGHT *******************************
 * File Name          : hidkbd.h
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/10
 * Description        :
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

#ifndef HIDKBD_H
#define HIDKBD_H

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************
 * INCLUDES
 */

/*********************************************************************
 * CONSTANTS
 */

// Task Events
#define START_DEVICE_EVT          0x0001
#define START_REPORT_EVT          0x0002
#define START_PARAM_UPDATE_EVT    0x0004
#define START_PHY_UPDATE_EVT      0x0008
#define BUTTON_SCAN_EVT           0x0010
#define TOUCH_SCAN_EVT            0x0020
#define FP_AUTH_EVT               0x0040
#define FP_ENROLL_EVT             0x0080
#define FP_POWER_OFF_EVT          0x0100
#define FP_WAKE_DONE_EVT          0x0200
#define FP_SEARCH_EVT             0x0400
#define OTA_FLASH_ERASE_EVT       0x0800
#define FP_NOTIFY_RETRY_EVT       0x1000
#define SLOW_ADV_EVT              0x2000
#define HID_KEY_RELEASE_EVT       0x4000
// 0x8000 reserved by SYS_EVENT_MSG
#define FP_GATE_EXEC_EVT          OTA_FLASH_ERASE_EVT  // reuse: signing and OTA are mutually exclusive

/*********************************************************************
 * MACROS
 */

/*********************************************************************
 * FUNCTIONS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */

/*
 * Task Initialization for the BLE Application
 */
extern void HidEmu_Init(void);

/*
 * Task Event Processor for the BLE Application
 */
extern uint16_t HidEmu_ProcessEvent(uint8_t task_id, uint16_t events);

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif
