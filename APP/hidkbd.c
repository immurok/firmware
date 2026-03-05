/********************************** (C) COPYRIGHT *******************************
 * File Name          : hidkbd.c
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/10
 * Description        : ��������Ӧ�ó��򣬳�ʼ���㲥���Ӳ�����Ȼ��㲥��ֱ�����������󣬶�ʱ�ϴ���ֵ
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

/*********************************************************************
 * INCLUDES
 */
#include "CONFIG.h"
#include "devinfoservice.h"
#include "battservice.h"
#include "hidkbdservice.h"
#include "hiddev.h"
#include "hidkbd.h"
#include "immurokservice.h"
#include "fingerprint.h"
#include "immurok_security.h"
#include "immurok_keystore.h"
#include "otaprofile.h"
#include "ota.h"

/*********************************************************************
 * MACROS
 */
// HID keyboard input report length
#define HID_KEYBOARD_IN_RPT_LEN              8

// HID LED output report length
#define HID_LED_OUT_RPT_LEN                  1

/*********************************************************************
 * CONSTANTS
 */
// Param update delay: 30s after connection (48000 = 30000ms / 0.625ms)
// macOS rejects high latency during service discovery; wait for enumeration to finish
#define START_PARAM_UPDATE_EVT_DELAY         48000

// Retry interval for param update if macOS ignores request (10s)
#define PARAM_UPDATE_RETRY_DELAY             16000
// Max param update retries
#define PARAM_UPDATE_MAX_RETRIES             3

// Param update delay
#define START_PHY_UPDATE_DELAY               1600

// HID idle timeout in msec; set to zero to disable timeout
#define DEFAULT_HID_IDLE_TIMEOUT             60000

// Minimum connection interval (units of 1.25ms)
// 24 = 30ms
#define DEFAULT_DESIRED_MIN_CONN_INTERVAL    24

// Maximum connection interval (units of 1.25ms)
// 40 = 50ms
#define DEFAULT_DESIRED_MAX_CONN_INTERVAL    40

// Slave latency to use if parameter update request
// 29 = skip up to 29 intervals; effective idle interval = 50ms * 30 = 1.5s
// Keystroke wakes immediately, latency drops back to 30-50ms
#define DEFAULT_DESIRED_SLAVE_LATENCY        29

// Supervision timeout value (units of 10ms)
// Apple requires: timeout > intervalMax * (latency + 1) * 3 = 50ms * 30 * 3 = 4500ms
// 600 = 6s (Apple max = 6s)
#define DEFAULT_DESIRED_CONN_TIMEOUT         600

// Default passcode
#define DEFAULT_PASSCODE                     0

// Default GAP pairing mode
#define DEFAULT_PAIRING_MODE                 GAPBOND_PAIRING_MODE_WAIT_FOR_REQ

// Default MITM mode (TRUE to require passcode or OOB when pairing)
#define DEFAULT_MITM_MODE                    FALSE

// Default bonding mode, TRUE to bond
#define DEFAULT_BONDING_MODE                 TRUE

// Default GAP bonding I/O capabilities
#define DEFAULT_IO_CAPABILITIES              GAPBOND_IO_CAP_NO_INPUT_NO_OUTPUT

// Battery level is critical when it is less than this %
#define DEFAULT_BATT_CRITICAL_LEVEL          6

// Button pin (directly use hex value)
#define PIN_BTN1    0x00004000  // PA14 - GPIO_Pin_14
#define PIN_TOUCH   0x00002000  // PA13 - GPIO_Pin_13, touch INT (active high)

// Button scan interval (in 625us units, 160 = 100ms)
#define BUTTON_SCAN_INTERVAL    160

// Fingerprint power off delay (10 seconds in 625us units)
// 10000ms / 0.625ms = 16000
#define FP_POWER_OFF_DELAY      16000

// Advertising intervals (units of 0.625ms)
#define ADV_FAST_INT             48     // 30ms - fast reconnection after disconnect
#define ADV_SLOW_INT             8000   // 5000ms - power saving when host is off

// Delay before switching to slow advertising (30s in 625us units)
// 30000ms / 0.625ms = 48000
#define SLOW_ADV_DELAY           48000

/*********************************************************************
 * TYPEDEFS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */

// Task ID (non-static: main loop checks GPIO flags and fires events)
uint8_t hidEmuTaskId = INVALID_TASK_ID;

// Fingerprint enrollment state
static uint8_t s_enroll_active = 0;
static uint16_t s_enroll_page_id = 0;
static uint8_t s_enroll_send_lift = 0;  // Flag: need to send lift finger notification
static uint8_t s_enroll_send_done = 0;  // Flag: need to send final success response

// AUTH_REQUEST preheat: power on + verify only, don't start search
static uint8_t s_auth_preheat = 0;
static uint32_t s_fp_power_on_tick = 0;  // RTC tick when fp_power_on() called

// Fingerprint search state machine
// Each state does send+recv in one call to avoid UART FIFO overflow
static uint8_t s_search_active = 0;
static uint8_t s_search_state = 0;   // 0=GET_IMAGE, 1=GEN_CHAR, 2=SEARCH
static uint32_t s_search_start_time = 0;

#define FP_SEARCH_TIMEOUT_MS    500   // 0.5 second timeout

// Fingerprint notify retry state (HID wake + ACK mechanism)
static uint8_t s_fp_notify_pending = 0;     // Has pending notification awaiting ACK
static uint16_t s_fp_notify_page_id = 0;    // Page ID for pending notification
static uint32_t s_fp_notify_start_time = 0; // Start time for 15s timeout
static uint8_t s_fp_notify_data[64];        // Cached notification data (0x21 + page_id + pwd)
static uint8_t s_fp_notify_len = 0;         // Length of cached data
static uint8_t s_fp_notify_phase = 0;       // 0=send CTRL, 1=send notification

// Fingerprint-gated write state machine
static uint8_t s_pending_cmd = 0;           // Pending command waiting for FP verification
static uint8_t s_pending_payload[64];       // Cached payload for pending command
static uint8_t s_pending_payload_len = 0;   // Length of cached payload
static uint32_t s_pending_cmd_start = 0;    // TMOS tick when gate started
#define FP_GATE_TIMEOUT_MS  25000           // 25s overall gate timeout (App has 30s)
static uint32_t s_fp_gate_last_verify = 0;  // TMOS tick of last FP verification
#define FP_GATE_COOLDOWN_MS 10000           // 10s cooldown after FP verify (batch ops)

// GPIO interrupt flags (set in ISR, consumed in TMOS event loop)
volatile uint8_t g_touch_irq_flag = 0;
volatile uint8_t g_btn_irq_flag = 0;

// OTA IAP state
static OTA_IAP_CMD_t s_ota_iap_data;
static uint32_t s_ota_erase_addr = 0;
static uint32_t s_ota_erase_blocks = 0;
static uint32_t s_ota_erase_count = 0;
static uint8_t s_ota_verify_status = 0;
static uint8_t s_ota_active = 0;  // OTA mode: suppress all non-OTA functionality

// OTA secure context (for encrypted .imfw upgrades)
#include "ota_keys.h"
static ota_secure_ctx_t s_ota_sec = {0};

/*********************************************************************
 * LOCAL FUNCTIONS
 */

// Reset fingerprint power-off timer (call after any FP operation)
static void fp_reset_power_timer(void)
{
    // Cancel any pending power-off event
    tmos_stop_task(hidEmuTaskId, FP_POWER_OFF_EVT);
    // Schedule new power-off event in 10 seconds
    tmos_start_task(hidEmuTaskId, FP_POWER_OFF_EVT, FP_POWER_OFF_DELAY);
}

// Ensure fingerprint module is ready for operation
static int fp_ensure_ready(void)
{
    int ret = fp_wake();
    if (ret == FP_OK) {
        fp_reset_power_timer();
    }
    return ret;
}

/*********************************************************************
 * EXTERNAL VARIABLES
 */

/*********************************************************************
 * EXTERNAL FUNCTIONS
 */

/*********************************************************************
 * LOCAL FUNCTION PROTOTYPES
 */
static void HidEmu_ImmurokCommandCB(uint16_t connHandle, uint8_t *pData, uint8_t len);
static void hidEmuSendCtrlKey(void);

// OTA callback functions
static void OTA_IAPReadDataComplete(uint8_t paramID);
static void OTA_IAPWriteData(uint8_t paramID, uint8_t *pData, uint8_t len);
static void OTA_IAP_DataDeal(void);
static void OTA_IAP_SendStatus(uint8_t status);
static void SwitchImageFlag(uint8_t new_flag);

/*********************************************************************
 * LOCAL VARIABLES
 */

// GAP Profile - Name attribute for SCAN RSP data
static uint8_t scanRspData[] = {
    0x0D,                           // length of this data (12 + 1)
    GAP_ADTYPE_LOCAL_NAME_COMPLETE, // AD Type = Complete local name
    'i',
    'm',
    'm',
    'u',
    'r',
    'o',
    'k',
    ' ',
    'I',
    'K',
    '-',
    '1',  // connection interval range
    0x05, // length of this data
    GAP_ADTYPE_SLAVE_CONN_INTERVAL_RANGE,
    LO_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL), // 100ms
    HI_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL),
    LO_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL), // 1s
    HI_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL),

    // service UUIDs
    0x05, // length of this data
    GAP_ADTYPE_16BIT_MORE,
    LO_UINT16(HID_SERV_UUID),
    HI_UINT16(HID_SERV_UUID),
    LO_UINT16(BATT_SERV_UUID),
    HI_UINT16(BATT_SERV_UUID),

    // Tx power level
    0x02, // length of this data
    GAP_ADTYPE_POWER_LEVEL,
    0 // 0dBm
};

// Advertising data
static uint8_t advertData[] = {
    // flags
    0x02, // length of this data
    GAP_ADTYPE_FLAGS,
    GAP_ADTYPE_FLAGS_GENERAL | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED,

    // appearance
    0x03, // length of this data
    GAP_ADTYPE_APPEARANCE,
    LO_UINT16(GAP_APPEARE_HID_KEYBOARD),
    HI_UINT16(GAP_APPEARE_HID_KEYBOARD)};

// Device name attribute value
static CONST uint8_t attDeviceName[GAP_DEVICE_NAME_LEN] = "immurok IK-1";

// HID Dev configuration
static hidDevCfg_t hidEmuCfg = {
    DEFAULT_HID_IDLE_TIMEOUT, // Idle timeout
    HID_FEATURE_FLAGS         // HID feature flags
};

static uint16_t hidEmuConnHandle = GAP_CONNHANDLE_INIT;

// Param update retry counter
static uint8_t s_param_update_retries = 0;
// Whether our desired latency has been accepted (extern'd by hiddev.c)
uint8_t s_latency_accepted = 0;

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static void    hidEmu_ProcessTMOSMsg(tmos_event_hdr_t *pMsg);
static void    hidEmuSendKbdReport(uint8_t keycode);
static uint8_t hidEmuRcvReport(uint8_t len, uint8_t *pData);
static uint8_t hidEmuRptCB(uint8_t id, uint8_t type, uint16_t uuid,
                           uint8_t oper, uint16_t *pLen, uint8_t *pData);
static void    hidEmuEvtCB(uint8_t evt);
static void    hidEmuStateCB(gapRole_States_t newState, gapRoleEvent_t *pEvent);

/*********************************************************************
 * PROFILE CALLBACKS
 */

static hidDevCB_t hidEmuHidCBs = {
    hidEmuRptCB,
    hidEmuEvtCB,
    NULL,
    hidEmuStateCB};

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

/*********************************************************************
 * @fn      HidEmu_Init
 *
 * @brief   Initialization function for the HidEmuKbd App Task.
 *          This is called during initialization and should contain
 *          any application specific initialization (ie. hardware
 *          initialization/setup, table initialization, power up
 *          notificaiton ... ).
 *
 * @param   task_id - the ID assigned by TMOS.  This ID should be
 *                    used to send messages and set timers.
 *
 * @return  none
 */
void HidEmu_Init()
{
    hidEmuTaskId = TMOS_ProcessEventRegister(HidEmu_ProcessEvent);

    // Initialize button GPIO (PA14 with pull-up, active low)
    GPIOA_ModeCfg(PIN_BTN1, GPIO_ModeIN_PU);

    // Initialize touch detection GPIO (PA13, active high)
    GPIOA_ModeCfg(PIN_TOUCH, GPIO_ModeIN_PD);

    // Configure GPIO interrupts for fast wake detection
    // Touch: rising edge (finger down), Button: falling edge (press)
    GPIOA_ITModeCfg(PIN_TOUCH, GPIO_ITMode_RiseEdge);
    GPIOA_ITModeCfg(PIN_BTN1, GPIO_ITMode_FallEdge);
    PFIC_EnableIRQ(GPIO_A_IRQn);
    PRINT("GPIO interrupts enabled (PA13 rise, PA14 fall)\n");

    // Initialize security module
    immurok_security_init();

    // Initialize keystore module
    immurok_keystore_init();

    // Setup the GAP Peripheral Role Profile
    {
        uint8_t initial_advertising_enable = TRUE;

        // Set the GAP Role Parameters
        GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &initial_advertising_enable);

        GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);
        GAPRole_SetParameter(GAPROLE_SCAN_RSP_DATA, sizeof(scanRspData), scanRspData);
    }

    // Set the GAP Characteristics
    GGS_SetParameter(GGS_DEVICE_NAME_ATT, GAP_DEVICE_NAME_LEN, (void *)attDeviceName);

    // Setup the GAP Bond Manager
    {
        uint32_t passkey = DEFAULT_PASSCODE;
        uint8_t  pairMode = DEFAULT_PAIRING_MODE;
        uint8_t  mitm = DEFAULT_MITM_MODE;
        uint8_t  ioCap = DEFAULT_IO_CAPABILITIES;
        uint8_t  bonding = DEFAULT_BONDING_MODE;
        GAPBondMgr_SetParameter(GAPBOND_PERI_DEFAULT_PASSCODE, sizeof(uint32_t), &passkey);
        GAPBondMgr_SetParameter(GAPBOND_PERI_PAIRING_MODE, sizeof(uint8_t), &pairMode);
        GAPBondMgr_SetParameter(GAPBOND_PERI_MITM_PROTECTION, sizeof(uint8_t), &mitm);
        GAPBondMgr_SetParameter(GAPBOND_PERI_IO_CAPABILITIES, sizeof(uint8_t), &ioCap);
        GAPBondMgr_SetParameter(GAPBOND_PERI_BONDING_ENABLED, sizeof(uint8_t), &bonding);
    }
    {
        // Preferred connection parameters (advertised to central)
        gapPeriConnectParams_t ConnectParams;
        ConnectParams.intervalMin = DEFAULT_DESIRED_MIN_CONN_INTERVAL;  // 100ms
        ConnectParams.intervalMax = DEFAULT_DESIRED_MAX_CONN_INTERVAL;  // 200ms
        ConnectParams.latency = DEFAULT_DESIRED_SLAVE_LATENCY;          // 20
        ConnectParams.timeout = DEFAULT_DESIRED_CONN_TIMEOUT;           // 5000ms
        GGS_SetParameter(GGS_PERI_CONN_PARAM_ATT, sizeof(gapPeriConnectParams_t), &ConnectParams);
    }
    // Setup Battery Characteristic Values
    {
        uint8_t critical = DEFAULT_BATT_CRITICAL_LEVEL;
        Batt_SetParameter(BATT_PARAM_CRITICAL_LEVEL, sizeof(uint8_t), &critical);
    }

    // Set serial number from chip MAC address
    {
        __attribute__((aligned(4))) uint8_t mac[6];
        GetMACAddress(mac);
        char sn[13];
        for(int i = 0; i < 6; i++) {
            uint8_t hi = mac[i] >> 4;
            uint8_t lo = mac[i] & 0x0F;
            sn[i * 2]     = hi < 10 ? '0' + hi : 'A' + hi - 10;
            sn[i * 2 + 1] = lo < 10 ? '0' + lo : 'A' + lo - 10;
        }
        sn[12] = '\0';
        DevInfo_SetParameter(DEVINFO_SERIAL_NUMBER, 12, sn);
        PRINT("Serial: %s\n", sn);
    }

    // Set up HID keyboard service
    Hid_AddService();

    // Set up immurok custom service
    ImmurokService_AddService();

    // Register immurok command callback
    static immurokServiceCBs_t immurokCBs = {
        .pfnCommandCB = HidEmu_ImmurokCommandCB
    };
    ImmurokService_RegisterAppCBs(&immurokCBs);

    // Set up OTA service
    OTAProfile_AddService(OTAPROFILE_SERVICE);

    // Register OTA callbacks
    static OTAProfileCBs_t otaCBs = {
        .pfnOTAProfileRead = OTA_IAPReadDataComplete,
        .pfnOTAProfileWrite = OTA_IAPWriteData
    };
    OTAProfile_RegisterAppCBs(&otaCBs);

    // Register for HID Dev callback
    HidDev_Register(&hidEmuCfg, &hidEmuHidCBs);

    // Set initial advertising interval (fast for first connection)
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
    GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);

    // Setup a delayed profile startup
    tmos_set_event(hidEmuTaskId, START_DEVICE_EVT);
}

/*********************************************************************
 * @fn      HidEmu_ProcessEvent
 *
 * @brief   HidEmuKbd Application Task event processor.  This function
 *          is called to process all events for the task.  Events
 *          include timers, messages and any other user defined events.
 *
 * @param   task_id  - The TMOS assigned task ID.
 * @param   events - events to process.  This is a bit map and can
 *                   contain more than one event.
 *
 * @return  events not processed
 */

uint16_t HidEmu_ProcessEvent(uint8_t task_id, uint16_t events)
{
    if(events & SYS_EVENT_MSG)
    {
        uint8_t *pMsg;

        if((pMsg = tmos_msg_receive(hidEmuTaskId)) != NULL)
        {
            hidEmu_ProcessTMOSMsg((tmos_event_hdr_t *)pMsg);

            // Release the TMOS message
            tmos_msg_deallocate(pMsg);
        }

        // return unprocessed events
        return (events ^ SYS_EVENT_MSG);
    }

    if(events & START_DEVICE_EVT)
    {
        // GPIO interrupts + main loop flag check handle detection.
        // No periodic polling needed - events fired from Main_Circulation.
        return (events ^ START_DEVICE_EVT);
    }

    if(events & START_PARAM_UPDATE_EVT)
    {
        if(s_latency_accepted)
        {
            // Already got acceptable params, skip
            return (events ^ START_PARAM_UPDATE_EVT);
        }
        s_param_update_retries++;
        PRINT("Requesting param update (attempt %d/%d): interval=%d-%d, latency=%d, timeout=%d\n",
              s_param_update_retries, PARAM_UPDATE_MAX_RETRIES,
              DEFAULT_DESIRED_MIN_CONN_INTERVAL, DEFAULT_DESIRED_MAX_CONN_INTERVAL,
              DEFAULT_DESIRED_SLAVE_LATENCY, DEFAULT_DESIRED_CONN_TIMEOUT);
        GAPRole_PeripheralConnParamUpdateReq(hidEmuConnHandle,
                                             DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                                             DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                                             DEFAULT_DESIRED_SLAVE_LATENCY,
                                             DEFAULT_DESIRED_CONN_TIMEOUT,
                                             hidEmuTaskId);

        // Schedule retry if not accepted
        if(s_param_update_retries < PARAM_UPDATE_MAX_RETRIES)
        {
            tmos_start_task(hidEmuTaskId, START_PARAM_UPDATE_EVT, PARAM_UPDATE_RETRY_DELAY);
        }

        return (events ^ START_PARAM_UPDATE_EVT);
    }

    if(events & START_PHY_UPDATE_EVT)
    {
        // start phy update
        PRINT("Send Phy Update %x...\n", GAPRole_UpdatePHY(hidEmuConnHandle, 0,
                    GAP_PHY_BIT_LE_2M, GAP_PHY_BIT_LE_2M, 0));

        return (events ^ START_PHY_UPDATE_EVT);
    }

    if(events & SLOW_ADV_EVT)
    {
        // Switch to slow advertising for power saving
        PRINT("Switching to slow advertising (%dms)\n", (int)(ADV_SLOW_INT * 0.625));
        GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_SLOW_INT);
        GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_SLOW_INT);
        // Restart advertising with new interval
        uint8_t adv_enable = TRUE;
        GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
        return (events ^ SLOW_ADV_EVT);
    }

    if(events & START_REPORT_EVT)
    {
        // No longer used for auto-send
        return (events ^ START_REPORT_EVT);
    }

    if(events & BUTTON_SCAN_EVT)
    {
        if(s_ota_active) return (events ^ BUTTON_SCAN_EVT);

        uint8_t btn = ((GPIOA_ReadPortPin(PIN_BTN1) & PIN_BTN1) == 0);  // Active low

        static uint8_t lastBtn = 0;
        static uint32_t pressStart = 0;
        static uint8_t longTriggered = 0;

        if(btn && !lastBtn)
        {
            pressStart = TMOS_GetSystemClock();
            longTriggered = 0;
            // Fast polling while pressed (long-press detection)
            tmos_start_task(hidEmuTaskId, BUTTON_SCAN_EVT, BUTTON_SCAN_INTERVAL);
        }
        else if(btn && lastBtn && !longTriggered && pressStart)
        {
            uint32_t elapsed = (TMOS_GetSystemClock() - pressStart) * 625 / 1000;
            if(elapsed >= 3000)
            {
                longTriggered = 1;
                PRINT("*** FACTORY RESET (long press) ***\n");

                // Wake fingerprint module and clear all templates
                if(fp_wake() == FP_OK)
                {
                    PRINT("Clearing all fingerprint templates...\n");
                    fp_clear_all();
                    fp_power_off();
                }

                // Clear password from DataFlash
                immurok_security_factory_reset();

                // Clear BLE bonds
                HidDev_SetParameter(HIDDEV_ERASE_ALLBONDS, 0, NULL);
                DelayMs(100);
                SYS_ResetExecute();
            }
            tmos_start_task(hidEmuTaskId, BUTTON_SCAN_EVT, BUTTON_SCAN_INTERVAL);
        }
        else if(!btn && lastBtn && !longTriggered && pressStart)
        {
            // Short press - no longer used for pairing
            pressStart = 0;
            // Released - stop polling, next press detected by GPIO IRQ
        }
        // else: idle, no timer needed - GPIO IRQ will trigger next event

        lastBtn = btn;
        return (events ^ BUTTON_SCAN_EVT);
    }

    if(events & TOUCH_SCAN_EVT)
    {
        if(s_ota_active) return (events ^ TOUCH_SCAN_EVT);

        static uint8_t touchDebounce = 0;
        uint8_t touch = (GPIOA_ReadPortPin(PIN_TOUCH) & PIN_TOUCH) ? 1 : 0;

        if(touch)
        {
            touchDebounce++;
            if(touchDebounce >= 3)
            {
                // Confirmed touch after 3 consecutive readings
                touchDebounce = 0;

                if(s_enroll_active) {
                    // Skip - enrollment handles touch internally
                }
                else if(s_search_active) {
                    // Skip - search already in progress
                }
                else
                {
                    // Send CTRL key immediately to wake host screen.
                    // Screen wake overlaps with FP module power-up + fingerprint matching.
                    hidEmuSendCtrlKey();
                    PRINT("CTRL sent (early wake)\n");

                    if(!fp_is_powered())
                    {
                        PRINT("Waking FP module (async)...\n");
                        fp_power_on();
                        s_fp_power_on_tick = RTC_GetCycle32k();
                        tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);  // 30ms (poll for 0x55)
                    }
                    else
                    {
                        if(immurok_security_has_pending_auth()) {
                            PRINT("Starting FP auth...\n");
                        } else {
                            PRINT("Test FP search...\n");
                        }
                        tmos_set_event(hidEmuTaskId, FP_AUTH_EVT);
                    }
                }
                // Done - next touch detected by GPIO IRQ
            }
            else
            {
                // Continue debounce - check again in 10ms
                tmos_start_task(hidEmuTaskId, TOUCH_SCAN_EVT, 16);  // 10ms
            }
        }
        else
        {
            // No touch (IRQ was noise or finger already lifted)
            touchDebounce = 0;
        }

        return (events ^ TOUCH_SCAN_EVT);
    }

    if(events & FP_WAKE_DONE_EVT)
    {
        if(s_ota_active) return (events ^ FP_WAKE_DONE_EVT);

        // Poll UART for 0x55 ready signal before verifying password.
        // Called first at 30ms after power-on, then every 10ms until 0x55 or 200ms timeout.
        {
            bool got_ready = false;
            while(R8_UART1_RFC > 0) {
                uint8_t b = R8_UART1_RBR;
                if(b == 0x55) { got_ready = true; break; }
            }
            if(!got_ready && !fp_is_password_verified()) {
                // Check elapsed time since power-on
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                if(elapsed < 200) {
                    // Retry in 10ms
                    tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 16);  // 10ms
                    return (events ^ FP_WAKE_DONE_EVT);
                }
                PRINT("FP 0x55 timeout (%dms), proceeding anyway\n", (int)elapsed);
            } else if(got_ready) {
                uint32_t elapsed = (RTC_GetCycle32k() - s_fp_power_on_tick) / 33;
                PRINT("FP 0x55 at %dms\n", (int)elapsed);
            }
        }

        PRINT("FP_WAKE: verifying password...\n");
        int ret = fp_start_verify();
        if(ret != FP_OK)
        {
            PRINT("FP wake failed: %d\n", ret);
            fp_power_off();
            return (events ^ FP_WAKE_DONE_EVT);
        }

        // Reset power-off timer
        fp_reset_power_timer();

        if(s_auth_preheat) {
            // AUTH_REQUEST preheat: module is ready, wait for touch GPIO
            s_auth_preheat = 0;
            PRINT("FP ready, waiting for touch...\n");
            return (events ^ FP_WAKE_DONE_EVT);
        }

        if(immurok_security_has_pending_auth()) {
            PRINT("Starting FP auth...\n");
        } else {
            PRINT("Test FP search...\n");
        }
        tmos_start_task(hidEmuTaskId, FP_AUTH_EVT, 1);  // 625us delay

        return (events ^ FP_WAKE_DONE_EVT);
    }

    if(events & FP_AUTH_EVT)
    {
        if(s_ota_active) return (events ^ FP_AUTH_EVT);

        // Module should already be awake at this point
        if(!fp_is_powered())
        {
            PRINT("FP_AUTH_EVT: module not powered!\n");
            return (events ^ FP_AUTH_EVT);
        }

        // Reset power-off timer
        fp_reset_power_timer();

        // Start non-blocking search state machine
        if(!s_search_active)
        {
            PRINT("FP_AUTH_EVT: starting non-blocking search...\n");
            s_search_active = 1;
            s_search_state = 0;  // Start from GET_IMAGE
            s_search_start_time = TMOS_GetSystemClock();

            // Use tmos_start_task to break event chain and let main loop feed watchdog
            tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 1);  // 625us delay
        }

        return (events ^ FP_AUTH_EVT);
    }

    if(events & FP_SEARCH_EVT)
    {
        if(s_ota_active) return (events ^ FP_SEARCH_EVT);
        // Fingerprint search state machine - yields to TMOS between steps
        // Each state does send+recv together (UART FIFO is only 8 bytes,
        // splitting send/recv across events causes FIFO overflow)
        // States: 0=GET_IMAGE(~30ms), 1=GEN_CHAR(~100ms), 2=SEARCH(~200ms)

        extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int fp_recv_ack(uint8_t *ack, uint8_t *data, uint16_t *len, uint32_t timeout_ms);

        if(!s_search_active)
        {
            return (events ^ FP_SEARCH_EVT);
        }

        // Check per-search timeout (finger not detected in time)
        uint32_t elapsed = (TMOS_GetSystemClock() - s_search_start_time) * 625 / 1000;
        if(elapsed > FP_SEARCH_TIMEOUT_MS)
        {
            s_search_active = 0;
            if(s_pending_cmd != 0)
            {
                uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                {
                    PRINT("FP search timeout + gate expired (%dms), clearing cmd 0x%02X\n",
                          (int)gate_elapsed, s_pending_cmd);
                    s_pending_cmd = 0;
                    s_pending_payload_len = 0;
                    uint8_t rspBuf[1] = { 0x07 };
                    ImmurokService_SendResponse(rspBuf, 1);
                }
                else
                {
                    PRINT("FP search timeout (gate pending, waiting for touch)\n");
                }
            }
            else if(immurok_security_has_pending_auth())
            {
                PRINT("FP search timeout (auth pending, waiting for touch)\n");
            }
            else
            {
                PRINT("FP search timeout\n");
                fp_led_flash(FP_LED_RED, 25, 1);
            }
            fp_reset_power_timer();
            return (events ^ FP_SEARCH_EVT);
        }

        uint8_t ack;
        int ret;

        switch(s_search_state)
        {
        case 0:  // GET_IMAGE: ~50ms block
            fp_send_cmd(0x01, NULL, 0);
            ret = fp_recv_ack(&ack, NULL, NULL, 50);
            if(ret == FP_OK && ack == 0x00)
            {
                WWDG_SetCounter(0);
                s_search_state = 1;
                tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 1);  // yield then GEN_CHAR
            }
            else
            {
                tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 160);  // 100ms retry
            }
            break;

        case 1:  // GEN_CHAR: send + recv (~100ms block)
        {
            uint8_t params[1] = { 1 };
            fp_send_cmd(0x02, params, 1);  // CMD_IMAGE2TZ
            ret = fp_recv_ack(&ack, NULL, NULL, 100);
            WWDG_SetCounter(0);
            if(ret == FP_OK && ack == 0x00)
            {
                s_search_state = 2;
                tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 1);  // yield then SEARCH
            }
            else
            {
                PRINT("FP gen_char failed\n");
                s_search_state = 0;
                tmos_start_task(hidEmuTaskId, FP_SEARCH_EVT, 80);  // 50ms retry
            }
            break;
        }

        case 2:  // SEARCH: send + recv (~200ms block)
        {
            uint8_t search_params[5];
            search_params[0] = 1;
            search_params[1] = 0;
            search_params[2] = 0;
            search_params[3] = 0;
            search_params[4] = FP_MAX_TEMPLATES;
            fp_send_cmd(0x04, search_params, 5);  // CMD_SEARCH

            uint8_t search_result[4];
            uint16_t result_len = 4;
            ret = fp_recv_ack(&ack, search_result, &result_len, 200);
            s_search_active = 0;
            WWDG_SetCounter(0);

            if(ret == FP_OK && ack == 0x00)
            {
                uint16_t page_id = (search_result[0] << 8) | search_result[1];
                uint16_t match_score = (search_result[2] << 8) | search_result[3];
                fp_led_flash(FP_LED_BLUE, 25, 1);
                PRINT("FP matched! id=%d, score=%d\n", page_id, match_score);

                // Match succeeded - power off unless pending cmd needs FP module
                if(s_pending_cmd != IMMUROK_CMD_DELETE_FP &&
                   s_pending_cmd != IMMUROK_CMD_FACTORY_RESET &&
                   s_pending_cmd != IMMUROK_CMD_ENROLL_START)
                {
                    fp_power_off();
                }

                // Expire stale pending command (gate timeout)
                if(s_pending_cmd != 0)
                {
                    uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                    {
                        PRINT("Pending cmd 0x%02X expired (%dms), clearing\n", s_pending_cmd, (int)gate_elapsed);
                        s_pending_cmd = 0;
                        s_pending_payload_len = 0;
                        fp_power_off();
                    }
                }

                // Priority 1: Execute pending fingerprint-gated command
                if(s_pending_cmd != 0)
                {
                    uint8_t cmd = s_pending_cmd;
                    s_pending_cmd = 0;
                    s_fp_gate_last_verify = TMOS_GetSystemClock();
                    PRINT("Executing pending cmd 0x%02X after FP verify (cooldown set)\n", cmd);

                    uint8_t rspBuf[2];
                    switch(cmd) {
                    case IMMUROK_CMD_ENROLL_START:
                        s_enroll_page_id = s_pending_payload[0];
                        s_enroll_active = 1;
                        tmos_set_event(hidEmuTaskId, FP_ENROLL_EVT);
                        rspBuf[0] = IMMUROK_RSP_OK;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    case IMMUROK_CMD_DELETE_FP:
                    {
                        int del_ret = fp_ensure_ready();
                        if(del_ret == FP_OK) {
                            del_ret = fp_delete(s_pending_payload[0], 1);
                        }
                        rspBuf[0] = (del_ret == FP_OK) ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_FACTORY_RESET:
                    {
                        // Clear all fingerprints
                        if(fp_ensure_ready() == FP_OK) {
                            fp_clear_all();
                        }
                        // Clear password
                        immurok_security_factory_reset();
                        // Clear BLE bonds
                        HidDev_SetParameter(HIDDEV_ERASE_ALLBONDS, 0, NULL);
                        rspBuf[0] = IMMUROK_RSP_OK;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_KEY_DELETE:
                    {
                        uint8_t kcat = s_pending_payload[0];
                        uint8_t kidx = s_pending_payload[1];
                        rspBuf[0] = (immurok_keystore_delete(kcat, kidx) == 0)
                                    ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_KEY_COMMIT:
                    {
                        uint8_t kcat = s_pending_payload[0];
                        uint8_t kidx = s_pending_payload[1];
                        rspBuf[0] = (immurok_keystore_commit(kcat, kidx) == 0)
                                    ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                    case IMMUROK_CMD_KEY_SIGN:
                    {
                        // Notify App: fingerprint approved, now signing
                        uint8_t fpApproved[1] = { 0x10 };  // FP_APPROVED
                        ImmurokService_SendResponse(fpApproved, 1);
                        // Defer sign to let BLE transmit the 0x10 notification first.
                        // The watchdog callback calls TMOS_SystemProcess() during the
                        // ~1.9s ECDSA computation to keep the BLE link alive.
                        tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 128);  // 80ms
                        break;
                    }
                    case IMMUROK_CMD_KEY_GENERATE:
                    {
                        uint8_t *name = &s_pending_payload[1];  // skip cat byte
                        // Generate directly into result buffer
                        int new_idx = immurok_keystore_generate(name, immurok_keystore_result_buf());
                        if(new_idx >= 0) {
                            immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                            uint8_t rsp3[3] = { IMMUROK_RSP_OK, 64, (uint8_t)new_idx };
                            ImmurokService_SendResponse(rsp3, 3);
                        } else {
                            rspBuf[0] = SEC_ERR_INTERNAL;
                            ImmurokService_SendResponse(rspBuf, 1);
                        }
                        break;
                    }
                    case IMMUROK_CMD_KEY_OTP_GET:
                    {
                        uint8_t kidx = s_pending_payload[0];
                        uint32_t ts = (uint32_t)s_pending_payload[1]
                                    | ((uint32_t)s_pending_payload[2] << 8)
                                    | ((uint32_t)s_pending_payload[3] << 16)
                                    | ((uint32_t)s_pending_payload[4] << 24);
                        // Adjust timestamp by elapsed time since gate started
                        uint32_t elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000000;
                        ts += elapsed;
                        uint8_t code[6];
                        if(immurok_keystore_totp(kidx, ts, code) == 0) {
                            uint8_t rsp7[7];
                            rsp7[0] = IMMUROK_RSP_OK;
                            memcpy(&rsp7[1], code, 6);
                            ImmurokService_SendResponse(rsp7, 7);
                        } else {
                            rspBuf[0] = SEC_ERR_INTERNAL;
                            ImmurokService_SendResponse(rspBuf, 1);
                        }
                        break;
                    }
                    case IMMUROK_CMD_PAIR_INIT:
                    {
                        if(immurok_security_pair_init() == 0) {
                            tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                            // Response sent from TMOS event handler
                        } else {
                            rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                            rspBuf[1] = SEC_ERR_INTERNAL;
                            ImmurokService_SendResponse(rspBuf, 2);
                        }
                        break;
                    }
                    default:
                        rspBuf[0] = IMMUROK_RSP_UNKNOWN_CMD;
                        ImmurokService_SendResponse(rspBuf, 1);
                        break;
                    }
                }
                // Priority 2: Pending auth request
                else if(immurok_security_has_pending_auth())
                {
                    s_fp_gate_last_verify = TMOS_GetSystemClock();
                    uint8_t rspBuf[1];
                    rspBuf[0] = SEC_OK;
                    ImmurokService_SendResponse(rspBuf, 1);
                    PRINT("Auth OK response sent (cooldown set)\n");
                    immurok_security_auth_cancel();
                }
                // Priority 3: Proactive match - send signed 0x21 notification
                else
                {
                    PRINT("FP match OK (no pending auth) - sending signed notify\n");

                    // Build signed notification: [0x21][page_id:2B][hmac:8B] = 11 bytes
                    int notify_len = immurok_security_sign_fp_match(page_id, s_fp_notify_data);
                    if(notify_len < 0) {
                        PRINT("Not paired, cannot send signed notify\n");
                        fp_power_off();
                        break;
                    }
                    s_fp_notify_len = notify_len;

                    s_fp_notify_pending = 1;
                    s_fp_notify_page_id = page_id;
                    s_fp_notify_start_time = TMOS_GetSystemClock();
                    s_fp_notify_phase = 0;
                    // CTRL already sent at touch debounce — host screen should be awake
                    tmos_start_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT, 16);  // 10ms (was 100ms)
                }
            }
            else
            {
                fp_led_flash(FP_LED_RED, 25, 1);
                PRINT("FP no match (ack=0x%02X)\n", ack);
                if(immurok_security_has_pending_auth() || s_pending_cmd != 0)
                {
                    // Notify App of mismatch so it can show "Try again" in terminal
                    PRINT("FP mismatch, notifying App, waiting for retry\n");
                    uint8_t notifyBuf[1] = { 0x07 };  // FP_NOT_MATCH
                    ImmurokService_SendResponse(notifyBuf, 1);
                }
                // Check overall gate timeout for pending commands
                if(s_pending_cmd != 0)
                {
                    uint32_t gate_elapsed = (TMOS_GetSystemClock() - s_pending_cmd_start) * 625 / 1000;
                    if(gate_elapsed > FP_GATE_TIMEOUT_MS)
                    {
                        PRINT("FP gate timeout (%dms), cancelling pending cmd 0x%02X\n",
                              (int)gate_elapsed, s_pending_cmd);
                        s_pending_cmd = 0;
                        uint8_t rspBuf[1];
                        rspBuf[0] = 0x07;  // AUTH_FAIL / gate timeout
                        ImmurokService_SendResponse(rspBuf, 1);
                    }
                    else
                    {
                        PRINT("FP gate: retry (%dms/%dms)\n", (int)gate_elapsed, FP_GATE_TIMEOUT_MS);
                    }
                }
                // No match - keep power on for retry via next touch IRQ
                fp_reset_power_timer();
            }
            break;
        }

        default:
            s_search_active = 0;
            break;
        }

        return (events ^ FP_SEARCH_EVT);
    }

    if(events & FP_ENROLL_EVT)
    {
        if(s_ota_active) { s_enroll_active = 0; return (events ^ FP_ENROLL_EVT); }

        // Non-blocking enrollment using state machine
        // States: 0=init, 1-6=wait finger N, 7=merge, 8=store
        static uint8_t enroll_step = 0;
        static uint32_t enroll_start = 0;

        if(!s_enroll_active) {
            enroll_step = 0;
            s_enroll_send_lift = 0;
            s_enroll_send_done = 0;
            return (events ^ FP_ENROLL_EVT);
        }

        // Check if we need to send final success response
        if(s_enroll_send_done) {
            s_enroll_send_done = 0;
            uint8_t rspBuf[2];
            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = (uint8_t)s_enroll_page_id;
            ImmurokService_SendResponse(rspBuf, 2);
            s_enroll_active = 0;
            enroll_step = 0;
            fp_reset_power_timer();
            return (events ^ FP_ENROLL_EVT);
        }

        // Extern functions from fingerprint.c
        extern int fp_send_cmd(uint8_t cmd, const uint8_t *data, uint16_t len);
        extern int fp_recv_ack(uint8_t *ack, uint8_t *data, uint16_t *len, uint32_t timeout_ms);

        uint8_t rspBuf[4];

        if(enroll_step == 0) {
            // Initialize - wake up fingerprint module first
            PRINT("ENROLL_EVT: waking module for slot %d\n", s_enroll_page_id);
            int wake_ret = fp_ensure_ready();
            if(wake_ret != FP_OK) {
                PRINT("ENROLL_EVT: wake failed %d\n", wake_ret);
                rspBuf[0] = 0x11;
                rspBuf[1] = 0xFF;  // FP_ENROLL_FAILED
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                fp_reset_power_timer();
                return (events ^ FP_ENROLL_EVT);
            }
            PRINT("ENROLL_EVT: starting slot %d\n", s_enroll_page_id);
            enroll_step = 1;
            enroll_start = TMOS_GetSystemClock();
            // Send initial status: [0x11, status=0(waiting), current=0, total=6]
            rspBuf[0] = 0x11;
            rspBuf[1] = 0;     // FP_ENROLL_WAITING
            rspBuf[2] = 0;     // current
            rspBuf[3] = 6;     // total
            ImmurokService_SendResponse(rspBuf, 4);
            tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 160);  // 100ms
        }
        else if(s_enroll_send_lift > 0) {
            // Send lift finger notification (delayed from previous capture)
            uint8_t capture_num = s_enroll_send_lift;
            s_enroll_send_lift = 0;
            rspBuf[0] = 0x11;
            rspBuf[1] = 3;     // FP_ENROLL_LIFT_FINGER
            rspBuf[2] = capture_num;
            rspBuf[3] = 6;
            ImmurokService_SendResponse(rspBuf, 4);
            // Wait for finger lift
            tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 1600);  // 1s
        }
        else if(enroll_step >= 1 && enroll_step <= 6) {
            // Try to capture finger N
            uint8_t capture_num = enroll_step;

            // Send GetImage command
            fp_send_cmd(0x01, NULL, 0);  // CMD_GET_IMAGE
            uint8_t ack;
            int ret = fp_recv_ack(&ack, NULL, NULL, 50);

            if(ret == FP_OK && ack == 0x00) {
                // Image captured, generate char
                uint8_t buf_id = capture_num;
                uint8_t params[1] = { buf_id };
                fp_send_cmd(0x02, params, 1);  // CMD_IMAGE2TZ
                ret = fp_recv_ack(&ack, NULL, NULL, 100);

                if(ret == FP_OK && ack == 0x00) {
                    PRINT("ENROLL_EVT: captured %d/6\n", capture_num);
                    // [0x11, status=1(captured), current, total]
                    rspBuf[0] = 0x11;
                    rspBuf[1] = 1;     // FP_ENROLL_CAPTURED
                    rspBuf[2] = capture_num;
                    rspBuf[3] = 6;
                    ImmurokService_SendResponse(rspBuf, 4);

                    enroll_step++;
                    if(enroll_step <= 6) {
                        // Schedule lift finger notification after 200ms (non-blocking)
                        s_enroll_send_lift = capture_num;  // Remember which capture to notify
                        tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // 320 * 625us = 200ms
                    } else {
                        // All captures done, merge
                        enroll_step = 7;  // Move to merge step
                        tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 160);
                    }
                } else {
                    // Gen char failed
                    PRINT("ENROLL_EVT: gen_char failed\n");
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);
                }
            }
            else {
                // No finger or timeout, retry
                uint32_t elapsed = (TMOS_GetSystemClock() - enroll_start) * 625 / 1000;
                if(elapsed > 60000) {
                    PRINT("ENROLL_EVT: timeout\n");
                    rspBuf[0] = 0x11;
                    rspBuf[1] = 0xFF;  // FP_ENROLL_FAILED
                    rspBuf[2] = 0;
                    rspBuf[3] = 0;
                    ImmurokService_SendResponse(rspBuf, 4);
                    s_enroll_active = 0;
                    enroll_step = 0;
                    fp_reset_power_timer();  // Start idle timer
                } else {
                    tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 320);  // 200ms
                }
            }
        }
        else if(enroll_step == 7) {
            // Merge
            PRINT("ENROLL_EVT: merging...\n");
            // Send processing notification
            rspBuf[0] = 0x11;
            rspBuf[1] = 2;     // FP_ENROLL_PROCESSING
            rspBuf[2] = 6;     // all captures done
            rspBuf[3] = 6;
            ImmurokService_SendResponse(rspBuf, 4);
            fp_send_cmd(0x05, NULL, 0);  // CMD_REG_MODEL
            uint8_t ack;
            int ret = fp_recv_ack(&ack, NULL, NULL, 500);

            if(ret == FP_OK && ack == 0x00) {
                enroll_step = 8;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 160);
            } else {
                PRINT("ENROLL_EVT: merge failed\n");
                rspBuf[0] = 0x11;
                rspBuf[1] = 0xFF;  // FP_ENROLL_FAILED
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
                s_enroll_active = 0;
                enroll_step = 0;
                fp_reset_power_timer();  // Start idle timer
            }
        }
        else if(enroll_step == 8) {
            // Store
            PRINT("ENROLL_EVT: storing to page %d\n", s_enroll_page_id);
            uint8_t params[3];
            params[0] = 1;  // buffer 1
            params[1] = (s_enroll_page_id >> 8) & 0xFF;
            params[2] = s_enroll_page_id & 0xFF;
            fp_send_cmd(0x06, params, 3);  // CMD_STORE
            uint8_t ack;
            int ret = fp_recv_ack(&ack, NULL, NULL, 500);

            if(ret == FP_OK && ack == 0x00) {
                PRINT("ENROLL_EVT: SUCCESS!\n");
                // Send completion progress notification first
                // Status 4 = FP_ENROLL_COMPLETE (custom status for completion)
                rspBuf[0] = 0x11;
                rspBuf[1] = 4;     // FP_ENROLL_COMPLETE
                rspBuf[2] = 6;
                rspBuf[3] = 6;
                ImmurokService_SendResponse(rspBuf, 4);
                // Schedule final success response after 100ms (non-blocking)
                s_enroll_send_done = 1;
                tmos_start_task(hidEmuTaskId, FP_ENROLL_EVT, 160);  // 100ms
                return (events ^ FP_ENROLL_EVT);
            } else {
                PRINT("ENROLL_EVT: store failed\n");
                rspBuf[0] = 0x11;
                rspBuf[1] = 0xFF;  // FP_ENROLL_FAILED
                rspBuf[2] = 0;
                rspBuf[3] = 0;
                ImmurokService_SendResponse(rspBuf, 4);
            }
            s_enroll_active = 0;
            enroll_step = 0;
            fp_reset_power_timer();  // Start idle timer after enrollment
        }

        return (events ^ FP_ENROLL_EVT);
    }

    if(events & FP_NOTIFY_RETRY_EVT)
    {
        // HID wake + ACK retry state machine for fingerprint match notification
        if(!s_fp_notify_pending)
        {
            // ACK received or cancelled
            return (events ^ FP_NOTIFY_RETRY_EVT);
        }

        // Check 15s total timeout
        uint32_t elapsed = (TMOS_GetSystemClock() - s_fp_notify_start_time) * 625 / 1000;
        if(elapsed > 15000)
        {
            PRINT("FP notify retry timeout (15s)\n");
            s_fp_notify_pending = 0;
            return (events ^ FP_NOTIFY_RETRY_EVT);
        }

        if(s_fp_notify_phase == 0)
        {
            // Phase 0: just sent CTRL (or retrying), now send notification
            ImmurokService_SendResponse(s_fp_notify_data, s_fp_notify_len);
            PRINT("FP notify sent (%d bytes), waiting ACK...\n", s_fp_notify_len);
            s_fp_notify_phase = 1;
            // Wait 200ms for ACK
            tmos_start_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT, 320);  // 320 * 625us = 200ms
        }
        else
        {
            // Phase 1: ACK not received within 200ms, retry with CTRL + notify
            PRINT("FP notify ACK timeout, retrying CTRL+notify...\n");
            hidEmuSendCtrlKey();
            s_fp_notify_phase = 0;
            // Wait 100ms then send notification
            tmos_start_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT, 160);  // 160 * 625us = 100ms
        }

        return (events ^ FP_NOTIFY_RETRY_EVT);
    }

    if(events & HID_KEY_RELEASE_EVT)
    {
        // Delayed key release — ensures press and release go in separate BLE packets
        uint8_t buf[HID_KEYBOARD_IN_RPT_LEN] = {0};
        HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                      HID_KEYBOARD_IN_RPT_LEN, buf);
        return (events ^ HID_KEY_RELEASE_EVT);
    }

    if(events & FP_POWER_OFF_EVT)
    {
        // Power off fingerprint module after idle timeout
        if(fp_is_powered() && !s_enroll_active) {
            PRINT("FP idle timeout - powering off\n");
            fp_power_off();
        }
        return (events ^ FP_POWER_OFF_EVT);
    }

    if(events & OTA_FLASH_ERASE_EVT)
    {
        // Shared event bit: deferred KEY_SIGN or ECDH compute (when not in OTA mode)
        if(!s_ota_active)
        {
            // All long computations (~2s) need supervision timeout > 2s.
            // Initial conn params have 720ms timeout — must request update first.
            if(!s_latency_accepted)
            {
                static uint8_t s_long_op_waited = 0;
                if(!s_long_op_waited)
                {
                    s_long_op_waited = 1;
                    PRINT("Long op deferred: requesting param update first\n");
                    tmos_set_event(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                    tmos_start_task(hidEmuTaskId, FP_GATE_EXEC_EVT, 3200);  // 2s
                    return (events ^ OTA_FLASH_ERASE_EVT);
                }
                s_long_op_waited = 0;
                PRINT("Long op: proceeding (param update may not be accepted yet)\n");
            }

            // Check if this is an ECDH computation
            immurok_ecdh_state_t ecdh_state = immurok_security_get_ecdh_state();
            if(ecdh_state == ECDH_STATE_MAKE_KEY)
            {
                // ECDH key generation (~2s)
                uint8_t rspBuf[34];
                if(immurok_security_pair_make_key() == 0) {
                    rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                    immurok_security_pair_get_pubkey(&rspBuf[1]);
                    ImmurokService_SendResponse(rspBuf, 34);
                    PRINT("ECDH PAIR_INIT response sent\n");
                } else {
                    rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                    rspBuf[1] = SEC_ERR_INTERNAL;
                    ImmurokService_SendResponse(rspBuf, 2);
                }
                return (events ^ OTA_FLASH_ERASE_EVT);
            }
            if(ecdh_state == ECDH_STATE_SHARED_SECRET)
            {
                // ECDH shared secret computation (~2s)
                uint8_t rspBuf[2];
                rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
                if(immurok_security_pair_compute_secret() == 0) {
                    rspBuf[1] = SEC_OK;
                    PRINT("ECDH PAIR_CONFIRM response sent (success)\n");
                } else {
                    rspBuf[1] = SEC_ERR_INTERNAL;
                    PRINT("ECDH PAIR_CONFIRM response sent (failed)\n");
                }
                ImmurokService_SendResponse(rspBuf, 2);
                return (events ^ OTA_FLASH_ERASE_EVT);
            }

            uint8_t kidx = s_pending_payload[1];
            uint8_t *hash = &s_pending_payload[2];
            uint8_t rspBuf[2];
            if(immurok_keystore_sign(kidx, hash, immurok_keystore_result_buf()) == 0) {
                immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = 64;
                PRINT("ECDSA sign done\n");
                ImmurokService_SendResponse(rspBuf, 2);
            } else {
                rspBuf[0] = SEC_ERR_INTERNAL;
                PRINT("ECDSA sign failed\n");
                ImmurokService_SendResponse(rspBuf, 1);
            }
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        uint8_t status;

        PRINT("OTA ERASE: %08x block %d/%d\n",
              (int)(s_ota_erase_addr + s_ota_erase_count * FLASH_BLOCK_SIZE),
              (int)s_ota_erase_count, (int)s_ota_erase_blocks);

        status = FLASH_ROM_ERASE(s_ota_erase_addr + s_ota_erase_count * FLASH_BLOCK_SIZE,
                                  FLASH_BLOCK_SIZE);

        if(status != SUCCESS)
        {
            PRINT("OTA ERASE failed: %d\n", status);
            OTA_IAP_SendStatus(status);
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        s_ota_erase_count++;

        if(s_ota_erase_count >= s_ota_erase_blocks)
        {
            PRINT("OTA ERASE complete\n");
            OTA_IAP_SendStatus(SUCCESS);
            return (events ^ OTA_FLASH_ERASE_EVT);
        }

        // Continue erasing (return events without XOR to process again)
        return events;
    }

    return 0;
}

/*********************************************************************
 * @fn      hidEmu_ProcessTMOSMsg
 *
 * @brief   Process an incoming task message.
 *
 * @param   pMsg - message to process
 *
 * @return  none
 */
static void hidEmu_ProcessTMOSMsg(tmos_event_hdr_t *pMsg)
{
    switch(pMsg->event)
    {
        default:
            break;
    }
}

/*********************************************************************
 * @fn      hidEmuSendKbdReport
 *
 * @brief   Build and send a HID keyboard report.
 *
 * @param   keycode - HID keycode.
 *
 * @return  none
 */
static void hidEmuSendKbdReport(uint8_t keycode)
{
    uint8_t buf[HID_KEYBOARD_IN_RPT_LEN];

    buf[0] = 0;       // Modifier keys
    buf[1] = 0;       // Reserved
    buf[2] = keycode; // Keycode 1
    buf[3] = 0;       // Keycode 2
    buf[4] = 0;       // Keycode 3
    buf[5] = 0;       // Keycode 4
    buf[6] = 0;       // Keycode 5
    buf[7] = 0;       // Keycode 6

    HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                  HID_KEYBOARD_IN_RPT_LEN, buf);
}

/*********************************************************************
 * @fn      hidEmuSendCtrlKey
 *
 * @brief   Send a CTRL key press and release to wake host from sleep.
 *          Uses LEFT_CTRL modifier only (no keycode) to avoid typing.
 *
 * @return  none
 */
static void hidEmuSendCtrlKey(void)
{
    uint8_t buf[HID_KEYBOARD_IN_RPT_LEN] = {0};

    // Press: LEFT_CTRL modifier only
    buf[0] = 0x01;  // LEFT_CTRL
    HidDev_Report(HID_RPT_ID_KEY_IN, HID_REPORT_TYPE_INPUT,
                  HID_KEYBOARD_IN_RPT_LEN, buf);

    // Schedule key release after 80ms (>1 connection interval)
    // to ensure press and release go in separate BLE packets
    tmos_start_task(hidEmuTaskId, HID_KEY_RELEASE_EVT, 128);  // 128 * 625us = 80ms
}

/*********************************************************************
 * @fn      hidEmuStateCB
 *
 * @brief   GAP state change callback.
 *
 * @param   newState - new state
 *
 * @return  none
 */
static void hidEmuStateCB(gapRole_States_t newState, gapRoleEvent_t *pEvent)
{
    switch(newState & GAPROLE_STATE_ADV_MASK)
    {
        case GAPROLE_STARTED:
        {
            uint8_t ownAddr[6];
            GAPRole_GetParameter(GAPROLE_BD_ADDR, ownAddr);
            GAP_ConfigDeviceAddr(ADDRTYPE_STATIC, ownAddr);
            PRINT("Initialized..\n");
        }
        break;

        case GAPROLE_ADVERTISING:
            if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Advertising..\n");
            }
            break;

        case GAPROLE_CONNECTED:
            if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                gapEstLinkReqEvent_t *event = (gapEstLinkReqEvent_t *)pEvent;

                // get connection handle
                hidEmuConnHandle = event->connectionHandle;
                tmos_start_task(hidEmuTaskId, START_PARAM_UPDATE_EVT, START_PARAM_UPDATE_EVT_DELAY);
                // Cancel slow advertising timer, restore fast interval for next disconnect
                tmos_stop_task(hidEmuTaskId, SLOW_ADV_EVT);
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
                PRINT("Connected..\n");
                // Print connection parameters
                // Interval: unit 1.25ms, Latency: events, Timeout: unit 10ms
                PRINT("Conn params: Interval=%d (%d.%02dms), Latency=%d, Timeout=%d (%dms)\n",
                      event->connInterval,
                      (event->connInterval * 5) / 4, ((event->connInterval * 5) % 4) * 25,
                      event->connLatency,
                      event->connTimeout, event->connTimeout * 10);
            }
            break;

        case GAPROLE_CONNECTED_ADV:
            if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Connected Advertising..\n");
            }
            break;

        case GAPROLE_WAITING:
            if(pEvent->gap.opcode == GAP_END_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Waiting for advertising..\n");
            }
            else if(pEvent->gap.opcode == GAP_LINK_TERMINATED_EVENT)
            {
                PRINT("Disconnected.. Reason:%x\n", pEvent->linkTerminate.reason);
                // Clear pending FP gate state
                s_pending_cmd = 0;
                s_pending_payload_len = 0;
                immurok_security_auth_cancel();
                // Reset param update state for next connection
                s_param_update_retries = 0;
                s_latency_accepted = 0;
                tmos_stop_task(hidEmuTaskId, START_PARAM_UPDATE_EVT);
                // Start fast advertising, schedule switch to slow after 30s
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, ADV_FAST_INT);
                GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, ADV_FAST_INT);
                tmos_start_task(hidEmuTaskId, SLOW_ADV_EVT, SLOW_ADV_DELAY);
            }
            else if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                PRINT("Advertising timeout..\n");
            }
            // Enable advertising
            {
                uint8_t adv_enable = TRUE;
                GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &adv_enable);
            }
            break;

        case GAPROLE_ERROR:
            PRINT("Error %x ..\n", pEvent->gap.opcode);
            break;

        default:
            break;
    }
}

/*********************************************************************
 * @fn      hidEmuRcvReport
 *
 * @brief   Process an incoming HID keyboard report.
 *
 * @param   len - Length of report.
 * @param   pData - Report data.
 *
 * @return  status
 */
static uint8_t hidEmuRcvReport(uint8_t len, uint8_t *pData)
{
    // verify data length
    if(len == HID_LED_OUT_RPT_LEN)
    {
        // set LEDs
        return SUCCESS;
    }
    else
    {
        return ATT_ERR_INVALID_VALUE_SIZE;
    }
}

/*********************************************************************
 * @fn      hidEmuRptCB
 *
 * @brief   HID Dev report callback.
 *
 * @param   id - HID report ID.
 * @param   type - HID report type.
 * @param   uuid - attribute uuid.
 * @param   oper - operation:  read, write, etc.
 * @param   len - Length of report.
 * @param   pData - Report data.
 *
 * @return  GATT status code.
 */
static uint8_t hidEmuRptCB(uint8_t id, uint8_t type, uint16_t uuid,
                           uint8_t oper, uint16_t *pLen, uint8_t *pData)
{
    uint8_t status = SUCCESS;

    // write
    if(oper == HID_DEV_OPER_WRITE)
    {
        if(uuid == REPORT_UUID)
        {
            // process write to LED output report; ignore others
            if(type == HID_REPORT_TYPE_OUTPUT)
            {
                status = hidEmuRcvReport(*pLen, pData);
            }
        }

        if(status == SUCCESS)
        {
            status = Hid_SetParameter(id, type, uuid, *pLen, pData);
        }
    }
    // read
    else if(oper == HID_DEV_OPER_READ)
    {
        status = Hid_GetParameter(id, type, uuid, pLen, pData);
    }
    // notifications enabled
    else if(oper == HID_DEV_OPER_ENABLE)
    {
        tmos_start_task(hidEmuTaskId, START_REPORT_EVT, 500);
    }
    return status;
}

/*********************************************************************
 * @fn      hidEmuEvtCB
 *
 * @brief   HID Dev event callback.
 *
 * @param   evt - event ID.
 *
 * @return  HID response code.
 */
static void hidEmuEvtCB(uint8_t evt)
{
    switch(evt)
    {
    case HID_DEV_SUSPEND_EVT:
        PRINT("HID Suspend\n");
        break;
    case HID_DEV_EXIT_SUSPEND_EVT:
        PRINT("HID Exit Suspend\n");
        break;
    default:
        PRINT("HID evt: %d\n", evt);
        break;
    }
}

/*********************************************************************
 * @fn      HidEmu_ImmurokCommandCB
 *
 * @brief   Process immurok GATT command from host
 *
 * @param   connHandle - connection handle
 * @param   pData - command data [cmd][len][payload...]
 * @param   len - data length
 *
 * @return  none
 */
// Check if fingerprint gate is needed (0 = no gate, 1 = need FP verification)
// Returns 0 if no fingerprints enrolled or recently verified (within cooldown)
// Fixed window: timer only set on actual FP verification, not on pass-through
static int fp_gate_needed(void)
{
    uint8_t bitmap = 0;
    if(fp_ensure_ready() == FP_OK) {
        fp_get_fingerprint_bitmap(&bitmap);
    }
    if(bitmap == 0) return 0;
    uint32_t ms_since = (TMOS_GetSystemClock() - s_fp_gate_last_verify) * 625 / 1000;
    if(ms_since > FP_GATE_COOLDOWN_MS) return 1;
    return 0;
}

static void HidEmu_ImmurokCommandCB(uint16_t connHandle, uint8_t *pData, uint8_t len)
{
    uint8_t rspBuf[IMMUROK_RSP_MAX_LEN];
    uint8_t rspLen = 1;

    if(len < 2) {
        rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
        ImmurokService_SendResponse(rspBuf, rspLen);
        return;
    }

    uint8_t cmd = pData[0];
    uint8_t payloadLen = pData[1];

    PRINT("immurok CMD: 0x%02X, len=%d\n", cmd, payloadLen);

    // Reject all immurok commands during OTA
    if(s_ota_active) {
        PRINT("  Rejected (OTA in progress)\n");
        rspBuf[0] = IMMUROK_RSP_BUSY;
        ImmurokService_SendResponse(rspBuf, rspLen);
        return;
    }

    // Store connection handle for notifications
    ImmurokService_SetConnHandle(connHandle);

    switch(cmd) {
    case IMMUROK_CMD_GET_STATUS:
        PRINT("  GET_STATUS\n");
        {
            // Response: [OK][fp_bitmap:1B][paired:1B]
            if(fp_ensure_ready() == FP_OK) {
                uint8_t bitmap = 0;
                fp_get_fingerprint_bitmap(&bitmap);
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = bitmap;
                rspBuf[2] = immurok_security_is_paired() ? 1 : 0;
                rspLen = 3;
            } else {
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = 0;  // bitmap unknown
                rspBuf[2] = immurok_security_is_paired() ? 1 : 0;
                rspLen = 3;
            }
        }
        break;

    case IMMUROK_CMD_FP_LIST:
        {
            // Wake up fingerprint module
            if(fp_ensure_ready() != FP_OK) {
                rspBuf[0] = 0xFF;  // Error
                break;
            }
            // Get bitmap of which slots have fingerprints
            uint8_t bitmap = 0;
            if(fp_get_fingerprint_bitmap(&bitmap) == FP_OK) {
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = bitmap;  // Bitmap: bit 0-4 for slots 0-4
                rspLen = 2;
                // Count bits for logging
                uint8_t count = 0;
                for(int i = 0; i < 5; i++) {
                    if(bitmap & (1 << i)) count++;
                }
                PRINT("  FP_LIST: bitmap=0x%02X (%d templates)\n", bitmap, count);
            } else {
                // Fallback to count-based response
                uint16_t count = 0;
                fp_get_template_count(&count);
                // Generate bitmap from count (assumes sequential slots)
                bitmap = (1 << count) - 1;
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = bitmap;
                rspLen = 2;
                PRINT("  FP_LIST: fallback bitmap=0x%02X (%d templates)\n", bitmap, count);
            }
        }
        break;

    case IMMUROK_CMD_ENROLL_START:
        // Payload: [slotId:1]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t slotId = pData[2];
            PRINT("  ENROLL_START slot=%d\n", slotId);

            if(s_enroll_active) {
                rspBuf[0] = IMMUROK_RSP_BUSY;
            } else if(slotId >= 5) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            } else {
                // Check if slot already has fingerprint
                uint8_t bitmap = 0;
                fp_ensure_ready();
                if(fp_get_fingerprint_bitmap(&bitmap) == FP_OK) {
                    if(bitmap & (1 << slotId)) {
                        PRINT("  Slot %d already occupied (bitmap=0x%02X)\n", slotId, bitmap);
                        rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                        break;
                    }
                }

                // Fingerprint gate: if any fingerprint exists, require verification
                if(bitmap != 0) {
                    PRINT("  FP gate: caching ENROLL_START, waiting for FP verify\n");
                    s_pending_cmd = IMMUROK_CMD_ENROLL_START;
                    s_pending_cmd_start = TMOS_GetSystemClock();
                    s_pending_payload[0] = slotId;
                    s_pending_payload_len = 1;
                    rspBuf[0] = IMMUROK_RSP_WAIT_FP;
                } else {
                    // No fingerprints yet, allow directly
                    s_enroll_page_id = slotId;
                    s_enroll_active = 1;
                    tmos_set_event(hidEmuTaskId, FP_ENROLL_EVT);
                    rspBuf[0] = IMMUROK_RSP_OK;
                }
            }
        }
        break;

    case IMMUROK_CMD_DELETE_FP:
        // Payload: [slotId:1]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t slotId = pData[2];
            PRINT("  DELETE_FP slot=%d\n", slotId);

            // Fingerprint gate: if any fingerprint exists, require verification
            uint8_t bitmap = 0;
            fp_ensure_ready();
            fp_get_fingerprint_bitmap(&bitmap);
            if(bitmap != 0) {
                PRINT("  FP gate: caching DELETE_FP, waiting for FP verify\n");
                s_pending_cmd = IMMUROK_CMD_DELETE_FP;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = slotId;
                s_pending_payload_len = 1;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints, delete directly (shouldn't normally happen)
                if(fp_ensure_ready() != FP_OK) {
                    rspBuf[0] = SEC_ERR_INTERNAL;
                    break;
                }
                int ret = fp_delete(slotId, 1);
                rspBuf[0] = (ret == FP_OK) ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
            }
        }
        break;

    case IMMUROK_CMD_AUTH_REQUEST:
        // No payload needed
        PRINT("  AUTH_REQUEST\n");
        {
            immurok_security_set_auth_state(AUTH_STATE_WAIT_FINGERPRINT);
            rspBuf[0] = IMMUROK_RSP_WAIT_FP;

            // Preheat FP module (power on + verify) but don't start search.
            // Search will be triggered by touch GPIO interrupt.
            if(!fp_is_powered()) {
                s_auth_preheat = 1;
                fp_power_on();
                s_fp_power_on_tick = RTC_GetCycle32k();
                tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 48);  // 30ms (poll for 0x55)
            } else if(!fp_is_ready()) {
                s_auth_preheat = 1;
                tmos_start_task(hidEmuTaskId, FP_WAKE_DONE_EVT, 16);  // 10ms delay
            }
            // If already ready, just wait for touch — no action needed
        }
        break;

    case IMMUROK_CMD_PAIR_INIT:
        PRINT("  PAIR_INIT\n");
        {
            // Fingerprint gate: require verification if fingerprints enrolled
            uint8_t bitmap = 0;
            if(fp_ensure_ready() == FP_OK) {
                fp_get_fingerprint_bitmap(&bitmap);
            }
            if(bitmap != 0 && fp_gate_needed()) {
                PRINT("  FP gate: caching PAIR_INIT, waiting for FP verify\n");
                s_pending_cmd = IMMUROK_CMD_PAIR_INIT;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload_len = 0;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
                break;
            }

            // Start ECDH key generation via TMOS event (non-blocking)
            if(immurok_security_pair_init() == 0) {
                tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                // No immediate response — response sent from TMOS event handler
                return;
            } else {
                rspBuf[0] = IMMUROK_CMD_PAIR_INIT;
                rspBuf[1] = SEC_ERR_INTERNAL;
                rspLen = 2;
            }
        }
        break;

    case IMMUROK_CMD_PAIR_CONFIRM:
        PRINT("  PAIR_CONFIRM\n");
        if(payloadLen != 33) {
            rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
            rspBuf[1] = SEC_ERR_INVALID_PARAM;
            rspLen = 2;
            break;
        }
        {
            // Receive App compressed pubkey, start shared_secret via TMOS event
            if(immurok_security_pair_confirm(&pData[2]) == 0) {
                tmos_set_event(hidEmuTaskId, FP_GATE_EXEC_EVT);
                // No immediate response — response sent from TMOS event handler
                return;
            } else {
                rspBuf[0] = IMMUROK_CMD_PAIR_CONFIRM;
                rspBuf[1] = SEC_ERR_INVALID_STATE;
                rspLen = 2;
            }
        }
        break;

    case IMMUROK_CMD_PAIR_STATUS:
        PRINT("  PAIR_STATUS\n");
        {
            rspBuf[0] = IMMUROK_CMD_PAIR_STATUS;
            rspBuf[1] = immurok_security_is_paired() ? 0x01 : 0x00;
            rspLen = 2;
        }
        break;

    case IMMUROK_CMD_FP_MATCH_ACK:
        PRINT("  FP_MATCH_ACK received\n");
        if(s_fp_notify_pending)
        {
            s_fp_notify_pending = 0;
            tmos_stop_task(hidEmuTaskId, FP_NOTIFY_RETRY_EVT);
            PRINT("  Notify retry cancelled (ACK OK)\n");
        }
        rspBuf[0] = IMMUROK_RSP_OK;
        break;

    case IMMUROK_CMD_FACTORY_RESET:
        PRINT("  FACTORY_RESET\n");
        {
            // Fingerprint gate: if any fingerprint exists, require verification
            uint8_t bitmap = 0;
            if(fp_ensure_ready() == FP_OK) {
                fp_get_fingerprint_bitmap(&bitmap);
            }
            if(bitmap != 0) {
                PRINT("  FP gate: caching FACTORY_RESET, waiting for FP verify\n");
                s_pending_cmd = IMMUROK_CMD_FACTORY_RESET;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload_len = 0;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints, reset directly
                immurok_security_factory_reset();
                HidDev_SetParameter(HIDDEV_ERASE_ALLBONDS, 0, NULL);
                rspBuf[0] = IMMUROK_RSP_OK;
            }
        }
        break;

    // ---- Keystore commands ----

    case IMMUROK_CMD_KEY_COUNT:
        // Payload: [cat:1B]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            int cnt = immurok_keystore_count(cat);
            if(cnt < 0) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            } else {
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = (uint8_t)cnt;
                rspLen = 2;
            }
            PRINT("  KEY_COUNT cat=%d count=%d\n", cat, cnt);
        }
        break;

    case IMMUROK_CMD_KEY_READ:
        // Payload: [cat:1B][idx:1B][off:1B]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            uint8_t off = pData[4];

            // Determine entry size and readable limit for this category
            // Secret portions are never exposed via KEY_READ
            uint16_t entry_size = 0;
            uint16_t readable_size = 0;
            switch(cat) {
            case KEYSTORE_CAT_SSH:
                entry_size = KEYSTORE_SSH_ENTRY_SIZE;   // 112B
                readable_size = 80;                      // name[16] + pubkey[64], hide privkey
                break;
            case KEYSTORE_CAT_OTP:
                entry_size = KEYSTORE_OTP_ENTRY_SIZE;   // 92B
                readable_size = 60;                      // name[30] + service[30], hide secret
                break;
            case KEYSTORE_CAT_API:
                entry_size = KEYSTORE_API_ENTRY_SIZE;   // 160B
                readable_size = KEYSTORE_API_ENTRY_SIZE; // full read allowed (FP gate below)
                break;
            default:
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                ImmurokService_SendResponse(rspBuf, rspLen);
                return;
            }

            // API keys require fingerprint verification to read
            if(cat == KEYSTORE_CAT_API && off >= 32) {
                if(fp_gate_needed()) {
                    PRINT("  FP gate: KEY_READ API secret\n");
                    // Cannot cache KEY_READ as pending (stateless), just reject
                    rspBuf[0] = SEC_ERR_WAIT_FP;
                    break;
                }
            }

            if(off >= readable_size) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                break;
            }

            uint16_t remaining = readable_size - off;
            uint8_t chunk = (remaining > 59) ? 59 : (uint8_t)remaining;

            // Response: [OK][total_lo:1B][off:1B][data...<=59B]
            // Note: total_lo = readable_size & 0xFF (App uses known size)
            if(immurok_keystore_read(cat, idx, off, &rspBuf[3], chunk) == 0) {
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = (uint8_t)(readable_size & 0xFF);
                rspBuf[2] = off;
                rspLen = 3 + chunk;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
            PRINT("  KEY_READ cat=%d idx=%d off=%d chunk=%d\n", cat, idx, off, chunk);
        }
        break;

    case IMMUROK_CMD_KEY_WRITE:
        // Payload: [cat:1B][idx:1B][off:1B][data...<=59B]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            uint8_t off = pData[4];
            uint8_t data_len = payloadLen - 3;

            if(immurok_keystore_stage(cat, idx, off, &pData[5], data_len) == 0) {
                rspBuf[0] = IMMUROK_RSP_OK;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
            PRINT("  KEY_WRITE cat=%d idx=%d off=%d len=%d\n", cat, idx, off, data_len);
        }
        break;

    case IMMUROK_CMD_KEY_DELETE:
        // Payload: [cat:1B][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            PRINT("  KEY_DELETE cat=%d idx=%d\n", cat, idx);

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed()) {
                PRINT("  FP gate: caching KEY_DELETE\n");
                s_pending_cmd = IMMUROK_CMD_KEY_DELETE;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = cat;
                s_pending_payload[1] = idx;
                s_pending_payload_len = 2;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                rspBuf[0] = (immurok_keystore_delete(cat, idx) == 0)
                            ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
            }
        }
        break;

    case IMMUROK_CMD_KEY_COMMIT:
        // Payload: [cat:1B][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t cat = pData[2];
            uint8_t idx = pData[3];
            PRINT("  KEY_COMMIT cat=%d idx=%d\n", cat, idx);

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed()) {
                PRINT("  FP gate: caching KEY_COMMIT\n");
                s_pending_cmd = IMMUROK_CMD_KEY_COMMIT;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = cat;
                s_pending_payload[1] = idx;
                s_pending_payload_len = 2;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                rspBuf[0] = (immurok_keystore_commit(cat, idx) == 0)
                            ? IMMUROK_RSP_OK : SEC_ERR_INTERNAL;
            }
        }
        break;

    // ---- SSH crypto commands ----

    case IMMUROK_CMD_KEY_SIGN:
        // Payload: [cat:1B(0)][idx:1B][hash_off:1B][hash_data...]
        if(payloadLen < 3) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[3];
            uint8_t hash_off = pData[4];
            uint8_t data_len = payloadLen - 3;
            PRINT("  KEY_SIGN idx=%d off=%d len=%d\n", idx, hash_off, data_len);

            // Store hash fragment into pending_payload
            if(hash_off + data_len <= 32) {
                memcpy(&s_pending_payload[2 + hash_off], &pData[5], data_len);
            }

            // Only proceed when we have the complete hash (off=0 with 32B is single-shot)
            if(hash_off == 0 && data_len >= 32) {
                // Fingerprint gate (with cooldown for batch ops)
                if(fp_gate_needed()) {
                    PRINT("  FP gate: caching KEY_SIGN\n");
                    s_pending_cmd = IMMUROK_CMD_KEY_SIGN;
                    s_pending_cmd_start = TMOS_GetSystemClock();
                    s_pending_payload[0] = 0;  // cat (SSH)
                    s_pending_payload[1] = idx;
                    // hash is at s_pending_payload[2..33]
                    memcpy(&s_pending_payload[2], &pData[5], 32);
                    s_pending_payload_len = 34;
                    rspBuf[0] = IMMUROK_RSP_WAIT_FP;
                } else {
                    // No fingerprints enrolled, sign directly into result buffer
                    if(immurok_keystore_sign(idx, &pData[5], immurok_keystore_result_buf()) == 0) {
                        immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                        rspBuf[0] = IMMUROK_RSP_OK;
                        rspBuf[1] = 64;
                        rspLen = 2;
                    } else {
                        rspBuf[0] = SEC_ERR_INTERNAL;
                    }
                }
            } else {
                // Partial hash received, ACK
                rspBuf[0] = IMMUROK_RSP_OK;
            }
        }
        break;

    case IMMUROK_CMD_KEY_GETPUB:
        // Payload: [cat:1B(0)][idx:1B]
        if(payloadLen < 2) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[3];
            PRINT("  KEY_GETPUB idx=%d\n", idx);

            if(immurok_keystore_getpub(idx, immurok_keystore_result_buf()) == 0) {
                immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                rspBuf[0] = IMMUROK_RSP_OK;
                rspBuf[1] = 64;
                rspLen = 2;
            } else {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            }
        }
        break;

    case IMMUROK_CMD_KEY_GENERATE:
        // Payload: [cat:1B(0)][name_data_16B]
        if(payloadLen < 17) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            PRINT("  KEY_GENERATE\n");

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed()) {
                PRINT("  FP gate: caching KEY_GENERATE\n");
                s_pending_cmd = IMMUROK_CMD_KEY_GENERATE;
                s_pending_cmd_start = TMOS_GetSystemClock();
                memcpy(s_pending_payload, &pData[2], 17);  // cat + 16B name
                s_pending_payload_len = 17;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                int new_idx = immurok_keystore_generate(&pData[3], immurok_keystore_result_buf());
                if(new_idx >= 0) {
                    immurok_keystore_set_result(immurok_keystore_result_buf(), 64);
                    rspBuf[0] = IMMUROK_RSP_OK;
                    rspBuf[1] = 64;
                    rspBuf[2] = (uint8_t)new_idx;
                    rspLen = 3;
                } else {
                    rspBuf[0] = SEC_ERR_INTERNAL;
                }
            }
        }
        break;

    case IMMUROK_CMD_KEY_RESULT:
        // Payload: [off:1B]
        if(payloadLen < 1) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t off = pData[2];
            uint8_t total = immurok_keystore_result_len();
            PRINT("  KEY_RESULT off=%d total=%d\n", off, total);

            if(off >= total) {
                rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
                break;
            }

            uint8_t remaining = total - off;
            uint8_t chunk = (remaining > 59) ? 59 : remaining;
            uint8_t *rbuf = immurok_keystore_result_buf();

            rspBuf[0] = IMMUROK_RSP_OK;
            rspBuf[1] = total;
            rspBuf[2] = off;
            memcpy(&rspBuf[3], &rbuf[off], chunk);
            rspLen = 3 + chunk;
        }
        break;

    case IMMUROK_CMD_KEY_OTP_GET:
        // Payload: [idx:1B][timestamp:4B LE]
        if(payloadLen < 5) {
            rspBuf[0] = IMMUROK_RSP_INVALID_PARAM;
            break;
        }
        {
            uint8_t idx = pData[2];
            uint32_t ts = (uint32_t)pData[3]
                        | ((uint32_t)pData[4] << 8)
                        | ((uint32_t)pData[5] << 16)
                        | ((uint32_t)pData[6] << 24);
            PRINT("  KEY_OTP_GET idx=%d ts=%lu\n", idx, ts);

            // Fingerprint gate (with cooldown for batch ops)
            if(fp_gate_needed()) {
                PRINT("  FP gate: caching KEY_OTP_GET\n");
                s_pending_cmd = IMMUROK_CMD_KEY_OTP_GET;
                s_pending_cmd_start = TMOS_GetSystemClock();
                s_pending_payload[0] = idx;
                s_pending_payload[1] = pData[3];
                s_pending_payload[2] = pData[4];
                s_pending_payload[3] = pData[5];
                s_pending_payload[4] = pData[6];
                s_pending_payload_len = 5;
                rspBuf[0] = IMMUROK_RSP_WAIT_FP;
            } else {
                // No fingerprints enrolled, compute directly
                uint8_t code[6];
                if(immurok_keystore_totp(idx, ts, code) == 0) {
                    rspBuf[0] = IMMUROK_RSP_OK;
                    memcpy(&rspBuf[1], code, 6);
                    rspLen = 7;
                } else {
                    rspBuf[0] = SEC_ERR_INTERNAL;
                }
            }
        }
        break;

    default:
        PRINT("  Unknown command\n");
        rspBuf[0] = IMMUROK_RSP_UNKNOWN_CMD;
        break;
    }

    // Send response
    ImmurokService_SendResponse(rspBuf, rspLen);
}

/*********************************************************************
 * OTA IAP Functions
 *********************************************************************/

/*********************************************************************
 * @fn      OTA_IAP_SendStatus
 * @brief   Send OTA command status response
 */
static void OTA_IAP_SendStatus(uint8_t status)
{
    uint8_t buf[2];
    buf[0] = status;
    buf[1] = 0;
    OTAProfile_SendData(OTAPROFILE_CHAR, buf, 2);
}

/*********************************************************************
 * @fn      SwitchImageFlag
 * @brief   Switch image flag in DataFlash
 */
static void SwitchImageFlag(uint8_t new_flag)
{
    __attribute__((aligned(8))) uint8_t block_buf[16];

    // Read current data
    EEPROM_READ(OTA_DATAFLASH_ADD, (uint32_t *)block_buf, 4);

    // Erase page
    EEPROM_ERASE(OTA_DATAFLASH_ADD, EEPROM_PAGE_SIZE);

    // Update image flag
    block_buf[0] = new_flag;

    // Write back
    EEPROM_WRITE(OTA_DATAFLASH_ADD, (uint32_t *)block_buf, 4);

    PRINT("Image flag switched to 0x%02X\n", new_flag);
}

/*********************************************************************
 * @fn      OTA_IAP_DataDeal
 * @brief   Process received OTA IAP command
 */
static void OTA_IAP_DataDeal(void)
{
    uint8_t cmd = s_ota_iap_data.other.buf[0];
    uint32_t addr, len;
    uint8_t status;

    switch(cmd)
    {
        case CMD_IAP_PROM:
        {
            // Program flash data
            len = s_ota_iap_data.program.len;
            addr = (uint32_t)(s_ota_iap_data.program.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.program.addr[1]) << 8);
            addr = addr * 16;  // Address is 16-byte aligned
            addr += IMAGE_B_START_ADD;  // Offset to Image B

            PRINT("OTA PROM: addr=%08x len=%d\n", (int)addr, (int)len);

            // Verify address is within Image B
            if(addr < IMAGE_B_START_ADD || (addr + len) > IMAGE_IAP_START_ADD)
            {
                PRINT("OTA PROM: address out of range\n");
                OTA_IAP_SendStatus(0xFF);
                break;
            }

            // Require HEADER before WRITE (no plaintext OTA)
            if(!s_ota_sec.active)
            {
                PRINT("OTA PROM: rejected - no HEADER\n");
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            {
                // Decrypt in-place, update SHA256
                uint32_t stream_offset = s_ota_sec.bytes_written;
                aes128_ctr_xcrypt(&s_ota_sec.aes_ctx, s_ota_sec.header.iv,
                                  stream_offset,
                                  s_ota_iap_data.program.buf, (size_t)len);
                sha256_update(&s_ota_sec.sha256_ctx,
                              s_ota_iap_data.program.buf, (size_t)len);
                s_ota_sec.bytes_written += len;
            }

            status = FLASH_ROM_WRITE(addr, s_ota_iap_data.program.buf, (uint16_t)len);
            if(status != SUCCESS)
            {
                PRINT("OTA PROM failed: %d\n", status);
            }
            OTA_IAP_SendStatus(status);
            break;
        }

        case CMD_IAP_HEADER:
        {
            // Receive .imfw header (96 bytes in program.buf area)
            // Raw data starts at buf[2] (skip cmd + len)
            uint8_t *hdr_data = &s_ota_iap_data.other.buf[2];
            uint8_t hdr_len = s_ota_iap_data.other.buf[1];

            PRINT("OTA HEADER: len=%d (expected %d)\n", hdr_len, IMFW_HEADER_SIZE);

            if(hdr_len != IMFW_HEADER_SIZE)
            {
                PRINT("OTA HEADER: invalid size\n");
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            // Copy header
            memcpy(&s_ota_sec.header, hdr_data, IMFW_HEADER_SIZE);

            // Validate magic and hardware ID
            if(s_ota_sec.header.magic != IMFW_MAGIC)
            {
                PRINT("OTA HEADER: bad magic 0x%08lx\n", (unsigned long)s_ota_sec.header.magic);
                OTA_IAP_SendStatus(0xFD);
                break;
            }
            if(s_ota_sec.header.hw_id != IMFW_HARDWARE_ID)
            {
                PRINT("OTA HEADER: bad hw_id 0x%04x\n", s_ota_sec.header.hw_id);
                OTA_IAP_SendStatus(0xFC);
                break;
            }
            if(s_ota_sec.header.fw_size > IMAGE_SIZE)
            {
                PRINT("OTA HEADER: fw too large %lu\n", (unsigned long)s_ota_sec.header.fw_size);
                OTA_IAP_SendStatus(0xFB);
                break;
            }

            // Initialize AES and SHA256 contexts
            aes128_init(&s_ota_sec.aes_ctx, OTA_AES_KEY);
            sha256_init(&s_ota_sec.sha256_ctx);
            s_ota_sec.bytes_written = 0;
            s_ota_sec.active = 1;

            PRINT("OTA HEADER: secure OTA initialized, fw_size=%lu\n",
                  (unsigned long)s_ota_sec.header.fw_size);
            OTA_IAP_SendStatus(SUCCESS);
            break;
        }

        case CMD_IAP_ERASE:
        {
            // Erase flash blocks (async to avoid BLE timeout)
            addr = (uint32_t)(s_ota_iap_data.erase.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.erase.addr[1]) << 8);
            addr = addr * 16;
            addr += IMAGE_B_START_ADD;

            uint32_t block_num = (uint32_t)(s_ota_iap_data.erase.block_num[0]);
            block_num |= ((uint32_t)(s_ota_iap_data.erase.block_num[1]) << 8);

            PRINT("OTA ERASE: addr=%08x blocks=%d\n", (int)addr, (int)block_num);

            // Verify address range
            if(addr < IMAGE_B_START_ADD ||
               (addr + (block_num - 1) * FLASH_BLOCK_SIZE) > IMAGE_IAP_START_ADD)
            {
                PRINT("OTA ERASE: address out of range\n");
                OTA_IAP_SendStatus(0xFF);
                break;
            }

            s_ota_erase_addr = addr;
            s_ota_erase_blocks = block_num;
            s_ota_erase_count = 0;
            s_ota_verify_status = 0;

            // Enter OTA mode: suppress fingerprint, HID, etc.
            if(!s_ota_active)
            {
                s_ota_active = 1;
                PRINT("OTA mode active - all other functions suppressed\n");
                // Power off fingerprint if running
                fp_power_off();
            }

            // Start async erase
            tmos_set_event(hidEmuTaskId, OTA_FLASH_ERASE_EVT);
            break;
        }

        case CMD_IAP_VERIFY:
        {
            // Verify flash data
            len = s_ota_iap_data.verify.len;
            addr = (uint32_t)(s_ota_iap_data.verify.addr[0]);
            addr |= ((uint32_t)(s_ota_iap_data.verify.addr[1]) << 8);
            addr = addr * 16;
            addr += IMAGE_B_START_ADD;

            PRINT("OTA VERIFY: addr=%08x len=%d\n", (int)addr, (int)len);

            status = FLASH_ROM_VERIFY(addr, s_ota_iap_data.verify.buf, len);
            if(status != SUCCESS)
            {
                PRINT("OTA VERIFY failed\n");
            }
            s_ota_verify_status |= status;
            OTA_IAP_SendStatus(s_ota_verify_status);
            break;
        }

        case CMD_IAP_END:
        {
            PRINT("OTA END\n");

            // Require HEADER before END (no plaintext OTA)
            if(!s_ota_sec.active)
            {
                PRINT("OTA END: rejected - no HEADER\n");
                s_ota_active = 0;
                OTA_IAP_SendStatus(0xFE);
                break;
            }

            {
                // Verify SHA256 + HMAC before accepting
                uint8_t computed[32];

                // Step 1: Verify SHA256 of decrypted firmware
                sha256_final(&s_ota_sec.sha256_ctx, computed);
                if(memcmp(computed, s_ota_sec.header.fw_sha256, 32) != 0)
                {
                    PRINT("OTA END: SHA256 mismatch!\n");
                    s_ota_sec.active = 0;
                    s_ota_active = 0;
                    OTA_IAP_SendStatus(OTA_ERR_SHA256_MISMATCH);
                    break;
                }
                PRINT("OTA END: SHA256 OK\n");

                // Step 2: Verify HMAC-SHA256 of header[0:0x40]
                uint8_t computed_hmac[32];
                immurok_hmac_sha256(OTA_SIGNING_KEY, sizeof(OTA_SIGNING_KEY),
                                    (const uint8_t *)&s_ota_sec.header, 0x40,
                                    computed_hmac);
                if(memcmp(computed_hmac, s_ota_sec.header.hmac, 32) != 0)
                {
                    PRINT("OTA END: HMAC mismatch!\n");
                    s_ota_sec.active = 0;
                    s_ota_active = 0;
                    OTA_IAP_SendStatus(OTA_ERR_HMAC_MISMATCH);
                    break;
                }
                PRINT("OTA END: HMAC OK - firmware verified!\n");

                s_ota_sec.active = 0;
            }

            PRINT("OTA END - switching to IAP\n");

            // Disable all interrupts
            SYS_DisableAllIrq(NULL);

            // Switch image flag to IAP (will trigger copy on next boot)
            SwitchImageFlag(IMAGE_IAP_FLAG);

            // Wait for print to complete, then reset
            DelayMs(10);
            SYS_ResetExecute();
            break;
        }

        case CMD_IAP_INFO:
        {
            uint8_t info_buf[20];

            PRINT("OTA INFO\n");

            // Image flag (currently running Image A)
            info_buf[0] = IMAGE_B_FLAG;

            // Image size (little-endian)
            info_buf[1] = (uint8_t)(IMAGE_SIZE & 0xFF);
            info_buf[2] = (uint8_t)((IMAGE_SIZE >> 8) & 0xFF);
            info_buf[3] = (uint8_t)((IMAGE_SIZE >> 16) & 0xFF);
            info_buf[4] = (uint8_t)((IMAGE_SIZE >> 24) & 0xFF);

            // Block size
            info_buf[5] = (uint8_t)(FLASH_BLOCK_SIZE & 0xFF);
            info_buf[6] = (uint8_t)((FLASH_BLOCK_SIZE >> 8) & 0xFF);

            // Chip ID
            info_buf[7] = CHIP_ID & 0xFF;
            info_buf[8] = (CHIP_ID >> 8) & 0xFF;

            // Reserved
            for(int i = 9; i < 20; i++) {
                info_buf[i] = 0;
            }

            OTAProfile_SendData(OTAPROFILE_CHAR, info_buf, 20);
            break;
        }

        default:
            PRINT("OTA: unknown cmd 0x%02X\n", cmd);
            OTA_IAP_SendStatus(0xFE);
            break;
    }
}

/*********************************************************************
 * @fn      OTA_IAPReadDataComplete
 * @brief   OTA read complete callback
 */
static void OTA_IAPReadDataComplete(uint8_t paramID)
{
    PRINT("OTA read complete\n");
}

/*********************************************************************
 * @fn      OTA_IAPWriteData
 * @brief   OTA write callback - process received data
 */
static void OTA_IAPWriteData(uint8_t paramID, uint8_t *pData, uint8_t len)
{
    if(len > IAP_LEN)
    {
        PRINT("OTA write: data too long\n");
        return;
    }

    tmos_memcpy((uint8_t *)&s_ota_iap_data, pData, len);
    OTA_IAP_DataDeal();
}

/*********************************************************************
 * @fn      GPIOA_IRQHandler
 * @brief   GPIO interrupt - set flags for TMOS event loop to consume.
 *          MUST NOT call tmos_set_event() here (race with TMOS_SystemProcess).
 */
__INTERRUPT
__HIGH_CODE
void GPIOA_IRQHandler(void)
{
    if(GPIOA_ReadITFlagBit(PIN_TOUCH))
    {
        GPIOA_ClearITFlagBit(PIN_TOUCH);
        g_touch_irq_flag = 1;
    }
    if(GPIOA_ReadITFlagBit(PIN_BTN1))
    {
        GPIOA_ClearITFlagBit(PIN_BTN1);
        g_btn_irq_flag = 1;
    }
}

/*********************************************************************
*********************************************************************/
