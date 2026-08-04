/*
 * immurok BLE init — runtime-selectable device BLE address
 *
 * A copy of the SDK's CH59x_BLEInit() (SDK/EVT/EXAM/BLE/HAL/MCU.c:105) that
 * takes the device MAC as a parameter instead of picking it from a
 * compile-time const array or the chip's factory value.
 *
 * WHY A COPY INSTEAD OF PATCHING THE SDK:
 *   Vendor code stays untouched so an SDK upgrade never conflicts with our
 *   changes. (CLAUDE.md claims the SDK is not in git — that is stale; it is
 *   committed. The separation rule stands on its own merits.)
 *
 * WHY NOT THE BLE_MAC=TRUE MACRO:
 *   CONFIG.h:149 declares `extern const uint8_t MacAddr[6]` — it lives in
 *   .rodata and cannot be written at runtime.
 *
 * BYTE ORDER — read this before touching the address:
 *   MCU.c's two branches disagree.
 *     BLE_MAC==TRUE : cfg.MacAddr[i] = MacAddr[5 - i]   (reversed)
 *     BLE_MAC==FALSE: cfg.MacAddr[i] = MacAddr[i]       (as-is, from
 *                                                        GetMACAddress)
 *   We follow the FALSE branch, because our input comes from
 *   GetMACAddress() too — which returns the address in REVERSE display
 *   order: mac[5] is the first byte you see printed, mac[0] the last.
 *   Measured on hardware 2026-08-03, see immurok_ble_slot_mac() below and
 *   docs/superpowers/specs/2026-08-03-dual-host-design.md §5.4.
 */

#include "CONFIG.h"
#include "HAL.h"
#include "immurok_ble_init.h"
#include "slot_meta.h"

// Defined in main.c
extern __attribute__((aligned(4))) uint32_t MEM_BUF[BLE_MEMHEAP_SIZE / 4];

// Defined in SDK HAL/MCU.c (non-static globals)
extern uint32_t g_LLE_IRQLibHandlerLocation;
extern uint32_t Lib_Read_Flash(uint32_t addr, uint32_t num, uint32_t *pBuf);
extern uint32_t Lib_Write_Flash(uint32_t addr, uint32_t num, uint32_t *pBuf);

void immurok_BLEInit(const uint8_t mac[6])
{
    uint8_t     i;
    bleConfig_t cfg;

    if(tmos_memcmp(VER_LIB, VER_FILE, strlen(VER_FILE)) == FALSE)
    {
        PRINT("head file error...\n");
        while(1);
    }

    SysTick_Config(SysTick_LOAD_RELOAD_Msk);
    PFIC_DisableIRQ(SysTick_IRQn);

    g_LLE_IRQLibHandlerLocation = (uint32_t)LLE_IRQLibHandler;
    PFIC_SetPriority(BLEL_IRQn, 0xF0);
    tmos_memset(&cfg, 0, sizeof(bleConfig_t));
    cfg.MEMAddr = (uint32_t)MEM_BUF;
    cfg.MEMLen = (uint32_t)BLE_MEMHEAP_SIZE;
    cfg.BufMaxLen = (uint32_t)BLE_BUFF_MAX_LEN;
    cfg.BufNumber = (uint32_t)BLE_BUFF_NUM;
    cfg.TxNumEvent = (uint32_t)BLE_TX_NUM_EVENT;
    cfg.TxPower = (uint32_t)BLE_TX_POWER;
#if(defined(BLE_SNV)) && (BLE_SNV == TRUE)
    if((BLE_SNV_ADDR + BLE_SNV_BLOCK * BLE_SNV_NUM) > (0x78000 - FLASH_ROM_MAX_SIZE))
    {
        PRINT("SNV config error...\n");
        while(1);
    }
    cfg.SNVAddr = (uint32_t)BLE_SNV_ADDR;
    cfg.SNVBlock = (uint32_t)BLE_SNV_BLOCK;
    cfg.SNVNum = (uint32_t)BLE_SNV_NUM;
    cfg.readFlashCB = Lib_Read_Flash;
    cfg.writeFlashCB = Lib_Write_Flash;
#endif
    cfg.ConnectNumber = (PERIPHERAL_MAX_CONNECTION & 3) | (CENTRAL_MAX_CONNECTION << 2);
    cfg.srandCB = SYS_GetSysTickCnt;
#if(defined TEM_SAMPLE) && (TEM_SAMPLE == TRUE)
    cfg.tsCB = HAL_GetInterTempValue;
  #if(CLK_OSC32K)
    cfg.rcCB = Lib_Calibration_LSI;
  #endif
#endif
#if(defined(HAL_SLEEP)) && (HAL_SLEEP == TRUE)
    cfg.idleCB = CH59x_LowPower;
#endif

    // The whole point of this file: the address is a runtime parameter.
    for(i = 0; i < 6; i++)
    {
        cfg.MacAddr[i] = mac[i];
    }

    if(!cfg.MEMAddr || cfg.MEMLen < 4 * 1024)
    {
        while(1);
    }
    if(cfg.TxPower & (1 << 7))
    {
        sys_safe_access_enable();
        *(PUINT32V)(0x40001048) |= (6 << 6);
        *(PUINT32V)(0x40001020) |= (2 << 19);
        sys_safe_access_disable();
    }
    i = BLE_LibInit(&cfg);
    if(i)
    {
        PRINT("LIB init error code: %x ...\n", i);
        while(1);
    }
}

void immurok_ble_slot_mac(uint8_t slot, uint8_t out_mac[6])
{
    /* gen=0（空白/未解绑过）沿用出厂 MAC + locally-administered 位这套原有
     * 方案（2026-08-03 实机确认：槽1 0C:3D:5E:5D:AD:A1 / 槽2 0E:3D:5E:5D:AD:A1），
     * 保证已出货设备升级后地址不变、不需重配。gen>0（解绑后轮换）由
     * slot_mac_derive() 走 SHA-256 派生静态随机地址。 */
    uint8_t factory_mac[6];
    GetMACAddress(factory_mac);
    slot_mac_derive(factory_mac, slot, slot_meta_gen(slot), out_mac);
}
