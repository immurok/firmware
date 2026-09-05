/*
 * Case-open hold（未配对设备开盖不广播）。见 factory_test.h 头注释。
 */
#include "CONFIG.h"
#include "factory_test.h"

#if HAS_FACTORY_TEST

volatile uint8_t g_factory_case_open = 0;

void factory_case_open_enter(void)
{
    if(g_factory_case_open) return;
    g_factory_case_open = 1;
    PRINT("FACTORY: case open (unpaired) -> adv off, red slow blink\n");
    HidEmu_CaseOpenHold();
}

void factory_case_open_exit(void)
{
    if(!g_factory_case_open) return;
    g_factory_case_open = 0;
    PRINT("FACTORY: case closed -> resume normal advertising\n");
    HidEmu_CaseOpenResume();
}

#endif // HAS_FACTORY_TEST
