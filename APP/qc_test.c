/*
 * immurok QC 自检（BLE 触发）。设计见 qc/ik1-selftest-proposal.md v2。
 *
 * 主循环上下文运行（GATT 回调只置 g_qc_start_req）。全程分片延时喂
 * WWDG + TMOS_SystemProcess 保 BLE 链路。日志走 PRINT（dbg_printf），
 * 禁 vsnprintf（512B 栈）。
 */
#include "CONFIG.h"
#include "qc_test.h"
#include "hardware_pins.h"
#include "fingerprint.h"
#include "immurok_security.h"
#include "immurok_keystore.h"
#include "immurokservice.h"
#include "version.h"
#include "battservice.h"

#define QC_DONE_ADDR     0x6D00   // 独立页：避开 0x6000 ImageFlag / 0x6300
#define QC_SCRATCH_ADDR  0x6C00   // slot_meta / 0x6E00 SVN / 0x6F00 tamper
#define QC_DONE_MAGIC    0xC1

#define QC_BATT_MIN_MV   3000
#define QC_BATT_MAX_MV   4400
#define QC_WAIT_HUMAN_MS 30000   // 人工阶段总窗口：触摸 + 按键
#define QC_LEVEL_HOLD_MS 40      // 触摸/按键电平须持续这么久才算（同 hidkbd 触摸去抖 2×~20ms）

extern volatile uint8_t g_sleep_inhibit;   // fingerprint.c
extern volatile uint8_t g_touch_irq_flag;  // hidkbd.c
extern volatile uint8_t g_btn_irq_flag;    // hidkbd.c

volatile uint8_t  g_qc_start_req = 0;
volatile uint8_t  g_qc_running = 0;
volatile uint8_t  g_qc_phase = QC_PHASE_IDLE;
volatile uint8_t  g_qc_result_bitmap = 0;
volatile uint16_t g_qc_result_mv = 0;
volatile uint8_t  g_qc_fail_code = QC_FAIL_NONE;
volatile uint8_t  g_qc_read_done = 0;
volatile uint8_t  g_qc_shutdown_req = 0;
volatile uint8_t  g_qc_finished = 0;
static uint8_t  s_qc_auto_bitmap = 0;
static uint8_t  s_qc_touch_ok = 0;    // 人工阶段：触摸已到
static uint8_t  s_qc_btn_ok = 0;      // 人工阶段：按键已到
static uint8_t  s_qc_touch_armed = 0; // 人工阶段：DETECT 已见过低电平（排除进入时残留的 latch 高）
static uint8_t  s_qc_btn_armed = 0;   // 人工阶段：BTN 已见过释放电平
static uint32_t s_qc_touch_t0 = 0;    // DETECT 首次读高的时刻（0=未开始）
static uint32_t s_qc_btn_t0 = 0;      // BTN 首次读低的时刻（0=未开始）
static uint32_t s_qc_wait_start = 0;
static uint32_t s_qc_done_time = 0;
static uint32_t s_qc_run_start = 0;   // 自检开始墙钟，驱动检测中慢闪白

// 前置声明（qc_delay 在文件前部就要用到）
static uint32_t qc_ms_since(uint32_t t0);
static void qc_led(uint8_t c);

/* ---------- qc_done 标志（FACTORY_RESET / 防拆擦除都不触及此页） ---------- */

uint8_t qc_done_read(void)
{
    uint8_t v = 0;
    EEPROM_READ(QC_DONE_ADDR, &v, sizeof(v));
    return v == QC_DONE_MAGIC;
}

static void qc_done_write(void)
{
    uint8_t v = QC_DONE_MAGIC;
    EEPROM_ERASE(QC_DONE_ADDR, EEPROM_PAGE_SIZE);
    EEPROM_WRITE(QC_DONE_ADDR, &v, sizeof(v));
}

void qc_done_clear(void)
{
    EEPROM_ERASE(QC_DONE_ADDR, EEPROM_PAGE_SIZE);
    PRINT("QC: qc_done cleared\n");
}

/* ---------- 小工具 ---------- */

#define QC_SLOW_HALF_MS  250   // 慢闪白半周期（检测中）

// 分片延时：喂狗 + 泵 TMOS（BLE 链路与 0x41 通知发送都靠它）。
// 自动检测阶段（phase==RUNNING）顺带驱动"慢闪白灯"——各项间隙都走 qc_delay，
// 整体呈现白灯慢闪的检测中状态。
static void qc_delay(uint32_t ms)
{
    while(ms) {
        uint32_t chunk = ms > 15 ? 15 : ms;
        DelayMs(chunk);
        ms -= chunk;
        WWDG_SetCounter(0);
        TMOS_SystemProcess();
        if(g_qc_phase == QC_PHASE_RUNNING)
            qc_led((qc_ms_since(s_qc_run_start) / QC_SLOW_HALF_MS) & 1 ? 0 : 'W');
    }
}

// R红 B蓝 G绿 Y黄(R+G) C青(G+B) M品红(R+B) W白(全亮) 0灭
static void qc_led(uint8_t c)
{
    LED_RED_Off(); LED_GREEN_Off(); LED_BLUE_Off();
    if(c == 'R') LED_RED_On();
    else if(c == 'B') LED_BLUE_On();
    else if(c == 'G') LED_GREEN_On();
    else if(c == 'Y') { LED_RED_On(); LED_GREEN_On(); }
    else if(c == 'C') { LED_GREEN_On(); LED_BLUE_On(); }
    else if(c == 'M') { LED_RED_On(); LED_BLUE_On(); }
    else if(c == 'W') { LED_RED_On(); LED_GREEN_On(); LED_BLUE_On(); }
}

/* ---------- 测试项（返回 1 = 通过） ---------- */

// a) 指纹模块：上电+口令 → 读参数 → 读模板数 → 断电。
//    善后保证「允许触摸后再次触摸」：no-ack 时再走一遍唤醒/断电周期
//    解锁 DETECT latch（历史 no-ack touch 死），并吞掉上下电产生的边沿。
static uint8_t qc_test_fp(uint16_t *templates)
{
    uint8_t ok = 1;
    fp_sys_params_t p = {0};
    *templates = 0xFFFF;

    if(fp_wake() != FP_OK) {
        ok = 0;
        PRINT("QC: fp_wake fail\n");
    } else {
        qc_delay(15);   // pump BLE：fp 子步骤间不能饿死连接
        if(fp_read_sys_params(&p) != FP_OK || p.capacity == 0) {
            ok = 0;
            PRINT("QC: fp params fail (cap=%d)\n", p.capacity);
        }
        qc_delay(15);
        if(ok && fp_get_template_count(templates) != FP_OK) {
            ok = 0;
            *templates = 0xFFFF;
            PRINT("QC: fp template count fail\n");
        }
    }
    qc_delay(15);
    if(!fp_power_off()) {
        // 传感器没确认 standby：touch-detect 可能 latch。再走一遍
        // 上电→握手→睡眠→断电把它解开（失败重启路径的触摸要能用）。
        PRINT("QC: fp no-ack, extra wake/off cycle\n");
        WWDG_SetCounter(0);
        if(fp_wake() == FP_OK) { /* 握手即可 */ }
        fp_power_off();
    }
    WWDG_SetCounter(0);
    g_touch_irq_flag = 0;   // 吞掉电源周期产生的 DETECT 边沿
    if(ok) PRINT("QC: fp ok, cap=%d templates=%d\n", p.capacity, *templates);
    return ok;
}

// b) 电池 ADC 范围
static uint8_t qc_test_batt(uint16_t *mv)
{
#if HAS_VBAT_ADC
    Batt_MeasLevel();
    *mv = HidEmu_LastBattMv();
    PRINT("QC: batt %d mV\n", *mv);
    return (*mv >= QC_BATT_MIN_MV && *mv <= QC_BATT_MAX_MV);
#else
    *mv = HidEmu_LastBattMv();
    return 1;
#endif
}

// c) 出厂数据必须为空：无残留模板 + 两槽均无绑定 + SNV 无 bond + keystore 空。
//    bond 数在这里查有双重意义：一是抓返修机残留，二是验证 QC 板的 Just Works
//    加密确实没在 ik1 落 bond（BLE_SNV_NUM=2，出厂就占一条会让用户少一台主机）。
//    自检时 QC 板正连着，所以正确值就是 0；若 JW 落了 bond，每台都会在此项失败。
static uint8_t qc_test_empty(uint16_t templates)
{
    if(templates != 0) {          // 0xFFFF（fp 读取失败）也按不空计
        PRINT("QC: empty fail, templates=%d\n", templates);
        return 0;
    }
    if(immurok_security_is_paired()) {
        PRINT("QC: empty fail, slot paired\n");
        return 0;
    }
    uint8_t bc = 0;
    GAPBondMgr_GetParameter(GAPBOND_BOND_COUNT, &bc);
    if(bc != 0) {
        PRINT("QC: empty fail, bond_count=%d\n", bc);
        return 0;
    }
    for(uint8_t cat = 0; cat < KEYSTORE_CAT_COUNT; cat++) {
        int n = immurok_keystore_count(cat);
        if(n != 0) {
            PRINT("QC: empty fail, keystore[%d] count=%d\n", cat, n);
            return 0;
        }
    }
    return 1;
}

// d) DataFlash：QC scratch 页擦→写→回读→擦→回读
static uint8_t qc_test_flash(void)
{
    static const uint8_t pat[8] = {0xA5, 0x5A, 0xC3, 0x3C, 0x0F, 0xF0, 0x69, 0x96};
    uint8_t buf[8];

    if(EEPROM_ERASE(QC_SCRATCH_ADDR, EEPROM_PAGE_SIZE) != 0) return 0;
    WWDG_SetCounter(0);
    if(EEPROM_WRITE(QC_SCRATCH_ADDR, (void *)pat, sizeof(pat)) != 0) return 0;
    if(EEPROM_READ(QC_SCRATCH_ADDR, buf, sizeof(buf)) != 0) return 0;
    for(int i = 0; i < (int)sizeof(pat); i++)
        if(buf[i] != pat[i]) { PRINT("QC: flash verify fail @%d\n", i); return 0; }
    if(EEPROM_ERASE(QC_SCRATCH_ADDR, EEPROM_PAGE_SIZE) != 0) return 0;
    WWDG_SetCounter(0);
    if(EEPROM_READ(QC_SCRATCH_ADDR, buf, sizeof(buf)) != 0) return 0;
    for(int i = 0; i < (int)sizeof(pat); i++)
        if(buf[i] == pat[i]) { PRINT("QC: flash erase verify fail\n"); return 0; }
    PRINT("QC: flash ok\n");
    return 1;
}

// f) 32.768kHz 外部晶振（X2）：以主频（60MHz，独立于 32k 时钟域）为时间
//    基准，测 RTC 32k 计数器在 100ms 窗口内的增量算实际频率。停振→增量 0；
//    负载电容过大/虚焊→频偏。参考诊断固件 lse_probe.c 的 measure_hz 思路。
//    合格窗口 32768Hz ±11%（约 2900-3600 计数/100ms）。
#define QC_LSE_WINDOW_MS   100
#define QC_LSE_CNT_MIN     2900   // 29.0 kHz
#define QC_LSE_CNT_MAX     3600   // 36.0 kHz
static uint8_t qc_test_lse(uint16_t *cnt_out)
{
    uint32_t r0 = RTC_GetCycle32k();
    DelayMs(QC_LSE_WINDOW_MS);       // 主频忙等，不依赖 32k
    WWDG_SetCounter(0);
    uint32_t dr = RTC_GetCycle32k() - r0;   // 32k tick 增量（计数器自环，无符号差正确）
    *cnt_out = (dr > 0xFFFF) ? 0xFFFF : (uint16_t)dr;
    if(dr < QC_LSE_CNT_MIN || dr > QC_LSE_CNT_MAX) {
        PRINT("QC: lse fail, %d ticks/100ms (want %d-%d)\n",
              (int)dr, QC_LSE_CNT_MIN, QC_LSE_CNT_MAX);
        return 0;
    }
    PRINT("QC: lse ok, %d ticks/100ms\n", (int)dr);
    return 1;
}

// e) GPIO 静态电平：BTN(RC 上拉) 高；ANTI_OPEN 低（合盖）。虚焊直接暴露。
static uint8_t qc_test_gpio(void)
{
    uint8_t ok = 1;
    if(BTN_ReadPin() == 0) {
        PRINT("QC: gpio fail, BTN low\n");
        ok = 0;
    }
#if HAS_TAMPER_DETECT
    if(ANTI_OPEN_ReadPin() != 0) {
        PRINT("QC: gpio fail, ANTI_OPEN high\n");
        ok = 0;
    }
#endif
    return ok;
}

/* ---------- 主流程（重构 v4：qc_test_run 只跑自动项后返回，
 * 等触摸+按键/DONE/关机在主循环 qc_test_tick 里事件式处理，避免紧循环压垮 BLE） ---------- */

static uint32_t qc_ms_since(uint32_t t0)
{
    uint32_t now = TMOS_GetSystemClock();
    // TMOS tick=625us，625/1000 = 5/8，纯 32 位算：曾写成 (uint64_t)*625/1000，
    // 一行拉进 __udivdi3/__divdi3 约 1KB 库代码（2026-09-19 体积审计）。
    return (uint32_t)(((now - t0) * 5u) / 8u);
}

// LED 语义（工人视角）：检测中=慢闪白灯（qc_delay 驱动）；等触摸=常亮白灯；
// 触摸到了等按键=常亮青灯；成功=慢闪绿灯（拨开关）；失败=快闪红灯（拨开关）。
// QC_SLOW_HALF_MS 见文件前部。
#define QC_FAST_HALF_MS  120   // 快闪红：亮 120ms / 灭 120ms

// 完成收尾（主循环空闲上下文调用，不返回）。
// pass→落盘+慢闪绿灯提示工人拨开关；fail→快闪红灯。均关 BLE/外设、停止工作。
// 刻意不用 LowPower_Shutdown 深度关机：一是它 __WFI 被残留唤醒源打断会软
// 复位（关机后又广播）；二是产线工人靠 LED 提示拨物理开关断电，深度关机
// 灭灯反而易忘关开关导致电池持续耗电。
static void __attribute__((noreturn)) qc_complete(uint8_t pass)
{
    PRINT("QC: complete pass=%d -> BLE/peripherals off, LED hold\n", pass);
    g_qc_finished = 1;               // 门住断链后重广播
    HidEmu_QcBleOff();               // 关蓝牙（断链+停广播）
    qc_delay(300);                   // pump TMOS 让断链/停广播真正生效
    fp_finish_off();                 // 关指纹模块电源
    PFIC_DisableIRQ(GPIO_A_IRQn);    // 禁 GPIO 中断（外设静默）
    PFIC_DisableIRQ(GPIO_B_IRQn);
    if(pass) {
        if(!qc_done_read()) qc_done_write();   // 复检确认路径已写过，不再擦写一次
        // 成功：绿灯持续慢闪，等工人拨开关
        while(1) {
            qc_led('G'); DelayMs(QC_SLOW_HALF_MS); qc_led(0); DelayMs(QC_SLOW_HALF_MS);
            WWDG_SetCounter(0);
        }
    }
    // 失败：红灯持续快闪，等工人拨开关
    while(1) {
        qc_led('R'); DelayMs(QC_FAST_HALF_MS); qc_led(0); DelayMs(QC_FAST_HALF_MS);
        WWDG_SetCounter(0);
    }
}

// fail-fast 收口：记录首个失败项，直接进 DONE（跳过剩余项与等触摸）。
// 结果由 QC 板轮询 QC_GET 读走；快闪红灯在 tick 里持续刷。
static void qc_fail_fast(uint8_t bitmap, uint8_t fail_code)
{
    g_qc_result_bitmap = bitmap;
    g_qc_fail_code = fail_code;
    g_qc_phase = QC_PHASE_DONE;
    s_qc_done_time = TMOS_GetSystemClock();
    g_qc_read_done = 0;
    qc_led('R');   // 快闪起点，tick 接管
    PRINT("QC: FAIL-FAST item=%d bitmap=0x%02X\n", fail_code, bitmap);
}

// 已过检设备再次收到 0x40：不重测，直接进 DONE（全过、无失败项）。
// QC 板轮询 QC_GET 会读到 phase=DONE + qc_done=1，据此把结果标成「仅确认」；
// 随后的 QC_SHUTDOWN 走正常收尾：绿灯慢闪等工人拨开关。
static void qc_confirm_done(void)
{
    g_qc_running = 1;
    g_qc_fail_code = QC_FAIL_NONE;
    g_qc_result_bitmap = QC_BITS_ALL;
    g_qc_result_mv = HidEmu_LastBattMv();
    g_qc_shutdown_req = 0;
    g_qc_read_done = 0;
    g_sleep_inhibit++;   // 与正常路径对称，qc_complete 不返回，无需减回
    g_qc_phase = QC_PHASE_DONE;
    s_qc_done_time = TMOS_GetSystemClock();
    PRINT("QC: already done -> confirm only, green\n");
}

void qc_test_run(void)
{
    if(qc_done_read()) { qc_confirm_done(); return; }

    g_qc_running = 1;
    g_qc_phase = QC_PHASE_RUNNING;
    g_qc_fail_code = QC_FAIL_NONE;
    g_qc_result_bitmap = 0;   // 自检中随各项通过实时置位（QC_GET 可见，供进度展示）
    g_qc_shutdown_req = 0;
    g_sleep_inhibit++;   // LED 时序靠 DelayMs
    s_qc_run_start = TMOS_GetSystemClock();   // 慢闪白起点
    PRINT("QC: self-test start\n");

    uint8_t bitmap = 0;
    uint16_t templates = 0xFFFF;
    uint16_t mv = 0;

    // 自动项，fail-fast：任一项失败立即停测进 DONE（fail_code=首个失败项），
    // 不再测后面的项。检测中 LED 由 qc_delay 统一慢闪白，不再分项彩色。
    // fp 项内部已做断电善后，失败路径外设是安全的。
    // 这些操作可能打断 BLE —— 不要紧，跑完就回主循环，连接会稳定重连。
    // 每过一项就把 bitmap 写到 g_qc_result_bitmap：QC 板轮询 QC_GET 时能看到进度。
    // 最终判定只看 phase=DONE 时的值，中途可见不影响旧 QC 板（它只在 DONE 时用 bitmap）。
    qc_delay(150);
    if(qc_test_fp(&templates)) bitmap |= QC_BIT_FP;
    else { qc_fail_fast(bitmap, QC_FAIL_FP); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    if(qc_test_batt(&mv)) bitmap |= QC_BIT_BATT;
    g_qc_result_mv = mv;         // 电压值无论过不过都带回
    if(!(bitmap & QC_BIT_BATT)) { qc_fail_fast(bitmap, QC_FAIL_BATT); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    if(qc_test_empty(templates)) bitmap |= QC_BIT_EMPTY;
    else { qc_fail_fast(bitmap, QC_FAIL_EMPTY); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    if(qc_test_flash()) bitmap |= QC_BIT_FLASH;
    else { qc_fail_fast(bitmap, QC_FAIL_FLASH); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    if(qc_test_gpio()) bitmap |= QC_BIT_GPIO;
    else { qc_fail_fast(bitmap, QC_FAIL_GPIO); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    uint16_t lse_cnt = 0;
    if(qc_test_lse(&lse_cnt)) bitmap |= QC_BIT_LSE;
    else { qc_fail_fast(bitmap, QC_FAIL_LSE); return; }
    g_qc_result_bitmap = bitmap;
    qc_delay(150);

    s_qc_auto_bitmap = bitmap;

    // fp 断电残留边沿：settle 后清；自检期间积压的按键边沿也清掉，
    // 然后进人工阶段（等触摸 + 按键），返回主循环。
    // 人工阶段判定只看电平不看 IRQ 边沿（见 qc_test_tick），这里若 DETECT
    // 仍 latch 高（断电瞬态没解开），再做一次上电/断电把它复位，避免
    // 工人真触摸时没有新的低→高跳变而白等 30s。
    qc_delay(400);
    if(TOUCH_ReadPin()) {
        PRINT("QC: DETECT latched high at wait entry, extra fp cycle\n");
        if(fp_wake() == FP_OK) { /* 握手即可 */ }
        fp_power_off();
        qc_delay(400);
    }
    g_touch_irq_flag = 0;
    g_btn_irq_flag = 0;
    s_qc_touch_ok = 0;
    s_qc_btn_ok = 0;
    s_qc_touch_armed = (TOUCH_ReadPin() == 0);
    s_qc_btn_armed = (BTN_ReadPin() != 0);
    s_qc_touch_t0 = 0;
    s_qc_btn_t0 = 0;
    s_qc_wait_start = TMOS_GetSystemClock();
    g_qc_phase = QC_PHASE_WAIT_TOUCH;
    PRINT("QC: auto done bitmap=0x%02X mv=%d, wait touch+btn (detect=%d btn=%d)\n",
          bitmap, mv, TOUCH_ReadPin() ? 1 : 0, BTN_ReadPin() ? 1 : 0);
    // 返回 —— 之后由 qc_test_tick 处理触摸/按键/结果/关机
}

// 人工阶段的电平判定：*armed 先要见过「未操作」电平（DETECT 低 / BTN 高），
// 之后「已操作」电平（DETECT 高 / BTN 低）持续 ≥QC_LEVEL_HOLD_MS 才算数。
// 纯看 IRQ 边沿不行：DETECT 在模块断电瞬态、BTN 在 RC 网络扰动下都会出
// 孤立边沿（1.7.11 产线实测：未操作就自动过了其中一项），hidkbd 的正常
// 流程也是边沿唤醒后再验电平，这里照做。
static uint8_t qc_level_confirm(uint8_t active, uint8_t *armed, uint32_t *t0, const char *tag)
{
    if(!*armed) {
        if(!active) *armed = 1;
        return 0;
    }
    if(!active) { *t0 = 0; return 0; }
    uint32_t now = TMOS_GetSystemClock();
    if(*t0 == 0) { *t0 = now ? now : 1; return 0; }
    if(qc_ms_since(*t0) < QC_LEVEL_HOLD_MS) return 0;
    PRINT("QC: %s ok (level held %dms)\n", tag, QC_LEVEL_HOLD_MS);
    return 1;
}

// 主循环每轮调用：等触摸+按键 → DONE → 等 QC 板读取并发关机命令 → 收尾。
// 人工阶段的 IRQ 标志由 main.c 在 g_qc_running 期间直接留给这里消费。
void qc_test_tick(void)
{
    if(!g_qc_running) return;

    if(g_qc_phase == QC_PHASE_WAIT_TOUCH) {
        // IRQ 边沿标志只清不用（判定看电平）；留着会在 QC 之后被误消费
        if(g_touch_irq_flag) { g_touch_irq_flag = 0; PRINT("QC: touch edge (detect=%d)\n", TOUCH_ReadPin() ? 1 : 0); }
        if(g_btn_irq_flag)   { g_btn_irq_flag = 0;   PRINT("QC: btn edge (btn=%d)\n", BTN_ReadPin() ? 1 : 0); }
        if(!s_qc_touch_ok && qc_level_confirm(TOUCH_ReadPin() ? 1 : 0,
                                              &s_qc_touch_armed, &s_qc_touch_t0, "touch"))
            s_qc_touch_ok = 1;
        if(!s_qc_btn_ok && qc_level_confirm(BTN_ReadPin() == 0,
                                            &s_qc_btn_armed, &s_qc_btn_t0, "btn"))
            s_qc_btn_ok = 1;
        // 人工阶段进度对 QC_GET 可见：bit5=已触摸 bit7=已按键（上位机据此提示下一步）
        g_qc_result_bitmap = s_qc_auto_bitmap
                           | (s_qc_touch_ok ? QC_BIT_TOUCH : 0)
                           | (s_qc_btn_ok ? QC_BIT_BTN : 0);
        if(s_qc_touch_ok && s_qc_btn_ok) {
            uint8_t bm = s_qc_auto_bitmap | QC_BIT_TOUCH | QC_BIT_BTN;
            g_qc_result_bitmap = bm;
            g_qc_phase = QC_PHASE_DONE;
            s_qc_done_time = TMOS_GetSystemClock();
            g_qc_read_done = 0;
            PRINT("QC: DONE bitmap=0x%02X pass=1 touch=1 btn=1\n", bm);
        } else if(qc_ms_since(s_qc_wait_start) > QC_WAIT_HUMAN_MS) {
            // 超时：触摸没到记 TOUCH（bitmap 不含 TOUCH/BTN），
            // 触摸到了只差按键记 BTN（bitmap 含 TOUCH，QC 板 detail 里 touch=1）
            uint8_t bm = s_qc_auto_bitmap | (s_qc_touch_ok ? QC_BIT_TOUCH : 0);
            qc_fail_fast(bm, s_qc_touch_ok ? QC_FAIL_BTN : QC_FAIL_TOUCH);
        } else {
            // 每 tick 重刷，压过广播 LED：白=等触摸，青=触摸到了等按键
            qc_led(s_qc_touch_ok ? 'C' : 'W');
        }
        return;
    }

    if(g_qc_phase == QC_PHASE_DONE) {
        uint8_t pass = (g_qc_fail_code == QC_FAIL_NONE);
        if(pass)                         // 成功：绿灯慢闪
            qc_led((qc_ms_since(s_qc_done_time) / QC_SLOW_HALF_MS) & 1 ? 0 : 'G');
        else                             // 失败：红灯快闪
            qc_led((qc_ms_since(s_qc_done_time) / QC_FAST_HALF_MS) & 1 ? 0 : 'R');
        // QC 板读走结果后发关机命令即收尾；60s 兜底
        if(g_qc_shutdown_req || qc_ms_since(s_qc_done_time) > 60000) {
            qc_complete(pass);   // 不返回
        }
    }
}
