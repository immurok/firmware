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
#include "immurokservice.h"
#include "version.h"
#include "battservice.h"

#define QC_DONE_ADDR     0x6D00   // 独立页：避开 0x6000 ImageFlag / 0x6300
#define QC_SCRATCH_ADDR  0x6C00   // slot_meta / 0x6E00 SVN / 0x6F00 tamper
#define QC_DONE_MAGIC    0xC1

#define QC_BATT_MIN_MV   3000
#define QC_BATT_MAX_MV   4400

extern volatile uint8_t g_sleep_inhibit;   // fingerprint.c
extern volatile uint8_t g_touch_irq_flag;  // hidkbd.c

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

// c) 出厂数据必须为空：无残留模板 + 两槽均无绑定
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
 * 等触摸/DONE/关机在主循环 qc_test_tick 里事件式处理，避免紧循环压垮 BLE） ---------- */

static uint32_t qc_ms_since(uint32_t t0)
{
    uint32_t now = TMOS_GetSystemClock();
    return (uint32_t)((uint64_t)(now - t0) * 625 / 1000);   // TMOS tick=625us
}

// LED 语义（工人视角）：检测中=慢闪白灯（qc_delay 驱动）；等触摸=常亮白灯；
// 成功=慢闪绿灯（拨开关）；失败=快闪红灯（拨开关）。QC_SLOW_HALF_MS 见文件前部。
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
        qc_done_write();
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

void qc_test_run(void)
{
    g_qc_running = 1;
    g_qc_phase = QC_PHASE_RUNNING;
    g_qc_fail_code = QC_FAIL_NONE;
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
    qc_delay(150);
    if(qc_test_fp(&templates)) bitmap |= QC_BIT_FP;
    else { qc_fail_fast(bitmap, QC_FAIL_FP); return; }
    qc_delay(150);

    if(qc_test_batt(&mv)) bitmap |= QC_BIT_BATT;
    g_qc_result_mv = mv;         // 电压值无论过不过都带回
    if(!(bitmap & QC_BIT_BATT)) { qc_fail_fast(bitmap, QC_FAIL_BATT); return; }
    qc_delay(150);

    if(qc_test_empty(templates)) bitmap |= QC_BIT_EMPTY;
    else { qc_fail_fast(bitmap, QC_FAIL_EMPTY); return; }
    qc_delay(150);

    if(qc_test_flash()) bitmap |= QC_BIT_FLASH;
    else { qc_fail_fast(bitmap, QC_FAIL_FLASH); return; }
    qc_delay(150);

    if(qc_test_gpio()) bitmap |= QC_BIT_GPIO;
    else { qc_fail_fast(bitmap, QC_FAIL_GPIO); return; }
    qc_delay(150);

    uint16_t lse_cnt = 0;
    if(qc_test_lse(&lse_cnt)) bitmap |= QC_BIT_LSE;
    else { qc_fail_fast(bitmap, QC_FAIL_LSE); return; }
    qc_delay(150);

    s_qc_auto_bitmap = bitmap;

    // fp 断电残留边沿：settle 后清；然后进等触摸态（tick 继续慢闪白），返回主循环。
    qc_delay(400);
    g_touch_irq_flag = 0;
    s_qc_wait_start = TMOS_GetSystemClock();
    g_qc_phase = QC_PHASE_WAIT_TOUCH;
    PRINT("QC: auto done bitmap=0x%02X mv=%d, wait touch (main loop)\n", bitmap, mv);
    // 返回 —— 之后由 qc_test_tick 处理触摸/结果/关机
}

// 主循环每轮调用：等触摸 → DONE → 等 QC 板读取并发关机命令 → 收尾。
void qc_test_tick(void)
{
    if(!g_qc_running) return;

    if(g_qc_phase == QC_PHASE_WAIT_TOUCH) {
        if(g_touch_irq_flag) {
            g_touch_irq_flag = 0;
            uint8_t bm = s_qc_auto_bitmap | QC_BIT_TOUCH;
            g_qc_result_bitmap = bm;
            g_qc_phase = QC_PHASE_DONE;
            s_qc_done_time = TMOS_GetSystemClock();
            g_qc_read_done = 0;
            PRINT("QC: DONE bitmap=0x%02X pass=1 touch=1\n", bm);
        } else if(qc_ms_since(s_qc_wait_start) > 20000) {
            qc_fail_fast(s_qc_auto_bitmap, QC_FAIL_TOUCH);   // 等触摸超时
        } else {
            qc_led('W');   // 等触摸：常亮白灯（每 tick 重刷，压过广播 LED）
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
