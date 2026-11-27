/*
 * 双主机功能对 immurok_keystore_work_buf[4096] 的借用分区。
 *
 * 背景：CH592F 只有 26KB RAM，release-debug 的 .highcode 比 debug 大
 * ~1.3KB，.bss 每多几百字节就会让 .stack 撞上 .stack_guard 链接不过。
 * 双主机需要约 300B 的临时缓冲，直接放 .bss 装不下。
 *
 * work_buf 是既有的跨模块 scratch（immurok_security.c:495 早就在裸
 * extern 借用），它同时充当 .stack_guard。这里把这个惯例正规化。
 *
 * === 唯一的安全前提 ===
 * keystore 的块读改写（KEY_* 命令、keystore_reset）与
 * save_security_data() 会用掉**整个** 4096 字节。因此：
 *
 *   任何 keystore / security-save 操作在飞行中时，不得有双主机缓冲存活。
 *
 * 这个前提当前成立，因为这些操作都是同步的、用完即还（它们不只从 GATT 回调里跑，
 * 也从 FP 匹配分发和 LED 任务的延后事件里跑），双主机的缓冲生命期从不跨越一次向
 * 分发器的返回。DEBUG 构建下有运行时断言兜底（见 immurok_keystore.c 的
 * immurok_scratch_assert_free；目前只有 TOTP 会置 busy）。
 *
 * 各分区偏移互不重叠，所以模块的缓冲可以同时存活。
 *
 * === 例外：ECC 标量乘（immurok_ecc_fast.c，2026-11-26）===
 * 标量乘期间，work_buf 低端约 3.4KB 放的是**正在执行的代码**，与下面所有分区重叠，
 * 再往上直到主栈是它的栈空间。它和 keystore 块操作一样是独占的：
 *
 *   标量乘在飞行中时，不得有任何别的代码读写 work_buf。
 *
 * 成立的根据只有一条：标量乘是一次不返回分发器的同步调用，期间只喂狗、不泵 TMOS，
 * 没有别的任务能运行。（进入前也查 immurok_scratch_is_busy()，但只有 TOTP 会置它，
 * 而 TOTP 同样是同步的，所以这项检查实际拦不到什么，别指望它。）
 * 以后若有人在 ECC 的回调里重新泵 TMOS，这条前提就破了。
 */
#ifndef IMMUROK_SCRATCH_H
#define IMMUROK_SCRATCH_H

#include <stdint.h>

extern uint8_t immurok_keystore_work_buf[4096];

/* 分区偏移。取自 4096B 的头部。
 * 曾有 SCRATCH_PIN_OFF / SCRATCH_HIDKBD_OFF 两个分区，服务临时 PIN 的
 * 登记流程；2026-08-03 该流程移除后一并删除。 */
#define SCRATCH_SLOTS_OFF   0     /* 64B  — immurok_slots 的页缓冲 */
/* TOTP 计算工作区（M12，2026-09-20）：sha1 的 W[80]、hmac 的 sha1_ctx/k_pad/tk、
 * hmac 结果，全放这里，把 1024B 栈拉回 512 内。只在 totp_compute 期间存活，
 * 那时命令串行、TOTP 不 yield、work_buf 无其他用户（见 spec 前提 1-4）。
 * otp_work_t 实际约 560B，留 1024 给足余量。 */
#define SCRATCH_OTP_OFF     64
#define SCRATCH_OTP_LEN     1024
#define SCRATCH_TOTAL       1088

#define SCRATCH_AT(off)  (&immurok_keystore_work_buf[(off)])

/* DEBUG 构建下：进入 keystore 块操作前断言没有双主机缓冲存活。 */
void immurok_scratch_mark_busy(uint8_t busy);
int  immurok_scratch_is_busy(void);

/*
 * === 嵌套派发（2026-11-26 审计）===
 * 指纹串口等待、VBAT 稳定延时、QC 自检会在函数中途调 TMOS_SystemProcess() 保链路。
 * 这时被派发的事件处理和 GATT 回调跑在比平时深得多的栈上（平时事件处理约 208 字节、
 * GATT 回调约 336 字节，嵌套时再加 200–350）。主栈只有 512 字节，再往下就是 work_buf：
 *
 *   - 整块读改写时 work_buf 里放着待写回的那一块，栈压进去多少字节，就有多少字节被
 *     原样写回 Flash（真实发生过：keystore 块尾 12 字节被 Flash 例程的栈帧盖掉）。
 *   - ECC 标量乘时 work_buf 低端是正在执行的代码，栈余量按非嵌套的深度算。
 *
 * 所以这两类操作只允许在非嵌套时做。凡是中途泵 TMOS 的地方一律用 TMOS_NESTED_PUMP()，
 * 做这两类操作的事件处理先看 immurok_tmos_nested()，是嵌套就把自己重新排期。
 * 入口函数（immurok_keystore_commit / delete、save_security_data）自己也查一次，
 * 嵌套时拒绝执行——宁可这次失败，不能悄悄写坏。
 */
extern volatile uint8_t g_tmos_nested;
static inline int immurok_tmos_nested(void) { return g_tmos_nested != 0; }

/* 问「现在是不是嵌套派发」的五个位置。正式固件里这个编号不产生任何代码。 */
enum {
    NEST_SITE_EXEC = 0,   /* hidEmu 执行事件：签名 / 密钥生成 / 配对 / 冷却期 COMMIT、DELETE */
    NEST_SITE_SAVE,       /* LED 任务 EEPROM_SAVE_EVT：配对数据落盘 */
    NEST_SITE_COMMIT,     /* LED 任务 KEYSTORE_COMMIT_EVT：新生成的 SSH 密钥落盘 */
    NEST_SITE_KS,         /* immurok_keystore_commit / delete 入口（拒绝，不改期） */
    NEST_SITE_SEC,        /* save_security_data 入口（拒绝，不改期） */
    NEST_SITE_COUNT
};

#ifdef TMOS_NESTED_DIAG
/*
 * 测试构建（make TEST_DEFS=-DTMOS_NESTED_DIAG）：数一数各处实际撞上嵌套多少次，并且能
 * 按位置注入「假装嵌套 N 次」。嵌套窗口只有几十到几百毫秒，从外面看不出撞没撞上，
 * 没有计数就没法说「测过了」。经 GET_CONN_PARAMS 载荷 [0xED …] 读写（hidkbd.c）。
 */
typedef struct {
    uint8_t  hits[NEST_SITE_COUNT];    /* 真嵌套时被问到的次数（饱和） */
    uint8_t  forced[NEST_SITE_COUNT];  /* 注入答「是」的次数（饱和） */
    uint8_t  streak_max;               /* 同一位置连续答「是」的最大次数；事件位置 ×5ms = 最长改期 */
    uint8_t  force_left;               /* 注入还剩几次 */
    uint8_t  force_mask;               /* 注入对哪些位置生效（bit n = 位置 n） */
    uint8_t  depth_max;                /* g_tmos_nested 见过的最大值 */
    uint16_t pumps;                    /* 嵌套泵执行次数（回绕） */
    /* 命令在嵌套窗口里到达时的去向：主机发了多少条可以从 App 日志数出来，和 cb_total
       一比就知道是「命令没进回调」还是「应答没发出去」。 */
    uint16_t cb_total;                 /* 命令回调进入次数（回绕） */
    uint8_t  cb_nested;                /* 其中在嵌套派发里进入的次数（饱和） */
    uint8_t  cb_nested_cmd;            /* 最近一条嵌套到达的命令码 */
    uint8_t  rsp_fail;                 /* 应答通知没发出去的次数（饱和） */
    uint8_t  rsp_fail_status;          /* 最近一次失败的状态码（0xFD 连接句柄无效 / 0xFE 未订阅 / 其余为协议栈返回值） */
    uint8_t  rsp_deferred;             /* 发不出去、留着等重发的次数（饱和） */
    uint8_t  rsp_retry_ok;             /* 其中重发成功的次数 */
    uint8_t  rsp_dropped;              /* 最终丢弃的次数（槽位被占、次数用完、不可重试的错误） */
} immurok_nest_diag_t;
extern immurok_nest_diag_t g_nest_diag;
int immurok_tmos_nested_at(uint8_t site);
#define TMOS_NESTED_PUMP()  do { \
        g_tmos_nested++; g_nest_diag.pumps++; \
        if (g_tmos_nested > g_nest_diag.depth_max) g_nest_diag.depth_max = g_tmos_nested; \
        TMOS_SystemProcess(); g_tmos_nested--; } while (0)
#else
#define TMOS_NESTED_PUMP()  do { g_tmos_nested++; TMOS_SystemProcess(); g_tmos_nested--; } while (0)
#define immurok_tmos_nested_at(site)  immurok_tmos_nested()
#endif
void immurok_scratch_assert_free(const char *who);

#endif /* IMMUROK_SCRATCH_H */
