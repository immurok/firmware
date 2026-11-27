/*
 * P-256 标量乘从 RAM 执行。
 *
 * 为什么：CH592 从 Flash 取指很慢。一次标量乘在 Flash 上约 2 s，比 macOS 给 HID 键盘的
 * 2000 ms supervision timeout 还长，配对和签名只能先把超时谈到 6000 ms 再算，主机不给就
 * 做不了。同一段机器码搬进 RAM 执行约 0.37 s（2026-11-26 真机实测，5.4 倍）。
 *
 * 怎么做：
 *   - 固件不单独编译 LIB/uECC.c，而是由本文件包含它（整个固件里 micro-ecc 只有这一份）。
 *     包含之前把 uECC_POINT_MULT 换成下面的跳板：make_key / shared_secret / sign 里做标量乘
 *     的那一个调用就走到这里。uECC_verify（OTA 验签）有自己的循环，不经过跳板，它的机器码
 *     与单独编译 uECC.c 时相同。
 *   - 链接脚本把标量乘用到的热点函数排在一起（Ld/ 下三个链接脚本的 _ecc_hot_start ~ _ecc_hot_end）。
 *     跳板在运算前把这一整段拷进 immurok_keystore_work_buf 低端，再跳到 RAM 里的
 *     EccPoint_mult。段内调用都是 PC 相对的，整段搬走仍然成立；段内代码不直接调用段外
 *     的函数——这两点由 tools/ecc_fast/verify.py 在每次构建后检查，不通过就不出固件。
 *   - 曲线表里的 mmod_fast 是绝对地址，所以另拷一份曲线表放在代码后面，把它改指到 RAM。
 *     double_jacobian 每次标量乘只调一次，留在 Flash 上执行。
 *   - RAM 没有常驻空间（只剩几个字节），所以是分时复用 work_buf：它只在读写 EEPROM 整块、
 *     TOTP、双主机页缓冲时使用，都是同步用完即还；标量乘期间不泵 TMOS，没有别的代码能
 *     插进来（约定写在 immurok_scratch.h）。
 *   - 栈余量是按「事件直接派发」的栈深留的。固件里别处仍有中途泵 TMOS 的地方（指纹串口
 *     等待等），那时派发出来的事件栈更深，所以 hidkbd.c 的执行事件在嵌套派发时不做 ECC，
 *     改期到外层返回之后（immurok_tmos_nested()）。
 *
 * 两个会跑飞的前提，都有兜底，不成立就留在 Flash 上跑（慢，但不崩）：
 *   - 链接器给的范围合理、入口在范围内：ecc_ram_layout_check。
 *   - 栈够用：work_buf 高端是栈溢出缓冲带，代码占了低端，进入前按当前 sp 算余量
 *     （ecc_ram_stack_ok）；占用区上方另留一条保护带，算完检查有没有被写穿。
 */
#include <stdint.h>
#include <string.h>
#include "uECC.h"
#include "uECC_vli.h"   /* uECC_word_t / bitcount_t，跳板的原型要用 */
#include "immurok_ecc_fast.h"
#include "ecc_ram_policy.h"

/* 不许内联：它的栈帧在标量乘期间一直占着，要保持很薄，且 verify.py 按这个符号量栈深。 */
__attribute__((noinline))
static void ecf_point_mult(uECC_word_t *result, const uECC_word_t *point,
                           const uECC_word_t *scalar, const uECC_word_t *initial_Z,
                           bitcount_t num_bits, uECC_Curve curve);
#define uECC_POINT_MULT ecf_point_mult

#include "../LIB/uECC.c"

extern uint8_t immurok_keystore_work_buf[4096];
extern int  immurok_scratch_is_busy(void);
extern void immurok_wdt_kick(void);

/* 热点代码上限。现在约 2.7KB；涨到这个数说明链接脚本里的列表混进了不该搬的东西。 */
#define ECF_MAX_CODE    3072u
/* 占用区上方的保护带，算完检查。 */
#define ECF_GUARD       32u
/* 进入标量乘后还要往下用的栈：调用链（EccPoint_mult → XYcZ_addC → modMult_fast →
   mult / mmod_fast）加中断处理的余量。verify.py 从反汇编里量调用链，构建时核对。 */
#define ECF_STACK_NEED  656u
/* 代码后面的数据区：曲线表副本（按 4 对齐占位）+ 借给调用方的临时空间。
   总长写成字面量，是因为要把它导出成符号给 verify.py（汇编里用不了 sizeof）；
   曲线表结构变大时下面的断言会在编译期报出来。 */
#define ECF_CURVE_SLOT  ((uint32_t)((sizeof(struct uECC_Curve_t) + 3u) & ~3u))
#define ECF_DATA_LEN    340u

/* 保护带被写穿过。PENDING：上一次运算的结果不可信，等调用方来读（读即清）。
   LATCHED：发生过一次就锁存到重启——栈余量既然估错了，再走 RAM 只会次次重蹈覆辙，
   此后一律在 Flash 上原地执行，immurok_ecc_fast_available() 也如实报不可用，让
   调用方的超时门重新生效。 */
#define ECF_FAULT_PENDING 0x01u
#define ECF_FAULT_LATCHED 0x02u
static uint8_t s_ecf_fault;

uint8_t immurok_ecc_fast_take_fault(void)
{
    uint8_t f = s_ecf_fault & ECF_FAULT_PENDING;
    s_ecf_fault &= (uint8_t)~ECF_FAULT_PENDING;
    return f;
}

#ifdef ECC_FAST_DIAG
static immurok_ecc_fast_diag_t s_diag = { 0, 0, 0, 0, 0xFFFF, 0 };
const immurok_ecc_fast_diag_t *immurok_ecc_fast_diag(void) { return &s_diag; }
#define ECF_DIAG(stmt) do { stmt; } while (0)
#else
#define ECF_DIAG(stmt) do { } while (0)
#endif

#ifdef IMMUROK_HOST_TEST

/* 主机上没有可搬的 RISC-V 代码段：原地执行。 */
uint8_t immurok_ecc_fast_available(void) { return 0; }
uint8_t *immurok_ecc_fast_scratch(void) { return immurok_keystore_work_buf + 2048; }

static void ecf_point_mult(uECC_word_t *result, const uECC_word_t *point,
                           const uECC_word_t *scalar, const uECC_word_t *initial_Z,
                           bitcount_t num_bits, uECC_Curve curve)
{
    EccPoint_mult(result, point, scalar, initial_Z, num_bits, curve);
}

#else /* 固件 */

extern const uint8_t _ecc_hot_start[];   /* 链接脚本 */
extern const uint8_t _ecc_hot_end[];

/* 只在固件里断言：主机上指针是 8 字节，曲线表更大，而主机构建根本不用这块数据区。 */
_Static_assert(ECF_DATA_LEN >= ((sizeof(struct uECC_Curve_t) + 3u) & ~3u) + IMMUROK_ECC_FAST_SCRATCH_LEN,
               "ECF_DATA_LEN too small for curve copy + caller scratch");

/* 把这几个常量导出成绝对符号，verify.py 拿它们和反汇编里量出的值核对。 */
#define ECF_STR2(x) #x
#define ECF_STR(x)  ECF_STR2(x)
__asm__(".globl ecf_stack_need\n.set ecf_stack_need, " ECF_STR(ECF_STACK_NEED) "\n"
        ".globl ecf_guard\n.set ecf_guard, " ECF_STR(ECF_GUARD) "\n"
        ".globl ecf_data_len\n.set ecf_data_len, " ECF_STR(ECF_DATA_LEN) "\n"
        ".globl ecf_max_code\n.set ecf_max_code, " ECF_STR(ECF_MAX_CODE) "\n");

typedef void (*ecf_mult_fn)(uECC_word_t *result, const uECC_word_t *point,
                            const uECC_word_t *scalar, const uECC_word_t *initial_Z,
                            bitcount_t num_bits, uECC_Curve curve);

static inline uintptr_t ecf_sp(void)
{
    uintptr_t sp;
    __asm__ volatile("mv %0, sp" : "=r"(sp));
    return sp;
}

static uint8_t ecf_layout(ecc_ram_layout_t *l)
{
    l->start = (uintptr_t)_ecc_hot_start;
    l->end   = (uintptr_t)_ecc_hot_end;
    l->mult  = (uintptr_t)&EccPoint_mult;
    l->mmod  = (uintptr_t)curve_secp256r1.mmod_fast;
    return ecc_ram_layout_check(l, ECF_MAX_CODE);
}

uint8_t immurok_ecc_fast_available(void)
{
    ecc_ram_layout_t l;
    return !(s_ecf_fault & ECF_FAULT_LATCHED) && ecf_layout(&l) == ECC_RAM_OK;
}

uint8_t *immurok_ecc_fast_scratch(void)
{
    ecc_ram_layout_t l;
    if (ecf_layout(&l) != ECC_RAM_OK) {
        /* 布局不可用时什么都不会搬进 work_buf，整块都空着；避开头部的 SLOTS / OTP 分区。 */
        return immurok_keystore_work_buf + 2048;
    }
    return immurok_keystore_work_buf + ecc_ram_data_offset(&l) + ECF_CURVE_SLOT;
}

/*
 * 检查并搬运。能走 RAM 时返回 RAM 里的曲线表副本，*fn 是 RAM 里的 EccPoint_mult，*guard 是
 * 占用区上方保护带的起点；不能走时返回 NULL。
 *
 * 单独成函数、不许内联：这里的局部变量只在搬运时需要，返回后它的栈帧就让出来了，
 * 不占标量乘期间的栈。sp 是调用者（跳板）的栈指针，余量按它算。
 */
__attribute__((noinline))
static const struct uECC_Curve_t *ecf_prepare(uintptr_t sp, ecf_mult_fn *fn, uint8_t **guard)
{
    uint8_t *wb = immurok_keystore_work_buf;
    ecc_ram_layout_t l;
    struct uECC_Curve_t *rc;
    uint32_t extent;
    uintptr_t delta;
    uint8_t reason;

    if (s_ecf_fault & ECF_FAULT_LATCHED) {
        reason = 5;
    } else if (ecf_layout(&l) != ECC_RAM_OK) {
        reason = 2;
    } else if (immurok_scratch_is_busy()) {
        reason = 3;
    } else if (!ecc_ram_stack_ok(sp, (uintptr_t)wb, ecc_ram_extent(&l, ECF_DATA_LEN),
                                 ECF_GUARD, ECF_STACK_NEED)) {
        reason = 4;
    } else {
        extent = ecc_ram_extent(&l, ECF_DATA_LEN);
        delta = (uintptr_t)wb - l.start;
        rc = (struct uECC_Curve_t *)(wb + ecc_ram_data_offset(&l));
        *fn = (ecf_mult_fn)(l.mult + delta);
        *guard = wb + extent;
#ifdef ECC_FAST_DIAG
        {
            /* 把保护带到本函数栈帧之间刷成标记，算完由 ecf_finish 看栈实际吃到哪。 */
            uint32_t room = ecc_ram_stack_room(sp, (uintptr_t)wb, extent, ECF_GUARD);
            uint8_t *hi = (uint8_t *)(ecf_sp() - 16u);
            uint8_t *q;
            if (room < s_diag.min_room) s_diag.min_room = (uint16_t)room;
            for (q = *guard + ECF_GUARD; q < hi; q++) *q = 0xA5;
        }
#endif
        memcpy(wb, (const void *)l.start, ecc_ram_code_size(&l));
        /* 曲线表副本：只改 mmod_fast。调用方借用区在它后面，不动。 */
        memcpy(rc, &curve_secp256r1, sizeof(*rc));
        rc->mmod_fast = (void (*)(uECC_word_t *, uECC_word_t *))(l.mmod + delta);
        memset(*guard, 0xA5, ECF_GUARD);
        return rc;
    }
    (void)reason;
    ECF_DIAG(s_diag.last_reason = reason; if (s_diag.flash_runs != 0xFF) s_diag.flash_runs++);
    return 0;
}

/* 算完检查保护带。被写穿说明栈余量估错了：记下来，调用方会把这次运算当作失败。 */
__attribute__((noinline))
static void ecf_finish(const uint8_t *guard, uintptr_t sp)
{
    uint32_t i;
    uint8_t intact = 1;
    for (i = 0; i < ECF_GUARD; i++) {
        if (guard[i] != 0xA5) intact = 0;
    }
    if (!intact) s_ecf_fault = ECF_FAULT_PENDING | ECF_FAULT_LATCHED;
    (void)sp;
#ifdef ECC_FAST_DIAG
    {
        const uint8_t *q = guard + ECF_GUARD;
        while ((uintptr_t)q < sp && *q == 0xA5) q++;
        if ((uint32_t)(sp - (uintptr_t)q) > s_diag.max_used)
            s_diag.max_used = (uint16_t)(sp - (uintptr_t)q);
        if (s_diag.ram_runs != 0xFF) s_diag.ram_runs++;
        if (!intact && s_diag.faults != 0xFF) s_diag.faults++;
    }
#endif
}

/*
 * uECC_POINT_MULT 的落点。固件只用 P-256；别的曲线（表里的函数不在热点段内）直接原地执行。
 * 本函数的栈帧在标量乘期间一直占着，所以保持很薄：检查和搬运都在 ecf_prepare 里。
 *
 * 标量乘期间保活回调必须只喂狗、不泵 TMOS：泵了别的任务就可能插进来读写 work_buf，
 * 把搬进去的代码冲掉。所以这里每次都把回调装成只喂狗的那个，不依赖别处注册了什么
 * （OTA 验签结束时会把它清成 NULL，之后的配对 / 签名也得有人喂狗）。
 */
static void ecf_point_mult(uECC_word_t *result, const uECC_word_t *point,
                           const uECC_word_t *scalar, const uECC_word_t *initial_Z,
                           bitcount_t num_bits, uECC_Curve curve)
{
    const struct uECC_Curve_t *rc = 0;
    ecf_mult_fn fn;
    uint8_t *guard;
    uintptr_t sp = ecf_sp();

    g_uECC_watchdog_cb = immurok_wdt_kick;
    if (curve == &curve_secp256r1) {
        rc = ecf_prepare(sp, &fn, &guard);
    } else {
        ECF_DIAG(s_diag.last_reason = 1; if (s_diag.flash_runs != 0xFF) s_diag.flash_runs++);
    }
    if (rc) {
        fn(result, point, scalar, initial_Z, num_bits, rc);
        ecf_finish(guard, sp);
    } else {
        EccPoint_mult(result, point, scalar, initial_Z, num_bits, curve);
    }
}

#endif /* IMMUROK_HOST_TEST */
