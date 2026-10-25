# RF 测试固件 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 CH592F VER=5 硬件构建一个独立的射频认证测试固件，通过指纹 UART(UART1 @115200 8N1)接收文本命令字驱动 RF 发射/接收，量产固件不含任何测试代码。

**Architecture:** 独立 Makefile target(`Makefile.rftest`)+ 独立源码目录(`firmware/RFTEST/`)，基于 SDK `RF_PHY` 例程的最小 BLE 初始化。命令解析与载荷/功率计算等纯逻辑抽到 `ftm_parse.c`(host 可单测)；RF 控制状态机与 UART/SDK 胶水在 `ftm.c`；入口/初始化在 `rftest_main.c`。上电即把指纹传感器电源 PB12(SENSOR_EN)置 0。

**Tech Stack:** C(gnu99)、WCH CH59x SDK、CH59xBLE LIB(`RF_Config`/`RF_Tx`/`RF_Rx`/`LL_SingleChannel`/`LL_SetTxPowerLevel`)、riscv-wch-gcc、host gcc(单测)。

设计文档：`docs/superpowers/specs/2026-06-16-rf-test-firmware-design.md`
分支：`feat/rf-test-firmware`(已创建并 checkout)

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `firmware/RFTEST/ftm_parse.h` | 纯逻辑接口:命令/错误枚举、解析结果结构、载荷/功率/频率换算原型、`FTM_PWR_*` 功率码常量 |
| `firmware/RFTEST/ftm_parse.c` | 纯逻辑实现:分词解析、PRBS/固定载荷生成、dBm→功率码映射、信道→频率换算(不含任何 I/O 与 SDK 依赖) |
| `firmware/RFTEST/ftm.h` | 板上 RF 控制接口:`ftm_init()`、`ftm_on_line()`、状态枚举 |
| `firmware/RFTEST/ftm.c` | RF 状态机 + 命令分发 + 响应格式化 + `rfStatusCB`;调用 `ftm_parse` 与 SDK RF API |
| `firmware/RFTEST/rftest_main.c` | 入口:时钟/GPIO(SENSOR_EN=0、UART1、LED)、BLE 最小初始化、UART1 行输入循环、TMOS 主循环 |
| `firmware/RFTEST/test/test_ftm_parse.c` | host 纯逻辑单元测试 |
| `firmware/RFTEST/test/Makefile` | host gcc 编译运行单测 |
| `firmware/RFTEST/PROTOCOL.md` | 命令字与响应说明文件(交付物) |
| `firmware/Makefile.rftest` | RF 测试固件构建(非 OTA,Link.ld,VER=5 默认) |

约定:`firmware/` 为工作目录前缀。所有 `make`/测试命令在 `firmware/` 下执行。

---

## Task 1: 纯逻辑接口头文件 `ftm_parse.h`

**Files:**
- Create: `firmware/RFTEST/ftm_parse.h`

- [ ] **Step 1: 写头文件**

```c
#ifndef FTM_PARSE_H
#define FTM_PARSE_H

#include <stdint.h>

/* 命令 ID */
typedef enum {
    FTM_CMD_NONE = 0,
    FTM_CMD_TX,          /* tx <ch> <power_level 0-3> */
    FTM_CMD_TXCW,        /* txcw <ch> */
    FTM_CMD_TX_PAYLOAD,  /* tx_payload <ch> <pattern 0-7> */
    FTM_CMD_TX_PHY,      /* tx_phy <0|1> */
    FTM_CMD_RX,          /* rx <ch> */
    FTM_CMD_STOP,        /* stop */
    FTM_CMD_RESET,       /* reset */
    FTM_CMD_HELP,        /* help */
    FTM_CMD_VER,         /* ver */
    FTM_CMD_ID,          /* id */
    FTM_CMD_FREQ,        /* freq <khz> */
    FTM_CMD_TXPOWER,     /* txpower <dbm> */
    FTM_CMD_VBAT,        /* vbat */
    FTM_CMD_ECHO,        /* echo <on|off> */
} ftm_cmd_id_t;

/* 错误码 */
typedef enum {
    FTM_OK = 0,
    FTM_ERR_UNKNOWN_CMD,
    FTM_ERR_BAD_ARGS,
    FTM_ERR_BAD_CHANNEL,
    FTM_ERR_BAD_POWER,
    FTM_ERR_BAD_PATTERN,
    FTM_ERR_BAD_PHY,
    FTM_ERR_BAD_FREQ,
} ftm_err_t;

/* 载荷图案(对齐截图 tx_payload pattern 编号) */
typedef enum {
    FTM_PAT_PRBS9  = 0,
    FTM_PAT_0F     = 1,
    FTM_PAT_55     = 2,
    FTM_PAT_PRBS15 = 3,
    FTM_PAT_ALL1   = 4,
    FTM_PAT_ALL0   = 5,
    FTM_PAT_F0     = 6,
    FTM_PAT_AA     = 7,
} ftm_pattern_t;

/* 解析结果:arg1/arg2 含义随命令而定
 *   TX:          arg1=ch,   arg2=power_level(0-3)
 *   TXCW/RX:     arg1=ch
 *   TX_PAYLOAD:  arg1=ch,   arg2=pattern(0-7)
 *   TX_PHY:      arg1=phy(0|1)
 *   FREQ:        arg1=khz
 *   TXPOWER:     arg1=dbm
 *   ECHO:        arg1=(1=on,0=off)
 */
typedef struct {
    ftm_cmd_id_t cmd;
    int          arg1;
    int          arg2;
    ftm_err_t    err;
} ftm_parsed_t;

/* CH59x LL_TX_PWR_*_DBM 功率码镜像(与 SDK 头一致,host 单测用) */
#define FTM_PWR_MINUS_20_DBM  0x01
#define FTM_PWR_MINUS_15_DBM  0x03
#define FTM_PWR_MINUS_10_DBM  0x05
#define FTM_PWR_MINUS_8_DBM   0x07
#define FTM_PWR_MINUS_5_DBM   0x0B
#define FTM_PWR_MINUS_3_DBM   0x0F
#define FTM_PWR_MINUS_1_DBM   0x13
#define FTM_PWR_0_DBM         0x15
#define FTM_PWR_1_DBM         0x1B
#define FTM_PWR_2_DBM         0x23
#define FTM_PWR_3_DBM         0x2B
#define FTM_PWR_4_DBM         0x3B

#define FTM_RF_CH_MIN     0
#define FTM_RF_CH_MAX     39
#define FTM_RF_FREQ_MIN   2400000   /* kHz */
#define FTM_RF_FREQ_MAX   2483500   /* kHz */
#define FTM_PAYLOAD_LEN   37        /* BLE DTM 惯例包长 */

/* 解析一行命令(不含结尾 \r\n),结果写入 *out。返回 out->err。 */
ftm_err_t ftm_parse_line(const char *line, ftm_parsed_t *out);

/* 把 pattern 对应的载荷填入 buf(len 字节)。PRBS9/PRBS15 用标准 BLE LFSR。 */
void ftm_fill_payload(int pattern, uint8_t *buf, int len);

/* dBm → CH59x 功率码(FTM_PWR_*);超范围钳到 [-20,4],无精确档取最近。 */
uint8_t ftm_dbm_to_pwr(int dbm);

/* tx 功率档(0-3)→ dBm:0=0,1=-3,2=-6,3=+3。非法档返回 0。 */
int ftm_level_to_dbm(int level);

/* 信道(0-39)→ 中心频率 MHz:f=2402+ch*2。 */
int ftm_ch_to_freq_mhz(int ch);

#endif /* FTM_PARSE_H */
```

- [ ] **Step 2: 提交**

```bash
git add firmware/RFTEST/ftm_parse.h
git commit -m "feat(rftest): ftm_parse 纯逻辑接口头"
```

---

## Task 2: host 单测脚手架 + 信道/频率换算(TDD)

**Files:**
- Create: `firmware/RFTEST/test/Makefile`
- Create: `firmware/RFTEST/test/test_ftm_parse.c`
- Create: `firmware/RFTEST/ftm_parse.c`

- [ ] **Step 1: 写 host 单测 Makefile**

```makefile
# host 纯逻辑单测(不依赖 SDK)
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -g -I..
SRC = ../ftm_parse.c test_ftm_parse.c

test: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o test_ftm_parse
	./test_ftm_parse

clean:
	rm -f test_ftm_parse
```

- [ ] **Step 2: 写第一个失败测试(信道→频率)**

`firmware/RFTEST/test/test_ftm_parse.c`:

```c
#include <stdio.h>
#include <string.h>
#include "ftm_parse.h"

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); g_fail++; } } while (0)

static void test_ch_to_freq(void) {
    CHECK(ftm_ch_to_freq_mhz(0)  == 2402);
    CHECK(ftm_ch_to_freq_mhz(19) == 2440);
    CHECK(ftm_ch_to_freq_mhz(39) == 2480);
}

int main(void) {
    test_ch_to_freq();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
```

- [ ] **Step 3: 写最小实现存根(让链接通过但测试失败)**

`firmware/RFTEST/ftm_parse.c`:

```c
#include "ftm_parse.h"

int ftm_ch_to_freq_mhz(int ch) { return 0; }
```

- [ ] **Step 4: 跑测试,确认 FAIL**

Run: `cd firmware/RFTEST/test && make`
Expected: 编译通过,输出 `FAIL ... ftm_ch_to_freq_mhz(0) == 2402` 等,退出码 1

- [ ] **Step 5: 实现 `ftm_ch_to_freq_mhz`**

把 `ftm_parse.c` 的存根替换为:

```c
int ftm_ch_to_freq_mhz(int ch) { return 2402 + ch * 2; }
```

- [ ] **Step 6: 跑测试,确认 PASS**

Run: `cd firmware/RFTEST/test && make`
Expected: `ALL TESTS PASSED`,退出码 0

- [ ] **Step 7: 提交**

```bash
git add firmware/RFTEST/test/Makefile firmware/RFTEST/test/test_ftm_parse.c firmware/RFTEST/ftm_parse.c
git commit -m "test(rftest): host 单测脚手架 + 信道→频率换算"
```

---

## Task 3: 功率映射(TDD)

**Files:**
- Modify: `firmware/RFTEST/test/test_ftm_parse.c`
- Modify: `firmware/RFTEST/ftm_parse.c`

- [ ] **Step 1: 加失败测试**

在 `test_ftm_parse.c` 的 `test_ch_to_freq` 之后加:

```c
static void test_power(void) {
    /* 档位→dBm */
    CHECK(ftm_level_to_dbm(0) == 0);
    CHECK(ftm_level_to_dbm(1) == -3);
    CHECK(ftm_level_to_dbm(2) == -6);
    CHECK(ftm_level_to_dbm(3) == 3);
    CHECK(ftm_level_to_dbm(9) == 0);   /* 非法档落 0 */

    /* dBm→功率码:精确档 */
    CHECK(ftm_dbm_to_pwr(0)   == FTM_PWR_0_DBM);
    CHECK(ftm_dbm_to_pwr(-3)  == FTM_PWR_MINUS_3_DBM);
    CHECK(ftm_dbm_to_pwr(3)   == FTM_PWR_3_DBM);
    /* -6dBm 无精确档 → 最近 -5dBm */
    CHECK(ftm_dbm_to_pwr(-6)  == FTM_PWR_MINUS_5_DBM);
    /* 钳位 */
    CHECK(ftm_dbm_to_pwr(100) == FTM_PWR_4_DBM);
    CHECK(ftm_dbm_to_pwr(-100)== FTM_PWR_MINUS_20_DBM);
}
```

并在 `main()` 里 `test_ch_to_freq();` 后加 `test_power();`。

- [ ] **Step 2: 跑测试,确认 FAIL**

Run: `cd firmware/RFTEST/test && make`
Expected: 链接失败(`undefined reference to ftm_level_to_dbm`)或 CHECK 失败

- [ ] **Step 3: 实现功率函数**

在 `ftm_parse.c` 末尾加:

```c
int ftm_level_to_dbm(int level) {
    switch (level) {
        case 0: return 0;
        case 1: return -3;
        case 2: return -6;
        case 3: return 3;
        default: return 0;
    }
}

uint8_t ftm_dbm_to_pwr(int dbm) {
    static const struct { int dbm; uint8_t code; } tbl[] = {
        { -20, FTM_PWR_MINUS_20_DBM }, { -15, FTM_PWR_MINUS_15_DBM },
        { -10, FTM_PWR_MINUS_10_DBM }, { -8,  FTM_PWR_MINUS_8_DBM  },
        { -5,  FTM_PWR_MINUS_5_DBM  }, { -3,  FTM_PWR_MINUS_3_DBM  },
        { -1,  FTM_PWR_MINUS_1_DBM  }, { 0,   FTM_PWR_0_DBM        },
        { 1,   FTM_PWR_1_DBM        }, { 2,   FTM_PWR_2_DBM        },
        { 3,   FTM_PWR_3_DBM        }, { 4,   FTM_PWR_4_DBM        },
    };
    int n = (int)(sizeof(tbl) / sizeof(tbl[0]));
    int best = 0, bestdiff = 1000000;
    for (int i = 0; i < n; i++) {
        int d = dbm - tbl[i].dbm;
        if (d < 0) d = -d;
        if (d < bestdiff) { bestdiff = d; best = i; }
    }
    return tbl[best].code;
}
```

- [ ] **Step 4: 跑测试,确认 PASS**

Run: `cd firmware/RFTEST/test && make`
Expected: `ALL TESTS PASSED`

- [ ] **Step 5: 提交**

```bash
git add firmware/RFTEST/test/test_ftm_parse.c firmware/RFTEST/ftm_parse.c
git commit -m "feat(rftest): 功率档→dBm 与 dBm→功率码映射"
```

---

## Task 4: 载荷生成(固定图案 + PRBS,TDD)

**Files:**
- Modify: `firmware/RFTEST/test/test_ftm_parse.c`
- Modify: `firmware/RFTEST/ftm_parse.c`

- [ ] **Step 1: 加失败测试**

在 `test_power` 之后加(PRBS9 全 1 初值 → 首字节 0xFF;0xC1 为标准 BLE PRBS9 第二字节):

```c
static void test_payload(void) {
    uint8_t b[FTM_PAYLOAD_LEN];

    /* 固定图案 */
    ftm_fill_payload(FTM_PAT_0F, b, 4);   CHECK(b[0]==0x0F && b[3]==0x0F);
    ftm_fill_payload(FTM_PAT_55, b, 4);   CHECK(b[0]==0x55 && b[3]==0x55);
    ftm_fill_payload(FTM_PAT_ALL1, b, 4); CHECK(b[0]==0xFF && b[3]==0xFF);
    ftm_fill_payload(FTM_PAT_ALL0, b, 4); CHECK(b[0]==0x00 && b[3]==0x00);
    ftm_fill_payload(FTM_PAT_F0, b, 4);   CHECK(b[0]==0xF0 && b[3]==0xF0);
    ftm_fill_payload(FTM_PAT_AA, b, 4);   CHECK(b[0]==0xAA && b[3]==0xAA);

    /* PRBS9:标准 BLE 序列前两字节 0xFF,0xC1;且确定性、非常量 */
    ftm_fill_payload(FTM_PAT_PRBS9, b, FTM_PAYLOAD_LEN);
    CHECK(b[0]==0xFF);
    CHECK(b[1]==0xC1);
    CHECK(!(b[2]==b[0] && b[3]==b[0]));   /* 不是常量填充 */

    /* PRBS15:全 1 初值首字节 0xFF,且非常量 */
    ftm_fill_payload(FTM_PAT_PRBS15, b, FTM_PAYLOAD_LEN);
    CHECK(b[0]==0xFF);
    CHECK(!(b[5]==0xFF && b[10]==0xFF));
}
```

并在 `main()` 加 `test_payload();`。

> 注:若 PRBS9 第二字节实测非 0xC1,说明 LFSR 移位方向/取位顺序与 BLE 标准相反——调整 Step 3 中 `out_bit` 取位与移位方向使其匹配标准序列(0xFF,0xC1,0xFB,0xE8,0x4C,0x90,...)。

- [ ] **Step 2: 跑测试,确认 FAIL**

Run: `cd firmware/RFTEST/test && make`
Expected: 链接失败(`undefined reference to ftm_fill_payload`)

- [ ] **Step 3: 实现 `ftm_fill_payload`**

在 `ftm_parse.c` 顶部 `#include "ftm_parse.h"` 后加 `#include <string.h>`,并在末尾加:

```c
/* 通用 LFSR:LSB-first 逐位输出。BLE PRBS9: x^9+x^5+1; PRBS15: x^15+x^14+1。 */
static void fill_prbs(uint8_t *buf, int len, uint16_t init,
                      int tap_a, int tap_b, int width) {
    uint16_t lfsr = init;
    for (int i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            uint8_t out_bit = lfsr & 1;          /* 取最低位作输出 */
            byte |= (out_bit << bit);            /* LSB-first 装入字节 */
            uint16_t fb = ((lfsr >> tap_a) ^ (lfsr >> tap_b)) & 1;
            lfsr = (lfsr >> 1) | (fb << (width - 1));
        }
        buf[i] = byte;
    }
}

void ftm_fill_payload(int pattern, uint8_t *buf, int len) {
    switch (pattern) {
        case FTM_PAT_0F:   memset(buf, 0x0F, len); break;
        case FTM_PAT_55:   memset(buf, 0x55, len); break;
        case FTM_PAT_ALL1: memset(buf, 0xFF, len); break;
        case FTM_PAT_ALL0: memset(buf, 0x00, len); break;
        case FTM_PAT_F0:   memset(buf, 0xF0, len); break;
        case FTM_PAT_AA:   memset(buf, 0xAA, len); break;
        case FTM_PAT_PRBS15:
            /* 15 位,taps x^15(bit14) 与 x^14(bit13) */
            fill_prbs(buf, len, 0x7FFF, 0, 1, 15); break;
        case FTM_PAT_PRBS9:
        default:
            /* 9 位,x^9+x^5+1 → taps bit0 与 bit4 */
            fill_prbs(buf, len, 0x01FF, 0, 4, 9); break;
    }
}
```

- [ ] **Step 4: 跑测试,确认 PASS(必要时按 Step 1 注解校准 PRBS)**

Run: `cd firmware/RFTEST/test && make`
Expected: `ALL TESTS PASSED`

- [ ] **Step 5: 提交**

```bash
git add firmware/RFTEST/test/test_ftm_parse.c firmware/RFTEST/ftm_parse.c
git commit -m "feat(rftest): 载荷生成(固定图案 + PRBS9/PRBS15)"
```

---

## Task 5: 命令行解析(TDD)

**Files:**
- Modify: `firmware/RFTEST/test/test_ftm_parse.c`
- Modify: `firmware/RFTEST/ftm_parse.c`

- [ ] **Step 1: 加失败测试**

在 `main()` 上方加:

```c
static ftm_parsed_t P(const char *line) {
    ftm_parsed_t p; ftm_parse_line(line, &p); return p;
}

static void test_parse(void) {
    ftm_parsed_t p;

    p = P("tx 0 0");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TX && p.arg1==0 && p.arg2==0);
    p = P("tx 39 3");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TX && p.arg1==39 && p.arg2==3);

    p = P("txcw 19");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TXCW && p.arg1==19);

    p = P("tx_payload 39 2");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TX_PAYLOAD && p.arg1==39 && p.arg2==2);

    p = P("tx_phy 1");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TX_PHY && p.arg1==1);

    p = P("rx 0");   CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_RX && p.arg1==0);
    p = P("stop");   CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_STOP);
    p = P("reset");  CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_RESET);
    p = P("help");   CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP);
    p = P("ver");    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_VER);
    p = P("id");     CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_ID);
    p = P("vbat");   CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_VBAT);

    p = P("freq 2402000");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_FREQ && p.arg1==2402000);
    p = P("txpower -8");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TXPOWER && p.arg1==-8);
    p = P("echo off");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_ECHO && p.arg1==0);
    p = P("echo on");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_ECHO && p.arg1==1);

    /* 容忍尾部 \r 与多余空格 */
    p = P("  tx   5   1  \r");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_TX && p.arg1==5 && p.arg2==1);

    /* 错误分支 */
    CHECK(P("bogus").err == FTM_ERR_UNKNOWN_CMD);
    CHECK(P("tx").err == FTM_ERR_BAD_ARGS);
    CHECK(P("tx 0").err == FTM_ERR_BAD_ARGS);
    CHECK(P("tx 40 0").err == FTM_ERR_BAD_CHANNEL);
    CHECK(P("tx 0 4").err == FTM_ERR_BAD_POWER);
    CHECK(P("tx_payload 0 8").err == FTM_ERR_BAD_PATTERN);
    CHECK(P("tx_phy 2").err == FTM_ERR_BAD_PHY);
    CHECK(P("freq 100").err == FTM_ERR_BAD_FREQ);
    CHECK(P("rx 40").err == FTM_ERR_BAD_CHANNEL);
    CHECK(P("").err == FTM_ERR_UNKNOWN_CMD);
}
```

并在 `main()` 加 `test_parse();`。

- [ ] **Step 2: 跑测试,确认 FAIL**

Run: `cd firmware/RFTEST/test && make`
Expected: 链接失败(`undefined reference to ftm_parse_line`)

- [ ] **Step 3: 实现 `ftm_parse_line`**

在 `ftm_parse.c` 末尾加(顶部已 include string.h,再加 `<stdlib.h>`):

```c
/* 取下一个空格分隔 token,返回是否取到;*pp 推进到 token 后 */
static int next_tok(const char **pp, char *buf, int bufsz) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == '\0') { *pp = p; return 0; }
    int n = 0;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        if (n < bufsz - 1) buf[n++] = *p;
        p++;
    }
    buf[n] = '\0';
    *pp = p;
    return 1;
}

/* 把 token 转 int;成功返回 1 */
static int tok_int(const char *s, int *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0') return 0;
    *out = (int)v;
    return 1;
}

ftm_err_t ftm_parse_line(const char *line, ftm_parsed_t *out) {
    char tok[16];
    const char *p = line;
    out->cmd = FTM_CMD_NONE; out->arg1 = 0; out->arg2 = 0; out->err = FTM_OK;

    if (!next_tok(&p, tok, sizeof(tok))) { out->err = FTM_ERR_UNKNOWN_CMD; return out->err; }

    /* 无参命令 */
    if      (!strcmp(tok, "stop"))  { out->cmd = FTM_CMD_STOP;  return FTM_OK; }
    else if (!strcmp(tok, "reset")) { out->cmd = FTM_CMD_RESET; return FTM_OK; }
    else if (!strcmp(tok, "help"))  { out->cmd = FTM_CMD_HELP;  return FTM_OK; }
    else if (!strcmp(tok, "ver"))   { out->cmd = FTM_CMD_VER;   return FTM_OK; }
    else if (!strcmp(tok, "id"))    { out->cmd = FTM_CMD_ID;    return FTM_OK; }
    else if (!strcmp(tok, "vbat"))  { out->cmd = FTM_CMD_VBAT;  return FTM_OK; }

    /* 单参命令 */
    else if (!strcmp(tok, "txcw") || !strcmp(tok, "rx")) {
        out->cmd = !strcmp(tok, "txcw") ? FTM_CMD_TXCW : FTM_CMD_RX;
        int ch;
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &ch)) { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if (ch < FTM_RF_CH_MIN || ch > FTM_RF_CH_MAX) { out->err = FTM_ERR_BAD_CHANNEL; return out->err; }
        out->arg1 = ch;
    }
    else if (!strcmp(tok, "tx_phy")) {
        out->cmd = FTM_CMD_TX_PHY;
        int phy;
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &phy)) { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if (phy != 0 && phy != 1) { out->err = FTM_ERR_BAD_PHY; return out->err; }
        out->arg1 = phy;
    }
    else if (!strcmp(tok, "freq")) {
        out->cmd = FTM_CMD_FREQ;
        int khz;
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &khz)) { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if (khz < FTM_RF_FREQ_MIN || khz > FTM_RF_FREQ_MAX) { out->err = FTM_ERR_BAD_FREQ; return out->err; }
        out->arg1 = khz;
    }
    else if (!strcmp(tok, "txpower")) {
        out->cmd = FTM_CMD_TXPOWER;
        int dbm;
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &dbm)) { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        out->arg1 = dbm;   /* dBm 由 ftm_dbm_to_pwr 钳位,这里不限制 */
    }
    else if (!strcmp(tok, "echo")) {
        out->cmd = FTM_CMD_ECHO;
        if (!next_tok(&p, tok, sizeof(tok))) { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if      (!strcmp(tok, "on"))  out->arg1 = 1;
        else if (!strcmp(tok, "off")) out->arg1 = 0;
        else { out->err = FTM_ERR_BAD_ARGS; return out->err; }
    }
    /* 双参命令 */
    else if (!strcmp(tok, "tx") || !strcmp(tok, "tx_payload")) {
        int is_tx = !strcmp(tok, "tx");
        out->cmd = is_tx ? FTM_CMD_TX : FTM_CMD_TX_PAYLOAD;
        int ch, a2;
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &ch))  { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if (!next_tok(&p, tok, sizeof(tok)) || !tok_int(tok, &a2))  { out->err = FTM_ERR_BAD_ARGS; return out->err; }
        if (ch < FTM_RF_CH_MIN || ch > FTM_RF_CH_MAX) { out->err = FTM_ERR_BAD_CHANNEL; return out->err; }
        if (is_tx) { if (a2 < 0 || a2 > 3) { out->err = FTM_ERR_BAD_POWER; return out->err; } }
        else       { if (a2 < 0 || a2 > 7) { out->err = FTM_ERR_BAD_PATTERN; return out->err; } }
        out->arg1 = ch; out->arg2 = a2;
    }
    else { out->err = FTM_ERR_UNKNOWN_CMD; return out->err; }

    return FTM_OK;
}
```

- [ ] **Step 4: 跑测试,确认 PASS**

Run: `cd firmware/RFTEST/test && make`
Expected: `ALL TESTS PASSED`

- [ ] **Step 5: 提交**

```bash
git add firmware/RFTEST/test/test_ftm_parse.c firmware/RFTEST/ftm_parse.c
git commit -m "feat(rftest): 命令行解析与参数校验"
```

---

## Task 6: 构建脚手架 `Makefile.rftest`

**Files:**
- Create: `firmware/Makefile.rftest`

- [ ] **Step 1: 写 Makefile.rftest**

(模仿 `firmware/Makefile`,源集替换为 RFTEST 三文件 + 必要 SDK 驱动,链接 BLE LIB,非 OTA。)

```makefile
# immurok CH592F RF 测试固件(认证/产线用,非 OTA,有线烧录)
TARGET = immurok_CH592F_RFTEST

TOOLCHAIN_PATH ?= /opt/riscv-wch-gcc
TOOLCHAIN_BIN = $(TOOLCHAIN_PATH)/bin
CC = "$(TOOLCHAIN_BIN)/riscv-wch-elf-gcc"
OBJCOPY = "$(TOOLCHAIN_BIN)/riscv-wch-elf-objcopy"
SIZE = "$(TOOLCHAIN_BIN)/riscv-wch-elf-size"

SDK_PATH = SDK/EVT/EXAM
SRC_PATH = $(SDK_PATH)/SRC
BLE_PATH = $(SDK_PATH)/BLE
BUILD_DIR = build_rftest

C_SOURCES = \
	RFTEST/rftest_main.c \
	RFTEST/ftm.c \
	RFTEST/ftm_parse.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_gpio.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_sys.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_clk.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart1.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart3.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_pwr.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_adc.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_flash.c \
	$(SRC_PATH)/RVMSIS/core_riscv.c \
	$(BLE_PATH)/HAL/MCU.c \
	$(BLE_PATH)/HAL/RTC.c \
	$(BLE_PATH)/HAL/SLEEP.c

ASM_SOURCES = \
	$(SRC_PATH)/Startup/startup_CH592.S \
	$(BLE_PATH)/LIB/ble_task_scheduler.S

C_INCLUDES = \
	-I$(BLE_PATH)/HAL/include \
	-I$(BLE_PATH)/LIB \
	-IRFTEST \
	-I$(SRC_PATH)/StdPeriphDriver/inc \
	-I$(SRC_PATH)/RVMSIS

HW_VER ?= 5
BLE_MEMHEAP = 5632

C_DEFS = \
	-DHARDWARE_VER$(HW_VER) \
	-DCH592 \
	-DDEBUG=3 \
	-DHAL_SLEEP=FALSE \
	-DBLE_MAC=FALSE \
	-DDCDC_ENABLE=TRUE \
	-DBLE_MEMHEAP_SIZE=$(BLE_MEMHEAP) \
	-DBLE_BUFF_MAX_LEN=251 \
	-DBLE_TX_NUM_EVENT=1 \
	-DCLK_OSC32K=0 \
	-DWAKE_UP_RTC_MAX_TIME=164 \
	-DBLE_TX_POWER=LL_TX_POWEER_0_DBM \
	-DRFTEST_BUILD=1

MCU_FLAGS = -march=rv32imac_zicsr -mabi=ilp32 -msmall-data-limit=8
CFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES)
CFLAGS += -std=gnu99 -Os -ffunction-sections -fdata-sections -fno-common
CFLAGS += -Wall -Wno-unused-function -g

ASFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES) -x assembler-with-cpp

LDSCRIPT = Ld/Link.ld
LIBS = -L$(BLE_PATH)/LIB -L$(SRC_PATH)/StdPeriphDriver -lCH59xBLE -lISP592 -lm
LDFLAGS = $(MCU_FLAGS) -T$(LDSCRIPT)
LDFLAGS += -nostartfiles -Xlinker --gc-sections
LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref
LDFLAGS += --specs=nano.specs --specs=nosys.specs
LDFLAGS += $(LIBS)

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

$(shell mkdir -p $(BUILD_DIR))

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin
	$(SIZE) $(BUILD_DIR)/$(TARGET).elf
	@echo "RFTEST 固件: HW VER$(HW_VER) — 仅有线烧录,勿走 OTA"

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "CC $<"
	@$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	@echo "AS $<"
	@$(CC) -c $(ASFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	@echo "LD $@"
	@$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/$(TARGET).hex: $(BUILD_DIR)/$(TARGET).elf
	@$(OBJCOPY) -O ihex $< $@

$(BUILD_DIR)/$(TARGET).bin: $(BUILD_DIR)/$(TARGET).elf
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
```

> 注:`CH59x_uart1.c`/`uart3.c` 等的实际文件名以 `firmware/SDK/EVT/EXAM/SRC/StdPeriphDriver/` 下为准(现有 `Makefile` 已用同名,直接沿用)。BLE LIB 名 `-lCH59xBLE`、`-lISP592` 与现有 Makefile 一致。

- [ ] **Step 2: 占位编译验证(此时 ftm.c/rftest_main.c 尚未建,预期失败但能看到工具链可用)**

Run: `cd firmware && make -f Makefile.rftest 2>&1 | head -5`
Expected: 报找不到 `RFTEST/ftm.c` / `RFTEST/rftest_main.c`(下一个 Task 补齐)。确认不是工具链路径错误。

- [ ] **Step 3: 提交**

```bash
git add firmware/Makefile.rftest
git commit -m "build(rftest): RF 测试固件 Makefile(非 OTA,VER=5 默认)"
```

---

## Task 7: 板上控制接口 `ftm.h`

**Files:**
- Create: `firmware/RFTEST/ftm.h`

- [ ] **Step 1: 写 ftm.h**

```c
#ifndef FTM_H
#define FTM_H

#include <stdint.h>

/* 初始化 RF 测试子系统(配置默认 RF、注册 TMOS 任务、置回显默认开)。
 * 在 BLE 协议栈初始化(CH59x_BLEInit/HAL_Init/RF_RoleInit)之后调用。 */
void ftm_init(void);

/* 处理一整行命令(不含结尾 \r\n)。由 UART 行组装层调用。 */
void ftm_on_line(const char *line);

/* 输出一行到命令口(UART1),自动补 \r\n。供内部与 main 打印横幅用。 */
void ftm_puts(const char *s);

#endif /* FTM_H */
```

- [ ] **Step 2: 提交**

```bash
git add firmware/RFTEST/ftm.h
git commit -m "feat(rftest): 板上 RF 控制接口头 ftm.h"
```

---

## Task 8: 入口与初始化 `rftest_main.c`

**Files:**
- Create: `firmware/RFTEST/rftest_main.c`

- [ ] **Step 1: 写 rftest_main.c**

(时钟、GPIO:PB12 SENSOR_EN=0、UART1 PA8/PA9 @115200、LED;BLE 最小初始化;UART1 轮询行组装;TMOS 主循环。)

```c
/* immurok IK-1 RF 测试固件入口(CH592F VER=5)
 * 指纹传感器断电;指纹 UART(UART1, PA8/PA9)作命令口 @115200 8N1。 */
#include "CH59x_common.h"
#include "CONFIG.h"
#include "ftm.h"

/* VER=5 引脚 */
#define PIN_SENSOR_EN   GPIO_Pin_12   /* PB12 FP_PWR,置 0 给指纹断电 */
#define PIN_LED_RED     GPIO_Pin_7    /* PB7 */
#define PIN_LED_BLUE    GPIO_Pin_22   /* PB22 */

__attribute__((aligned(4))) uint32_t MEM_BUF[BLE_MEMHEAP_SIZE / 4];

/* UART1 行缓冲 */
#define LINE_MAX 64
static char  s_line[LINE_MAX];
static int   s_len = 0;

static void board_gpio_init(void) {
    /* 指纹传感器断电:PB12 输出低 */
    GPIOB_ModeCfg(PIN_SENSOR_EN, GPIO_ModeOut_PP_5mA);
    GPIOB_ResetBits(PIN_SENSOR_EN);

    /* 状态 LED(低有效/高有效以实际硬件为准,这里高=亮) */
    GPIOB_ModeCfg(PIN_LED_RED | PIN_LED_BLUE, GPIO_ModeOut_PP_5mA);
    GPIOB_ResetBits(PIN_LED_RED | PIN_LED_BLUE);
}

static void uart1_cmdport_init(void) {
    /* UART1 默认在 PA8(RXD1)/PA9(TXD1),无需 remap */
    GPIOA_SetBits(GPIO_Pin_9);
    GPIOA_ModeCfg(GPIO_Pin_8, GPIO_ModeIN_PU);          /* RX */
    GPIOA_ModeCfg(GPIO_Pin_9, GPIO_ModeOut_PP_5mA);     /* TX */
    UART1_DefInit();
    UART1_BaudRateCfg(115200);
}

/* 轮询 UART1 RX FIFO,按 \n 组装行后交给 ftm_on_line */
static void uart1_poll(void) {
    while (R8_UART1_RFC) {              /* RX FIFO 有数据 */
        uint8_t c = UART1_RecvByte();
        if (c == '\n' || c == '\r') {
            if (s_len > 0) {
                s_line[s_len] = '\0';
                ftm_on_line(s_line);
                s_len = 0;
            }
        } else if (s_len < LINE_MAX - 1) {
            s_line[s_len++] = (char)c;
        } else {
            /* 超长行:丢弃并报错 */
            s_len = 0;
            ftm_puts("ERR line too long");
        }
    }
}

int main(void) {
    SetSysClock(CLK_SOURCE_PLL_60MHz);

    board_gpio_init();
    uart1_cmdport_init();

    CH59x_BLEInit();
    HAL_Init();
    RF_RoleInit();
    ftm_init();

    ftm_puts("[FTM] ready");
    ftm_puts("immurok IK-1 RFTEST v" FW_VERSION_STRING " HW=5");

    while (1) {
        TMOS_SystemProcess();
        uart1_poll();
    }
}
```

> 注:`R8_UART1_RFC`(RX FIFO 计数寄存器)在 `CH592SFR.h`;若实际寄存器名不同,用 `(UART1_GetLinSTA() & RB_LSR_DATA_RDY)` 逐字节判断替代。`MEM_BUF` 与 `BLE_MEMHEAP_SIZE` 由 CONFIG 提供给 `CH59x_BLEInit()`;参照 `firmware/APP/main.c` 现有的 BLE 内存声明写法对齐(若现有用 `__attribute__((aligned(4))) uint32_t MEM_BUF[...]` 之外的形式,以现有为准)。

- [ ] **Step 2: 提交**

```bash
git add firmware/RFTEST/rftest_main.c
git commit -m "feat(rftest): 入口与板级初始化(SENSOR_EN=0 + UART1 命令口)"
```

---

## Task 9: RF 控制状态机与命令分发 `ftm.c`

**Files:**
- Create: `firmware/RFTEST/ftm.c`

- [ ] **Step 1: 写 ftm.c**

(配置 RF、实现 tx 连续发射/txcw/tx_payload/tx_phy/rx/stop/reset 与 meta 命令,响应格式化,`rfStatusCB` 重装发射与收包计数。)

```c
#include "CH59x_common.h"
#include "CONFIG.h"
#include "ftm.h"
#include "ftm_parse.h"
#include <stdio.h>
#include <string.h>

/* 功率码常量必须与 SDK 宏一致(host 单测用 FTM_PWR_*,设备上断言对齐) */
_Static_assert(FTM_PWR_0_DBM == LL_TX_PWR_0_DBM, "pwr 0dBm mismatch");
_Static_assert(FTM_PWR_MINUS_3_DBM == LL_TX_PWR_MINUS_3_DBM, "pwr -3dBm mismatch");
_Static_assert(FTM_PWR_MINUS_5_DBM == LL_TX_PWR_MINUS_5_DBM, "pwr -5dBm mismatch");
_Static_assert(FTM_PWR_3_DBM == LL_TX_PWR_3_DBM, "pwr +3dBm mismatch");

#define PIN_LED_RED   GPIO_Pin_7
#define PIN_LED_BLUE  GPIO_Pin_22

typedef enum { ST_IDLE, ST_TX, ST_CW, ST_RX } ftm_state_t;

static uint8_t      s_taskID;
static ftm_state_t  s_state = ST_IDLE;
static uint8_t      s_phy = 0;                 /* 0=1M,1=2M */
static int          s_echo = 1;
static uint8_t      s_cur_ch = 0;
static __attribute__((aligned(4))) uint8_t s_txbuf[FTM_PAYLOAD_LEN];
static volatile uint32_t s_rx_pkt = 0;
static volatile uint32_t s_rx_crc_err = 0;

#define EVT_TX_RELOAD   (1 << 0)

/* ---- UART1 输出 ---- */
void ftm_puts(const char *s) {
    while (*s) { while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP)); UART1_SendByte(*s++); }
    while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP)); UART1_SendByte('\r');
    while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP)); UART1_SendByte('\n');
}

static void reply_err(ftm_err_t e) {
    switch (e) {
        case FTM_ERR_BAD_CHANNEL: ftm_puts("ERR bad channel (0-39)"); break;
        case FTM_ERR_BAD_POWER:   ftm_puts("ERR bad power (0-3)"); break;
        case FTM_ERR_BAD_PATTERN: ftm_puts("ERR bad pattern (0-7)"); break;
        case FTM_ERR_BAD_PHY:     ftm_puts("ERR bad phy (0|1)"); break;
        case FTM_ERR_BAD_FREQ:    ftm_puts("ERR bad freq (2400000-2483500)"); break;
        case FTM_ERR_BAD_ARGS:    ftm_puts("ERR bad args"); break;
        default:                  ftm_puts("ERR unknown cmd"); break;
    }
}

/* ---- RF 配置 ---- */
static void rf_apply_config(uint8_t ch, uint32_t freq_khz, int use_freq) {
    rfConfig_t cfg;
    tmos_memset(&cfg, 0, sizeof(cfg));
    cfg.accessAddress = 0x71764129;
    cfg.CRCInit = 0x555555;
    cfg.Channel = ch;
    cfg.Frequency = use_freq ? freq_khz : (uint32_t)(2402000 + ch * 2000);
    cfg.LLEMode = LLE_MODE_BASIC | (s_phy ? LLE_MODE_PHY_2M : LLE_MODE_PHY_1M);
    if (use_freq) cfg.LLEMode |= LLE_MODE_EX_CHANNEL;
    cfg.rfStatusCB = (pfnRFStatusCB_t)0; /* 占位,下一行设真正回调 */
    extern void ftm_rf_cb(uint8_t sta, uint8_t rsr, uint8_t *rxBuf);
    cfg.rfStatusCB = ftm_rf_cb;
    cfg.RxMaxlen = 251;
    RF_Config(&cfg);
}

static void stop_all(void) {
    RF_Shut();
    tmos_clear_event(s_taskID, EVT_TX_RELOAD);
    GPIOB_ResetBits(PIN_LED_RED | PIN_LED_BLUE);
    s_state = ST_IDLE;
}

/* ---- 回调:连续发射重装 + 收包计数 ---- */
void ftm_rf_cb(uint8_t sta, uint8_t rsr, uint8_t *rxBuf) {
    (void)rxBuf;
    switch (sta) {
        case TX_MODE_TX_FINISH:
        case TX_MODE_TX_FAIL:
            if (s_state == ST_TX) tmos_set_event(s_taskID, EVT_TX_RELOAD);
            break;
        case RX_MODE_RX_DATA:
            if (rsr == 0) s_rx_pkt++;     /* rsr: CRC 结果,0=OK */
            else          s_rx_crc_err++;
            RF_Rx(s_txbuf, FTM_PAYLOAD_LEN, 0xFF, 0xFF);  /* 继续收 */
            break;
        default:
            break;
    }
}

/* ---- TMOS 事件:发下一包 ---- */
static uint16_t ftm_event(uint8_t task_id, uint16_t events) {
    (void)task_id;
    if (events & EVT_TX_RELOAD) {
        if (s_state == ST_TX)
            RF_Tx(s_txbuf, FTM_PAYLOAD_LEN, 0xFF, 0xFF);
        return events ^ EVT_TX_RELOAD;
    }
    return 0;
}

/* ---- 命令执行 ---- */
static void do_tx(int ch, int level) {
    stop_all();
    ftm_fill_payload(FTM_PAT_PRBS9, s_txbuf, FTM_PAYLOAD_LEN);
    LL_SetTxPowerLevel(ftm_dbm_to_pwr(ftm_level_to_dbm(level)));
    rf_apply_config((uint8_t)ch, 0, 0);
    s_cur_ch = (uint8_t)ch;
    s_state = ST_TX;
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    char m[64];
    snprintf(m, sizeof(m), "OK tx ch=%d pwr=%ddBm phy=%s payload=PRBS9",
             ch, ftm_level_to_dbm(level), s_phy ? "2M" : "1M");
    ftm_puts(m);
}

static void do_tx_payload(int ch, int pat) {
    stop_all();
    ftm_fill_payload(pat, s_txbuf, FTM_PAYLOAD_LEN);
    rf_apply_config((uint8_t)ch, 0, 0);
    s_cur_ch = (uint8_t)ch;
    s_state = ST_TX;
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    static const char *names[] = {"PRBS9","0x0F","0x55","PRBS15","all-1","all-0","0xF0","0xAA"};
    char m[64];
    snprintf(m, sizeof(m), "OK tx_payload ch=%d pattern=%s", ch, names[pat]);
    ftm_puts(m);
}

static void do_txcw(int ch) {
    stop_all();
    LL_SingleChannel((uint8_t)ch);
    s_cur_ch = (uint8_t)ch;
    s_state = ST_CW;
    GPIOB_SetBits(PIN_LED_RED);
    char m[48];
    snprintf(m, sizeof(m), "OK txcw ch=%d freq=%dMHz", ch, ftm_ch_to_freq_mhz(ch));
    ftm_puts(m);
}

static void do_rx(int ch) {
    stop_all();
    s_rx_pkt = 0; s_rx_crc_err = 0;
    rf_apply_config((uint8_t)ch, 0, 0);
    s_cur_ch = (uint8_t)ch;
    s_state = ST_RX;
    GPIOB_SetBits(PIN_LED_BLUE);
    RF_Rx(s_txbuf, FTM_PAYLOAD_LEN, 0xFF, 0xFF);
    char m[32];
    snprintf(m, sizeof(m), "OK rx ch=%d listening", ch);
    ftm_puts(m);
}

static void print_rxstats(void) {
    char m[64];
    snprintf(m, sizeof(m), "rxstats ch=%d pkt=%lu crc_err=%lu",
             s_cur_ch, (unsigned long)s_rx_pkt, (unsigned long)s_rx_crc_err);
    ftm_puts(m);
}

static void do_stop(void) {
    int was_rx = (s_state == ST_RX);
    stop_all();
    ftm_puts("OK stop");
    if (was_rx) print_rxstats();
}

static void do_freq(int khz) {
    stop_all();
    ftm_fill_payload(FTM_PAT_PRBS9, s_txbuf, FTM_PAYLOAD_LEN);
    rf_apply_config(0, (uint32_t)khz, 1);
    s_state = ST_TX;
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    char m[48];
    snprintf(m, sizeof(m), "OK freq=%dkHz", khz);
    ftm_puts(m);
}

static void do_txpower(int dbm) {
    LL_SetTxPowerLevel(ftm_dbm_to_pwr(dbm));
    char m[32];
    snprintf(m, sizeof(m), "OK txpower=%ddBm", dbm);
    ftm_puts(m);
}

static void do_ver(void) {
    char m[80];
    snprintf(m, sizeof(m), "immurok IK-1 RFTEST v%s build=0x%X HW=5 phy=%s",
             FW_VERSION_STRING, (unsigned)FW_BUILD_NUMBER, s_phy ? "2M" : "1M");
    ftm_puts(m);
}

static void do_id(void) {
    uint8_t mac[6] = {0};
    GetMACAddress(mac);
    char m[48];
    snprintf(m, sizeof(m), "id MAC=%02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    ftm_puts(m);
}

static void do_vbat(void) {
    /* PA14 = AIN4,VER=5 为 1/4 分压;粗略读取并换算 mV。 */
    ADC_ExtSingleChSampInit(SampleFreq_3_2, ADC_PGA_0);
    ADC_ChannelCfg(4);
    int adc = ADC_ExcutSingleConver();
    /* 满量程近似换算,系数随实际校准调整;此处给 1/4 分压粗值 */
    int mv = (int)((long)adc * 1050 / 512 * 4 / 1000) * 1000 / 1; /* 占位换算 */
    char m[32];
    snprintf(m, sizeof(m), "vbat=%dmV", mv);
    ftm_puts(m);
}

static void do_help(void) {
    ftm_puts("cmds: tx <ch> <0-3> | txcw <ch> | tx_payload <ch> <0-7>");
    ftm_puts("      tx_phy <0|1> | rx <ch> | stop | reset");
    ftm_puts("      freq <khz> | txpower <dbm> | vbat | ver | id | echo <on|off>");
}

void ftm_init(void) {
    s_taskID = TMOS_ProcessEventRegister(ftm_event);
    s_state = ST_IDLE;
    s_phy = 0;
    s_echo = 1;
}

void ftm_on_line(const char *line) {
    if (s_echo) ftm_puts(line);

    ftm_parsed_t p;
    ftm_parse_line(line, &p);
    if (p.err != FTM_OK) { reply_err(p.err); return; }

    switch (p.cmd) {
        case FTM_CMD_TX:         do_tx(p.arg1, p.arg2); break;
        case FTM_CMD_TXCW:       do_txcw(p.arg1); break;
        case FTM_CMD_TX_PAYLOAD: do_tx_payload(p.arg1, p.arg2); break;
        case FTM_CMD_TX_PHY:     s_phy = (uint8_t)p.arg1;
                                 ftm_puts(s_phy ? "OK phy=2M" : "OK phy=1M"); break;
        case FTM_CMD_RX:         do_rx(p.arg1); break;
        case FTM_CMD_STOP:       do_stop(); break;
        case FTM_CMD_RESET:      ftm_puts("OK reset"); SYS_ResetExecute(); break;
        case FTM_CMD_HELP:       do_help(); break;
        case FTM_CMD_VER:        do_ver(); break;
        case FTM_CMD_ID:         do_id(); break;
        case FTM_CMD_FREQ:       do_freq(p.arg1); break;
        case FTM_CMD_TXPOWER:    do_txpower(p.arg1); break;
        case FTM_CMD_VBAT:       do_vbat(); break;
        case FTM_CMD_ECHO:       s_echo = p.arg1;
                                 ftm_puts(s_echo ? "OK echo=on" : "OK echo=off"); break;
        default:                 reply_err(FTM_ERR_UNKNOWN_CMD); break;
    }
}
```

> 注（实现期校准点，编译/上板时确认）：
> - `R8_UART1_LSR` / `RB_LSR_TX_FIFO_EMP` / `RB_LSR_DATA_RDY` / `R8_UART1_RFC` 名称以 `CH592SFR.h` 为准。
> - `tmos_clear_event` / `tmos_set_event` / `TMOS_ProcessEventRegister` / `SYS_ResetExecute` / `GetMACAddress` / `ADC_*` 签名以 `CH59xBLE_LIB.h` 与 `StdPeriphDriver/inc/*.h` 为准。
> - `rsr` 在 RX 回调里的 CRC 语义参考 `RF_PHY.c` 的 `RX_MODE_RX_DATA` 分支用法（该例程里第二参数为 CRC/RSSI 状态）；按实际位定义校正 `s_rx_crc_err` 判定。
> - `do_vbat` 的换算系数是占位，需按 VER=5 的 1/4 分压与 ADC 基准实测标定（可参考 `firmware/APP/` 中现有电池电压读取代码，若有则复用其换算）。

- [ ] **Step 2: 编译 RF 测试固件**

Run: `cd firmware && make -f Makefile.rftest 2>&1 | tail -20`
Expected: 链接成功，输出 `.elf/.hex/.bin` 与 size；如有寄存器/函数名报错，按上面「校准点」逐条改名后重编。

- [ ] **Step 3: 提交**

```bash
git add firmware/RFTEST/ftm.c
git commit -m "feat(rftest): RF 控制状态机与命令分发(tx/cw/payload/rx/meta)"
```

---

## Task 10: 命令说明文件 `PROTOCOL.md`

**Files:**
- Create: `firmware/RFTEST/PROTOCOL.md`

- [ ] **Step 1: 写 PROTOCOL.md**

内容覆盖：连接方式(UART1 PA8/PA9 @115200 8N1)、上电横幅、每条命令的语法/行为/响应示例、错误响应表、**-6dBm→-5dBm 偏差说明**、功率档表、手动测试清单(频谱仪/功率计/PER，频点 ch0/19/39)。结构对齐设计文档 §4 与 §6.2。结尾注明「非 OTA、仅有线烧录、不可下发现场设备」。

(正文按设计文档 §4 表格逐条展开为「语法 / 行为 / 响应示例」三段式；此处不重复粘贴，实现时从 spec §4/§4.2/§4.3 直接转写。)

- [ ] **Step 2: 提交**

```bash
git add firmware/RFTEST/PROTOCOL.md
git commit -m "docs(rftest): 命令字与响应说明文件 PROTOCOL.md"
```

---

## Task 11: 全量验证与收尾

**Files:**
- 无新增（验证 + 可选复制）

- [ ] **Step 1: 跑全部 host 单测**

Run: `cd firmware/RFTEST/test && make clean && make`
Expected: `ALL TESTS PASSED`

- [ ] **Step 2: 编译 RF 测试固件(干净构建)**

Run: `cd firmware && make -f Makefile.rftest clean && make -f Makefile.rftest 2>&1 | tail -10`
Expected: 生成 `firmware/build_rftest/immurok_CH592F_RFTEST.hex`、size 正常

- [ ] **Step 3: 验证量产构建未受影响**

Run: `cd firmware && make clean >/dev/null 2>&1; make 2>&1 | tail -5`
Expected: 量产 debug 固件正常编译；`grep -rn "ftm_\|RFTEST" build/` 无结果(测试代码不进量产产物)

- [ ] **Step 4:（可选）复制说明文件到认证资料目录**

```bash
cp firmware/RFTEST/PROTOCOL.md certificate/resource/23_rf_test_mode.md
git add certificate/resource/23_rf_test_mode.md
git commit -m "docs(cert): RF 测试模式说明纳入认证资料"
```

- [ ] **Step 5: 上板手动测试(需硬件 + 串口工具,非阻塞 CI)**

按 `PROTOCOL.md` 手动测试清单逐条验证：`ver`/`id`/`help` 回显正常；`txcw 0`/`19`/`39` 频谱仪见 CW；`tx 0 0`/`tx 0 3` 功率计读数随档变化；`tx_phy 1` 后 2M 调制；`rx` + 信号源看 `rxstats` 计数。记录结果。

---

## 自检对照(spec 覆盖)

- 独立固件 target、量产零测试代码 → Task 6 + Task 11 Step 3 ✓
- 指纹传感器断电 SENSOR_EN=0(PB12) → Task 8 `board_gpio_init` ✓
- 指纹 UART1(PA8/PA9)作命令口 @115200 8N1 → Task 8 `uart1_cmdport_init` ✓
- 截图命令 tx/txcw/tx_payload/tx_phy/rx/stop/reset → Task 9 ✓
- 新增 help/ver/id/freq/txpower/vbat/echo → Task 9 ✓
- 响应 OK/ERR + 开机 `[FTM] ready` → Task 8 + Task 9 ✓
- -6dBm→-5dBm 映射并注明 → Task 3 + Task 10 ✓
- 命令说明文件 → Task 10 ✓
- 纯逻辑单测(解析/PRBS/功率/频率) → Task 2-5 ✓
```
