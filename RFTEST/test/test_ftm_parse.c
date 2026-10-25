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
    /* -9dBm 与 -10/-8 等距,平局解析到下标更小的 -10(保守功率),最近邻先到先得 */
    CHECK(ftm_dbm_to_pwr(-9) == FTM_PWR_MINUS_10_DBM);
    /* 钳位 */
    CHECK(ftm_dbm_to_pwr(100) == FTM_PWR_4_DBM);
    CHECK(ftm_dbm_to_pwr(-100)== FTM_PWR_MINUS_20_DBM);

    /* ftm_pwr_snap_dbm:返回实际映射到的硬件 dBm */
    CHECK(ftm_pwr_snap_dbm(-6)   == -5);    /* 无 -6 档,snap 到 -5 */
    CHECK(ftm_pwr_snap_dbm(0)    == 0);
    CHECK(ftm_pwr_snap_dbm(3)    == 3);
    CHECK(ftm_pwr_snap_dbm(100)  == 4);     /* 钳位上限 */
    CHECK(ftm_pwr_snap_dbm(-100) == -20);   /* 钳位下限 */
    CHECK(ftm_pwr_snap_dbm(-9)   == -10);   /* 平局 → 较低功率,与 ftm_dbm_to_pwr 一致 */
}

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
    CHECK(P("tx 0x1 0").err == FTM_ERR_BAD_ARGS); /* 十六进制参数被 strtol 拒绝(junk 检测) */
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

static void test_help(void) {
    ftm_parsed_t p;

    /* bare help: cmd=HELP, arg1=NONE(0), arg2=0 */
    p = P("help");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_NONE && p.arg2==0);

    /* help <known cmd>: arg1=that cmd id, arg2=1 */
    p = P("help tx");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_TX && p.arg2==1);

    p = P("help txpower");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_TXPOWER && p.arg2==1);

    p = P("help txcw");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_TXCW && p.arg2==1);

    p = P("help tx_payload");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_TX_PAYLOAD && p.arg2==1);

    p = P("help tx_phy");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_TX_PHY && p.arg2==1);

    p = P("help rx");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_RX && p.arg2==1);

    p = P("help stop");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_STOP && p.arg2==1);

    p = P("help reset");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_RESET && p.arg2==1);

    p = P("help help");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_HELP && p.arg2==1);

    p = P("help ver");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_VER && p.arg2==1);

    p = P("help id");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_ID && p.arg2==1);

    p = P("help freq");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_FREQ && p.arg2==1);

    p = P("help vbat");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_VBAT && p.arg2==1);

    p = P("help echo");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_ECHO && p.arg2==1);

    /* help <unknown>: arg1=NONE, arg2=1 (topic given but not found) */
    p = P("help foo");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_NONE && p.arg2==1);

    p = P("help bogus_cmd");
    CHECK(p.err==FTM_OK && p.cmd==FTM_CMD_HELP && p.arg1==FTM_CMD_NONE && p.arg2==1);

    /* ftm_cmd_from_name direct tests */
    CHECK(ftm_cmd_from_name("tx")         == FTM_CMD_TX);
    CHECK(ftm_cmd_from_name("txcw")       == FTM_CMD_TXCW);
    CHECK(ftm_cmd_from_name("tx_payload") == FTM_CMD_TX_PAYLOAD);
    CHECK(ftm_cmd_from_name("tx_phy")     == FTM_CMD_TX_PHY);
    CHECK(ftm_cmd_from_name("rx")         == FTM_CMD_RX);
    CHECK(ftm_cmd_from_name("stop")       == FTM_CMD_STOP);
    CHECK(ftm_cmd_from_name("reset")      == FTM_CMD_RESET);
    CHECK(ftm_cmd_from_name("help")       == FTM_CMD_HELP);
    CHECK(ftm_cmd_from_name("ver")        == FTM_CMD_VER);
    CHECK(ftm_cmd_from_name("id")         == FTM_CMD_ID);
    CHECK(ftm_cmd_from_name("freq")       == FTM_CMD_FREQ);
    CHECK(ftm_cmd_from_name("txpower")    == FTM_CMD_TXPOWER);
    CHECK(ftm_cmd_from_name("vbat")       == FTM_CMD_VBAT);
    CHECK(ftm_cmd_from_name("echo")       == FTM_CMD_ECHO);
    CHECK(ftm_cmd_from_name("nope")       == FTM_CMD_NONE);
    CHECK(ftm_cmd_from_name("")           == FTM_CMD_NONE);
}

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

int main(void) {
    test_ch_to_freq();
    test_power();
    test_payload();
    test_parse();
    test_help();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
