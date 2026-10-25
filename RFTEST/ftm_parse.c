#include "ftm_parse.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int ftm_ch_to_freq_mhz(int ch) { return 2402 + ch * 2; }

int ftm_level_to_dbm(int level) {
    switch (level) {
        case 0: return 0;
        case 1: return -3;
        case 2: return -6;
        case 3: return 3;
        default: return 0;
    }
}

/* 功率表:dBm 值与对应的 CH59x 硬件功率码 */
static const struct { int dbm; uint8_t code; } s_pwr_tbl[] = {
    { -20, FTM_PWR_MINUS_20_DBM }, { -15, FTM_PWR_MINUS_15_DBM },
    { -10, FTM_PWR_MINUS_10_DBM }, { -8,  FTM_PWR_MINUS_8_DBM  },
    { -5,  FTM_PWR_MINUS_5_DBM  }, { -3,  FTM_PWR_MINUS_3_DBM  },
    { -1,  FTM_PWR_MINUS_1_DBM  }, { 0,   FTM_PWR_0_DBM        },
    { 1,   FTM_PWR_1_DBM        }, { 2,   FTM_PWR_2_DBM        },
    { 3,   FTM_PWR_3_DBM        }, { 4,   FTM_PWR_4_DBM        },
};
#define PWR_TBL_N ((int)(sizeof(s_pwr_tbl) / sizeof(s_pwr_tbl[0])))

/* 共用查找逻辑:钳位后最近邻搜索,返回表下标 */
static int pwr_best_idx(int dbm) {
    /* 先钳位到表范围,避免 d = dbm - tbl[i].dbm 在超范围值时发生有符号溢出 UB */
    if (dbm < s_pwr_tbl[0].dbm)         dbm = s_pwr_tbl[0].dbm;        /* -20 */
    if (dbm > s_pwr_tbl[PWR_TBL_N-1].dbm) dbm = s_pwr_tbl[PWR_TBL_N-1].dbm; /* +4  */
    int best = 0, bestdiff = 1000000;
    for (int i = 0; i < PWR_TBL_N; i++) {
        int d = dbm - s_pwr_tbl[i].dbm;
        if (d < 0) d = -d;
        if (d < bestdiff) { bestdiff = d; best = i; }
    }
    return best;
}

uint8_t ftm_dbm_to_pwr(int dbm) {
    return s_pwr_tbl[pwr_best_idx(dbm)].code;
}

int ftm_pwr_snap_dbm(int dbm) {
    return s_pwr_tbl[pwr_best_idx(dbm)].dbm;
}

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
            /* 15 位 LSB-first Fibonacci LFSR,x^15+x^14+1;LSB=oldest → tap bit0^bit1 */
            fill_prbs(buf, len, 0x7FFF, 0, 1, 15); break;
        case FTM_PAT_PRBS9:
        default:
            /* 9 位,x^9+x^5+1 → taps bit0 与 bit4 */
            fill_prbs(buf, len, 0x01FF, 0, 4, 9); break;
    }
}

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
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || errno == ERANGE) return 0;
    *out = (int)v;
    return 1;
}

ftm_cmd_id_t ftm_cmd_from_name(const char *name) {
    if (!strcmp(name, "tx"))          return FTM_CMD_TX;
    if (!strcmp(name, "txcw"))        return FTM_CMD_TXCW;
    if (!strcmp(name, "tx_payload"))  return FTM_CMD_TX_PAYLOAD;
    if (!strcmp(name, "tx_phy"))      return FTM_CMD_TX_PHY;
    if (!strcmp(name, "rx"))          return FTM_CMD_RX;
    if (!strcmp(name, "stop"))        return FTM_CMD_STOP;
    if (!strcmp(name, "reset"))       return FTM_CMD_RESET;
    if (!strcmp(name, "help"))        return FTM_CMD_HELP;
    if (!strcmp(name, "ver"))         return FTM_CMD_VER;
    if (!strcmp(name, "id"))          return FTM_CMD_ID;
    if (!strcmp(name, "freq"))        return FTM_CMD_FREQ;
    if (!strcmp(name, "txpower"))     return FTM_CMD_TXPOWER;
    if (!strcmp(name, "vbat"))        return FTM_CMD_VBAT;
    if (!strcmp(name, "echo"))        return FTM_CMD_ECHO;
    return FTM_CMD_NONE;
}

ftm_err_t ftm_parse_line(const char *line, ftm_parsed_t *out) {
    char tok[16]; /* 超过 15 字符的 token 被截断:过长命令名会落入 unknown cmd,安全且有意为之 */
    const char *p = line;
    out->cmd = FTM_CMD_NONE; out->arg1 = 0; out->arg2 = 0; out->err = FTM_OK;

    if (!next_tok(&p, tok, sizeof(tok))) { out->err = FTM_ERR_UNKNOWN_CMD; return out->err; }

    /* 无参命令 */
    if      (!strcmp(tok, "stop"))  { out->cmd = FTM_CMD_STOP;  return FTM_OK; }
    else if (!strcmp(tok, "reset")) { out->cmd = FTM_CMD_RESET; return FTM_OK; }
    else if (!strcmp(tok, "help"))  {
        out->cmd = FTM_CMD_HELP;
        /* Optional second token: help <cmd> */
        if (next_tok(&p, tok, sizeof(tok))) {
            out->arg2 = 1;                          /* has_topic */
            out->arg1 = ftm_cmd_from_name(tok);     /* FTM_CMD_NONE if unknown */
        }
        /* else: arg1=0 (NONE), arg2=0 (no topic) — already set above */
        return FTM_OK;
    }
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
