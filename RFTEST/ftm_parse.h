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

/* 命令名 → 命令 ID。找不到返回 FTM_CMD_NONE。 */
ftm_cmd_id_t ftm_cmd_from_name(const char *name);

/* 把 pattern 对应的载荷填入 buf(len 字节)。PRBS9/PRBS15 用标准 BLE LFSR。 */
void ftm_fill_payload(int pattern, uint8_t *buf, int len);

/* dBm → CH59x 功率码(FTM_PWR_*);超范围钳到 [-20,4],无精确档取最近。 */
uint8_t ftm_dbm_to_pwr(int dbm);

/* 返回最接近的硬件功率档对应的实际 dBm(与 ftm_dbm_to_pwr 同样的最近邻+钳位逻辑) */
int ftm_pwr_snap_dbm(int dbm);

/* tx 功率档(0-3)→ dBm:0=0,1=-3,2=-6,3=+3。非法档返回 0。 */
int ftm_level_to_dbm(int level);

/* 信道(0-39)→ 中心频率 MHz:f=2402+ch*2。 */
int ftm_ch_to_freq_mhz(int ch);

#endif /* FTM_PARSE_H */
