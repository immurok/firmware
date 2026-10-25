// immurok IK-1 RF test firmware -- RF control state machine and command dispatch
//
// API verification notes (confirmed against SDK headers):
//   - R8_UART1_LSR, RB_LSR_TX_FIFO_EMP, R8_UART1_RFC: CH592SFR.h confirmed
//   - LL_TX_PWR_xDBM: CH59xBLE_LIB.h lines 191-202, values match FTM_PWR_x exactly
//   - tmos_x, TMOS_ProcessEventRegister, LL_SetTxPowerLevel, RF_x, LL_SingleChannel:
//     CH59xBLE_LIB.h confirmed
//   - SYS_ResetExecute: CH59x_sys.h confirmed
//   - GetMACAddress: provided via CH59x_common.h -> ISP592.h (do not include ISP592.h directly)
//   - do_vbat conversion factor: see APP/hidkbd.c battCalcCB (1/4 divider, Vref=2.1V)
//     raw_mv = adc * (2100 * 4) / 4096; calibrate on real hardware.
#include "CH59x_common.h"
#include "CONFIG.h"
#include "HAL.h"
#include "version.h"
#include "ftm.h"
#include "ftm_parse.h"
#include <stdio.h>
#include <string.h>

/* _Static_assert: FTM_PWR_* (ftm_parse.h) must equal SDK LL_TX_PWR_*_DBM.
 * If assertion fails, the SDK header has changed -- sync ftm_parse.h. */
_Static_assert(FTM_PWR_MINUS_20_DBM == LL_TX_PWR_MINUS_20_DBM, "pwr -20dBm mismatch");
_Static_assert(FTM_PWR_MINUS_15_DBM == LL_TX_PWR_MINUS_15_DBM, "pwr -15dBm mismatch");
_Static_assert(FTM_PWR_MINUS_10_DBM == LL_TX_PWR_MINUS_10_DBM, "pwr -10dBm mismatch");
_Static_assert(FTM_PWR_MINUS_8_DBM  == LL_TX_PWR_MINUS_8_DBM,  "pwr -8dBm mismatch");
_Static_assert(FTM_PWR_MINUS_5_DBM  == LL_TX_PWR_MINUS_5_DBM,  "pwr -5dBm mismatch");
_Static_assert(FTM_PWR_MINUS_3_DBM  == LL_TX_PWR_MINUS_3_DBM,  "pwr -3dBm mismatch");
_Static_assert(FTM_PWR_MINUS_1_DBM  == LL_TX_PWR_MINUS_1_DBM,  "pwr -1dBm mismatch");
_Static_assert(FTM_PWR_0_DBM        == LL_TX_PWR_0_DBM,        "pwr 0dBm mismatch");
_Static_assert(FTM_PWR_1_DBM        == LL_TX_PWR_1_DBM,        "pwr +1dBm mismatch");
_Static_assert(FTM_PWR_2_DBM        == LL_TX_PWR_2_DBM,        "pwr +2dBm mismatch");
_Static_assert(FTM_PWR_3_DBM        == LL_TX_PWR_3_DBM,        "pwr +3dBm mismatch");
_Static_assert(FTM_PWR_4_DBM        == LL_TX_PWR_4_DBM,        "pwr +4dBm mismatch");

#define PIN_LED_RED   GPIO_Pin_7    /* PB7  */
#define PIN_LED_BLUE  GPIO_Pin_22   /* PB22 */

typedef enum { ST_IDLE, ST_TX, ST_CW, ST_RX } ftm_state_t;

static tmosTaskID           s_taskID;
static volatile ftm_state_t s_state   = ST_IDLE;
static volatile uint8_t     s_phy     = 0;       /* 0=1M, 1=2M */
static int                  s_echo    = 1;
static volatile uint8_t     s_cur_ch  = 0;
static __attribute__((aligned(4))) uint8_t s_txbuf[FTM_PAYLOAD_LEN];
static volatile uint32_t s_rx_pkt     = 0;
static volatile uint32_t s_rx_crc_err = 0;

#define EVT_TX_RELOAD   (1u << 0)
#define EVT_RX_REARM    (1u << 1)

/* ---- UART1 output ---- */
void ftm_puts(const char *s) {
    /* Wait for TX FIFO empty then send byte by byte.
     * R8_UART1_LSR / RB_LSR_TX_FIFO_EMP: see CH592SFR.h */
    while (*s) {
        while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP));
        UART1_SendByte(*s++);
    }
    while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP));
    UART1_SendByte('\r');
    while (!(R8_UART1_LSR & RB_LSR_TX_FIFO_EMP));
    UART1_SendByte('\n');
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

/* ---- RF configuration ---- */

/* Forward declaration: rfStatusCB defined below */
void ftm_rf_cb(uint8_t sta, uint8_t rsr, uint8_t *rxBuf);

static void rf_apply_config(uint8_t ch, uint32_t freq_khz, int use_freq) {
    rfConfig_t cfg;
    tmos_memset(&cfg, 0, sizeof(cfg));
    cfg.accessAddress = 0x71764129;
    cfg.CRCInit       = 0x555555;
    cfg.Channel       = ch;
    cfg.Frequency     = use_freq ? freq_khz : (uint32_t)(2402000u + ch * 2000u);
    cfg.LLEMode       = LLE_MODE_BASIC
                        | (s_phy ? LLE_MODE_PHY_2M : LLE_MODE_PHY_1M);
    if (use_freq) cfg.LLEMode |= LLE_MODE_EX_CHANNEL;
    cfg.rfStatusCB    = ftm_rf_cb;
    cfg.RxMaxlen      = 251;
    RF_Config(&cfg);
}

static void stop_all(void) {
    RF_Shut();
    tmos_clear_event(s_taskID, EVT_TX_RELOAD | EVT_RX_REARM);
    GPIOB_ResetBits(PIN_LED_RED | PIN_LED_BLUE);
    s_state = ST_IDLE;
}

/* ---- Callback: continuous TX reload + RX packet counting ----
 * rsr: CRC/status byte, see RF_PHY.c RF_2G4StatusCallBack example:
 *   rsr==0 -> OK; rsr & (1<<0) -> CRC error; rsr & (1<<1) -> type mismatch */
void ftm_rf_cb(uint8_t sta, uint8_t rsr, uint8_t *rxBuf) {
    (void)rxBuf;
    switch (sta) {
        case TX_MODE_TX_FINISH:
        case TX_MODE_TX_FAIL:
            if (s_state == ST_TX) tmos_set_event(s_taskID, EVT_TX_RELOAD);
            break;
        case RX_MODE_RX_DATA:
            if (rsr == 0) s_rx_pkt++;
            else          s_rx_crc_err++;
            /* Defer RF_Rx re-arm to TMOS event handler -- never call RF_Rx directly
             * from inside rfStatusCB (matches WCH RF_PHY example pattern). */
            if (s_state == ST_RX) tmos_set_event(s_taskID, EVT_RX_REARM);
            break;
        default:
            break;
    }
}

/* ---- TMOS event: send next packet / re-arm RX ---- */
static tmosEvents ftm_event(tmosTaskID task_id, tmosEvents events) {
    (void)task_id;
    if (events & EVT_TX_RELOAD) {
        if (s_state == ST_TX)
            RF_Tx(s_txbuf, FTM_PAYLOAD_LEN, 0xFF, 0xFF);
        return events ^ EVT_TX_RELOAD;
    }
    if (events & EVT_RX_REARM) {
        if (s_state == ST_RX)
            RF_Rx(s_txbuf, FTM_PAYLOAD_LEN, 0xFF, 0xFF);
        return events ^ EVT_RX_REARM;
    }
    return 0;
}

/* ---- Command handlers ---- */
static void do_tx(int ch, int level) {
    stop_all();
    ftm_fill_payload(FTM_PAT_PRBS9, s_txbuf, FTM_PAYLOAD_LEN);
    LL_SetTxPowerLevel(ftm_dbm_to_pwr(ftm_level_to_dbm(level)));
    rf_apply_config((uint8_t)ch, 0, 0);
    s_cur_ch = (uint8_t)ch;
    s_state  = ST_TX;
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    char m[64];
    snprintf(m, sizeof(m), "OK tx ch=%d pwr=%ddBm phy=%s payload=PRBS9",
             ch, ftm_pwr_snap_dbm(ftm_level_to_dbm(level)), s_phy ? "2M" : "1M");
    ftm_puts(m);
}

static void do_tx_payload(int ch, int pat) {
    stop_all();
    ftm_fill_payload(pat, s_txbuf, FTM_PAYLOAD_LEN);
    /* Uses the currently-set TX power (default 0 dBm from ftm_init,
     * or whatever the last 'tx' / 'txpower' command set). */
    rf_apply_config((uint8_t)ch, 0, 0);
    s_cur_ch = (uint8_t)ch;
    s_state  = ST_TX;
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    static const char *names[] = {
        "PRBS9","0x0F","0x55","PRBS15","all-1","all-0","0xF0","0xAA"
    };
    char m[64];
    snprintf(m, sizeof(m), "OK tx_payload ch=%d pattern=%s", ch, names[pat]);
    ftm_puts(m);
}

static void do_txcw(int ch) {
    stop_all();
    LL_SingleChannel((uint8_t)ch);
    s_cur_ch = (uint8_t)ch;
    s_state  = ST_CW;
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
    s_state  = ST_RX;
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
    s_state  = ST_TX;
    s_cur_ch = 0;   /* freq mode uses exact kHz, not a channel; reset to avoid stale channel in rxstats */
    GPIOB_SetBits(PIN_LED_RED);
    tmos_set_event(s_taskID, EVT_TX_RELOAD);
    char m[48];
    snprintf(m, sizeof(m), "OK freq=%dkHz", khz);
    ftm_puts(m);
}

static void do_txpower(int dbm) {
    LL_SetTxPowerLevel(ftm_dbm_to_pwr(dbm));
    char m[32];
    snprintf(m, sizeof(m), "OK txpower=%ddBm", ftm_pwr_snap_dbm(dbm));
    ftm_puts(m);
}

static void do_ver(void) {
    char m[128];
    snprintf(m, sizeof(m), "immurok IK-1 RFTEST v%s build=0x%X HW=5 phy=%s",
             FW_VERSION_STRING, (unsigned)FW_BUILD_NUMBER, s_phy ? "2M" : "1M");
    ftm_puts(m);
}

static void do_id(void) {
    /* GetMACAddress is a macro in ISP592.h, expands to FLASH_EEPROM_CMD(CMD_GET_ROM_INFO,...).
     * ISP592.h is included transitively via CH59x_common.h -- no direct include needed. */
    uint8_t mac[6] = {0};
    GetMACAddress(mac);
    char m[48];
    snprintf(m, sizeof(m), "id MAC=%02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    ftm_puts(m);
}

static void do_vbat(void) {
    /* PA14 = AIN4 (CH_EXTIN_4), VER=5: 1/4 voltage divider (R2=3M, R3=1M).
     * Conversion follows APP/hidkbd.c battCalcCB:
     *   raw_mv = adc * (2100 * VBAT_DIV_RATIO) / 4096
     *          = adc * (2100 * 4) / 4096
     * Fine correction (+20mV, *1021/1024) requires on-board calibration.
     * TODO: measure on real hardware and cross-check with production voltmeter. */
    GPIOA_ModeCfg(GPIO_Pin_14, GPIO_ModeIN_Floating);
    ADC_ExtSingleChSampInit(SampleFreq_3_2, ADC_PGA_0);
    ADC_ChannelCfg(4);   /* CH_EXTIN_4 = 4 */
    uint16_t adc = ADC_ExcutSingleConver();
    /* Rough conversion: Vref~2.1V, 12-bit ADC, 1/4 divider */
    uint32_t mv = (uint32_t)adc * (2100u * 4u) / 4096u;
    char m[32];
    snprintf(m, sizeof(m), "vbat=%lumV (raw=%u)", (unsigned long)mv, adc);
    ftm_puts(m);
}

static void do_help(int topic_cmd, int has_topic) {
    if (!has_topic) {
        ftm_puts("cmds: tx <ch> <0-3> | txcw <ch> | tx_payload <ch> <0-7>");
        ftm_puts("      tx_phy <0|1> | rx <ch> | stop | reset");
        ftm_puts("      freq <khz> | txpower <dbm> | vbat | ver | id | echo <on|off>");
        ftm_puts("      type 'help <cmd>' for detailed usage");
        return;
    }

    /* has_topic==1 && topic_cmd==FTM_CMD_NONE → unknown topic */
    if (topic_cmd == FTM_CMD_NONE) {
        ftm_puts("ERR no such command (try: help)");
        return;
    }

    /* Detailed usage per command */
    switch ((ftm_cmd_id_t)topic_cmd) {
        case FTM_CMD_TX:
            ftm_puts("tx <ch> <level>  ch=0-39  level=0-3");
            ftm_puts("  level: 0=0dBm  1=-3dBm  2=-5dBm(req -6)  3=+3dBm");
            ftm_puts("  PRBS9 payload, loops until stop.  e.g. tx 19 0");
            break;
        case FTM_CMD_TXCW:
            ftm_puts("txcw <ch>  ch=0-39  unmodulated CW carrier");
            ftm_puts("  freq=2402+ch*2 MHz, current txpower setting applies");
            ftm_puts("  loops until stop.  e.g. txcw 19");
            break;
        case FTM_CMD_TX_PAYLOAD:
            ftm_puts("tx_payload <ch> <pattern>  ch=0-39  pattern=0-7");
            ftm_puts("  0=PRBS9 1=0x0F 2=0x55 3=PRBS15 4=all-1 5=all-0 6=0xF0 7=0xAA");
            ftm_puts("  e.g. tx_payload 0 2");
            break;
        case FTM_CMD_TX_PHY:
            ftm_puts("tx_phy <0|1>  0=LE 1M PHY  1=LE 2M PHY");
            ftm_puts("  affects tx / tx_payload / rx; txcw is unaffected");
            ftm_puts("  e.g. tx_phy 1  -> OK phy=2M");
            break;
        case FTM_CMD_RX:
            ftm_puts("rx <ch>  ch=0-39  start receive, clears pkt/crc_err counters");
            ftm_puts("  send stop to end; rxstats printed automatically after stop");
            ftm_puts("  e.g. rx 0  -> OK rx ch=0 listening");
            break;
        case FTM_CMD_STOP:
            ftm_puts("stop  halt TX or RX, turn off LEDs");
            ftm_puts("  if in RX mode also prints: rxstats ch=N pkt=N crc_err=N");
            ftm_puts("  e.g. stop  -> OK stop");
            break;
        case FTM_CMD_RESET:
            ftm_puts("reset  software reset (SYS_ResetExecute)");
            ftm_puts("  device reboots and prints the power-on banner again");
            ftm_puts("  e.g. reset  -> OK reset  (then banner)");
            break;
        case FTM_CMD_HELP:
            ftm_puts("help           print command list");
            ftm_puts("help <cmd>     print detailed usage for one command");
            ftm_puts("  e.g. help tx  /  help rx  /  help txpower");
            break;
        case FTM_CMD_VER:
            ftm_puts("ver  print firmware version, build number, current PHY");
            ftm_puts("  format: immurok IK-1 RFTEST v<ver> build=0x<hex> HW=5 phy=<1M|2M>");
            ftm_puts("  e.g. ver");
            break;
        case FTM_CMD_ID:
            ftm_puts("id  print chip MAC address (network byte order, MSB first)");
            ftm_puts("  format: id MAC=AA:BB:CC:DD:EE:FF");
            ftm_puts("  e.g. id");
            break;
        case FTM_CMD_FREQ:
            ftm_puts("freq <khz>  khz=2400000-2483500  exact-frequency TX (PRBS9)");
            ftm_puts("  uses LLE_MODE_EX_CHANNEL; loops until stop");
            ftm_puts("  e.g. freq 2441000  -> OK freq=2441000kHz");
            break;
        case FTM_CMD_TXPOWER:
            ftm_puts("txpower <dbm>  set TX power, clamped to [-20,+4] dBm");
            ftm_puts("  snaps to nearest HW step; -6->-5, -9->-10, etc.");
            ftm_puts("  e.g. txpower -8  -> OK txpower=-8dBm");
            break;
        case FTM_CMD_VBAT:
            ftm_puts("vbat  read battery voltage via PA14 AIN4 (1/4 divider)");
            ftm_puts("  format: vbat=NNNNmV (raw=NNNN)  (rough; calibrate on HW)");
            ftm_puts("  e.g. vbat  -> vbat=4153mV (raw=2013)");
            break;
        case FTM_CMD_ECHO:
            ftm_puts("echo <on|off>  toggle command echo (default: on)");
            ftm_puts("  on: each received line is echoed before the response");
            ftm_puts("  e.g. echo off  -> OK echo=off");
            break;
        default:
            ftm_puts("ERR no such command (try: help)");
            break;
    }
}

void ftm_init(void) {
    s_taskID = TMOS_ProcessEventRegister(ftm_event);
    s_state  = ST_IDLE;
    s_phy    = 0;
    s_echo   = 1;
    /* Establish a defined default TX power (0 dBm) so tx_payload is valid
     * even if 'tx' or 'txpower' has not been called first. */
    LL_SetTxPowerLevel(ftm_dbm_to_pwr(0));
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
        case FTM_CMD_TX_PHY:
            s_phy = (uint8_t)p.arg1;
            ftm_puts(s_phy ? "OK phy=2M" : "OK phy=1M");
            break;
        case FTM_CMD_RX:         do_rx(p.arg1); break;
        case FTM_CMD_STOP:       do_stop(); break;
        case FTM_CMD_RESET:
            ftm_puts("OK reset");
            SYS_ResetExecute();
            break;
        case FTM_CMD_HELP:       do_help(p.arg1, p.arg2); break;
        case FTM_CMD_VER:        do_ver(); break;
        case FTM_CMD_ID:         do_id(); break;
        case FTM_CMD_FREQ:       do_freq(p.arg1); break;
        case FTM_CMD_TXPOWER:    do_txpower(p.arg1); break;
        case FTM_CMD_VBAT:       do_vbat(); break;
        case FTM_CMD_ECHO:
            s_echo = p.arg1;
            ftm_puts(s_echo ? "OK echo=on" : "OK echo=off");
            break;
        default:
            reply_err(FTM_ERR_UNKNOWN_CMD);
            break;
    }
}
