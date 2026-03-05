/*
 * OTA Protocol Definitions for immurok CH592F
 * Based on WCH BackupUpgrade_OTA example
 */

#ifndef __OTA_H
#define __OTA_H

#include "CH59x_common.h"
#include <stdint.h>
#include "../../LIB/aes128.h"
#include "../../LIB/sha256.h"

/* ============================================================================
 * Flash Layout V1 - WCH 方式一 (448KB total)
 * ============================================================================
 *
 * +------------------+ 0x00000000
 * |   JumpIAP        | 4KB  - Single jump instruction to IAP
 * +------------------+ 0x00001000
 * |   Image A (APP)  | 216KB - Current running application
 * +------------------+ 0x00037000
 * |   Image B (OTA)  | 216KB - OTA upgrade target
 * +------------------+ 0x0006D000
 * |   IAP Bootloader | 12KB - Reads flag, copies B→A, jumps to App
 * +------------------+ 0x00070000
 *
 * DataFlash (separate 32KB):
 *   0x0000: Security/pairing data
 *   OTA_DATAFLASH_ADD: OTA ImageFlag
 */

/* Flash block size */
#define FLASH_BLOCK_SIZE       EEPROM_BLOCK_SIZE  /* 4KB */
#define IMAGE_SIZE             (216 * 1024)       /* 216KB per image */

/* Image A (current application) */
#define IMAGE_A_FLAG           0x01
#define IMAGE_A_START_ADD      (4 * 1024)         /* 0x00001000 */
#define IMAGE_A_SIZE           IMAGE_SIZE

/* Image B (OTA target) */
#define IMAGE_B_FLAG           0x02
#define IMAGE_B_START_ADD      (IMAGE_A_START_ADD + IMAGE_SIZE)  /* 0x00037000 */
#define IMAGE_B_SIZE           IMAGE_SIZE

/* Image IAP (bootloader at end of Flash) */
#define IMAGE_IAP_FLAG         0x03
#define IMAGE_IAP_START_ADD    (IMAGE_B_START_ADD + IMAGE_SIZE)  /* 0x0006D000 */
#define IMAGE_IAP_SIZE         (12 * 1024)

/* OTA DataFlash address (for ImageFlag storage) */
/* WCH standard formula: separate from security pairing data at address 0 */
#define OTA_DATAFLASH_ADD      (0x00076000 - FLASH_ROM_MAX_SIZE)

/* OTA IAP Command Codes */
#define CMD_IAP_PROM           0x80    /* Program flash data */
#define CMD_IAP_ERASE          0x81    /* Erase flash blocks */
#define CMD_IAP_VERIFY         0x82    /* Verify flash data */
#define CMD_IAP_END            0x83    /* End upgrade, reboot */
#define CMD_IAP_INFO           0x84    /* Get device info */
#define CMD_IAP_HEADER         0x85    /* Send .imfw header (96 bytes) */

/* Maximum data frame length (MTU - 3) */
#define IAP_LEN                247

/* OTA security error codes (returned in END response) */
#define OTA_ERR_SHA256_MISMATCH  0xF1  /* Firmware SHA256 mismatch */
#define OTA_ERR_HMAC_MISMATCH    0xF2  /* Header HMAC signature invalid */

/* OTA DataFlash structure */
typedef struct {
    unsigned char ImageFlag;   /* Current image flag */
    unsigned char Revd[3];     /* Reserved for alignment */
} OTADataFlashInfo_t;

/* OTA IAP Command Union (for parsing received data) */
typedef union {
    /* Erase command: cmd + len + addr[2] + block_num[2] */
    struct {
        unsigned char cmd;
        unsigned char len;
        unsigned char addr[2];      /* Start address (16-byte aligned) */
        unsigned char block_num[2]; /* Number of blocks to erase */
    } erase;

    /* End command: cmd + len + status[2] */
    struct {
        unsigned char cmd;
        unsigned char len;
        unsigned char status[2];
    } end;

    /* Verify command: cmd + len + addr[2] + buf[] */
    struct {
        unsigned char cmd;
        unsigned char len;
        unsigned char addr[2];          /* Verify address */
        unsigned char buf[IAP_LEN - 4]; /* Expected data */
    } verify;

    /* Program command: cmd + len + addr[2] + buf[] */
    struct {
        unsigned char cmd;
        unsigned char len;
        unsigned char addr[2];          /* Write address */
        unsigned char buf[IAP_LEN - 4]; /* Data to write */
    } program;

    /* Info command: cmd + len + buf[] */
    struct {
        unsigned char cmd;
        unsigned char len;
        unsigned char buf[IAP_LEN - 2];
    } info;

    /* Raw buffer */
    struct {
        unsigned char buf[IAP_LEN];
    } other;
} OTA_IAP_CMD_t;

/* ============================================================================
 * .imfw Secure Firmware Format
 * ============================================================================ */

#define IMFW_MAGIC          0x494D4657  /* "IMFW" */
#define IMFW_VERSION        0x01
#define IMFW_HARDWARE_ID    0x0592
#define IMFW_HEADER_SIZE    96

/* .imfw file header (96 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* 0x00: "IMFW" (0x494D4657) */
    uint8_t  version;         /* 0x04: Format version (0x01) */
    uint8_t  flags;           /* 0x05: Reserved */
    uint16_t hw_id;           /* 0x06: Hardware ID (0x0592) */
    uint32_t fw_size;         /* 0x08: Firmware size (plaintext) */
    uint32_t reserved;        /* 0x0C: Reserved */
    uint8_t  iv[16];          /* 0x10: AES-128-CTR IV */
    uint8_t  fw_sha256[32];   /* 0x20: SHA256 of plaintext firmware */
    uint8_t  hmac[32];        /* 0x40: HMAC-SHA256(signing_key, header[0:0x40]) */
} imfw_header_t;

/* OTA secure context (active during encrypted OTA) */
typedef struct {
    uint8_t      active;       /* 1 if secure OTA in progress */
    imfw_header_t header;      /* Received .imfw header */
    aes128_ctx_t  aes_ctx;     /* AES-128 context */
    sha256_ctx_t  sha256_ctx;  /* SHA256 running hash */
    uint32_t      bytes_written; /* Total bytes written so far */
} ota_secure_ctx_t;

/* Current image flag (exported for IAP bootloader) */
extern unsigned char CurrImageFlag;

#endif /* __OTA_H */
