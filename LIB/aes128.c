/*
 * AES-128 Implementation (ECB + CTR mode)
 * Based on Tiny AES - public domain
 */

#include "aes128.h"
#include <string.h>

/* S-Box */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants */
static const uint8_t rcon[11] = {
    0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* xtime: multiply by 2 in GF(2^8) */
#define xtime(x) ((uint8_t)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)))

static void key_expansion(const uint8_t *key, uint8_t *round_key)
{
    uint8_t tempa[4];

    /* First round key is the key itself */
    memcpy(round_key, key, AES128_KEY_SIZE);

    /* All other round keys are derived from previous round keys */
    for (int i = 4; i < 44; i++) {
        int k = (i - 1) * 4;
        tempa[0] = round_key[k + 0];
        tempa[1] = round_key[k + 1];
        tempa[2] = round_key[k + 2];
        tempa[3] = round_key[k + 3];

        if (i % 4 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t u8tmp = tempa[0];
            tempa[0] = sbox[tempa[1]] ^ rcon[i / 4];
            tempa[1] = sbox[tempa[2]];
            tempa[2] = sbox[tempa[3]];
            tempa[3] = sbox[u8tmp];
        }

        int j = i * 4;
        k = (i - 4) * 4;
        round_key[j + 0] = round_key[k + 0] ^ tempa[0];
        round_key[j + 1] = round_key[k + 1] ^ tempa[1];
        round_key[j + 2] = round_key[k + 2] ^ tempa[2];
        round_key[j + 3] = round_key[k + 3] ^ tempa[3];
    }
}

static void add_round_key(uint8_t round, uint8_t state[4][4],
                           const uint8_t *round_key)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= round_key[(round * 16) + (i * 4) + j];
        }
    }
}

static void sub_bytes(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

static void shift_rows(uint8_t state[4][4])
{
    uint8_t temp;

    /* Row 1: shift left 1 — state[*][1] */
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    /* Row 2: shift left 2 — state[*][2] */
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;
    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    /* Row 3: shift left 3 — state[*][3] */
    temp = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = state[0][3];
    state[0][3] = temp;
}

static void mix_columns(uint8_t state[4][4])
{
    uint8_t tmp, tm, t;

    for (int i = 0; i < 4; i++) {
        t   = state[i][0];
        tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
        tm  = state[i][0] ^ state[i][1]; tm = xtime(tm); state[i][0] ^= tm ^ tmp;
        tm  = state[i][1] ^ state[i][2]; tm = xtime(tm); state[i][1] ^= tm ^ tmp;
        tm  = state[i][2] ^ state[i][3]; tm = xtime(tm); state[i][2] ^= tm ^ tmp;
        tm  = state[i][3] ^ t;           tm = xtime(tm); state[i][3] ^= tm ^ tmp;
    }
}

void aes128_init(aes128_ctx_t *ctx, const uint8_t *key)
{
    key_expansion(key, ctx->round_key);
}

void aes128_encrypt_block(const aes128_ctx_t *ctx,
                          const uint8_t *in, uint8_t *out)
{
    uint8_t state[4][4];

    /* Copy input to state array (byte-sequential, matching tiny-AES layout) */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = in[i * 4 + j];
        }
    }

    add_round_key(0, state, ctx->round_key);

    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, ctx->round_key);
    }

    /* Final round (no MixColumns) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(10, state, ctx->round_key);

    /* Copy state to output */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            out[i * 4 + j] = state[i][j];
        }
    }
}

void aes128_ctr_xcrypt(const aes128_ctx_t *ctx,
                       const uint8_t *iv,
                       uint32_t offset,
                       uint8_t *buf, size_t len)
{
    uint8_t counter_block[AES128_BLOCK_SIZE];
    uint8_t keystream[AES128_BLOCK_SIZE];
    uint32_t block_num = offset / AES128_BLOCK_SIZE;
    size_t pos = 0;

    while (pos < len) {
        /* Build counter block: IV[0:12] || counter[4] (big-endian) */
        memcpy(counter_block, iv, 12);
        counter_block[12] = (uint8_t)(block_num >> 24);
        counter_block[13] = (uint8_t)(block_num >> 16);
        counter_block[14] = (uint8_t)(block_num >> 8);
        counter_block[15] = (uint8_t)(block_num);

        /* Encrypt counter block to get keystream */
        aes128_encrypt_block(ctx, counter_block, keystream);

        /* XOR with data */
        size_t block_remaining = AES128_BLOCK_SIZE;
        for (size_t i = 0; i < block_remaining && pos < len; i++, pos++) {
            buf[pos] ^= keystream[i];
        }

        block_num++;
    }
}
