/*
 * AES-128 Implementation (ECB + CTR mode)
 * Compact implementation for embedded use
 */

#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

#define AES128_KEY_SIZE   16
#define AES128_BLOCK_SIZE 16

typedef struct {
    uint8_t round_key[176];  /* 11 round keys * 16 bytes */
} aes128_ctx_t;

/**
 * Initialize AES-128 context with key
 */
void aes128_init(aes128_ctx_t *ctx, const uint8_t *key);

/**
 * Encrypt a single 16-byte block (ECB mode)
 */
void aes128_encrypt_block(const aes128_ctx_t *ctx,
                          const uint8_t *in, uint8_t *out);

/**
 * AES-128-CTR encrypt/decrypt (same operation)
 * @param ctx      Initialized AES context
 * @param iv       16-byte IV/nonce (not modified)
 * @param offset   Byte offset in stream (must be block-aligned for partial blocks)
 * @param buf      Data buffer (encrypted/decrypted in-place)
 * @param len      Data length
 */
void aes128_ctr_xcrypt(const aes128_ctx_t *ctx,
                       const uint8_t *iv,
                       uint32_t offset,
                       uint8_t *buf, size_t len);

#endif /* AES128_H */
