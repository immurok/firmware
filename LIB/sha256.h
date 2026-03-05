/*
 * SHA-256 Implementation
 * Public domain implementation
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

/**
 * Initialize SHA-256 context
 */
void sha256_init(sha256_ctx_t *ctx);

/**
 * Update SHA-256 with data
 */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * Finalize SHA-256 and get digest
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t *digest);

/**
 * One-shot SHA-256
 */
void sha256(const uint8_t *data, size_t len, uint8_t *digest);

#endif // SHA256_H
