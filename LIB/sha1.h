/*
 * SHA-1 Implementation
 * Public domain implementation based on FIPS 180-1
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[SHA1_BLOCK_SIZE];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, uint8_t *digest);
void sha1(const uint8_t *data, size_t len, uint8_t *digest);

#endif // SHA1_H
