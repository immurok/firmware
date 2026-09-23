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

/*
 * 共享的 SHA-256 工作上下文（104B，BSS）。
 *
 * CH592F 栈只有 512B、BSS 余量 ~100B，装不下每个调用方各一份上下文。
 * hmac_sha256、immurok_rng（DRBG）、immurok_ecdsa（确定性签名的 HMAC 回调）
 * 共用这一份。安全前提：单线程 TMOS，且三者都不会在「init 与 final 之间」
 * 被另一方打断 —— hmac_sha256 是不泵 TMOS 的叶函数；DRBG fill 只在 uECC
 * 内部被调、同样是叶函数；确定性签名的 HMAC 序列与点乘（会泵 TMOS）严格
 * 先后，不交错。任何新调用方必须维持这个前提。
 */
extern sha256_ctx_t sha256_scratch_ctx;

/**
 * HMAC-SHA256。内部用静态缓冲区 + 共享上下文（从 BLE 回调调用，栈仅 512B），
 * 因此不可重入 —— 单线程 TMOS 下没问题。
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

#endif // SHA256_H
