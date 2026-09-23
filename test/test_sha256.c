/*
 * SHA-256 / HMAC-SHA256 已知答案测试（FIPS 180-4 / RFC 4231）。
 * 2026-09-19 加：把 hmac_sha256 的静态上下文改成共享导出前先锁住行为。
 */
#include "sha256.h"
#include "test_main.h"
#include <string.h>

static int hex_eq(const uint8_t *d, const char *hex)
{
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(hex + 2 * i, "%2x", &v);
        if (d[i] != (uint8_t)v) return 0;
    }
    return 1;
}

static void test_sha256_vectors(void)
{
    uint8_t d[32];
    sha256((const uint8_t *)"", 0, d);
    CHECK(hex_eq(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256(\"\")");
    sha256((const uint8_t *)"abc", 3, d);
    CHECK(hex_eq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256(\"abc\")");
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t *)m, strlen(m), d);
    CHECK(hex_eq(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), "sha256(448-bit)");
}

static void test_sha256_incremental_matches_oneshot(void)
{
    uint8_t a[32], b[32];
    uint8_t msg[200];
    for (int i = 0; i < 200; i++) msg[i] = (uint8_t)(i * 7);
    sha256(msg, 200, a);
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, 1);
    sha256_update(&ctx, msg + 1, 63);
    sha256_update(&ctx, msg + 64, 100);
    sha256_update(&ctx, msg + 164, 36);
    sha256_final(&ctx, b);
    CHECK(memcmp(a, b, 32) == 0, "incremental == one-shot");
}

static void test_hmac_rfc4231(void)
{
    uint8_t out[32];
    uint8_t k1[20]; memset(k1, 0x0b, 20);
    hmac_sha256(k1, 20, (const uint8_t *)"Hi There", 8, out);
    CHECK(hex_eq(out, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), "RFC 4231 case 1");
    const char *k2 = "Jefe", *m2 = "what do ya want for nothing?";
    hmac_sha256((const uint8_t *)k2, 4, (const uint8_t *)m2, strlen(m2), out);
    CHECK(hex_eq(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "RFC 4231 case 2");
    /* 32B key，本项目实际用法（HKDF PRK / shared_key） */
    uint8_t k3[32]; for (int i = 0; i < 32; i++) k3[i] = (uint8_t)i;
    hmac_sha256(k3, 32, (const uint8_t *)"\x21\x00\x00", 3, out);
    uint8_t again[32];
    hmac_sha256(k3, 32, (const uint8_t *)"\x21\x00\x00", 3, again);
    CHECK(memcmp(out, again, 32) == 0, "hmac is repeatable (static scratch not leaking state)");
}

int main(void)
{
    RUN(test_sha256_vectors);
    RUN(test_sha256_incremental_matches_oneshot);
    RUN(test_hmac_rfc4231);
    TEST_MAIN_END;
}
