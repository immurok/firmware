/*
 * TOTP 核心的已知答案测试（RFC 6238 附录 B，SHA-1）+ SHA-1 外置 W 的正确性。
 *
 * 2026-09-20 M12 修复：sha1_transform 的 W[80] 和 TOTP/HMAC 缓冲移到 work_buf，
 * 把 1024B 栈拉回 512 内。这里锁定「搬缓冲不改功能」：
 *   A1 RFC 6238 SHA-1 六个标准向量（secret = ASCII "12345678901234567890"）
 *   A2 sha1() 本身在外置 W 下仍算对（含多块消息，触发多次 transform）
 */
#include "totp_core.h"
#include "sha1.h"
#include "test_main.h"
#include <string.h>
#include <stdint.h>

/* totp_core.c 借 work_buf 的 OTP 分区；主机侧提供这块内存。 */
uint8_t immurok_keystore_work_buf[4096] __attribute__((aligned(4)));

static int sha1_hex_eq(const uint8_t *d, const char *hex)
{
    for (int i = 0; i < 20; i++) {
        unsigned v; sscanf(hex + 2 * i, "%2x", &v);
        if (d[i] != (uint8_t)v) return 0;
    }
    return 1;
}

/* A2：SHA-1 外置 W。测试前必须先 sha1_set_w 指向一块 W[80]。 */
static uint32_t g_test_w[80];

static void test_sha1_vectors(void)
{
    sha1_set_w(g_test_w);
    uint8_t d[20];
    sha1((const uint8_t *)"abc", 3, d);
    CHECK(sha1_hex_eq(d, "a9993e364706816aba3e25717850c26c9cd0d89d"), "sha1(\"abc\")");
    sha1((const uint8_t *)"", 0, d);
    CHECK(sha1_hex_eq(d, "da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1(\"\")");
    /* 56 字节：final 的补位会再触发一次 transform，覆盖多块路径 */
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha1((const uint8_t *)m, strlen(m), d);
    CHECK(sha1_hex_eq(d, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"), "sha1(56-byte, multi-block)");
}

/* A1：RFC 6238 附录 B，SHA-1，T0=0, X=30, secret = 20 字节 ASCII */
static void check_totp(uint32_t t, const char *expect6)
{
    static const uint8_t secret[20] = {
        '1','2','3','4','5','6','7','8','9','0',
        '1','2','3','4','5','6','7','8','9','0' };
    uint8_t out[6];
    int rc = totp_compute(secret, sizeof secret, t, out);
    char got[7]; memcpy(got, out, 6); got[6] = 0;
    char msg[64];
    snprintf(msg, sizeof msg, "RFC6238 T=%u -> %s (got %s)", t, expect6, got);
    CHECK(rc == 0 && memcmp(out, expect6, 6) == 0, msg);
}

static void test_rfc6238_vectors(void)
{
    check_totp(59u,          "287082");   /* full HOTP 94287082, 6 位取低 6 */
    check_totp(1111111109u,  "081804");
    check_totp(1111111111u,  "050471");
    check_totp(1234567890u,  "005924");
    check_totp(2000000000u,  "279037");
    /* 20000000000 超 uint32，固件接口是 uint32_t unix_time，不测该向量 */
}

static void test_secret_trailing_zero_trim(void)
{
    /* 固件把尾部 0 视为 padding 裁掉：短 secret 补 0 到 32 后应与不补一致 */
    uint8_t s1[3] = { 0xAA, 0xBB, 0xCC };
    uint8_t s2[8] = { 0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0 };
    uint8_t o1[6], o2[6];
    CHECK(totp_compute(s1, 3, 59, o1) == 0, "compute s1");
    CHECK(totp_compute(s2, 8, 59, o2) == 0, "compute s2 (zero-padded)");
    CHECK(memcmp(o1, o2, 6) == 0, "trailing-zero secret trimmed identically");
}

static void test_all_zero_secret_rejected(void)
{
    uint8_t z[8] = {0};
    uint8_t o[6];
    CHECK(totp_compute(z, 8, 59, o) != 0, "all-zero secret -> error");
}

int main(void)
{
    RUN(test_sha1_vectors);
    RUN(test_rfc6238_vectors);
    RUN(test_secret_trailing_zero_trim);
    RUN(test_all_zero_secret_rejected);
    TEST_MAIN_END;
}
