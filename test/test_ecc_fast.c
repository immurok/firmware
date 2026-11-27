/*
 * 固件里的 micro-ecc 由 immurok_ecc_fast.c 包含编译：make_key / shared_secret / sign 的标量乘
 * 经 uECC_POINT_MULT 走跳板，跳板把热点代码拷进 RAM 执行。主机上搬不了 RISC-V 代码，跳板
 * 原地执行，所以这里测的是「经跳板编译出来的这份 uECC」有没有把运算弄错：
 *   - 结果与一份不带钩子的参照实现一致（test_ecc_fast_ref.c，符号前缀 ref_）；
 *   - 它签的名，它自己的 uECC_verify（OTA 验签用的同一个函数）和参照实现都验得过；
 *   - P-256 以外的曲线照常能算（跳板对它们原地执行）。
 */
#include <stdint.h>
#include <string.h>
#include "uECC.h"
#include "immurok_ecc_fast.h"
#include "test_main.h"

/* 参照实现（test_ecc_fast_ref.c） */
uECC_Curve ref_secp256r1(void);
uECC_Curve ref_secp256k1(void);
void ref_set_rng(uECC_RNG_Function f);
int ref_compute_public_key(const uint8_t *priv, uint8_t *pub, uECC_Curve c);
int ref_shared_secret(const uint8_t *pub, const uint8_t *priv, uint8_t *secret, uECC_Curve c);
int ref_verify(const uint8_t *pub, const uint8_t *hash, unsigned hash_size, const uint8_t *sig, uECC_Curve c);

/* 确定性「随机源」。 */
static uint32_t s_rng;
static int test_rng(uint8_t *dest, unsigned size)
{
    for (unsigned i = 0; i < size; i++) {
        s_rng ^= s_rng << 13; s_rng ^= s_rng >> 17; s_rng ^= s_rng << 5;
        dest[i] = (uint8_t)s_rng;
    }
    return 1;
}

int immurok_scratch_is_busy(void) { return 0; }
uint8_t immurok_keystore_work_buf[4096];

static void test_make_key_matches_reference(void)
{
    uint8_t pub[64], priv[32], pub_ref[64];
    s_rng = 0x12345678u;
    CHECK(uECC_make_key(pub, priv, uECC_secp256r1()) == 1, "uECC_make_key");
    CHECK(ref_compute_public_key(priv, pub_ref, ref_secp256r1()) == 1, "参照实现算公钥");
    CHECK(memcmp(pub, pub_ref, 64) == 0, "同一私钥，公钥与参照实现一致");
    CHECK(uECC_valid_public_key(pub, uECC_secp256r1()) == 1, "公钥在曲线上");
}

static void test_shared_secret_agrees(void)
{
    uint8_t pub_a[64], priv_a[32], pub_b[64], priv_b[32];
    uint8_t s_ab[32], s_ba[32], s_ref[32];
    s_rng = 0xCAFEBABEu;
    CHECK(uECC_make_key(pub_a, priv_a, uECC_secp256r1()) == 1, "A");
    CHECK(uECC_make_key(pub_b, priv_b, uECC_secp256r1()) == 1, "B");
    CHECK(uECC_shared_secret(pub_b, priv_a, s_ab, uECC_secp256r1()) == 1, "A 侧");
    CHECK(uECC_shared_secret(pub_a, priv_b, s_ba, uECC_secp256r1()) == 1, "B 侧");
    CHECK(memcmp(s_ab, s_ba, 32) == 0, "两侧共享密钥一致");
    CHECK(ref_shared_secret(pub_b, priv_a, s_ref, ref_secp256r1()) == 1, "参照实现");
    CHECK(memcmp(s_ab, s_ref, 32) == 0, "与参照实现一致");
}

static void test_sign_verifies(void)
{
    uint8_t pub[64], priv[32], sig[64], hash[32];
    s_rng = 0x0BADF00Du;
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t)(i * 7 + 1);
    CHECK(uECC_make_key(pub, priv, uECC_secp256r1()) == 1, "密钥");
    for (int round = 0; round < 4; round++) {
        hash[0] = (uint8_t)round;
        CHECK(uECC_sign(priv, hash, 32, sig, uECC_secp256r1()) == 1, "uECC_sign");
        CHECK(uECC_verify(pub, hash, 32, sig, uECC_secp256r1()) == 1, "uECC_verify 验得过");
        CHECK(ref_verify(pub, hash, 32, sig, ref_secp256r1()) == 1, "参照实现也验得过");
        hash[5] ^= 0x01;
        CHECK(uECC_verify(pub, hash, 32, sig, uECC_secp256r1()) == 0, "改了哈希就验不过");
        hash[5] ^= 0x01;
    }
}

static void test_other_curve_still_works(void)
{
    /* 热点段里只有 P-256 的函数。别的曲线跳板必须原地执行，不能拿 RAM 里那套去算。 */
    uint8_t pub[64], priv[32], pub_ref[64];
    s_rng = 0x13579BDFu;
    CHECK(uECC_make_key(pub, priv, uECC_secp256k1()) == 1, "secp256k1 的 make_key");
    CHECK(ref_compute_public_key(priv, pub_ref, ref_secp256k1()) == 1, "参照实现");
    CHECK(memcmp(pub, pub_ref, 64) == 0, "secp256k1 公钥与参照实现一致");
}

static void test_host_build_reports_unavailable(void)
{
    /* 主机上没有可搬的代码段：必须老实说不可用，调用方据此保留旧的超时门。 */
    CHECK(immurok_ecc_fast_available() == 0, "主机构建不可用");
    CHECK(immurok_ecc_fast_take_fault() == 0, "没有故障标记");
    uint8_t *sc = immurok_ecc_fast_scratch();
    CHECK(sc >= immurok_keystore_work_buf &&
          sc + IMMUROK_ECC_FAST_SCRATCH_LEN <= immurok_keystore_work_buf + 4096, "借用区在 work_buf 内");
    CHECK(((uintptr_t)sc & 3u) == 0, "借用区 4 字节对齐");
}

int main(void)
{
    uECC_set_rng(test_rng);
    ref_set_rng(test_rng);
    RUN(test_make_key_matches_reference);
    RUN(test_shared_secret_agrees);
    RUN(test_sign_verifies);
    RUN(test_other_curve_still_works);
    RUN(test_host_build_reports_unavailable);
    TEST_MAIN_END;
}
