/* 参照实现：不带 uECC_POINT_MULT 钩子的 micro-ecc，公开符号加 ref_ 前缀。只给 test_ecc_fast 用。 */
#define uECC_secp256r1             ref_secp256r1
#define uECC_secp256k1             ref_secp256k1
#define uECC_set_rng               ref_set_rng
#define uECC_get_rng               ref_get_rng
#define uECC_set_watchdog_cb       ref_set_watchdog_cb
#define uECC_curve_private_key_size ref_curve_private_key_size
#define uECC_curve_public_key_size ref_curve_public_key_size
#define uECC_make_key              ref_make_key
#define uECC_shared_secret         ref_shared_secret
#define uECC_compute_public_key    ref_compute_public_key
#define uECC_valid_public_key      ref_valid_public_key
#define uECC_sign                  ref_sign
#define uECC_sign_with_k           ref_sign_with_k
#define uECC_sign_deterministic    ref_sign_deterministic
#define uECC_verify                ref_verify
#define uECC_compress              ref_compress
#define uECC_decompress            ref_decompress
#include "../LIB/uECC.c"
