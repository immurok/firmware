/*
 * TOTP (RFC 6238, HMAC-SHA1) 纯计算核心。
 *
 * 2026-09-20 M12：从 immurok_keystore.c 抽出，工作缓冲（sha1 的 W[80]、hmac 的
 * sha1_ctx/k_pad/tk、hmac 结果）全放 work_buf 的 OTP 分区，不在栈上，把原来
 * 1024B 的栈拉回 512 内。不依赖 SDK，主机可测真代码（test/test_totp.c）。
 *
 * 独占前提：只在 totp_compute 期间借 work_buf OTP 分区；TOTP 是纯计算不 yield，
 * sha1 全仓库只服务 TOTP，调用方（immurok_keystore_totp）在前后 mark_busy。
 */
#ifndef TOTP_CORE_H
#define TOTP_CORE_H

#include <stdint.h>
#include <stddef.h>

/* secret：raw 字节（尾部 0 视为 padding 裁掉）。unix_time：秒。out6：6 位 ASCII
 * 数字，非 null 结尾。返回 0 成功，-1（secret 全 0 / 无效）。 */
int totp_compute(const uint8_t *secret, size_t sec_len, uint32_t unix_time, uint8_t out6[6]);

#endif /* TOTP_CORE_H */
