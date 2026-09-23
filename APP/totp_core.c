/* TOTP 核心，见 totp_core.h。缓冲落在 work_buf 的 OTP 分区。 */
#include "totp_core.h"
#include "immurok_scratch.h"
#include "../LIB/sha1.h"
#include <string.h>

typedef struct {
    sha1_ctx_t ctx;                     /* ~92B */
    uint32_t   W[80];                   /* 320B — sha1_transform 的消息调度表 */
    uint8_t    k_pad[SHA1_BLOCK_SIZE];  /* 64B  */
    uint8_t    tk[SHA1_DIGEST_SIZE];    /* 20B  — key>block 时的哈希暂存 */
    uint8_t    hmac[SHA1_DIGEST_SIZE];  /* 20B  — HMAC 结果 */
    uint8_t    msg[8];                  /* time_step 大端，避免栈上 msg[8] */
} otp_work_t;

_Static_assert(sizeof(otp_work_t) <= SCRATCH_OTP_LEN,
               "otp_work_t exceeds SCRATCH_OTP_LEN");

/* HMAC-SHA1，所有中间缓冲在 w（work_buf）。调用前 sha1_set_w(w->W) 已设好。 */
static void hmac_sha1_w(otp_work_t *w, const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len, uint8_t *out)
{
    int i;
    if (key_len > SHA1_BLOCK_SIZE) {
        sha1(key, key_len, w->tk);      /* sha1() 内部同样用 s_sha1_w */
        key = w->tk;
        key_len = SHA1_DIGEST_SIZE;
    }
    memset(w->k_pad, 0x36, SHA1_BLOCK_SIZE);
    for (i = 0; i < (int)key_len; i++) w->k_pad[i] ^= key[i];
    sha1_init(&w->ctx);
    sha1_update(&w->ctx, w->k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&w->ctx, data, data_len);
    sha1_final(&w->ctx, out);

    memset(w->k_pad, 0x5C, SHA1_BLOCK_SIZE);
    for (i = 0; i < (int)key_len; i++) w->k_pad[i] ^= key[i];
    sha1_init(&w->ctx);
    sha1_update(&w->ctx, w->k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&w->ctx, out, SHA1_DIGEST_SIZE);
    sha1_final(&w->ctx, out);
}

int totp_compute(const uint8_t *secret, size_t sec_len, uint32_t unix_time, uint8_t out6[6])
{
    otp_work_t *w = (otp_work_t *)SCRATCH_AT(SCRATCH_OTP_OFF);

    while (sec_len > 0 && secret[sec_len - 1] == 0) sec_len--;
    if (sec_len == 0) return -1;

    uint64_t step = (uint64_t)unix_time / 30;
    for (int i = 7; i >= 0; i--) { w->msg[i] = (uint8_t)step; step >>= 8; }

    sha1_set_w(w->W);
    hmac_sha1_w(w, secret, sec_len, w->msg, 8, w->hmac);
    sha1_set_w((uint32_t *)0);

    uint8_t offset = w->hmac[19] & 0x0F;
    uint32_t code = ((uint32_t)(w->hmac[offset]     & 0x7F) << 24)
                  | ((uint32_t) w->hmac[offset + 1]         << 16)
                  | ((uint32_t) w->hmac[offset + 2]         << 8)
                  | ((uint32_t) w->hmac[offset + 3]);
    code %= 1000000u;
    for (int i = 5; i >= 0; i--) { out6[i] = (uint8_t)('0' + code % 10); code /= 10; }

    memset(w, 0, sizeof(*w));   /* 清 HMAC 中间态（含 k_pad^key 派生） */
    return 0;
}
