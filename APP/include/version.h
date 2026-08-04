#ifndef _VERSION_H_
#define _VERSION_H_

#define FW_VERSION_MAJOR 1
#define FW_VERSION_MINOR 6
#define FW_VERSION_PATCH 20

// OTA security version (SVN) for anti-rollback. Bump ONLY when shipping a
// fix for a security issue — not on every release. The device persists a
// monotonic floor in DataFlash (OTA_SVN_FLOOR_ADDR) and rejects any package
// with a lower SVN. 1.6.0 = first ECDSA-verified (v2) firmware = SVN 1.
#define FW_SEC_VERSION 1

// FW_BUILD_NUMBER: set by Makefile via -D (git short hash as uint17_t)
// Fallback to 0 for IDE builds without Makefile
#ifndef FW_BUILD_NUMBER
#define FW_BUILD_NUMBER 0
#endif

// Version string 由上面的数字宏派生，不要手写 —— 曾经是独立的字符串
// 常量，结果版本号一路 bump 到 1.6.9 而它还停在 1.6.3：GET_STATUS 报
// 1.6.9、启动日志打 1.6.3，排查时对不上号。2026-08-03 发现。
#define _FW_VER_STR2(x) #x
#define _FW_VER_STR(x)  _FW_VER_STR2(x)
#define FW_VERSION_STRING \
    _FW_VER_STR(FW_VERSION_MAJOR) "." \
    _FW_VER_STR(FW_VERSION_MINOR) "." \
    _FW_VER_STR(FW_VERSION_PATCH)

#endif
