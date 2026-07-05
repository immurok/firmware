#ifndef _VERSION_H_
#define _VERSION_H_

#define FW_VERSION_MAJOR 1
#define FW_VERSION_MINOR 6
#define FW_VERSION_PATCH 2

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

// Version string: "1.2.2" (build number shown separately in logs)
#define FW_VERSION_STRING "1.6.2"

#endif
