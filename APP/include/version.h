#ifndef _VERSION_H_
#define _VERSION_H_

#define FW_VERSION_MAJOR 1
#define FW_VERSION_MINOR 0
#define FW_VERSION_PATCH 7

// FW_BUILD_NUMBER: set by Makefile via -D (git short hash as uint16_t)
// Fallback to 0 for IDE builds without Makefile
#ifndef FW_BUILD_NUMBER
#define FW_BUILD_NUMBER 0
#endif

// Version string: "1.0.7" (build number shown separately in logs)
#define FW_VERSION_STRING "1.0.7"

#endif
