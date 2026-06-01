#ifndef _VERSION_H_
#define _VERSION_H_

#define FW_VERSION_MAJOR 1
#define FW_VERSION_MINOR 4
#define FW_VERSION_PATCH 9

// FW_BUILD_NUMBER: set by Makefile via -D (git short hash as uint17_t)
// Fallback to 0 for IDE builds without Makefile
#ifndef FW_BUILD_NUMBER
#define FW_BUILD_NUMBER 0
#endif

// Version string: "1.2.2" (build number shown separately in logs)
#define FW_VERSION_STRING "1.4.9"

#endif
