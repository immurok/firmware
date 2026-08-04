#ifndef TEST_MAIN_H
#define TEST_MAIN_H
#include <stdio.h>

static int g_fail;

#define CHECK(cond, msg) do {                                            \
    if (!(cond)) { printf("  FAIL %s:%d %s\n", __FILE__, __LINE__, msg); \
                   g_fail++; }                                           \
} while (0)

#define RUN(fn) do { printf("- %s\n", #fn); fn(); } while (0)

#define TEST_MAIN_END \
    do { printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail); \
         return g_fail ? 1 : 0; } while (0)

#endif
