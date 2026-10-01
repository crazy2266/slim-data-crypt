/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Shared test harness for the slim-data-crypt test suite.
 * Lightweight PASS/FAIL accounting with no external dependencies.
 */

#ifndef SDC_TEST_COMMON_H
#define SDC_TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__)
#define T_MAYBE_UNUSED __attribute__((unused))
#else
#define T_MAYBE_UNUSED
#endif

static int g_tests_run     = 0;
static int g_tests_passed  = 0;
static int g_tests_failed  = 0;
static int g_tests_skipped = 0;

#define T_SUITE(name) do { \
    printf("========================================\n"); \
    printf("  %s\n", (name)); \
    printf("========================================\n"); \
} while (0)

#define T_SECTION(name) \
    printf("\n--- %s ---\n", (name))

#define T_CHECK(cond, desc) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", (desc)); \
    } else { \
        g_tests_failed++; \
        printf("  [FAIL] %s\n", (desc)); \
    } \
} while (0)

#define T_CHECK_MEM(a, b, n, desc) \
    T_CHECK(memcmp((a), (b), (n)) == 0, (desc))

#define T_SKIP(desc) do { \
    g_tests_skipped++; \
    printf("  [SKIP] %s\n", (desc)); \
} while (0)

#define T_SUMMARY() do { \
    printf("\n----------------------------------------\n"); \
    printf("  Total: %d   Passed: %d   Failed: %d   Skipped: %d\n", \
           g_tests_run, g_tests_passed, g_tests_failed, g_tests_skipped); \
    printf("----------------------------------------\n"); \
    return (g_tests_failed == 0) ? 0 : 1; \
} while (0)

static T_MAYBE_UNUSED void t_print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

#endif /* SDC_TEST_COMMON_H */
