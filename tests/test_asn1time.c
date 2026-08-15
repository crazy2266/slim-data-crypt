/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test ASN.1 time module.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/asn1time.h>
#include <sdcrypt/errcode.h>

static int test_passed = 0;
static int test_total = 0;

#define TEST_START(name) printf("\n=== %s ===\n", name)
#define TEST_ASSERT(cond, msg) \
    do { \
        test_total++; \
        if (cond) { \
            printf("  [PASS] %s\n", msg); \
            test_passed++; \
        } else { \
            printf("  [FAIL] %s\n", msg); \
        } \
    } while (0)

int main(void) {
    uint64_t ts;
    int ret;

    printf("========================================\n");
    printf("  ASN.1 Time Test\n");
    printf("========================================\n");

    /* ============================================================
       Test 1: Known timestamps
       ============================================================ */
    TEST_START("Known timestamps");

    /* Unix epoch: 1970-01-01 00:00:00 */
    ts = sdc_asn1_time_to_timestamp(1970, 1, 1, 0, 0, 0);
    TEST_ASSERT(ts == 0, "1970-01-01 00:00:00 -> 0");

    /* 2024-01-01 00:00:00 UTC */
    ts = sdc_asn1_time_to_timestamp(2024, 1, 1, 0, 0, 0);
    TEST_ASSERT(ts == 1704067200ULL, "2024-01-01 00:00:00 -> 1704067200");

    /* 2025-01-01 00:00:00 UTC */
    ts = sdc_asn1_time_to_timestamp(2025, 1, 1, 0, 0, 0);
    TEST_ASSERT(ts == 1735689600ULL, "2025-01-01 00:00:00 -> 1735689600");

    /* 2026-08-15 12:34:56 UTC */
    ts = sdc_asn1_time_to_timestamp(2026, 8, 15, 12, 34, 56);
    TEST_ASSERT(ts == 1786797296ULL, "2026-08-15 12:34:56 UTC -> 1786797296");

    /* ============================================================
       Test 2: Edge cases
       ============================================================ */
    TEST_START("Edge cases");

    /* Leap year: 2024-02-29 */
    ts = sdc_asn1_time_to_timestamp(2024, 2, 29, 0, 0, 0);
    TEST_ASSERT(ts == 1709164800ULL, "2024-02-29 -> 1709164800");

    /* Non-leap year: 2025-02-29 should fail */
    ts = sdc_asn1_time_to_timestamp(2025, 2, 29, 0, 0, 0);
    TEST_ASSERT(ts == 0, "2025-02-29 -> 0 (invalid)");

    /* Invalid month */
    ts = sdc_asn1_time_to_timestamp(2025, 13, 1, 0, 0, 0);
    TEST_ASSERT(ts == 0, "Month 13 -> 0 (invalid)");

    /* Invalid day */
    ts = sdc_asn1_time_to_timestamp(2025, 1, 32, 0, 0, 0);
    TEST_ASSERT(ts == 0, "Day 32 -> 0 (invalid)");

    /* Year before 1970 */
    ts = sdc_asn1_time_to_timestamp(1969, 12, 31, 0, 0, 0);
    TEST_ASSERT(ts == 0, "Year 1969 -> 0 (invalid)");

    /* Year 2038 (beyond 32-bit time_t) */
    ts = sdc_asn1_time_to_timestamp(2038, 1, 19, 3, 14, 7);
    TEST_ASSERT(ts == 2147483647ULL, "2038-01-19 03:14:07 -> 2147483647");

    /* ============================================================
       Test 3: Cache refresh
       ============================================================ */
    TEST_START("Cache operations");

    /* Set current time to a known value */
    sdc_asn1_time_set_current(1735689600ULL);

    /* Get current time */
    ret = sdc_asn1_time_now(&ts);
    TEST_ASSERT(ret == SDC_ERR_OK && ts == 1735689600ULL,
                "sdc_asn1_time_now returns set time");

    /* Refresh cache */
    sdc_asn1_time_cache_refresh();

    /* Get cache range */
    int start, end;
    sdc_asn1_time_get_cache_range(&start, &end);
    TEST_ASSERT(start <= end, "Cache range valid");

    /* ============================================================
       Test 4: Time parse failure
       ============================================================ */
    TEST_START("Time parse failure");

    /* Clear user time to use system time */
    sdc_asn1_time_set_current(0);

    ret = sdc_asn1_time_now(&ts);
    /* Can't predict exact value, just check it's reasonable */
    TEST_ASSERT(ret == SDC_ERR_OK && ts > 1700000000ULL,
                "System time is reasonable (> 2023)");

    /* ============================================================
       Test 5: sdc_asn1_time_to_timestamp consistency
       ============================================================ */
    TEST_START("Round-trip consistency");

    /* 2025-06-15 08:30:45 -> timestamp -> back to date (we just check it doesn't crash) */
    ts = sdc_asn1_time_to_timestamp(2025, 6, 15, 8, 30, 45);
    TEST_ASSERT(ts > 0, "2025-06-15 08:30:45 -> valid timestamp");

    /* Edge: max year 9999 */
    ts = sdc_asn1_time_to_timestamp(9999, 12, 31, 23, 59, 59);
    TEST_ASSERT(ts == 253402300799ULL, "9999-12-31 23:59:59 -> 253402300799");

    /* ============================================================
       Final
       ============================================================ */
    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");

    return (test_passed == test_total) ? 0 : 1;
}