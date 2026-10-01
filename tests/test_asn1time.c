/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 time module tests: known timestamps, edge cases, cache behavior.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/asn1time.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/config.h>
#include "test_common.h"

int main(void) {
    uint64_t ts;
    int ret;

    T_SUITE("ASN.1 Time Tests");

    T_SECTION("Known timestamps");
    ts = sdc_asn1_time_to_timestamp(1970, 1, 1, 0, 0, 0);
    T_CHECK(ts == 0, "1970-01-01 00:00:00 -> 0");
    ts = sdc_asn1_time_to_timestamp(2024, 1, 1, 0, 0, 0);
    T_CHECK(ts == 1704067200ULL, "2024-01-01 00:00:00 -> 1704067200");
    ts = sdc_asn1_time_to_timestamp(2025, 1, 1, 0, 0, 0);
    T_CHECK(ts == 1735689600ULL, "2025-01-01 00:00:00 -> 1735689600");
    ts = sdc_asn1_time_to_timestamp(2026, 8, 15, 12, 34, 56);
    T_CHECK(ts == 1786797296ULL, "2026-08-15 12:34:56 -> 1786797296");

    T_SECTION("Edge cases");
    ts = sdc_asn1_time_to_timestamp(2024, 2, 29, 0, 0, 0);
    T_CHECK(ts == 1709164800ULL, "2024-02-29 leap day -> 1709164800");
    ts = sdc_asn1_time_to_timestamp(2025, 2, 29, 0, 0, 0);
    T_CHECK(ts == 0, "2025-02-29 invalid -> 0");
    ts = sdc_asn1_time_to_timestamp(2025, 13, 1, 0, 0, 0);
    T_CHECK(ts == 0, "Month 13 invalid -> 0");
    ts = sdc_asn1_time_to_timestamp(2025, 1, 32, 0, 0, 0);
    T_CHECK(ts == 0, "Day 32 invalid -> 0");
    ts = sdc_asn1_time_to_timestamp(1969, 12, 31, 0, 0, 0);
    T_CHECK(ts == 0, "Year 1969 pre-epoch -> 0");
    ts = sdc_asn1_time_to_timestamp(2038, 1, 19, 3, 14, 7);
    T_CHECK(ts == 2147483647ULL, "2038-01-19 03:14:07 -> 2147483647");

    T_SECTION("Cache operations");
    sdc_asn1_time_set_current(1735689600ULL);
    ret = sdc_asn1_time_now(&ts);
    T_CHECK(ret == SDC_ERR_OK && ts == 1735689600ULL,
            "sdc_asn1_time_now returns injected time");
    sdc_asn1_time_cache_refresh();
    {
        int start, end;
        sdc_asn1_time_get_cache_range(&start, &end);
        T_CHECK(start <= end, "cache range is valid");
    }

    T_SECTION("System time");
    sdc_asn1_time_set_current(0);
    ret = sdc_asn1_time_now(&ts);
    T_CHECK(ret == SDC_ERR_OK && ts > 1700000000ULL,
            "system time is reasonable (> 2023)");

    T_SECTION("Round-trip consistency");
    ts = sdc_asn1_time_to_timestamp(2025, 6, 15, 8, 30, 45);
    T_CHECK(ts > 0, "2025-06-15 08:30:45 -> valid timestamp");
    ts = sdc_asn1_time_to_timestamp(9999, 12, 31, 23, 59, 59);
    T_CHECK(ts == 253402300799ULL, "9999-12-31 23:59:59 -> 253402300799");

    T_SUMMARY();
}
