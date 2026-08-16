/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 time parsing implementation.
 */

#include <string.h>
#include <sdcrypt/asn1time.h>
#include <sdcrypt/errcode.h>

#if SDC_ASN1_TIME_PROVIDER == 0
#  include <time.h>
#  if SDC_32BIT
#    warning "SDC_ASN1_TIME_PROVIDER=0 uses time(), which overflows in 2038 on 32-bit systems. Consider setting SDC_ASN1_TIME_PROVIDER=1 and providing a custom time function."
#  endif
#else
extern int sdc_asn1_get_current_time(uint64_t *out);
#endif

#define CACHE_ELEMENTS (SDC_ASN1_TIME_CACHE_RANGE * 2 + 1)

static uint64_t days_cache[CACHE_ELEMENTS];
static int cache_start_year;
static int cache_initialized;

static uint64_t user_timestamp;
static int user_time_set;

/* ============================================================
   Internal helpers
   ============================================================ */

static int is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int days_in_month(int year, int month) {
    static const int days[12] = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31
    };
    if (month < 1 || month > 12) return 0;
    if (month == 2 && is_leap_year(year)) return 29;
    return days[month - 1];
}

static int days_in_year(int year) {
    return is_leap_year(year) ? 366 : 365;
}

static void timestamp_to_ymdhms(uint64_t ts, int *year, int *month, int *day,
                                int *hour, int *min, int *sec) {
    uint64_t t = ts;

    *sec = t % 60; t /= 60;
    *min = t % 60; t /= 60;
    *hour = t % 24; t /= 24;

    int y = 1970;
    while (t >= (uint64_t)days_in_year(y)) {
        t -= days_in_year(y);
        y++;
    }
    *year = y;

    int m;
    for (m = 1; m <= 12; m++) {
        int dim = days_in_month(y, m);
        if (t < (uint64_t)dim) break;
        t -= dim;
    }
    *month = m;
    *day = (int)t + 1;
}

static int get_current_year(void) {
#if SDC_ASN1_TIME_PROVIDER == 0
    if (user_time_set) {
        int y, m, d, h, mn, s;
        timestamp_to_ymdhms(user_timestamp, &y, &m, &d, &h, &mn, &s);
        return y;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) return 0;

    int y, m, d, h, mn, s;
    timestamp_to_ymdhms((uint64_t)now, &y, &m, &d, &h, &mn, &s);
    return y;
#else
    extern int sdc_asn1_get_current_year(void);
    return sdc_asn1_get_current_year();
#endif
}

static void init_cache(void) {
    if (cache_initialized) return;

    int current_year = get_current_year();
    if (current_year == 0) {
        current_year = 1970;
    }

    cache_start_year = current_year - SDC_ASN1_TIME_CACHE_RANGE;
    uint64_t days = 0;
    for (int y = 1970; y < cache_start_year; y++) {
        days += days_in_year(y);
    }
    for (int i = 0; i < CACHE_ELEMENTS; i++) {
        days_cache[i] = days;
        days += days_in_year(cache_start_year + i);
    }
    cache_initialized = 1;
}

static uint64_t days_before_year(int year) {
    if (!cache_initialized) init_cache();

    int offset = year - cache_start_year;
    if (offset >= 0 && offset < CACHE_ELEMENTS) {
        return days_cache[offset];
    }

    uint64_t days = 0;
    for (int y = 1970; y < year; y++) {
        days += days_in_year(y);
    }
    return days;
}

/* ============================================================
   Public API
   ============================================================ */

uint64_t sdc_asn1_time_to_timestamp(int year, int month, int day,
                                    int hour, int min, int sec) {
    if (year < 1970 || year > 9999) return 0;
    if (month < 1 || month > 12) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour > 23 || min > 59 || sec > 59) return 0;

    int max_day = days_in_month(year, month);
    if (day > max_day) return 0;

    uint64_t days = days_before_year(year);

    for (int m = 1; m < month; m++) {
        days += days_in_month(year, m);
    }
    days += (uint64_t)(day - 1);

    return days * 86400 +
           (uint64_t)hour * 3600 +
           (uint64_t)min * 60 +
           (uint64_t)sec;
}

void sdc_asn1_time_set_current(uint64_t timestamp) {
    user_timestamp = timestamp;
    user_time_set = (timestamp != 0);
    cache_initialized = 0;
}

void sdc_asn1_time_cache_refresh(void) {
    cache_initialized = 0;
}

void sdc_asn1_time_get_cache_range(int *start_year, int *end_year) {
    if (!cache_initialized) init_cache();

    if (start_year) *start_year = cache_start_year;
    if (end_year) *end_year = cache_start_year + CACHE_ELEMENTS - 1;
}

int sdc_asn1_time_now(uint64_t *out) {
    if (!out) return SDC_ERR_INVALID_PARAM;

#if SDC_ASN1_TIME_PROVIDER == 0
    if (user_time_set) {
        *out = user_timestamp;
        return SDC_ERR_OK;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        *out = 0;
        return SDC_ERR_TIME_FAIL;
    }

    *out = (uint64_t)now;
    return SDC_ERR_OK;
#else
    return sdc_asn1_get_current_time(out);
#endif
}