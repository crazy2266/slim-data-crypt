/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 general parsing implementation.
 */

#include <string.h>
#include <sdcrypt/asn1.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/asn1time.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/utils.h>

/* ============================================================
   内部辅助函数
   ============================================================ */

static inline int read_byte(sdc_asn1_reader_t *reader, uint8_t *out) {
    if (reader->pos >= reader->length) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    *out = reader->data[reader->pos++];
    return SDC_ERR_OK;
}

static inline int read_bytes(sdc_asn1_reader_t *reader, uint8_t *out, size_t len) {
    /* 确保 reader 状态合法 */
    if (reader->pos > reader->length) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    size_t remaining = reader->length - reader->pos;
    if (len > remaining) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    if (out != NULL && len > 0) {
        memcpy(out, reader->data + reader->pos, len);
    }
    reader->pos += len;
    return SDC_ERR_OK;
}

static inline void skip_bytes(sdc_asn1_reader_t *reader, size_t len) {
    reader->pos += len;
}

/* ============================================================
   解析辅助函数
   ============================================================ */

/* 解析 2 位数字 */
static int parse_2_digits(const uint8_t *s, int *out) {
    if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    *out = (s[0] - '0') * 10 + (s[1] - '0');
    return SDC_ERR_OK;
}

/* 解析 4 位数字 */
static int parse_4_digits(const uint8_t *s, int *out) {
    int ret;
    int high, low;
    ret = parse_2_digits(s, &high);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(s + 2, &low);
    if (ret != SDC_ERR_OK) return ret;
    *out = high * 100 + low;
    return SDC_ERR_OK;
}

/* ============================================================
   公开 API
   ============================================================ */

void sdc_asn1_reader_init(sdc_asn1_reader_t *reader, const uint8_t *data, size_t length) {
    if (!reader) return;
    reader->data = data;
    reader->length = length;
    reader->pos = 0;
}

int sdc_asn1_peek_tag(const sdc_asn1_reader_t *reader, uint8_t *tag) {
    if (!reader || !tag) return SDC_ERR_INVALID_PARAM;
    if (reader->pos >= reader->length) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    *tag = reader->data[reader->pos];
    return SDC_ERR_OK;
}

int sdc_asn1_read_tag(sdc_asn1_reader_t *reader, uint8_t *tag, size_t *length) {
    uint8_t b;
    int ret;

    if (!reader || !tag || !length) {
        return SDC_ERR_INVALID_PARAM;
    }

    ret = read_byte(reader, &b);
    if (ret != SDC_ERR_OK) return ret;
    *tag = b;

    ret = read_byte(reader, &b);
    if (ret != SDC_ERR_OK) return ret;
    if (!(b & 0x80)) {
        *length = b;
        return SDC_ERR_OK;
    }
    size_t nbytes = b & 0x7F;
    if (nbytes > 4) {
        return SDC_ERR_ASN1_BAD_LENGTH;
    }
    size_t len = 0;
    for (size_t i = 0; i < nbytes; i++) {
        ret = read_byte(reader, &b);
        if (ret != SDC_ERR_OK) return ret;
        len = (len << 8) | b;
    }
    *length = len;
    return SDC_ERR_OK;
}

int sdc_asn1_read_sequence(sdc_asn1_reader_t *reader, sdc_asn1_reader_t *seq) {
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader || !seq) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_SEQUENCE) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    seq->data = reader->data + reader->pos;
    seq->length = len;
    seq->pos = 0;
    skip_bytes(reader, len);
    return SDC_ERR_OK;
}

int sdc_asn1_read_set(sdc_asn1_reader_t *reader, sdc_asn1_reader_t *set) {
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader || !set) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_SET) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    set->data = reader->data + reader->pos;
    set->length = len;
    set->pos = 0;
    skip_bytes(reader, len);
    return SDC_ERR_OK;
}

int sdc_asn1_read_integer_to_bytes(sdc_asn1_reader_t *reader, uint8_t *data, size_t *len) {
    uint8_t tag;
    size_t value_len;
    int ret;

    if (!reader || !data || !len) {
        return SDC_ERR_INVALID_PARAM;
    }

    ret = sdc_asn1_read_tag(reader, &tag, &value_len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_INTEGER) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (value_len == 0) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    if (value_len > *len) {
        *len = value_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    ret = read_bytes(reader, data, value_len);
    if (ret != SDC_ERR_OK) return ret;
    if (value_len > 1 && data[0] == 0x00 && !(data[1] & 0x80)) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    *len = value_len;
    return SDC_ERR_OK;
}

int sdc_asn1_read_integer_to_words(sdc_asn1_reader_t *reader, sdc_word_t *data, size_t *limbs){
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader || !data || !limbs) {
        return SDC_ERR_INVALID_PARAM;
    }

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_INTEGER) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (len == 0) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    if (reader->data[reader->pos] & 0x80) {
        return SDC_ERR_NOT_IMPLEMENTED;
    }
    size_t need = (len + SDC_WORD_SIZE - 1) / SDC_WORD_SIZE;
    if (*limbs < need) {
        *limbs = need;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    memset(data, 0, need * SDC_WORD_SIZE);
    sdc_int_frombytes_be(data, need, reader->data + reader->pos);
    *limbs = need;
    skip_bytes(reader, len);
    return SDC_ERR_OK;
}

int sdc_asn1_read_integer_to_u64(sdc_asn1_reader_t *reader, uint64_t *out) {
    uint8_t tag;
    size_t len;
    uint8_t buf[16];
    int ret;
    uint64_t val = 0;

    if (!reader || !out) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_INTEGER) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (len == 0) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    if (len > 9) {
        return SDC_ERR_ASN1_INTEGER_TOO_LARGE;
    }
    ret = read_bytes(reader, buf, len);
    if (ret != SDC_ERR_OK) return ret;
    if (buf[0] & 0x80) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    if (len == 9) {
        if (buf[0] != 0x00) {
            return SDC_ERR_ASN1_INTEGER_TOO_LARGE;
        }
        if (!(buf[1] & 0x80)) {
            return SDC_ERR_ASN1_BAD_FORMAT;
        }
        val = load64_be(buf + 1);
    } else {
        for (size_t i = 0; i < len; i++) {
            val = (val << 8) | buf[i];
        }
    }
    *out = val;
    return SDC_ERR_OK;
}

int sdc_asn1_read_boolean(sdc_asn1_reader_t *reader, int *out) {
    uint8_t tag;
    size_t len;
    uint8_t val;
    int ret;

    if (!reader || !out) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_BOOLEAN) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (len != 1) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    ret = read_byte(reader, &val);
    if (ret != SDC_ERR_OK) return ret;
    *out = (val != 0) ? 1 : 0;
    return SDC_ERR_OK;
}

int sdc_asn1_read_oid(sdc_asn1_reader_t *reader, uint8_t *oid, size_t *oid_len) {
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader || !oid || !oid_len) {
        return SDC_ERR_INVALID_PARAM;
    }
    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_OBJECT_ID) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (len > *oid_len) {
        *oid_len = len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    ret = read_bytes(reader, oid, len);
    if (ret != SDC_ERR_OK) return ret;
    *oid_len = len;
    return SDC_ERR_OK;
}

int sdc_asn1_read_octet_string(sdc_asn1_reader_t *reader, const uint8_t **data, size_t *len) {
    uint8_t tag;
    size_t length;
    int ret;

    if (!reader || !data || !len) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &length);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_OCTET_STRING) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    *data = reader->data + reader->pos;
    *len = length;
    skip_bytes(reader, length);
    return SDC_ERR_OK;
}

int sdc_asn1_read_bit_string(sdc_asn1_reader_t *reader, const uint8_t **data, size_t *len) {
    uint8_t tag;
    size_t value_len;
    int ret;
    uint8_t unused_bits;

    if (!reader || !data || !len) {
        return SDC_ERR_INVALID_PARAM;
    }

    ret = sdc_asn1_read_tag(reader, &tag, &value_len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_BIT_STRING) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (value_len < 1) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    if (reader->pos + value_len > reader->length) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    unused_bits = reader->data[reader->pos];
    if (unused_bits > 7) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    *data = reader->data + reader->pos + 1;
    *len = value_len - 1;
    reader->pos += value_len;
    return SDC_ERR_OK;
}

int sdc_asn1_read_null(sdc_asn1_reader_t *reader) {
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_NULL) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    if (len != 0) {
        return SDC_ERR_ASN1_BAD_LENGTH;
    }
    return SDC_ERR_OK;
}

int sdc_asn1_read_utctime(sdc_asn1_reader_t *reader, uint64_t *timestamp) {
    uint8_t tag;
    size_t len;
    uint8_t buf[16];
    int ret;
    int year, month, day, hour, min, sec;

    if (!reader || !timestamp) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_UTC_TIME) {
        return SDC_ERR_ASN1_BAD_TAG;
    }

    if (len != 13) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    ret = read_bytes(reader, buf, len);
    if (ret != SDC_ERR_OK) return ret;

    if (buf[12] != 'Z') {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    ret = parse_2_digits(buf, &year);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 2, &month);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 4, &day);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 6, &hour);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 8, &min);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 10, &sec);
    if (ret != SDC_ERR_OK) return ret;

    if (year >= 50) {
        year += 1900;
    } else {
        year += 2000;
    }

    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || min > 59 || sec > 59) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    *timestamp = sdc_asn1_time_to_timestamp(year, month, day, hour, min, sec);
    if (*timestamp == 0) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    return SDC_ERR_OK;
}

int sdc_asn1_read_generalized_time(sdc_asn1_reader_t *reader, uint64_t *timestamp) {
    uint8_t tag;
    size_t len;
    uint8_t buf[32];
    int ret;
    int year, month, day, hour, min, sec;

    if (!reader || !timestamp) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != ASN1_TAG_GENERALIZED_TIME) {
        return SDC_ERR_ASN1_BAD_TAG;
    }

    if (len != 15) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    ret = read_bytes(reader, buf, len);
    if (ret != SDC_ERR_OK) return ret;

    if (buf[14] != 'Z') {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    ret = parse_4_digits(buf, &year);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 4, &month);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 6, &day);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 8, &hour);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 10, &min);
    if (ret != SDC_ERR_OK) return ret;
    ret = parse_2_digits(buf + 12, &sec);
    if (ret != SDC_ERR_OK) return ret;

    if (year < 1970 || year > 9999 ||
        month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || min > 59 || sec > 59) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }

    *timestamp = sdc_asn1_time_to_timestamp(year, month, day, hour, min, sec);
    if (*timestamp == 0) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    return SDC_ERR_OK;
}

int sdc_asn1_skip(sdc_asn1_reader_t *reader) {
    uint8_t tag;
    size_t len;
    int ret;

    if (!reader) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_read_tag(reader, &tag, &len);
    if (ret != SDC_ERR_OK) return ret;
    if (len > reader->length - reader->pos) {
        return SDC_ERR_ASN1_TRUNCATED;
    }
    skip_bytes(reader, len);
    return SDC_ERR_OK;
}

int sdc_asn1_expect_tag(sdc_asn1_reader_t *reader, uint8_t expected_tag) {
    uint8_t tag;
    int ret;

    if (!reader) return SDC_ERR_INVALID_PARAM;

    ret = sdc_asn1_peek_tag(reader, &tag);
    if (ret != SDC_ERR_OK) return ret;
    if (tag != expected_tag) {
        return SDC_ERR_ASN1_BAD_TAG;
    }
    return SDC_ERR_OK;
}

size_t sdc_asn1_remaining(const sdc_asn1_reader_t *reader) {
    if (!reader) return 0;
    if (reader->pos > reader->length) {
        return 0;
    }
    return reader->length - reader->pos;
}