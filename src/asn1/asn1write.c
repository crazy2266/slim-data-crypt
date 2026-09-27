/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 DER encoder.
 *
 * The writer uses reverse construction. Content is written first from the
 * end of the caller's buffer towards the beginning; the DER length and tag
 * are then prepended. This avoids reserving a length field and avoids the
 * memmove previously required by BEGIN/END containers.
 */

#include <string.h>
#include <sdcrypt/asn1.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/asn1time.h>

void sdc_asn1_writer_init(sdc_asn1_writer_t *writer, uint8_t *buf, size_t len) {
    if (!writer) return;
    writer->data = buf;
    writer->length = len;
    writer->pos = len;
    writer->error = 0;
}

size_t sdc_asn1_writer_length(const sdc_asn1_writer_t *writer) {
    if (!writer || writer->pos > writer->length) return 0;
    return writer->length - writer->pos;
}

uint8_t *sdc_asn1_writer_data(sdc_asn1_writer_t *writer) {
    if (!writer || !writer->data || writer->pos > writer->length) return NULL;
    return writer->data + writer->pos;
}

int sdc_asn1_writer_has_error(const sdc_asn1_writer_t *writer) {
    return writer && writer->error != 0;
}

/* ============================================================
   Reverse-write helpers
   ============================================================ */

static int write_byte_rev(sdc_asn1_writer_t *writer, uint8_t val) {
    if (!writer) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (writer->pos == 0) {
        writer->error = 1;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    writer->data[--writer->pos] = val;
    return SDC_ERR_OK;
}

static int write_bytes_rev(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    if (!writer) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (len > writer->pos) {
        writer->error = 1;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    writer->pos -= len;
    if (len && data) {
        /* memmove also permits a source range inside the output buffer. */
        memmove(writer->data + writer->pos, data, len);
    }
    return SDC_ERR_OK;
}

static int write_length_rev(sdc_asn1_writer_t *writer, size_t len) {
    uint8_t buf[1 + sizeof(size_t)];
    size_t n = 0;

    if (!writer) return SDC_ERR_INVALID_PARAM;
    if (len < 0x80) {
        buf[n++] = (uint8_t)len;
    } else {
        size_t t = len;
        size_t nbytes = 0;

        while (t != 0) {
            buf[sizeof(buf) - 1 - nbytes] = (uint8_t)t;
            t >>= 8;
            nbytes++;
        }

        if (nbytes == 0 || nbytes > 0x7F || nbytes > sizeof(size_t)) {
            writer->error = 1;
            return SDC_ERR_ASN1_BAD_LENGTH;
        }

        buf[0] = (uint8_t)(0x80 | nbytes);
        for (size_t i = 0; i < nbytes; i++)
            buf[1 + i] = buf[sizeof(buf) - nbytes + i];
        n = 1 + nbytes;
    }

    return write_bytes_rev(writer, buf, n);
}

static int write_tlv_header_rev(sdc_asn1_writer_t *writer, uint8_t tag, size_t len) {
    int ret = write_length_rev(writer, len);
    if (ret != SDC_ERR_OK) return ret;
    return write_byte_rev(writer, tag);
}

/* ============================================================
   Tag / raw bytes
   ============================================================ */

int sdc_asn1_write_tag(sdc_asn1_writer_t *writer, uint8_t tag, size_t len) {
    return write_tlv_header_rev(writer, tag, len);
}

int sdc_asn1_write_explicit_tag(sdc_asn1_writer_t *writer, uint8_t tag, size_t len) {
    return write_tlv_header_rev(writer, tag, len);
}

int sdc_asn1_write_bytes(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    return write_bytes_rev(writer, data, len);
}

/* ============================================================
   Primitive values
   ============================================================ */

int sdc_asn1_write_null(sdc_asn1_writer_t *writer) {
    return write_tlv_header_rev(writer, ASN1_TAG_NULL, 0);
}

int sdc_asn1_write_boolean(sdc_asn1_writer_t *writer, int value) {
    int ret = write_byte_rev(writer, value ? 0xFF : 0x00);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_BOOLEAN, 1);
}

int sdc_asn1_write_integer(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    if (!writer || !data || len == 0) return SDC_ERR_INVALID_PARAM;

    size_t start = 0;
    while (start + 1 < len && data[start] == 0x00 && !(data[start + 1] & 0x80))
        start++;

    const uint8_t *actual = data + start;
    size_t actual_len = len - start;
    int prepend_zero = (actual[0] & 0x80) != 0;

    if (prepend_zero) {
        if (actual_len == SIZE_MAX) return SDC_ERR_ASN1_BAD_LENGTH;
        int ret = write_bytes_rev(writer, actual, actual_len);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte_rev(writer, 0x00);
        if (ret != SDC_ERR_OK) return ret;
        return write_tlv_header_rev(writer, ASN1_TAG_INTEGER, actual_len + 1);
    }

    int ret = write_bytes_rev(writer, actual, actual_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_INTEGER, actual_len);
}

int sdc_asn1_write_integer_u64(sdc_asn1_writer_t *writer, uint64_t value) {
    uint8_t buf[8];
    size_t len = 0;

    if (value == 0) {
        buf[0] = 0;
        len = 1;
    } else {
        for (int i = 7; i >= 0; i--) {
            uint8_t byte = (uint8_t)(value >> (i * 8));
            if (byte != 0 || len != 0)
                buf[len++] = byte;
        }
    }
    return sdc_asn1_write_integer(writer, buf, len);
}

int sdc_asn1_write_integer_from_words(sdc_asn1_writer_t *writer,
                                      const sdc_word_t *data, size_t limbs) {
    if (!writer || !data || limbs == 0) return SDC_ERR_INVALID_PARAM;
    if (limbs > (SIZE_MAX - 1) / SDC_WORD_SIZE)
        return SDC_ERR_ASN1_BAD_LENGTH;

    size_t need = limbs * SDC_WORD_SIZE;
    uint8_t *buf = (uint8_t *)sdc_malloc(need + 1);
    if (!buf) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_int_tobytes_be(data, limbs, buf);

    size_t len = need;
    while (len > 1 && buf[0] == 0x00) {
        memmove(buf, buf + 1, len - 1);
        len--;
    }

    int ret = sdc_asn1_write_integer(writer, buf, len);
    sdc_free(buf);
    return ret;
}

int sdc_asn1_write_utf8_string(sdc_asn1_writer_t *writer,
                               const uint8_t *data, size_t len) {
    int ret = write_bytes_rev(writer, data, len);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_UTF8_STRING, len);
}

int sdc_asn1_write_octet_string(sdc_asn1_writer_t *writer,
                                const uint8_t *data, size_t len) {
    int ret = write_bytes_rev(writer, data, len);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_OCTET_STRING, len);
}

int sdc_asn1_write_oid(sdc_asn1_writer_t *writer,
                       const uint8_t *oid, size_t oid_len) {
    int ret = write_bytes_rev(writer, oid, oid_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_OBJECT_ID, oid_len);
}

/* ============================================================
   BIT STRING
   ============================================================ */

int sdc_asn1_write_bit_string(sdc_asn1_writer_t *writer,
                              const uint8_t *data, size_t len,
                              uint8_t unused_bits) {
    if (!writer || (len != 0 && !data))
        return SDC_ERR_INVALID_PARAM;
    if (unused_bits > 7)
        return SDC_ERR_ASN1_BAD_FORMAT;
    if (len == 0 && unused_bits != 0)
        return SDC_ERR_ASN1_BAD_FORMAT;
    if (len > 0 && unused_bits != 0 &&
        (data[len - 1] & ((uint8_t)0xFF >> (8 - unused_bits))))
        return SDC_ERR_ASN1_BAD_FORMAT;
    if (len == SIZE_MAX)
        return SDC_ERR_ASN1_BAD_LENGTH;

    int ret = write_bytes_rev(writer, data, len);
    if (ret != SDC_ERR_OK) return ret;
    ret = write_byte_rev(writer, unused_bits);
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_BIT_STRING, len + 1);
}

int sdc_asn1_write_bit_string_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit) {
    if (!writer || !bit) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    /* The caller writes BIT STRING payload bytes after this call. */
    bit->data = writer->data;
    bit->length = writer->pos;
    bit->pos = writer->pos;
    bit->error = 0;
    return SDC_ERR_OK;
}

int sdc_asn1_write_bit_string_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit) {
    if (!writer || !bit) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (bit->data != writer->data || bit->pos != bit->length || bit->length > writer->length)
        return SDC_ERR_INVALID_PARAM;

    size_t content_len = bit->length - writer->pos;
    if (content_len == SIZE_MAX)
        return SDC_ERR_ASN1_BAD_LENGTH;

    int ret = write_byte_rev(writer, 0x00); /* unused bits */
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_BIT_STRING, content_len + 1);
}

/* ============================================================
   SEQUENCE / SET

   BEGIN/END is a reverse-construction API. If the desired DER is
       SEQUENCE { A, B, C }
   the calls must write C, then B, then A, and finally END.
   ============================================================ */

int sdc_asn1_write_sequence_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq) {
    if (!writer || !seq) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    seq->data = writer->data;
    seq->length = writer->pos; /* start boundary */
    seq->pos = writer->pos;
    seq->error = 0;
    return SDC_ERR_OK;
}

int sdc_asn1_write_sequence_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq) {
    if (!writer || !seq) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (seq->data != writer->data || seq->length > writer->length ||
        seq->pos != seq->length || writer->pos > seq->length)
        return SDC_ERR_INVALID_PARAM;

    size_t content_len = seq->length - writer->pos;
    int ret = write_length_rev(writer, content_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_byte_rev(writer, ASN1_TAG_SEQUENCE);
}

int sdc_asn1_write_set_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set) {
    if (!writer || !set) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    set->data = writer->data;
    set->length = writer->pos;
    set->pos = writer->pos;
    set->error = 0;
    return SDC_ERR_OK;
}

int sdc_asn1_write_set_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set) {
    if (!writer || !set) return SDC_ERR_INVALID_PARAM;
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (set->data != writer->data || set->length > writer->length ||
        set->pos != set->length || writer->pos > set->length)
        return SDC_ERR_INVALID_PARAM;

    size_t content_len = set->length - writer->pos;
    int ret = write_length_rev(writer, content_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_byte_rev(writer, ASN1_TAG_SET);
}

/* ============================================================
   Time helpers
   ============================================================ */

static int is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int days_in_year(int year) {
    return is_leap_year(year) ? 366 : 365;
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

static void format_utctime(uint8_t *buf, int year, int month, int day,
                           int hour, int min, int sec) {
    buf[0] = '0' + (year / 10) % 10;
    buf[1] = '0' + year % 10;
    buf[2] = '0' + (month / 10) % 10;
    buf[3] = '0' + month % 10;
    buf[4] = '0' + (day / 10) % 10;
    buf[5] = '0' + day % 10;
    buf[6] = '0' + (hour / 10) % 10;
    buf[7] = '0' + hour % 10;
    buf[8] = '0' + (min / 10) % 10;
    buf[9] = '0' + min % 10;
    buf[10] = '0' + (sec / 10) % 10;
    buf[11] = '0' + sec % 10;
    buf[12] = 'Z';
}

int sdc_asn1_write_utctime(sdc_asn1_writer_t *writer, uint64_t timestamp) {
    uint8_t buf[13];

    uint64_t t = timestamp;
    int sec = (int)(t % 60); t /= 60;
    int min = (int)(t % 60); t /= 60;
    int hour = (int)(t % 24); t /= 24;

    int y = 1970;
    while (t >= (uint64_t)days_in_year(y)) {
        t -= (uint64_t)days_in_year(y);
        y++;
    }

    int m;
    for (m = 1; m <= 12; m++) {
        int dim = days_in_month(y, m);
        if (t < (uint64_t)dim) break;
        t -= (uint64_t)dim;
    }

    format_utctime(buf, y % 100, m, (int)t + 1, hour, min, sec);
    int ret = write_bytes_rev(writer, buf, sizeof(buf));
    if (ret != SDC_ERR_OK) return ret;
    return write_tlv_header_rev(writer, ASN1_TAG_UTC_TIME, sizeof(buf));
}
