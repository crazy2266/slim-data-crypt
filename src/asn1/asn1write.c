/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 DER encoder.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/asn1.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/asn1time.h>

/* ============================================================
   Writer initialize
   ============================================================ */
void sdc_asn1_writer_init(sdc_asn1_writer_t *writer, uint8_t *buf, size_t len) {
    writer->data = buf;
    writer->length = len;
    writer->pos = 0;
    writer->error = 0;
}

size_t sdc_asn1_writer_length(const sdc_asn1_writer_t *writer) {
    return writer->pos;
}

int sdc_asn1_writer_has_error(const sdc_asn1_writer_t *writer) {
    return writer->error != 0;
}

/* ============================================================
   Internal helper functions
   ============================================================ */

static int write_byte(sdc_asn1_writer_t *writer, uint8_t val) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (writer->pos >= writer->length) {
        writer->error = 1;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    writer->data[writer->pos++] = val;
    return SDC_ERR_OK;
}

static int write_bytes(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (writer->pos + len > writer->length) {
        writer->error = 1;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (data && len > 0) {
        memcpy(writer->data + writer->pos, data, len);
        writer->pos += len;
    }
    return SDC_ERR_OK;
}

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
    /* YYMMDDHHMMSSZ */
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

/* ============================================================
   Write Tag + Length (DER encoding)
   ============================================================ */
int sdc_asn1_write_tag(sdc_asn1_writer_t *writer, uint8_t tag, size_t len) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    if (len > 0xFFFFFFFF) {
        writer->error = 1;
        return SDC_ERR_ASN1_BAD_LENGTH;
    }

    int ret = write_byte(writer, tag);
    if (ret != SDC_ERR_OK) return ret;

    if (len < 0x80) {
        ret = write_byte(writer, (uint8_t)len);
    } else if (len <= 0xFF) {
        ret = write_byte(writer, 0x81);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)len);
    } else if (len <= 0xFFFF) {
        ret = write_byte(writer, 0x82);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 8));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len & 0xFF));
    } else if (len <= 0xFFFFFF) {
        ret = write_byte(writer, 0x83);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 16));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 8));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len & 0xFF));
    } else {
        ret = write_byte(writer, 0x84);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 24));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 16));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len >> 8));
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)(len & 0xFF));
    }
    return ret;
}

/* ============================================================
   Write raw bytes
   ============================================================ */
int sdc_asn1_write_bytes(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    return write_bytes(writer, data, len);
}

/* ============================================================
   Write NULL
   ============================================================ */
int sdc_asn1_write_null(sdc_asn1_writer_t *writer) {
    return sdc_asn1_write_tag(writer, ASN1_TAG_NULL, 0);
}

/* ============================================================
   Write BOOLEAN
   ============================================================ */
int sdc_asn1_write_boolean(sdc_asn1_writer_t *writer, int value) {
    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_BOOLEAN, 1);
    if (ret != SDC_ERR_OK) return ret;
    return write_byte(writer, value ? 0xFF : 0x00);
}

/* ============================================================
   Write INTEGER (from byte array)
   ============================================================ */
int sdc_asn1_write_integer(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len) {
    if (!data || len == 0) {
        return SDC_ERR_INVALID_PARAM;
    }

    size_t start = 0;
    while (start + 1 < len && data[start] == 0x00 && !(data[start + 1] & 0x80)) {
        start++;
    }
    const uint8_t *actual_data = data + start;
    size_t actual_len = len - start;

    if (actual_len > 0 && (actual_data[0] & 0x80)) {
        int ret = sdc_asn1_write_tag(writer, ASN1_TAG_INTEGER, actual_len + 1);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, 0x00);
        if (ret != SDC_ERR_OK) return ret;
        return write_bytes(writer, actual_data, actual_len);
    }

    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_INTEGER, actual_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, actual_data, actual_len);
}

/* ============================================================
   Write INTEGER (from uint64_t)
   ============================================================ */
int sdc_asn1_write_integer_u64(sdc_asn1_writer_t *writer, uint64_t value) {
    uint8_t buf[9];
    size_t len = 0;

    if (value == 0) {
        return sdc_asn1_write_integer(writer, (const uint8_t *)"\x00", 1);
    }
    for (int i = 7; i >= 0; i--) {
        uint8_t byte = (uint8_t)(value >> (i * 8));
        if (byte != 0 || len > 0) {
            buf[len++] = byte;
        }
    }
    return sdc_asn1_write_integer(writer, buf, len);
}

/* ============================================================
   Write INTEGER (from sdc_word_t array)
   ============================================================ */
int sdc_asn1_write_integer_from_words(sdc_asn1_writer_t *writer,
                                      const sdc_word_t *data, size_t limbs) {
    uint8_t *buf;
    size_t len, need;
    int ret;

    if (!writer || !data || limbs == 0) {
        return SDC_ERR_INVALID_PARAM;
    }

    need = limbs * SDC_WORD_SIZE;
    buf = sdc_malloc(need + 1);
    if (!buf) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_int_tobytes_be(data, limbs, buf);
    len = need;

    /* Remove leading zeros */
    while (len > 1 && buf[0] == 0x00) {
        memmove(buf, buf + 1, len - 1);
        len--;
    }

    /* If the highest bit is 1, prepend 0x00 */
    if (len > 0 && (buf[0] & 0x80)) {
        uint8_t *ext = sdc_malloc(len + 1);
        if (!ext) { sdc_free(buf); return SDC_ERR_MEM_ALLOCATE_FAIL; }
        ext[0] = 0x00;
        memcpy(ext + 1, buf, len);
        ret = sdc_asn1_write_integer(writer, ext, len + 1);
        sdc_free(ext);
        sdc_free(buf);
        return ret;
    }

    ret = sdc_asn1_write_integer(writer, buf, len);
    sdc_free(buf);
    return ret;
}

int sdc_asn1_write_utf8_string(sdc_asn1_writer_t *writer,
                               const uint8_t *data, size_t len) {
    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_UTF8_STRING, len);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, data, len);
}

/* ============================================================
   Write OCTET STRING
   ============================================================ */
int sdc_asn1_write_octet_string(sdc_asn1_writer_t *writer,
                                const uint8_t *data, size_t len) {
    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_OCTET_STRING, len);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, data, len);
}

/* ============================================================
   Write BIT STRING
   ============================================================ */
int sdc_asn1_write_bit_string_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    bit->data = writer->data;
    bit->pos = writer->pos;
    bit->length = 0;
    bit->error = 0;

    int ret = write_byte(writer, ASN1_TAG_BIT_STRING);
    if (ret != SDC_ERR_OK) return ret;

    bit->length = writer->pos;
    for (int i = 0; i < 4; i++) {
        ret = write_byte(writer, 0x00);
        if (ret != SDC_ERR_OK) return ret;
    }
    ret = write_byte(writer, 0x00);
    if (ret != SDC_ERR_OK) return ret;
    return SDC_ERR_OK;
}

int sdc_asn1_write_bit_string_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (bit->pos > writer->pos) return SDC_ERR_INVALID_PARAM;

    size_t content_len = writer->pos - (bit->length + 4);
    uint8_t len_buf[4];
    size_t len_bytes;

    if (content_len < 0x80) {
        len_bytes = 1;
        len_buf[0] = (uint8_t)content_len;
    } else if (content_len <= 0xFF) {
        len_bytes = 2;
        len_buf[0] = 0x81;
        len_buf[1] = (uint8_t)content_len;
    } else if (content_len <= 0xFFFF) {
        len_bytes = 3;
        len_buf[0] = 0x82;
        len_buf[1] = (uint8_t)(content_len >> 8);
        len_buf[2] = (uint8_t)(content_len & 0xFF);
    } else {
        len_bytes = 4;
        len_buf[0] = 0x83;
        len_buf[1] = (uint8_t)(content_len >> 16);
        len_buf[2] = (uint8_t)(content_len >> 8);
        len_buf[3] = (uint8_t)(content_len & 0xFF);
    }

    if (len_bytes < 4) {
        size_t src = bit->length + 4;
        size_t dst = bit->length + len_bytes;
        size_t move_len = writer->pos - src;
        if (move_len > 0) {
            memmove(writer->data + dst, writer->data + src, move_len);
        }
        writer->pos -= (4 - len_bytes);
    } else if (len_bytes > 4) {
        writer->error = 1;
        return SDC_ERR_ASN1_BAD_LENGTH;
    }
    memcpy(writer->data + bit->length, len_buf, len_bytes);
    return SDC_ERR_OK;
}

int sdc_asn1_write_bit_string(sdc_asn1_writer_t *writer,
                              const uint8_t *data, size_t len,
                              uint8_t unused_bits) {
    if (unused_bits > 7) {
        return SDC_ERR_ASN1_BAD_FORMAT;
    }
    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_BIT_STRING, len + 1);
    if (ret != SDC_ERR_OK) return ret;
    ret = write_byte(writer, unused_bits);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, data, len);
}

/* ============================================================
   Write OID
   ============================================================ */
int sdc_asn1_write_oid(sdc_asn1_writer_t *writer,
                       const uint8_t *oid, size_t oid_len) {
    int ret = sdc_asn1_write_tag(writer, ASN1_TAG_OBJECT_ID, oid_len);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, oid, oid_len);
}

/* ============================================================
   SEQUENCE / SET
   ============================================================ */
int sdc_asn1_write_sequence_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    seq->data = writer->data;
    seq->pos = writer->pos;
    seq->length = 0;
    seq->error = 0;

    int ret = write_byte(writer, ASN1_TAG_SEQUENCE);
    if (ret != SDC_ERR_OK) return ret;
    seq->length = writer->pos;
    for (int i = 0; i < 4; i++) {
        ret = write_byte(writer, 0x00);
        if (ret != SDC_ERR_OK) return ret;
    }
    return SDC_ERR_OK;
}

int sdc_asn1_write_sequence_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;
    if (seq->pos > writer->pos) return SDC_ERR_INVALID_PARAM;

    size_t content_len = writer->pos - (seq->length + 4);
    uint8_t len_buf[4];
    size_t len_bytes;

    if (content_len < 0x80) {
        len_bytes = 1;
        len_buf[0] = (uint8_t)content_len;
    } else if (content_len <= 0xFF) {
        len_bytes = 2;
        len_buf[0] = 0x81;
        len_buf[1] = (uint8_t)content_len;
    } else if (content_len <= 0xFFFF) {
        len_bytes = 3;
        len_buf[0] = 0x82;
        len_buf[1] = (uint8_t)(content_len >> 8);
        len_buf[2] = (uint8_t)(content_len & 0xFF);
    } else {
        len_bytes = 4;
        len_buf[0] = 0x83;
        len_buf[1] = (uint8_t)(content_len >> 16);
        len_buf[2] = (uint8_t)(content_len >> 8);
        len_buf[3] = (uint8_t)(content_len & 0xFF);
    }

    if (len_bytes < 4) {
        size_t src = seq->length + 4;
        size_t dst = seq->length + len_bytes;
        size_t move_len = writer->pos - src;
        if (move_len > 0) {
            memmove(writer->data + dst, writer->data + src, move_len);
        }
        writer->pos -= (4 - len_bytes);
    }
    memcpy(writer->data + seq->length, len_buf, len_bytes);
    return SDC_ERR_OK;
}

int sdc_asn1_write_set_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set) {
    if (writer->error) return SDC_ERR_ASN1_WRITE_ERROR;

    set->data = writer->data;
    set->pos = writer->pos;
    set->length = 0;
    set->error = 0;

    int ret = write_byte(writer, ASN1_TAG_SET);
    if (ret != SDC_ERR_OK) return ret;
    set->length = writer->pos;
    for (int i = 0; i < 4; i++) {
        ret = write_byte(writer, 0x00);
        if (ret != SDC_ERR_OK) return ret;
    }
    return SDC_ERR_OK;
}

int sdc_asn1_write_set_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set) {
    return sdc_asn1_write_sequence_end(writer, set);
}

/* ============================================================
   Write UTCTime
   ============================================================ */
int sdc_asn1_write_utctime(sdc_asn1_writer_t *writer, uint64_t timestamp) {
    uint8_t buf[13];
    int year, month, day, hour, min, sec;
    int ret;

    uint64_t t = timestamp;
    sec = t % 60; t /= 60;
    min = t % 60; t /= 60;
    hour = t % 24; t /= 24;

    int y = 1970;
    while (t >= (uint64_t)days_in_year(y)) {
        t -= days_in_year(y);
        y++;
    }
    year = y % 100;

    int m;
    for (m = 1; m <= 12; m++) {
        int dim = days_in_month(y, m);
        if (t < (uint64_t)dim) break;
        t -= dim;
    }
    month = m;
    day = (int)t + 1;

    format_utctime(buf, year, month, day, hour, min, sec);
    ret = sdc_asn1_write_tag(writer, ASN1_TAG_UTC_TIME, 13);
    if (ret != SDC_ERR_OK) return ret;
    return write_bytes(writer, buf, 13);
}

/* ============================================================
   Write EXPLICIT tag
   ============================================================ */
int sdc_asn1_write_explicit_tag(sdc_asn1_writer_t *writer,
                                uint8_t tag, size_t len)
{
    int ret = write_byte(writer, tag);
    if (ret != SDC_ERR_OK) return ret;

    if (len < 0x80) {
        ret = write_byte(writer, (uint8_t)len);
    } else {
        ret = write_byte(writer, 0x81);
        if (ret != SDC_ERR_OK) return ret;
        ret = write_byte(writer, (uint8_t)len);
    }
    return ret;
}