/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 encoder(writer) and decoder(reader) functions.
 */

#ifndef SDC_ASN1_H
#define SDC_ASN1_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
   ASN.1 Common Tag
   ============================================================ */

#define ASN1_TAG_BOOLEAN                0x01
#define ASN1_TAG_INTEGER                0x02
#define ASN1_TAG_BIT_STRING             0x03
#define ASN1_TAG_OCTET_STRING           0x04
#define ASN1_TAG_NULL                   0x05
#define ASN1_TAG_OBJECT_ID              0x06
#define ASN1_TAG_UTF8_STRING            0x0C

#define ASN1_TAG_PRINTABLE_STRING       0x13
#define ASN1_TAG_TELETEX_STRING         0x14
#define ASN1_TAG_VIDEOTEX_STRING        0x15
#define ASN1_TAG_IA5_STRING             0x16
#define ASN1_TAG_UTC_TIME               0x17
#define ASN1_TAG_GENERALIZED_TIME       0x18
#define ASN1_TAG_GRAPHIC_STRING         0x19
#define ASN1_TAG_VISIBLE_STRING         0x1A
#define ASN1_TAG_GENERAL_STRING         0x1B
#define ASN1_TAG_UNIVERSAL_STRING       0x1C
#define ASN1_TAG_BMP_STRING             0x1E

#define ASN1_TAG_SEQUENCE               0x30
#define ASN1_TAG_SET                    0x31


/*
 * ASN.1 Writer Structure
 *
 * The writer uses reverse construction:
 *   - data[0 .. length) is the caller-provided buffer.
 *   - pos points to the first byte of the encoded output.
 *   - bytes are added immediately before pos, so pos moves downward.
 *
 * Therefore the final DER object is obtained with:
 *
 *   uint8_t *out = sdc_asn1_writer_data(&writer);
 *   size_t out_len = sdc_asn1_writer_length(&writer);
 *
 * For constructed objects, fields must be written in reverse order.
 */
typedef struct {
    uint8_t *data;
    size_t length;
    size_t pos;
    int error;
} sdc_asn1_writer_t;

/* ASN.1 Reader Structure */
typedef struct {
    const uint8_t *data;
    size_t length;
    size_t pos;
} sdc_asn1_reader_t;

/* ============================================================
   Writer Functions
   ============================================================ */

void sdc_asn1_writer_init(sdc_asn1_writer_t *writer, uint8_t *buf, size_t len);
size_t sdc_asn1_writer_length(const sdc_asn1_writer_t *writer);
uint8_t *sdc_asn1_writer_data(sdc_asn1_writer_t *writer);
int sdc_asn1_writer_has_error(const sdc_asn1_writer_t *writer);

/*
 * Low-level reverse writer primitives.
 *
 * write_bytes() prepends the value bytes. write_tag() and
 * write_explicit_tag() prepend a complete DER tag+length header for
 * an already-written value of 'len' bytes. They must therefore be
 * called AFTER the corresponding value has been written.
 */
int sdc_asn1_write_tag(sdc_asn1_writer_t *writer, uint8_t tag, size_t len);
int sdc_asn1_write_explicit_tag(sdc_asn1_writer_t *writer, uint8_t tag, size_t len);
int sdc_asn1_write_bytes(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len);
int sdc_asn1_write_null(sdc_asn1_writer_t *writer);
int sdc_asn1_write_boolean(sdc_asn1_writer_t *writer, int value);
int sdc_asn1_write_integer(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len);
int sdc_asn1_write_integer_from_words(sdc_asn1_writer_t *writer, const sdc_word_t *data, size_t limbs);
int sdc_asn1_write_integer_u64(sdc_asn1_writer_t *writer, uint64_t value);
int sdc_asn1_write_utf8_string(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len);
int sdc_asn1_write_octet_string(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len);
int sdc_asn1_write_bit_string(sdc_asn1_writer_t *writer, const uint8_t *data, size_t len, uint8_t unused_bits);
int sdc_asn1_write_oid(sdc_asn1_writer_t *writer, const uint8_t *oid, size_t oid_len);
/*
 * BEGIN/END mode is also reverse-written. begin() only records the
 * current position; end() prepends the constructed-object header.
 *
 * Example for final DER order A, B, C:
 *     begin();
 *     write C;
 *     write B;
 *     write A;
 *     end();
 */
/* BEGIN/END Mode - SEQUENCE */
int sdc_asn1_write_sequence_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq);
int sdc_asn1_write_sequence_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *seq);
/* BEGIN/END Mode - SET */
int sdc_asn1_write_set_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set);
int sdc_asn1_write_set_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *set);
/* BEGIN/END Mode - BIT STRING */
int sdc_asn1_write_bit_string_begin(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit);
int sdc_asn1_write_bit_string_end(sdc_asn1_writer_t *writer, sdc_asn1_writer_t *bit);
int sdc_asn1_write_utctime(sdc_asn1_writer_t *writer, uint64_t timestamp);

/* ============================================================
   Reader Functions
   ============================================================ */

void sdc_asn1_reader_init(sdc_asn1_reader_t *reader, const uint8_t *data, size_t length);
int sdc_asn1_peek_tag(const sdc_asn1_reader_t *reader, uint8_t *tag);
int sdc_asn1_read_tag(sdc_asn1_reader_t *reader, uint8_t *tag, size_t *length);
int sdc_asn1_read_sequence(sdc_asn1_reader_t *reader, sdc_asn1_reader_t *seq);
int sdc_asn1_read_set(sdc_asn1_reader_t *reader, sdc_asn1_reader_t *set);
int sdc_asn1_read_integer_to_bytes(sdc_asn1_reader_t *reader, uint8_t *data, size_t *len);
int sdc_asn1_read_integer_to_words(sdc_asn1_reader_t *reader, sdc_word_t *data, size_t *limbs);
int sdc_asn1_read_integer_to_u64(sdc_asn1_reader_t *reader, uint64_t *out);
int sdc_asn1_read_boolean(sdc_asn1_reader_t *reader, int *out);
int sdc_asn1_read_oid(sdc_asn1_reader_t *reader, uint8_t *oid, size_t *oid_len);
int sdc_asn1_read_utf8_string(sdc_asn1_reader_t *reader, const uint8_t **data, size_t *len);
int sdc_asn1_read_octet_string(sdc_asn1_reader_t *reader, const uint8_t **data, size_t *len);
int sdc_asn1_read_bit_string(sdc_asn1_reader_t *reader, const uint8_t **data, size_t *len);
int sdc_asn1_read_null(sdc_asn1_reader_t *reader);
int sdc_asn1_read_utctime(sdc_asn1_reader_t *reader, uint64_t *timestamp);
int sdc_asn1_read_generalized_time(sdc_asn1_reader_t *reader, uint64_t *timestamp);
int sdc_asn1_skip(sdc_asn1_reader_t *reader);
int sdc_asn1_expect_tag(sdc_asn1_reader_t *reader, uint8_t expected_tag);
size_t sdc_asn1_remaining(const sdc_asn1_reader_t *reader);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ASN1_H */
