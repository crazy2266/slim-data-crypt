/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test ASN.1 DER encoder and parser.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/asn1.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/asn1time.h>
#include <sdcrypt/integer.h>
#include "test_common.h"



static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* ============================================================
   Reader test helpers
   ============================================================ */

static int test_read_boolean(const uint8_t *der, size_t len, int expected) {
    sdc_asn1_reader_t reader;
    int value;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_boolean(&reader, &value);
    if (ret != SDC_ERR_OK) return 0;
    return value == expected;
}

static int test_read_integer_u64(const uint8_t *der, size_t len, uint64_t expected) {
    sdc_asn1_reader_t reader;
    uint64_t value;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_integer_to_u64(&reader, &value);
    if (ret != SDC_ERR_OK) return 0;
    return value == expected;
}

static int test_read_oid(const uint8_t *der, size_t len,
                         const uint8_t *expected, size_t expected_len) {
    sdc_asn1_reader_t reader;
    uint8_t oid[32];
    size_t oid_len = sizeof(oid);
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_oid(&reader, oid, &oid_len);
    if (ret != SDC_ERR_OK) return 0;
    return oid_len == expected_len && compare_bytes(oid, expected, oid_len);
}

static int test_read_octet_string(const uint8_t *der, size_t len,
                                  const uint8_t *expected, size_t expected_len) {
    sdc_asn1_reader_t reader;
    const uint8_t *data;
    size_t data_len;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_octet_string(&reader, &data, &data_len);
    if (ret != SDC_ERR_OK) return 0;
    return data_len == expected_len && compare_bytes(data, expected, data_len);
}

static int test_read_bit_string(const uint8_t *der, size_t len,
                                const uint8_t *expected, size_t expected_len) {
    sdc_asn1_reader_t reader;
    const uint8_t *data;
    size_t data_len;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_bit_string(&reader, &data, &data_len);
    if (ret != SDC_ERR_OK) return 0;
    return data_len == expected_len && compare_bytes(data, expected, data_len);
}

static int test_read_utctime(const uint8_t *der, size_t len, uint64_t expected) {
    sdc_asn1_reader_t reader;
    uint64_t ts;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_utctime(&reader, &ts);
    if (ret != SDC_ERR_OK) return 0;
    return ts == expected;
}

static int test_read_sequence(const uint8_t *der, size_t len,
                              size_t expected_content_len) {
    sdc_asn1_reader_t reader;
    sdc_asn1_reader_t seq;
    sdc_asn1_reader_init(&reader, der, len);
    int ret = sdc_asn1_read_sequence(&reader, &seq);
    if (ret != SDC_ERR_OK) return 0;
    return seq.length == expected_content_len;
}

/* ============================================================
   Main
   ============================================================ */

int main(void) {
    uint8_t buf[256];
    sdc_asn1_writer_t writer;

    printf("========================================\n");
    printf("  ASN.1 DER Encoder & Parser Test\n");
    printf("========================================\n");

    /* ============================================================
       Encoder Tests
       ============================================================ */

    T_SECTION("ENCODER: BOOLEAN");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_boolean(&writer, 1);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 3 && out[0] == 0x01 && out[1] == 0x01 && out[2] == 0xFF,
                    "TRUE -> 01 01 FF");
    }

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_boolean(&writer, 0);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 3 && out[0] == 0x01 && out[1] == 0x01 && out[2] == 0x00,
                    "FALSE -> 01 01 00");
    }

    T_SECTION("ENCODER: NULL");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_null(&writer);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 2 && out[0] == 0x05 && out[1] == 0x00,
                    "NULL -> 05 00");
    }

    T_SECTION("ENCODER: INTEGER");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 3 && out[0] == 0x02 && out[1] == 0x01 && out[2] == 0x00,
                    "0 -> 02 01 00");
    }

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0x12345678);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 6 &&
                    out[0] == 0x02 && out[1] == 0x04 &&
                    out[2] == 0x12 && out[3] == 0x34 &&
                    out[4] == 0x56 && out[5] == 0x78,
                    "0x12345678 -> 02 04 12 34 56 78");
    }

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0x80);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 4 &&
                    out[0] == 0x02 && out[1] == 0x02 &&
                    out[2] == 0x00 && out[3] == 0x80,
                    "0x80 -> 02 02 00 80");
    }

    T_SECTION("ENCODER: OCTET STRING");
    const uint8_t octet_data[] = {0x01, 0x02, 0x03, 0x04};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_octet_string(&writer, octet_data, 4);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 6 &&
                    out[0] == 0x04 && out[1] == 0x04 &&
                    out[2] == 0x01 && out[3] == 0x02 &&
                    out[4] == 0x03 && out[5] == 0x04,
                    "OCTET STRING -> 04 04 01 02 03 04");
    }

    T_SECTION("ENCODER: OID");
    const uint8_t sha256_oid[] = {
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    };
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 11 && out[0] == 0x06 && out[1] == 0x09,
                    "OID -> 06 09 ...");
    }

    T_SECTION("ENCODER: SEQUENCE");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_writer_t seq;
    sdc_asn1_write_sequence_begin(&writer, &seq);

    /* Final DER order is NULL, TRUE, so write TRUE first. */
    sdc_asn1_write_boolean(&writer, 1);
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_sequence_end(&writer, &seq);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        const uint8_t expected[] = {
            0x30, 0x05, 0x05, 0x00, 0x01, 0x01, 0xFF
        };
        T_CHECK(len == sizeof(expected) &&
                    compare_bytes(out, expected, sizeof(expected)),
                    "SEQUENCE { NULL, TRUE } -> 30 05 05 00 01 01 FF");
    }

    T_SECTION("ENCODER: UTCTime");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_utctime(&writer, 1735689600ULL);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len == 15 &&
                    out[0] == 0x17 && out[1] == 0x0D &&
                    out[2] == '2' && out[3] == '5' &&
                    out[14] == 'Z',
                    "UTCTime 2025-01-01 -> 17 0D ... 5A");
    }

    T_SECTION("ENCODER: BIT STRING");
    const uint8_t bit_data[] = {0xAA, 0x55};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_bit_string(&writer, bit_data, 2, 0);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        const uint8_t expected[] = {
            0x03, 0x03, 0x00, 0xAA, 0x55
        };
        T_CHECK(len == sizeof(expected) &&
                    compare_bytes(out, expected, sizeof(expected)),
                    "BIT STRING -> 03 03 00 AA 55");
    }

    T_SECTION("ENCODER: DigestInfo");
    const uint8_t hash[32] = {0};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_writer_t outer, inner;
    sdc_asn1_write_sequence_begin(&writer, &outer);

    /* Final order: AlgorithmIdentifier, digest OCTET STRING. */
    sdc_asn1_write_octet_string(&writer, hash, 32);

    sdc_asn1_write_sequence_begin(&writer, &inner);
    /* Final order: OID, NULL. */
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    sdc_asn1_write_sequence_end(&writer, &inner);

    sdc_asn1_write_sequence_end(&writer, &outer);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len > 50 && out != NULL,
                    "DigestInfo encoded successfully");
    }

    T_SECTION("ENCODER: SPKI");
    const uint8_t rsa_oid[] = {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
    };
    const uint8_t pubkey[] = {0x00, 0x01, 0x02, 0x03, 0x04};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_sequence_begin(&writer, &outer);

    /* Final order: AlgorithmIdentifier, subjectPublicKey. */
    sdc_asn1_write_bit_string(&writer, pubkey, sizeof(pubkey), 0);

    sdc_asn1_write_sequence_begin(&writer, &inner);
    /* Final order: RSA OID, NULL. */
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_oid(&writer, rsa_oid, sizeof(rsa_oid));
    sdc_asn1_write_sequence_end(&writer, &inner);

    sdc_asn1_write_sequence_end(&writer, &outer);
    {
        uint8_t *out = sdc_asn1_writer_data(&writer);
        size_t len = sdc_asn1_writer_length(&writer);
        T_CHECK(len > 20 && out != NULL,
                    "SPKI encoded successfully");
    }

    /* ============================================================
       Parser Tests
       ============================================================ */

    T_SECTION("PARSER: BOOLEAN");
    uint8_t der_bool_true[] = {0x01, 0x01, 0xFF};
    uint8_t der_bool_false[] = {0x01, 0x01, 0x00};
    T_CHECK(test_read_boolean(der_bool_true, 3, 1), "TRUE parsed successfully");
    T_CHECK(test_read_boolean(der_bool_false, 3, 0), "FALSE parsed successfully");

    T_SECTION("PARSER: NULL");
    uint8_t der_null[] = {0x05, 0x00};
    sdc_asn1_reader_t reader;
    sdc_asn1_reader_init(&reader, der_null, 2);
    T_CHECK(sdc_asn1_read_null(&reader) == SDC_ERR_OK, "NULL parsed successfully");

    T_SECTION("PARSER: INTEGER");
    uint8_t der_int_0[] = {0x02, 0x01, 0x00};
    uint8_t der_int_12345678[] = {0x02, 0x04, 0x12, 0x34, 0x56, 0x78};
    uint8_t der_int_80[] = {0x02, 0x02, 0x00, 0x80};
    T_CHECK(test_read_integer_u64(der_int_0, 3, 0), "INTEGER 0 parsed successfully");
    T_CHECK(test_read_integer_u64(der_int_12345678, 6, 0x12345678),
                "INTEGER 0x12345678 parsed successfully");
    T_CHECK(test_read_integer_u64(der_int_80, 4, 0x80),
                "INTEGER 0x80 parsed successfully");

    T_SECTION("PARSER: OID");
    uint8_t der_oid[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    };
    T_CHECK(test_read_oid(der_oid, sizeof(der_oid),
                             sha256_oid, sizeof(sha256_oid)),
                "SHA-256 OID parsed successfully");

    T_SECTION("PARSER: OCTET STRING");
    uint8_t der_octet[] = {0x04, 0x04, 0x01, 0x02, 0x03, 0x04};
    T_CHECK(test_read_octet_string(der_octet, 6, octet_data, 4),
                "OCTET STRING parsed successfully");

    T_SECTION("PARSER: BIT STRING");
    uint8_t der_bit[] = {0x03, 0x03, 0x00, 0xAA, 0x55};
    T_CHECK(test_read_bit_string(der_bit, 5, bit_data, 2),
                "BIT STRING parsed successfully");

    T_SECTION("PARSER: UTCTime");
    uint8_t der_utctime[] = {
        0x17, 0x0D, '2','5','0','1','0','1','0','0','0','0','0','0','Z'
    };
    T_CHECK(test_read_utctime(der_utctime, 15, 1735689600ULL),
                "UTCTime 2025-01-01 parsed successfully");

    T_SECTION("PARSER: SEQUENCE");
    uint8_t der_seq[] = {0x30, 0x05, 0x05, 0x00, 0x01, 0x01, 0xFF};
    T_CHECK(test_read_sequence(der_seq, 7, 5),
                "SEQUENCE parsed successfully (content length 5)");

    T_SECTION("PARSER: Nested SEQUENCE");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_sequence_begin(&writer, &outer);
    sdc_asn1_write_octet_string(&writer, hash, 32);
    sdc_asn1_write_sequence_begin(&writer, &inner);
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    sdc_asn1_write_sequence_end(&writer, &inner);
    sdc_asn1_write_sequence_end(&writer, &outer);

    {
        uint8_t *encoded = sdc_asn1_writer_data(&writer);
        size_t encoded_len = sdc_asn1_writer_length(&writer);

        sdc_asn1_reader_init(&reader, encoded, encoded_len);
        sdc_asn1_reader_t outer_parsed, inner_parsed;
        const uint8_t *data;
        size_t data_len;
        uint8_t parsed_oid[32];
        size_t parsed_oid_len = sizeof(parsed_oid);
        int ret = sdc_asn1_read_sequence(&reader, &outer_parsed);

        if (ret == SDC_ERR_OK)
            ret = sdc_asn1_read_sequence(&outer_parsed, &inner_parsed);
        if (ret == SDC_ERR_OK)
            ret = sdc_asn1_read_oid(&inner_parsed, parsed_oid, &parsed_oid_len);
        if (ret == SDC_ERR_OK)
            ret = sdc_asn1_read_null(&inner_parsed);
        if (ret == SDC_ERR_OK)
            ret = sdc_asn1_read_octet_string(&outer_parsed, &data, &data_len);

        T_CHECK(ret == SDC_ERR_OK &&
                    parsed_oid_len == sizeof(sha256_oid) &&
                    compare_bytes(parsed_oid, sha256_oid, sizeof(sha256_oid)) &&
                    data_len == 32 &&
                    sdc_asn1_remaining(&inner_parsed) == 0 &&
                    sdc_asn1_remaining(&outer_parsed) == 0 &&
                    sdc_asn1_remaining(&reader) == 0,
                    "Nested DigestInfo parsed successfully");
    }

    /* ============================================================
       Parser Boundary / DER Canonicality Tests
       ============================================================ */

    T_SECTION("PARSER: DER Length Validation");
    {
        const uint8_t indefinite[] = {0x04, 0x80};
        const uint8_t long_form_short[] = {0x04, 0x81, 0x01, 0xAA};
        const uint8_t leading_zero[] = {0x04, 0x82, 0x00, 0x01, 0xAA};
        sdc_asn1_reader_t r;

        sdc_asn1_reader_init(&r, indefinite, sizeof(indefinite));
        T_CHECK(sdc_asn1_skip(&r) != SDC_ERR_OK,
                    "Indefinite length is rejected");

        sdc_asn1_reader_init(&r, long_form_short, sizeof(long_form_short));
        T_CHECK(sdc_asn1_skip(&r) != SDC_ERR_OK,
                    "Non-minimal long-form length is rejected");

        sdc_asn1_reader_init(&r, leading_zero, sizeof(leading_zero));
        T_CHECK(sdc_asn1_skip(&r) != SDC_ERR_OK,
                    "Length with leading zero is rejected");
    }

    T_SECTION("PARSER: DER INTEGER Validation");
    {
        const uint8_t redundant_zero[] = {0x02, 0x02, 0x00, 0x7F};
        const uint8_t required_zero[] = {0x02, 0x02, 0x00, 0x80};
        sdc_asn1_reader_t r;
        uint64_t value;

        sdc_asn1_reader_init(&r, redundant_zero, sizeof(redundant_zero));
        T_CHECK(sdc_asn1_read_integer_to_u64(&r, &value) != SDC_ERR_OK,
                    "Redundant INTEGER leading zero is rejected");

        sdc_asn1_reader_init(&r, required_zero, sizeof(required_zero));
        T_CHECK(sdc_asn1_read_integer_to_u64(&r, &value) == SDC_ERR_OK &&
                    value == 0x80,
                    "Required INTEGER sign-protection zero is accepted");
    }

    T_SECTION("PARSER: DER BIT STRING Validation");
    {
        const uint8_t empty_nonzero_unused[] = {0x03, 0x01, 0x01};
        const uint8_t nonzero_unused_bits[] = {0x03, 0x02, 0x03, 0xA5};
        const uint8_t valid_unused_bits[] = {0x03, 0x02, 0x03, 0xA0};
        sdc_asn1_reader_t r;
        const uint8_t *data;
        size_t data_len;

        sdc_asn1_reader_init(&r, empty_nonzero_unused, sizeof(empty_nonzero_unused));
        T_CHECK(sdc_asn1_read_bit_string(&r, &data, &data_len) != SDC_ERR_OK,
                    "Empty BIT STRING with unused bits is rejected");

        sdc_asn1_reader_init(&r, nonzero_unused_bits, sizeof(nonzero_unused_bits));
        T_CHECK(sdc_asn1_read_bit_string(&r, &data, &data_len) != SDC_ERR_OK,
                    "Non-zero unused BIT STRING bits are rejected");

        sdc_asn1_reader_init(&r, valid_unused_bits, sizeof(valid_unused_bits));
        T_CHECK(sdc_asn1_read_bit_string(&r, &data, &data_len) == SDC_ERR_OK &&
                    data_len == 1 && data[0] == 0xA0,
                    "Canonical BIT STRING with unused bits is accepted");
    }

    T_SECTION("PARSER: Truncated DER");
    {
        const uint8_t truncated_header[] = {0x04};
        const uint8_t truncated_length[] = {0x04, 0x02, 0xAA};
        const uint8_t truncated_long_length[] = {0x04, 0x82, 0x01};
        sdc_asn1_reader_t r;
        const uint8_t *data;
        size_t data_len;

        sdc_asn1_reader_init(&r, truncated_header, sizeof(truncated_header));
        T_CHECK(sdc_asn1_read_octet_string(&r, &data, &data_len) != SDC_ERR_OK,
                    "Truncated tag/length header is rejected");

        sdc_asn1_reader_init(&r, truncated_length, sizeof(truncated_length));
        T_CHECK(sdc_asn1_read_octet_string(&r, &data, &data_len) != SDC_ERR_OK,
                    "Truncated value is rejected");

        sdc_asn1_reader_init(&r, truncated_long_length, sizeof(truncated_long_length));
        T_CHECK(sdc_asn1_read_octet_string(&r, &data, &data_len) != SDC_ERR_OK,
                    "Truncated long-form length is rejected");
    }

    /* ============================================================
       Final result
       ============================================================ */
    T_SUMMARY();
}
