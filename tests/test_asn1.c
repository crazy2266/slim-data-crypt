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

static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* ============================================================
   Reader 测试辅助
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

static int test_read_oid(const uint8_t *der, size_t len, const uint8_t *expected, size_t expected_len) {
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

static int test_read_sequence(const uint8_t *der, size_t len, size_t expected_content_len) {
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
       Encoder Tests (复用之前的)
       ============================================================ */

    /* BOOLEAN */
    TEST_START("ENCODER: BOOLEAN");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_boolean(&writer, 1);
    TEST_ASSERT(writer.pos == 3 && buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 0xFF, "TRUE -> 01 01 FF");

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_boolean(&writer, 0);
    TEST_ASSERT(writer.pos == 3 && buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 0x00, "FALSE -> 01 01 00");

    /* NULL */
    TEST_START("ENCODER: NULL");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_null(&writer);
    TEST_ASSERT(writer.pos == 2 && buf[0] == 0x05 && buf[1] == 0x00, "NULL -> 05 00");

    /* INTEGER */
    TEST_START("ENCODER: INTEGER");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0);
    TEST_ASSERT(writer.pos == 3 && buf[0] == 0x02 && buf[1] == 0x01 && buf[2] == 0x00, "0 -> 02 01 00");

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0x12345678);
    TEST_ASSERT(writer.pos == 6 &&
                buf[0] == 0x02 && buf[1] == 0x04 &&
                buf[2] == 0x12 && buf[3] == 0x34 &&
                buf[4] == 0x56 && buf[5] == 0x78,
                "0x12345678 -> 02 04 12 34 56 78");

    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_integer_u64(&writer, 0x80);
    TEST_ASSERT(writer.pos == 4 &&
                buf[0] == 0x02 && buf[1] == 0x02 &&
                buf[2] == 0x00 && buf[3] == 0x80,
                "0x80 -> 02 02 00 80");

    /* OCTET STRING */
    TEST_START("ENCODER: OCTET STRING");
    const uint8_t octet_data[] = {0x01, 0x02, 0x03, 0x04};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_octet_string(&writer, octet_data, 4);
    TEST_ASSERT(writer.pos == 6 &&
                buf[0] == 0x04 && buf[1] == 0x04 &&
                buf[2] == 0x01 && buf[3] == 0x02 &&
                buf[4] == 0x03 && buf[5] == 0x04,
                "OCTET STRING -> 04 04 01 02 03 04");

    /* OID */
    TEST_START("ENCODER: OID");
    const uint8_t sha256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    TEST_ASSERT(writer.pos == 11 &&
                buf[0] == 0x06 && buf[1] == 0x09,
                "OID -> 06 09 ...");

    /* SEQUENCE */
    TEST_START("ENCODER: SEQUENCE");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_writer_t seq;
    sdc_asn1_write_sequence_begin(&writer, &seq);
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_boolean(&writer, 1);
    sdc_asn1_write_sequence_end(&writer, &seq);
    TEST_ASSERT(writer.pos == 7 &&
                buf[0] == 0x30 && buf[1] == 0x05 &&
                buf[2] == 0x05 && buf[3] == 0x00 &&
                buf[4] == 0x01 && buf[5] == 0x01 && buf[6] == 0xFF,
                "SEQUENCE { NULL, TRUE } -> 30 05 05 00 01 01 FF");

    /* UTCTime */
    TEST_START("ENCODER: UTCTime");
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_utctime(&writer, 1735689600ULL); /* 2025-01-01 00:00:00 UTC */
    TEST_ASSERT(writer.pos == 15 &&
                buf[0] == 0x17 && buf[1] == 0x0D &&
                buf[2] == '2' && buf[3] == '5' &&
                buf[14] == 'Z',
                "UTCTime 2025-01-01 -> 17 0D 32 35 30 31 30 31 30 30 30 30 30 30 5A");

    /* BIT STRING */
    TEST_START("ENCODER: BIT STRING");
    const uint8_t bit_data[] = {0xAA, 0x55};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_bit_string(&writer, bit_data, 2, 0);
    TEST_ASSERT(writer.pos == 5 &&
                buf[0] == 0x03 && buf[1] == 0x03 &&
                buf[2] == 0x00 && buf[3] == 0xAA && buf[4] == 0x55,
                "BIT STRING -> 03 03 00 AA 55");

    /* DigestInfo */
    TEST_START("ENCODER: DigestInfo");
    const uint8_t hash[32] = {0};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_writer_t outer, inner;
    sdc_asn1_write_sequence_begin(&writer, &outer);
    sdc_asn1_write_sequence_begin(&writer, &inner);
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_sequence_end(&writer, &inner);
    sdc_asn1_write_octet_string(&writer, hash, 32);
    sdc_asn1_write_sequence_end(&writer, &outer);
    TEST_ASSERT(writer.pos > 50, "DigestInfo 长度合理");

    /* SPKI */
    TEST_START("ENCODER: SPKI");
    const uint8_t rsa_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    const uint8_t pubkey[] = {0x00, 0x01, 0x02, 0x03, 0x04};
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_sequence_begin(&writer, &outer);
    sdc_asn1_write_sequence_begin(&writer, &inner);
    sdc_asn1_write_oid(&writer, rsa_oid, sizeof(rsa_oid));
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_sequence_end(&writer, &inner);
    sdc_asn1_write_bit_string(&writer, pubkey, sizeof(pubkey), 0);
    sdc_asn1_write_sequence_end(&writer, &outer);
    TEST_ASSERT(writer.pos > 20, "SPKI 编码成功");

    /* ============================================================
       Parser Tests
       ============================================================ */

    /* Parser: BOOLEAN */
    TEST_START("PARSER: BOOLEAN");
    uint8_t der_bool_true[] = {0x01, 0x01, 0xFF};
    uint8_t der_bool_false[] = {0x01, 0x01, 0x00};
    TEST_ASSERT(test_read_boolean(der_bool_true, 3, 1), "TRUE 解析成功");
    TEST_ASSERT(test_read_boolean(der_bool_false, 3, 0), "FALSE 解析成功");

    /* Parser: NULL */
    TEST_START("PARSER: NULL");
    uint8_t der_null[] = {0x05, 0x00};
    sdc_asn1_reader_t reader;
    sdc_asn1_reader_init(&reader, der_null, 2);
    TEST_ASSERT(sdc_asn1_read_null(&reader) == SDC_ERR_OK, "NULL 解析成功");

    /* Parser: INTEGER */
    TEST_START("PARSER: INTEGER");
    uint8_t der_int_0[] = {0x02, 0x01, 0x00};
    uint8_t der_int_12345678[] = {0x02, 0x04, 0x12, 0x34, 0x56, 0x78};
    uint8_t der_int_80[] = {0x02, 0x02, 0x00, 0x80};
    TEST_ASSERT(test_read_integer_u64(der_int_0, 3, 0), "INTEGER 0 解析成功");
    TEST_ASSERT(test_read_integer_u64(der_int_12345678, 6, 0x12345678), "INTEGER 0x12345678 解析成功");
    TEST_ASSERT(test_read_integer_u64(der_int_80, 4, 0x80), "INTEGER 0x80 解析成功");

    /* Parser: OID */
    TEST_START("PARSER: OID");
    uint8_t der_oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    TEST_ASSERT(test_read_oid(der_oid, sizeof(der_oid), sha256_oid, sizeof(sha256_oid)),
                "SHA-256 OID 解析成功");

    /* Parser: OCTET STRING */
    TEST_START("PARSER: OCTET STRING");
    uint8_t der_octet[] = {0x04, 0x04, 0x01, 0x02, 0x03, 0x04};
    TEST_ASSERT(test_read_octet_string(der_octet, 6, octet_data, 4),
                "OCTET STRING 解析成功");

    /* Parser: BIT STRING */
    TEST_START("PARSER: BIT STRING");
    uint8_t der_bit[] = {0x03, 0x03, 0x00, 0xAA, 0x55};
    TEST_ASSERT(test_read_bit_string(der_bit, 5, bit_data, 2),
                "BIT STRING 解析成功");

    /* Parser: UTCTime */
    TEST_START("PARSER: UTCTime");
    uint8_t der_utctime[] = {0x17, 0x0D, '2','5','0','1','0','1','0','0','0','0','0','0','Z'};
    TEST_ASSERT(test_read_utctime(der_utctime, 15, 1735689600ULL),
                "UTCTime 2025-01-01 解析成功");

    /* Parser: SEQUENCE */
    TEST_START("PARSER: SEQUENCE");
    uint8_t der_seq[] = {0x30, 0x05, 0x05, 0x00, 0x01, 0x01, 0xFF};
    TEST_ASSERT(test_read_sequence(der_seq, 7, 5),
                "SEQUENCE 解析成功 (内容长度 5)");

    /* Parser: 嵌套 SEQUENCE (DigestInfo) */
    TEST_START("PARSER: 嵌套 SEQUENCE");
    /* 用编码器生成 DigestInfo DER */
    sdc_asn1_writer_init(&writer, buf, sizeof(buf));
    sdc_asn1_write_sequence_begin(&writer, &outer);
    sdc_asn1_write_sequence_begin(&writer, &inner);
    sdc_asn1_write_oid(&writer, sha256_oid, sizeof(sha256_oid));
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_sequence_end(&writer, &inner);
    sdc_asn1_write_octet_string(&writer, hash, 32);
    sdc_asn1_write_sequence_end(&writer, &outer);

    sdc_asn1_reader_init(&reader, buf, writer.pos);
    sdc_asn1_reader_t outer_parsed, inner_parsed;
    const uint8_t *data;
    size_t data_len;

    int ret = sdc_asn1_read_sequence(&reader, &outer_parsed);
    if (ret == SDC_ERR_OK) {
        ret = sdc_asn1_read_sequence(&outer_parsed, &inner_parsed);
    }
    uint8_t parsed_oid[32];
    size_t parsed_oid_len = sizeof(parsed_oid);
    if (ret == SDC_ERR_OK) {
        ret = sdc_asn1_read_oid(&inner_parsed, parsed_oid, &parsed_oid_len);
    }
    if (ret == SDC_ERR_OK) {
        ret = sdc_asn1_read_null(&inner_parsed);
    }
    if (ret == SDC_ERR_OK) {
        ret = sdc_asn1_read_octet_string(&outer_parsed, &data, &data_len);
    }
    TEST_ASSERT(ret == SDC_ERR_OK && data_len == 32,
                "嵌套 DigestInfo 解析成功");

    /* ============================================================
       Final result
       ============================================================ */
    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");

    return (test_passed == test_total) ? 0 : 1;
}