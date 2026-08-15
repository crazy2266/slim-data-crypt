#ifndef SDC_ERRCODE_H
#define SDC_ERRCODE_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
   General Error Codes (0 ~ -99)
   ============================================================ */
#define SDC_ERR_OK                         0
#define SDC_ERR_INVALID_PARAM             -1
#define SDC_ERR_NOT_IMPLEMENTED           -2
#define SDC_ERR_ALREADY_EXISTS            -3
#define SDC_ERR_RANDOM_FAIL               -4
#define SDC_ERR_TIME_FAIL                 -5
#define SDC_ERR_NOT_FOUND                 -6
#define SDC_ERR_NOT_READY                 -7
#define SDC_ERR_UNSUPPORTED               -8

/* ============================================================
   Integer / Prime Generation (-10 ~ -19)
   ============================================================ */
#define SDC_ERR_INTEGER_GENPRIME_TIMEOUT  -10
#define SDC_ERR_INTEGER_DIVIDE_BY_ZERO    -11
#define SDC_ERR_INTEGER_ODD_REQUIRED      -12

/* ============================================================
   Verification (-20 ~ -29)
   ============================================================ */
#define SDC_ERR_VERIFY_FAIL               -20
#define SDC_ERR_SIGNATURE_INVALID         -21

/* ============================================================
   Key Errors (-30 ~ -39)
   ============================================================ */
#define SDC_ERR_KEY_INVALID               -30
#define SDC_ERR_KEY_SIZE_INVALID          -31
#define SDC_ERR_KEY_EXHAUSTED             -32
#define SDC_ERR_KEY_NOT_FOUND             -33

/* ============================================================
   Memory / Buffer (-50 ~ -59)
   ============================================================ */
#define SDC_ERR_MEM_ALLOCATE_FAIL         -50
#define SDC_ERR_BUFFER_TOO_SMALL          -51

/* ============================================================
   ASN.1 Errors (-60 ~ -79)
   ============================================================ */
#define SDC_ERR_ASN1_TRUNCATED            -60
#define SDC_ERR_ASN1_BAD_TAG              -61
#define SDC_ERR_ASN1_BAD_LENGTH           -62
#define SDC_ERR_ASN1_BAD_FORMAT           -63
#define SDC_ERR_ASN1_INTEGER_TOO_LARGE    -64
#define SDC_ERR_ASN1_ENCODE_FAIL          -65
#define SDC_ERR_ASN1_WRITE_ERROR          -66

/* ============================================================
   RSA Errors (-80 ~ -99)
   ============================================================ */
#define SDC_ERR_RSA_PADDING_TOO_SHORT     -80
#define SDC_ERR_RSA_PADDING_INVALID       -81
#define SDC_ERR_RSA_PLAINTEXT_TOO_LONG    -82
#define SDC_ERR_RSA_CIPHERTEXT_INVALID    -83
#define SDC_ERR_RSA_SIG_INVALID           -84
#define SDC_ERR_RSA_PRIVATE_KEY_INVALID   -85
#define SDC_ERR_RSA_PUBLIC_KEY_INVALID    -86

/* ============================================================
   X.509 / Certificate Errors (-100 ~ -119)
   ============================================================ */
#define SDC_ERR_X509_INVALID_CERT         -100
#define SDC_ERR_X509_UNSUPPORTED_ALG      -101
#define SDC_ERR_X509_UNSUPPORTED_VERSION  -102
#define SDC_ERR_X509_CERT_EXPIRED         -103
#define SDC_ERR_X509_CERT_NOT_YET_VALID   -104
#define SDC_ERR_X509_SIGNATURE_FAIL       -105
#define SDC_ERR_X509_SELF_SIGNED_FAIL     -106

#ifdef __cplusplus
}
#endif

#endif /* SDC_ERRCODE_H */