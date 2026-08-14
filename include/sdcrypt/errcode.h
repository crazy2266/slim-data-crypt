#ifndef SDC_ERRCODE_H
#define SDC_ERRCODE_H

// ======= General Error Code (0 ~ -9) =======
#define SDC_ERR_OK                         0
#define SDC_ERR_INVALID_PARAM             -1
#define SDC_ERR_NOT_IMPLEMENTED           -2
#define SDC_ERR_RANDOM_FAIL               -3

#define SDC_ERR_INTEGER_GENPRIME_TIMEOUT  -10

#define SDC_ERR_VERIFY_FAIL               -20

#define SDC_ERR_KEY_INVALID               -30
#define SDC_ERR_KEY_SIZE_INVALID          -31

#define SDC_ERR_MEM_ALLOCATE_FAIL         -50
#define SDC_ERR_BUFFER_TOO_SMALL          -51

#endif /* SDC_ERRCODE_H */