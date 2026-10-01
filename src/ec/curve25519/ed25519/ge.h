#ifndef SDC_ED25519_GE_H
#define SDC_ED25519_GE_H

#include "fe.h"

#define ED25519_GE(name) _sdc_ed25519_ge_##name

#define ge_p3_tobytes                  ED25519_GE(p3_tobytes)
#define ge_tobytes                     ED25519_GE(tobytes)
#define ge_frombytes_negate_vartime    ED25519_GE(frombytes_negate_vartime)
#define ge_add                         ED25519_GE(add)
#define ge_sub                         ED25519_GE(sub)
#define ge_double_scalarmult_vartime   ED25519_GE(double_scalarmult_vartime)
#define ge_madd                        ED25519_GE(madd)
#define ge_msub                        ED25519_GE(msub)
#define ge_scalarmult_base             ED25519_GE(scalarmult_base)
#define ge_p1p1_to_p2                  ED25519_GE(p1p1_to_p2)
#define ge_p1p1_to_p3                  ED25519_GE(p1p1_to_p3)
#define ge_p2_0                        ED25519_GE(p2_0)
#define ge_p2_dbl                      ED25519_GE(p2_dbl)
#define ge_p3_0                        ED25519_GE(p3_0)
#define ge_p3_dbl                      ED25519_GE(p3_dbl)
#define ge_p3_to_cached                ED25519_GE(p3_to_cached)
#define ge_p3_to_p2                    ED25519_GE(p3_to_p2)

typedef struct { fe X; fe Y; fe Z; } ge_p2;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p1p1;
typedef struct { fe yplusx; fe yminusx; fe xy2d; } ge_precomp;
typedef struct { fe YplusX; fe YminusX; fe Z; fe T2d; } ge_cached;

void ge_p3_tobytes(unsigned char *s, const ge_p3 *h);
void ge_tobytes(unsigned char *s, const ge_p2 *h);
int ge_frombytes_negate_vartime(ge_p3 *h, const unsigned char *s);
void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_double_scalarmult_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b);
void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_scalarmult_base(ge_p3 *h, const unsigned char *a);
void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void ge_p2_0(ge_p2 *h);
void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p);
void ge_p3_0(ge_p3 *h);
void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p);
void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p);

#endif
