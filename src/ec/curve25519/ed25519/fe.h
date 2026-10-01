#ifndef SDC_ED25519_FE_H
#define SDC_ED25519_FE_H

#include <stdint.h>

#define ED25519_FE(name) _sdc_ed25519_fe_##name

#define fe_0          ED25519_FE(zero)
#define fe_1          ED25519_FE(one)
#define fe_copy       ED25519_FE(copy)
#define fe_cmov       ED25519_FE(cmov)
#define fe_cswap      ED25519_FE(cswap)
#define fe_neg        ED25519_FE(neg)
#define fe_add        ED25519_FE(add)
#define fe_sub        ED25519_FE(sub)
#define fe_mul        ED25519_FE(mul)
#define fe_sq         ED25519_FE(sq)
#define fe_sq2        ED25519_FE(sq2)
#define fe_mul121666  ED25519_FE(mul121666)
#define fe_invert     ED25519_FE(invert)
#define fe_pow22523   ED25519_FE(pow22523)
#define fe_frombytes  ED25519_FE(frombytes)
#define fe_tobytes    ED25519_FE(tobytes)
#define fe_isnegative ED25519_FE(isnegative)
#define fe_isnonzero  ED25519_FE(isnonzero)

typedef int32_t fe[10];

void fe_0(fe h);
void fe_1(fe h);
void fe_frombytes(fe h, const unsigned char *s);
void fe_tobytes(unsigned char *s, const fe h);
void fe_copy(fe h, const fe f);
int fe_isnegative(const fe f);
int fe_isnonzero(const fe f);
void fe_cmov(fe f, const fe g, unsigned int b);
void fe_cswap(fe f, fe g, unsigned int b);
void fe_neg(fe h, const fe f);
void fe_add(fe h, const fe f, const fe g);
void fe_invert(fe out, const fe z);
void fe_sq(fe h, const fe f);
void fe_sq2(fe h, const fe f);
void fe_mul(fe h, const fe f, const fe g);
void fe_mul121666(fe h, fe f);
void fe_pow22523(fe out, const fe z);
void fe_sub(fe h, const fe f, const fe g);

#endif
