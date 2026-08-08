#ifndef FE_H
#define FE_H

#include <stdint.h>

typedef uint64_t fe[5];

#define FE25519(name) _x25519_fe_##name
#define fe_0          FE25519(zero)
#define fe_1          FE25519(one)
#define fe_copy       FE25519(copy)
#define fe_cswap      FE25519(cswap)
#define fe_add        FE25519(add)
#define fe_sub        FE25519(sub)
#define fe_mul        FE25519(mul)
#define fe_sq         FE25519(sq)
#define fe_mul121666  FE25519(mul121666)
#define fe_invert     FE25519(invert)
#define fe_frombytes  FE25519(frombytes)
#define fe_tobytes    FE25519(tobytes)

void fe_0(fe h);
void fe_1(fe h);
void fe_copy(fe h, const fe f);
void fe_cswap(fe f, fe g, unsigned ctl);
void fe_add(fe h, const fe f, const fe g);
void fe_sub(fe h, const fe f, const fe g);
void fe_mul(fe h, const fe f, const fe g);
void fe_sq(fe h, const fe f);
void fe_mul121666(fe h, const fe f);
void fe_invert(fe h, const fe f);
void fe_frombytes(fe h, const uint8_t s[32]);
void fe_tobytes(uint8_t s[32], const fe h);

#endif /* FE_H */
