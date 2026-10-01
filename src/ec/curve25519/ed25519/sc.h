#ifndef SDC_ED25519_SC_H
#define SDC_ED25519_SC_H

#define ED25519_SC(name) _sdc_ed25519_sc_##name
#define sc_reduce  ED25519_SC(reduce)
#define sc_muladd  ED25519_SC(muladd)

void sc_reduce(unsigned char *s);
void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);

#endif
