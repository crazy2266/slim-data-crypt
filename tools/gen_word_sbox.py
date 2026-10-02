#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Generate a 32-bit word-parallel (4 bytes in a uint32_t) constant-time SM4 S-box,
# derived from the verified bitsliced circuit constants.
#
import sys

# ---- constants from sm4_sbox_bitsliced_derive.py (verified) ----
A1p = [0x9e,0x98,0xcc,0x89,0x91,0x82,0xe2,0x53]
C1p = 0xa3
A2p = [0xcb,0x71,0x4e,0xb0,0x49,0x9e,0x79,0xd3]
C2p = 0xd3
LAM = 0xc

def gmul4(a,b,poly=0x13):
    p=0
    for _ in range(4):
        if b&1: p^=a
        hi=a&0x8; a=(a<<1)&0xF
        if hi: a^=(poly&0xF)
        b>>=1
    return p

SQ4_basis=[gmul4(1<<i,1<<i) for i in range(4)]
LAMMUL_basis=[gmul4(1<<i,LAM) for i in range(4)]
mult_terms={k:[] for k in range(4)}
for i in range(4):
    for j in range(4):
        pr=gmul4(1<<i,1<<j)
        for k in range(4):
            if (pr>>k)&1: mult_terms[k].append((i,j))

INV4=[0]*16
for a in range(1,16):
    for b in range(1,16):
        if gmul4(a,b)==1: INV4[a]=b; break
def anf_coeffs(func,nbits):
    size=1<<nbits; ob=[]
    for b in range(nbits):
        f=[(func[x]>>b)&1 for x in range(size)]; g=f[:]
        for i in range(nbits):
            for x in range(size):
                if x&(1<<i): g[x]^=g[x^(1<<i)]
        ob.append(g)
    return ob
inv_anf=anf_coeffs(INV4,4)

# ---- generate C for one 32-bit word (4 bytes in parallel) ----
M=0x01010101
lines=[]
lines.append("/*")
lines.append(" * Constant-time SM4 S-box over 4 parallel bytes packed in a uint32_t.")
lines.append(" * Byte j lives in bits [8j, 8j+7]; a bit-plane is (x>>k)&0x01010101.")
lines.append(" * Pure boolean circuit (AND/XOR/NOT), no table lookups, no branches.")
lines.append(" * Derived from the verified bitsliced SM4 S-box circuit.")
lines.append(" */")
lines.append("static uint32_t sm4_sbox_word(uint32_t x) {")
lines.append("    uint32_t p0,p1,p2,p3,p4,p5,p6,p7;")
lines.append("    uint32_t c0,c1,c2,c3,c4,c5,c6,c7;")
lines.append("    uint32_t h0,h1,h2,h3,l0,l1,l2,l3;")
lines.append("    uint32_t hh0,hh1,hh2,hh3,ll0,ll1,ll2,ll3;")
lines.append("    uint32_t hhlam0,hhlam1,hhlam2,hhlam3;")
lines.append("    uint32_t hl0,hl1,hl2,hl3,d0,d1,d2,d3;")
lines.append("    uint32_t dinv0,dinv1,dinv2,dinv3;")
lines.append("    uint32_t nh0,nh1,nh2,nh3,hxl0,hxl1,hxl2,hxl3;")
lines.append("    uint32_t nl0,nl1,nl2,nl3,o0,o1,o2,o3,o4,o5,o6,o7;")
lines.append("    uint32_t q0,q1,q2,q3,q4,q5,q6,q7;")
lines.append("")
for k in range(8):
    # matches the reference: p0 <- x[7] (LSB plane), p7 <- x[0] (MSB plane)
    shift = k
    if shift == 0:
        lines.append(f"    p{k} = x & 0x01010101;")
    else:
        lines.append(f"    p{k} = (x >> {shift}) & 0x01010101;")
lines.append("")
lines.append("    /* pre-affine A1' + C1' -> composite element (h,l) */")
# A1p basis: A1p[j] bit i determines c_i contribution of p_j; C1p bit i is const
for i in range(8):
    terms=[f"p{j}" for j in range(8) if (A1p[j]>>i)&1]
    const=(C1p>>i)&1
    expr=" ^ ".join(terms) if terms else "0"
    if const:
        expr=f"~({expr}) & 0x01010101" if terms else "0x01010101"
    lines.append(f"    c{i} = {expr};")
lines.append("")
lines.append("    h0 = c4; h1 = c5; h2 = c6; h3 = c7;")
lines.append("    l0 = c0; l1 = c1; l2 = c2; l3 = c3;")
lines.append("")
def lin_expr(base, terms_list, masks):
    if not terms_list: return "0"
    return " ^ ".join(f"{base}{j}" for j in terms_list)
# hh = h^2
for i in range(4):
    ts=[j for j in range(4) if (SQ4_basis[j]>>i)&1]
    lines.append(f"    hh{i} = {lin_expr('h',ts,None) if ts else '0'};")
for i in range(4):
    ts=[j for j in range(4) if (SQ4_basis[j]>>i)&1]
    lines.append(f"    ll{i} = {lin_expr('l',ts,None) if ts else '0'};")
lines.append("")
for i in range(4):
    ts=[j for j in range(4) if (LAMMUL_basis[j]>>i)&1]
    lines.append(f"    hhlam{i} = {lin_expr('hh',ts,None) if ts else '0'};")
lines.append("")
for k in range(4):
    terms=" ^ ".join(f"(h{i} & l{j})" for (i,j) in mult_terms[k])
    lines.append(f"    hl{k} = {terms if terms else '0'};")
lines.append("")
for i in range(4):
    lines.append(f"    d{i} = hhlam{i} ^ hl{i} ^ ll{i};")
lines.append("")
for b in range(4):
    parts=[]; const=False
    for mask in range(16):
        if inv_anf[b][mask]:
            if mask==0: const=True; continue
            factors=" & ".join(f"d{ii}" for ii in range(4) if (mask>>ii)&1)
            parts.append(f"({factors})")
    expr=" ^ ".join(parts) if parts else "0"
    if const:
        expr = expr+" ^ 0x01010101" if parts else "0x01010101"
    lines.append(f"    dinv{b} = {expr};")
lines.append("")
for k in range(4):
    lines.append(f"    nh{k} = {' ^ '.join(f'(h{i} & dinv{j})' for (i,j) in mult_terms[k]) or '0'};")
lines.append("")
for i in range(4):
    lines.append(f"    hxl{i} = h{i} ^ l{i};")
lines.append("")
for k in range(4):
    lines.append(f"    nl{k} = {' ^ '.join(f'(hxl{i} & dinv{j})' for (i,j) in mult_terms[k]) or '0'};")
lines.append("")
lines.append("    o0 = nl0; o1 = nl1; o2 = nl2; o3 = nl3;")
lines.append("    o4 = nh0; o5 = nh1; o6 = nh2; o7 = nh3;")
lines.append("")
for i in range(8):
    terms=[f"o{j}" for j in range(8) if (A2p[j]>>i)&1]
    const=(C2p>>i)&1
    expr=" ^ ".join(terms) if terms else "0"
    if const:
        expr=f"~({expr}) & 0x01010101" if terms else "0x01010101"
    lines.append(f"    q{i} = {expr};")
lines.append("")
lines.append("    return (q7 << 7) | (q6 << 6) | (q5 << 5) | (q4 << 4)")
lines.append("         | (q3 << 3) | (q2 << 2) | (q1 << 1) |  q0;")
lines.append("}")
open("./sm4_sbox_word_generated.c","w").write("\n".join(lines)+"\n")
print("wrote", len(lines), "lines to sm4_sbox_word_generated.c")

# ---- validate the generated logic in Python (emulate 32-bit word ops) ----
def word_sbox(x):
    # emulate 32-bit, 4 bytes; but test each byte independently
    p=[((x>>k)&M) for k in range(8)]
    def notm(e): return (~e)&M
    c=[0]*8
    for i in range(8):
        terms=[p[j] for j in range(8) if (A1p[j]>>i)&1]
        acc=0
        for t in terms: acc^=t
        if (C1p>>i)&1: acc=notm(acc)
        c[i]=acc
    h=[c[4],c[5],c[6],c[7]]; l=[c[0],c[1],c[2],c[3]]
    def sq(v): return [0,0,0,0] if False else [ (v[0]^v[2]) if i==0 else (v[2] if i==1 else (v[1]^v[3] if i==2 else v[3])) for i in range(4)]
    # use basis-based to be safe:
    def apply_basis(basis, v):
        out=[0]*4
        for i in range(4):
            acc=0
            for j in range(4):
                if (basis[j]>>i)&1: acc^=v[j]
            out[i]=acc
        return out
    hh=apply_basis(SQ4_basis,h); ll=apply_basis(SQ4_basis,l)
    hhlam=apply_basis(LAMMUL_basis,hh)
    def mul(a,b):
        out=[0]*4
        for k in range(4):
            acc=0
            for (i,j) in mult_terms[k]: acc^=(a[i]&b[j])
            out[k]=acc
        return out
    hl=mul(h,l)
    d=[hhlam[i]^hl[i]^ll[i] for i in range(4)]
    def inv4(a):
        out=[0]*4
        for b in range(4):
            acc=0
            for mask in range(16):
                if inv_anf[b][mask]:
                    if mask==0: term=M
                    else:
                        term=M
                        for ii in range(4):
                            if (mask>>ii)&1: term&=a[ii]
                    acc^=term
            out[b]=acc
        return out
    dinv=inv4(d)
    nh=mul(h,dinv); hxl=[h[i]^l[i] for i in range(4)]; nl=mul(hxl,dinv)
    o=nl+nh
    q=[0]*8
    for i in range(8):
        acc=0
        for j in range(8):
            if (A2p[j]>>i)&1: acc^=o[j]
        if (C2p>>i)&1: acc=notm(acc)
        q[i]=acc
    return q

SM4_SBOX = [
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]

# test: byte b -> word = b*0x01010101 (all 4 bytes = b)
bad=0
for b in range(256):
    x=b*0x01010101
    q=word_sbox(x)
    out=0
    for i in range(8):
        out |= ((q[i]&1)<<i)
    if out != SM4_SBOX[b]:
        bad+=1
        if bad<=5: print("MISMATCH", hex(b), hex(out), hex(SM4_SBOX[b]))
print("word-sbox byte0 mismatches:", bad)
