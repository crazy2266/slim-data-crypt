# slim-data-crypt

A small, self-contained cryptography library written in portable C99. It is
optimised for ARM64 (using the Crypto Extensions when available) but builds
and runs on any platform, falling back to portable scalar code where there is
no hardware acceleration.

## Supported algorithms

| Area | Algorithms |
|------|------------|
| **Block ciphers** | AES-128/192/256, SM4 — ECB, CBC, CTR, GCM |
| **AEAD** | AES-GCM, SM4-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| **Hash** | SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256, SM3 |
| **MAC / KDF** | HMAC, PBKDF2-HMAC-SHA256 |
| **Public key** | X25519, Ed25519, RSA (keygen, PKCS#1 v1.5 encrypt/sign, OAEP, PSS) |
| **Other** | ASN.1 parse/write, big-integer arithmetic, system / ChaCha20 RNG |

**Hardware acceleration** (runtime-dispatched, portable fallback):

| | x86-64 | ARM64 |
|---|---|---|
| AES | AES-NI | Crypto Extensions (AESE/AESD) |
| GHASH (GCM) | PCLMULQDQ | PMULL |
| ChaCha20 | AVX2 | NEON |

The AES and SM4 S-boxes are also available as **table-free constant-time
implementations** (see [Constant-time backends](#constant-time-backends)).

## Building

    make            # builds the libraries and all tests
    make test       # builds and runs every test program
    make clean      # removes build/, bin/ and lib/

Output:

    lib/libsdcrypt.a          static library
    lib/libsdcrypt.dll        shared library (libsdcrypt.so on Unix)
    lib/libsdcrypt.dll.a      import library (Windows only)
    bin/libsdcrypt.{dll,so}   runtime copy of the shared library
    bin/test_*                test programs (linked against the static library)

On Windows the build uses MinGW/MSYS2 (`mingw32-make`).

## Using the library

    #include <sdcrypt/aes.h>

    uint8_t key[16] = { /* ... */ };
    uint8_t in[16]  = { /* ... */ };
    uint8_t out[16];

    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 16);
    sdc_aes_encrypt_block(&k, in, out);

Link against the static library:

    gcc app.c -Iinclude -Llib -lsdcrypt -lm -lbcrypt -o app     # Windows
    gcc app.c -Iinclude -Llib -lsdcrypt -lrt -lm -o app         # Unix

## The block_cipher abstraction

Block ciphers are exposed through a small operations table
(`sdc_block_cipher_ops_t`), the same pattern used by `sdc_hash_ops_t` and
`sdc_rng_ops_t`. Each backend exports a global `const` instance:

| ops | cipher | key size |
|-----|--------|----------|
| `sdc_aes128_ops` | AES-128 | 16 |
| `sdc_aes192_ops` | AES-192 | 24 |
| `sdc_aes256_ops` | AES-256 | 32 |
| `sdc_sm4_table_ops` | SM4 (table-driven) | 16 |
| `sdc_sm4_ct_ops` | SM4 (constant-time) | 16 |

A context carries an ops pointer plus the key state, and the generic mode
helpers dispatch through it — so any cipher works with CTR and CBC:

    #include <sdcrypt/aes.h>
    #include <sdcrypt/block_cipher.h>

    sdc_block_cipher_ctx ctx;
    sdc_block_cipher_init(&ctx, &sdc_aes128_ops);
    sdc_aes_set_encrypt_key((sdc_aes_key *)ctx.inner_state, key, 16);

    sdc_block_cipher_ctr(&ctx, nonce, in, len, out);         // CTR
    sdc_block_cipher_cbc_encrypt(&ctx, iv, in, len, out);    // CBC

The native APIs (`sdc_aes_*`, `sdc_sm4_*`) remain available for direct use.

## Constant-time backends

The SM4 S-box has a table-free implementation that uses only AND/XOR/NOT on
4 parallel bytes packed in a `uint32_t` — no lookups, no secret-dependent
branches, so it is immune to cache-timing attacks. It is derived from a
GF(2^8) field-tower construction; the derivation and code generator live in
`tools/` and are verified against the official SM4 S-box (GB/T 32907-2016).

Select it with `sdc_sm4_ct_ops` (see above). It is slower than the
table-driven version but safe in a shared/attacker-observable environment.

## Layout

    include/sdcrypt/   public headers
    src/               implementation (grouped by area: aes/, sm4/, gcm/, ...)
    tests/             test and benchmark programs
    tools/             SM4 S-box derivation + generator
    mk/                platform makefile fragments (windows / unix)

## Licence

MIT.
