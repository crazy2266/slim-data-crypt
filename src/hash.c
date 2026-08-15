#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <string.h>

static void sha224_init_wrap(void *ctx) {
    sdc_sha224_init((sdc_sha256_ctx *)ctx);
}
static void sha224_update_wrap(void *ctx, const uint8_t *data, size_t len) {
    sdc_sha224_update((sdc_sha256_ctx *)ctx, data, len);
}
static void sha224_final_wrap(void *ctx, uint8_t *out) {
    sdc_sha224_final((sdc_sha256_ctx *)ctx, out);
}
static void sha224_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha224_hash(out, in, len);
}

static void sha256_init_wrap(void *ctx) {
    sdc_sha256_init((sdc_sha256_ctx *)ctx);
}
static void sha256_update_wrap(void *ctx, const uint8_t *data, size_t len) {
    sdc_sha256_update((sdc_sha256_ctx *)ctx, data, len);
}
static void sha256_final_wrap(void *ctx, uint8_t *out) {
    sdc_sha256_final((sdc_sha256_ctx *)ctx, out);
}
static void sha256_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha256_hash(out, in, len);
}

static void sha384_init_wrap(void *ctx) {
    sdc_sha384_init((sdc_sha512_ctx *)ctx);
}
static void sha384_update_wrap(void *ctx, const uint8_t *data, size_t len) {
    sdc_sha384_update((sdc_sha512_ctx *)ctx, data, len);
}
static void sha384_final_wrap(void *ctx, uint8_t *out) {
    sdc_sha384_final((sdc_sha512_ctx *)ctx, out);
}
static void sha384_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha384_hash(out, in, len);
}

static void sha512_init_wrap(void *ctx) {
    sdc_sha512_init((sdc_sha512_ctx *)ctx);
}
static void sha512_update_wrap(void *ctx, const uint8_t *data, size_t len) {
    sdc_sha512_update((sdc_sha512_ctx *)ctx, data, len);
}
static void sha512_final_wrap(void *ctx, uint8_t *out) {
    sdc_sha512_final((sdc_sha512_ctx *)ctx, out);
}
static void sha512_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha512_hash(out, in, len);
}

/* ============================================================
   Global hash algorithm table (read-only, accessed directly by index)
   ============================================================ */
static const sdc_hash_ops_t hash_ops_table[SDC_HASH_COUNT] = {
    [SDC_HASH_NONE] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "NONE"
    },
    [SDC_HASH_SHA224] = {
        .init = sha224_init_wrap,
        .update = sha224_update_wrap,
        .final = sha224_final_wrap,
        .hash = sha224_hash_wrap,
        .hash_len = 28,
        .name = "SHA-224"
    },
    [SDC_HASH_SHA256] = {
        .init = sha256_init_wrap,
        .update = sha256_update_wrap,
        .final = sha256_final_wrap,
        .hash = sha256_hash_wrap,
        .hash_len = 32,
        .name = "SHA-256"
    },
    [SDC_HASH_SHA384] = {
        .init = sha384_init_wrap,
        .update = sha384_update_wrap,
        .final = sha384_final_wrap,
        .hash = sha384_hash_wrap,
        .hash_len = 48,
        .name = "SHA-384"
    },
    [SDC_HASH_SHA512] = {
        .init = sha512_init_wrap,
        .update = sha512_update_wrap,
        .final = sha512_final_wrap,
        .hash = sha512_hash_wrap,
        .hash_len = 64,
        .name = "SHA-512"
    }
};

/* ============================================================
   Thread-local storage: current thread hash algorithm ID
   ============================================================ */
static __thread sdc_hash_id_t current_hash_id = SDC_HASH_SHA256;

/* ============================================================
   API implementation
   ============================================================ */

void sdc_hash_thread_init(void) {
    current_hash_id = SDC_HASH_SHA256;
}

void sdc_hash_thread_set(sdc_hash_id_t id) {
    if (id > SDC_HASH_NONE && id < SDC_HASH_COUNT) {
        current_hash_id = id;
    }
}

sdc_hash_id_t sdc_hash_thread_get(void) {
    return current_hash_id;
}

const sdc_hash_ops_t *sdc_hash_get_ops(sdc_hash_id_t id) {
    if (id <= SDC_HASH_NONE || id >= SDC_HASH_COUNT) {
        return NULL;
    }
    return &hash_ops_table[id];
}

void sdc_hash_compute(const uint8_t *in, size_t in_len, uint8_t *out) {
    const sdc_hash_ops_t *ops = &hash_ops_table[current_hash_id];
    if (ops && ops->hash) {
        ops->hash(out, in, in_len);
    }
}

void sdc_hash_compute_with(sdc_hash_id_t id,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out) {
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    if (ops && ops->hash) {
        ops->hash(out, in, in_len);
    }
}

size_t sdc_hash_current_len(void) {
    const sdc_hash_ops_t *ops = &hash_ops_table[current_hash_id];
    return ops ? ops->hash_len : 0;
}

size_t sdc_hash_len(sdc_hash_id_t id) {
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    return ops ? ops->hash_len : 0;
}