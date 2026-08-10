#include <string.h>
#include "xchacha20.h"
#include "utils.h"

#define ROTL32(x, n) \
    vorrq_u32(vshlq_n_u32(x, n), vshrq_n_u32(x, 32 - n))

#define QR(a, b, c, d) \
    do { \
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = ROTL32(d, 16); \
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = ROTL32(b, 12); \
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = ROTL32(d, 8);  \
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = ROTL32(b, 7);  \
    } while(0)

static void chacha20_4block(uint32x4_t out[16], const uint32x4_t in[16]) {
    int i;
    uint32x4_t x[16];
    
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) {
        out[i] = vaddq_u32(x[i], in[i]);
    }
}

static void next_block(sdc_xchacha20_ctx *ctx) {
    uint32x4_t newlow, carry, out[16];
    chacha20_4block(out, ctx->state);
    for (int j = 0; j < 16; j++) {
        // SoA -> AoS Transformation
        store32_le(ctx->buf + 0 * 64 + j * 4, vgetq_lane_u32(out[j], 0));
        store32_le(ctx->buf + 1 * 64 + j * 4, vgetq_lane_u32(out[j], 1));
        store32_le(ctx->buf + 2 * 64 + j * 4, vgetq_lane_u32(out[j], 2));
        store32_le(ctx->buf + 3 * 64 + j * 4, vgetq_lane_u32(out[j], 3));
    }
    newlow = vaddq_u32(ctx->state[12], vdupq_n_u32(4));
    carry = vshrq_n_u32(vcltq_u32(newlow, ctx->state[12]), 31);
    ctx->state[13] = vaddq_u32(ctx->state[13], carry);
    ctx->state[12] = newlow;
    ctx->buf_used = 0;
}

static void hchacha20(uint32x4_t out[8], const uint32x4_t in[16]) {
    int i;
    uint32x4_t x[16];
    
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    out[0] = x[0];
    out[1] = x[1];
    out[2] = x[2];
    out[3] = x[3];
    out[4] = x[12];
    out[5] = x[13];
    out[6] = x[14];
    out[7] = x[15];
}

void sdc_xchacha20_init(sdc_xchacha20_ctx *ctx, const uint8_t key[32],
                    const uint8_t nonce[24], uint64_t counter) {
    if (!ctx || !key || !nonce) return;
    int i;
    uint32x4_t hkey[8];
    uint32x4_t in[16];
    
    // 常量
    in[0] = vdupq_n_u32(0x61707865);
    in[1] = vdupq_n_u32(0x3320646e);
    in[2] = vdupq_n_u32(0x79622d32);
    in[3] = vdupq_n_u32(0x6b206574);
    
    // 密钥
    for (i = 0; i < 8; i++) {
        in[i + 4] = vdupq_n_u32(load32_le(key + 4 * i));
    }
    
    // Nonce 前 12 字节
    in[12] = vdupq_n_u32(load32_le(nonce));
    in[13] = vdupq_n_u32(load32_le(nonce + 4));
    in[14] = vdupq_n_u32(load32_le(nonce + 8));
    in[15] = vdupq_n_u32(load32_le(nonce + 12));
    
    hchacha20(hkey, in);
    
    // 设置状态
    ctx->state[0] = vdupq_n_u32(0x61707865);
    ctx->state[1] = vdupq_n_u32(0x3320646e);
    ctx->state[2] = vdupq_n_u32(0x79622d32);
    ctx->state[3] = vdupq_n_u32(0x6b206574);
    
    for (i = 0; i < 8; i++) {
        ctx->state[i + 4] = hkey[i];
    }
    
    // 4个并行块的计数器
    uint32_t state12[4] = {
        (uint32_t)(counter),
        (uint32_t)(counter + 1),
        (uint32_t)(counter + 2),
        (uint32_t)(counter + 3)
    };
    uint32_t state13[4] = {
        (uint32_t)(counter >> 32),
        (uint32_t)((counter + 1) >> 32),
        (uint32_t)((counter + 2) >> 32),
        (uint32_t)((counter + 3) >> 32)
    };
    
    ctx->state[12] = vld1q_u32(state12);
    ctx->state[13] = vld1q_u32(state13);
    ctx->state[14] = vdupq_n_u32(load32_le(nonce + 16));
    ctx->state[15] = vdupq_n_u32(load32_le(nonce + 20));
    ctx->buf_used = 256;
}

void sdc_xchacha20_crypt(sdc_xchacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !in || !out || len == 0) return;
    
    size_t i = 0;
    while (i < len) {
        if (ctx->buf_used >= 256) {
            next_block(ctx);
        }
        
        size_t available = 256 - ctx->buf_used;
        size_t remaining = len - i;
        size_t n = (available > remaining) ? remaining : available;
        
        while (n >= 64) {
            // 直接加载 64 字节密钥流和明文
            uint8x16x4_t key = vld1q_u8_x4(ctx->buf + ctx->buf_used);
            uint8x16x4_t data = vld1q_u8_x4(in + i);
            
            // 异或
            uint8x16x4_t result;
            result.val[0] = veorq_u8(key.val[0], data.val[0]);
            result.val[1] = veorq_u8(key.val[1], data.val[1]);
            result.val[2] = veorq_u8(key.val[2], data.val[2]);
            result.val[3] = veorq_u8(key.val[3], data.val[3]);
            
            // 写回
            vst1q_u8_x4(out + i, result);
            
            i += 64;
            ctx->buf_used += 64;
            n -= 64;
        }
        
        // ===== 处理剩余 16 字节 =====
        while (n >= 16) {
            uint8x16_t key = vld1q_u8(ctx->buf + ctx->buf_used);
            uint8x16_t data = vld1q_u8(in + i);
            vst1q_u8(out + i, veorq_u8(key, data));
            i += 16;
            ctx->buf_used += 16;
            n -= 16;
        }
        
        // ===== 处理零头（< 16 字节） =====
        while (n) {
            out[i] = in[i] ^ ctx->buf[ctx->buf_used];
            i++;
            ctx->buf_used++;
            n--;
        }
    }
}