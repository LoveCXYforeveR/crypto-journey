/*
 * SM4 (GB/T 32907-2016) — C reference implementation.
 *
 * 与 ../src/sm4.py 一比一对齐。常量来自 constants.h（由 work/gen_constants.py
 * 从 src/sm4.py 自动生成，禁止手改）。
 *
 * 第一版不做任何优化：无 T-table、无向量化、无内联汇编。
 * 唯一的两个可观测旋钮就是「是否预计算轮密钥」。
 */
#include "sm4.h"
#include "constants.h"

/* ---------- 内部基础运算 ---------- */

static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* τ: 32 位字拆 4 字节过 S 盒再拼回（与 Python _tau 相同）。 */
static inline uint32_t tau(uint32_t x)
{
    return ((uint32_t)SBOX[(x >> 24) & 0xFF] << 24)
         | ((uint32_t)SBOX[(x >> 16) & 0xFF] << 16)
         | ((uint32_t)SBOX[(x >>  8) & 0xFF] <<  8)
         | ((uint32_t)SBOX[ x        & 0xFF]);
}

/* 加密轮线性变换 L(B) = B ^ rotl(B,2) ^ rotl(B,10) ^ rotl(B,18) ^ rotl(B,24)。 */
static inline uint32_t L(uint32_t b)
{
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

/* 密钥扩展线性变换 L'(B) = B ^ rotl(B,13) ^ rotl(B,23)。
 * 注意：与加密轮的 L 不一样，抄错必炸（见手册排查表第 4 条）。 */
static inline uint32_t Lp(uint32_t b)
{
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}

/* 大端读 4 字节为 uint32_t。 */
static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         | ((uint32_t)p[3]);
}

/* 大端写 uint32_t 到 4 字节。 */
static inline void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

/* ---------- 公开接口 ---------- */

void sm4_key_schedule(const uint8_t key[SM4_KEY_SIZE],
                     uint32_t      rks[SM4_ROUNDS])
{
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = load_be32(key + i * 4) ^ FK[i];
    }
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t t  = Lp(tau(k[1] ^ k[2] ^ k[3] ^ CK[i]));
        uint32_t rk = k[0] ^ t;
        rks[i] = rk;
        /* k <- (k1, k2, k3, rk)，等价于 Python 的元组同时赋值。 */
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = rk;
    }
}

void sm4_crypt_block_rks(const uint32_t rks[SM4_ROUNDS],
                         const uint8_t in[SM4_BLOCK_SIZE],
                         uint8_t       out[SM4_BLOCK_SIZE])
{
    uint32_t x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = load_be32(in + i * 4);
    }
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t t     = L(tau(x[1] ^ x[2] ^ x[3] ^ rks[i]));
        uint32_t x_new = x[0] ^ t;
        /* x <- (x1, x2, x3, x0 ^ t)。必须用临时量，不能顺序覆盖。 */
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = x_new;
    }
    /* 32 轮后按 X[35], X[34], X[33], X[32] 反序拼回（与 Python 一致）。 */
    store_be32(out +  0, x[3]);
    store_be32(out +  4, x[2]);
    store_be32(out +  8, x[1]);
    store_be32(out + 12, x[0]);
}

void sm4_encrypt_block(const uint8_t key[SM4_KEY_SIZE],
                      const uint8_t in[SM4_BLOCK_SIZE],
                      uint8_t       out[SM4_BLOCK_SIZE])
{
    uint32_t rks[SM4_ROUNDS];
    sm4_key_schedule(key, rks);
    sm4_crypt_block_rks(rks, in, out);
}

void sm4_decrypt_block(const uint8_t key[SM4_KEY_SIZE],
                      const uint8_t in[SM4_BLOCK_SIZE],
                      uint8_t       out[SM4_BLOCK_SIZE])
{
    uint32_t rks[SM4_ROUNDS];
    uint32_t rev[SM4_ROUNDS];
    sm4_key_schedule(key, rks);
    for (int i = 0; i < SM4_ROUNDS; i++) {
        rev[i] = rks[SM4_ROUNDS - 1 - i];
    }
    sm4_crypt_block_rks(rev, in, out);
}
