/*
 * SM4 (GB/T 32907-2016) — C reference implementation.
 *
 * 与 ../src/sm4.py 一比一对齐：相同的 S 盒、FK、CK，相同的轮函数，
 * 相同的大端字节序。第一版不做任何优化（无 T-table、无手写 SIMD）。
 *
 * 两个入口：
 *   - sm4_encrypt_block / sm4_decrypt_block
 *       每块内部重新做密钥扩展，与 Python encrypt_block 严格可比。
 *   - sm4_key_schedule + sm4_crypt_block_rks
 *       轮密钥只算一次，可复用在多个 block 上，量化「轮密钥预计算」的收益。
 */
#ifndef SM4_H
#define SM4_H

#include <stdint.h>

#define SM4_BLOCK_SIZE 16   /* 128-bit block */
#define SM4_KEY_SIZE   16   /* 128-bit key   */
#define SM4_ROUNDS     32

/* 每块重算轮密钥（对齐 Python 行为）。 */
void sm4_encrypt_block(const uint8_t key[SM4_KEY_SIZE],
                      const uint8_t in[SM4_BLOCK_SIZE],
                      uint8_t       out[SM4_BLOCK_SIZE]);
void sm4_decrypt_block(const uint8_t key[SM4_KEY_SIZE],
                      const uint8_t in[SM4_BLOCK_SIZE],
                      uint8_t       out[SM4_BLOCK_SIZE]);

/* 轮密钥预计算版：先算一次 rks[32]，再对任意多块复用。 */
void sm4_key_schedule(const uint8_t key[SM4_KEY_SIZE],
                     uint32_t      rks[SM4_ROUNDS]);
void sm4_crypt_block_rks(const uint32_t rks[SM4_ROUNDS],
                         const uint8_t in[SM4_BLOCK_SIZE],
                         uint8_t       out[SM4_BLOCK_SIZE]);

#endif /* SM4_H */
