/*
 * test_sm4.c — SM4 C 实现的向量测试。
 *
 * 数据源（与 Python 版同一份）：
 *   ../data/vectors/sm4_vectors.json  —— 两条国标向量
 *   ../work/pairs.json               —— Python 生成的 1000 组随机 block 交叉比对
 *
 * 退出码：全部 PASS = 0；任意一条失败 = 1（CI 据此判红）。
 */
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ---------- 小工具 ---------- */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 把 hex 字符串解码为字节，返回写出的字节数（失败返回 -1）。 */
static int hex_decode(const char *hex, uint8_t *out, int out_cap)
{
    int n = 0;
    while (*hex) {
        while (*hex && isspace((unsigned char)*hex)) hex++;
        if (!*hex) break;
        int hi = hexval((unsigned char)*hex);
        if (hi < 0) return -1;
        hex++;
        while (*hex && isspace((unsigned char)*hex)) hex++;
        if (!*hex) return -1;
        int lo = hexval((unsigned char)*hex);
        if (lo < 0) return -1;
        hex++;
        if (n >= out_cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void hex_encode(const uint8_t *in, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2]     = h[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = h[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}

/* 读整个文件到 malloc 的 buffer（*out_len 为字节数）。失败返回 NULL。 */
static char *slurp_file(const char *path, long *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out_len = (long)rd;
    return buf;
}

/*
 * 在 text 里找 "key": "string"，把字符串内容拷到 out（out_cap 字节）。
 * 返回找到的字符串长度；未找到返回 -1。
 * from_pos：从 text 的这个偏移开始找（用于多个 vector 分段）。
 * end_pos：若非 NULL，*end_pos 返回找到位置的下一个偏移。
 */
static int find_json_string(const char *text, long text_len, const char *key,
                           long from_pos, char *out, int out_cap, long *end_pos)
{
    char pat[64];
    int klen = snprintf(pat, sizeof(pat), "\"%s\"", key);
    for (long i = from_pos; i + klen < text_len; i++) {
        if (memcmp(text + i, pat, (size_t)klen) != 0) continue;
        long j = i + klen;
        /* 跳过空白和冒号 */
        while (j < text_len && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r' || text[j] == ':')) j++;
        if (j >= text_len || text[j] != '"') continue;
        j++; /* 跳过开引号 */
        int n = 0;
        while (j < text_len && text[j] != '"' && n < out_cap - 1) {
            out[n++] = text[j++];
        }
        out[n] = '\0';
        if (end_pos) *end_pos = j;
        return n;
    }
    return -1;
}

/* 在 text 里找 "key": number，返回 int 值；未找到返回 -1（且 *found 置 0）。 */
static int find_json_int(const char *text, long text_len, const char *key,
                         long from_pos, int *found)
{
    char pat[64];
    int klen = snprintf(pat, sizeof(pat), "\"%s\"", key);
    for (long i = from_pos; i + klen < text_len; i++) {
        if (memcmp(text + i, pat, (size_t)klen) != 0) continue;
        long j = i + klen;
        while (j < text_len && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r' || text[j] == ':')) j++;
        if (j >= text_len || !isdigit((unsigned char)text[j])) continue;
        int val = 0;
        while (j < text_len && isdigit((unsigned char)text[j])) {
            val = val * 10 + (text[j] - '0');
            j++;
        }
        if (found) *found = 1;
        return val;
    }
    if (found) *found = 0;
    return -1;
}

/* 在 text 里找下一个 "name": "..." 的位置，返回偏移；找不到返回 -1。 */
static long find_next_name(const char *text, long text_len, long from_pos)
{
    const char *pat = "\"name\"";
    size_t plen = 6;
    for (long i = from_pos; i + (long)plen < text_len; i++) {
        if (memcmp(text + i, pat, plen) == 0) return i;
    }
    return -1;
}

/* ---------- 单条 vector 的执行 ---------- */

static int run_one_vector(const char *text, long text_len, long vstart)
{
    char name[128] = {0}, key_hex[64] = {0}, plain_hex[64] = {0}, cipher_hex[128] = {0};
    long after = 0;
    if (find_json_string(text, text_len, "name", vstart, name, sizeof(name), &after) < 0) return -1;
    long vend = find_next_name(text, text_len, after);
    if (vend < 0) vend = text_len;

    /* 关键：把当前 vector 的文本段单独切出来查找字段，
     * 避免第一条 vector 跨段读到第二条的 iterations=1000000。 */
    const char *seg = text + vstart;
    long seg_len = vend - vstart;

    find_json_string(seg, seg_len, "key_hex", 0, key_hex, sizeof(key_hex), NULL);
    find_json_string(seg, seg_len, "plain_hex", 0, plain_hex, sizeof(plain_hex), NULL);
    find_json_string(seg, seg_len, "cipher_hex", 0, cipher_hex, sizeof(cipher_hex), NULL);

    int found_iter = 0;
    int iterations = find_json_int(seg, seg_len, "iterations", 0, &found_iter);

    uint8_t key[16], plain[16], expected[16];
    if (hex_decode(key_hex, key, 16) != 16) { fprintf(stderr, "  bad key_hex\n"); return 1; }
    if (hex_decode(plain_hex, plain, 16) != 16) { fprintf(stderr, "  bad plain_hex\n"); return 1; }
    if (hex_decode(cipher_hex, expected, 16) != 16) { fprintf(stderr, "  bad cipher_hex\n"); return 1; }

    uint8_t out[16];
    if (found_iter && iterations > 1) {
        /* 迭代模式：每次把上一轮密文当明文 */
        uint8_t cur[16];
        memcpy(cur, plain, 16);
        for (int i = 0; i < iterations; i++) {
            sm4_encrypt_block(key, cur, out);
            memcpy(cur, out, 16);
        }
    } else {
        sm4_encrypt_block(key, plain, out);
    }

    char got_hex[33];
    hex_encode(out, 16, got_hex);
    int ok = (memcmp(out, expected, 16) == 0);
    printf("%-28s %s  got=%s\n", name, ok ? "PASS" : "FAIL", got_hex);
    if (!ok) {
        char exp_hex[33];
        hex_encode(expected, 16, exp_hex);
        printf("    expected=%s\n", exp_hex);
    }
    return ok ? 0 : 1;
}

/* ---------- pairs.json 交叉比对 ---------- */

static int run_pairs(const char *pairs_path)
{
    long len = 0;
    char *text = slurp_file(pairs_path, &len);
    if (!text) {
        printf("pairs.json not found at %s — skipping cross-check\n", pairs_path);
        return 0; /* 不算失败，只是没跑 */
    }

    char key_hex[64] = {0};
    find_json_string(text, len, "key_hex", 0, key_hex, sizeof(key_hex), NULL);
    uint8_t key[16];
    if (hex_decode(key_hex, key, 16) != 16) {
        fprintf(stderr, "  pairs.json: bad key_hex\n");
        free(text);
        return 1;
    }

    /* 数 pairs 条数：数 "plain_hex" 出现次数 */
    int total = 0, passed = 0;
    const char *pat = "\"plain_hex\"";
    size_t plen = strlen(pat);
    long pos = 0;
    while (pos < len) {
        long found = -1;
        for (long i = pos; i + (long)plen < len; i++) {
            if (memcmp(text + i, pat, plen) == 0) { found = i; break; }
        }
        if (found < 0) break;
        long vend = -1;
        for (long i = found + (long)plen; i < len; i++) {
            if (memcmp(text + i, pat, plen) == 0) { vend = i; break; }
        }
        if (vend < 0) vend = len;

        char plain_hex[64] = {0}, cipher_hex[64] = {0};
        find_json_string(text, len, "plain_hex", found, plain_hex, sizeof(plain_hex), NULL);
        find_json_string(text, len, "cipher_hex", found, cipher_hex, sizeof(cipher_hex), NULL);

        uint8_t plain[16], expected[16], out[16];
        if (hex_decode(plain_hex, plain, 16) == 16 && hex_decode(cipher_hex, expected, 16) == 16) {
            total++;
            sm4_encrypt_block(key, plain, out);
            if (memcmp(out, expected, 16) == 0) passed++;
            else {
                char got[33], exp[33];
                hex_encode(out, 16, got);
                hex_encode(expected, 16, exp);
                printf("  pair #%d MISMATCH plain=%s got=%s expected=%s\n",
                       total, plain_hex, got, exp);
            }
        }
        pos = vend;
    }

    printf("cross-check pairs: %d/%d passed\n", passed, total);
    free(text);
    return (passed == total && total > 0) ? 0 : 1;
}

/* 解密往返：encrypt 再 decrypt 必须还原原文。
 * 不依赖外部文件，自包含。 */
static int run_decrypt_roundtrip(void)
{
    /* 用国标向量的 key */
    const char *key_hex = "0123456789abcdeffedcba9876543210";
    /* 试三个不同的 block：全 0、国标明文、随机样式 */
    const char *blocks_hex[] = {
        "00000000000000000000000000000000",
        "0123456789abcdeffedcba9876543210",
        "ffeeddccbbaa99887766554433221100",
    };
    uint8_t key[16];
    if (hex_decode(key_hex, key, 16) != 16) return 1;

    int fails = 0;
    for (size_t i = 0; i < sizeof(blocks_hex)/sizeof(blocks_hex[0]); i++) {
        uint8_t pt[16], ct[16], rt[16];
        if (hex_decode(blocks_hex[i], pt, 16) != 16) { fails++; continue; }
        sm4_encrypt_block(key, pt, ct);
        sm4_decrypt_block(key, ct, rt);
        if (memcmp(rt, pt, 16) != 0) {
            char pt_h[33], rt_h[33];
            hex_encode(pt, 16, pt_h);
            hex_encode(rt, 16, rt_h);
            printf("  roundtrip #%d FAIL: pt=%s rt=%s\n", (int)i, pt_h, rt_h);
            fails++;
        }
    }
    printf("decrypt roundtrip: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails;
}

int main(void)
{
    const char *vec_path = "../data/vectors/sm4_vectors.json";
    const char *pairs_path = "../work/pairs.json";

    long len = 0;
    char *text = slurp_file(vec_path, &len);
    if (!text) {
        fprintf(stderr, "cannot open %s\n", vec_path);
        return 2;
    }

    int fails = 0;
    long pos = 0;
    int vec_count = 0;
    while (1) {
        long vstart = find_next_name(text, len, pos);
        if (vstart < 0) break;
        int rc = run_one_vector(text, len, vstart);
        if (rc != 0) fails++;
        vec_count++;
        /* 找下一个 name */
        long after = vstart + 6;
        long nxt = -1;
        const char *pat = "\"name\"";
        for (long i = after; i + 6 < len; i++) {
            if (memcmp(text + i, pat, 6) == 0) { nxt = i; break; }
        }
        if (nxt < 0) break;
        pos = nxt;
    }
    free(text);

    if (vec_count == 0) {
        fprintf(stderr, "no vectors parsed\n");
        return 2;
    }

    fails += run_pairs(pairs_path);
    fails += run_decrypt_roundtrip();

    printf("----\n");
    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d FAILURE(S)\n", fails);
    return fails == 0 ? 0 : 1;
}
