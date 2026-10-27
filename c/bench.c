/*
 * bench.c — SM4 C 版基准测试。
 *
 * 两个口径分开报：
 *   mode A：每块都重新做 key schedule（对齐 Python encrypt_block）
 *   mode B：key schedule 只做一次，crypt 复用（量化预计算收益）
 *
 * 测量纪律（见手册 2.2）：
 *   - block 数：1,000,000（= 16 MB）
 *   - block 内容：全 0（固定，可复现）
 *   - 预热：正式计时前先跑 1000 块
 *   - 每口径跑 3 次，取中位数
 *   - 同进程不要同时跑 Python 版
 */
#include "sm4.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ---------- 计时 ---------- */
#if defined(_WIN32)
#include <windows.h>
static double now_sec(void)
{
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#else
#include <time.h>
static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
#endif

#ifndef BENCH_BLOCKS
#define BENCH_BLOCKS 1000000
#endif
#ifndef BENCH_WARMUP
#define BENCH_WARMUP 1000
#endif
#ifndef BENCH_TRIALS
#define BENCH_TRIALS 3
#endif

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

int main(void)
{
    /* 固定 key（与国标向量一致），固定全 0 block */
    uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t block[16] = {0};
    uint8_t out[16];
    static volatile unsigned char sink;  /* prevent loop elision */

    printf("=== SM4 C benchmark ===\n");
#ifdef __VERSION__
    printf("compiler: %s\n", __VERSION__);
#else
    printf("compiler: (unknown)\n");
#endif
#ifdef __OPTIMIZE__
    printf("flags:    optimized (__OPTIMIZE__ set), see Makefile for exact flags\n");
#else
    printf("flags:    NO OPTIMIZATION (debug build) — numbers not comparable\n");
#endif
    printf("key:      0123456789abcdeffedcba9876543210\n");
    printf("block:    all-zero\n");
    printf("blocks:   %d\n", (int)BENCH_BLOCKS);
    printf("warmup:   %d\n", (int)BENCH_WARMUP);
    printf("trials:   %d (median)\n", (int)BENCH_TRIALS);
    printf("\n");

    /* ---- 预热 ---- */
    for (int i = 0; i < BENCH_WARMUP; i++) {
        sm4_encrypt_block(key, block, out);
    }
    uint32_t rks[SM4_ROUNDS];
    sm4_key_schedule(key, rks);
    for (int i = 0; i < BENCH_WARMUP; i++) {
        sm4_crypt_block_rks(rks, block, out);
    }

    /* ---- mode A：每块重算 ---- */
    double times_a[BENCH_TRIALS];
    for (int t = 0; t < BENCH_TRIALS; t++) {
        double t0 = now_sec();
        for (int i = 0; i < BENCH_BLOCKS; i++) {
            sm4_encrypt_block(key, block, out);
            sink ^= out[0];
        }
        times_a[t] = now_sec() - t0;
    }
    qsort(times_a, BENCH_TRIALS, sizeof(double), cmp_double);
    double med_a = times_a[BENCH_TRIALS / 2];

    /* ---- mode B：预计算 ---- */
    double times_b[BENCH_TRIALS];
    for (int t = 0; t < BENCH_TRIALS; t++) {
        double t0 = now_sec();
        for (int i = 0; i < BENCH_BLOCKS; i++) {
            sm4_crypt_block_rks(rks, block, out);
            sink ^= out[0];
        }
        times_b[t] = now_sec() - t0;
    }
    qsort(times_b, BENCH_TRIALS, sizeof(double), cmp_double);
    double med_b = times_b[BENCH_TRIALS / 2];

    double mb = (double)BENCH_BLOCKS * 16.0 / 1e6; /* MB (10^6) */
    printf("mode A (key schedule per block):  %8.3f MB/s   %7.3f us/block\n",
           mb / med_a, med_a * 1e6 / BENCH_BLOCKS);
    printf("mode B (precomputed rks):        %8.3f MB/s   %7.3f us/block\n",
           mb / med_b, med_b * 1e6 / BENCH_BLOCKS);
    printf("\nraw trial seconds: A=[%.4f, %.4f, %.4f]  B=[%.4f, %.4f, %.4f]\n",
           times_a[0], times_a[1], times_a[2],
           times_b[0], times_b[1], times_b[2]);
    (void)sink;
    return 0;
}
