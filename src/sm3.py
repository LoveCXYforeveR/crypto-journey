"""SM3 密码杂凑算法（GB/T 32905-2016）纯 Python 实现。

- 输入: bytes
- 输出: 32 字节摘要
- 仅使用标准库，不依赖 hashlib / 任何第三方库。

算法结构:
1. 填充: 消息后追加 0x80, 若干 0x00, 再追加 64 位原始比特长度,
   使总长度 (不含 64 位长度域) 满足 len % 64 == 56。
2. 迭代压缩: 512 位消息块 -> 64 轮压缩函数更新 256 位链值 V。
3. 输出: 链值 V 的 8 个 32 位字按大端拼成 32 字节。
"""

from __future__ import annotations

# 初始链值 IV（标准 5.3 节）
IV = bytes.fromhex(
    "7380166f4914b2b9172442d7da8a0600"
    "a96f30bc163138aae38dee4db0fb0e4e"
)

# 压缩函数常量: j=0..15 用 T0, j=16..63 用 T1
_T0 = 0x79CC4519
_T1 = 0x7A879D8A

_MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    """32 位循环左移。"""
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p0(x: int) -> int:
    """线性置换 P0，用于压缩函数。"""
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    """线性置换 P1，用于消息扩展。"""
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & z)


def _expand(b: bytes):
    """消息扩展: 16 个字 -> W[68] 与 W'[64]。"""
    w = [int.from_bytes(b[i * 4:(i + 1) * 4], "big") for i in range(16)]
    w += [0] * 52
    for j in range(16, 68):
        w[j] = (
            _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
            ^ _rotl(w[j - 13], 7)
            ^ w[j - 6]
        )
    wp = [0] * 64
    for j in range(64):
        wp[j] = w[j] ^ w[j + 4]
    return w, wp


def _compress(v: bytes, b: bytes) -> bytes:
    """压缩函数 CF: 512 位消息块更新 256 位链值。"""
    words = [int.from_bytes(v[i * 4:(i + 1) * 4], "big") for i in range(8)]
    a, b0, c, d, e, f, g, h = words
    w, wp = _expand(b)

    for j in range(64):
        t = _T0 if j < 16 else _T1
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & _MASK32, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_ff(a, b0, c, j) + d + ss2 + wp[j]) & _MASK32
        tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & _MASK32

        d = c
        c = _rotl(b0, 9)
        b0 = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)

    out = b"".join(x.to_bytes(4, "big") for x in (a, b0, c, d, e, f, g, h))
    # 标准 5.3.3: V(i+1) ← ABCDEFGH ⊕ V(i)
    return bytes(x ^ y for x, y in zip(out, v))


def sm3(data: bytes) -> bytes:
    """计算 data 的 SM3 摘要，返回 32 字节。"""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sm3() 需要 bytes 输入")

    # --- 填充 ---
    bit_len = len(data) * 8
    # k 满足: (len(data) + 1 + k) % 64 == 56  (56 字节 = 448 位)
    k = (56 - (len(data) + 1) % 64) % 64
    padded = data + b"\x80" + b"\x00" * k + bit_len.to_bytes(8, "big")

    # --- 迭代压缩 ---
    v = IV
    for i in range(0, len(padded), 64):
        v = _compress(v, padded[i:i + 64])
    return v
