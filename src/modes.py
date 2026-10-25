"""SM4 工作模式（ECB / CBC / CTR）纯 Python 实现。

统一原则:
- 三种模式全部复用 src/sm4.py 的 encrypt_block / decrypt_block，
  绝不在本模块重复实现分组算法。
- ECB / CBC 基于 PKCS#7 填充；CTR 为流模式，不填充。
- 参数校验失败一律抛 ValueError 并给出人话提示。
"""

from __future__ import annotations

from .sm4 import encrypt_block, decrypt_block
from .padding import pad, unpad

_BLOCK = 16


def _check_block_len(name: str, data: bytes) -> None:
    if len(data) % _BLOCK != 0:
        raise ValueError(f"{name} 长度必须是 {_BLOCK} 字节的整数倍，实际 {len(data)} 字节")


# ---------------------------------------------------------------------------
# ECB
# ---------------------------------------------------------------------------

def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """ECB 加密: 填充 -> 逐块独立加密。相同明文块 -> 相同密文块。"""
    padded = pad(data, _BLOCK)
    return b"".join(
        encrypt_block(key, padded[i:i + _BLOCK])
        for i in range(0, len(padded), _BLOCK)
    )


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """ECB 解密: 逐块独立解密 -> 移除填充。"""
    _check_block_len("密文", data)
    plain = b"".join(
        decrypt_block(key, data[i:i + _BLOCK])
        for i in range(0, len(data), _BLOCK)
    )
    return unpad(plain, _BLOCK)


# ---------------------------------------------------------------------------
# CBC
# ---------------------------------------------------------------------------

def cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """CBC 加密: 明文块异或前一块密文（首块异或 IV）后再加密。"""
    if len(iv) != _BLOCK:
        raise ValueError(f"CBC 的 IV 必须为 {_BLOCK} 字节，实际 {len(iv)} 字节")
    padded = pad(data, _BLOCK)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), _BLOCK):
        block = bytes(a ^ b for a, b in zip(padded[i:i + _BLOCK], prev))
        prev = encrypt_block(key, block)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """CBC 解密: 每块只依赖前一块密文（首块依赖 IV），可并行。"""
    if len(iv) != _BLOCK:
        raise ValueError(f"CBC 的 IV 必须为 {_BLOCK} 字节，实际 {len(iv)} 字节")
    _check_block_len("密文", data)
    blocks = [data[i:i + _BLOCK] for i in range(0, len(data), _BLOCK)]
    plain = bytearray()
    prev = iv
    for ct in blocks:
        block = bytes(a ^ b for a, b in zip(decrypt_block(key, ct), prev))
        plain += block
        prev = ct
    return unpad(bytes(plain), _BLOCK)


# ---------------------------------------------------------------------------
# CTR
# ---------------------------------------------------------------------------

def ctr_crypt(key: bytes, data: bytes, nonce: bytes) -> bytes:
    """CTR 加解密（同一个函数）: 以 nonce 为初始计数器逐块产生密钥流异或。

    - nonce 必须 16 字节（与 SM4 块长一致）
    - 计数器按 128 位大端整数递增（含进位）
    - 不填充，数据长度任意
    """
    if len(nonce) != _BLOCK:
        raise ValueError(f"CTR 的 nonce 必须为 {_BLOCK} 字节，实际 {len(nonce)} 字节")
    out = bytearray()
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), _BLOCK):
        keystream = encrypt_block(key, counter.to_bytes(_BLOCK, "big"))
        chunk = data[i:i + _BLOCK]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)
