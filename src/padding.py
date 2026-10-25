"""PKCS#7 填充（RFC 5652）纯 Python 实现。

- pad: 明文 -> 对齐到 block_size 的整数倍
  明文长度正好是 block_size 的倍数时，额外补一整块（值为 block_size）。
- unpad: 校验并移除填充，非法时抛 ValueError，并区分两类错误：
  * 长度非法（数据为空 / 不是 block_size 的倍数 / 填充值大于块长）
  * 填充字节非法（填充值指示的长度与实际填充字节不一致）
"""

from __future__ import annotations


def pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 填充，返回对齐后的 bytes。"""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data 必须是 bytes")
    if block_size <= 0 or block_size > 256:
        raise ValueError(f"block_size 必须在 1..256，实际 {block_size}")
    n = block_size - (len(data) % block_size)
    return bytes(data) + bytes([n]) * n


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """校验并移除 PKCS#7 填充，返回原始 bytes。

    非法情形:
    - 数据为空
    - 数据长度不是 block_size 的倍数
    - 最后一个填充值 p 为 0 或大于 block_size（长度非法）
    - 末尾 p 个字节并非全部等于 p（填充字节非法）
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data 必须是 bytes")
    if block_size <= 0 or block_size > 256:
        raise ValueError(f"block_size 必须在 1..256，实际 {block_size}")
    if len(data) == 0:
        raise ValueError("unpad 失败：数据为空，无填充可移除（长度非法）")
    if len(data) % block_size != 0:
        raise ValueError(
            f"unpad 失败：数据长度 {len(data)} 不是块长 {block_size} 的倍数（长度非法）"
        )
    p = data[-1]
    if p == 0 or p > block_size:
        raise ValueError(f"unpad 失败：填充值 {p} 非法（长度非法）")
    if data[-p:] != bytes([p]) * p:
        raise ValueError(f"unpad 失败：末尾 {p} 个字节并非合法填充（填充字节非法）")
    return bytes(data[:-p])
