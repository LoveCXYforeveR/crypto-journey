"""SM3 测试: GB/T 32905 附录 A 向量 + 边界 + 百万次迭代。"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sm3 import sm3  # noqa: E402


def _load_vectors():
    """从 data/vectors/sm3_vectors.json 加载国标测试向量。"""
    path = os.path.join(
        os.path.dirname(__file__), "..", "data", "vectors", "sm3_vectors.json"
    )
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [
        (bytes.fromhex(v["message_hex"]), bytes.fromhex(v["digest_hex"]))
        for v in data["vectors"]
    ]


VECTORS = _load_vectors()


def test_abc_vector():
    """附录 A 示例 1: 'abc' -> 66c7f0f4..."""
    assert sm3(b"abc").hex() == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_abcd_x16_vector():
    """附录 A 示例 2: 'abcd' x16 -> debe9ff9..."""
    msg = b"abcd" * 16
    assert sm3(msg).hex() == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"


def test_loaded_vectors():
    """data/vectors 中的全部向量。"""
    assert len(VECTORS) >= 2
    for msg, digest in VECTORS:
        assert sm3(msg) == digest


def test_output_length_and_digest_len():
    """输出恒为 32 字节。"""
    for size in (0, 1, 55, 56, 64, 65, 127, 128, 1000):
        d = sm3(b"\x00" * size)
        assert isinstance(d, bytes)
        assert len(d) == 32


def test_boundary_sizes_no_crash():
    """空串 / 1 / 55 / 56 / 64 字节边界不崩。"""
    for n in (0, 1, 55, 56, 64):
        sm3(b"a" * n)  # 只要求不抛异常


def test_avalanche():
    """单比特翻转应引起大面积变化。"""
    a = sm3(b"hello world")
    b = sm3(b"hello worle")
    diff = sum(x != y for x, y in zip(a, b))
    assert diff >= 8  # 至少 8 字节不同（宽松冒烟检查）


@pytest.mark.slow
def test_one_million_a():
    """'a' 重复 100 万次（GB/T 32905 附录 A 迭代压力测试）。

    注意: 国标附录 A 正式向量仅示例1('abc')与示例2('abcd'x16)，
    百万次迭代为业界常用长消息压力测试。期望值经本机
    OpenSSL/hashlib 的 SM3 实现交叉验证一致。
    """
    d = sm3(b"a" * 1_000_000)
    assert d.hex() == "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
