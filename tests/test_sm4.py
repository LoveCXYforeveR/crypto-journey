"""SM4 测试: 国标向量 + 一百万次迭代 + 随机往返 + key_schedule 独立测试。"""

import sys
import os
import json
import random

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sm4 import key_schedule, encrypt_block, decrypt_block  # noqa: E402


def _load_vectors():
    path = os.path.join(
        os.path.dirname(__file__), "..", "data", "vectors", "sm4_vectors.json"
    )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


VECTORS = _load_vectors()

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
PT = bytes.fromhex("0123456789abcdeffedcba9876543210")


def test_standard_vector():
    """国标标准向量: 密钥==明文 -> 681edf34..."""
    for v in VECTORS["vectors"]:
        if v["name"] == "standard_vector":
            assert encrypt_block(key=KEY, block=PT).hex() == v["cipher_hex"]
            return
    pytest.fail("sm4_vectors.json 缺少 standard_vector")


def test_decrypt_standard_vector():
    """标准向量解密还原。"""
    ct = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    assert decrypt_block(KEY, ct) == PT


@pytest.mark.slow
def test_one_million_iterations():
    """同一密钥加密 1,000,000 次（国标向量，约 1 分钟）。"""
    target = None
    for v in VECTORS["vectors"]:
        if v["name"] == "one_million_iterations":
            target = v
            break
    assert target is not None
    x = PT
    for _ in range(int(target["iterations"])):
        x = encrypt_block(KEY, x)
    assert x.hex() == target["cipher_hex"]


def test_roundtrip_random_100():
    """随机密钥/明文往返 100 次全过。"""
    rng = random.Random(20261024)
    for _ in range(100):
        k = bytes(rng.randrange(256) for _ in range(16))
        b = bytes(rng.randrange(256) for _ in range(16))
        assert decrypt_block(k, encrypt_block(k, b)) == b


def test_key_schedule_independent():
    """key_schedule 可独立调用: 32 个 32 位轮密钥、确定性、随密钥变化。"""
    rks = key_schedule(KEY)
    assert isinstance(rks, list)
    assert len(rks) == 32
    assert all(isinstance(r, int) and 0 <= r <= 0xFFFFFFFF for r in rks)
    assert key_schedule(KEY) == rks  # 确定性
    other = bytes.fromhex("fedcba98765432100123456789abcdef")
    assert key_schedule(other) != rks  # 不同密钥 -> 不同轮密钥


def test_key_schedule_matches_manual_round():
    """用 key_schedule 结果手工走一遍加密轮，验证与 encrypt_block 一致。

    通过独立调用 key_schedule 手工实现轮函数，验证调度结果与
    encrypt_block 内部使用完全一致（防止密钥扩展被藏在加解密里）。
    """
    from src.sm4 import _rotl, _tau, _l, _MASK32  # noqa: PLC0415

    def manual_encrypt(rks, block):
        x = [int.from_bytes(block[i * 4:(i + 1) * 4], "big") for i in range(4)]
        for rk in rks:
            t = _l(_tau(x[1] ^ x[2] ^ x[3] ^ rk))
            x = [x[1], x[2], x[3], x[0] ^ t]
        return b"".join(w.to_bytes(4, "big") for w in (x[3], x[2], x[1], x[0]))

    rks = key_schedule(KEY)
    assert manual_encrypt(rks, PT) == encrypt_block(KEY, PT)


@pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
def test_key_length_must_be_16(bad_len):
    with pytest.raises(ValueError):
        key_schedule(b"\x00" * bad_len)
    with pytest.raises(ValueError):
        encrypt_block(b"\x00" * bad_len, PT)
    with pytest.raises(ValueError):
        decrypt_block(b"\x00" * bad_len, PT)


@pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
def test_block_length_must_be_16(bad_len):
    with pytest.raises(ValueError):
        encrypt_block(KEY, b"\x00" * bad_len)
    with pytest.raises(ValueError):
        decrypt_block(KEY, b"\x00" * bad_len)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
