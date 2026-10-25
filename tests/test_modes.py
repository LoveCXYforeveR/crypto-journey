"""工作模式测试: ECB / CBC / CTR 往返、参数校验、块重复性 + PKCS#7 填充。"""

import sys
import os
import random

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, ctr_crypt  # noqa: E402
from src.padding import pad, unpad  # noqa: E402

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")

SIZES = [0, 1, 2, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 1000]


# ---------------------------------------------------------------------------
# PKCS#7 填充
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", range(0, 33))
def test_pad_unpad_roundtrip_0_to_32(size):
    data = bytes(range(size))
    padded = pad(data)
    assert padded == data + bytes([16 - size % 16]) * (16 - size % 16)
    assert unpad(padded) == data


def test_pad_exact_block_adds_full_block():
    """长度正好 16 的倍数时必须额外补一整块。"""
    assert len(pad(b"\x00" * 16)) == 32
    assert pad(b"\x00" * 16)[-16:] == bytes([16]) * 16
    assert unpad(pad(b"\x00" * 16)) == b"\x00" * 16


def test_unpad_tampered_byte_raises():
    """篡改一个填充字节必须抛 ValueError（填充字节非法）。"""
    padded = pad(b"hello world!")  # 9 字节 -> 填充 7
    bad = bytearray(padded)
    bad[-1] = 3
    with pytest.raises(ValueError):
        unpad(bytes(bad))


def test_unpad_wrong_padding_value_raises():
    """填充值本身非法（0 或大于块长）抛 ValueError（长度非法）。"""
    with pytest.raises(ValueError):
        unpad(b"abc")  # 非块长倍数
    with pytest.raises(ValueError):
        unpad(b"\x00" * 16)  # 填充值 0
    with pytest.raises(ValueError):
        unpad(b"\x00" * 16 + b"\x00" * 17)  # 填充值 17 > 16
    with pytest.raises(ValueError):
        unpad(b"")  # 空数据


def test_unpad_error_messages_distinguish():
    """「长度非法」与「填充字节非法」提示可区分。"""
    with pytest.raises(ValueError, match="长度非法"):
        unpad(b"abc")
    with pytest.raises(ValueError, match="填充字节非法"):
        unpad(b"\x00" * 15 + b"\x05")


# ---------------------------------------------------------------------------
# ECB
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_ecb_roundtrip(size):
    data = bytes(random.Random(size).randrange(256) for _ in range(size))
    ct = ecb_encrypt(KEY, data)
    assert ecb_decrypt(KEY, ct) == data


def test_ecb_same_block_same_cipher():
    """ECB: 相同明文块 -> 相同密文块。"""
    data = b"0123456789abcdef" * 4
    ct = ecb_encrypt(KEY, data)
    assert ct[:16] == ct[16:32] == ct[32:48] == ct[48:64]


def test_ecb_length_must_be_multiple_of_16():
    with pytest.raises(ValueError):
        ecb_decrypt(KEY, b"\x00" * 17)


# ---------------------------------------------------------------------------
# CBC
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_cbc_roundtrip(size):
    data = bytes(random.Random(1000 + size).randrange(256) for _ in range(size))
    ct = cbc_encrypt(KEY, data, IV)
    assert cbc_decrypt(KEY, ct, IV) == data


def test_cbc_changing_iv_changes_cipher():
    """CBC: 换 IV 结果不同。"""
    data = b"attack at dawn" * 10
    ct1 = cbc_encrypt(KEY, data, IV)
    ct2 = cbc_encrypt(KEY, data, bytes(16))
    assert ct1 != ct2


@pytest.mark.parametrize("bad_iv_len", [0, 1, 15, 17, 32])
def test_cbc_iv_length_must_be_16(bad_iv_len):
    with pytest.raises(ValueError):
        cbc_encrypt(KEY, b"x" * 32, b"\x00" * bad_iv_len)
    with pytest.raises(ValueError):
        cbc_decrypt(KEY, b"\x00" * 32, b"\x00" * bad_iv_len)


# ---------------------------------------------------------------------------
# CTR
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_ctr_roundtrip_same_function(size):
    """CTR: 加解密同一个函数，结果对称。"""
    data = bytes(random.Random(2000 + size).randrange(256) for _ in range(size))
    ct = ctr_crypt(KEY, data, NONCE)
    assert ctr_crypt(KEY, ct, NONCE) == data


def test_ctr_long_data_counter_carry():
    """长数据触发计数器进位（> 一个块以上）仍正确。"""
    data = bytes(random.Random(7).randrange(256) for _ in range(3000))
    assert ctr_crypt(KEY, ctr_crypt(KEY, data, NONCE), NONCE) == data


def test_ctr_changing_nonce_changes_output():
    ct1 = ctr_crypt(KEY, b"hello", NONCE)
    ct2 = ctr_crypt(KEY, b"hello", bytes(16))
    assert ct1 != ct2


@pytest.mark.parametrize("bad_nonce_len", [0, 1, 8, 15, 17])
def test_ctr_nonce_length_must_be_16(bad_nonce_len):
    with pytest.raises(ValueError):
        ctr_crypt(KEY, b"x" * 32, b"\x00" * bad_nonce_len)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
