"""crypto-journey 命令行工具: encrypt / decrypt / hash 三个子命令。

用法:
    python -m demo.cli encrypt --in <file> --out <file> --key <hex|keyfile> --mode <ecb|cbc|ctr>
    python -m demo.cli decrypt --in <file> --out <file> --key <hex|keyfile> --mode <ecb|cbc|ctr>
    python -m demo.cli hash    --in <file>

--key 支持两种输入: 32 位十六进制字符串，或 16 字节的 .key 文件路径（按原始字节读取）。

CBC / CTR 的 IV / nonce 在加密时随机生成并写入输出文件头部（16 字节），
解密时从文件头部读出，因此加密文件 = 头部(16 字节) + 密文。
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src import sm3, modes  # noqa: E402

HEADER = 16  # CBC IV / CTR nonce 长度，与 SM4 块长一致


def _parse_key(text: str) -> bytes:
    # 1) .key 文件路径：文件存在时读取原始字节
    if text.lower().endswith(".key"):
        if not os.path.exists(text):
            raise argparse.ArgumentTypeError(f"密钥文件不存在: {text}")
        with open(text, "rb") as f:
            key = f.read()
        if len(key) != 16:
            raise argparse.ArgumentTypeError(
                f"密钥文件长度错误: 需要 16 字节，实际 {len(key)} 字节"
            )
        return key
    # 2) 十六进制字符串（32 个十六进制字符 = 16 字节）
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "密钥必须是 16 字节的十六进制字符串（32 个十六进制字符）或 .key 文件路径"
        )
    if len(key) != 16:
        raise argparse.ArgumentTypeError(
            f"密钥长度错误: 需要 16 字节（32 个十六进制字符），实际 {len(key)} 字节"
        )
    return key


def _read_file(path: str) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"文件不存在: {path}")
    with open(path, "rb") as f:
        return f.read()


def _write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _encrypt(args):
    data = _read_file(args.infile)
    if args.mode == "ecb":
        out = modes.ecb_encrypt(args.key, data)
    elif args.mode == "cbc":
        iv = os.urandom(HEADER)
        out = iv + modes.cbc_encrypt(args.key, data, iv)
    elif args.mode == "ctr":
        nonce = os.urandom(HEADER)
        out = nonce + modes.ctr_crypt(args.key, data, nonce)
    else:
        raise ValueError(f"不支持的加密模式: {args.mode}（可选 ecb/cbc/ctr）")
    _write_file(args.outfile, out)
    print(f"已加密 {args.infile} -> {args.outfile}（模式: {args.mode}）")


def _decrypt(args):
    data = _read_file(args.infile)
    if args.mode == "ecb":
        out = modes.ecb_decrypt(args.key, data)
    elif args.mode == "cbc":
        if len(data) < HEADER:
            raise ValueError("CBC 密文文件太短，缺少 16 字节 IV 头部")
        iv, body = data[:HEADER], data[HEADER:]
        out = modes.cbc_decrypt(args.key, body, iv)
    elif args.mode == "ctr":
        if len(data) < HEADER:
            raise ValueError("CTR 密文文件太短，缺少 16 字节 nonce 头部")
        nonce, body = data[:HEADER], data[HEADER:]
        out = modes.ctr_crypt(args.key, body, nonce)
    else:
        raise ValueError(f"不支持的加密模式: {args.mode}（可选 ecb/cbc/ctr）")
    _write_file(args.outfile, out)
    print(f"已解密 {args.infile} -> {args.outfile}（模式: {args.mode}）")


def _hash(args):
    data = _read_file(args.infile)
    digest = sm3.sm3(data)
    print(digest.hex())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="demo.cli",
        description="crypto-journey 国密命令行工具（SM3 / SM4 / ECB / CBC / CTR）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="加密文件（SM4 工作模式）")
    p_enc.add_argument("--in", dest="infile", required=True, help="输入文件路径")
    p_enc.add_argument("--out", dest="outfile", required=True, help="输出文件路径")
    p_enc.add_argument("--key", type=_parse_key, required=True, help="16 字节密钥（32 位十六进制）")
    p_enc.add_argument("--mode", choices=["ecb", "cbc", "ctr"], required=True, help="加密模式")
    p_enc.set_defaults(func=_encrypt)

    p_dec = sub.add_parser("decrypt", help="解密文件（SM4 工作模式）")
    p_dec.add_argument("--in", dest="infile", required=True, help="输入文件路径")
    p_dec.add_argument("--out", dest="outfile", required=True, help="输出文件路径")
    p_dec.add_argument("--key", type=_parse_key, required=True, help="16 字节密钥（32 位十六进制）")
    p_dec.add_argument("--mode", choices=["ecb", "cbc", "ctr"], required=True, help="解密模式")
    p_dec.set_defaults(func=_decrypt)

    p_hash = sub.add_parser("hash", help="计算文件 SM3 摘要")
    p_hash.add_argument("--in", dest="infile", required=True, help="输入文件路径")
    p_hash.set_defaults(func=_hash)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (FileNotFoundError, ValueError) as e:
        print(f"错误: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
