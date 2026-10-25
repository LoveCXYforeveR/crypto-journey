"""ECB 模式图片演示：生成「左原图 | 右 ECB 加密图」对比图。

用法:
    python demo/ecb_penguin.py <图片路径>
输出:
    demo/output/ecb_demo.png

ECB 相同明文块产生相同密文块，平坦色块区域在加密后仍保持一致，
因此加密图仍能看出原图轮廓——这正是 ECB 模式的经典安全缺陷。
"""

import os
import sys

from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.modes import ecb_encrypt  # noqa: E402

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")


def main():
    if len(sys.argv) != 2:
        print("用法: python demo/ecb_penguin.py <图片路径>")
        return 1
    src = sys.argv[1]
    if not os.path.exists(src):
        print(f"错误: 文件不存在 {src}")
        return 1

    img = Image.open(src).convert("RGB")
    w, h = img.size
    raw = img.tobytes()                       # RGB 字节流
    enc = ecb_encrypt(KEY, raw)               # 内部自动 PKCS#7 填充
    enc_img = Image.frombytes("RGB", (w, h), enc[: len(raw)])

    out = Image.new("RGB", (w * 2, h))
    out.paste(img, (0, 0))
    out.paste(enc_img, (w, 0))

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "ecb_demo.png")
    out.save(out_path)
    print(f"已生成: {out_path}（左原图 | 右 ECB 加密图）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
