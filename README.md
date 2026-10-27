# crypto-journey

用 Python 从零实现国密 SM3 / SM4，不依赖任何密码库。

[![CI](https://github.com/LoveCXYforeveR/crypto-journey/actions/workflows/ci.yml/badge.svg)](https://github.com/LoveCXYforeveR/crypto-journey/actions)

## 这是什么

一个纯 Python 标准库实现的国密算法作品：SM3 杂凑、SM4 分组密码及其
ECB / CBC / CTR 三种工作模式，全部从算法原理手写，不依赖 `hashlib`、
`cryptography` 等任何密码库。配套完整 pytest 测试、ECB 模式图片演示和
命令行工具，克隆后一键可跑。适合用来理解国密算法的真实实现细节，
也适合作为课程作品或面试项目展示。

## 已验证

- SM3：GB/T 32905 附录 A 测试向量通过
  - `abc`
  - `abcd` × 16
  - `a` 重复 100 万次（业界公开压力向量，经 OpenSSL 交叉验证）
- SM4：GB/T 32907 测试向量通过
  - 标准向量 `681edf34d206965e86b3e94f536e4246`
  - 100 万次迭代 `595298c7c6fd271f0402f804c33d3f66`
  - 随机密钥/明文往返 100 次
- 工作模式：ECB / CBC / CTR 往返测试通过
  - 覆盖 0 到 1000 字节各种长度
- 全量测试 117 项通过（含 2 项 `slow` 百万次迭代）

## 快速开始

```bash
git clone https://github.com/LoveCXYforeveR/crypto-journey.git
cd crypto-journey
pip install -r requirements.txt
pytest
```

全部测试应通过。跳过耗时用例用 `pytest -m "not slow"`（约 2 秒）。

## ECB 模式演示

![ECB](demo/output/ecb_demo.png)

左：原图　右：ECB 加密后

相同明文块产生相同密文块，所以图片加密后仍能看出轮廓。

运行演示（需要 Pillow）：

```bash
python demo/ecb_penguin.py <图片路径>
```

任意有明显色块的图片都可以，比如一张 logo 或纯色块拼接图。仓库内置了自造的 `demo/sample.png`（192×192 三分色块图，无版权风险）：

```bash
python demo/ecb_penguin.py demo/sample.png
```

输出保存到 `demo/output/ecb_demo.png`。

## 命令行工具

```bash
# SM3 摘要
python -m demo.cli hash --in README.md

# SM4 加密 / 解密（--key 支持 16 字节 hex 或 .key 文件）
python -m demo.cli encrypt --in in.bin --out out.enc --key 0123456789abcdeffedcba9876543210 --mode cbc
python -m demo.cli decrypt --in out.enc --out back.bin --key 0123456789abcdeffedcba9876543210 --mode cbc
```

CBC 的 IV / CTR 的 nonce 在加密时随机生成并写入密文文件头 16 字节，解密时自动读出。

## 目录说明

| 目录 | 内容 |
|---|---|
| src/ | SM3、SM4、工作模式、填充 |
| tests/ | 单元测试（117 项） |
| demo/ | ECB 演示与命令行工具 |
| data/vectors/ | 国标测试向量 |
| notes/ | 实现笔记与踩坑 |

## 性能基准

同机实测（2026-10-27），SM4-ECB，1,000,000 个全 0 block，正式计时前预热 1000 块，
每口径跑 3 次取中位数。

| 实现 | 口径 | 吞吐 | us/block | 相对 Python |
|---|---|---:|---:|---:|
| Python 3.13（纯标准库） | 每块重算轮密钥 | 0.301 MB/s | 53.20 | 1× |
| Python 3.13（纯标准库） | 轮密钥预计算 | 0.634 MB/s | 25.25 | 2.1× |
| C（自写，gcc -O2） | 每块重算轮密钥 | 66.67 MB/s | 0.240 | 222× |
| C（自写，gcc -O2） | 轮密钥预计算 | 122.84 MB/s | 0.130 | 408× |
| OpenSSL 3.6.5（参考） | SM4-ECB，16B block | 835.4 MB/s | ~0.019 | 2775× |

**测试条件**：CPU Intel Core Ultra 7 251HX / OS Windows 11（build 26200）/
编译器 gcc 16.2.0（MSYS2 UCRT64）/ 优化 `-O2` / 1,000,000 block / block 全 0 / 3 次中位数。
OpenSSL 行取自 `openssl speed -evp sm4-ecb` 的 16 字节列。

**怎么读这张表**：
- C 版把 Python 的解释器开销摊掉后快了 **222–408 倍**——这是纯语言层面对比，
  不是算法层面的差距。
- 同一 C 实现里，**轮密钥预计算比每块重算快约 1.84 倍**（Python 里是 2.1 倍），
  说明密钥扩展在总耗时里占约 45%；这是 SM4 结构本身决定的，跟优化无关。
- 我们的 C 版（无 T-table、无 SIMD）比 OpenSSL 慢约 **6.8 倍**。这个差距不是
  "C 不够快"，而是 OpenSSL 在 SM4 上用了查表/手写汇编——它是优化过的参考实现，
  我们这一版是一比一直译算法骨架。两者并列才是工程判断。

## 已知限制

- **三种模式均不提供完整性/认证保护**：密文被篡改无法检测，也没有身份绑定；
  需要认证时应使用 GCM / CCM 等 AEAD 模式（本项目尚未实现）
- 纯 Python 实现仅供学习与对拍；C 版把吞吐提高约 200 倍，但同样**不具备生产能力**
  （无侧信道防护、无认证、无内存清零），生产环境请使用经过审计的实现（如 OpenSSL）
- 未做侧信道防护（时序攻击等）
- 未做内存清零，密钥可能残留在 Python 对象中
- SM4 仅支持 128 位密钥
- 不支持流式处理，一次性读入整个文件
- CTR 的 nonce 由调用方负责唯一性，库本身不检测重用（重用会导致密钥流复用）

## 为什么写这个

学密码学时最大的困惑是：教材讲的安全性，和代码里实际发生什么，中间隔着很远。

所以把国密算法从标准原文一行行敲出来，再用一张图把 ECB 的缺陷讲清楚
——加密后的图片还能看出轮廓，这件事比任何文字解释都有说服力。

## 参考标准

- GB/T 32905-2016 SM3
- GB/T 32907-2016 SM4

## 许可

MIT，2026 Li Ru
