# G3 内核：crypto++ AES（Zvkned，CTR + CBC，128/192/256）

日期 2026-11-16 · 板子 SpacemiT K3（`10.91.8.28`，Bianbu，`gcc 15.2.0`，`vlenb=32`）
门禁：功能逐字节 + 真机 A/B（两侧同 `-march=rv64gcv_zvkned_zvbb`、同 `-O2`，唯一变量 `-DCRYPTOPP_RVV_AES`）

## 1. 结论

64 KiB 缓冲，5 轮 × best-of-5，三轮重复：

| 路径 | off（上游 T-table C） | on（Zvkned） | 倍率 |
|---|---|---|---|
| AES-256 CTR | 0.953 / 0.978 / 0.953 ms | **0.302 ms**（三轮一致） | **3.15×** |
| AES-256 CBC | 0.982 / 1.010 / 0.982 | **0.313 ms** | **3.14×** |
| AES-192 CTR | 0.843 / 0.865 / 0.843 | **0.264 ms** | **3.19×** |
| AES-192 CBC | 0.872 / 0.895 / 0.872 | **0.275 ms** | **3.17×** |
| AES-128 CTR | 0.734 / 0.756 / 0.734 | **0.226 ms** | **3.25×** |
| AES-128 CBC | 0.763 / 0.787 / 0.763 | **0.237 ms** | **3.22×** |
| SHA-256（对照，未改动） | 0.774–0.822 ms | 0.770–0.814 ms | 1.00× |

功能：六条路径的 FNV 全同，`cmp` 得 `BYTES_SAME`：

```
sha256    fnv=ab0624b961d45259     aes256cbc fnv=889fb3dcc628ed12
aes256ctr fnv=6b642726bef75efc     aes128ctr fnv=22b7db75d62a2fe1
aes128cbc fnv=ae561610192139a0     aes192ctr fnv=2006a9e3cc50c427
aes192cbc fnv=15c07267dcb1cd79
```

## 2. Zvkned 指令面的实测边界（Bianbu binutils 2.46）

| 助记符 | 可编 | 备注 |
|---|---|---|
| `vaesem.vv vd, vs2` | 是 | 中间轮（含 MixColumns） |
| `vaesef.vv vd, vs2` | 是 | 末轮（不含 MixColumns） |
| `vaesefs.vv` / `vaesel.vv` / 3 操作数形式 / `.vs` 形式 | 否 | 全部 FAIL |

`/usr/lib/gcc/riscv64-linux-gnu/15/include/riscv_crypto.h`（309 行）只有 zknd/zksed 标量 intrinsic，
**没有 vaes 向量 intrinsic**，只能内联汇编。

裸向量 asm 必须先设 `vl`：纯 asm 程序在没有 `vsetivli zero,4,e32,m1` 前执行 `vle32` 会 segfault。

## 3. 语义实证（不猜）

零基准单轮对拍，`in[i]=i*17+3`、`key[i]=i+1`：

| 指令 | 实测 | Python 独立实现 |
|---|---|---|
| `vaesem.vv v8,v9` | `ab7eba9883fc2f86ae75dc3a40d57fd1` | SubBytes+ShiftRows+**MixColumns**+AddKey，一致 |
| `vaesef.vv v8,v9` | `7a689673a5d8a60d34eb34d687f4f6be` | SubBytes+ShiftRows+AddKey，一致 |

⇒ 状态在 **vd**（同时是目标），轮密钥在 **vs2**。

## 4. 最难的一坑：Crypto++ 只对首末轮 round key 做字节反转

`Rijndael::Base::UncheckedSetKey` 用 `GetUserKey(BIG_ENDIAN_ORDER, rk, ...)` 写成大端 word，之后：

```c
ConditionalByteReverse(BIG_ENDIAN_ORDER, rk,              rk,              16);  // 轮 0
ConditionalByteReverse(BIG_ENDIAN_ORDER, rk + m_rounds*4, rk + m_rounds*4, 16);  // 轮 R
```

**只有首轮与末轮被反转，中间轮保持大端 word**。小端机上该调用是实反转，于是：

- `k[0]`、`k[R]` → 内存已是 AES 字节序，**直接 `vle32`**
- `k[1..R-1]` → 仍是大端 word，**必须 `vrev8`**

对全体轮做 `vrev8` 的指纹是"性能已 3× 但哈希不符、且输出不落在任何一轮中间态上"。
改成 `RvvLdKeyEdge` / `RvvLdKeyMid` 分开装载后，单块与 3 块 CTR 立即与 off 逐字节一致。

## 5. 派发层：实测没有额外收益（修正一条早期错误结论）

早期一次测量记录过"AES-256 单块只有 1.026×"，并据此推断"逐块虚调用的派发开销吃掉了轮函数收益"。
本轮用**受控实验**推翻了这个推断：把多块接管临时禁用（`if (0)` 替掉分派条件，重新编库），
同一份 64 KiB 负载测得：

| 版本 | AES-256 CTR | AES-256 CBC |
|---|---|---|
| 只走单块 `ProcessAndXorBlock`（禁用多块接管） | 0.302 / 0.310 ms | 0.313 / 0.332 ms |
| 接管 `AdvancedProcessBlocks`（轮密钥常驻） | 0.302 / 0.311 ms | 0.313 / 0.332 ms |

**两者完全等价**。K3 的乱序执行把每块 15 次 `vle32+vrev8` 的装载开销吸收进了 `vaesem` 的延迟里，
所以逐块虚调用在此尺寸下并不构成瓶颈。3.15× 全部归因于 **Zvkned 把一整轮压成一条指令**，
不是归因于派发粒度。

（早期 1.026× 的那次测量已作废：同轮 on/off 差异仅 2.6%，且与当前受控实验不一致，
说明该次测量取到了不可靠的中间态库。证据以本节的三轮重复 + 禁用对照为准。）

**保留多块接管的理由**：它是与单块等价的第二条路径，对**无乱序**或**小 VLEN** 的核可能有意义
（装载开销不会被吸收）；本机无法证实，故不作为性能结论引用。

## 6. 覆盖范围与边界

| 层面 | 状态 |
|---|---|
| AES-256 CTR | 多块接管（`m_rounds == 14` + `BT_InBlockIsCounter`） |
| AES-256 CBC 加密 | 多块接管（`m_rounds == 14` + 恰好 `BT_XorInput`） |
| AES-128 / AES-192 的 CTR 与 CBC | 未写多块，走单块 `ProcessAndXorBlock`（实测同样 3.2×） |
| 解密方向（`Dec`、CBC 解密） | 未做，回落 T-table |
| cbcmac / ccm / cmac | 不接管（它们另带 `BT_DontIncrementInOutPointers`，已在分派里排除） |

CBC 的判据是"带 `BT_XorInput` 且不带 `BT_InBlockIsCounter`"：`modes.cpp` 里只有 CBC 加密用纯
`BT_XorInput`，cbcmac/ccm/cmac 一律额外带 `BT_DontIncrementInOutPointers`，因此不会误接管。

## 7. 复现

```bash
cd /root/rvv-k/cryptopp/src
M="-O2 -march=rv64gcv_zvkned_zvbb"
touch *.cpp && make -j8 libcryptopp.a CXXFLAGS="$M -DCRYPTOPP_RVV_AES"; cp libcryptopp.a libcryptopp_on.a
touch *.cpp && make -j8 libcryptopp.a CXXFLAGS="$M"                        # off 侧
cd .. && g++ $M -I src test/pkg_cryptopp.cpp src/libcryptopp.a     -o bench_off
       g++ $M -I src test/pkg_cryptopp.cpp src/libcryptopp_on.a -o bench_on
./bench_off /tmp/c_off.bin 5; ./bench_on /tmp/c_on.bin 5; cmp /tmp/c_off.bin /tmp/c_on.bin
```

坑：`make` 会**直接覆盖** `libcryptopp.a`，on 侧必须先 `cp` 另存再编 off 侧；
`g++` 链接静态库必须把 `.a` 放**命令行最后**。

## 8. 复现用的中间样机（板上）

| 文件 | 用途 |
|---|---|
| `vt.c` | 纯 asm 单轮，验证"必须先 `vsetivli`" |
| `vt2.c` | intrinsic + `vrev8` + asm 单轮 |
| `vt3.c` | 60 个 round-key 常量做完整 14 轮（`8c5b77dfa6593649d2620ad83c244a88`） |
| `k1.cpp` | 单块 + 3 块 CTR 小样本（`8c5871d6aa56245c…`） |

`vt3.c` 是定位"首末轮 key 不反转"的关键工具：它用标准 key schedule 常量独立复现出与 off 相同的密文，
从而把问题锁定在 Crypto++ 的 `m_key` 布局，而不是轮函数或指令语义。

## 9. 后续

- 解密方向：需要 `vaesdm`/`vaesdf`（`Dec` 的 `m_key` 是 `Rijndael_UncheckedSetKeyRev` 形式，
  riscv 上不存在，要自己做 InvMixColumns 变换）。
- AES-GCM：上层 `GCM` 走 `ProcessBlock` 单块流，收益取决于能否拿到多块接口。
