# G3 内核：crypto++ AES-256-CTR（Zvkned）

日期 2026-11-16 · 板子 SpacemiT K3（`10.91.8.28`，Bianbu，`gcc 15.2.0`，`vlenb=32`）
门禁：功能逐字节 + 真机 A/B 性能（两侧同 `-march`、同 `-O2`，唯一变量 `-DCRYPTOPP_RVV_AES`）

## 1. 结论

| 项 | off（上游 C） | on（RVV Zvkned） | 倍率 |
|---|---|---|---|
| AES-256-CTR 64 KiB | 0.951 ms（best-of-5，三轮 0.951/0.951/0.976） | **0.302 ms**（三轮全部 0.302） | **3.15×** |
| SHA-256 64 KiB（对照，未改动） | 0.776–0.821 ms | 0.780–0.789 ms | 1.00×（无变化，证明 A/B 只有一个变量） |

功能：`aesctr fnv=6b642726bef75efc`、`sha256 fnv=ab0624b961d45259`，两侧与 G2 基线一致，`cmp` 逐字节 `BYTES_SAME`。

## 2. Zvkned 指令面的实测边界（Bianbu binutils 2.46）

`as` 只认 **2 操作数**、只有两条：

| 助记符 | 结果 |
|---|---|
| `vaesem.vv vd, vs2` | 可编（中间轮，含 MixColumns） |
| `vaesef.vv vd, vs2` | 可编（最后一轮，不含 MixColumns） |
| `vaesefs.vv` / `vaesel.vv` / 3 操作数形式 / `.vs` 形式 | 全部 FAIL |

`/usr/lib/gcc/riscv64-linux-gnu/15/include/riscv_crypto.h` 只有 zknd/zksed 相关标量 intrinsic，**没有 vaes 向量 intrinsic**，因此必须内联汇编。

真机不崩溃的前提：任何裸向量指令前必须先设 `vl`。纯 asm 程序启用 `vsetivli zero,4,e32,m1` 前直接执行会 segfault。

## 3. 语义实证（不猜）

零基准单轮对拍，输入 `in[i]=i*17+3`、`key[i]=i+1`：

| 指令 | 实测输出 | Python 独立实现（SubBytes+ShiftRows[+MixColumns]+AddKey） |
|---|---|---|
| `vaesem.vv v8,v9` | `ab7eba9883fc2f86ae75dc3a40d57fd1` | 同（含 MixColumns） |
| `vaesef.vv v8,v9` | `7a689673a5d8a60d34eb34d687f4f6be` | 同（不含 MixColumns） |

⇒ **状态在 vd（同时是目标），轮密钥在 vs2**，语义与 AES 的 middle/final 轮一致。

## 4. 最难的一坑：Crypto++ 只对首末轮 round key 做字节反转

`Rijndael::Base::UncheckedSetKey` 用 `GetUserKey(BIG_ENDIAN_ORDER, rk, ...)` 把用户密钥写成大端 word，随后：

```c
ConditionalByteReverse(BIG_ENDIAN_ORDER, rk,                 rk,                 16);  // 轮 0
ConditionalByteReverse(BIG_ENDIAN_ORDER, rk + m_rounds*4,    rk + m_rounds*4,    16);  // 轮 R
```

**只有首轮与末轮被反转，中间轮保持大端 word 原样**。在小端机器上 `ConditionalByteReverse(BIG_ENDIAN_ORDER, ...)` 是实反转，于是：

- `k[0]`、`k[R]`：内存已是 AES 字节序 → **直接 `vle32`**
- `k[1..R-1]`：仍是大端 word → **必须 `vrev8`**

对全部轮都做 `vrev8` 会让首末两轮错位。表现是"性能已 3× 但哈希不符"，且输出不落在任何一轮的中间态上——这正是本坑的指纹。

修正后单块与 3 块 CTR 立即与 off 逐字节一致。

## 5. 单块为何只有 1.026×

首版只在 `Enc::ProcessAndXorBlock` 内加速。`BlockTransformation::AdvancedProcessBlocks`（`src/cryptlib.cpp:141`）的默认实现是**逐块虚调用**：

```cpp
while (length >= blockSize) {
    ProcessAndXorBlock(inBlocks, xorBlocks, outBlocks);
    if (flags & BT_InBlockIsCounter) const_cast<byte*>(inBlocks)[blockSize-1]++;
    ...
}
```

每块要付一次虚调用 + 每轮一次密钥装载（14 次 `vle32`+`vrev8`），把轮函数本身的收益吃掉了：0.976 → 0.951 ms，仅 1.026×。

## 6. 接管 AdvancedProcessBlocks

`CTR_ModePolicy::OperateKeystream`（`src/modes.cpp:159`）调用：

```cpp
AdvancedProcessBlocks(m_counterArray, input, output, blocks*s,
                      BT_InBlockIsCounter | BT_AllowParallel);
```

其中 `blocks = min(iterationCount, 256u - lsb)`，保证低字节不 wrap；`inBlocks` 是计数器（实现负责 `inBlocks[15]++`），`xorBlocks` 是明文。

实现（`src/rijndael.cpp`，`#if defined(CRYPTOPP_RVV_AES)`）：

- 只接管 `m_rounds == 14` 且 flags 恰为 `BT_InBlockIsCounter` 的纯 CTR；CBC/XTS/反向/`BT_XorInput` 一律回落基类，保证语义不越界。
- **15 个轮密钥一次装进 15 个 m1 向量寄存器**（K3 共 32 个），循环体内只剩 14 条 `vaesem`/`vaesef` + 1 条 `vxor` + 逐块 `ctr[15]++`。
- 首末轮用 `RvvLdKeyEdge`（不 `vrev8`），中间轮用 `RvvLdKeyMid`（`vrev8`）。
- 裸 asm 全部标 `volatile`，入口显式 `vsetivli zero,4,e32,m1`。

## 7. 复现

```bash
# 真机（Bianbu, gcc 15）
cd /root/rvv-k/cryptopp/src
M="-O2 -march=rv64gcv_zvkned_zvbb"
touch *.cpp && make -j8 libcryptopp.a CXXFLAGS="$M -DCRYPTOPP_RVV_AES"; cp libcryptopp.a libcryptopp_on.a
touch *.cpp && make -j8 libcryptopp.a CXXFLAGS="$M"                        # off 侧
cd .. && g++ $M -I src test/pkg_cryptopp.cpp src/libcryptopp.a     -o bench_off
       g++ $M -I src test/pkg_cryptopp.cpp src/libcryptopp_on.a -o bench_on
./bench_off /tmp/c_off.bin 5; ./bench_on /tmp/c_on.bin 5; cmp /tmp/c_off.bin /tmp/c_on.bin
```

注意：`make` 会直接覆盖 `libcryptopp.a`，所以 on 侧必须先 `cp` 另存再编 off 侧；`g++` 链接静态库必须把库放**命令行最后**（放前面会 undefined reference）。

## 8. 后续

- AES-128/192 的 CTR（`m_rounds != 14`）目前回落逐块路径，可同样接管。
- CBC 走 `BitBlockCipher` 的 `AdvancedProcessBlocks`，flags 不是 `BT_InBlockIsCounter`，需单独一套（可复用同样的密钥常驻骨架）。
- AES-GCM 的上层是 `GCM` 模式，走 `ProcessBlock` 流，收益取决于是否能拿到多块接口。
