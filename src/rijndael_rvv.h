/* rijndael_rvv.h -- Zvkned AES 内核（RVV）
 *
 * 两层：
 *   1) 单块：ProcessAndXorBlock 用一条 vaesem 代一整轮
 *   2) 多块：AdvancedProcessBlocks 接管 CTR 形态（BT_InBlockIsCounter），
 *      把 15 个轮密钥一次装进寄存器常驻，省掉每块 14 次密钥装载与虚调用
 *
 * 字节序：状态按内存原序 vle32 装载（AES state byte = 4*col + row，与 block 布局一致）；
 *        轮密钥在 Crypto++ 里是大端 word，装载后必须 vrev8 转成内存字节序。
 * 轮函数：中间轮 vaesem（含 MixColumns），最后一轮 vaesef（不含）。
 *
 * 开关 -DCRYPTOPP_RVV_AES，需 -march 含 zvkned 与 zvbb。
 */
#ifndef CRYPTOPP_RIJNDAEL_RVV_H
#define CRYPTOPP_RIJNDAEL_RVV_H

#if defined(CRYPTOPP_RVV_AES)

#include <stdint.h>
#include <riscv_vector.h>

/* 装载轮密钥。
 * 坑：Crypto++ 的 UncheckedSetKey 只对**首轮与末轮**做 ConditionalByteReverse(BIG_ENDIAN_ORDER)，
 *     中间轮保持大端 word 原样。所以：中间轮要 vrev8，首末轮直接装载。 */
static inline vuint32m1_t RvvLdKeyMid(const uint32_t *p)
{
	return __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1(p, 4), 4);
}
static inline vuint32m1_t RvvLdKeyEdge(const uint32_t *p)
{
	return __riscv_vle32_v_u32m1(p, 4);
}

#endif
#endif
