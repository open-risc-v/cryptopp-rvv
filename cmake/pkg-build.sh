#!/usr/bin/env bash
# 构建上游 cryptopp（GNUmakefile）→ <out>/prefix：静态库 libcryptopp.a + 头。
# 上游不提供 install 目标，这里手工造前缀；HOST/CC/CXX 由调用方给（交叉时指向 riscv 工具链）。
set -euo pipefail
SRC=$1
OUT=$2
MARCH=${3:-rv64gcv}
KERN=${4:-0}
EXTRA_MARCH=""
if [ "$KERN" = "1" ]; then EXTRA_MARCH="-march=${MARCH} -DRVV_KERNELS=1"; fi
rm -rf "${OUT}"
mkdir -p "${OUT}/prefix/include" "${OUT}/prefix/lib" "${OUT}/src"
cp -R "${SRC}" "${OUT}/src/pkg"
cd "${OUT}/src/pkg"
NPROC=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
CXX_BIN=${CXX:-c++}
make -j"${NPROC}" static CXX="${CXX_BIN}" CXXFLAGS="${CXXFLAGS:--O2 -DNDEBUG -std=c++11} ${EXTRA_MARCH}" >/dev/null
cp *.h "${OUT}/prefix/include/"
cp libcryptopp.a "${OUT}/prefix/lib/"
echo "== 上游 cryptopp 构建完成：${OUT}/prefix"
