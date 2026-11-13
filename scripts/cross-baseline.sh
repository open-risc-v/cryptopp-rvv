#!/usr/bin/env bash
# 交叉编译基线版本：容器内把 baseline 编成 riscv64，探针用 qemu-user 跑，比对两侧哈希。
# 上游是 GNUmakefile（cryptopp）：直接给 CXX=riscv64-linux-gnu-g++，不需要 configure。
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-rvv-cross:2}
MARCH=${MARCH:-rv64gc}
OUT=build/riscv64-b
HARNESS=${HARNESS:-cryptopp_harness}

docker run --rm -v "$PWD":/work -w /work "${IMAGE}" bash -lc "
set -e
rm -rf ${OUT}
mkdir -p ${OUT}
CXX=riscv64-linux-gnu-g++ CXXFLAGS='-O2 -DNDEBUG -std=c++11 -march=${MARCH}' \
./cmake/pkg-build.sh /work/baseline /work/${OUT}/pkg > /tmp/pkg.log 2>&1 || { tail -30 /tmp/pkg.log; exit 1; }

cmake -S . -B ${OUT}/harness -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/work/cmake/toolchain-riscv64-linux.cmake \
  -DCMAKE_CXX_FLAGS='-march=${MARCH}' \
  -DPKG_PREFIX=/work/${OUT}/pkg/prefix > /tmp/h.log 2>&1 || { tail -30 /tmp/h.log; exit 1; }
cmake --build ${OUT}/harness -j > /tmp/hb.log 2>&1 || { tail -20 /tmp/hb.log; exit 1; }

mkdir -p ${OUT}/out
qemu-riscv64 -L /usr/riscv64-linux-gnu ${OUT}/harness/${HARNESS} ${OUT}/out/cryptopp.bin > ${OUT}/out/hash.txt \
  || { echo 'qemu 运行失败'; exit 1; }
echo '--- riscv64（${MARCH}）---'; cat ${OUT}/out/hash.txt
echo '--- native 基线 ---'; cat build/ab-data/out/01_cryptopp/a/hash.txt
"
