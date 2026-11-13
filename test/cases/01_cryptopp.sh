#!/usr/bin/env bash
# 真实包用例：cryptopp SHA-256 与 AES-256-CTR，输出确定性二进制 + 哈希文本。
set -euo pipefail
: "${STAGE:=run}" "${SIDE:=A}" "${BIN:=build/native}" "${DATA:=build/ab-data}" "${OUT:=build/ab-data/out}"
mkdir -p "$DATA" "$OUT"
case "$STAGE" in
  gen) : > "$DATA/cryptopp-input.txt" ;;
  run) "$BIN/cryptopp_harness" "$OUT/cryptopp.bin" > "$OUT/hash.txt" ;;
  *) echo "unknown STAGE=$STAGE" >&2; exit 2 ;;
esac
