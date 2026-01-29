#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLIPSTREAM_DIR="${SLIPSTREAM_DIR:-"${ROOT_DIR}/../slipstream"}"
VECTOR_DIR="${ROOT_DIR}/tools/vector_gen"
BUILD_DIR="${VECTOR_DIR}/build"
OUTPUT_DIR="${ROOT_DIR}/fixtures/vectors"

if [[ ! -d "${SLIPSTREAM_DIR}" ]]; then
  echo "Slipstream C repo not found at ${SLIPSTREAM_DIR}." >&2
  echo "Clone https://github.com/EndPositive/slipstream and set SLIPSTREAM_DIR to override." >&2
  exit 1
fi

required_files=(
  "extern/SPCDNS/src/codec.c"
  "extern/SPCDNS/src/mappings.c"
  "extern/lua-resty-base-encoding/base32.c"
  "src/slipstream_inline_dots.c"
)

for rel_path in "${required_files[@]}"; do
  if [[ ! -f "${SLIPSTREAM_DIR}/${rel_path}" ]]; then
    echo "Missing ${rel_path} in ${SLIPSTREAM_DIR}." >&2
    echo "Ensure the C repo is checked out with submodules." >&2
    exit 1
  fi
done

mkdir -p "${BUILD_DIR}" "${OUTPUT_DIR}"

cc -std=c99 -O2 \
  -I"${SLIPSTREAM_DIR}/extern/SPCDNS/src" \
  -I"${SLIPSTREAM_DIR}/extern/lua-resty-base-encoding" \
  -I"${SLIPSTREAM_DIR}/include" \
  "${VECTOR_DIR}/gen_vectors.c" \
  "${SLIPSTREAM_DIR}/extern/SPCDNS/src/codec.c" \
  "${SLIPSTREAM_DIR}/extern/SPCDNS/src/mappings.c" \
  "${SLIPSTREAM_DIR}/extern/lua-resty-base-encoding/base32.c" \
  "${SLIPSTREAM_DIR}/src/slipstream_inline_dots.c" \
  -lm \
  -o "${BUILD_DIR}/gen_vectors"

"${BUILD_DIR}/gen_vectors" "${VECTOR_DIR}/vectors.txt" > "${OUTPUT_DIR}/dns-vectors.json"

printf "Wrote %s\n" "${OUTPUT_DIR}/dns-vectors.json"
