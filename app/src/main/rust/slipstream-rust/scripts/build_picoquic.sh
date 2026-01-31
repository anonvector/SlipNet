#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PICOQUIC_DIR="${PICOQUIC_DIR:-"${ROOT_DIR}/vendor/picoquic"}"
BUILD_DIR="${PICOQUIC_BUILD_DIR:-"${ROOT_DIR}/.picoquic-build"}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
FETCH_PTLS="${PICOQUIC_FETCH_PTLS:-ON}"

if [[ ! -d "${PICOQUIC_DIR}" ]]; then
  echo "picoquic not found at ${PICOQUIC_DIR}. Run: git submodule update --init --recursive" >&2
  exit 1
fi

CMAKE_ARGS=(
  "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
  "-DPICOQUIC_FETCH_PTLS=${FETCH_PTLS}"
  "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
  "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
)

BUILD_TARGET=()
if [[ -n "${CARGO_FEATURE_PICOQUIC_MINIMAL_BUILD:-}" ]]; then
  case "${CARGO_FEATURE_PICOQUIC_MINIMAL_BUILD,,}" in
    1|true|yes|on)
      CMAKE_ARGS+=(
        "-DBUILD_DEMO=OFF"
        "-DBUILD_HTTP=OFF"
        "-DBUILD_LOGLIB=OFF"
        "-DBUILD_LOGREADER=OFF"
        "-Dpicoquic_BUILD_TESTS=OFF"
      )
      BUILD_TARGET=(--target picoquic-core)
      ;;
  esac
fi

ANDROID_REQUESTED=""
if [[ -n "${PICOQUIC_ANDROID:-}" ]]; then
  ANDROID_REQUESTED=1
elif [[ -n "${PICOQUIC_TARGET:-}" && "${PICOQUIC_TARGET}" == *android* ]]; then
  ANDROID_REQUESTED=1
elif [[ -n "${TARGET:-}" && "${TARGET}" == *android* ]]; then
  ANDROID_REQUESTED=1
fi

if [[ -n "${ANDROID_REQUESTED}" ]]; then
  if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ANDROID_NDK_HOME must be set when building for Android." >&2
    exit 1
  fi
  TOOLCHAIN_FILE="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"
  if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    echo "Android NDK toolchain file not found at ${TOOLCHAIN_FILE}" >&2
    exit 1
  fi
  CMAKE_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}")
  CMAKE_ARGS+=("-DPTLS_WITH_FUSION=OFF")
  CMAKE_ARGS+=("-DWITH_FUSION=OFF")
  if [[ -n "${ANDROID_ABI:-}" ]]; then
    CMAKE_ARGS+=("-DANDROID_ABI=${ANDROID_ABI}")
  fi
  if [[ -n "${ANDROID_PLATFORM:-}" ]]; then
    CMAKE_ARGS+=("-DANDROID_PLATFORM=${ANDROID_PLATFORM}")
  fi
fi

if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
  CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
fi
if [[ -n "${OPENSSL_INCLUDE_DIR:-}" ]]; then
  CMAKE_ARGS+=("-DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
fi
if [[ -n "${OPENSSL_CRYPTO_LIBRARY:-}" ]]; then
  CMAKE_ARGS+=("-DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
fi
if [[ -n "${OPENSSL_SSL_LIBRARY:-}" ]]; then
  CMAKE_ARGS+=("-DOPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY}")
fi
if [[ -n "${OPENSSL_USE_STATIC_LIBS:-}" ]]; then
  CMAKE_ARGS+=("-DOPENSSL_USE_STATIC_LIBS=${OPENSSL_USE_STATIC_LIBS}")
fi

cmake -S "${PICOQUIC_DIR}" -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}"
if [[ ${#BUILD_TARGET[@]} -gt 0 ]]; then
  cmake --build "${BUILD_DIR}" "${BUILD_TARGET[@]}"
else
  cmake --build "${BUILD_DIR}"
fi
