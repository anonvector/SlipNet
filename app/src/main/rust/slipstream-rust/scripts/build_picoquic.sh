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
  case "$(echo "${CARGO_FEATURE_PICOQUIC_MINIMAL_BUILD}" | tr '[:upper:]' '[:lower:]')" in
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

# macOS cross-compilation (e.g. x86_64 on ARM64 runner)
if [[ -n "${CMAKE_OSX_ARCHITECTURES:-}" ]]; then
  CMAKE_ARGS+=("-DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}")
fi

# Windows: force-include wincompat.h (provides ssize_t, Winsock2.h) and
# ws2tcpip.h (provides sockaddr_in6, inet_pton) before any source file.
# This ensures all picoquic and picotls headers see these definitions.
if [[ "${OS:-}" == "Windows_NT" ]] || [[ "$(uname -s 2>/dev/null)" == MINGW* ]]; then
  WINCOMPAT_H="${PICOQUIC_DIR}/picoquic/wincompat.h"
  if command -v cygpath &>/dev/null; then
    WINCOMPAT_H="$(cygpath -w "${WINCOMPAT_H}")"
  fi
  CMAKE_ARGS+=("-DCMAKE_C_FLAGS_INIT=/FI\"${WINCOMPAT_H}\" /FI\"ws2tcpip.h\"")
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

# Prefer Ninja on non-Windows (much faster than make).
# On Windows, keep the Visual Studio generator — Ninja picks up MinGW GCC
# instead of MSVC, and the /FI flags are MSVC-specific.
IS_WINDOWS=""
if [[ "${OS:-}" == "Windows_NT" ]] || [[ "$(uname -s 2>/dev/null)" == MINGW* ]]; then
  IS_WINDOWS=1
fi
if [[ -z "${IS_WINDOWS}" ]] && command -v ninja &>/dev/null && [[ -z "${CMAKE_GENERATOR:-}" ]]; then
  CMAKE_ARGS+=("-G" "Ninja")
fi

cmake -S "${PICOQUIC_DIR}" -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}"
if [[ ${#BUILD_TARGET[@]} -gt 0 ]]; then
  cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" "${BUILD_TARGET[@]}"
else
  cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}"
fi
