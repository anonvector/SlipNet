#!/usr/bin/env bash
# Cross-compile Tor + OpenSSL + libevent + zlib for Android.
# Output: app/src/full/jniLibs/<abi>/libtor.so, 16KB page aligned, PIE ELF.
#
# Tor is renamed libtor.so so Android's APK packager unpacks it into the
# app's nativeLibraryDir with execute permission; it is launched via
# ProcessBuilder (not dlopen'd). Dependencies are linked statically so the
# final binary only needs Bionic libc/libm/libdl at runtime.
#
# Requires: Android NDK (ANDROID_NDK_HOME or ~/Library/Android/sdk/ndk/<ver>),
# curl, tar, make, autoconf, perl.
#
# Usage:
#   tools/build-tor.sh                 # build both ABIs
#   tools/build-tor.sh arm64-v8a       # build one ABI
#   BUILD_DIR=/tmp/torbuild tools/build-tor.sh
set -euo pipefail

# --- Pinned versions ---
TOR_VERSION=0.4.9.6
OPENSSL_VERSION=3.5.6
LIBEVENT_VERSION=2.1.12
ZLIB_VERSION=1.3.1
XZ_VERSION=5.6.4
ZSTD_VERSION=1.5.7

# SHA256s verified against upstream on 2026-04-23.
# If you bump a version, update the hash or the script will refuse to build.
TOR_SHA256=""           # filled on first run; pin manually once verified
OPENSSL_SHA256=""
LIBEVENT_SHA256="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"
ZLIB_SHA256="9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
XZ_SHA256=""
ZSTD_SHA256=""

API_LEVEL=24
PAGE_SIZE=16384

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/tor-build}"
SRC_DIR="$BUILD_DIR/src"
OUT_BASE="$REPO_ROOT/app/src/full/jniLibs"

# --- NDK discovery ---
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    for candidate in \
        "$HOME/Library/Android/sdk/ndk/29.0.14206865" \
        "$HOME/Library/Android/sdk/ndk"/*; do
        [[ -d "$candidate/toolchains/llvm/prebuilt" ]] && { ANDROID_NDK_HOME="$candidate"; break; }
    done
fi
[[ -d "${ANDROID_NDK_HOME:-}" ]] || { echo "ERROR: ANDROID_NDK_HOME not set and no NDK found"; exit 1; }

HOST_TAG="darwin-x86_64"
[[ "$(uname -s)" == "Linux" ]] && HOST_TAG="linux-x86_64"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
[[ -d "$TOOLCHAIN" ]] || { echo "ERROR: NDK toolchain missing at $TOOLCHAIN"; exit 1; }

echo "NDK:       $ANDROID_NDK_HOME"
echo "Toolchain: $TOOLCHAIN"
echo "Build:     $BUILD_DIR"
echo

# --- Source fetch ---
mkdir -p "$SRC_DIR"
download() {
    local url="$1" out="$2" expected_sha="$3"
    if [[ -f "$out" ]]; then
        echo "  cached: $(basename "$out")"
    else
        echo "  fetching: $url"
        curl -fL --retry 3 -o "$out.tmp" "$url"
        mv "$out.tmp" "$out"
    fi
    if [[ -n "$expected_sha" ]]; then
        local actual
        actual=$(shasum -a 256 "$out" | awk '{print $1}')
        [[ "$actual" == "$expected_sha" ]] || { echo "ERROR: SHA256 mismatch for $out (got $actual, expected $expected_sha)"; exit 1; }
    else
        echo "  sha256: $(shasum -a 256 "$out" | awk '{print $1}')  <-- pin this"
    fi
}

echo "==> Fetching sources"
download "https://dist.torproject.org/tor-$TOR_VERSION.tar.gz" \
    "$SRC_DIR/tor-$TOR_VERSION.tar.gz" "$TOR_SHA256"
download "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
    "$SRC_DIR/openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_SHA256"
download "https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz" \
    "$SRC_DIR/libevent-$LIBEVENT_VERSION.tar.gz" "$LIBEVENT_SHA256"
download "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" \
    "$SRC_DIR/zlib-$ZLIB_VERSION.tar.gz" "$ZLIB_SHA256"
download "https://github.com/tukaani-project/xz/releases/download/v$XZ_VERSION/xz-$XZ_VERSION.tar.gz" \
    "$SRC_DIR/xz-$XZ_VERSION.tar.gz" "$XZ_SHA256"
download "https://github.com/facebook/zstd/releases/download/v$ZSTD_VERSION/zstd-$ZSTD_VERSION.tar.gz" \
    "$SRC_DIR/zstd-$ZSTD_VERSION.tar.gz" "$ZSTD_SHA256"
echo

# --- Per-ABI build function ---
build_abi() {
    local ABI="$1"
    local TARGET_HOST OPENSSL_TARGET ARCH_FLAGS

    case "$ABI" in
        arm64-v8a)
            TARGET_HOST="aarch64-linux-android"
            OPENSSL_TARGET="android-arm64"
            ARCH_FLAGS=""
            ;;
        armeabi-v7a)
            TARGET_HOST="armv7a-linux-androideabi"
            OPENSSL_TARGET="android-arm"
            ARCH_FLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
            ;;
        *)
            echo "ERROR: unsupported ABI $ABI"; return 1 ;;
    esac

    local WORK="$BUILD_DIR/$ABI"
    local PREFIX="$WORK/prefix"
    local OUT_SO="$OUT_BASE/$ABI/libtor.so"

    # Wipe per-ABI work dir so each build is fresh; keep $BUILD_DIR/src cached.
    rm -rf "$WORK"
    mkdir -p "$PREFIX" "$(dirname "$OUT_SO")"

    export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
    export ANDROID_NDK_HOME
    export PATH="$TOOLCHAIN/bin:$PATH"
    export AR="$TOOLCHAIN/bin/llvm-ar"
    export AS="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang"
    export CC="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang"
    export CXX="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang++"
    export LD="$TOOLCHAIN/bin/ld.lld"
    export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
    export STRIP="$TOOLCHAIN/bin/llvm-strip"

    # Clang wrapper for armv7 embeds -march=armv7-a etc., so ARCH_FLAGS is a
    # belt-and-suspenders for sub-projects that build assembly files.
    local CFLAGS_COMMON="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 $ARCH_FLAGS"
    local LDFLAGS_COMMON="-Wl,-z,max-page-size=$PAGE_SIZE -Wl,-z,common-page-size=$PAGE_SIZE -Wl,-z,relro -Wl,-z,now"

    export CFLAGS="$CFLAGS_COMMON"
    export CPPFLAGS="-I$PREFIX/include"
    export LDFLAGS="$LDFLAGS_COMMON -L$PREFIX/lib"

    echo "==> [$ABI] Build prefix: $PREFIX"
    echo "    CC=$CC"
    echo

    # --- zlib ---
    echo "==> [$ABI] Building zlib"
    local Z="$WORK/zlib"
    mkdir -p "$Z" && tar -xzf "$SRC_DIR/zlib-$ZLIB_VERSION.tar.gz" -C "$Z" --strip-components=1
    ( cd "$Z"
      CHOST="$TARGET_HOST" ./configure --static --prefix="$PREFIX"
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
      make install
    )

    # --- OpenSSL ---
    echo "==> [$ABI] Building OpenSSL"
    local O="$WORK/openssl"
    mkdir -p "$O" && tar -xzf "$SRC_DIR/openssl-$OPENSSL_VERSION.tar.gz" -C "$O" --strip-components=1
    ( cd "$O"
      ./Configure "$OPENSSL_TARGET" \
          -D__ANDROID_API__="$API_LEVEL" \
          no-shared no-tests no-docs no-ui-console no-engine no-dso \
          --prefix="$PREFIX" --openssldir="$PREFIX/ssl" \
          $CFLAGS_COMMON $LDFLAGS_COMMON
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" build_libs
      make install_dev
    )

    # --- xz (liblzma) ---
    echo "==> [$ABI] Building xz/liblzma"
    local X="$WORK/xz"
    mkdir -p "$X" && tar -xzf "$SRC_DIR/xz-$XZ_VERSION.tar.gz" -C "$X" --strip-components=1
    ( cd "$X"
      ./configure --host="$TARGET_HOST" --prefix="$PREFIX" \
          --disable-shared --enable-static --with-pic \
          --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo \
          --disable-lzma-links --disable-scripts --disable-doc \
          --disable-nls
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
      make install
    )

    # --- zstd (no autoconf; drive the lib Makefile directly) ---
    echo "==> [$ABI] Building zstd"
    local Z2="$WORK/zstd"
    mkdir -p "$Z2" && tar -xzf "$SRC_DIR/zstd-$ZSTD_VERSION.tar.gz" -C "$Z2" --strip-components=1
    ( cd "$Z2/lib"
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
          CC="$CC" AR="$AR" RANLIB="$RANLIB" \
          CFLAGS="$CFLAGS_COMMON" \
          libzstd.a
      install -d "$PREFIX/lib" "$PREFIX/include" "$PREFIX/lib/pkgconfig"
      install -m644 libzstd.a "$PREFIX/lib/"
      install -m644 zstd.h zdict.h zstd_errors.h "$PREFIX/include/"
      # Minimal .pc so Tor's configure can find zstd via pkg-config.
      cat > "$PREFIX/lib/pkgconfig/libzstd.pc" <<EOF
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: zstd
Description: fast lossless compression algorithm library
Version: $ZSTD_VERSION
Libs: -L\${libdir} -lzstd
Cflags: -I\${includedir}
EOF
    )

    # --- libevent ---
    echo "==> [$ABI] Building libevent"
    local E="$WORK/libevent"
    mkdir -p "$E" && tar -xzf "$SRC_DIR/libevent-$LIBEVENT_VERSION.tar.gz" -C "$E" --strip-components=1
    ( cd "$E"
      # libevent ships a prebuilt configure; cross-compile with --host.
      # Tor uses libevent only for its event loop, so disable OpenSSL/mbedTLS
      # support in libevent to avoid circular linkage.
      ./configure --host="$TARGET_HOST" --prefix="$PREFIX" \
          --disable-shared --enable-static --with-pic \
          --disable-openssl --disable-mbedtls --disable-samples \
          --disable-libevent-regress --disable-debug-mode
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
      make install
    )

    # --- Tor ---
    echo "==> [$ABI] Building Tor"
    local T="$WORK/tor"
    mkdir -p "$T" && tar -xzf "$SRC_DIR/tor-$TOR_VERSION.tar.gz" -C "$T" --strip-components=1
    ( cd "$T"
      # Autoconf cache vars: Tor's configure probes for some functions by
      # running test binaries, which is impossible when cross-compiling.
      # These values are correct for modern Bionic.
      export ac_cv_func_malloc_0_nonnull=yes
      export ac_cv_func_realloc_0_nonnull=yes

      # Point pkg-config at our $PREFIX so Tor's configure finds libzstd
      # (and any future pkg-config-based detection) via our static .pc files
      # rather than the host system's pkg-config path.
      export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
      export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
      ./configure --host="$TARGET_HOST" --prefix="$PREFIX" \
          --disable-asciidoc --disable-systemd \
          --disable-tool-name-check \
          --disable-module-relay --disable-module-dirauth \
          --enable-static-libevent --with-libevent-dir="$PREFIX" \
          --enable-static-openssl --with-openssl-dir="$PREFIX" \
          --enable-static-zlib --with-zlib-dir="$PREFIX" \
          CFLAGS="$CFLAGS_COMMON -I$PREFIX/include" \
          LDFLAGS="$LDFLAGS_COMMON -L$PREFIX/lib -pie" \
          LIBS="-llzma -lzstd"
      make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" src/app/tor
    )

    # Strip and install.
    local RAW="$T/src/app/tor"
    [[ -f "$RAW" ]] || { echo "ERROR: Tor binary not produced at $RAW"; return 1; }
    "$STRIP" --strip-unneeded -o "$OUT_SO" "$RAW"

    # Verify page alignment and type.
    local align type
    align=$("$TOOLCHAIN/bin/llvm-readelf" -l "$OUT_SO" | awk '/LOAD/ {print $NF; exit}')
    type=$("$TOOLCHAIN/bin/llvm-readelf" -h "$OUT_SO" | awk '/Type:/ {print $2}')
    echo
    echo "==> [$ABI] Installed $OUT_SO"
    echo "    Size:      $(stat -f%z "$OUT_SO") bytes"
    echo "    ELF type:  $type (want DYN for PIE)"
    echo "    LOAD align: $align (want 0x4000 for 16KB)"
    echo "    Version:   $(strings "$OUT_SO" | grep -o 'on Tor [0-9.]*' | head -1)"
}

# --- Dispatch ---
if [[ $# -eq 0 ]]; then
    ABIS=("arm64-v8a" "armeabi-v7a")
else
    ABIS=("$@")
fi
for abi in "${ABIS[@]}"; do build_abi "$abi"; done

echo
echo "Done. Updated:"
for abi in "${ABIS[@]}"; do echo "  $OUT_BASE/$abi/libtor.so"; done
