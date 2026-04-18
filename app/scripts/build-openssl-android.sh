#!/bin/bash
#
# Build OpenSSL for Android (all ABIs)
# Usage: ./build-openssl-android.sh
#
# Environment variables:
#   OPENSSL_VERSION - OpenSSL version to build (default: 3.0.15)
#   OUTPUT_DIR - Output directory (default: ~/android-openssl/android-ssl)
#   ANDROID_NDK_HOME - Path to Android NDK
#

set -e

OPENSSL_VERSION="${OPENSSL_VERSION:-3.0.15}"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/android-openssl/android-ssl}"
ANDROID_API=24

# Find NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "$HOME/Library/Android/sdk/ndk"/*/ 2>/dev/null | head -1 | sed 's:/$::')
    elif [ -d "$ANDROID_HOME/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME/ndk"/*/ 2>/dev/null | head -1 | sed 's:/$::')
    fi
fi

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "Error: Android NDK not found. Set ANDROID_NDK_HOME environment variable."
    exit 1
fi

echo "Using NDK: $ANDROID_NDK_HOME"
echo "OpenSSL version: $OPENSSL_VERSION"
echo "Output directory: $OUTPUT_DIR"

# Create working directory
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"

echo "Working directory: $WORK_DIR"

# Download OpenSSL
echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
curl -LO "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

# Detect host platform
case "$(uname -s)" in
    Darwin*)
        HOST_TAG="darwin-x86_64"
        ;;
    Linux*)
        HOST_TAG="linux-x86_64"
        ;;
    *)
        echo "Unsupported host platform"
        exit 1
        ;;
esac

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"

# Build function
build_openssl() {
    local ABI=$1
    local TARGET=$2
    local ARCH=$3

    echo ""
    echo "=========================================="
    echo "Building OpenSSL for $ABI"
    echo "=========================================="

    export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
    export PATH="$TOOLCHAIN/bin:$PATH"

    local OUTPUT="$OUTPUT_DIR/$ABI"
    mkdir -p "$OUTPUT"

    make clean 2>/dev/null || true

    ./Configure "$TARGET" \
        -D__ANDROID_API__=$ANDROID_API \
        --prefix="$OUTPUT" \
        --openssldir="$OUTPUT" \
        no-shared \
        no-tests \
        no-ui-console

    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make install_sw

    echo "OpenSSL for $ABI installed to $OUTPUT"
}

# Build for each ABI
build_openssl "arm64-v8a" "android-arm64" "aarch64"
build_openssl "armeabi-v7a" "android-arm" "arm"
build_openssl "x86_64" "android-x86_64" "x86_64"
build_openssl "x86" "android-x86" "x86"

# Cleanup
cd /
rm -rf "$WORK_DIR"

echo ""
echo "=========================================="
echo "OpenSSL build complete!"
echo "Output directory: $OUTPUT_DIR"
echo "=========================================="
