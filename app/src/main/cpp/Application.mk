# Application.mk for hev-socks5-tunnel

APP_ABI := arm64-v8a armeabi-v7a
APP_PLATFORM := android-24
APP_OPTIM := release
APP_STL := none

# Reproducible builds: strip the checkout location from __FILE__ strings (lwIP
# asserts) and debug info, as -trimpath does for Go and --remap-path-prefix
# for Rust.
SLIPNET_CPP_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
APP_CFLAGS += -ffile-prefix-map=$(SLIPNET_CPP_DIR)=. -ffile-prefix-map=$(HOME)=~
