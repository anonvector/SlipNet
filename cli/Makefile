.PHONY: build build-slipstream build-cli clean

VERSION ?= dev
RUST_DIR := ../app/src/main/rust/slipstream-rust
SLIPSTREAM_BIN := $(RUST_DIR)/target/release/slipstream-client

# CONFIG_ENCRYPTION_KEY: 64-char hex string for slipnet-enc:// decryption.
# Same key used by the Rust build (see slipstream-client/build.rs).
# Pass via: make CONFIG_ENCRYPTION_KEY=abc123...
CONFIG_ENCRYPTION_KEY ?=

LDFLAGS := -s -w -X main.version=$(VERSION)
ifneq ($(CONFIG_ENCRYPTION_KEY),)
	LDFLAGS += -X main.configKey=$(CONFIG_ENCRYPTION_KEY)
endif

# Default: full build (Rust + Go with embedded binary)
build: build-slipstream build-cli

build-slipstream:
	CONFIG_ENCRYPTION_KEY=$(CONFIG_ENCRYPTION_KEY) \
	cargo build --release --bin slipstream-client \
		--features openssl-vendored,picoquic-minimal-build \
		--manifest-path $(RUST_DIR)/Cargo.toml
	mkdir -p embedded
	cp $(SLIPSTREAM_BIN) embedded/slipstream-client

build-cli:
	CGO_ENABLED=0 go build -tags embed_slipstream -trimpath \
		-ldflags='$(LDFLAGS)' \
		-o slipnet .

# Go-only build (no embedded Slipstream — looks for it on PATH at runtime)
build-lite:
	CGO_ENABLED=0 go build -trimpath \
		-ldflags='$(LDFLAGS)' \
		-o slipnet .

clean:
	rm -f slipnet
	rm -rf embedded/slipstream-client
