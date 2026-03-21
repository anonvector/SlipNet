.PHONY: build build-slipstream build-cli windows resolvers clean

VERSION ?= dev
RUST_DIR := ../app/src/main/rust/slipstream-rust
SLIPSTREAM_BIN := $(RUST_DIR)/target/release/slipstream-client

# CONFIG_ENCRYPTION_KEY: 64-char hex string for slipnet-enc:// decryption.
# Same key used by the Rust build (see slipstream-client/build.rs).
# Pass via: make CONFIG_ENCRYPTION_KEY=abc123...
CONFIG_ENCRYPTION_KEY ?=

LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_TAGS :=

# When a config key is provided, generate XOR-obfuscated key file
ifneq ($(CONFIG_ENCRYPTION_KEY),)
	BUILD_TAGS += has_config_key
endif

# Default: full build (Rust + Go with embedded binary)
build: build-slipstream build-cli

build-slipstream:
	CONFIG_ENCRYPTION_KEY=$(CONFIG_ENCRYPTION_KEY) \
	cargo build --release --bin slipstream-client \
		--features openssl-vendored,picoquic-minimal-build \
		--manifest-path $(RUST_DIR)/Cargo.toml
	mkdir -p embedded
	gzip -9 -c $(SLIPSTREAM_BIN) > embedded/slipstream-client.gz

build-cli: keygen resolvers
	CGO_ENABLED=0 garble -seed=random build \
		-tags 'embed_slipstream $(BUILD_TAGS)' -trimpath \
		-ldflags='$(LDFLAGS)' \
		-o slipnet .

windows: keygen resolvers
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 garble -seed=random build \
		-tags '$(BUILD_TAGS)' -trimpath \
		-ldflags='$(LDFLAGS)' \
		-o slipnet.exe .

# Copy resolver list from app resources for embedding into the binary
resolvers:
	cp ../app/src/main/res/raw/resolvers.txt resolvers.txt

# Generate XOR-obfuscated key file (or clean it for keyless builds)
keygen:
ifneq ($(CONFIG_ENCRYPTION_KEY),)
	go run ./cmd/keygen $(CONFIG_ENCRYPTION_KEY) > key_generated.go
else
	rm -f key_generated.go
endif

clean:
	rm -f slipnet slipnet.exe key_generated.go resolvers.txt
	rm -rf embedded/slipstream-client embedded/slipstream-client.gz
