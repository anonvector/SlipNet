.PHONY: build windows resolvers clean

VERSION ?= dev

# CONFIG_ENCRYPTION_KEY: 64-char hex string for slipnet-enc:// decryption.
# Pass via: make CONFIG_ENCRYPTION_KEY=abc123...
CONFIG_ENCRYPTION_KEY ?=

LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_TAGS :=

# When a config key is provided, generate XOR-obfuscated key file
ifneq ($(CONFIG_ENCRYPTION_KEY),)
	BUILD_TAGS += has_config_key
endif

build: keygen resolvers
	CGO_ENABLED=0 garble -seed=random build \
		-tags '$(BUILD_TAGS)' -trimpath \
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
