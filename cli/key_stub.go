//go:build !has_config_key

package main

import "encoding/hex"

// configKey is set via -ldflags "-X main.configKey=<hex>" at build time.
var configKey string

// configKeyBytes returns the decoded config encryption key, or nil if not set.
func configKeyBytes() []byte {
	if configKey == "" {
		return nil
	}
	key, err := hex.DecodeString(configKey)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}
