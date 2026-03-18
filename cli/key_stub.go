//go:build !has_config_key

package main

// configKeyBytes returns nil when no config encryption key was embedded at build time.
func configKeyBytes() []byte { return nil }
