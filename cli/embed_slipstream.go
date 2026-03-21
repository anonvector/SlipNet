//go:build embed_slipstream

package main

import (
	_ "embed"
)

//go:embed embedded/slipstream-client.gz
var embeddedSlipstreamGz []byte
