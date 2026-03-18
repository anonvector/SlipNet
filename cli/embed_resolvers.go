package main

import _ "embed"

//go:embed resolvers.txt
var defaultResolverList []byte
