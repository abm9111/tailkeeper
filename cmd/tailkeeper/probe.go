package main

import (
	"context"
	"io"

	"github.com/abm9111/tailkeeper/internal/api"
)

// probeCommand is `tailkeeper probe-acl`. It is nil unless the binary was built with
// -tags probe, which only `make probe-acl` does (probe_on.go sets it). A release is built
// without the tag, so it contains neither the command nor the probe package.
var probeCommand func(ctx context.Context, c *api.Client, args []string, stdout, stderr io.Writer) int
