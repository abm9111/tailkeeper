//go:build probe

package main

import "github.com/abm9111/tailkeeper/internal/probe"

func init() { probeCommand = probe.Command }
