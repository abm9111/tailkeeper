// Package version holds the build version of tailkeeper.
package version

// Version is replaced at build time:
//
//	go build -ldflags "-X github.com/abm9111/tailkeeper/internal/version.Version=v0.1.0"
var Version = "dev"
