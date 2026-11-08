//go:build ignore

// Command mcpb builds and verifies deterministic native MCP bundles.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/abm9111/tailkeeper/internal/releasebundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected build, verify or sbom")
	}
	switch args[0] {
	case "build":
		return build(args[1:])
	case "sbom":
		return sbom(args[1:])
	case "archive-sbom":
		return archiveSBOM(args[1:])
	case "verify":
		return verify(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	version := fs.String("version", "", "release version")
	universal := fs.String("universal", "", "universal executable")
	root := fs.String("root", "", "repository root")
	out := fs.String("out", "", "new output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	return releasebundle.Build(releasebundle.BuildOptions{Version: *version, UniversalPath: *universal, RootDir: *root, OutputPath: *out})
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "bundle file")
	dist := fs.String("dist", "", "release build directory")
	version := fs.String("version", "", "release version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	return releasebundle.Verify(*bundle, *dist, *version)
}

func sbom(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "bundle file")
	out := fs.String("out", "", "new output file")
	syft := fs.String("syft", "", "Syft executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *syft == "" {
		return fmt.Errorf("invalid arguments")
	}
	path, err := exec.LookPath(*syft)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	return releasebundle.WriteSBOM(context.Background(), *bundle, *out, path)
}

func archiveSBOM(args []string) error {
	fs := flag.NewFlagSet("archive-sbom", flag.ContinueOnError)
	archive := fs.String("archive", "", "release archive")
	dist := fs.String("dist", "", "release build directory")
	out := fs.String("out", "", "new output file")
	syft := fs.String("syft", "", "Syft executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *syft == "" {
		return fmt.Errorf("invalid arguments")
	}
	path, err := exec.LookPath(*syft)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	return releasebundle.WriteArchiveSBOM(context.Background(), *archive, *dist, *out, path)
}
