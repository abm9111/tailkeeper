// Command tailkeeper is the tailkeeper CLI and stdio MCP server.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/cli"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal the default handling returns, so a second Ctrl-C ends
	// the process at once instead of waiting for in-flight calls.
	go func() {
		<-ctx.Done()
		stop()
	}()
	r := &cli.Runner{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Build: func(ctx context.Context, contextName string) (*app.App, error) {
			return app.Build(ctx, app.Options{Context: contextName})
		},
		// The exec provider's wrapper injects the read credential and runs
		// tailkeeper again with the same arguments (spec §7.3).
		Reexec: func(p config.Provider) error {
			self, err := os.Executable()
			if err != nil {
				return tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot locate the tailkeeper binary to re-run it", "")
			}
			return creds.Reexec(p.Command, self, os.Args[1:])
		},
		ServeMCP: serveStdio,
	}
	code := r.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// shutdownGrace is how long the MCP server waits for in-flight calls after a
// signal before the process exits anyway.
const shutdownGrace = 2 * time.Second

// serveStdio serves MCP on stdin and stdout.
func serveStdio(ctx context.Context, srv *mcp.Server) error {
	return serve(ctx, srv, &mcp.StdioTransport{})
}

// serve runs srv on t until the client disconnects or a signal cancels ctx; after a
// signal, in-flight calls get shutdownGrace to finish.
func serve(ctx context.Context, srv *mcp.Server, t mcp.Transport) error {
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx, t) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	select {
	case err := <-done:
		return err
	case <-time.After(shutdownGrace):
		return ctx.Err()
	}
}
