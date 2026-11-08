package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// Caller is who asked for a tool call, as the surface that received the call says: the
// command line ("cli"), an MCP client ("mcp", "mcp-resource") or the doctor ("doctor"). A
// surface sets it with WithCaller before it runs a tool. It is never read from a tool's
// input: input is the caller's text, and a record that names the caller must not be
// writable by it.
type Caller struct {
	Kind   string
	Client string // the client's self-declared name, already sanitized and capped by the surface
}

// Call is what the framework knows about the tool call in progress. Prepared.Run sets it, so
// code that runs under a tool can record what it did against the call that asked for it.
type Call struct {
	Tool   string // the registered name of the tool
	ID     string // 16 hexadecimal digits, new for each call
	Caller Caller
}

type (
	callerKey struct{}
	callKey   struct{}
)

// WithCaller returns a context that names the caller of the tool calls made under it.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallOf returns the call in progress, or the zero Call when ctx is not under a tool call.
func CallOf(ctx context.Context) Call {
	c, _ := ctx.Value(callKey{}).(Call)
	return c
}

// withCall returns a context for one run of the tool: the caller the surface named, the
// tool, and a new identifier. A run inside a run gets an identifier of its own.
func withCall(ctx context.Context, tool string) context.Context {
	caller, _ := ctx.Value(callerKey{}).(Caller)
	return context.WithValue(ctx, callKey{}, Call{Tool: tool, ID: newCallID(), Caller: caller})
}

// newCallID is 8 random bytes in hexadecimal. A failure of the random source leaves the
// identifier empty, which a record shows as no correlation, never as a guessable one.
func newCallID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
