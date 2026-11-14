package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// A raw MCP client: it writes JSON-RPC lines to the server's standard input and keeps
// every line the server prints on standard output, so a test sees exactly what a
// client would, and can close standard input as a client that goes away does. The SDK's
// client hides both.

// lineBuffer splits what a process writes into lines. Every line is kept, and a
// channel announces each one.
type lineBuffer struct {
	mu    sync.Mutex
	part  []byte
	lines []string
	ch    chan string
}

func newLineBuffer() *lineBuffer { return &lineBuffer{ch: make(chan string, 1024)} }

func (b *lineBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.part = append(b.part, p...)
	for {
		i := bytes.IndexByte(b.part, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(b.part[:i])
		b.part = b.part[i+1:]
		b.lines = append(b.lines, line)
		select {
		case b.ch <- line:
		default: // a test that reads none of them still sees them all in lines
		}
	}
}

// all returns every complete line so far, and the unfinished one after them.
func (b *lineBuffer) all() (lines []string, partial string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...), string(b.part)
}

// syncBuffer is a bytes.Buffer that a process and a test can use together.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// rawServer is a running `tailkeeper mcp` and the pipes to it.
type rawServer struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *lineBuffer
	stderr *syncBuffer
	exited chan struct{} // closed when the process has exited and its output is read
	err    error         // what Wait returned; valid once exited is closed
}

// startRawServer starts `tailkeeper args...` in env. The process is killed when the
// test ends, so a server that ignored what the test did to it cannot outlive it.
func startRawServer(t *testing.T, env []string, args ...string) *rawServer {
	t.Helper()
	s := &rawServer{t: t, cmd: exec.Command(bin, args...), stdout: newLineBuffer(), stderr: &syncBuffer{}, exited: make(chan struct{})}
	s.cmd.Env = env
	s.cmd.Stdout, s.cmd.Stderr = s.stdout, s.stderr
	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	s.stdin = stdin
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { s.err = s.cmd.Wait(); close(s.exited) }()
	t.Cleanup(func() {
		_ = s.cmd.Process.Kill()
		<-s.exited
	})
	return s
}

// send writes one JSON-RPC message.
func (s *rawServer) send(v any) {
	s.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		s.t.Fatalf("writing to the server: %v", err)
	}
}

// reply waits for the response to request id and returns its line.
func (s *rawServer) reply(id int, within time.Duration) string {
	s.t.Helper()
	timeout := time.After(within)
	for {
		select {
		case line := <-s.stdout.ch:
			var m struct {
				ID *int `json:"id"`
			}
			if json.Unmarshal([]byte(line), &m) == nil && m.ID != nil && *m.ID == id {
				return line
			}
		case <-s.exited:
			s.t.Fatalf("the server exited before it answered request %d; stderr: %q", id, s.stderr.String())
		case <-timeout:
			s.t.Fatalf("no answer to request %d within %s; stderr: %q", id, within, s.stderr.String())
		}
	}
}

// initialize runs the MCP handshake.
func (s *rawServer) initialize() {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "raw", "version": "1"}}})
	s.reply(1, 15*time.Second)
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

// callTool sends a tools/call request with the given id and no arguments, and does not wait.
func (s *rawServer) callTool(id int, name string) {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": map[string]any{}}})
}

// waitExit waits for the process to exit.
func (s *rawServer) waitExit(within time.Duration, what string) {
	s.t.Helper()
	select {
	case <-s.exited:
	case <-time.After(within):
		s.t.Fatalf("the server had not exited %s after %s; stderr: %q", within, what, s.stderr.String())
	}
}

// waitFor polls until cond holds, for at most within, and fails the test naming what.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// describe is a line shortened for a failure message.
func describe(line string) string {
	if len(line) > 120 {
		return fmt.Sprintf("%.120s... (%d bytes)", line, len(line))
	}
	return strings.TrimSpace(line)
}
