package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

const (
	hostileVSO = "##vso[task.setvariable variable=x]y"
	hostileTC  = "##teamcity[buildProblem description='x']"
	// jsonHashEscape is the JSON escape for the character #, spelled without writing
	// the escape itself in this file.
	jsonHashEscape = "\x5cu0023"
)

// noCILogCommand reports the first line of s that a CI log parser would act on:
// one that starts with "::" or "##[" after colour codes and white space, or that
// holds "##vso[" or "##teamcity[" anywhere.
func noCILogCommand(s string) (string, bool) {
	for _, line := range strings.Split(s, "\n") {
		rest := line
		for _, code := range []string{ansiRed, ansiGreen, ansiYellow} {
			rest = strings.TrimPrefix(rest, code)
		}
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		if strings.HasPrefix(rest, "::") || strings.HasPrefix(rest, "##[") ||
			strings.Contains(line, "##vso[") || strings.Contains(line, "##teamcity[") {
			return line, false
		}
	}
	return "", true
}

// The JSON the command line prints holds no CI log command in any string, and
// decodes to the strings it was given: the first # of each marker is written as
// the JSON escape for #, which a decoder reads back as #.
func TestJSONOutputKeepsCILogCommandsOutOfStrings(t *testing.T) {
	type payload struct {
		Name  string            `json:"name"`
		Notes []string          `json:"notes"`
		ByKey map[string]string `json:"byKey"`
	}
	in := payload{
		Name:  "x " + hostileVSO,
		Notes: []string{hostileTC, "###vso[a] ##vso[##vso[b]", `back\slash ` + hostileVSO, "plain"},
		ByKey: map[string]string{"k " + hostileVSO: "v " + hostileTC},
	}
	for name, write := range map[string]func(*bytes.Buffer) error{
		"indented":  func(b *bytes.Buffer) error { return writeJSON(b, in) },
		"one line":  func(b *bytes.Buffer) error { return writeJSONLine(b, in) },
		"an object": func(b *bytes.Buffer) error { return writeJSON(b, map[string]any{"error": in}) },
	} {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if line, ok := noCILogCommand(b.String()); !ok {
			t.Errorf("%s: the JSON holds a CI log command: %q", name, line)
		}
		if !strings.Contains(b.String(), jsonHashEscape+"#vso[task.setvariable") {
			t.Errorf("%s: the marker was not written with the JSON escape: %q", name, b.String())
		}
		var out payload
		if name == "an object" {
			var wrap struct{ Error payload }
			if err := json.Unmarshal(b.Bytes(), &wrap); err != nil {
				t.Fatalf("%s: the output is not JSON: %v\n%s", name, err, &b)
			}
			out = wrap.Error
		} else if err := json.Unmarshal(b.Bytes(), &out); err != nil {
			t.Fatalf("%s: the output is not JSON: %v\n%s", name, err, &b)
		}
		if out.Name != in.Name || strings.Join(out.Notes, "|") != strings.Join(in.Notes, "|") || out.ByKey["k "+hostileVSO] != "v "+hostileTC {
			t.Errorf("%s: the JSON decodes to %+v, want %+v", name, out, in)
		}
	}
}

// A result value and an error message that hold a CI log command print without it
// and decode to what the tool returned.
func TestJSONResultAndJSONErrorKeepCILogCommandsOut(t *testing.T) {
	h := newHarness(t, nil)
	reg := registry.New()
	reg.MustAdd(defineSurface("plain", plainOut{Name: "n " + hostileVSO}))
	h.r.Registry = func() *registry.Registry { return reg }
	if code := h.run("--json", "plain", "check"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.err)
	}
	if line, ok := noCILogCommand(h.out.String()); !ok {
		t.Errorf("the JSON result holds a CI log command: %q", line)
	}
	var res plainOut
	if err := json.Unmarshal(h.out.Bytes(), &res); err != nil || res.Name != "n "+hostileVSO {
		t.Errorf("the result decodes to %+v (%v), want the tool's string", res, err)
	}

	h = newHarness(t, nil)
	msg := "no such thing " + hostileVSO + " and " + hostileTC
	if code := h.r.fail(tkerr.New(tkerr.NotFound, msg, "hint "+hostileTC), true); code == 0 {
		t.Fatal("fail returned 0")
	}
	if line, ok := noCILogCommand(h.out.String()); !ok {
		t.Errorf("the JSON error holds a CI log command: %q", line)
	}
	var e struct {
		Error struct{ Message, Hint string }
	}
	if err := json.Unmarshal(h.out.Bytes(), &e); err != nil || e.Error.Message != msg || e.Error.Hint != "hint "+hostileTC {
		t.Errorf("the error decodes to %+v (%v)", e, err)
	}
}

// The reproduced case: an argument the user typed comes back in a JSON error.
func TestJSONErrorEchoingATypedArgumentHoldsNoCILogCommand(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("--json", "docs", "--check", "##vso[x]"); code == 0 {
		t.Fatal("docs --check of a missing file passed")
	}
	if line, ok := noCILogCommand(h.out.String()); !ok {
		t.Fatalf("the JSON error holds a CI log command: %q", line)
	}
	var e struct{ Error struct{ Message string } }
	if err := json.Unmarshal(h.out.Bytes(), &e); err != nil || !strings.Contains(e.Error.Message, "cannot check ##vso[x]: ") {
		t.Errorf("the message decodes to %q (%v), want the typed path back", e.Error.Message, err)
	}
}

// The usage text of a command echoes what the user typed as a default.
func TestUsageTextHoldsNoCILogCommand(t *testing.T) {
	for _, args := range [][]string{
		{"--context", "##vso[x]", "devices", "list", "-h"},
		{"--context", "::error::x", "devices", "list", "-h"},
		{"--context", "##teamcity[x]", "dns", "get", "--help"},
		{"--context", "##vso[x]", "doctor", "-h"},
	} {
		h := newHarness(t, nil)
		if code := h.run(args...); code != 0 {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.err)
		}
		if line, ok := noCILogCommand(h.err.String()); !ok {
			t.Errorf("%v: the usage holds a CI log command: %q", args, line)
		}
		if !strings.Contains(h.err.String(), "(default ") {
			t.Errorf("%v: the usage lost the default:\n%s", args, h.err)
		}
	}
}

// A hint a check carries into the doctor's fix line.
func TestDoctorFixLineHoldsNoCILogCommand(t *testing.T) {
	h := newHarness(t, nil)
	h.r.Build = func(context.Context, string) (*app.App, error) {
		return nil, tkerr.New(tkerr.ConfigUnsafe, "config is writable "+hostileVSO, "chmod 600 "+hostileVSO+" "+hostileTC)
	}
	if code := h.run("doctor"); code != 8 {
		t.Errorf("exit %d, want 8", code)
	}
	if line, ok := noCILogCommand(h.out.String()); !ok {
		t.Errorf("doctor holds a CI log command: %q\n%s", line, h.out)
	}
	if !strings.Contains(h.out.String(), "fix configuration: chmod 600 ") {
		t.Errorf("the fix line is gone:\n%s", h.out)
	}
}

// The audit path comes from HOME or the state directory, so it can start a line:
// audit verify and audit rotate print it first.
func TestAuditLinesStartingWithThePathHoldNoCILogCommand(t *testing.T) {
	if !audit.RotateSupported() {
		t.Skip("audit rotate needs the file lock, which this platform does not have yet")
	}
	t.Chdir(t.TempDir())
	h := newDNSHarness(t)
	hostile := "::error::" + hostileVSO + ".jsonl"
	log, err := audit.Open(hostile, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	h.app.Audit, h.app.AuditPath = log, hostile
	if code := h.run("dns", "get"); code != 0 {
		t.Fatalf("dns get: exit %d, stderr %q", code, h.err)
	}
	for _, verb := range []string{"verify", "rotate", "verify"} {
		h.out.Reset()
		if code := h.run("audit", verb); code != 0 {
			t.Fatalf("audit %s: exit %d, stderr %q", verb, code, h.err)
		}
		if line, ok := noCILogCommand(h.out.String()); !ok {
			t.Errorf("audit %s holds a CI log command: %q", verb, line)
		}
		if !strings.Contains(h.out.String(), "error::") {
			t.Errorf("audit %s lost the path:\n%s", verb, h.out)
		}
	}
}

// The warning that a read was not audited quotes the audit failure.
func TestWarningLinesHoldNoCILogCommand(t *testing.T) {
	h := newDNSHarness(t)
	h.app.Audit, h.app.AuditErr = nil, tkerr.New(tkerr.AuditUnavailable, "cannot open "+hostileVSO, "")
	if code := h.run("dns", "get"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.err)
	}
	if !strings.Contains(h.err.String(), "warning: this read was not audited: cannot open ") {
		t.Fatalf("no warning was printed: %q", h.err)
	}
	if line, ok := noCILogCommand(h.err.String()); !ok {
		t.Errorf("the warning holds a CI log command: %q", line)
	}
}

// Text on standard output and standard error from every command that prints text,
// asked with hostile arguments, holds nothing a CI log parser acts on, and the JSON
// form does not either.
func TestNoCommandWritesACILogCommand(t *testing.T) {
	hostileArgs := []string{hostileVSO, hostileTC, "::error::x", "##[group]x", "  ::warning::x"}
	var runs [][]string
	for _, h := range hostileArgs {
		for _, json := range []string{"", "--json"} {
			with := func(args ...string) []string {
				if json != "" {
					args = append([]string{json}, args...)
				}
				return args
			}
			runs = append(runs,
				with("--context", h, "devices", "list", "-h"),
				with("--context", h, "dns", "get"),
				with("--context", h, "doctor"),
				with("--context", h, "scopes"),
				with("--context", h, "version"),
				with("--context", h, "audit", "verify"),
				with("--context", h, "audit", "tail"),
				with("docs", "--check", h),
				with("docs", h),
				with("scopes", h),
				with("doctor", h),
				with("audit", "verify", h),
				with("devices", "list", "--"+h),
				with("devices", "list", "--os", h, h),
				with("devices", "get", h),
				with(h),
				with(h, "list"),
				with("devices", h),
				with("devices"),
				with("--"+h),
				with("--format", h, "acl", "get"),
				with("help"),
				with("-h"),
				nil,
			)
		}
	}
	for _, args := range runs {
		h := newDNSHarness(t)
		if slices.Contains(args, "doctor") {
			// doctor reads a missing credential as a finding; a harness with a working
			// one has no configuration for it to describe.
			h = newHarness(t, nil)
		}
		h.run(args...)
		for _, out := range []struct{ name, s string }{{"stdout", h.out.String()}, {"stderr", h.err.String()}} {
			if line, ok := noCILogCommand(out.s); !ok {
				t.Errorf("%q: %s holds a CI log command: %q", args, out.name, line)
			}
		}
	}
}

// A write that fails is still exit 1 when the output ends in a line without its
// newline, which the guard holds back until the command is over.
func TestAnUnfinishedLastLineStillReachesTheWriterAndItsFailureStillCounts(t *testing.T) {
	var b bytes.Buffer
	g := &lineGuard{w: &b}
	if _, err := g.Write([]byte("a\n::b")); err != nil {
		t.Fatal(err)
	}
	if b.String() != "a\n" {
		t.Errorf("before the flush: %q", b.String())
	}
	if err := g.Flush(); err != nil || b.String() != "a\n"+`\u{003A}`+":b" {
		t.Errorf("after the flush: %q (%v)", b.String(), err)
	}
	bad := &lineGuard{w: &writeCounter{}}
	if _, err := bad.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := bad.Flush(); err == nil || err.Error() != "broken pipe" {
		t.Errorf("Flush of an unfinished line on a dead writer = %v, want its error", err)
	}
}
