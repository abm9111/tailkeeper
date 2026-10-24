package probe

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

func TestParseArgs(t *testing.T) {
	a, err := parseArgs([]string{"--out", "dir", "--only=A-1,H-1", "--gap", "0s"})
	if err != nil || a.out != "dir" || len(a.only) != 2 || a.only[1] != "H-1" || a.gap != 0 {
		t.Errorf("parseArgs = %+v, %v", a, err)
	}
	if a, err = parseArgs(nil); err != nil || a.gap != DefaultGap || a.out != "" || a.only != nil {
		t.Errorf("defaults = %+v, %v", a, err)
	}
	for _, bad := range [][]string{{"--out"}, {"--only"}, {"--only", "A-99"}, {"--only=A-1,"}, {"--gap", "soon"}, {"--gap", "-1s"}, {"--gap", "2h"}, {"--gap"}, {"--live"}, {"extra"}} {
		if _, err := parseArgs(bad); err == nil {
			t.Errorf("parseArgs(%q) was accepted", bad)
		}
	}
}

// The command prints the banner, the report and the summary, writes the files, and exits
// 0 when every probe ran, whatever its checks found.
func TestCommandRunsWritesAndReports(t *testing.T) {
	w := newWorld(t)
	w.auditLogs = []map[string]any{{"old": liveText, "new": liveText}}
	var out, errb bytes.Buffer
	dir := filepath.Join(t.TempDir(), "observed")
	code := command(context.Background(), w.f.Client(t), []string{"--out", dir, "--gap", "0s"}, &out, &errb, func() time.Time { return time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC) })
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	var starts []string
	for _, p := range All() {
		starts = append(starts, "tailkeeper: probe-acl: "+p.ID)
	}
	if errb.String() != strings.Join(starts, "\n")+"\n" {
		t.Errorf("stderr is %q, want one line per probe and nothing else", errb.String())
	}
	for _, want := range []string{"probe-acl: 15 probes, read-only", "nothing from the tailnet is printed", "\nA-1  ", "\nH-1  ", "  sends:    ", "  expected: ", "MATCH   the control fails",
		"checks match, 0 differ, 0 probes stopped by an error, 0 not run", "wrote 15 skeleton files to " + dir} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q:\n%s", want, out.String())
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "A-9.json"))
	if err != nil || !strings.Contains(string(b), `"observedOn": "2026-10-20"`) {
		t.Errorf("A-9.json: %v %s", err, b)
	}
}

// A credential that is revoked, or lacks a scope, gets a 403 for every request. The run
// still ends, but it exits 1, says why each probe has no file, and leaves the capture alone.
func TestCommandRefusedProbesKeepTheirCaptureAndExitOne(t *testing.T) {
	f := apitest.New(t)
	f.PermitProbeRequests()
	f.Fallback(func(w http.ResponseWriter, _ *http.Request) { apitest.Forbidden403().Write(w) })
	dir := t.TempDir()
	old := []byte("the capture of an earlier run\n")
	if err := os.WriteFile(filepath.Join(dir, "A-1.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := command(context.Background(), f.Client(t), []string{"--out", dir, "--gap", "0s"}, &out, &errb, time.Now)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	for _, p := range All() {
		want := "tailkeeper: probe-acl: no file for " + p.ID + ": every request was refused (401 or 403); check the credential and its scopes\n"
		if p.ID == "A-7" || p.ID == "A-12" {
			// These two end in an error; the error is the one reason given (A-12 has no observation to refuse).
			want = "tailkeeper: probe-acl: no file for " + p.ID + ": api_error\n"
		}
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb.String())
		}
		if n := strings.Count(errb.String(), "no file for "+p.ID+":"); n != 1 {
			t.Errorf("%s has %d no-file lines, want 1:\n%s", p.ID, n, errb.String())
		}
	}
	if !strings.Contains(out.String(), "wrote 0 skeleton files to "+dir) {
		t.Errorf("stdout lacks the count of zero files:\n%s", out.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "A-1.json" {
		t.Errorf("the capture directory holds %v, %v", entries, err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "A-1.json")); err != nil || !bytes.Equal(got, old) {
		t.Errorf("A-1.json after a refused run: %q, %v", got, err)
	}
}

// A run of one probe that is refused and nothing else ends in exit 1 on that alone.
func TestCommandExitsOneWhenOnlyARefusedProbeRan(t *testing.T) {
	f := apitest.New(t)
	f.PermitProbeRequests()
	f.Fallback(func(w http.ResponseWriter, _ *http.Request) { apitest.Forbidden403().Write(w) })
	dir := t.TempDir()
	old := []byte("the capture of an earlier run\n")
	if err := os.WriteFile(filepath.Join(dir, "A-1.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := command(context.Background(), f.Client(t), []string{"--only", "A-1", "--out", dir, "--gap", "0s"}, &out, &errb, time.Now)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "0 probes stopped by an error, 0 not run") {
		t.Errorf("the run was not refused alone:\n%s", out.String())
	}
	if want := "tailkeeper: probe-acl: no file for A-1: every request was refused (401 or 403); check the credential and its scopes\n"; !strings.Contains(errb.String(), want) {
		t.Errorf("stderr lacks %q:\n%s", want, errb.String())
	}
	if got, err := os.ReadFile(filepath.Join(dir, "A-1.json")); err != nil || !bytes.Equal(got, old) {
		t.Errorf("A-1.json after a refused run: %q, %v", got, err)
	}
}

// A run that ends in an error, or cannot write its files, or is told something it does not
// understand, does not exit 0.
func TestCommandExitCodes(t *testing.T) {
	now := time.Now
	w := newWorld(t)
	var out, errb bytes.Buffer
	if code := command(context.Background(), w.f.Client(t), []string{"--only", "A-5", "--gap", "0s", "--out", filepath.Join(t.TempDir(), "o")}, &out, &errb, now); code != 0 {
		t.Errorf("one probe: exit %d (%s)", code, errb.String())
	}
	if strings.Contains(out.String(), "\nA-1  ") || !strings.Contains(out.String(), "wrote 1 skeleton file to ") || !strings.Contains(out.String(), "probe-acl: 1 probe, read-only") {
		t.Errorf("--only did not narrow the run:\n%s", out.String())
	}
	w.f.Server.Close()
	out.Reset()
	if code := command(context.Background(), w.f.Client(t), []string{"--only", "A-5", "--gap", "0s"}, &out, &errb, now); code != 1 || !strings.Contains(out.String(), "1 probe stopped by an error") {
		t.Errorf("a dead connection: exit %d\n%s", code, out.String())
	}
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w2 := newWorld(t)
	errb.Reset()
	if code := command(context.Background(), w2.f.Client(t), []string{"--only", "A-5", "--gap", "0s", "--out", file}, &out, &errb, now); code != 1 || !strings.Contains(errb.String(), "cannot write the skeletons") {
		t.Errorf("an unwritable directory: exit %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := command(context.Background(), w2.f.Client(t), []string{"--only", "A-99\x1b[2J"}, &out, &errb, now); code != 2 || strings.Contains(errb.String(), "\x1b") || !strings.Contains(errb.String(), "usage: probe-acl") {
		t.Errorf("a usage error: exit %d, stderr %q", code, errb.String())
	}
}

// captureOptions runs the command with runProbes replaced and returns the options it passed.
func captureOptions(t *testing.T, args []string) Options {
	t.Helper()
	var got Options
	prev := runProbes
	runProbes = func(ctx context.Context, a API, probes []Probe, o Options) []Result {
		got = o
		return nil
	}
	t.Cleanup(func() { runProbes = prev })
	var out, errb bytes.Buffer
	if code := command(context.Background(), newWorld(t).f.Client(t), args, &out, &errb, time.Now); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	return got
}

// Run's Gap defaults to 0, so the command has to pass DefaultGap itself.
func TestCommandPassesTheGapAndTheSelection(t *testing.T) {
	if o := captureOptions(t, nil); o.Gap != DefaultGap || DefaultGap != 2*time.Second || len(o.Only) != 0 {
		t.Errorf("default options = %+v", o)
	}
	if o := captureOptions(t, []string{"--gap", "0s", "--only", "A-3,H-1"}); o.Gap != 0 || len(o.Only) != 2 || o.Only[0] != "A-3" || o.Only[1] != "H-1" {
		t.Errorf("options with flags = %+v", o)
	}
}

// While the probes run the owner sees one line per probe on stderr, as it starts: the ID
// and nothing else, so about two minutes of pacing are not silence.
func TestCommandPrintsEachProbeIDAsItStarts(t *testing.T) {
	w := newWorld(t)
	var out, errb bytes.Buffer
	code := command(context.Background(), w.f.Client(t), []string{"--only", "A-5,A-6", "--gap", "0s"}, &out, &errb, time.Now)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if want := "tailkeeper: probe-acl: A-5\ntailkeeper: probe-acl: A-6\n"; errb.String() != want {
		t.Errorf("stderr = %q, want %q", errb.String(), want)
	}
}

// An ID that is not a probe is a usage error that names it, and nothing is sent.
func TestCommandRefusesAnUnknownProbe(t *testing.T) {
	w := newWorld(t)
	var out, errb bytes.Buffer
	code := command(context.Background(), w.f.Client(t), []string{"--only", "A-1,A-99", "--gap", "0s"}, &out, &errb, time.Now)
	if code != 2 || !strings.Contains(errb.String(), `"A-99"`) || !strings.Contains(errb.String(), "usage: probe-acl") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("a refused command printed a report:\n%s", out.String())
	}
	if n := len(w.f.Requests()); n != 0 {
		t.Errorf("a refused command sent %d requests", n)
	}
}

// WriteFiles writes nothing for a probe that stopped on an error or did not run, so the
// command says which, and why, without quoting anything from the tailnet.
func TestCommandSaysWhichProbesHaveNoFile(t *testing.T) {
	prev := runProbes
	runProbes = func(ctx context.Context, a API, probes []Probe, o Options) []Result {
		return []Result{
			{ID: "A-1", Title: "ok"},
			{ID: "A-2", Title: "stopped", Error: "rate_limited"},
			{ID: "A-3", Title: "later", NotRun: true},
		}
	}
	t.Cleanup(func() { runProbes = prev })
	dir := filepath.Join(t.TempDir(), "o")
	var out, errb bytes.Buffer
	code := command(context.Background(), newWorld(t).f.Client(t), []string{"--out", dir}, &out, &errb, time.Now)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	for _, want := range []string{"no file for A-2: rate_limited", "no file for A-3: not run"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb.String())
		}
	}
	if strings.Contains(errb.String(), "A-1") || !strings.Contains(out.String(), "wrote 1 skeleton file to "+dir) {
		t.Errorf("stderr %q, stdout %q", errb.String(), out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "A-1.json")); err != nil {
		t.Error(err)
	}
	for _, id := range []string{"A-2", "A-3"} {
		if _, err := os.Stat(filepath.Join(dir, id+".json")); err == nil {
			t.Errorf("%s.json was written", id)
		}
	}
}

// The exported Command keeps the 2 s pacing: no gap below DefaultGap reaches the API.
func TestCommandRefusesAGapBelowTheFloor(t *testing.T) {
	t.Setenv("TAILKEEPER_LIVE", "1")
	w := newWorld(t)
	var out, errb bytes.Buffer
	for _, gap := range []string{"1s", "0s", "1999ms"} {
		out.Reset()
		errb.Reset()
		if code := Command(context.Background(), w.f.Client(t), []string{"--gap", gap}, &out, &errb); code != 2 || out.Len() != 0 ||
			!strings.Contains(errb.String(), "--gap below 2s") || !strings.Contains(errb.String(), "usage: probe-acl") {
			t.Errorf("--gap %s: exit %d, stdout %q, stderr %q", gap, code, out.String(), errb.String())
		}
	}
	if n := len(w.f.Requests()); n != 0 {
		t.Errorf("a refused gap sent %d requests", n)
	}
	var got Options
	prev := runProbes
	runProbes = func(ctx context.Context, a API, probes []Probe, o Options) []Result {
		got = o
		return nil
	}
	t.Cleanup(func() { runProbes = prev })
	if code := Command(context.Background(), w.f.Client(t), []string{"--gap", "3s"}, &out, &errb); code != 0 || got.Gap != 3*time.Second {
		t.Errorf("--gap 3s: exit %d, gap %v", code, got.Gap)
	}
	got = Options{}
	if code := Command(context.Background(), w.f.Client(t), nil, &out, &errb); code != 0 || got.Gap != DefaultGap {
		t.Errorf("no --gap: exit %d, gap %v", code, got.Gap)
	}
}

// A run that was stopped before it began has no errored probe, only probes that did not
// run, and that is not a success.
func TestCommandExitsOneWhenProbesDidNotRun(t *testing.T) {
	w := newWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := command(ctx, w.f.Client(t), []string{"--gap", "0s"}, &out, &errb, time.Now)
	if code != 1 || !strings.Contains(out.String(), "0 probes stopped by an error, 15 not run") {
		t.Errorf("exit %d\n%s", code, out.String())
	}
	if n := len(w.f.Requests()); n != 0 {
		t.Errorf("a cancelled run sent %d requests", n)
	}
}

func TestCommandRefusesAnEmptyOut(t *testing.T) {
	for _, args := range [][]string{{"--out", ""}, {"--out="}} {
		w := newWorld(t)
		var out, errb bytes.Buffer
		if code := command(context.Background(), w.f.Client(t), args, &out, &errb, time.Now); code != 2 || !strings.Contains(errb.String(), "--out needs a directory") || out.Len() != 0 || len(w.f.Requests()) != 0 {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
	}
}

// When a file cannot be written, the command says how many it did write, and which, and
// leaves the per-probe "no file" lines out.
func TestCommandReportsFilesWrittenBeforeAFailure(t *testing.T) {
	prev := runProbes
	runProbes = func(ctx context.Context, a API, probes []Probe, o Options) []Result {
		return []Result{{ID: "A-1", Title: "ok"}, {ID: "A-2", Title: "ok"}, {ID: "A-3", Title: "stopped", Error: "rate_limited"}}
	}
	t.Cleanup(func() { runProbes = prev })
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "A-2.json"), 0o750); err != nil { // a directory where the file belongs
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := command(context.Background(), newWorld(t).f.Client(t), []string{"--out", dir}, &out, &errb, time.Now)
	if code != 1 || !strings.Contains(errb.String(), "cannot write the skeletons") ||
		!strings.Contains(errb.String(), "1 skeleton file written before the failure") || !strings.Contains(errb.String(), filepath.Join(dir, "A-1.json")) {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	if strings.Contains(errb.String(), "no file for") || strings.Contains(out.String(), "wrote ") {
		t.Errorf("stdout %q, stderr %q", out.String(), errb.String())
	}
}

// After a full run through the command, neither stream holds a name from the live policy.
func TestCommandPrintsNoLiveValue(t *testing.T) {
	w := newWorld(t)
	w.auditLogs = []map[string]any{{"eventTime": "2026-10-01T00:00:00Z", "old": liveText, "new": liveText}}
	dir := filepath.Join(t.TempDir(), "observed")
	var out, errb bytes.Buffer
	if code := command(context.Background(), w.f.Client(t), []string{"--out", dir, "--gap", "0s"}, &out, &errb, time.Now); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	// the directory is the caller's own argument, so it is not a value from the tailnet
	all := strings.ReplaceAll(out.String()+"\n"+errb.String(), dir, "<dir>")
	for _, tok := range liveTokens {
		if strings.Contains(all, tok) {
			t.Errorf("the command's output holds %q, a name from the live policy", tok)
		}
	}
	if !strings.Contains(all, "15 probes") {
		t.Errorf("the run did not happen:\n%s", all)
	}
}
