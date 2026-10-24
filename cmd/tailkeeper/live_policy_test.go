package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/probe"
)

// selfCheckTimeout bounds the self-check: about thirty requests, two seconds apart, and
// the policy reads, well inside the go test timeout.
const selfCheckTimeout = 10 * time.Minute

// probeStarted begins the line the probe command writes to stderr as each probe starts.
const probeStarted = "tailkeeper: probe-acl: "

// judgeSelfCheck reads the output of `probe-acl --self-check` and the exit status of the
// process. It returns the lines that are fit to log, every one of them, and the problems:
// a status other than 0, a line that is not of the forms the self-check prints (it is not
// logged: it could be a value), a closing count that is not the number of checks the run
// must make (want), a count that is not the number of check lines, and checks that did not
// hold.
func judgeSelfCheck(out []byte, code, want int) (lines, problems []string) {
	if code != 0 {
		problems = append(problems, fmt.Sprintf("self-check exit %d", code))
	}
	checkLines, closing := 0, -1
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, probeStarted) {
			continue
		}
		kind, n, notHeld := probe.ClassifyLine(line)
		switch kind {
		case probe.LineCheck:
			checkLines++
		case probe.LineClosing:
			closing = n
			if notHeld > 0 {
				problems = append(problems, fmt.Sprintf("%d checks did not hold", notHeld))
			}
		default:
			problems = append(problems, "a self-check line is not a count, a boolean or a probe name")
			continue
		}
		lines = append(lines, line)
	}
	switch {
	case closing < 0:
		problems = append(problems, "the self-check printed no closing count")
	case closing != want:
		problems = append(problems, fmt.Sprintf("the self-check made %d checks, and the run must make %d", closing, want))
	case checkLines != closing:
		problems = append(problems, fmt.Sprintf("the closing count is %d, and %d checks were printed", closing, checkLines))
	}
	return lines, problems
}

// reporter is the part of *testing.T the self-check's judgement writes to, so that a test can
// read what the live run would have logged and failed on.
type reporter interface {
	Helper()
	Log(args ...any)
	Error(args ...any)
	Fatal(args ...any)
}

// checkLivePolicy runs `probe-acl --self-check` of the tagged binary bin against the captures
// in against, in env, and reports it: every line fit to log is logged first, then each
// problem fails the run, so a failure names the check. The run must make as many checks as
// the probe says a full self-check makes.
func checkLivePolicy(r reporter, bin string, env []string, against string, timeout time.Duration) {
	r.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "probe-acl", "--self-check", "--against", against)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		r.Fatal(err)
		return
	}
	lines, problems := judgeSelfCheck(out, code, probe.SelfCheckCount())
	for _, line := range lines {
		r.Log(line)
	}
	if ctx.Err() != nil {
		problems = append(problems, "the self-check did not finish in time")
	}
	for _, p := range problems {
		r.Error(p)
	}
}

// capturesDir is the directory of the committed captures the shapes are compared with.
func capturesDir() (string, error) {
	return filepath.Abs(filepath.Join("..", "..", "internal", "api", "apitest", "testdata", "observed"))
}

func TestLivePolicy(t *testing.T) {
	liveOnly(t)
	if probeBin == "" {
		t.Fatal("the tagged binary was not built")
	}
	against, err := capturesDir()
	if err != nil {
		t.Fatal(err)
	}
	checkLivePolicy(t, probeBin, liveEnv(), against, selfCheckTimeout)
}

// TestTheTaggedBinaryIsBuiltOnlyForALiveRun: the second build is inside the live switch, and
// this process was not started with it, so the path is empty. `make verify` therefore does
// not build the tagged binary.
func TestTheTaggedBinaryIsBuiltOnlyForALiveRun(t *testing.T) {
	if os.Getenv("TAILKEEPER_LIVE") != "1" && probeBin != "" {
		t.Fatal("the tagged binary was built without the live switch")
	}
}
