package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// probeBinary builds the binary with -tags probe, once, next to the one TestMain built.
// It is the binary `make probe-acl` builds; the release is built without the tag.
var (
	probeOnce sync.Once
	probePath string
	probeErr  string
)

func probeBinary(t *testing.T) string {
	t.Helper()
	probeOnce.Do(func() {
		probePath = filepath.Join(filepath.Dir(bin), "tailkeeper-probe")
		if runtime.GOOS == "windows" {
			probePath += ".exe"
		}
		if out, err := exec.Command("go", "build", "-tags", "probe", "-o", probePath, ".").CombinedOutput(); err != nil {
			probeErr = err.Error() + "\n" + string(out)
		}
	})
	if probeErr != "" {
		t.Fatal("go build -tags probe: " + probeErr)
	}
	return probePath
}

// runWith runs binary in the isolated environment plus extra variables.
func runWith(t *testing.T, binary string, extra []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(isolated(t), extra...)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return so.String(), se.String(), code
}

// A build without the tag, which is the release, has no probe-acl: not even with the switch set.
func TestProbeACLIsNotInTheDefaultBuild(t *testing.T) {
	_, stderr, code := runWith(t, bin, []string{"TAILKEEPER_LIVE=1"}, "probe-acl")
	if code != 2 || !strings.Contains(stderr, `unknown area "probe-acl"`) {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if out, _, _ := runWith(t, bin, nil, "help"); strings.Contains(out, "probe-acl") {
		t.Errorf("the help lists probe-acl:\n%s", out)
	}
}

// A build with the tag still refuses without TAILKEEPER_LIVE=1, and the help does not list it.
func TestProbeACLBuildRefusesWithoutTheSwitch(t *testing.T) {
	probe := probeBinary(t)
	_, stderr, code := runWith(t, probe, nil, "probe-acl")
	if code != 2 || !strings.Contains(stderr, "make probe-acl") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if out, _, _ := runWith(t, probe, nil, "help"); strings.Contains(out, "probe-acl") {
		t.Errorf("the help lists probe-acl:\n%s", out)
	}
}

// With the switch and no configuration, the tagged build stops at the configuration: it has
// no tailnet to read, and nothing is sent anywhere.
func TestProbeACLBuildNeedsAConfiguration(t *testing.T) {
	_, stderr, code := runWith(t, probeBinary(t), []string{"TAILKEEPER_LIVE=1"}, "probe-acl")
	if code != 6 || !strings.Contains(stderr, "config_missing") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}
