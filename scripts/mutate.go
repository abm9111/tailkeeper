//go:build ignore

// Command mutate checks that the tests of a package notice a change to its code. For each
// mutant listed in the package's mutants.txt it makes the change in a temporary copy of
// the repository, runs the tests the mutant is expected to fail, and reports whether one
// did. A mutant that no listed test fails is a missing test.
//
//	go run scripts/mutate.go [PACKAGE_DIR ...]
//
// With no argument it runs every directory under internal/ that has a mutants.txt. Run it
// from the repository root (make mutate does). It is not part of make verify: each mutant
// builds and tests a package.
//
// The copy holds only the files git lists for the repository: the tracked files, and the
// untracked ones that are not ignored. A file git ignores (tool state, local notes, build
// output, other worktrees) never reaches the temporary directory. The directory is removed
// on every way out of the program, including an interrupt.
//
// mutants.txt holds blocks separated by blank lines, with # comment lines:
//
//	mutant: a short name
//	file: parse.go                     the file, relative to the package directory
//	old: text to replace               must occur exactly once in the file
//	new: replacement                   \n, \t and \\ stand for a line feed, a tab and a backslash
//	kill: TestA|TestB                  the tests of which at least one must fail
//
// Before the mutants, the kill tests of the package run unchanged and must all pass (and
// must all exist: a name that matches no test would pass vacuously). A failing baseline
// would kill every mutant for the wrong reason, so it stops the run. A mutant is
//
//	KILLED    when one of its kill tests fails with the change
//	SURVIVED  when all of them pass with it: a test is missing
//	BROKEN    when the old text does not occur exactly once, the changed package does
//	          not build, or the run failed without any of the kill tests failing
//
// The last line of output for a package is
// "mutate: PACKAGE: N mutants, K killed, S survived, B broken", and the exit status is 0
// only when every mutant of every package was killed.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type mutant struct {
	name, file, old, new, kill string
	line                       int
}

func main() { os.Exit(run()) }

// run does the whole job and returns the exit status. The temporary copy is removed by the
// defer below whichever way run returns; main only exits after that.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root, err := os.Getwd()
	if err != nil {
		fmt.Println("mutate:", err)
		return 1
	}
	pkgs, err := packages(os.Args[1:])
	if err != nil {
		fmt.Println("mutate:", err)
		return 1
	}
	// Every mutants.txt is read and checked before anything is copied or written.
	lists := map[string][]mutant{}
	for _, pkg := range pkgs {
		list, err := parseMutants(filepath.Join(pkg, "mutants.txt"))
		if err != nil {
			fmt.Println("mutate:", err)
			return 1
		}
		lists[pkg] = list
	}
	work, err := os.MkdirTemp("", "mutate-")
	if err != nil {
		fmt.Println("mutate:", err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			fmt.Println("mutate: removing the copy:", err)
		}
	}()
	n, err := copyTree(ctx, root, work)
	if err != nil {
		fmt.Println("mutate: copying the repository:", err)
		return 1
	}
	fmt.Printf("mutate: copied %d files that git lists\n", n)
	status := 0
	for _, pkg := range pkgs {
		if ctx.Err() != nil {
			fmt.Println("mutate: interrupted")
			return 1
		}
		if !runPackage(ctx, work, pkg, lists[pkg]) {
			status = 1
		}
	}
	return status
}

// packages names the package directories to run: the arguments, cleaned, or every
// internal/*/mutants.txt when there are none.
func packages(args []string) ([]string, error) {
	if len(args) == 0 {
		found, err := filepath.Glob("internal/*/mutants.txt")
		if err != nil || len(found) == 0 {
			return nil, errors.New("no internal/*/mutants.txt found; run it from the repository root")
		}
		for _, f := range found {
			args = append(args, filepath.Dir(f))
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		p := path.Clean(filepath.ToSlash(a))
		if p == "." || path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") {
			return nil, fmt.Errorf("%q is not a package directory inside the repository", a)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// copyTree copies the files git lists for the repository in src into dst and returns how
// many. An allowlist: nothing git ignores is copied. A listed file that is gone from the
// working tree (deleted, not yet committed) is skipped, as is anything that is not a
// regular file.
func copyTree(ctx context.Context, src, dst string) (int, error) {
	cmd := exec.CommandContext(ctx, "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = src
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	list, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("git ls-files: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	copied := 0
	seen := map[string]bool{}
	for _, name := range strings.Split(string(list), "\x00") {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if !fs.ValidPath(name) {
			return copied, fmt.Errorf("git listed %q, which is not a path inside the repository", name)
		}
		from := filepath.Join(src, filepath.FromSlash(name))
		info, err := os.Lstat(from)
		if errors.Is(err, fs.ErrNotExist) || err == nil && !info.Mode().IsRegular() {
			continue
		}
		if err != nil {
			return copied, err
		}
		to := filepath.Join(dst, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			return copied, err
		}
		if err := copyFile(from, to, info.Mode().Perm()); err != nil {
			return copied, err
		}
		copied++
	}
	return copied, nil
}

func copyFile(from, to string, perm fs.FileMode) error {
	in, err := os.Open(from) //nolint:gosec // G304: from is a path git lists in this repository, checked by fs.ValidPath
	if err != nil {
		return err
	}
	// A failed close of a file opened for reading loses nothing.
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: to is inside the temporary copy, built from a path fs.ValidPath accepted
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close() // the copy error is the one returned
		return err
	}
	return out.Close()
}

var unescape = strings.NewReplacer(`\\`, "\x00", `\n`, "\n", `\t`, "\t")

func parseMutants(file string) ([]mutant, error) {
	data, err := os.ReadFile(file) //nolint:gosec // G304: file is the mutants.txt of a package directory named on the command line
	if err != nil {
		return nil, err
	}
	var out []mutant
	var cur mutant
	have := map[string]bool{}
	flush := func() error {
		if len(have) == 0 {
			return nil
		}
		if cur.name == "" || cur.file == "" || cur.old == "" || cur.kill == "" {
			return fmt.Errorf("%s:%d: a mutant needs mutant, file, old and kill", file, cur.line)
		}
		if !fs.ValidPath(cur.file) || cur.file == "." || strings.Contains(cur.file, `\`) {
			return fmt.Errorf("%s:%d: file %q is not a path inside the package directory", file, cur.line, cur.file)
		}
		out = append(out, cur)
		cur, have = mutant{}, map[string]bool{}
		return nil
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			key, value, ok = strings.Cut(line, ":")
			ok = ok && value == ""
		}
		if !ok {
			return nil, fmt.Errorf("%s:%d: not a \"key: value\" line", file, i+1)
		}
		if len(have) == 0 {
			cur.line = i + 1
		}
		if have[key] {
			return nil, fmt.Errorf("%s:%d: %q appears twice in one mutant", file, i+1, key)
		}
		have[key] = true
		value = strings.ReplaceAll(unescape.Replace(value), "\x00", `\`)
		switch key {
		case "mutant":
			cur.name = value
		case "file":
			cur.file = value
		case "old":
			cur.old = value
		case "new":
			cur.new = value
		case "kill":
			cur.kill = value
		default:
			return nil, fmt.Errorf("%s:%d: unknown key %q", file, i+1, key)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

var testName = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)

// goTest runs the named tests of a package in the copy and returns the output and whether
// go test exited 0.
func goTest(ctx context.Context, work, pkg string, names []string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-v", "-count=1", "-timeout", "600s", //nolint:gosec // G204: a developer tool that runs go test on the repository's own copy; names are checked against testName
		"-run", "^("+strings.Join(names, "|")+")$", "./"+pkg)
	cmd.Dir = work
	// go test starts the test binary, which exec.CommandContext cannot reach. Run the pair in
	// a process group of their own and, when the context ends, kill the group.
	if ownProcessGroup(cmd) {
		cmd.Cancel = func() error {
			if exec.Command("kill", "-KILL", "--", "-"+strconv.Itoa(cmd.Process.Pid)).Run() == nil { //nolint:gosec // G204: kills the process group of the go test it started; the argument is a pid
				return nil
			}
			return cmd.Process.Kill()
		}
	}
	cmd.WaitDelay = 10 * time.Second
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "TAILKEEPER_LIVE=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err == nil
}

// ownProcessGroup puts cmd in a new process group where the platform has them. This file is
// one source file (go run names it alone), so it cannot split by operating system: the
// Setpgid field is set by name through reflection, which builds everywhere and does nothing
// where syscall.SysProcAttr has no such field, and the group is killed with kill(1).
func ownProcessGroup(cmd *exec.Cmd) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	attr := &syscall.SysProcAttr{}
	f := reflect.ValueOf(attr).Elem().FieldByName("Setpgid")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return false
	}
	f.SetBool(true)
	cmd.SysProcAttr = attr
	return true
}

// result reports whether the output of a -v run holds a top-level result line for a test.
func result(out, verb, name string) bool {
	return regexp.MustCompile(`(?m)^--- ` + verb + `: ` + regexp.QuoteMeta(name) + ` \(`).MatchString(out)
}

func runPackage(ctx context.Context, work, pkg string, mutants []mutant) bool {
	if len(mutants) == 0 {
		fmt.Printf("mutate: %s: no mutants\n", pkg)
		return false
	}
	// The kill tests of all the mutants must exist and pass as the code stands.
	set := map[string]bool{}
	for _, m := range mutants {
		for _, n := range strings.Split(m.kill, "|") {
			if !testName.MatchString(n) {
				fmt.Printf("mutate: %s: %q is not a test name\n", m.name, n)
				return false
			}
			set[n] = true
		}
	}
	var all []string
	for n := range set {
		all = append(all, n)
	}
	sort.Strings(all)
	out, ok := goTest(ctx, work, pkg, all)
	if !ok {
		fmt.Printf("mutate: %s: the kill tests fail before any change, so they prove nothing:\n%s\n", pkg, tail(out))
		return false
	}
	for _, n := range all {
		if !result(out, "PASS", n) {
			fmt.Printf("mutate: %s: %s did not run and pass before any change (no such test, or it skipped)\n", pkg, n)
			return false
		}
	}
	killed, survived, broken := 0, 0, 0
	for _, m := range mutants {
		if ctx.Err() != nil {
			fmt.Println("mutate: interrupted")
			return false
		}
		file := filepath.Join(work, filepath.FromSlash(pkg), filepath.FromSlash(m.file))
		orig, err := os.ReadFile(file) //nolint:gosec // G304: file is in the temporary copy; parseMutants accepted m.file only as an fs.ValidPath
		if err != nil {
			fmt.Printf("BROKEN    %s: %v\n", m.name, err)
			broken++
			continue
		}
		if n := strings.Count(string(orig), m.old); n != 1 {
			fmt.Printf("BROKEN    %s: the old text occurs %d times in %s, not once\n", m.name, n, m.file)
			broken++
			continue
		}
		if m.old == m.new {
			fmt.Printf("BROKEN    %s: the new text is the old text\n", m.name)
			broken++
			continue
		}
		if err := os.WriteFile(file, []byte(strings.Replace(string(orig), m.old, m.new, 1)), 0o600); err != nil { //nolint:gosec // G703: file is in the temporary copy; parseMutants accepted m.file only as an fs.ValidPath
			fmt.Printf("BROKEN    %s: %v\n", m.name, err)
			broken++
			continue
		}
		names := strings.Split(m.kill, "|")
		out, passed := goTest(ctx, work, pkg, names)
		if err := os.WriteFile(file, orig, 0o600); err != nil { //nolint:gosec // G703: as above, the same path in the temporary copy
			fmt.Println("mutate: restoring", m.file, err)
			return false
		}
		switch {
		case ctx.Err() != nil:
			fmt.Println("mutate: interrupted")
			return false
		case strings.Contains(out, "[build failed]") || strings.Contains(out, "[setup failed]"):
			fmt.Printf("BROKEN    %s: the changed package does not build:\n%s\n", m.name, tail(out))
			broken++
		case anyResult(out, "FAIL", names):
			fmt.Printf("KILLED    %s (%s)\n", m.name, m.kill)
			killed++
		case passed && allResults(out, "PASS", names):
			fmt.Printf("SURVIVED  %s (%s passed with the change)\n", m.name, m.kill)
			survived++
		default:
			fmt.Printf("BROKEN    %s: the run failed or skipped, but no test of %s failed:\n%s\n", m.name, m.kill, tail(out))
			broken++
		}
	}
	fmt.Printf("mutate: %s: %d mutants, %d killed, %d survived, %d broken\n", pkg, len(mutants), killed, survived, broken)
	return survived == 0 && broken == 0
}

func anyResult(out, verb string, names []string) bool {
	for _, n := range names {
		if result(out, verb, n) {
			return true
		}
	}
	return false
}

func allResults(out, verb string, names []string) bool {
	for _, n := range names {
		if !result(out, verb, n) {
			return false
		}
	}
	return true
}

func tail(s string) string {
	if len(s) > 1500 {
		return "..." + s[len(s)-1500:]
	}
	return s
}
