package workflows

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// goreleaserLog shapes the part of GoReleaser's --verbose output around its changelog
// stage, as v2.18.2 prints it for a run with --release-notes: the stage's step line, then
// its two debug lines, then the next stage. The padding between "bytes" and "file=" is
// GoReleaser's column alignment; the script does not depend on it.
func goreleaserLog(stage string, lines ...string) string {
	return gitTagOutput + "  • skipped sign & notarize macOS binaries\n" + stage + strings.Join(lines, "") + "  • archives\n"
}

// gitTagOutput is what a verbose run prints early on for an annotated tag: the output of
// `git tag -l --format=...%00...`, which holds NUL bytes. grep treats a file with a NUL
// as binary and prints "Binary file matches" in place of a line, so every canned log
// carries one, as the real ones do.
const gitTagOutput = "    • git command result                             args=[tag -l --format=%(contents:subject)%00%(contents)]\n" +
	"      stdout=\n      │ tailkeeper 0.5.0\x00│ tailkeeper 0.5.0\n      stderr=\n"

func readLines(size int, path string) []string {
	return []string{
		fmt.Sprintf("    • loading file %q\n", path),
		fmt.Sprintf("    • read %d bytes%sfile=%s\n", size, strings.Repeat(" ", 34), path),
	}
}

// release-notes-check.sh is the check `make release-notes-check` and the snapshot job of
// release.yml make of a GoReleaser run, so it must pass the log of a run in which the
// changelog stage read the fixture and fail on every log in which it did not. The logs
// are canned in the shape of the real ones: the disabled stage is the line GoReleaser
// printed for the configuration of 0.5.0.
func TestReleaseNotesCheckJudgesALog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check it runs is a POSIX shell script")
	}
	script, err := filepath.Abs("../../scripts/release-notes-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const notes = "A notes file.\n"
	fixture := write("notes.md", notes)
	size := len(notes)
	run := func(fixture, log string) (int, string) {
		out, err := exec.Command("sh", script, fixture, log).CombinedOutput()
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			return ee.ExitCode(), string(out)
		case err != nil:
			t.Fatal(err)
		}
		return 0, string(out)
	}

	const stage = "  • generating changelog\n"
	for _, c := range []struct {
		name    string
		fixture string
		log     string
		exit    int
		out     string
	}{
		{"the stage read the fixture", fixture, write("good.log", goreleaserLog(stage, readLines(size, fixture)...)), 0, fmt.Sprintf("read the %d bytes of %s", size, fixture)},
		{"the stage is skipped, as in the 0.5.0 configuration", fixture, write("skipped.log", goreleaserLog("  • skipped generating changelog\n")), 1, "skipped its changelog stage"},
		{"no stage line at all", fixture, write("none.log", "  • archives\n"), 1, "shows no changelog stage"},
		{"an empty log", fixture, write("empty.log", ""), 1, "shows no changelog stage"},
		{"the stage ran and read nothing", fixture, write("nothing.log", goreleaserLog(stage)), 1, fmt.Sprintf("did not report reading %d bytes", size)},
		{"the stage read another size", fixture, write("size.log", goreleaserLog(stage, readLines(size+1, fixture)...)), 1, fmt.Sprintf("did not report reading %d bytes", size)},
		{"the stage read another file", fixture, write("file.log", goreleaserLog(stage, readLines(size, filepath.Join(dir, "other.md"))...)), 1, fmt.Sprintf("did not report reading %d bytes", size)},
		{"the size is on one line and the file on another", fixture, write("split.log", goreleaserLog(stage,
			fmt.Sprintf("    • read %d bytes%sfile=%s\n", size, " ", filepath.Join(dir, "other.md")),
			fmt.Sprintf("    • loading file %q\n", fixture))), 1, "did not report reading"},
		{"an unrelated line that says changelog, and no stage step", fixture, write("unrelated.log", goreleaserLog("  • loading changelog config\n", readLines(size, fixture)...)), 1, "shows no changelog stage"},
		{"the stage read a file whose name only begins with the fixture's", fixture, write("prefix.log", goreleaserLog(stage, readLines(size, fixture+".bak")...)), 1, fmt.Sprintf("did not report reading %d bytes", size)},
		{"the stage read the fixture and a field follows the path", fixture, write("field.log", goreleaserLog(stage, fmt.Sprintf("    • read %d bytes   file=%s other=1\n", size, fixture))), 0, fmt.Sprintf("read the %d bytes of %s", size, fixture)},
		{"a log that is not there", fixture, filepath.Join(dir, "absent.log"), 1, "there is no GoReleaser log"},
		{"a fixture that is not there", filepath.Join(dir, "absent.md"), write("any.log", goreleaserLog(stage)), 1, "there is no fixture"},
		{"an empty fixture, whose size 0 any stage would match", write("zero.md", ""), write("zero.log", goreleaserLog(stage, readLines(0, filepath.Join(dir, "zero.md"))...)), 1, "is empty"},
	} {
		code, out := run(c.fixture, c.log)
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d; output:\n%s", c.name, code, c.exit, out)
		}
		if !strings.Contains(out, c.out) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.out, out)
		}
	}
}
