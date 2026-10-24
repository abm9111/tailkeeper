//go:build ignore

// Command recipes extracts fenced yaml, sh and bash blocks from docs/recipes
// into a directory named with -dir.
//
//	$(GO) run scripts/recipes.go -dir DEST
//
// A yaml fence becomes DEST/github/workflows/<name>-<n>.yml and a sh or bash
// fence becomes DEST/scripts/<name>-<n>.sh. <name> is the markdown file's base
// name. <n> counts fences of that kind in that file, starting at 1. A fence
// opens with three or more backticks or three or more tildes and closes with
// the same character, at least as many; it may be indented by up to three
// spaces, and that indent is removed from its body.
// A fence tagged hujson, json, toml, xml, ini or nothing is left out, and the
// command says which it left out, with the file and line, so a reader sees what
// make actionlint did not lint. Any other tag (yml, shell, zsh, a typo) is an
// error: a fence that was meant to be linted must not be skipped silently. The
// command prints, for each file it writes, the markdown file and line the fence
// opens at, since the linters name the extracted file and not the markdown.
// A fence the command cannot read as a fence is also an error, named by file
// and line, and never skipped: one inside a blockquote ("> ```sh"), and one
// indented by four or more spaces or a tab (which Markdown reads as an indented
// code block, or as a fence inside a list item). Move it out, or indent it by
// three spaces at most.
// The command exits 1 when a fence is not closed, has a tag it does not know, is
// one of the fences above, or two fences would write one path, and exits 2 when
// -dir is missing.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	dest, err := destination(args)
	if err != nil {
		return fail(2, err)
	}
	report, err := extract(filepath.Join("docs", "recipes"), dest)
	if err != nil {
		return fail(1, err)
	}
	for _, line := range report {
		_, _ = fmt.Fprintln(os.Stdout, "recipes:", line)
	}
	return 0
}

func fail(code int, err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "recipes:", err.Error())
	return code
}

func destination(args []string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == "-dir" && args[1] != "":
		return args[1], nil
	case len(args) == 1 && strings.HasPrefix(args[0], "-dir=") && len(args[0]) > len("-dir="):
		return strings.TrimPrefix(args[0], "-dir="), nil
	default:
		return "", errors.New("usage: recipes -dir DEST")
	}
}

// recipeStem is the markdown base name that becomes the output file name.
// It is a single path segment so the shell that lints the output can glob it.
var recipeStem = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type fenceFile struct {
	rel, origin string
	body        []byte
}

// skippedTags are the fence tags that are left out on purpose: they are not
// yaml or shell, and nothing here lints them.
var skippedTags = map[string]bool{"hujson": true, "json": true, "toml": true, "xml": true, "ini": true}

// extract writes the fences of every *.md file in docs under dest and returns
// what it did, one line each: the file written and the fence it came from, then
// the fences left out.
func extract(docs, dest string) ([]string, error) {
	info, err := os.Stat(docs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", filepath.ToSlash(docs))
	}
	matches, err := filepath.Glob(filepath.Join(docs, "*.md"))
	if err != nil {
		return nil, err
	}
	var files []fenceFile
	var left []string
	for _, name := range matches {
		part, skipped, err := fencesIn(name)
		if err != nil {
			return nil, err
		}
		files = append(files, part...)
		left = append(left, skipped...)
	}
	if err := writeFences(dest, files); err != nil {
		return nil, err
	}
	var report []string
	for _, f := range files {
		report = append(report, fmt.Sprintf("%s is the fence that opens at %s (line 1 of the file is the line after it)", f.rel, f.origin))
	}
	if len(left) > 0 {
		report = append(report, "not linted: "+strings.Join(left, ", "))
	}
	return report, nil
}

func fencesIn(name string) ([]fenceFile, []string, error) {
	stem := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	if !recipeStem.MatchString(stem) {
		return nil, nil, fmt.Errorf("%s: recipe file name cannot be written", filepath.ToSlash(name))
	}
	data, err := os.ReadFile(name) //nolint:gosec // G304: name is a *.md path from Glob of the docs/recipes directory passed in, not a caller path
	if err != nil {
		return nil, nil, err
	}
	shown := filepath.ToSlash(name)
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	var out []fenceFile
	var skipped []string
	var open *openFence
	yamlN, shellN := 0, 0
	for i, line := range lines {
		if open == nil {
			indent, char, ticks, info, ok := fenceOpen(line)
			if !ok {
				if why := unreadableFence(line); why != "" {
					return nil, nil, fmt.Errorf("%s:%d: %s", shown, i+1, why)
				}
				continue
			}
			open = &openFence{indent: indent, char: char, ticks: ticks, info: info, line: i + 1}
			continue
		}
		if fenceClose(line, open.char, open.ticks) {
			ext := fenceExt(open.info)
			if ext == "" {
				tag := fenceTag(open.info)
				if tag != "" && !skippedTags[tag] {
					return nil, nil, fmt.Errorf("%s:%d: fence tag %q is not one the extractor knows: use yaml, sh or bash to lint the fence, or %s to leave it out", shown, open.line, tag, skippedList())
				}
				if tag == "" {
					tag = "no tag"
				}
				skipped = append(skipped, fmt.Sprintf("%s:%d (%s)", shown, open.line, tag))
			} else {
				n := 0
				switch ext {
				case "yml":
					yamlN++
					n = yamlN
				default:
					shellN++
					n = shellN
				}
				body := []byte(strings.Join(open.lines, "\n"))
				if len(open.lines) > 0 {
					body = append(body, '\n')
				}
				dir := "scripts"
				if ext == "yml" {
					dir = filepath.Join("github", "workflows")
				}
				rel := filepath.ToSlash(filepath.Join(dir, stem+"-"+strconv.Itoa(n)+"."+ext))
				out = append(out, fenceFile{
					rel:    rel,
					origin: fmt.Sprintf("%s:%d", shown, open.line),
					body:   body,
				})
			}
			open = nil
			continue
		}
		open.lines = append(open.lines, stripIndent(line, open.indent))
	}
	if open != nil {
		return nil, nil, fmt.Errorf("%s:%d: fence is not closed", shown, open.line)
	}
	return out, skipped, nil
}

func skippedList() string {
	return "hujson, json, toml, xml or ini"
}

type openFence struct {
	indent, ticks, line int
	char                byte
	info                string
	lines               []string
}

// fenceOpen reports a fence opening: three or more backticks or tildes after at
// most three spaces. The info string of a backtick fence holds no backtick (a
// line that does is inline code); a tilde fence's may.
func fenceOpen(line string) (indent int, char byte, ticks int, info string, ok bool) {
	indent, rest, ok := fenceRest(line)
	if !ok || rest == "" || (rest[0] != '`' && rest[0] != '~') {
		return 0, 0, 0, "", false
	}
	char = rest[0]
	n := 0
	for n < len(rest) && rest[n] == char {
		n++
	}
	if n < 3 {
		return 0, 0, 0, "", false
	}
	info = rest[n:]
	if char == '`' && strings.Contains(info, "`") {
		return 0, 0, 0, "", false
	}
	return indent, char, n, strings.TrimSpace(info), true
}

// unreadableFence says why a line that is not a readable fence opening is still
// one that the extractor must not skip: it opens a fence inside a blockquote, or
// after four or more spaces or a tab. It returns "" for any other line.
func unreadableFence(line string) string {
	rest := strings.TrimLeft(line, " \t")
	quoted := false
	for strings.HasPrefix(rest, ">") {
		quoted = true
		rest = strings.TrimLeft(strings.TrimPrefix(rest, ">"), " \t")
	}
	if _, _, _, _, ok := fenceOpen(rest); !ok {
		return ""
	}
	if quoted {
		return "a fence inside a blockquote is not extracted or linted: move it out of the quote"
	}
	return "a fence indented by four or more spaces or a tab is not extracted or linted: indent it by three spaces at most, or move it out of the list item"
}

func fenceClose(line string, char byte, ticks int) bool {
	_, rest, ok := fenceRest(line)
	if !ok {
		return false
	}
	rest = strings.TrimRight(rest, " \t")
	if len(rest) < ticks {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] != char {
			return false
		}
	}
	return true
}

// fenceRest reports the spaces before a fence (at most three) and the rest of
// the line. A line indented by four or more spaces is not a fence.
func fenceRest(line string) (int, string, bool) {
	i := 0
	for i < len(line) && i < 3 && line[i] == ' ' {
		i++
	}
	if i < len(line) && line[i] == ' ' {
		return 0, "", false
	}
	return i, line[i:], true
}

// fenceTag is the first word of a fence's info string.
func fenceTag(info string) string {
	fields := strings.Fields(info)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func fenceExt(info string) string {
	switch fenceTag(info) {
	case "yaml":
		return "yml"
	case "sh", "bash":
		return "sh"
	default:
		return ""
	}
}

func stripIndent(line string, n int) string {
	i := 0
	for i < n && i < len(line) && line[i] == ' ' {
		i++
	}
	return line[i:]
}

func writeFences(dest string, files []fenceFile) error {
	seen := make(map[string]string, len(files))
	for _, f := range files {
		if prev, ok := seen[f.rel]; ok {
			return fmt.Errorf("%s and %s would write %s", prev, f.origin, f.rel)
		}
		seen[f.rel] = f.origin
		if !fs.ValidPath(f.rel) {
			return fmt.Errorf("%s: refusing to write %s", f.origin, f.rel)
		}
		full := filepath.Join(dest, filepath.FromSlash(f.rel))
		back, err := filepath.Rel(filepath.Clean(dest), full)
		if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s: refusing to write %s", f.origin, f.rel)
		}
		// full is -dir joined with a name recipeStem accepted. fs.ValidPath and
		// filepath.Rel above refused anything that would leave dest.
		if _, err := os.Lstat(full); err == nil { //nolint:gosec // G703: full is -dir plus a recipeStem name, kept inside dest by the checks above
			return fmt.Errorf("%s would write %s, which already exists", f.origin, f.rel)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil { //nolint:gosec // G703: the directory of the path checked above
			return err
		}
		if err := os.WriteFile(full, f.body, 0o600); err != nil { //nolint:gosec // G703: the file at the path checked above
			return err
		}
	}
	return nil
}
