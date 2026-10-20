package tkerr

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// catalogueExits reads the error table of docs/design.md §19: for each code named in the
// first column of a row, the number in its Exit column. A row whose Exit cell is not one
// number ("5 / 11", "0 (typed result)") is left out.
func catalogueExits(t *testing.T) map[Code]int {
	t.Helper()
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	section, in := []string{}, false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "## ") {
			in = strings.HasPrefix(line, "## 19. Error model")
			continue
		}
		if in {
			section = append(section, line)
		}
	}
	if len(section) == 0 {
		t.Fatal("docs/design.md has no \"## 19. Error model\" section")
	}
	name := regexp.MustCompile("`([a-z_]+)`")
	out := map[Code]int{}
	for _, line := range section {
		cells := strings.Split(line, "|")
		if !strings.HasPrefix(line, "|") || len(cells) < 5 {
			continue
		}
		exit, err := strconv.Atoi(strings.TrimSpace(cells[len(cells)-2]))
		if err != nil {
			continue
		}
		for _, m := range name.FindAllStringSubmatch(cells[1], -1) {
			if _, twice := out[Code(m[1])]; twice {
				t.Errorf("%q has more than one row in docs/design.md §19: the catalogue must name each code once", m[1])
			}
			out[Code(m[1])] = exit
		}
	}
	return out
}

// The error catalogue of the design (§19) is where a reader finds what a code means and
// what it exits with, and where the README's table is checked against. Every code the
// binary declares must be in it, with the exit ExitCode returns.
func TestDesignCatalogueAgreesWithTheCodes(t *testing.T) {
	catalogue := catalogueExits(t)
	if len(catalogue) < 20 {
		t.Fatalf("read %d codes from the design's error table, want most of them: the reading is broken", len(catalogue))
	}
	var names []string
	for code := range declaredCodes(t) {
		names = append(names, string(code))
	}
	sort.Strings(names)
	for _, n := range names {
		code := Code(n)
		want, ok := catalogue[code]
		if !ok {
			t.Errorf("%q is declared in tkerr.go and has no row, or no single exit number, in docs/design.md §19", code)
			continue
		}
		if got := ExitCode(New(code, "m", "")); got != want {
			t.Errorf("%q: docs/design.md §19 says exit %d, ExitCode returns %d", code, want, got)
		}
	}
}
