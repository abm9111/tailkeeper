package probe

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// liveMark is in every name of the live policies below. The model tailnet of the other
// tests holds a tag, a group, a host and a service, so none of its probes skips anything;
// a Skip reason, a Fact name or a Check name built from a live name would never be seen.
// These policies make every skip path fire, with names that all carry the mark.
const liveMark = "zzmark"

// skipScenario is a live policy that makes some skip paths fire, and the reasons it must produce.
type skipScenario struct {
	name   string
	text   string
	detail int                 // when not 0, the status a details read answers with
	ssh    bool                // answer a policy that carries sshTests with "unknown field", so A-10 tries its fallback
	want   map[string][]string // probe ID -> substrings of reasons that must be among its Skipped
}

func skipScenarios() []skipScenario {
	return []skipScenario{
		{
			name: "a tag and nothing else",
			text: `{"tagOwners":{"tag:zzmark":[]},"acls":[]}`,
			ssh:  true,
			want: map[string][]string{
				"A-9":  {"defines no host alias", "no group member written as an address", "names no svc: service"},
				"A-10": {"no ssh rule a test can be built from"},
			},
		},
		{
			name: "host aliases and an ssh rule no test can be built from, but no source",
			text: `{"hosts":{"zzmarkhost":"100.64.0.9"},"ssh":[{"action":"accept","src":["zzmark@example.com"],"dst":["autogroup:self"],"users":["zzmarkuser"]}],"acls":[]}`,
			ssh:  true,
			want: map[string][]string{
				"A-9":  {"defines no tag, no login and no group, so no tests-mode request has a source"},
				"A-10": {"no ssh rule a test can be built from"},
				"A-12": {"so there is no source for a test"},
			},
		},
		{
			name: "a group whose only member is a login, and no tag",
			text: `{"groups":{"group:zzmark":["zzmark@example.com"]},"acls":[]}`,
			want: map[string][]string{
				"A-9": {"defines no tag", "defines no host alias", "names no svc: service"},
			},
		},
		{
			name:   "a live policy that cannot be read",
			text:   liveText,
			detail: 403,
			want: map[string][]string{
				"A-9": {"the live policy could not be read, so no tests-mode request has a source"},
			},
		},
	}
}

func isIdent(e ast.Expr) bool { _, ok := e.(*ast.Ident); return ok }

// skipSites parses probes.go and returns the line of every call of Skip, the literal
// reasons it can give, and the Skip arguments that are not a literal (as source text).
func skipSites(t *testing.T) (lines []int, literals []string, dynamic []string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Skip" || len(x.Args) != 1 {
				return true
			}
			lines = append(lines, fset.Position(x.Pos()).Line)
			if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				literals = append(literals, s)
			} else if arg, ok := x.Args[0].(*ast.SelectorExpr); ok && isIdent(arg.X) {
				dynamic = append(dynamic, arg.X.(*ast.Ident).Name+"."+arg.Sel.Name)
			} else {
				dynamic = append(dynamic, "an expression that is not k.absent")
			}
		case *ast.KeyValueExpr:
			// destination{..., absent: "the sentence"}: the reasons x.Skip(k.absent) can give.
			if id, ok := x.Key.(*ast.Ident); ok && id.Name == "absent" {
				if lit, ok := x.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					literals = append(literals, s)
				}
			}
		}
		return true
	})
	return lines, literals, dynamic
}

// A Skip reason is a sentence written in probes.go: its argument is a string literal, or
// k.absent, whose values are literals too. This fails on any other expression, which
// could carry a name from the live policy; the run below fails on a leak that gets past it.
func TestEverySkipReasonIsALiteral(t *testing.T) {
	lines, literals, dynamic := skipSites(t)
	if len(lines) < 5 || len(literals) < 8 {
		t.Fatalf("found %d Skip calls and %d reasons in probes.go (lines %v): the parse is not seeing them", len(lines), len(literals), lines)
	}
	for _, d := range dynamic {
		if d != "k.absent" {
			t.Errorf("a Skip call takes %s; a reason must be a string literal or k.absent", d)
		}
	}
}

// Every skip path of probes.go fires against a live policy that makes it fire, and
// nothing from that policy (every name of which carries the mark) reaches the report,
// the files or stderr.
func TestNoLiveNameReachesTheOutputOfASkippingRun(t *testing.T) {
	_, literals, _ := skipSites(t)
	seen := map[string]bool{}
	for _, sc := range skipScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			w := newWorld(t)
			w.serveText(sc.text)
			if sc.detail != 0 {
				w.detailsFail = &struct {
					code int
					body string
				}{sc.detail, `{"message":"` + liveMark + ` is denied"}`}
			}
			if sc.ssh {
				w.override = func(body string) (apitest.Shape, bool) {
					if strings.Contains(body, `"sshTests":[{`) {
						return apitest.PolicyUnknownField("sshTests"), true
					}
					return apitest.Shape{}, false
				}
			}
			var results []Result
			prev := runProbes
			runProbes = func(ctx context.Context, a API, probes []Probe, o Options) []Result {
				results = Run(ctx, a, probes, o)
				return results
			}
			t.Cleanup(func() { runProbes = prev })
			var out, errb bytes.Buffer
			dir := filepath.Join(t.TempDir(), "observed")
			command(context.Background(), w.f.Client(t), []string{"--out", dir, "--gap", "0s"}, &out, &errb, func() time.Time { return time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC) })

			// The skip paths fired.
			byID := map[string]Result{}
			for _, r := range results {
				byID[r.ID] = r
				for _, s := range r.Skipped {
					seen[s] = true
				}
			}
			for id, subs := range sc.want {
				r, ok := byID[id]
				if !ok || len(r.Skipped) == 0 {
					t.Errorf("%s skipped nothing", id)
					continue
				}
				for _, sub := range subs {
					found := false
					for _, s := range r.Skipped {
						found = found || strings.Contains(s, sub)
					}
					if !found {
						t.Errorf("%s: no skip reason contains %q (skipped: %q)", id, sub, r.Skipped)
					}
				}
			}

			// The policy's names were used: some request carried the mark. Without that,
			// the check below would prove nothing.
			used := false
			for _, q := range w.f.Requests() {
				used = used || strings.Contains(string(q.Body), liveMark)
			}
			if sc.detail == 0 && !used {
				t.Error("no request carried a name from the live policy: the scenario does not exercise the probes")
			}

			// Nothing carries the mark: not stdout (the report), not stderr, not a file.
			all := out.String() + "\n" + errb.String()
			files, err := filepath.Glob(filepath.Join(dir, "*.json"))
			if err != nil || len(files) == 0 {
				t.Fatalf("no skeleton files were written (%v)", err)
			}
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				all += "\n" + string(b)
			}
			if strings.Contains(all, liveMark) {
				at := strings.Index(all, liveMark)
				t.Errorf("a name from the live policy reached the output, near %q", all[max(0, at-60):min(len(all), at+60)])
			}
			if !strings.Contains(out.String(), "  skipped   ") {
				t.Errorf("the report shows no skipped line:\n%s", out.String())
			}
		})
	}
	// Every reason probes.go can give came up in some scenario.
	sort.Strings(literals)
	for _, l := range literals {
		if !seen[l] {
			t.Errorf("no scenario made this skip path fire: %q", l)
		}
	}
}
