package tools_test

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// firstRead is how much of a text Hide reads at first (the unexported firstRead of the
// package); CutAt takes any limit, and these tests cut at this one.
const firstRead = 4096

// Resolve once named every login of the tailnet for every pseudonym it was asked to resolve:
// 64 resolutions over 5,000 users made 320,000 calls to the naming function (an HMAC each).
// The users are named once, when they are read, and a resolution is a lookup.
func TestResolveDoesNotRenameEveryLoginPerCall(t *testing.T) {
	const users, resolutions = 5000, 64
	logins := make([]string, users)
	for i := range logins {
		logins[i] = fmt.Sprintf("user%04d@example.com", i)
	}
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, logins...))
	kenv, k := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	calls := 0
	r.SetPseudonymFunc(func(login string) string { calls++; return k.APIPseudonym(login) })
	for i := 0; i < resolutions; i++ {
		login := logins[i*70]
		got, err := r.Resolve(context.Background(), k.APIPseudonym(login))
		if err != nil || got.Reveal() != login {
			t.Fatalf("resolution %d: %v", i, err)
		}
	}
	if calls != users {
		t.Errorf("the naming function ran %d times for %d resolutions over %d users, want %d (once per user)", calls, resolutions, users, users)
	}
	if got := usersRequests(f); got != 1 {
		t.Errorf("%d requests for the users, want 1", got)
	}
}

// Hide compiled one regular expression per login it had handed out, on every call. The
// patterns are compiled when the login is resolved and Hide only runs them, so what a call
// over text that holds none of the logins allocates for each further login is a small
// fraction of what compiling its pattern costs. The test measures the compile in the same
// run and compares: it counts nothing absolute, so a toolchain that moves the cost of a
// compile or of a match moves both sides.
func TestHideCompilesNothingPerCall(t *testing.T) {
	three := resolvedAll(t, "amy@example.com", "bob@example.org", "carol@example.com")
	withLogins := "src=amy@example.com dst=bob@example.org note carol@example.com done"
	if got := three.Hide(withLogins); strings.Contains(got, "amy") || strings.Contains(got, "bob") || strings.Contains(got, "carol") {
		t.Fatalf("Hide(%q) = %q still shows a login", withLogins, got)
	}
	one := resolvedAll(t, "amy@example.com")
	const noLogin = "a note that names nobody, only words, from a tailnet"
	allocsOne := testing.AllocsPerRun(20, func() { _ = one.Hide(noLogin) })
	allocsThree := testing.AllocsPerRun(20, func() { _ = three.Hide(noLogin) })
	// The yardstick is a pattern of the same kind as a login's: the case-blind login with
	// its alternatives for the at sign.
	compile := testing.AllocsPerRun(20, func() { _ = regexp.MustCompile(`(?i)amy(?:@|%40)example\.com`) })
	perLogin := (allocsThree - allocsOne) / 2
	if compile < 10 || perLogin > compile/2 {
		t.Errorf("each further login adds %.1f allocations to a call of Hide (%.0f over three logins, %.0f over one), and compiling a pattern costs %.0f: a call that adds about as much as a compile compiles one per login", perLogin, allocsThree, allocsOne, compile)
	}
}

// What a read of limit bytes leaves of a login that starts before the cut and ends after it:
// nothing, whole or in part. A login that ends a byte before the cut is inside the text.
func TestACutLeavesNothingOfALoginThatStraddlesIt(t *testing.T) {
	r := resolvedAll(t, "amy@example.com", "bob@example.org")
	// The login starts k bytes before the cut, so the cut falls inside it for k = 1 to 14.
	const login = "amy@example.com"
	checked := 0
	for k := 1; k < len(login); k++ {
		checked++
		out := r.CutAt(strings.Repeat(" ", firstRead-k)+login+" tail", firstRead)
		if len(out) > firstRead {
			t.Errorf("k=%d: %d bytes, want at most %d", k, len(out), firstRead)
		}
		if strings.TrimSpace(out) != "" {
			t.Errorf("k=%d: the cut left %q of a login, want nothing of it", k, strings.TrimSpace(out))
		}
	}
	if checked != len(login)-1 {
		t.Fatalf("checked %d cuts, want %d", checked, len(login)-1)
	}
	// A login that ends at the cut cannot be told from one that goes on, so it goes with the
	// word it ends; one that ends a byte before the cut is inside the text and stays whole.
	text := strings.Repeat(" ", firstRead-len(login)) + login + " tail"
	if out := r.CutAt(text, firstRead); strings.TrimSpace(out) != "" {
		t.Errorf("a login that ends at the cut left %q, want nothing of it", strings.TrimSpace(out))
	}
	text = strings.Repeat(" ", firstRead-len(login)-1) + login + " tail"
	if out := r.CutAt(text, firstRead); strings.TrimSpace(out) != login {
		t.Errorf("a login inside the text: %q, want it whole", strings.TrimSpace(out))
	}
	// A text under the limit is not cut.
	if out := r.CutAt("short amy@example.com text", firstRead); out != "short amy@example.com text" {
		t.Errorf("a short text came back as %q", out)
	}
}

// The cut leaves no part of an address in any spelling the masker reads, not only the
// plain one: where the cut falls inside the local part, the remnant would be the local part
// of a login (the first characters of it, with the start of the escape that spells its at
// sign). Each row spells one login, and the cut is taken at every offset inside it.
func TestHideCutLeavesNoPartOfALoginInAnySpelling(t *testing.T) {
	bs := string(rune(92)) // a backslash, built so that no tool turns it and the next letter into a character
	r := resolvedAll(t, "amy@example.com")
	for name, spelled := range map[string]string{
		"a plain at sign":                           "amy@example.com",
		"a JSON escape":                             "amy" + bs + "u0040example.com",
		"a brace escape":                            "amy" + bs + "u{40}example.com",
		"a brace escape with leading zeros":         "amy" + bs + "u{000040}example.com",
		"a percent escape":                          "amy%40example.com",
		"a quoted local part":                       `"amy"@example.com`,
		"a quoted local part and a JSON escape":     `"amy"` + bs + "u0040example.com",
		"a local part spelled in escapes, past 320": strings.Repeat(bs+"u0061", 60) + "@example.com",
	} {
		checked, left := 0, 0
		for k := 1; k < len(spelled); k++ {
			checked++
			out := r.CutAt(strings.Repeat(" ", firstRead-k)+spelled+" tail", firstRead)
			if len(out) > firstRead {
				t.Errorf("%s, k=%d: %d bytes, want at most %d", name, k, len(out), firstRead)
			}
			if strings.TrimSpace(out) != "" {
				left++
				if left == 1 {
					t.Errorf("%s, k=%d: the cut left %q of a login, want nothing of it", name, k, strings.TrimSpace(out))
				}
			}
		}
		if checked != len(spelled)-1 {
			t.Errorf("%s: checked %d cuts, want %d", name, checked, len(spelled)-1)
		}
		if left > 1 {
			t.Errorf("%s: %d of %d cuts left part of the login", name, left, checked)
		}
	}
}

// hideEndsWithLoginPrefix reports whether text ends with a non-empty prefix of spelled, in
// any letter case, and which one. The prefixes are cut at rune boundaries.
func hideEndsWithLoginPrefix(text, spelled string) (string, bool) {
	lower := strings.ToLower(text)
	for j := 1; j <= len(spelled); j++ {
		if j < len(spelled) && !utf8.RuneStart(spelled[j]) {
			continue
		}
		if p := strings.ToLower(spelled[:j]); strings.HasSuffix(lower, p) {
			return spelled[:j], true
		}
	}
	return "", false
}

// The output of the cut holds no start of a login that straddles it, whatever bytes the
// local part of the login holds and however each at sign is spelled. The bytes a local part
// may hold that the address scan does not read (a slash, a space, a backslash, a quote around
// a word) are the ones a cut that only walks back over address bytes leaves behind: the
// walk stops at them, and what stands before them stays. Each row is one login; each is
// written with every at sign as @, as a JSON escape, as a brace escape (with and without
// leading zeros) and as %40, in the case it was resolved in and in upper case, and the cut is
// taken at every offset inside it and at its end.
func TestHideCutLeavesNoStartOfAnyLoginWhateverItsLocalPartHolds(t *testing.T) {
	bs := string(rune(92)) // a backslash, built so that no tool turns it and the next letter into a character
	logins := map[string]string{
		"letters":                          "amy@example.com",
		"digits":                           "a1b2@example.com",
		"a dot":                            "a.b@example.com",
		"a plus":                           "a+b@example.com",
		"a hyphen":                         "a-b@example.com",
		"an underscore":                    "a_b@example.com",
		"a slash":                          "ops/amy@example.com",
		"a space":                          "a b@example.com",
		"a quoted local part with a space": `"ops amy"@example.com`,
		"a quoted local part with an at":   `"a@b"@example.com`,
		"a backslash escape":               "a" + bs + " b@example.com",
		"a backslash before an at":         "a" + bs + "@b@example.com",
		"a percent-encoded byte":           "a%2Fb@example.com",
		"a percent-encoded at":             "a%40b@example.com",
		"a non-ASCII letter":               "\u00e9mile@example.com",
	}
	ats := map[string]string{
		"a plain at sign":                   "@",
		"a JSON escape":                     bs + "u0040",
		"a brace escape":                    bs + "u{40}",
		"a brace escape with leading zeros": bs + "u{000040}",
		"a percent escape":                  "%40",
	}
	cuts := 0
	for lname, login := range logins {
		r := resolvedAll(t, login)
		for aname, at := range ats {
			for _, upper := range []bool{false, true} {
				spelled := strings.ReplaceAll(login, "@", at)
				if upper {
					spelled = strings.ToUpper(spelled)
				}
				name := fmt.Sprintf("%s, %s, upper=%v", lname, aname, upper)
				bad := 0
				for k := 1; k <= len(spelled); k++ {
					if k < len(spelled) && !utf8.RuneStart(spelled[len(spelled)-k]) {
						continue // the cut is taken at rune boundaries only
					}
					cuts++
					out := r.CutAt(strings.Repeat(" ", firstRead-k)+spelled+" tail", firstRead)
					if len(out) > firstRead {
						t.Errorf("%s, k=%d: %d bytes, want at most %d", name, k, len(out), firstRead)
					}
					if p, ok := hideEndsWithLoginPrefix(out, spelled); ok {
						bad++
						if bad == 1 {
							t.Errorf("%s, k=%d: the cut left %q of the login %q, want none of it", name, k, p, spelled)
						}
					}
				}
				if bad > 1 {
					t.Errorf("%s: %d cuts left part of the login", name, bad)
				}
			}
		}
	}
	if want := len(logins) * len(ats) * 2; cuts < want*10 {
		t.Fatalf("checked %d cuts over %d spellings, want at least ten each", cuts, want)
	}
}

// A word glued to the front of a login whose local part holds a slash is part of the same
// address, so a cut inside the login takes the word with it, as it does for a plain login.
func TestHideCutTakesAWordGluedToAnUnreadableLoginWithIt(t *testing.T) {
	r := resolvedAll(t, "ops/amy@example.com")
	const login = "ops/amy@example.com"
	checked := 0
	for k := 1; k < len(login); k++ {
		checked++
		out := r.CutAt(strings.Repeat(" ", firstRead-k-3)+"big"+login+" tail", firstRead)
		if strings.TrimSpace(out) != "" {
			t.Errorf("k=%d: the cut left %q of the address, want nothing of it", k, strings.TrimSpace(out))
		}
	}
	if checked != len(login)-1 {
		t.Fatalf("checked %d cuts, want %d", checked, len(login)-1)
	}
}

// The unforging is what keeps an echoed marker from reading as a pseudonym Hide appended
// (it appends none): with a key, every marker of the text is rewritten; without one the text
// is as it came.
func TestHideUnforgesAMarkerTheTextHolds(t *testing.T) {
	r := resolvedAll(t, "amy@example.com", "bob@example.org")
	in := "the server said [p:abcdefghij] about [p:klmnopqrst]"
	got := r.Hide(in)
	if strings.Contains(got, "[p:") {
		t.Errorf("Hide(%q) = %q still holds a marker", in, got)
	}
	if want := strings.ReplaceAll(in, "[p:", string(rune(92))+"u{005B}p:"); got != want {
		t.Errorf("Hide(%q) = %q, want only the markers rewritten: %q", in, got, want)
	}
	_, _, env := apiEnv(t)
	if got := tools.NewSubjectResolver(env).Hide(in); got != in {
		t.Errorf("a resolver with no key returned %q, want the text as it came", got)
	}
}

// reach is what a dumper that follows pointers finds: every string reachable from a value
// through pointers, interfaces, slices, arrays, maps and struct fields, exported or not, and
// how many function values it met. A function value is where it stops: its closure cannot be
// read from outside. It also stops at the environment the resolver was built over, which is
// the process's shared state (an HTTP client with live connections, read by other goroutines)
// and not the resolver's own; it counts how often it stopped there.
type reach struct {
	seen  map[[2]uintptr]bool
	found []string
	funcs int
	nodes int
	envs  int
}

func (d *reach) walk(v reflect.Value) {
	if d.nodes++; d.nodes > 2_000_000 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		d.found = append(d.found, v.String())
	case reflect.Pointer:
		if v.IsNil() || d.seen[[2]uintptr{v.Pointer(), 0}] {
			return
		}
		if v.Type() == reflect.TypeOf((*registry.Env)(nil)) {
			d.envs++
			return
		}
		d.seen[[2]uintptr{v.Pointer(), 0}] = true
		d.walk(v.Elem())
	case reflect.Interface:
		if !v.IsNil() {
			d.walk(v.Elem())
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice {
			if v.IsNil() || d.seen[[2]uintptr{v.Pointer(), uintptr(v.Len())}] {
				return
			}
			d.seen[[2]uintptr{v.Pointer(), uintptr(v.Len())}] = true
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			d.walk(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() || d.seen[[2]uintptr{v.Pointer(), 1}] {
			return
		}
		d.seen[[2]uintptr{v.Pointer(), 1}] = true
		for it := v.MapRange(); it.Next(); {
			d.walk(it.Key())
			d.walk(it.Value())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			d.walk(v.Field(i))
		}
	case reflect.Func:
		if !v.IsNil() {
			d.funcs++
		}
	}
}

func dumpOf(v any) *reach {
	d := &reach{seen: map[[2]uintptr]bool{}}
	d.walk(reflect.ValueOf(v))
	return d
}

func (d *reach) holds(secrets ...string) []string {
	var hit []string
	for _, s := range d.found {
		for _, secret := range secrets {
			if strings.Contains(strings.ToLower(s), secret) {
				hit = append(hit, secret)
			}
		}
	}
	return hit
}

// After a resolution the resolver holds the logins of the whole tailnet. A reflection walk
// that follows pointers and reads unexported fields (what a debug dumper or a crash reporter
// does) reaches a function value where the logins are kept, and no login. A test that only
// calls fmt would pass with the logins in a plain struct field one pointer down.
func TestADumperThatFollowsPointersFindsNoLogin(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	got, err := r.Resolve(context.Background(), shownRef(t, reg, kenv, "u1"))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Hide("amy@example.com")
	logins := []string{"amy@example.com", "bob@example.org"}
	// The detector first: a login one pointer down in a plain struct is found.
	planted := struct{ p *struct{ logins []string } }{&struct{ logins []string }{[]string{"Amy@Example.com"}}}
	if hit := dumpOf(planted).holds(logins...); len(hit) != 1 {
		t.Fatalf("the walk found %v in a planted login, want it found", hit)
	}
	for name, v := range map[string]any{
		"the resolver":            r,
		"an exported field":       struct{ R *tools.SubjectResolver }{r},
		"an unexported field":     struct{ r *tools.SubjectResolver }{r},
		"a slice of resolvers":    []*tools.SubjectResolver{r},
		"the login it handed out": got,
	} {
		d := dumpOf(v)
		if hit := d.holds(logins...); len(hit) != 0 {
			t.Errorf("a walk from %s found %v", name, hit)
		}
		if d.funcs == 0 {
			t.Errorf("a walk from %s met no function value: the logins are not behind a closure", name)
		}
		if name != "the login it handed out" && d.envs == 0 {
			t.Errorf("a walk from %s never reached the environment: it did not read the resolver's fields", name)
		}
	}
}
