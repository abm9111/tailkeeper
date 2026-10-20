package tools_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A resolver that has resolved two users, the first with a slash in its login: a byte the
// address scan does not read as part of a local part.
func resolvedTwo(t *testing.T) (*tools.SubjectResolver, string, string) {
	t.Helper()
	f, reg, env := apiEnv(t)
	const slashed, plain = "ops/amy@example.com", "bob@example.org"
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, slashed, plain))
	kenv, _ := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	for _, id := range []string{"u1", "u2"} {
		if _, err := r.Resolve(context.Background(), shownRef(t, reg, kenv, id)); err != nil {
			t.Fatal(err)
		}
	}
	return r, slashed, plain
}

// resolvedAll is a resolver that has resolved every one of logins, listed in that order.
func resolvedAll(t *testing.T, logins ...string) *tools.SubjectResolver {
	t.Helper()
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, logins...))
	kenv, _ := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	for i := range logins {
		if _, err := r.Resolve(context.Background(), shownRef(t, reg, kenv, fmt.Sprintf("u%d", i+1))); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// A reply that repeats a login masks both echoes, and the walk back over the local-part bytes
// of the second never runs into the first (it once panicked with slice bounds out of range).
func TestHideSurvivesTwoEchoesOfOneLogin(t *testing.T) {
	r := resolvedAll(t, "amy@example.com", "bob@example.org")
	checked := 0
	for _, echo := range []string{
		"src=amy@example.com&dst=amy@example.com",
		"amy@example.com=amy@example.com",
		"amy@example.com+amy@example.com",
	} {
		checked++
		got := r.Hide(echo)
		if strings.Contains(got, "amy") {
			t.Errorf("Hide(%q) = %q still shows amy", echo, got)
		}
	}
	if checked != 3 {
		t.Fatalf("checked %d echoes, want 3", checked)
	}
}

// A login with a byte the address scan does not read (a slash) is hidden whole in every
// spelling of its at sign, whichever login another user's address shares its tail with and in
// whichever order the two were resolved: the longer login goes first.
func TestHideShowsNothingOfASlashedLoginInAnyEcho(t *testing.T) {
	bs := string(rune(92))
	checked := 0
	for name, logins := range map[string][]string{
		"short then long": {"amy@example.com", "ops/amy@example.com"},
		"long then short": {"ops/amy@example.com", "amy@example.com"},
	} {
		r := resolvedAll(t, logins...)
		for _, at := range []string{"@", bs + "u0040", "%40", bs + "u{40}", bs + "u{0040}"} {
			checked++
			in := "invalid: ops/amy" + at + "example.com"
			if got := r.Hide(in); got != "invalid: o…" {
				t.Errorf("%s: Hide(%q) = %q, want %q", name, in, got, "invalid: o…")
			}
		}
	}
	if checked != 10 {
		t.Fatalf("checked %d echoes, want 10", checked)
	}
}

func TestHideMasksEveryLoginTheResolverHandedOutInEveryEcho(t *testing.T) {
	r, slashed, plain := resolvedTwo(t)
	bs := string(rune(92))
	// How a reply may echo a login: as sent, in another case, with the at sign escaped as JSON
	// or as a URL does, inside a longer token, in a sentence.
	for _, login := range []string{slashed, plain} {
		local, domain, _ := strings.Cut(login, "@")
		for _, echo := range []string{
			login,
			strings.ToUpper(login),
			local + bs + "u0040" + domain,
			local + "%40" + domain,
			local + bs + "u{40}" + domain,
			local + bs + "u{0040}" + domain,
			"user=" + login,
			`"` + login + `"`,
			"user or host is invalid: " + login + ".",
			"[" + login + "] and [" + login + "]",
		} {
			got := r.Hide(echo)
			for _, leak := range []string{local, strings.ToUpper(local)} {
				if strings.Contains(got, leak) {
					t.Errorf("Hide(%q) = %q still shows %q", echo, got, leak)
				}
			}
			if strings.Contains(got, "[p:") {
				t.Errorf("Hide(%q) = %q names a pseudonym: a reply echoes what was sent, and a pseudonym beside it would confirm a guess", echo, got)
			}
			if again := r.Hide(got); again != got {
				t.Errorf("Hide(%q) = %q, but hiding that again gives %q", echo, got, again)
			}
		}
	}
	// The reverse map is not the address scan's work: it reads the whole login as one name.
	if scan := sanitize.MaskEmails(slashed); !strings.Contains(scan, "ops/") {
		t.Fatalf("MaskEmails(%q) = %q: the example no longer shows what the reverse map adds", slashed, scan)
	}
	if got := r.Hide("invalid: " + slashed); got != "invalid: o…" {
		t.Errorf("Hide of the slashed login = %q, want %q", got, "invalid: o…")
	}
	// Other addresses are masked as the registry masks them, without a pseudonym.
	if got := r.Hide("not carol@example.net"); got != "not c…@example.net" {
		t.Errorf("Hide of another address = %q", got)
	}
	if got := r.Hide("nothing here"); got != "nothing here" {
		t.Errorf("Hide of text with no address = %q", got)
	}
}

func TestHideLeavesTextAloneWhilePersonalDataIsShown(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com"))
	kenv, _ := keyed(t, env)
	ref := shownRef(t, reg, kenv, "u1")
	r := tools.NewSubjectResolver(show(kenv))
	if _, err := r.Resolve(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if got := r.Hide("invalid: amy@example.com"); got != "invalid: amy@example.com" {
		t.Errorf("Hide with personalData show = %q, want the text as it came", got)
	}
}

func TestHideErrorKeepsTheCodeAndStatusAndMasksTheText(t *testing.T) {
	r, slashed, _ := resolvedTwo(t)
	cause := tkerr.New(tkerr.APIError, "inner: "+slashed, "")
	in := &tkerr.Error{Code: tkerr.ValidationFailed, Message: "user or host is invalid: " + slashed, Hint: "check " + slashed, Status: http.StatusBadRequest, Err: cause}
	out, ok := tkerr.As(r.HideError(in))
	if !ok {
		t.Fatal("HideError returned something that is not a *tkerr.Error")
	}
	if out.Code != tkerr.ValidationFailed || out.Status != http.StatusBadRequest {
		t.Errorf("code %s status %d, want validation_failed 400", out.Code, out.Status)
	}
	text := out.Error() + out.Message + out.Hint
	if strings.Contains(text, "ops") || out.Err != nil {
		t.Errorf("the login or its cause survived: %q (cause %v)", text, out.Err)
	}
	if in.Message != "user or host is invalid: "+slashed {
		t.Error("HideError changed the error it was given")
	}
	// Any error becomes a *tkerr.Error, and nil stays nil.
	if e, ok := tkerr.As(r.HideError(context.DeadlineExceeded)); !ok || e.Code != tkerr.Internal {
		t.Errorf("a plain error: %v, want internal_error", e)
	}
	if r.HideError(nil) != nil {
		t.Error("HideError(nil) must be nil")
	}
}

func TestHideMasksAWordGluedToALoginAsOneAddress(t *testing.T) {
	r, _, plain := resolvedTwo(t)
	// Another user's address that ends in a resolved login: masked from its first byte, as
	// the address scan alone would mask it, never with a longer front showing.
	glued := []string{"big", "mary.", "z", "x_", "a+", "q=", "9"}
	for _, lead := range glued {
		if got, want := r.Hide(lead+plain), sanitize.MaskIdentifier(lead+plain); got != want {
			t.Errorf("Hide(%q) = %q, want %q", lead+plain, got, want)
		}
	}
	if len(glued) != 7 {
		t.Fatalf("%d glued leads, want 7", len(glued))
	}
	// A byte the address scan does not read as part of a local part ends the word: the login
	// is masked alone and the byte stays.
	apart := []string{"/", " ", "(", `"`, ":"}
	for _, lead := range apart {
		if got, want := r.Hide(lead+plain), lead+sanitize.MaskIdentifier(plain); got != want {
			t.Errorf("Hide(%q) = %q, want %q", lead+plain, got, want)
		}
	}
	if len(apart) != 5 {
		t.Fatalf("%d separating leads, want 5", len(apart))
	}
}

func TestHideErrorOfATypedNilIsAnInternalError(t *testing.T) {
	r, _, _ := resolvedTwo(t)
	var typed *tkerr.Error
	e, ok := tkerr.As(r.HideError(typed))
	if !ok || e.Code != tkerr.Internal {
		t.Errorf("a typed nil: %v (ok %v), want internal_error", e, ok)
	}
}
