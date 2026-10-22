package tools_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/registry"
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

// A reply may write a login in another letter case than the one that was sent. The address
// scan masks the plain spelling in any case, but it reads neither the escaped spellings of
// the at sign nor a slash in the local part, so what masks those in another case is the
// pattern of the login being blind to letter case.
func TestHideMasksALoginInAnotherLetterCase(t *testing.T) {
	bs := string(rune(92))
	r := resolvedAll(t, "amy@example.com", "ops/bob@example.org")
	checked := 0
	for _, in := range []string{
		"AMY" + bs + "u0040EXAMPLE.COM",
		"Amy" + bs + "u0040Example.com",
		"AMY%40EXAMPLE.COM",
		"AMY" + bs + "u{40}EXAMPLE.COM",
		"OPS/BOB@EXAMPLE.ORG",
		"Ops/Bob@Example.org",
		"OPS/BOB%40EXAMPLE.ORG",
	} {
		checked++
		got := r.Hide("invalid: " + in)
		for _, leak := range []string{"amy", "bob", "ops/", "example"} {
			if strings.Contains(strings.ToLower(got), leak) {
				t.Errorf("Hide(%q) = %q still shows %q", in, got, leak)
			}
		}
	}
	if checked != 7 {
		t.Fatalf("checked %d echoes, want 7", checked)
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

// echoLogin is a login of n bytes whose masked form is the same for every n: its first
// character, an ellipsis and the domain.
func echoLogin(n int) string {
	const domain = "@example.com"
	return "u" + strings.Repeat("x", n-1-len(domain)) + domain
}

// echoLengths are the lengths of the logins the tests below compare. The masked form of all of
// them is one string, so equal output means the length of a login did not show.
var echoLengths = []int{20, 60, 120, 250}

// assertOneMaskedForm fails the test unless every login of the lengths is masked to one string.
func assertOneMaskedForm(t *testing.T) string {
	t.Helper()
	want := sanitize.MaskIdentifier(echoLogin(echoLengths[0]))
	for _, n := range echoLengths {
		if got := sanitize.MaskIdentifier(echoLogin(n)); got != want || len(echoLogin(n)) != n {
			t.Fatalf("a login of %d bytes is masked to %q (length %d), want %q: the case compares nothing", n, got, len(echoLogin(n)), want)
		}
	}
	return want
}

// Two texts whose logins differ only in length give the same result: how much of a message
// Hide shows does not depend on how long the logins in it are. The text is a list of 400
// logins, as a server echoes the members it was sent, long enough that the masked form fills
// what a display shows for every length.
func TestHideShowsTheSameWhateverTheLengthOfTheLoginsInTheText(t *testing.T) {
	masked := assertOneMaskedForm(t)
	var first string
	for _, n := range echoLengths {
		login := echoLogin(n)
		r := resolvedAll(t, login)
		got := r.Hide("invalid members: [" + strings.Repeat(`"`+login+`", `, 400) + "]")
		if strings.Contains(got, "xxx") {
			t.Fatalf("a login of %d bytes shows in %.200q", n, got)
		}
		if shown := strings.Count(got, masked); shown < 40 {
			t.Errorf("a login of %d bytes shows %d masked addresses, want at least 40: the case must reach the cut", n, shown)
		}
		if len(got) <= registry.ResultStringMax {
			t.Errorf("a login of %d bytes gives %d bytes, so a display could not tell that it cut", n, len(got))
		}
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("logins of %d and %d bytes give different results:\n%.300q\n%.300q", echoLengths[0], n, first, got)
		}
	}
}

// The result of Hide ends at a character, never inside one: a multi-byte letter that the cut
// of the masked head falls in comes whole.
func TestHideEndsAtACharacterNotInsideOne(t *testing.T) {
	r := resolvedAll(t, "amy@example.com")
	for _, pad := range []string{"", "x"} {
		got := r.Hide(pad + strings.Repeat("é", 2000))
		if !utf8.ValidString(got) {
			t.Errorf("pad %q: the result ends inside a character: %q", pad, got[len(got)-4:])
		}
		if len(got) <= registry.ResultStringMax {
			t.Errorf("pad %q: %d bytes, so a display could not tell that the text was cut", pad, len(got))
		}
		if len(got) > registry.ResultStringMax+utf8.UTFMax {
			t.Errorf("pad %q: %d bytes, want the head a display needs and no more", pad, len(got))
		}
	}
}

// Hide reads as far as the masked form needs and no further, whatever the length of the text:
// a megabyte and four megabytes of addresses are read to the same place, a small multiple of
// what the display shows. A masked address stands for the whole login, so a long login takes
// more of the text to fill the display, and the read is bounded by that.
func TestHideReadsAsFarAsTheMaskedFormNeedsWhateverTheLengthOfTheText(t *testing.T) {
	assertOneMaskedForm(t)
	need := registry.ResultStringMax + 1
	for _, n := range []int{echoLengths[0], echoLengths[len(echoLengths)-1]} {
		login := echoLogin(n)
		r := resolvedAll(t, login)
		unit := login + " "
		maskedUnit := sanitize.MaskIdentifier(login) + " "
		// The masked head is need bytes, which is need/len(maskedUnit) units of len(unit)
		// bytes each; the read doubles from firstRead, so it is under twice that or firstRead.
		bound := 2*(need/len(maskedUnit)+1)*len(unit) + firstRead
		var reads []int
		for _, size := range []int{1 << 16, 1 << 20, 4 << 20} {
			text := strings.Repeat(unit, size/len(unit))
			got, read := r.HideRead(text)
			if len(got) < need || len(got) > need+utf8.UTFMax {
				t.Errorf("login of %d bytes, text of %d: result of %d bytes, want %d to %d", n, len(text), len(got), need, need+utf8.UTFMax)
			}
			if read > bound {
				t.Errorf("login of %d bytes, text of %d: read %d bytes, want at most %d", n, len(text), read, bound)
			}
			if size >= 1<<20 && read*32 > len(text) {
				t.Errorf("login of %d bytes, text of %d: read %d bytes, which is not far less than the text", n, len(text), read)
			}
			reads = append(reads, read)
		}
		if reads[1] != reads[2] {
			t.Errorf("login of %d bytes: a text of 1 MiB is read to %d and one of 4 MiB to %d, want the same", n, reads[1], reads[2])
		}
	}
}

// A text whose masked form stays short however far it is read (a long run of address bytes
// glued before each login, all masked with it) is read to a limit and no further: the work of
// Hide has an end that does not depend on the text. 64 resolved logins over such a megabyte
// took 1.2 s to read 512 KiB before the limit.
func TestHideStopsReadingATextThatMasksToAlmostNothing(t *testing.T) {
	logins := []string{"a@b.co"}
	for i := range 63 {
		logins = append(logins, fmt.Sprintf("user%02d@example.com", i))
	}
	r := resolvedAll(t, logins...)
	unit := strings.Repeat("a", 2900) + "a@b.co "
	text := strings.Repeat(unit, (1<<20)/len(unit)+1)[:1<<20]
	got, read := r.HideRead(text)
	if read > 65600 {
		t.Errorf("read %d bytes of a megabyte that masks to %d, want at most 65,600", read, len(got))
	}
	if len(got) == 0 || strings.Contains(got, "aaaaaaaaaa") || !strings.Contains(got, "a…@b.co") {
		t.Errorf("the result of the limited read is %.100q, want masked addresses and nothing of the run", got)
	}
}
