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

func TestHideMasksABareLocalPart(t *testing.T) {
	r := resolvedAll(t, "amy@example.com", "AmyLongerName@example.com")
	got := r.Hide("no such user: amy; no such user: AMY; no such user: AmyLongerName")
	if strings.Contains(strings.ToLower(got), "amy") || strings.Contains(got, "Longer") {
		t.Fatalf("a bare local part was shown: %q", got)
	}
	if strings.Count(got, "a…") < 2 {
		t.Fatalf("the two local parts did not mask to one form: %q", got)
	}
}

// A bare local part is masked at every place it stands alone, however close the places are:
// one separator between two of them, a part at the start or at the end of the text, beside
// punctuation. The boundary around one occurrence is not consumed by the next.
func TestHideMasksEveryOccurrenceOfARepeatedBareLocalPart(t *testing.T) {
	r := resolvedAll(t, "amy@example.com")
	for in, want := range map[string]string{
		"amy amy":              "a… a…",
		"amy:amy":              "a…:a…",
		"no user amy/amy":      "no user a…/a…",
		"amy,amy,amy":          "a…,a…,a…",
		"amy amy amy amy amy":  "a… a… a… a… a…",
		"AMY Amy aMy":          "a… a… a…",
		"amy":                  "a…",
		"amy is unknown":       "a… is unknown",
		"unknown user amy":     "unknown user a…",
		"amy: not amy":         "a…: not a…",
		"(amy)":                "(a…)",
		"[amy].amy.":           "[a…].a….",
		`"amy" 'amy' amy;amy`:  `"a…" 'a…' a…;a…`,
		"amy\namy\tamy":        "a…\na…\ta…",
		"amy-amy":              "a…-a…",
		"amy=amy&amy=amy":      "a…=a…&a…=a…",
		"bigamy amy amyx":      "bigamy a… amyx",
		"amy_x amy x_amy amy2": "amy_x a… x_amy amy2",
	} {
		if got := r.Hide(in); got != want {
			t.Errorf("Hide(%q) = %q, want %q", in, got, want)
		}
	}
}

// A bare local part masks to one form whatever bytes it holds: hyphens, dots, plus signs,
// digits and underscores do not leave a piece of it showing or a trace of its length.
func TestHideMasksABareLocalPartToOneFormWhateverItHolds(t *testing.T) {
	for _, local := range []string{"amy", "amy-zzzzqqqqmuchlongerlocalpart", "amy.smith", "amy+tag", "amy123", "amy_x", "amy-z.q+9_k", "Amy-Zed"} {
		r := resolvedAll(t, local+"@example.com")
		for _, c := range []struct{ in, want string }{
			{local, "a…"},
			{"no such user: " + local, "no such user: a…"},
			{"user=" + local + ";", "user=a…;"},
			{"(" + local + ")", "(a…)"},
			{local + " " + local, "a… a…"},
			{strings.ToUpper(local), "a…"},
			{"x " + local + "-" + local, "x a…-a…"},
		} {
			if got := r.Hide(c.in); got != c.want {
				t.Errorf("local part %q: Hide(%q) = %q, want %q", local, c.in, got, c.want)
			}
		}
	}
}

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

// A login that holds a multi-byte character is dropped whole when the cut falls inside
// that character or inside the login. Nothing of the login, and no split byte, remains.
func TestCutForHideKeepsAMultibyteLoginWhole(t *testing.T) {
	const login = "amé@example.com"
	r := resolvedAll(t, login)
	prefix := "preface "
	text := prefix + login + " tail"
	at := strings.Index(text, "é")
	if at < 0 {
		t.Fatal("the fixture lost its character")
	}
	for _, limit := range []int{at + 1, at + len("é@exa")} {
		got := r.CutAt(text, limit)
		if !utf8.ValidString(got) || strings.Contains(got, "amé") || strings.Contains(got, "@example.com") || strings.Contains(got, "é") {
			t.Errorf("CutAt(%d) = %q, want only the preface", limit, got)
		}
		if got != prefix {
			t.Errorf("CutAt(%d) = %q, want %q", limit, got, prefix)
		}
	}
}

// The three places the cut keeps a character whole, each shown by a text that the other two
// do not mend. A login with a slash in front of its multi-byte character: the address bytes
// before the cut would otherwise stop at the slash and leave it showing.
func TestACutInsideAMultibyteCharacterOfALoginWithASlashDropsTheWholeLogin(t *testing.T) {
	const login = "ops/amé@example.com"
	r := resolvedAll(t, login)
	prefix := "preface "
	text := prefix + login + " tail"
	at := strings.Index(text, "é")
	for _, limit := range []int{at + 1, at + len("é@exa")} {
		if got := r.CutAt(text, limit); got != prefix {
			t.Errorf("CutAt(%d) = %q, want %q", limit, got, prefix)
		}
	}
}

// A run of address bytes longer than the longest address is not walked back whole, and the
// byte it stops at can be the second of a character: the cut then steps back to the
// character's first byte and never leaves half of one.
func TestACutAfterALongRunOfAddressBytesNeverLeavesHalfACharacter(t *testing.T) {
	r := resolvedAll(t, "amy@example.com")
	text := strings.Repeat("é", 1500) + "z" + " tail"
	got := r.CutAt(text, 2*1500+1)
	if !utf8.ValidString(got) || got != strings.Repeat("é", 540) {
		t.Errorf("CutAt = %d bytes, valid %t, want 540 characters", len(got), utf8.ValidString(got))
	}
}

// A login whose first character is the replacement character reads the continuation byte
// of any character as its start. The search for the start of a login goes by whole
// characters, so a text that ends in an ordinary character is not taken as ending in a login.
func TestTheStartOfALoginIsSoughtByWholeCharacters(t *testing.T) {
	r := resolvedAll(t, string(rune(0xFFFD))+"@example.com")
	text := "x" + strings.Repeat("é", 1500) + " tail"
	got := r.CutAt(text, 1+2*1500)
	if !utf8.ValidString(got) || got != "x"+strings.Repeat("é", 540) {
		t.Errorf("CutAt = %d bytes, valid %t, want 1081 bytes of whole characters", len(got), utf8.ValidString(got))
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

// A word the caller typed is shown as it is, whether or not it is a word of a login the call
// resolved: a reply that masked it only when it was one would answer each guess. A word that
// Tailscale adds is still masked.
func TestHideLeavesAWordTheCallerTypedAsItIsAndMasksTheOnesTailscaleAdds(t *testing.T) {
	for _, typed := range []string{"amy", "ops", "bob", "zed", "ops/amy", "AMY"} {
		r := resolvedAll(t, "ops/amy@example.com", "bob@example.org")
		r.Typed(typed + ":22")
		quoted := `address "` + typed + `:22" (protocol "tcp"): want: Drop, got: Accept`
		if got := r.Hide(quoted); got != quoted {
			t.Errorf("a word typed as %q was masked: %q", typed, got)
		}
	}
	r := resolvedAll(t, "ops/amy@example.com")
	r.Typed("zed:22")
	if got := r.Hide(`address "zed:22": no such user: amy`); got != `address "zed:22": no such user: a…` {
		t.Errorf("a word Tailscale added was shown or a typed one changed: %q", got)
	}
	// What is typed as part of a longer word does not make the shorter word typed.
	r = resolvedAll(t, "amy@example.com")
	r.Typed("amyx:22")
	if got := r.Hide("no such user: amy; amyx"); got != "no such user: a…; amyx" {
		t.Errorf("a word that is only part of a typed one was left alone: %q", got)
	}
}

// A local part of several words is typed whole or in part: neither the span nor a word of it
// is masked in the text that holds it, and a word that was not typed still is.
func TestHideLeavesAWholeLocalPartTheCallerTypedAsItIs(t *testing.T) {
	r := resolvedAll(t, "amy-smith@example.com")
	r.Typed("amy-smith:22")
	for _, in := range []string{`"amy-smith:22"`, `amy-smith-jones:22`, `smith:22`, `amy:22`} {
		if got := r.Hide(in); got != in {
			t.Errorf("Hide(%q) = %q: a span the caller typed was masked", in, got)
		}
	}
	r = resolvedAll(t, "amy-smith@example.com")
	r.Typed("amy:22")
	for in, want := range map[string]string{`amy:22`: `amy:22`, `smith:22`: `s…:22`, `amy-smith:22`: `a…:22`} {
		if got := r.Hide(in); got != want {
			t.Errorf("Hide(%q) = %q, want %q", in, got, want)
		}
	}
}

// What the call resolved cannot show through the way a typed text reads: for every text the
// caller typed, the reply reads the same whichever login the call resolved. The login with a
// slash is the one the plain address scan reads differently from the resolved pattern.
func TestHideReadsATypedTextTheSameWhicheverLoginTheCallResolved(t *testing.T) {
	typed := []string{"ops/amy@example.com", "ops/zed@example.com", "amy", "ops", "bob@example.org", "amy:22", "ops/amy", "bigamy@example.com"}
	for _, text := range typed {
		var shown []string
		for _, resolved := range []string{"ops/amy@example.com", "bob@example.org", "carol@example.net"} {
			r := resolvedAll(t, resolved)
			r.Typed(text)
			shown = append(shown, r.Hide(`ssh user "`+text+`" is unknown for `+text+`:22`))
		}
		if shown[0] != shown[1] || shown[1] != shown[2] {
			t.Errorf("the reply to a typed %q depends on the login the call resolved:\n%q\n%q\n%q", text, shown[0], shown[1], shown[2])
		}
	}
}

func TestATypedSetOfNothingChangesNothing(t *testing.T) {
	r := resolvedAll(t, "amy@example.com")
	r.Typed()
	r.Typed("")
	if got := r.Hide("no such user: amy"); got != "no such user: a…" {
		t.Errorf("Hide = %q", got)
	}
}

// A typed text whose first occurrence of a word is inside a longer word is searched on: the
// word stands alone further along. What the caller was told twice is held twice.
func TestHideSearchesATypedTextForALaterOccurrenceAndKeepsEveryTelling(t *testing.T) {
	r := resolvedAll(t, "amy@example.com", "bob@example.org")
	r.Typed("xamy amy:22")
	if got := r.Hide(`address "amy:22"`); got != `address "amy:22"` {
		t.Errorf("a word that stands alone later in a typed text was masked: %q", got)
	}
	r.Typed("bob:22")
	r.Typed("")
	for _, in := range []string{`"amy:22"`, `"bob:22"`} {
		if got := r.Hide(in); got != in {
			t.Errorf("Hide(%s) = %q: an earlier telling was forgotten", in, got)
		}
	}
}
