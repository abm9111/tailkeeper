package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func subjectEnv(t *testing.T, logins ...string) (*apitest.Fake, *registry.Env, *privacy.Key) {
	t.Helper()
	f := apitest.New(t)
	var users []map[string]string
	for i, l := range logins {
		users = append(users, map[string]string{"id": fmt.Sprintf("u%d", i+1), "loginName": l, "type": "member", "status": "active"})
	}
	body, err := json.Marshal(map[string]any{"users": users})
	if err != nil {
		t.Fatal(err)
	}
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", 200, string(body))
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env := &registry.Env{API: f.Client(t), Privacy: k}
	return f, env, k
}

func subjectCode(err error) tkerr.Code {
	if e, ok := tkerr.As(err); ok {
		return e.Code
	}
	return ""
}

func userGets(f *apitest.Fake) int {
	n := 0
	for _, r := range f.Requests() {
		if r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/users") {
			n++
		}
	}
	return n
}

func TestALiteralLoginInSrcOrADestinationIsRefusedWhileMasking(t *testing.T) {
	_, env, _ := subjectEnv(t, "alice@example.com")
	keylessEnv := &registry.Env{}
	shown := *env
	shown.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	cases := []struct {
		src  string
		dsts []string
	}{
		{src: "alice@example.com"},
		{dsts: []string{"alice@example.com:22"}},
		{src: `"alice@example.com"`},
		{dsts: []string{"alice@example.com:80-443"}},
		{dsts: []string{"tag:x:22 alice@example.com"}},
		{dsts: []string{"tag:prod:22,alice@example.com"}},
		{dsts: []string{"[p:abcdefghij]:22,alice@example.com"}},
		{dsts: []string{"p:abcdefghij:22 alice@example.com"}},
		{dsts: []string{"a…@example.com [p:abcdefghij]:22 alice@example.com"}},
		{src: "group:eng@example.com,alice@example.com"},
	}
	for _, c := range cases {
		err := screenTestSubjects(env, c.src, c.dsts)
		if subjectCode(err) != tkerr.FilterRefused || err == nil || !strings.Contains(err.Error(), "pseudonym") {
			t.Errorf("screen(%q, %q) = %v, want filter_refused with the pseudonym hint", c.src, c.dsts, err)
			continue
		}
		if strings.Contains(err.Error(), "alice@") {
			t.Errorf("the refusal repeats the login: %v", err)
		}
		kerr := screenTestSubjects(keylessEnv, c.src, c.dsts)
		if subjectCode(kerr) != tkerr.FilterRefused || kerr == nil || !strings.Contains(kerr.Error(), "privacy key") {
			t.Errorf("keyless screen(%q, %q) = %v, want the keyless hint", c.src, c.dsts, kerr)
		}
		if err := screenTestSubjects(&shown, c.src, c.dsts); err != nil {
			t.Errorf("personalData show screen(%q, %q) = %v", c.src, c.dsts, err)
		}
	}
	for _, src := range []string{"group:engineering@example.com", "group:finance team@example.com", "tag:web", "user:*@example.com"} {
		if err := screenTestSubjects(env, src, nil); err != nil {
			t.Errorf("screen(%q) = %v, want the subject allowed", src, err)
		}
	}
	if err := screenTestSubjects(env, "tag:x # alice@example.com", nil); subjectCode(err) != tkerr.FilterRefused {
		t.Errorf("a login after a hash: %v, want filter_refused", err)
	}
	bs := string(rune(92))
	err := screenTestSubjects(env, "tag:web", []string{"tskey" + bs + "u002dapi-x:22"})
	if subjectCode(err) != tkerr.ValidationFailed || err == nil || !strings.Contains(err.Error(), "shaped like a credential") || strings.Contains(err.Error(), "tskey") || strings.Contains(err.Error(), "u002d") {
		t.Errorf("destination credential: %v", err)
	}
}

// A credential-shaped string is refused whatever the masking mode: personal data shown
// means logins may be typed, not that a key may be sent to Tailscale in a source or a
// destination. The destination has no other credential check.
func TestACredentialShapeIsRefusedEvenWhenPersonalDataIsShown(t *testing.T) {
	_, env, _ := subjectEnv(t, "alice@example.com")
	shown := *env
	shown.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	bs := string(rune(92))
	for name, c := range map[string]struct {
		src  string
		dsts []string
	}{
		"a source":                     {src: "tskey-api-x"},
		"a source with an escape":      {src: "tskey" + bs + "u002dapi-x"},
		"a destination":                {src: "tag:web", dsts: []string{"tskey-api-x:22"}},
		"a destination with an escape": {src: "tag:web", dsts: []string{"tskey" + bs + "u002dapi-x:22"}},
		"the second destination":       {src: "tag:web", dsts: []string{"tag:db:22", "tskey-api-x:22"}},
	} {
		for label, e := range map[string]*registry.Env{"shown": &shown, "masked": env} {
			err := screenTestSubjects(e, c.src, c.dsts)
			if subjectCode(err) != tkerr.ValidationFailed || err == nil || !strings.Contains(err.Error(), "shaped like a credential") {
				t.Errorf("%s, personal data %s: %v, want validation_failed for a credential shape", name, label, err)
			}
			if err != nil && strings.Contains(err.Error(), "tskey") {
				t.Errorf("%s, personal data %s: the refusal repeats the key: %v", name, label, err)
			}
		}
	}
	// A login typed while personal data is shown still passes the screen.
	if err := screenTestSubjects(&shown, "alice@example.com", []string{"alice@example.com:22"}); err != nil {
		t.Errorf("a login while personal data is shown: %v", err)
	}
}

func TestResolveTestSubjectsSubstitutesOnlyTheCarrierAndKeepsTheShownForm(t *testing.T) {
	_, env, k := subjectEnv(t, "alice@example.com", "bob@example.org")
	alice, bob := k.APIPseudonym("alice@example.com"), k.APIPseudonym("bob@example.org")
	masked := "b…@example.org [" + bob + "]"
	got, err := resolveTestSubjects(context.Background(), NewSubjectResolver(env), "["+alice+"]", []string{masked, "tag:prod", "group:finance team@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Src != "alice@example.com" {
		t.Errorf("Src = %q", got.Src)
	}
	if got.Shown[got.Src] != "["+alice+"]" {
		t.Errorf("Shown[src] = %q, want the bracket carrier", got.Shown[got.Src])
	}
	if len(got.Dsts) != 3 || got.Dsts[0] != "bob@example.org" || got.Dsts[1] != "tag:prod" || got.Dsts[2] != "group:finance team@example.com" {
		t.Errorf("Dsts = %#v", got.Dsts)
	}
	if got.Shown[got.Dsts[0]] != masked {
		t.Errorf("Shown[dst] = %q, want the masked carrier", got.Shown[got.Dsts[0]])
	}
	if _, ok := got.Shown["tag:prod"]; ok {
		t.Error("a tag was recorded as substituted")
	}
}

func TestOneReadOfTheUsersServesManyCarriers(t *testing.T) {
	f, env, k := subjectEnv(t, "alice@example.com", "bob@example.org", "carol@example.com")
	refs := []string{k.APIPseudonym("alice@example.com"), k.APIPseudonym("bob@example.org"), k.APIPseudonym("carol@example.com")}
	before := userGets(f)
	got, err := resolveTestSubjects(context.Background(), NewSubjectResolver(env), refs[0], []string{refs[1], "[" + refs[2] + "]", "a…@example.com [" + refs[0] + "]"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Src != "alice@example.com" || got.Dsts[0] != "bob@example.org" || got.Dsts[1] != "carol@example.com" || got.Dsts[2] != "alice@example.com" {
		t.Errorf("resolved = %#v", got)
	}
	if n := userGets(f) - before; n != 1 {
		t.Errorf("%d GETs of /users, want 1", n)
	}
}

func TestAForcedCollisionAndAPseudonymFromAReplacedKeyAreValidationFailed(t *testing.T) {
	_, env, k := subjectEnv(t, "alice@example.com", "bob@example.org")
	collide := k.APIPseudonym("alice@example.com")
	r := NewSubjectResolver(env)
	r.SetPseudonymFunc(func(login string) string { return collide })
	for name, call := range map[string]struct {
		src  string
		dsts []string
	}{
		"source":      {src: collide},
		"destination": {src: "tag:web", dsts: []string{collide}},
	} {
		_, err := resolveTestSubjects(context.Background(), r, call.src, call.dsts)
		if subjectCode(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "more than one user") {
			t.Errorf("%s collision: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "alice@") || strings.Contains(err.Error(), collide)) {
			t.Errorf("%s collision repeats a name: %v", name, err)
		}
	}
	other, err := privacy.Parse(strings.Repeat("c3", 32))
	if err != nil {
		t.Fatal(err)
	}
	foreign := other.APIPseudonym("alice@example.com")
	fresh := NewSubjectResolver(env)
	for name, call := range map[string]struct {
		src  string
		dsts []string
	}{
		"source":      {src: foreign},
		"destination": {src: "tag:web", dsts: []string{foreign}},
	} {
		_, err := resolveTestSubjects(context.Background(), fresh, call.src, call.dsts)
		if subjectCode(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "no user has that pseudonym") {
			t.Errorf("%s replaced key: %v", name, err)
		}
	}
}

func TestAStringThatHoldsAMarkerButIsNoCarrierIsRefused(t *testing.T) {
	f, env, k := subjectEnv(t, "alice@example.com")
	marker := k.APIPseudonym("alice@example.com")
	host, port, err := splitDestination("tag:x [" + marker + "]:22")
	if err != nil || port != "22" || host != "tag:x ["+marker+"]" {
		t.Fatalf("split = %q, %q, %v", host, port, err)
	}
	before := userGets(f)
	_, err = resolveTestSubjects(context.Background(), NewSubjectResolver(env), "tag:web", []string{host})
	if subjectCode(err) != tkerr.ValidationFailed || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "alice@") {
		t.Errorf("destination: %v", err)
	}
	_, err = resolveTestSubjects(context.Background(), NewSubjectResolver(env), host, nil)
	if subjectCode(err) != tkerr.ValidationFailed {
		t.Errorf("source: %v", err)
	}
	if userGets(f) != before {
		t.Errorf("a refused marker still read the users list")
	}
}

func TestEachPseudonymShapeIsTiedToThePrivacyPackage(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	p := k.APIPseudonym("amy@example.com")
	ref, ok := privacy.Ref(p)
	if !ok || ref != p || !bareCarrierRE.MatchString(p) {
		t.Fatalf("bare %q is not the shape privacy.Ref and bareCarrierRE share", p)
	}
	if m := bracketCarrierRE.FindStringSubmatch("[" + p + "]"); m == nil || m[1] != p {
		t.Fatalf("bracket form of %q", p)
	}
	masked := "a…@example.com [" + p + "]"
	if m := maskedCarrierRE.FindStringSubmatch(masked); m == nil || m[1] != p {
		t.Fatalf("masked form of %q", p)
	}
	if !markerRE.MatchString("["+p+"]") || markerRE.MatchString(p) {
		t.Fatalf("markerRE on %q", p)
	}
	if _, ok := privacy.Ref("p:short"); ok || bareCarrierRE.MatchString("p:short") {
		t.Fatal("a short token matched")
	}
}
