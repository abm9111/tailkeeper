package tools_test

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// usersBody is the users list the API would send for these logins; the last is suspended.
func usersBody(t *testing.T, logins ...string) string {
	t.Helper()
	var users []map[string]string
	for i, l := range logins {
		status := "active"
		if i == len(logins)-1 && len(logins) > 2 {
			status = "suspended"
		}
		users = append(users, map[string]string{"id": fmt.Sprintf("u%d", i+1), "loginName": l, "type": "member", "status": status})
	}
	b, err := json.Marshal(map[string]any{"users": users})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// usersRequests counts the GETs of the users list the fake saw.
func usersRequests(f *apitest.Fake) int {
	n := 0
	for _, r := range f.Requests() {
		if r.Method == http.MethodGet && r.Path == "/api/v2/tailnet/"+apitest.Tailnet+"/users" {
			n++
		}
	}
	return n
}

// shownRef reads the pseudonym a tool shows for the login of the user with the given ID.
func shownRef(t *testing.T, reg *registry.Registry, env *registry.Env, id string) string {
	t.Helper()
	var out struct {
		Users []struct {
			ID        string `json:"id"`
			LoginName string `json:"loginName"`
		} `json:"users"`
	}
	mustCall(t, reg, env, "users_list", `{}`, &out)
	for _, u := range out.Users {
		if u.ID == id {
			ref, ok := privacy.Ref(u.LoginName)
			if !ok {
				t.Fatalf("users_list shows %q, want a masked value with a pseudonym", u.LoginName)
			}
			return ref
		}
	}
	t.Fatalf("users_list does not list %s", id)
	return ""
}

func TestResolverFindsTheUserAPseudonymFromUsersListNames(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com", "carol@example.org"))
	kenv, _ := keyed(t, env)
	shown := map[string]string{"u1": "amy@example.com", "u2": "bob@example.com", "u3": "carol@example.org"}
	for id, login := range shown {
		ref := shownRef(t, reg, kenv, id)
		for _, form := range []string{ref, "[" + ref + "]", "x…@example.com [" + ref + "]"} {
			got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), form)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", form, err)
			}
			if got.Reveal() != login {
				t.Errorf("Resolve(%q) names the wrong user", form)
			}
		}
	}
}

func TestResolverReadsUsersWithOneRequestPerCallAndKeepsNothingBetweenCalls(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com"))
	kenv, _ := keyed(t, env)
	amy, bob := shownRef(t, reg, kenv, "u1"), shownRef(t, reg, kenv, "u2")
	before := usersRequests(f)
	r := tools.NewSubjectResolver(kenv)
	for _, ref := range []string{amy, bob, amy} {
		if _, err := r.Resolve(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	if got := usersRequests(f) - before; got != 1 {
		t.Errorf("one resolver made %d requests for the users, want 1", got)
	}
	var q string
	for _, req := range f.Requests() {
		if req.Path == "/api/v2/tailnet/"+apitest.Tailnet+"/users" {
			q = req.Query.Encode()
		}
	}
	if q != "role=all&type=all" {
		t.Errorf("the users request carried %q, want role=all&type=all (members, shared and suspended users)", q)
	}
	// A second call builds a second resolver, and it reads the users again: nothing is held.
	before = usersRequests(f)
	if _, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), amy); err != nil {
		t.Fatal(err)
	}
	if got := usersRequests(f) - before; got != 1 {
		t.Errorf("a new resolver made %d requests, want 1", got)
	}
}

// The pseudonym users_list shows names the login the API returned, not the text it would decode
// to: a user whose login spells an escape is that user, and amy@example.com is another.
func TestResolverNamesAPILoginsWithoutDecodingEscapes(t *testing.T) {
	bs := string(rune(92))
	spelled := "am" + bs + "u0079@example.com"
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, spelled, "bob@example.org"))
	kenv, _ := keyed(t, env)
	got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), shownRef(t, reg, kenv, "u1"))
	if err != nil {
		t.Fatalf("the spelled login did not resolve from the pseudonym users_list shows: %v", err)
	}
	if got.Reveal() != spelled {
		t.Errorf("Resolve returned %q, want exactly the spelled login %q", got.Reveal(), spelled)
	}
	// With amy@example.com listed too, each pseudonym is exactly one match and names its own user.
	f, reg, env = apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, spelled, "bob@example.org", "amy@example.com"))
	kenv, _ = keyed(t, env)
	checked := 0
	for id, want := range map[string]string{"u1": spelled, "u3": "amy@example.com"} {
		checked++
		got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), shownRef(t, reg, kenv, id))
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if got.Reveal() != want {
			t.Errorf("%s resolved to %q, want %q", id, got.Reveal(), want)
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d users, want 2", checked)
	}
}

func TestResolverFindsASuspendedUserAndNotAnAbsentOne(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com", "gone-soon@example.com"))
	kenv, k := keyed(t, env)
	suspended := shownRef(t, reg, kenv, "u3")
	if got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), suspended); err != nil || got.Reveal() != "gone-soon@example.com" {
		t.Errorf("a suspended user did not resolve: %v", err)
	}
	// A user the list does not hold, a departed one, is no match.
	_, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym("departed@example.com"))
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "no user has that pseudonym") {
		t.Errorf("a departed user: %v, want validation_failed: no user has that pseudonym", err)
	}
}

func TestResolverRefusesAPseudonymFromAReplacedKey(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com"))
	oldEnv, _ := keyed(t, env)
	remembered := shownRef(t, reg, oldEnv, "u1")
	newKey, err := privacy.Parse(strings.Repeat("c3", 32))
	if err != nil {
		t.Fatal(err)
	}
	replaced := *env
	replaced.Privacy = newKey
	_, err = tools.NewSubjectResolver(&replaced).Resolve(context.Background(), remembered)
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "privacy key was replaced") {
		t.Errorf("a pseudonym from a replaced key: %v, want validation_failed naming the key", err)
	}
	if strings.Contains(err.Error(), remembered) {
		t.Errorf("the error repeats the pseudonym it was given: %v", err)
	}
}

func TestResolverRefusesSeveralUsersWithOnePseudonym(t *testing.T) {
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com", "carol@example.org"))
	kenv, k := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	collide := k.APIPseudonym("amy@example.com")
	r.SetPseudonymFunc(func(login string) string {
		if login == "amy@example.com" || login == "bob@example.com" {
			return collide // a forced collision: two users, one pseudonym
		}
		return k.APIPseudonym(login)
	})
	_, err := r.Resolve(context.Background(), collide)
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "more than one user") {
		t.Errorf("a collision: %v, want validation_failed: more than one user", err)
	}
	for _, login := range []string{"amy@example.com", "bob@example.com"} {
		if strings.Contains(err.Error(), login) {
			t.Errorf("the error names %s", login)
		}
	}
	// The user who does not collide still resolves, from the users already read.
	if got, err := r.Resolve(context.Background(), k.APIPseudonym("carol@example.org")); err != nil || got.Reveal() != "carol@example.org" {
		t.Errorf("the user who does not collide: %v", err)
	}
}

func TestResolverDedupsOnlyAnExactRepeat(t *testing.T) {
	// The same row listed twice is one user.
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "amy@example.com"))
	kenv, k := keyed(t, env)
	if got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym("amy@example.com")); err != nil || got.Reveal() != "amy@example.com" {
		t.Errorf("one login listed twice: %v", err)
	}
	// Two logins that differ only in case are two users, and an address is folded, so they share a pseudonym.
	f, _, env = apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "AMY@example.com"))
	kenv, k = keyed(t, env)
	_, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym("amy@example.com"))
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "more than one user") {
		t.Errorf("two addresses that differ in case: %v, want validation_failed: more than one user", err)
	} else if strings.Contains(strings.ToLower(err.Error()), "amy") {
		t.Errorf("the error names a spelling: %v", err)
	}
	// Two logins with no at sign that differ in case have different pseudonyms: each resolves to itself.
	f, _, env = apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "Alice", "alice"))
	kenv, k = keyed(t, env)
	for _, login := range []string{"Alice", "alice"} {
		if got, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym(login)); err != nil || got.Reveal() != login {
			t.Errorf("Resolve(APIPseudonym(%q)): %v", login, err)
		}
	}
}

func TestResolverRemembersAFailedUsersCall(t *testing.T) {
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 403, `{"message":"not allowed"}`)
	kenv, k := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	for i := 0; i < 3; i++ {
		_, err := r.Resolve(context.Background(), k.APIPseudonym("amy@example.com"))
		if code(err) != tkerr.ScopeMissing {
			t.Errorf("call %d: %v, want scope_missing", i+1, err)
		}
	}
	if n := usersRequests(f); n != 1 {
		t.Errorf("a failed users call was made %d times in one call, want 1", n)
	}
}

func TestResolverNeedsAKeyAndAPseudonym(t *testing.T) {
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com"))
	_, err := tools.NewSubjectResolver(env).Resolve(context.Background(), "p:abcdefghij")
	if code(err) != tkerr.PrivacyKeyUnavailable {
		t.Errorf("no key: %v, want privacy_key_unavailable", err)
	}
	kenv, _ := keyed(t, env)
	for _, typed := range []string{"amy@example.com", "a…@example.com", "", "p:short", "tag:prod", "P:ABCDEFGHIJ"} {
		_, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), typed)
		if code(err) != tkerr.ValidationFailed {
			t.Errorf("Resolve(%q): %v, want validation_failed", typed, err)
		}
		if typed != "" && strings.Contains(err.Error(), typed) {
			t.Errorf("the error repeats what was typed, %q: %v", typed, err)
		}
		if typed == "P:ABCDEFGHIJ" {
			if e, ok := tkerr.As(err); !ok || !strings.Contains(e.Hint, "lower-case") {
				t.Errorf("the hint for %q does not say the shape of a pseudonym: %v", typed, err)
			}
		}
	}
	if n := usersRequests(f); n != 0 {
		t.Errorf("%d requests for the users before a pseudonym was given, want 0", n)
	}
}

func TestResolverMapsAMissingUsersScopeToAClearError(t *testing.T) {
	for _, status := range []int{403, 404} {
		f, _, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/users", status, `{"message":"not allowed"}`)
		kenv, k := keyed(t, env)
		_, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym("amy@example.com"))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.ScopeMissing || !strings.Contains(e.Message, "users:read") {
			t.Errorf("HTTP %d: %v, want scope_missing naming users:read", status, err)
		}
	}
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 401, `{"message":"unauthorized"}`)
	kenv, k := keyed(t, env)
	if _, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), k.APIPseudonym("amy@example.com")); code(err) != tkerr.TokenRejected {
		t.Errorf("HTTP 401: %v, want the client's token_rejected, unchanged", err)
	}
}

func TestALoginPrintsAndEncodesAsAPlaceholder(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.com"))
	kenv, _ := keyed(t, env)
	login, err := tools.NewSubjectResolver(kenv).Resolve(context.Background(), shownRef(t, reg, kenv, "u1"))
	if err != nil {
		t.Fatal(err)
	}
	type holder struct {
		L tools.Login
		P *tools.Login
	}
	type hidden struct{ l tools.Login }
	b, _ := json.Marshal(map[string]any{"direct": login, "pointer": &login, "struct": holder{login, &login}, "list": []tools.Login{login}})
	text := string(b)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%c", "%e", "%T", "%p"} {
		for name, v := range map[string]any{"value": login, "pointer": &login, "struct": holder{login, &login}, "hidden": hidden{login}, "slice": []tools.Login{login}, "map": map[string]tools.Login{"k": login}} {
			text += "\n" + fmt.Sprintf(verb, v)
			_ = name
		}
	}
	text += "\n" + fmt.Sprint(login) + fmt.Sprintln(login) + login.String()
	// What it prints and encodes is the placeholder itself, not only something that is not the
	// login. The value goes through an interface so that go vet cannot judge the verbs.
	var v any = login
	checked := 0
	for name, got := range map[string]string{
		"%v": fmt.Sprintf("%v", v), "%d": fmt.Sprintf("%d", v), "%x": fmt.Sprintf("%x", v),
		"Sprint": fmt.Sprint(v), "String": login.String(),
	} {
		checked++
		if got != "[login]" {
			t.Errorf("%s of a login = %q, want [login]", name, got)
		}
	}
	if j, err := json.Marshal(login); err != nil || string(j) != `"[login]"` {
		t.Errorf("json.Marshal(login) = %q, %v, want \"[login]\"", j, err)
	}
	// json.Marshal would fall back on MarshalText, and a method that is gone would not show in a
	// call that names it, so each encoder is asked for by its interface.
	if m, ok := v.(json.Marshaler); !ok {
		t.Error("a Login does not implement json.Marshaler")
	} else if j, err := m.MarshalJSON(); err != nil || string(j) != `"[login]"` {
		t.Errorf("MarshalJSON = %q, %v, want \"[login]\"", j, err)
	}
	if m, ok := v.(encoding.TextMarshaler); !ok {
		t.Error("a Login does not implement encoding.TextMarshaler")
	} else if tx, err := m.MarshalText(); err != nil || string(tx) != "[login]" {
		t.Errorf("MarshalText = %q, %v, want [login]", tx, err)
	}
	if checked != 5 {
		t.Fatalf("checked %d prints, want 5", checked)
	}
	for _, secret := range []string{"amy", "example.com", "616d79", "6d79"} {
		if strings.Contains(strings.ToLower(text), secret) {
			t.Errorf("a login printed or encoded something of itself (%q):\n%s", secret, text)
		}
	}
	if login.Reveal() != "amy@example.com" {
		t.Error("Reveal must return the login: it is how the request is built")
	}
	if (tools.Login{}).Reveal() != "" {
		t.Error("the zero Login reveals nothing")
	}
}

// A resolver holds every login of the tailnet once it has resolved one. No fmt verb prints
// them, whether the resolver is printed itself or sits in a field of a struct, a slice or a pointer.
func TestASubjectResolverPrintsNoLogin(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	r := tools.NewSubjectResolver(kenv)
	if _, err := r.Resolve(context.Background(), shownRef(t, reg, kenv, "u1")); err != nil {
		t.Fatal(err)
	}
	subjects := []struct {
		name string
		v    any
	}{
		{"pointer", r},
		{"value", *r},
		{"exported pointer field", struct{ R *tools.SubjectResolver }{r}},
		{"unexported pointer field", struct{ r *tools.SubjectResolver }{r}},
		{"unexported value field", struct{ r tools.SubjectResolver }{*r}},
		{"slice of pointers", []*tools.SubjectResolver{r}},
	}
	checked := 0
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
		for _, s := range subjects {
			t.Run(verb+" "+s.name, func(t *testing.T) {
				checked++
				got := strings.ToLower(fmt.Sprintf(verb, s.v))
				for _, secret := range []string{"amy", "bob", "example.com", "example.org", "616d79", "626f62"} {
					if strings.Contains(got, secret) {
						t.Errorf("%s of a %s printed %q:\n%s", verb, s.name, secret, got)
					}
				}
			})
		}
	}
	if checked != 42 {
		t.Fatalf("checked %d prints, want 42", checked)
	}
	if got := fmt.Sprintf("%v", r); got != "subject resolver" {
		t.Errorf("a resolver printed %q, want %q", got, "subject resolver")
	}
}

// A resolver that NewSubjectResolver did not build has no state: it must refuse or answer, not panic.
func TestAZeroSubjectResolverDoesNotPanic(t *testing.T) {
	_, _, env := apiEnv(t)
	_, key := keyed(t, env)
	ref := key.APIPseudonym("nobody@example.net")
	// A keyless environment: Resolve returns its error.
	if _, err := tools.ZeroSubjectResolver(env).Resolve(context.Background(), ref); err == nil {
		t.Error("a zero resolver over a keyless environment resolved a pseudonym")
	} else if e, ok := tkerr.As(err); !ok || e.Code != tkerr.PrivacyKeyUnavailable {
		t.Errorf("a zero resolver over a keyless environment returned %v, want the privacy_key_unavailable error", err)
	}
	// A keyed environment: the users are read, and a pseudonym that no one has is refused.
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	z := tools.ZeroSubjectResolver(kenv)
	if _, err := z.Resolve(context.Background(), ref); err == nil {
		t.Error("a zero resolver resolved a pseudonym that no user has")
	}
	got, err := z.Resolve(context.Background(), shownRef(t, reg, kenv, "u1"))
	if err != nil || got.Reveal() != "amy@example.com" {
		t.Errorf("a zero resolver resolved to %q, %v, want amy@example.com", got.Reveal(), err)
	}
	// Hide on a resolver that resolved nothing masks the text as a fresh one does.
	const text = "bob@example.org wrote to amy@example.com"
	fresh := tools.ZeroSubjectResolver(kenv).Hide(text)
	if want := tools.NewSubjectResolver(kenv).Hide(text); fresh != want {
		t.Errorf("Hide on a zero resolver = %q, want %q", fresh, want)
	}
	if strings.Contains(fresh, "bob@example.org") || strings.Contains(fresh, "amy@example.com") {
		t.Errorf("Hide on a zero resolver left an address showing: %q", fresh)
	}
	if he := tools.ZeroSubjectResolver(kenv).HideError(tkerr.New(tkerr.ValidationFailed, text, text)); he == nil {
		t.Error("HideError on a zero resolver returned nil")
	}
}
