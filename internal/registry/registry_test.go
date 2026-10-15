package registry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

type echoIn struct {
	Name  string `json:"name" jsonschema:"a name"`
	Count int    `json:"count,omitempty"`
}

type echoOut struct {
	Name  string `json:"name" tk:"untrusted"`
	Count int    `json:"count"`
}

func echoTool(m Meta) Tool {
	return Define(m, func(_ context.Context, _ *Env, in echoIn) (echoOut, error) {
		return echoOut(in), nil
	})
}

func readMeta(name, area, verb string) Meta {
	return Meta{Name: name, Area: area, Verb: verb, Summary: "echo", Tier: TierRead, Stage: StageGA,
		Credential: CredRead, Scopes: []string{"devices:core:read"}}
}

func TestCallValidatesAndSanitizes(t *testing.T) {
	tool := echoTool(readMeta("echo_get", "echo", "get"))
	out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"a`+"\\n"+`b","count":2}`))
	if err != nil {
		t.Fatal(err)
	}
	got := out.(echoOut)
	if got.Name != `a\u{000A}b` || got.Count != 2 {
		t.Fatalf("out = %+v", got)
	}
	if strings.Join(tool.UntrustedFields, ",") != "name" {
		t.Fatalf("UntrustedFields = %v", tool.UntrustedFields)
	}
}

type personOut struct {
	Login  string `json:"login" tk:"untrusted,personal"`
	Health string `json:"health" tk:"untrusted"`
}

// Personal data is masked unless the owner set "personalData": "show", and
// before the untrusted-text cap, which would leave a cut address unparsed with
// more of it showing than its network.
func TestPersonalDataIsMaskedUnlessShown(t *testing.T) {
	// Place the address so that the cap keeps its first 13 bytes, "2001:db8:1:2:"
	// when it is cut first.
	visible := strings.Count(sanitize.String(strings.Repeat("x", 2*sanitize.DefaultMax), sanitize.DefaultMax), "x")
	health := strings.Repeat("x", visible-14) + " 2001:db8:1:2:3:4:5:6 is past the cap"
	tool := Define(readMeta("echo_person", "echo", "person"), func(context.Context, *Env, echoIn) (personOut, error) {
		return personOut{Login: "amy@example.com", Health: health}, nil
	})
	if strings.Join(tool.PersonalFields, ",") != "login" {
		t.Errorf("PersonalFields = %v", tool.PersonalFields)
	}
	for _, c := range []struct {
		env    *Env
		masked bool
	}{
		{&Env{}, true},
		{&Env{Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataMask}}}, true},
		{&Env{Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}}, false},
	} {
		out, err := tool.Call(context.Background(), c.env, json.RawMessage(`{"name":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		got := out.(personOut)
		if c.masked && (got.Login != "a…@example.com" || strings.Contains(got.Health, "2001:db8:1:2") || !strings.Contains(got.Health, " 2001:db8:1::")) {
			t.Errorf("masked: %q, %q", got.Login, got.Health[len(got.Health)-40:])
		}
		if !c.masked && (got.Login != "amy@example.com" || !strings.Contains(got.Health, "2001:db8:1:2")) {
			t.Errorf("shown: %q, %q", got.Login, got.Health[len(got.Health)-40:])
		}
	}
}

// Errors quote the API and the local CLI: they are masked like free text.
func TestErrorsAreMaskedUnlessShown(t *testing.T) {
	tool := Define(readMeta("echo_err", "echo", "err"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, "cannot list users for amy@example.com from 203.0.113.9", "ask amy@example.com")
	})
	for _, c := range []struct {
		env  *Env
		want string
	}{
		{nil, "cannot list users for a…@example.com from 203.0.113.0/24"},
		{&Env{}, "cannot list users for a…@example.com from 203.0.113.0/24"},
		{&Env{Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}}, "cannot list users for amy@example.com from 203.0.113.9"},
	} {
		_, err := tool.Call(context.Background(), c.env, json.RawMessage(`{"name":"x"}`))
		if e := tkerr.From(err); e == nil || e.Message != c.want || (c.env == nil && e.Hint != "ask a…@example.com") {
			t.Errorf("env %v: err = %v (hint %q), want %q", c.env, err, e.Hint, c.want)
		}
	}
}

func TestCallRejectsBadArguments(t *testing.T) {
	tool := echoTool(readMeta("echo_get", "echo", "get"))
	for _, raw := range []string{`{"count":1}`, `{"name":"x","extra":1}`, `{"name":5}`, `[1]`, `not json`} {
		_, err := tool.Call(context.Background(), &Env{}, json.RawMessage(raw))
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", raw, err)
		}
	}
}

func TestCallRecoversFromAPanickingTool(t *testing.T) {
	tool := Define(readMeta("echo_boom", "echo", "boom"), func(context.Context, *Env, echoIn) (echoOut, error) {
		panic("panic-payload-must-not-surface")
	})
	out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); out != nil || !ok || e.Code != tkerr.Internal || strings.Contains(err.Error(), "panic-payload") {
		t.Fatalf("out = %v, err = %v", out, err)
	}
}

func TestCallSurvivesATypedNilError(t *testing.T) {
	tool := Define(readMeta("echo_nil", "echo", "nil"), func(context.Context, *Env, echoIn) (echoOut, error) {
		var e *tkerr.Error
		return echoOut{}, e
	})
	out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); out != nil || !ok || e == nil || e.Code != tkerr.Internal {
		t.Fatalf("out = %v, err = %v", out, err)
	}
}

// rawOut has a field the registry does not treat as tailnet text.
type rawOut struct {
	Name string `json:"name" tk:"untrusted"`
	Raw  string `json:"raw"`
}

func TestTripwireWithholdsResultsAndErrors(t *testing.T) {
	// Assembled at run time so that no credential shape sits in the source.
	key := "tskey" + "-api-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	result := Define(readMeta("echo_leak", "echo", "leak"), func(context.Context, *Env, echoIn) (rawOut, error) {
		return rawOut{Raw: "x " + key}, nil
	})
	failure := Define(readMeta("echo_fail", "echo", "fail"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, "upstream said "+key, "")
	})
	hinted := Define(readMeta("echo_hint", "echo", "hint"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, "upstream failed", "retry with "+key)
	})
	for _, tool := range []Tool{result, failure, hinted} {
		out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
		if e, ok := tkerr.As(err); out != nil || !ok || e.Code != tkerr.OutputWithheld || strings.Contains(err.Error(), "tskey") {
			t.Errorf("%s: out = %v, err = %v", tool.Meta.Name, out, err)
		}
	}
	// In tailnet text the shape is replaced instead, so one hostile name cannot
	// withhold a whole result.
	named := Define(readMeta("echo_named", "echo", "named"), func(context.Context, *Env, echoIn) (rawOut, error) {
		return rawOut{Name: "x " + key, Raw: "ok"}, nil
	})
	out, err := named.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if got, ok := out.(rawOut); err != nil || !ok || strings.Contains(got.Name, "tskey") || !strings.Contains(got.Name, tripwire.Redacted) || got.Raw != "ok" {
		t.Errorf("tailnet text: out = %+v, err = %v", out, err)
	}
}

func TestErrorsAreSanitized(t *testing.T) {
	failure := Define(readMeta("echo_fail", "echo", "fail"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, "upstream said \x1b[31mred", "retry \u202eslowly")
	})
	_, err := failure.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.APIError || e.Message != `upstream said \u{001B}[31mred` || e.Hint != `retry \u{202E}slowly` {
		t.Errorf("tkerr error: %v", err)
	}
	plain := Define(readMeta("echo_plain", "echo", "plain"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, errors.New("raw cause text")
	})
	_, err = plain.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.Internal || strings.Contains(err.Error(), "raw cause") {
		t.Errorf("plain error: %v", err)
	}
}

type secretOut struct {
	ID     string `json:"id"`
	Nested struct {
		ClientSecret string `json:"clientSecret"`
	} `json:"nested"`
}

type tokenOut struct {
	Rows []struct {
		AccessToken string `json:"access_token"`
	} `json:"rows"`
}

func TestAddRejectsBadMetadata(t *testing.T) {
	good := readMeta("echo_get", "echo", "get")
	cases := map[string]Meta{
		"bad name":    {Name: "Echo", Area: "echo", Verb: "x", Summary: "s", Tier: TierRead, Stage: StageGA, Credential: CredRead, Scopes: []string{"a"}},
		"no scopes":   {Name: "echo_x", Area: "echo", Verb: "x", Summary: "s", Tier: TierRead, Stage: StageGA, Credential: CredRead},
		"bad stage":   {Name: "echo_x", Area: "echo", Verb: "x", Summary: "s", Tier: TierRead, Stage: "rc", Credential: CredRead, Scopes: []string{"a"}},
		"write tier":  {Name: "echo_x", Area: "echo", Verb: "x", Summary: "s", Tier: TierReversible, Stage: StageGA, Credential: CredRead, Scopes: []string{"a"}},
		"local creds": {Name: "echo_x", Area: "echo", Verb: "x", Summary: "s", Tier: TierLocal, Stage: StageGA, Credential: CredRead, Scopes: []string{"a"}},
	}
	for name, m := range cases {
		if err := New().Add(echoTool(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	typo := good
	typo.Tier = "reads"
	if err := New().Add(echoTool(typo)); err == nil || !strings.Contains(err.Error(), "unknown tier") {
		t.Errorf("unknown tier: %v", err)
	}
	if err := New().Add(Tool{Meta: good}); err == nil {
		t.Error("a Tool not built with Define was accepted")
	}
	r := New()
	if err := r.Add(echoTool(good)); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(echoTool(good)); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := r.Add(echoTool(readMeta("echo_other", "echo", "get"))); err == nil {
		t.Error("duplicate CLI command accepted")
	}
	leak := Define(readMeta("echo_leak", "echo", "leak"), func(context.Context, *Env, echoIn) (secretOut, error) {
		return secretOut{}, nil
	})
	if err := r.Add(leak); err == nil || !strings.Contains(err.Error(), "clientSecret") {
		t.Errorf("secret-shaped output accepted: %v", err)
	}
	token := Define(readMeta("echo_token", "echo", "token"), func(context.Context, *Env, echoIn) (tokenOut, error) {
		return tokenOut{}, nil
	})
	if err := r.Add(token); err == nil || !strings.Contains(err.Error(), "rows.access_token") {
		t.Errorf("token-shaped output accepted: %v", err)
	}
}

func TestAddChecksDeclaredOperations(t *testing.T) {
	for _, op := range []string{"PUT /x", "GET x", "GET /a b", "DELETE /x", ""} {
		m := readMeta("echo_ops", "echo", "ops")
		m.Operations = []string{op}
		if err := New().Add(echoTool(m)); err == nil || !strings.Contains(err.Error(), "must be GET or POST and a path") {
			t.Errorf("operation %q: %v", op, err)
		}
	}
	local := Meta{Name: "echo_local", Area: "echo", Verb: "local", Summary: "s", Tier: TierLocal, Stage: StageGA,
		Credential: CredNone, Operations: []string{"GET /x"}}
	if err := New().Add(echoTool(local)); err == nil || !strings.Contains(err.Error(), "only API tools call operations") {
		t.Errorf("operation on a local tool: %v", err)
	}
	ok := readMeta("echo_ok", "echo", "ok")
	ok.Operations = []string{"GET /tailnet/{tailnet}/devices", "POST /tailnet/{tailnet}/acl/validate"}
	if err := New().Add(echoTool(ok)); err != nil {
		t.Errorf("valid operations refused: %v", err)
	}
}

func TestProfiles(t *testing.T) {
	r := New()
	r.MustAdd(echoTool(readMeta("echo_get", "echo", "get")))
	alpha := readMeta("echo_alpha", "echo", "alpha")
	alpha.Stage = StageAlpha
	r.MustAdd(echoTool(alpha))
	reads, _ := r.Profile("reads", false)
	if len(reads) != 1 {
		t.Fatalf("reads without alpha = %d tools, want 1", len(reads))
	}
	withAlpha, _ := r.Profile("reads", true)
	if len(withAlpha) != 2 {
		t.Fatalf("reads with alpha = %d tools, want 2", len(withAlpha))
	}
	if _, err := r.Profile("everything", false); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if got := r.ReadScopes(); len(got) != 1 || got[0] != "devices:core:read" {
		t.Fatalf("ReadScopes = %v", got)
	}
}

func TestRequireAPIExplainsAbsence(t *testing.T) {
	env := &Env{APIErr: tkerr.New(tkerr.ConfigMissing, "no config", "")}
	if _, err := env.RequireAPI(); err == nil {
		t.Fatal("RequireAPI succeeded without a client")
	}
	if _, err := (&Env{}).RequireAPI(); err == nil {
		t.Fatal("RequireAPI succeeded on an empty Env")
	}
}

func TestScopeMissingNamesTheToolsScopes(t *testing.T) {
	tool := Define(readMeta("echo_get", "echo", "get"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.ScopeMissing, "forbidden", "a generic hint")
	})
	_, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ScopeMissing || !strings.Contains(e.Hint, "devices:core:read") {
		t.Errorf("err = %v", err)
	}
}

// unwrapBoom is an error whose Unwrap panics.
type unwrapBoom struct{}

func (unwrapBoom) Error() string { return "boom" }
func (unwrapBoom) Unwrap() error { panic("unwrap boom") }

func TestCallSurvivesAnErrorThatPanics(t *testing.T) {
	tool := Define(readMeta("echo_boom2", "echo", "boom2"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, unwrapBoom{}
	})
	out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); out != nil || !ok || e.Code != tkerr.Internal {
		t.Fatalf("out = %v, err = %v", out, err)
	}
}

// A loaded key names masked values in results, once, and never reaches one.
// Errors are masked without it: they echo caller input, and a pseudonym beside
// an echoed guess would confirm the guess.
func TestKeyedEnvNamesMaskedValuesOnce(t *testing.T) {
	raw := strings.Repeat("5a", 32)
	k, err := privacy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Privacy: k}
	want := privacy.Suffix(k.Pseudonym("amy@example.com"))
	person := Define(readMeta("echo_person", "echo", "person"), func(context.Context, *Env, echoIn) (personOut, error) {
		return personOut{Login: "amy@example.com"}, nil
	})
	out, err := person.Call(context.Background(), env, json.RawMessage(`{"name":"x"}`))
	if got := out.(personOut).Login; err != nil || got != "a…@example.com"+want {
		t.Fatalf("Login = %q, %v; want the address named once", got, err)
	}
	failing := Define(readMeta("echo_err", "echo", "err"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, "cannot list users for amy@example.com", "ask amy@example.com")
	})
	for name, e := range map[string]*Env{"keyed": env, "no key": {}, "nil": nil} {
		_, err = failing.Call(context.Background(), e, json.RawMessage(`{"name":"x"}`))
		fe := tkerr.From(err)
		if fe == nil || fe.Message != "cannot list users for a…@example.com" || fe.Hint != "ask a…@example.com" ||
			strings.Contains(fe.Hint+fe.Message, "[p:") || strings.Contains(fe.Hint+fe.Message, raw) {
			t.Errorf("%s: err = %v; want the address masked and never named", name, err)
		}
	}
}

func TestRequirePrivacy(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (&Env{Privacy: k}).RequirePrivacy(); err != nil || got != k {
		t.Errorf("loaded: %v, %v", got, err)
	}
	cause := tkerr.New(tkerr.PrivacyKeyUnavailable, "the key is malformed", "")
	if _, err := (&Env{PrivacyErr: cause}).RequirePrivacy(); !errors.Is(err, cause) {
		t.Errorf("malformed: %v", err)
	}
	for _, e := range []*Env{{}, nil} {
		if _, err := e.RequirePrivacy(); tkerr.From(err).Code != tkerr.PrivacyKeyUnavailable || !strings.Contains(err.Error(), privacy.EnvKey) {
			t.Errorf("absent: %v", err)
		}
	}
	if got := (*Env)(nil).Masker().Identifier("amy@example.com"); got != "a…@example.com" {
		t.Errorf("nil Env masker = %q", got)
	}
}
