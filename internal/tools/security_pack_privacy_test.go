package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/securitypack"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestPackRecordedTokensFollowCurrentPrivacy(t *testing.T) {
	key, err := privacy.Parse(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := "sha256:" + strings.Repeat("a", 64)
	keyed := "hmac-sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name      string
		show      bool
		key       bool
		wantPlain bool
		wantKeyed bool
	}{
		{"show", true, true, true, false}, {"masked-key", false, true, false, true}, {"masked-no-key", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := &registry.Env{Config: &config.Loaded{}}
			if tc.show {
				env.Config.Config.PersonalData = config.PersonalDataShow
			}
			if tc.key {
				env.Privacy = key
			}
			for _, v := range []struct {
				value string
				want  bool
			}{{plain, tc.wantPlain}, {keyed, tc.wantKeyed}} {
				got, note := recordedToken(env, v.value, false)
				if (got != "") != v.want || (note != "") == v.want {
					t.Fatalf("got %q note %q", got, note)
				}
				if got == v.value {
					t.Fatal("full recorded digest escaped")
				}
			}
			policy := `"` + strings.Repeat("c", 64) + `"`
			got, note := recordedToken(env, policy, true)
			if (got != "") != tc.wantPlain || (note != "") == tc.wantPlain || got == policy {
				t.Fatalf("policy %q note %q", got, note)
			}
		})
	}
}
func TestPackResultMasksUntrustedReplayText(t *testing.T) {
	const sentinel = "owner@example.invalid"
	result := SecurityReplayOutput{Replay: ReplayInfo{Reproduced: true}, Report: ReplayReport{Coverage: []ReplayCoverage{{Source: sentinel, Explanation: sentinel}}, Findings: []ReplayFinding{{Rule: sentinel, RuleRevision: sentinel, Explanation: sentinel, Verification: []string{sentinel}, Evidence: []ReplayEvidence{{Error: sentinel}}}}}, Access: &ReplayAccess{Expectations: []ReplayAccessRow{{Source: sentinel, Cells: []SecurityExplainCell{{Destination: sentinel}}, Candidates: []ReplayAccessRule{{Source: sentinel, Destination: sentinel}}}}}}
	original, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, show := range []bool{false, true} {
		var fresh SecurityReplayOutput
		if err := json.Unmarshal(original, &fresh); err != nil {
			t.Fatal(err)
		}
		tool := registry.Define(packLocalMeta("test_pack", "pack", "Synthetic result"), func(context.Context, *registry.Env, struct{}) (SecurityReplayOutput, error) { return fresh, nil })
		env := &registry.Env{Config: &config.Loaded{}}
		if show {
			env.Config.Config.PersonalData = config.PersonalDataShow
		}
		out, err := tool.Call(context.Background(), env, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), sentinel) != show {
			t.Fatalf("show=%t result=%s", show, b)
		}
	}
}

func TestPackCatalogDigestDisclosure(t *testing.T) {
	public, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	env := &registry.Env{Config: &config.Loaded{}}
	shared := securitypack.CatalogSummary{Digest: public.Digest}
	if got := replayCatalog(env, shared); got.Digest != public.Digest {
		t.Fatal("shipped catalog digest was not proved public")
	}
	custom := securitypack.CatalogSummary{Digest: strings.Repeat("c", 64)}
	for _, show := range []bool{false, true} {
		env.Config.Config.PersonalData = config.PersonalDataMask
		if show {
			env.Config.Config.PersonalData = config.PersonalDataShow
		}
		got := replayCatalog(env, custom)
		if show && got.Digest != custom.Digest[:12] {
			t.Fatalf("shown digest %q", got.Digest)
		}
		if !show && (got.Digest != "" || got.WithheldNote == "") {
			t.Fatalf("masked catalog %+v", got)
		}
	}
}

// poisonPackStrings walks every tagged string field, including nested slices and pointers.
// The explicit manifest in the test makes a missing or newly added free-text tag observable.
func poisonPackStrings(v reflect.Value, path string, seen map[string]string) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		poisonPackStrings(v.Elem(), path, seen)
		return
	}
	if v.Kind() != reflect.Struct {
		return
	}
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := typ.Field(i)
		value := v.Field(i)
		name := f.Name
		if path != "" {
			name = path + "." + name
		}
		marked := strings.Contains(","+f.Tag.Get("tk")+",", ",untrusted,")
		switch value.Kind() {
		case reflect.String:
			if marked {
				sentinel := fmt.Sprintf("poison%03d@example.invalid", len(seen))
				value.SetString(sentinel)
				seen[name] = sentinel
			}
		case reflect.Pointer, reflect.Struct:
			poisonPackStrings(value, name, seen)
		case reflect.Slice:
			if value.Type().Elem().Kind() == reflect.String {
				if marked {
					sentinel := fmt.Sprintf("poison%03d@example.invalid", len(seen))
					value.Set(reflect.ValueOf([]string{sentinel}))
					seen[name] = sentinel
				}
			} else if value.Type().Elem().Kind() == reflect.Struct {
				value.Set(reflect.MakeSlice(value.Type(), 1, 1))
				poisonPackStrings(value.Index(0), name, seen)
			}
		}
	}
}
func TestPackReplayEveryUntrustedFieldThroughRegistry(t *testing.T) {
	want := []string{"Replay.Differences", "Report.IntentDigest", "Report.IntentRevision", "Report.Coverage.Source", "Report.Coverage.Explanation", "Report.Findings.Rule", "Report.Findings.RuleRevision", "Report.Findings.Device", "Report.Findings.Explanation", "Report.Findings.Verification", "Report.Findings.Evidence.Error", "Access.PolicyVersion", "Access.Expectations.ID", "Access.Expectations.Source", "Access.Expectations.Cells.Destination", "Access.Expectations.Cells.User", "Access.Expectations.Candidates.Source", "Access.Expectations.Candidates.Destination", "Access.Expectations.Candidates.Ports", "Access.Expectations.Candidates.Traffic", "Access.Blast.Source", "Access.Blast.Heading", "Access.Blast.Reaches.Destination", "Access.Blast.Reaches.User", "Access.Blast.Broad.Source", "Access.Blast.Broad.Destination", "Access.Blast.Broad.Ports", "Access.Blast.Broad.Traffic", "Access.Blast.Tags", "Access.Notes"}
	var result SecurityReplayOutput
	seen := make(map[string]string)
	poisonPackStrings(reflect.ValueOf(&result).Elem(), "", seen)
	if len(seen) != len(want) {
		t.Fatalf("manifest has %d fields, reflection found %d: %v", len(want), len(seen), seen)
	}
	for _, name := range want {
		if _, ok := seen[name]; !ok {
			t.Errorf("untrusted tag absent from %s", name)
		}
	}
	original, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, show := range []bool{false, true} {
		var fresh SecurityReplayOutput
		if err := json.Unmarshal(original, &fresh); err != nil {
			t.Fatal(err)
		}
		tool := registry.Define(packLocalMeta("test_pack", "pack", "Synthetic result"), func(context.Context, *registry.Env, struct{}) (SecurityReplayOutput, error) { return fresh, nil })
		env := &registry.Env{Config: &config.Loaded{}}
		if show {
			env.Config.Config.PersonalData = config.PersonalDataShow
		}
		out, err := tool.Call(context.Background(), env, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		for name, sentinel := range seen {
			if strings.Contains(string(b), sentinel) != show {
				t.Errorf("show=%t field=%s", show, name)
			}
		}
	}
}
func TestPackSummaryPathThroughRegistry(t *testing.T) {
	const sentinel = "owner@example.invalid"
	tool := registry.Define(packLocalMeta("test_pack", "pack", "Synthetic result"), func(context.Context, *registry.Env, struct{}) (SecurityPackSummary, error) {
		return SecurityPackSummary{Path: sentinel}, nil
	})
	for _, show := range []bool{false, true} {
		env := &registry.Env{Config: &config.Loaded{}}
		if show {
			env.Config.Config.PersonalData = config.PersonalDataShow
		}
		out, err := tool.Call(context.Background(), env, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), sentinel) != show {
			t.Fatalf("show=%t path=%s", show, b)
		}
	}
}

func TestPackBuildErrorsUseSafeExitCodes(t *testing.T) {
	for _, err := range []error{securitypack.ErrStoppedEarly, securitypack.ErrNotReproduced} {
		got := packCodecError(err)
		if tkerr.ExitCode(got) != 1 || strings.Contains(got.Error(), err.Error()) {
			t.Fatalf("stopped/reproduction error was not mapped safely: %v", got)
		}
	}
	if got := packCodecError(securitypack.ErrIntegrityMismatch); tkerr.ExitCode(got) != 2 || strings.Contains(got.Error(), securitypack.ErrIntegrityMismatch.Error()) {
		t.Fatalf("integrity refusal was not mapped safely: %v", got)
	}
}

func TestPackInterruptionDoesNotExposeCause(t *testing.T) {
	const sentinel = "synthetic-private-fixture"
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		got := packCodecError(fmt.Errorf("%s: %w", sentinel, cause))
		if tkerr.ExitCode(got) != 1 || !errors.Is(got, cause) || strings.Contains(got.Error(), sentinel) {
			t.Fatalf("unsafe interruption: %v", got)
		}
		b, err := json.Marshal(got)
		if err != nil || strings.Contains(string(b), sentinel) {
			t.Fatalf("unsafe JSON: %s %v", b, err)
		}
	}
}
