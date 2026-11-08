package securitypack

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

const correctionPrefix = `{"schema_version":1,"action_at":"2026-11-02T10:15:00Z",`

func TestDecodeCorrectionAcceptsNonCanonicalInputAndAllTargets(t *testing.T) {
	data := []byte(` { "expect" : { "features" : [{"name":"tailscale_ssh", "device":"node1", "value":false}], "versions":[{"at_least":"1.32.3","name":"client","device":"node1","role":"local_cli"}] }, "expectations":["network-1"], "findings":[{"device":"node1","rule":"CVE-2022-41925"}], "action_at":"2026-11-02T10:15:00Z", "schema_version":1 } `)
	got, err := DecodeCorrection(data)
	if err != nil {
		t.Fatalf("valid correction refused: %v", err)
	}
	if len(got.Findings) != 1 || len(got.ExpectationIDs) != 1 || len(got.Versions) != 1 || len(got.Features) != 1 || got.Features[0].Value {
		t.Fatalf("targets lost or false changed: %+v", got)
	}
	if got.Features[0].Role != "running_daemon" {
		t.Fatalf("default role = %q", got.Features[0].Role)
	}
}

func TestDecodeCorrectionRejectsInvalidDocuments(t *testing.T) {
	tests := map[string]string{
		"missing schema":                      `{"action_at":"2026-11-02T10:15:00Z","expectations":["one"]}`,
		"missing action":                      `{"schema_version":1,"expectations":["one"]}`,
		"wrong schema":                        `{"schema_version":2,"action_at":"2026-11-02T10:15:00Z","expectations":["one"]}`,
		"zero action":                         `{"schema_version":1,"action_at":"0001-01-01T00:00:00Z","expectations":["one"]}`,
		"invalid action":                      correctionPrefix + `"expectations":["one"],"action_at":"tomorrow"}`,
		"no targets":                          correctionPrefix + `"expect":{}}`,
		"unknown top key":                     correctionPrefix + `"expectations":["one"],"policies":[]}`,
		"case changed key":                    correctionPrefix + `"Expectations":["one"]}`,
		"duplicate escaped key":               correctionPrefix + `"expectations":["one"],"expect\u0061tions":["two"]}`,
		"duplicate nested key":                correctionPrefix + `"findings":[{"rule":"A","rule":"B","device":"one"}]}`,
		"unknown nested key":                  correctionPrefix + `"expect":{"versions":[{"device":"one","name":"client","at_least":"1.2.3","extra":true}]}}`,
		"null schema":                         `{ "schema_version":null,"action_at":"2026-11-02T10:15:00Z","expectations":["one"]}`,
		"null action":                         `{ "schema_version":1,"action_at":null,"expectations":["one"]}`,
		"wrong boolean type":                  correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":"false"}]}}`,
		"null array":                          correctionPrefix + `"expectations":null}`,
		"null object":                         correctionPrefix + `"expect":null}`,
		"null target":                         correctionPrefix + `"findings":[null]}`,
		"null string":                         correctionPrefix + `"expectations":[null]}`,
		"missing feature value":               correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh"}]}}`,
		"null feature value":                  correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":null}]}}`,
		"null role":                           correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":true,"role":null}]}}`,
		"empty role":                          correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":true,"role":""}]}}`,
		"invalid role":                        correctionPrefix + `"expect":{"versions":[{"device":"one","name":"client","at_least":"1.2.3","role":"other"}]}}`,
		"missing field":                       correctionPrefix + `"findings":[{"device":"one"}]}`,
		"empty field":                         correctionPrefix + `"findings":[{"device":"one","rule":""}]}`,
		"bad text":                            correctionPrefix + `"expectations":["one\nline"]}`,
		"invalid utf8":                        correctionPrefix + "\"expectations\":[\"\xff\"]}",
		"credential shape escaped":            correctionPrefix + `"expectations":["\u0074skey-api-example"]}`,
		"duplicate finding":                   correctionPrefix + `"findings":[{"device":"one","rule":"A"},{"rule":"A","device":"one"}]}`,
		"duplicate expectation":               correctionPrefix + `"expectations":["one","one"]}`,
		"duplicate version with default role": correctionPrefix + `"expect":{"versions":[{"device":"one","name":"client","at_least":"1.2.3"},{"device":"one","name":"client","role":"running_daemon","at_least":"2.0.0"}]}}`,
		"conflicting feature":                 correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":true},{"device":"one","name":"ssh","value":false}]}}`,
		"guard feature":                       correctionPrefix + `"expect":{"features":[{"device":"one","name":"connected_to_control","value":true}]}}`,
		"trailing json":                       correctionPrefix + `"expectations":["one"]} {}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeCorrection([]byte(data))
			if !errors.Is(err, ErrCorrectionInvalid) || err.Error() != "correction_invalid" {
				t.Fatalf("got %v; want closed correction_invalid", err)
			}
		})
	}
}

func TestCorrectionReleaseGrammar(t *testing.T) {
	for _, v := range []string{"1.32", "1.32.3-t0123456", " 1.32.3", "01.32.3"} {
		data := fmt.Sprintf(correctionPrefix+`"expect":{"versions":[{"device":"one","name":"client","at_least":%q}]}}`, v)
		if _, err := DecodeCorrection([]byte(data)); !errors.Is(err, ErrCorrectionInvalid) {
			t.Errorf("release %q accepted: %v", v, err)
		}
	}
}

func TestCorrectionTargetAndByteLimits(t *testing.T) {
	for _, n := range []int{1, 256, 257} {
		values := make([]string, n)
		for i := range values {
			values[i] = fmt.Sprintf("\"id-%d\"", i)
		}
		data := correctionPrefix + `"expectations":[` + strings.Join(values, ",") + `]}`
		_, err := DecodeCorrection([]byte(data))
		if (err == nil) != (n <= 256) {
			t.Errorf("%d targets: %v", n, err)
		}
	}
	base := correctionPrefix + `"expectations":["one"]}`
	for _, size := range []int{64 * 1024, 64*1024 + 1} {
		data := []byte(base + strings.Repeat(" ", size-len(base)))
		_, err := DecodeCorrection(data)
		if (err == nil) != (size == 64*1024) {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
}

func FuzzDecodeCorrection(f *testing.F) {
	for _, s := range []string{correctionPrefix + `"expectations":["one"]}`, correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":false}]}}`, correctionPrefix + `"expectations":["\u0074skey-api-x"]}`, `{"schema_version":1,"schema_version":1}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeCorrection(data)
		if err != nil {
			if !errors.Is(err, ErrCorrectionInvalid) {
				t.Fatalf("open error: %v", err)
			}
			return
		}
		if err := ValidateCorrection(got); err != nil {
			t.Fatalf("decoded invalid value: %v", err)
		}
	})
}

// Direct callers must not be able to bypass the semantic checks of the wire decoder.
func TestValidateCorrectionConstructedIntents(t *testing.T) {
	base, err := DecodeCorrection([]byte(correctionPrefix + `"expectations":["one"]}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*security.CorrectionIntent)
	}{
		{"bad schema", func(c *security.CorrectionIntent) { c.SchemaVersion = 2 }},
		{"no targets", func(c *security.CorrectionIntent) { c.ExpectationIDs = nil }},
		{"duplicate expectation", func(c *security.CorrectionIntent) { c.ExpectationIDs = append(c.ExpectationIDs, "one") }},
		{"invalid text", func(c *security.CorrectionIntent) { c.ExpectationIDs = []string{"bad\ntext"} }},
		{"invalid feature role", func(c *security.CorrectionIntent) {
			c.Features = []security.ExpectedFeature{{Asset: "one", Name: "ssh", Role: "other"}}
		}},
		{"guard feature", func(c *security.CorrectionIntent) {
			c.Features = []security.ExpectedFeature{{Asset: "one", Name: "connected_to_control"}}
		}},
		{"invalid release", func(c *security.CorrectionIntent) {
			c.Versions = []security.ExpectedVersion{{Asset: "one", Name: "client", AtLeast: "1.32"}}
		}},
		{"default and explicit role duplicate", func(c *security.CorrectionIntent) {
			c.Versions = []security.ExpectedVersion{{Asset: "one", Name: "client", AtLeast: "1.32.3"}, {Asset: "one", Name: "client", Role: security.VersionRunningDaemon, AtLeast: "1.34.0"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.edit(&c)
			if err := ValidateCorrection(c); !errors.Is(err, ErrCorrectionInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCorrectionDistinctRolesAndQuotedDelimiters(t *testing.T) {
	data := correctionPrefix + `"expectations":["braces [[[[[[[[[[ and }}}}}}}}}}"],"expect":{"versions":[{"device":"one","name":"client","at_least":"1.2.3"},{"device":"one","name":"client","role":"api_reported","at_least":"1.2.3"}]}}`
	if _, err := DecodeCorrection([]byte(data)); err != nil {
		t.Fatalf("valid targets or quoted delimiters refused: %v", err)
	}
	data = correctionPrefix + `"expectations":[[[[[[[[["one"]]]]]]]]]}`
	if _, err := DecodeCorrection([]byte(data)); !errors.Is(err, ErrCorrectionInvalid) {
		t.Fatalf("deep nesting accepted: %v", err)
	}
}

func TestCorrectionCountsAllTargetKinds(t *testing.T) {
	ids := make([]string, 253)
	for i := range ids {
		ids[i] = fmt.Sprintf("\"id-%d\"", i)
	}
	data := correctionPrefix + `"findings":[{"rule":"A","device":"one"}],"expectations":[` + strings.Join(ids, ",") + `],"expect":{"versions":[{"device":"one","name":"client","at_least":"1.2.3"}],"features":[{"device":"one","name":"ssh","value":false}]}}`
	if _, err := DecodeCorrection([]byte(data)); err != nil {
		t.Fatalf("256 mixed targets refused: %v", err)
	}
	data = strings.Replace(data, `"id-252"`, `"id-252","id-253"`, 1)
	if _, err := DecodeCorrection([]byte(data)); !errors.Is(err, ErrCorrectionInvalid) {
		t.Fatalf("257 mixed targets accepted: %v", err)
	}
}

func TestCorrectionRejectsOppositeFeatureValuesAcrossRoles(t *testing.T) {
	for _, role := range []string{"local_cli", "api_reported"} {
		t.Run(role, func(t *testing.T) {
			data := correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":true},{"device":"one","name":"ssh","role":"` + role + `","value":false}]}}`
			if _, err := DecodeCorrection([]byte(data)); !errors.Is(err, ErrCorrectionInvalid) {
				t.Fatalf("opposite values across roles accepted: %v", err)
			}
		})
	}
}

func TestValidateCorrectionRejectsOppositeFeatureValuesAcrossRoles(t *testing.T) {
	base, err := DecodeCorrection([]byte(correctionPrefix + `"expectations":["one"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []security.VersionRole{security.VersionLocalCLI, security.VersionAPIReported} {
		t.Run(string(role), func(t *testing.T) {
			c := base
			c.Features = []security.ExpectedFeature{{Asset: "one", Name: "ssh", Value: true}, {Asset: "one", Name: "ssh", Role: role, Value: false}}
			if err := ValidateCorrection(c); !errors.Is(err, ErrCorrectionInvalid) {
				t.Fatalf("opposite values across roles accepted: %v", err)
			}
		})
	}
}

func TestCorrectionAcceptsSameFeatureValueAcrossRoles(t *testing.T) {
	data := correctionPrefix + `"expect":{"features":[{"device":"one","name":"ssh","value":false},{"device":"one","name":"ssh","role":"local_cli","value":false},{"device":"two","name":"ssh","value":true}]}}`
	if _, err := DecodeCorrection([]byte(data)); err != nil {
		t.Fatalf("compatible feature targets refused: %v", err)
	}
}
