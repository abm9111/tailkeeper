package securitypack

import (
	"strings"
	"testing"
)

func TestPackTokenForms(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if !validIntentToken(nil, "") || !validIntentToken(&packToken{Form: "plain", Value: "sha256:" + digest}, digest[:12]) {
		t.Fatal("valid intent token refused")
	}
	if validIntentToken(&packToken{Form: "plain", Value: "sha256:" + digest}, "other") {
		t.Fatal("wrong revision accepted")
	}
	if !validPolicyToken(&packToken{Form: "plain", Value: `"` + digest + `"`}) {
		t.Fatal("quoted policy token refused")
	}
	for _, token := range []string{digest, `"` + strings.ToUpper(digest) + `"`, " " + `"` + digest + `"`} {
		if validPolicyToken(&packToken{Form: "plain", Value: token}) {
			t.Fatal("bad policy token accepted")
		}
	}
}
