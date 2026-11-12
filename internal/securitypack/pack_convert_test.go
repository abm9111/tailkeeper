package securitypack

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestIntentConversionOwnership(t *testing.T) {
	in := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "one", Accept: []string{"destination"}, SourcePostureAttributes: security.PostureAttributes{"attribute": {Kind: security.ScalarNumber, Number: "1.50"}}}}}
	wire, err := intentToPack(&in, "")
	if err != nil {
		t.Fatal(err)
	}
	in.Network[0].Accept[0] = "changed"
	in.Network[0].SourcePostureAttributes["attribute"] = security.Scalar{Kind: security.ScalarString, String: "changed"}
	if wire.Network[0].Accept[0] != "destination" || *wire.Network[0].SrcPostureAttrs[0].Number != "1.50" {
		t.Fatal("producer retained ownership")
	}
	decoded, _, err := intentFromPack(wire)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Network[0].Accept[0] = "changed"
	decoded.Network[0].SourcePostureAttributes["attribute"] = security.Scalar{Kind: security.ScalarBool, Bool: true}
	if wire.Network[0].Accept[0] != "destination" || *wire.Network[0].SrcPostureAttrs[0].Number != "1.50" {
		t.Fatal("consumer retained ownership")
	}
	if _, err := attributeToPack("a", security.Scalar{Kind: security.ScalarNumber, Number: "1", String: "inactive"}); err == nil {
		t.Fatal("accepted inactive member")
	}
}
