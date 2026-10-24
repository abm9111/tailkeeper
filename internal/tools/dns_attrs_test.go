package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestEveryNameInTheTableMatchesItsShapeAndAChangeMovesItsProvenance(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	var names []string
	for _, n := range dnsNodeAttrs {
		if !shape.MatchString(n) {
			t.Errorf("%q does not match %s", n, shape)
		}
		names = append(names, n)
	}
	if len(names) != 7 {
		t.Fatalf("the table has %d names", len(names))
	}
	sum := sha256.Sum256([]byte(strings.Join(names, "\n") + "\n"))
	want := "provenance: tailcfg/nodecap, " + dnsAttrTableAsOf + ", names sha256 " + hex.EncodeToString(sum[:])
	src, err := os.ReadFile("dns_attrs.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), want) {
		t.Errorf("the provenance comment is not %q", want)
	}
}
