package privacy

import (
	"strings"
	"testing"
)

func BenchmarkPseudonym(b *testing.B) {
	k, err := Parse(strings.Repeat("5a", 32))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		k.Pseudonym("amy@example.com")
	}
}

func BenchmarkDigest(b *testing.B) {
	k, err := Parse(strings.Repeat("5a", 32))
	if err != nil {
		b.Fatal(err)
	}
	v := []byte(strings.Repeat(`{"acls":[{"action":"accept"}]}`, 32))
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		k.Digest(v)
	}
}
