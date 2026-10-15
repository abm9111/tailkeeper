package sanitize

import (
	"strings"
	"testing"
)

// policyPage is about 64 KiB of policy-like text with 200 addresses: the shape
// acl_get masks a page at a time.
func policyPage() string {
	var b strings.Builder
	for i := range 200 {
		b.WriteString(`  {"action": "accept", "src": ["user`)
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(`@example.com"], "dst": ["tag:web:443", "203.0.113.7:22"]},` + "\n")
		b.WriteString(strings.Repeat("  // a comment line with no address in it at all\n", 4))
	}
	return b.String()
}

func BenchmarkMaskEmailsPolicyPage(b *testing.B) {
	s := policyPage()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		MaskEmails(s)
	}
}

func BenchmarkKeyedEmailsPolicyPage(b *testing.B) {
	m, _ := keyedMasker(b)
	s := policyPage()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		m.Emails(s)
	}
}

func BenchmarkKeyedTextPolicyPage(b *testing.B) {
	m, _ := keyedMasker(b)
	s := policyPage()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		m.Text(s)
	}
}

func BenchmarkMaskAddrsPolicyPage(b *testing.B) {
	s := policyPage()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		MaskAddrs(s)
	}
}

func BenchmarkStringField(b *testing.B) {
	s := strings.Repeat("web-1.example.ts.net\u200b ", 40)
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		String(s, DefaultMax)
	}
}

func BenchmarkTextPolicyPage(b *testing.B) {
	s := policyPage()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		Text(s, MaxText)
	}
}

func BenchmarkKeyedMask1000Rows(b *testing.B) {
	m, _ := keyedMasker(b)
	rows := make([]scalingRow, 1000)
	for b.Loop() {
		b.StopTimer()
		for i := range rows {
			rows[i] = scalingRow{Login: "amy@example.com", Note: "owner bob@example.com", Tags: []string{"tag:web"}}
		}
		out := scalingOut{Rows: rows}
		b.StartTimer()
		m.Mask(&out)
	}
}
