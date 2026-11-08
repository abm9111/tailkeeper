package securitypack

import (
	"regexp"
	"strings"
	"testing"
)

var plainPolicyTokenPattern = regexp.MustCompile(`\A"[0-9a-f]{64}"\z`)

func validPlainPolicyTokenOracle(token string) bool {
	if len(token) != 66 {
		return false
	}
	return plainPolicyTokenPattern.MatchString(token)
}

func TestValidPlainPolicyToken(t *testing.T) {
	validDigits := `"` + strings.Repeat("0123456789", 6) + "0123" + `"`
	validLetters := `"` + strings.Repeat("abcdef", 10) + "abcd" + `"`
	validMixed := `"` + strings.Repeat("a1b2c3d4e5f6", 5) + "0a1b" + `"`

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "valid digits",
			token: validDigits,
			want:  true,
		},
		{
			name:  "valid letters a through f",
			token: validLetters,
			want:  true,
		},
		{
			name:  "valid mixed hex",
			token: validMixed,
			want:  true,
		},
		{
			name:  "63 digits",
			token: `"` + strings.Repeat("a", 63) + `"`,
			want:  false,
		},
		{
			name:  "65 digits",
			token: `"` + strings.Repeat("a", 65) + `"`,
			want:  false,
		},
		{
			name:  "uppercase A",
			token: `"` + strings.Repeat("A", 64) + `"`,
			want:  false,
		},
		{
			name:  "uppercase F",
			token: `"` + strings.Repeat("F", 64) + `"`,
			want:  false,
		},
		{
			name:  "single uppercase A",
			token: `"` + strings.Repeat("a", 63) + "A" + `"`,
			want:  false,
		},
		{
			name:  "single uppercase F",
			token: `"` + strings.Repeat("a", 63) + "F" + `"`,
			want:  false,
		},
		{
			name:  "actual weak ETag prefix",
			token: "W/" + validLetters,
			want:  false,
		},
		{
			name:  "opaque pristine tag",
			token: "ts-default",
			want:  false,
		},
		{
			name:  "weak marker inside quoted value",
			token: `"W/` + strings.Repeat("a", 62) + `"`,
			want:  false,
		},
		{
			name:  "bare hex",
			token: strings.Repeat("0123456789abcdef", 4),
			want:  false,
		},
		{
			name:  "missing opening quote",
			token: strings.Repeat("a", 64) + `"`,
			want:  false,
		},
		{
			name:  "missing closing quote",
			token: `"` + strings.Repeat("a", 64),
			want:  false,
		},
		{
			name:  "wrong opening byte at full length",
			token: "0" + strings.Repeat("a", 64) + `"`,
			want:  false,
		},
		{
			name:  "wrong closing byte at full length",
			token: `"` + strings.Repeat("a", 64) + "0",
			want:  false,
		},
		{
			name:  "extra trailing quote",
			token: validDigits + `"`,
			want:  false,
		},
		{
			name:  "leading space",
			token: " " + validDigits,
			want:  false,
		},
		{
			name:  "trailing space",
			token: validDigits + " ",
			want:  false,
		},
		{
			name:  "embedded space",
			token: `"` + strings.Repeat("a", 32) + " " + strings.Repeat("a", 31) + `"`,
			want:  false,
		},
		{
			name:  "embedded NUL",
			token: `"` + strings.Repeat("a", 32) + "\x00" + strings.Repeat("a", 31) + `"`,
			want:  false,
		},
		{
			name:  "trailing newline",
			token: validDigits + "\n",
			want:  false,
		},
		{
			name:  "non-ASCII character",
			token: `"` + strings.Repeat("a", 32) + "é" + strings.Repeat("a", 30) + `"`,
			want:  false,
		},
		{
			name:  "non-hex ASCII g",
			token: `"` + strings.Repeat("a", 63) + "g" + `"`,
			want:  false,
		},
		{
			name:  "empty",
			token: "",
			want:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := validPlainPolicyToken(tc.token); got != tc.want {
				t.Fatalf("validPlainPolicyToken(%q) = %v, want %v", tc.token, got, tc.want)
			}
			if got := validPlainPolicyTokenOracle(tc.token); got != tc.want {
				t.Fatalf("test oracle for %q = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

func FuzzValidPlainPolicyToken(f *testing.F) {
	validDigits := `"` + strings.Repeat("0123456789", 6) + "0123" + `"`
	validLetters := `"` + strings.Repeat("abcdef", 10) + "abcd" + `"`

	seeds := []string{
		validDigits,
		validLetters,
		"W/" + validLetters,
		"ts-default",
		`"` + strings.Repeat("A", 64) + `"`,
		`"W/` + strings.Repeat("a", 62) + `"`,
		strings.Repeat("a", 64),
		`"` + strings.Repeat("a", 63) + `"`,
		`"` + strings.Repeat("a", 65) + `"`,
		"0" + strings.Repeat("a", 64) + `"`,
		`"` + strings.Repeat("a", 64) + "0",
		" " + validDigits,
		validDigits + " ",
		`"` + strings.Repeat("a", 32) + "\x00" + strings.Repeat("a", 31) + `"`,
		validDigits + "\n",
		`"` + strings.Repeat("a", 32) + "é" + strings.Repeat("a", 30) + `"`,
		validDigits + `"`,
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		got := validPlainPolicyToken(token)
		want := validPlainPolicyTokenOracle(token)
		if got != want {
			t.Fatalf("validPlainPolicyToken(%q) = %v, want %v", token, got, want)
		}
	})
}
