package workflows

import (
	"go/build"
	"path/filepath"
	"testing"
)

func TestMCPBProcessTestsAreDarwinOnly(t *testing.T) {
	cases := []struct {
		file                   string
		darwin, linux, windows bool
	}{
		{"cmd/tailkeeper/mcpb_darwin_test.go", true, false, false},
		{"internal/cli/mcpb_provider_unix_test.go", true, true, false},
		{"internal/releasebundle/install_test.go", true, true, true},
		{"internal/releasebundle/bundle_test.go", true, true, true},
		{"internal/creds/read_test.go", true, true, true},
	}
	for _, tc := range cases {
		for _, platform := range []struct {
			name string
			want bool
		}{{"darwin", tc.darwin}, {"linux", tc.linux}, {"windows", tc.windows}} {
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH = platform.name, "amd64"
			path := filepath.Join("../..", tc.file)
			got, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
			if err != nil || got != platform.want {
				t.Errorf("%s on %s: compiled=%t, want %t: %v", tc.file, platform.name, got, platform.want, err)
			}
		}
	}
}
