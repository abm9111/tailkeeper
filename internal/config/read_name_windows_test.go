//go:build windows

package config

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// On Windows the real name check is wired in: a credential, key or token file at a UNC path,
// a device name or an alternate data stream is refused before anything is opened. None of
// these paths needs to exist, because the refusal comes before the file system is asked, and
// a path that was asked about would fail with another message.
func TestReadCheckedLimitRefusesWindowsNamesBeforeOpeningThem(t *testing.T) {
	for path, reason := range map[string]string{
		`\\server\share\key.env`: "UNC paths",
		`\\?\C:\keys\key.env`:    "UNC paths",
		`C:\keys\NUL`:            "device names",
		`C:\keys\com1.env`:       "device names",
		`C:\keys\key.env:stream`: "alternate data streams",
	} {
		for _, limit := range []int64{secretCap, 0} {
			data, err := readCheckedLimit(path, inspected{}, limit)
			e, ok := tkerr.As(err)
			if !ok || len(data) != 0 || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, reason) {
				t.Errorf("readCheckedLimit(%q, limit %d) = %d bytes, %v: want config_unsafe saying %q", path, limit, len(data), err, reason)
			}
		}
		data, err := ReadSecretFile(path)
		if e, ok := tkerr.As(err); !ok || len(data) != 0 || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, reason) {
			t.Errorf("ReadSecretFile(%q) = %d bytes, %v: want config_unsafe saying %q", path, len(data), err, reason)
		}
	}
}
