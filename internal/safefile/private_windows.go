//go:build windows

package safefile

import "github.com/abm9111/tailkeeper/internal/tkerr"

// WritePrivate refuses platforms on which private ownership cannot be verified.
func WritePrivate(_ string, _ []byte, _ func() error) error {
	return tkerr.New(tkerr.UnsupportedTarget, "private files are unsupported on Windows", "")
}

// ReadPrivate refuses platforms on which private ownership cannot be verified.
func ReadPrivate(_ string) ([]byte, error) {
	return nil, tkerr.New(tkerr.UnsupportedTarget, "private files are unsupported on Windows", "")
}
