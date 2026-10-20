package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// randomHex returns n random lower-case hex digits.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system's random source failing is not something a probe can work around
	}
	return hex.EncodeToString(b)[:n]
}
