package securitypack

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

// Freshness describes the supplied replay instant independently of the recorded report.
type Freshness struct {
	Valid          bool
	EvaluatedAt    time.Time
	ReplayedAt     time.Time
	Age            time.Duration
	CatalogState   security.CatalogState
	StaleReviews   int
	ClockUncertain bool
}

// ReplayFreshness never reads a clock or changes the recorded report. A replay clock
// more than five minutes behind the evaluation clock is marked uncertain.
func ReplayFreshness(pack EvidencePack, replayedAt time.Time) Freshness {
	pi, err := packInputOf(pack)
	if err != nil || replayedAt.IsZero() {
		return Freshness{}
	}
	catalog, err := advisory.Merge(pi.Sources)
	if err != nil || catalog.Digest != pi.CatalogDigest {
		return Freshness{}
	}
	at := replayedAt.UTC().Round(0)
	out := Freshness{Valid: true, EvaluatedAt: pi.EvaluationAt, ReplayedAt: at,
		Age: at.Sub(pi.EvaluationAt), CatalogState: security.CatalogStateAt(catalog, at)}
	out.ClockUncertain = out.Age < -5*time.Minute
	for _, rule := range catalog.Records {
		if security.ReviewStale(rule, at) {
			out.StaleReviews++
		}
	}
	return out
}

// Reference returns the short current-privacy reference, never a full digest.
// Authentication of an existing seal belongs to Decode.
func Reference(pack EvidencePack, seal Sealer, show bool) (string, error) {
	if _, err := packInputOf(pack); err != nil {
		return "", err
	}
	if !show && seal == nil {
		return "", nil
	}
	body, err := encodePackBody(pack.envelope.Body)
	if err != nil {
		return "", ErrInvalidPack
	}
	input := append([]byte("tailkeeper-evidence-pack/1\n"), body...)
	if show {
		sum := sha256.Sum256(input)
		return fmt.Sprintf("%x", sum)[:12], nil
	}
	value := seal(input)
	if !strictDigest(value, "hmac-sha256:") {
		return "", ErrInvalidPack
	}
	return value[len("hmac-sha256:") : len("hmac-sha256:")+12], nil
}
