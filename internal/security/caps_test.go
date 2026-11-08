package security

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The caps are the design's numbers. The tests that use them elsewhere take them from the
// constants, so a cap that grew by one would grow every test with it; these name the
// numbers, and the places that use each one, so that a change to a cap is a change here.

func TestTheCapsAreTheDesignsNumbers(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"SchemaVersion", SchemaVersion, 1},
		{"MaxFindings", MaxFindings, 10000},
		{"MaxTextBytes", MaxTextBytes, 4096},
		{"MaxObservations", MaxObservations, 10000},
		{"MaxCatalogRecords", MaxCatalogRecords, 1000},
		{"MaxRanges", MaxRanges, 32},
		{"MaxCandidates", MaxCandidates, 250000},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestCapsHoldAtTheirExactNumbers(t *testing.T) {
	t.Run("text of 4096 bytes is accepted and 4097 is not", func(t *testing.T) {
		if err := validateString(strings.Repeat("x", 4096)); err != nil {
			t.Fatal(err)
		}
		if err := validateString(strings.Repeat("x", 4097)); err == nil || err.Error() != "invalid or oversized text" {
			t.Fatal(err)
		}
	})
	t.Run("a catalog of 1000 rules is accepted and 1001 is not", func(t *testing.T) {
		c, _ := catalogFixture()
		manyRecords(&c, 1000)
		if err := ValidateCatalog(c); err != nil {
			t.Fatal(err)
		}
		manyRecords(&c, 1001)
		if err := ValidateCatalog(c); err == nil || err.Error() != "too many records" {
			t.Fatal(err)
		}
	})
	t.Run("a rule of 32 ranges and 32 required features is accepted and 33 is not", func(t *testing.T) {
		c, _ := catalogFixture()
		c.Records[0].Ranges = evenRanges(32)
		for i := 0; i < 32; i++ {
			c.Records[0].RequiredFeatures = append(c.Records[0].RequiredFeatures, "feature-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		}
		if err := ValidateCatalog(c); err != nil {
			t.Fatal(err)
		}
		c.Records[0].Ranges = evenRanges(33)
		if err := ValidateCatalog(c); err == nil || err.Error() != "too many ranges" {
			t.Fatal(err)
		}
		c.Records[0].Ranges = evenRanges(32)
		c.Records[0].RequiredFeatures = append(c.Records[0].RequiredFeatures, "feature-extra")
		if err := ValidateCatalog(c); err == nil || err.Error() != "too many required features" {
			t.Fatal(err)
		}
	})
	t.Run("a work budget of 250000 steps is allowed and 250001 is not", func(t *testing.T) {
		w := newWorld(ScopeLocal)
		w.daemon("1.30.0")
		if _, _, err := w.match(WorkBudget{Candidates: 250000}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.match(WorkBudget{Candidates: 250001}); !errors.Is(err, ErrInvalidBudget) {
			t.Fatal(err)
		}
	})
	t.Run("the errors of the budget have their words", func(t *testing.T) {
		if ErrWorkBudget.Error() != "advisory work budget exhausted" || ErrInvalidBudget.Error() != "invalid advisory work budget" {
			t.Fatalf("%q %q", ErrWorkBudget, ErrInvalidBudget)
		}
	})
}

func TestTimeCheckMessagesAreExact(t *testing.T) {
	floor := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		in   time.Time
		want string // empty: accepted
	}{
		{"the floor", floor, ""},
		{"a nanosecond before the floor", floor.Add(-time.Nanosecond), "timestamp before 2019-01-01T00:00:00Z"},
		{"another zone", floor.Add(time.Hour).In(time.FixedZone("plus one", 3600)), "timestamp must use UTC offset"},
		{"the last year JSON holds", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), ""},
	} {
		err := validateTime(tc.in)
		if (tc.want == "") != (err == nil) || (err != nil && err.Error() != tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := validateTime(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.HasPrefix(err.Error(), "invalid timestamp: ") {
		t.Errorf("year 10000: %v", err)
	}
}
