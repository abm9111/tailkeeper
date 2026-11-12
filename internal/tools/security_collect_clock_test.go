package tools_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A wall clock that steps back (a correction by NTP, a change of the system time) must not end
// a run: the duration of a source is measured by a monotonic clock, so it is never negative,
// and the times written into the snapshot never run backward, so no fact is acquired after
// the snapshot was observed. The run goes through a real App, whose audit record refuses an
// event with a negative time, as a run does. Timestamps still come from the injected clock.
func TestABackwardStepOfTheClockNeverEndsTheRun(t *testing.T) {
	for name, whenToStep := range map[string]string{
		"during the first source":         "request",
		"after the API source is written": "record",
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := newAppRig(t)
			var back atomic.Bool
			clock := func() time.Time {
				if back.Load() {
					return now.Add(-3 * time.Second)
				}
				return now
			}
			r.env.Now = clock
			switch whenToStep {
			case "request":
				r.f.Handle("GET", tailnetPath+"/devices", func(w http.ResponseWriter, _ *http.Request) {
					back.Store(true)
					time.Sleep(30 * time.Millisecond)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"devices":[` + mustJSON(t, dev("nA1CNTRL", nil)) + `]}`))
				})
			default:
				r.devices(dev("nA1CNTRL", nil))
				inner := r.forward
				r.forward = func(ctx context.Context, ev security.CollectionEvent) error {
					if ev.Source == security.SourceAPIDevices && ev.Phase == security.PhaseOutcome {
						back.Store(true)
					}
					return inner(ctx, ev)
				}
			}
			c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
			if err != nil {
				t.Fatalf("a clock that stepped back ended the run: %v", err)
			}
			requireValid(t, c)
			for _, o := range r.got {
				if o.ev.Phase == security.PhaseOutcome && (o.ev.Millis < 0 || o.ev.Millis > 10_000) {
					t.Errorf("%s took %d ms", o.ev.Source, o.ev.Millis)
				}
			}
			// The times written down are the injected clock's, and never go back: a step before the
			// first reading is that reading; a step after it is held at the reading before.
			want := now
			if whenToStep == "request" {
				want = now.Add(-3 * time.Second)
			}
			for _, v := range c.Snapshot.Versions {
				if v.Evidence.AcquiredAt.After(c.Snapshot.ObservedAt) {
					t.Errorf("a fact acquired at %s, after the snapshot was observed at %s", v.Evidence.AcquiredAt, c.Snapshot.ObservedAt)
				}
				if !v.Evidence.AcquiredAt.Equal(want) {
					t.Errorf("acquired at %s, want %s", v.Evidence.AcquiredAt, want)
				}
			}
			if !c.Snapshot.ObservedAt.Equal(want) {
				t.Errorf("observed at %s, want %s", c.Snapshot.ObservedAt, want)
			}
		})
	}
}

// The duration of a source is real elapsed time, not the difference of two readings of the
// injected clock, which a test (or a clock that is wrong) can freeze.
func TestTheDurationOfASourceIsMeasuredNotReadFromTheInjectedClock(t *testing.T) {
	r := newRig(t)
	r.f.Handle("GET", tailnetPath+"/devices", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	r.collect(security.ScopeFleet) // the injected clock stands still at now
	if ms := r.apiOutcome().Millis; ms < 60 || ms > 5000 {
		t.Errorf("the source took %d ms with a frozen clock, want about 80", ms)
	}
}
