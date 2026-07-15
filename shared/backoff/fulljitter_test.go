package backoff

import (
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func TestFullJitterWithinCeiling(t *testing.T) {
	// randFloat just below 1.0 draws the maximum of the interval.
	f := &FullJitter{Base: time.Second, Cap: 60 * time.Second, randFloat: func() float64 { return 0.999999 }}

	// attempt 0 ceiling = 1s, attempt 1 = 2s, ... doubling until the 60s cap.
	wantCeilings := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	for i, ceil := range wantCeilings {
		got := f.NextBackOff()
		if got < 0 || got > ceil {
			t.Fatalf("attempt %d: delay %s outside [0, %s]", i, got, ceil)
		}
		// with randFloat≈1 the draw should be very close to the ceiling
		if got < ceil-time.Millisecond {
			t.Fatalf("attempt %d: delay %s not near ceiling %s", i, got, ceil)
		}
	}
}

func TestFullJitterFullRange(t *testing.T) {
	// randFloat = 0 draws the floor (0); the calculator must allow a full
	// spread down to zero — that spread is what de-synchronizes the fleet.
	f := &FullJitter{Base: time.Second, Cap: 60 * time.Second, randFloat: func() float64 { return 0 }}
	if got := f.NextBackOff(); got != 0 {
		t.Fatalf("randFloat=0 should draw 0, got %s", got)
	}
}

func TestFullJitterResetRestartsGrowth(t *testing.T) {
	f := &FullJitter{Base: time.Second, Cap: 60 * time.Second, randFloat: func() float64 { return 0.999999 }}
	for i := 0; i < 4; i++ {
		f.NextBackOff()
	}
	f.Reset()
	// after reset the ceiling is Base again
	got := f.NextBackOff()
	if got > time.Second {
		t.Fatalf("after reset delay %s should be within Base ceiling 1s", got)
	}
}

func TestFullJitterMaxElapsedStops(t *testing.T) {
	now := time.Unix(0, 0)
	f := &FullJitter{
		Base:       time.Second,
		Cap:        60 * time.Second,
		MaxElapsed: 10 * time.Second,
		randFloat:  func() float64 { return 0.5 },
		now:        func() time.Time { return now },
	}
	f.Reset() // stamp start at now
	if got := f.NextBackOff(); got == backoff.Stop {
		t.Fatal("should not stop before MaxElapsed")
	}
	now = now.Add(11 * time.Second)
	if got := f.NextBackOff(); got != backoff.Stop {
		t.Fatalf("should stop after MaxElapsed, got %s", got)
	}
}

func TestFullJitterNoOverflowAtHighAttempt(t *testing.T) {
	// A long-lived open retry loop advances attempt far past the point where
	// Base<<attempt would overflow int64; the ceiling must stay clamped to Cap.
	f := &FullJitter{Base: time.Second, Cap: 60 * time.Second, randFloat: func() float64 { return 0.999999 }}
	for i := 0; i < 200; i++ {
		got := f.NextBackOff()
		if got < 0 || got > 60*time.Second {
			t.Fatalf("attempt %d: delay %s outside [0, 60s]", i, got)
		}
	}
}

// FullJitter must satisfy the cenkalti BackOff interface so it drops into
// backoff.NewTicker / backoff.Retry.
var _ backoff.BackOff = (*FullJitter)(nil)
