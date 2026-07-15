// Package backoff provides a full-jitter exponential backoff calculator used
// by the NetBird client to keep control-plane retry load decaying when
// delivery fails.
//
// Introduced for goat ADR 1081 (control-plane storm resilience), Layer 1:
// the 2026-07-15 EFDI collapse was caused by ~90 clients retrying signal
// offers and stream re-registration at a fixed cadence regardless of outcome,
// saturating a degraded uplink. Full jitter spreads retries across the whole
// interval so a fleet that loses its signal streams together does not
// re-storm together.
package backoff

import (
	"math/bits"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// FullJitter is an exponential backoff with AWS-style full jitter: each delay
// is drawn uniformly from [0, min(Cap, Base*2^attempt)]. It implements
// github.com/cenkalti/backoff/v4.BackOff so it drops into backoff.NewTicker
// and backoff.Retry in place of an ExponentialBackOff.
//
// Zero value is not usable; set Base and Cap. Not safe for concurrent use —
// each retry loop owns its own instance, matching the ExponentialBackOff it
// replaces.
type FullJitter struct {
	// Base is the first interval's ceiling (attempt 0 draws from [0, Base]).
	Base time.Duration
	// Cap bounds the growing interval; the draw ceiling never exceeds Cap.
	Cap time.Duration
	// MaxElapsed, if > 0, gives up (returns backoff.Stop) once this much time
	// has passed since the last Reset. 0 means never give up.
	MaxElapsed time.Duration

	// randFloat returns a value in [0.0, 1.0); nil uses the default source.
	// Injectable for deterministic tests.
	randFloat func() float64
	// now returns the current time; nil uses time.Now. Injectable for tests.
	now func() time.Time

	attempt int
	start   time.Time
}

// Reset returns the backoff to its initial state and restarts the MaxElapsed
// clock. Call it after a successful delivery so the next failure retries
// promptly rather than at the grown interval.
func (f *FullJitter) Reset() {
	f.attempt = 0
	f.start = f.clock()
}

// NextBackOff returns the next delay, or backoff.Stop if MaxElapsed is
// exceeded.
func (f *FullJitter) NextBackOff() time.Duration {
	if f.start.IsZero() {
		f.start = f.clock()
	}
	if f.MaxElapsed > 0 && f.clock().Sub(f.start) >= f.MaxElapsed {
		return backoff.Stop
	}

	ceiling := f.ceilingFor(f.attempt)
	f.attempt++
	return time.Duration(f.random() * float64(ceiling))
}

// ceilingFor returns min(Cap, Base*2^attempt), guarding against the shift
// overflowing int64 for large attempt counts (a long-lived open retry loop).
func (f *FullJitter) ceilingFor(attempt int) time.Duration {
	if f.Base <= 0 {
		return f.Cap
	}
	// If Base*2^attempt would overflow, clamp to Cap. bits.LeadingZeros64
	// tells us how many left-shifts Base tolerates before overflow.
	if attempt >= bits.LeadingZeros64(uint64(f.Base)) {
		return f.Cap
	}
	scaled := f.Base << uint(attempt)
	if scaled <= 0 || scaled > f.Cap {
		return f.Cap
	}
	return scaled
}

func (f *FullJitter) random() float64 {
	if f.randFloat != nil {
		return f.randFloat()
	}
	return rand.Float64()
}

func (f *FullJitter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}
