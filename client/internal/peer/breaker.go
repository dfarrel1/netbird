package peer

import (
	"sync"
	"time"
)

// goat ADR 1081 (control-plane storm resilience) Layer 1: per-peer-pair offer
// circuit breaker.
//
// During the 2026-07-15 EFDI collapse, clients kept sending offers to peers
// whose signal streams were absent — the sends failed (notfound / deadline)
// but the retry cadence never relented, so ~90 peers poured undeliverable
// offers into a saturated uplink. The breaker makes that load decay: after a
// run of failed sends to one peer it stops blind-retrying, and re-dials only
// on a positive signal — either management reporting that peer online again
// (an event the client already receives on every network-map update) or a
// slow fallback probe if that event is lost.
const (
	// breakerFailureThreshold is the number of consecutive failed offer sends
	// to one peer before the breaker opens.
	breakerFailureThreshold = 5
	// breakerProbeInterval is the fallback half-open window: if no online
	// report arrives, the breaker still permits one probe this often. It is
	// the safety net for a lost network-map event, not the primary re-dial
	// path (that is OnPeerReportedOnline).
	breakerProbeInterval = 5 * time.Minute
)

type breakerState int

const (
	breakerClosed   breakerState = iota // sends allowed; counting failures
	breakerOpen                         // sends suppressed until a probe is permitted
	breakerHalfOpen                     // exactly one probe permitted
)

// pairBreaker is the offer circuit breaker for a single peer-pair. Safe for
// concurrent use: the guard loop calls Allow/OnResult while the engine calls
// OnPeerReportedOnline from the management update path.
type pairBreaker struct {
	mu       sync.Mutex
	state    breakerState
	failures int
	openedAt time.Time

	// now is injectable for tests; nil uses time.Now.
	now func() time.Time
}

func newPairBreaker() *pairBreaker {
	return &pairBreaker{state: breakerClosed}
}

func (b *pairBreaker) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// Allow reports whether an offer send should proceed now. When the breaker is
// open it stays suppressed until breakerProbeInterval has elapsed, at which
// point it transitions to half-open and permits a single probe.
func (b *pairBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case breakerOpen:
		if b.clock().Sub(b.openedAt) >= breakerProbeInterval {
			b.state = breakerHalfOpen
			return true
		}
		return false
	default: // breakerClosed, breakerHalfOpen
		return true
	}
}

// OnResult records the outcome of an attempted offer send. Success closes the
// breaker; a failure counts toward the threshold when closed, or re-opens the
// breaker (restarting the probe timer) when it was a half-open probe.
func (b *pairBreaker) OnResult(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if success {
		b.state = breakerClosed
		b.failures = 0
		return
	}

	switch b.state {
	case breakerHalfOpen:
		b.state = breakerOpen
		b.openedAt = b.clock()
	case breakerClosed:
		b.failures++
		if b.failures >= breakerFailureThreshold {
			b.state = breakerOpen
			b.openedAt = b.clock()
		}
	}
}

// OnPeerReportedOnline is the positive management signal that a peer is
// reachable again. It half-opens an open breaker so the next guard tick probes
// immediately instead of waiting out breakerProbeInterval. It never suppresses
// a closed breaker.
func (b *pairBreaker) OnPeerReportedOnline() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == breakerOpen {
		b.state = breakerHalfOpen
	}
}
