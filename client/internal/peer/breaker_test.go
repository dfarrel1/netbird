package peer

import (
	"testing"
	"time"
)

func TestBreakerOpensAfterThreshold(t *testing.T) {
	b := newPairBreaker()

	// below threshold the breaker stays closed and keeps allowing sends
	for i := 0; i < breakerFailureThreshold-1; i++ {
		if !b.Allow() {
			t.Fatalf("send %d should be allowed while closed", i)
		}
		b.OnResult(false)
	}
	if !b.Allow() {
		t.Fatal("still closed before the threshold-crossing failure")
	}
	b.OnResult(false) // threshold-th consecutive failure -> open

	if b.Allow() {
		t.Fatal("breaker should be open and suppress sends after threshold failures")
	}
}

func TestBreakerSuccessResetsFailureRun(t *testing.T) {
	b := newPairBreaker()
	for i := 0; i < breakerFailureThreshold-1; i++ {
		b.OnResult(false)
	}
	b.OnResult(true) // success resets the run

	// a fresh run of failures below threshold must not open the breaker
	for i := 0; i < breakerFailureThreshold-1; i++ {
		b.OnResult(false)
	}
	if !b.Allow() {
		t.Fatal("breaker should still be closed; success reset the failure count")
	}
}

func TestBreakerTimerFallbackHalfOpen(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newPairBreaker()
	b.now = func() time.Time { return now }

	for i := 0; i < breakerFailureThreshold; i++ {
		b.OnResult(false)
	}
	if b.Allow() {
		t.Fatal("breaker open, should suppress before probe window")
	}

	now = now.Add(breakerProbeInterval - time.Second)
	if b.Allow() {
		t.Fatal("still inside probe window, should suppress")
	}

	now = now.Add(2 * time.Second) // now past breakerProbeInterval
	if !b.Allow() {
		t.Fatal("probe window elapsed, should permit one half-open probe")
	}
	// a failed probe re-opens and restarts the window
	b.OnResult(false)
	if b.Allow() {
		t.Fatal("failed probe should re-open the breaker")
	}
}

func TestBreakerPeerOnlineHalfOpensImmediately(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newPairBreaker()
	b.now = func() time.Time { return now }

	for i := 0; i < breakerFailureThreshold; i++ {
		b.OnResult(false)
	}
	if b.Allow() {
		t.Fatal("breaker should be open")
	}

	// mgmt reports the peer online well before the fallback window
	b.OnPeerReportedOnline()
	if !b.Allow() {
		t.Fatal("online report should half-open the breaker for an immediate probe")
	}
	// a successful probe closes the breaker
	b.OnResult(true)
	if !b.Allow() {
		t.Fatal("successful probe should close the breaker")
	}
}

func TestBreakerOnlineReportNoopWhenClosed(t *testing.T) {
	b := newPairBreaker()
	b.OnPeerReportedOnline() // must not disturb a healthy closed breaker
	if !b.Allow() {
		t.Fatal("closed breaker must keep allowing sends")
	}
}
