package hmac

import (
	"strconv"
	"testing"
	"time"
)

// F-269: the store must know its token's own expiry (the payload IS the
// unix expiry) and escalate — rate-limited — when an expired token was
// about to be presented.

func TestTokenStoreExpiry(t *testing.T) {
	now := time.Now()
	s := &TokenStore{}

	if s.TokenExpired(now) {
		t.Fatal("empty store must never report expired")
	}

	fresh := &Token{Payload: strconv.FormatInt(now.Add(time.Hour).Unix(), 10), Signature: "c2ln"}
	if err := s.UpdateToken(fresh); err != nil {
		t.Fatalf("UpdateToken fresh: %v", err)
	}
	if s.TokenExpired(now) {
		t.Error("fresh token reported expired")
	}
	if !s.TokenExpired(now.Add(2 * time.Hour)) {
		t.Error("aged-out token not reported expired")
	}

	// Unparseable payload = unknown expiry = never refuse.
	weird := &Token{Payload: "not-a-timestamp", Signature: "c2ln"}
	if err := s.UpdateToken(weird); err != nil {
		t.Fatalf("UpdateToken weird: %v", err)
	}
	if s.TokenExpired(now.Add(1000 * time.Hour)) {
		t.Error("unknown-expiry token must never report expired")
	}

	// nil receiver is safe (test fixtures construct clients without a store).
	var nilStore *TokenStore
	if nilStore.TokenExpired(now) {
		t.Error("nil store must report not-expired")
	}
	nilStore.NotifyExpiredUse(now) // must not panic
}

func TestNotifyExpiredUseRateLimited(t *testing.T) {
	s := &TokenStore{}
	fired := 0
	s.SetOnExpiredUse(func() { fired++ })

	base := time.Now()
	s.NotifyExpiredUse(base)
	s.NotifyExpiredUse(base.Add(time.Second))
	s.NotifyExpiredUse(base.Add(2 * time.Second))
	if fired != 1 {
		t.Errorf("burst fired %d times, want 1 (rate limit)", fired)
	}
	s.NotifyExpiredUse(base.Add(expiredUseNotifyInterval + time.Second))
	if fired != 2 {
		t.Errorf("post-interval notify fired %d times total, want 2", fired)
	}
}
