package hmac

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"sync"
	"time"

	v2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

// expiredUseNotifyInterval rate-limits the expired-token-use callback:
// relay reconnect loops retry aggressively, and each refused attempt
// must not trigger another full client restart.
const expiredUseNotifyInterval = 5 * time.Minute

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
//
// F-269: the store also tracks the token's own expiry (the payload IS
// the unix expiry timestamp) and carries an escalation callback for
// when a caller is about to present an already-expired token. A token
// only ages out here when the management sync stream that pushes
// refreshes (at 3/4 TTL) has been silently dead for longer than the
// TTL — retrying the relay with it can never succeed; only a fresh
// management login can heal it.
type TokenStore struct {
	mu             sync.Mutex
	token          []byte
	expiresAt      time.Time
	onExpiredUse   func()
	lastExpiredUse time.Time
}

func (a *TokenStore) UpdateToken(token *Token) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if token == nil {
		return nil
	}

	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	tok := v2.Token{
		AuthAlgo:  v2.AuthAlgoHMACSHA256,
		Signature: sig,
		Payload:   []byte(token.Payload),
	}

	a.token = tok.Marshal()
	// The payload is the ASCII-decimal unix expiry stamped by
	// management. Unparseable → zero time = "expiry unknown" (never
	// refuse on it).
	if ts, err := strconv.ParseInt(token.Payload, 10, 64); err == nil {
		a.expiresAt = time.Unix(ts, 0)
	} else {
		a.expiresAt = time.Time{}
	}
	return nil
}

func (a *TokenStore) TokenBinary() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}

// TokenExpired reports whether the stored token is known to be past
// its own expiry. Unknown expiry (no token yet, or unparseable
// payload) is never "expired" — refusal is only for tokens that
// provably cannot authenticate.
func (a *TokenStore) TokenExpired(now time.Time) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.expiresAt.IsZero() && now.After(a.expiresAt)
}

// SetOnExpiredUse registers the escalation callback fired (rate-limited)
// when a caller was refused for presenting an expired token.
func (a *TokenStore) SetOnExpiredUse(f func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onExpiredUse = f
}

// NotifyExpiredUse fires the escalation callback, at most once per
// expiredUseNotifyInterval. Safe to call from any goroutine; the
// callback runs without the store lock held.
func (a *TokenStore) NotifyExpiredUse(now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	f := a.onExpiredUse
	if f == nil || now.Sub(a.lastExpiredUse) < expiredUseNotifyInterval {
		a.mu.Unlock()
		return
	}
	a.lastExpiredUse = now
	a.mu.Unlock()
	f()
}
