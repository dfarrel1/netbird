package hmac

import (
	"encoding/base64"
	"fmt"
	"sync"

	v2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
type TokenStore struct {
	mu    sync.Mutex
	token []byte
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

	// Use the algorithm the server selected (goat ADR 1021). 0/unset means
	// the server is older / issuing unbound tokens → default to
	// AuthAlgoHMACSHA256 for backward compatibility. The client only
	// replays the server-computed signature; for peer-bound tokens the
	// binding is verified relay-side against the Auth frame's peer_id, so
	// the client does no extra crypto — it just stamps the right algo byte.
	algo := v2.AuthAlgo(token.AuthAlgo)
	if algo == v2.AuthAlgoUnknown {
		algo = v2.AuthAlgoHMACSHA256
	}

	tok := v2.Token{
		AuthAlgo:  algo,
		Signature: sig,
		Payload:   []byte(token.Payload),
	}

	a.token = tok.Marshal()
	return nil
}

func (a *TokenStore) TokenBinary() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}
