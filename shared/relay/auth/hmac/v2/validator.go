package v2

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const minLengthUnixTimestamp = 10

type Validator struct {
	secret []byte
}

func NewValidator(secret []byte) *Validator {
	return &Validator{secret: secret}
}

// PeerBoundCredentials carries both the raw token bytes and the claimed
// relay peer_id (from the Auth frame) so the validator can verify a
// peer-ID-bound token (goat ADR 1021, AuthAlgoHMACSHA256PeerBound).
// Callers that have no peer_id context may pass the raw []byte token
// instead — that path validates AuthAlgoHMACSHA256 (unbound) only and
// rejects peer-bound tokens for lack of a peer_id to verify against.
type PeerBoundCredentials struct {
	PeerID []byte
	Token  []byte
}

func (v *Validator) Validate(data any) error {
	var raw, peerID []byte
	switch d := data.(type) {
	case []byte:
		raw = d
	case PeerBoundCredentials:
		raw, peerID = d.Token, d.PeerID
	case *PeerBoundCredentials:
		raw, peerID = d.Token, d.PeerID
	default:
		return fmt.Errorf("invalid data type")
	}

	token, err := UnmarshalToken(raw)
	if err != nil {
		return fmt.Errorf("unmarshal token: %w", err)
	}

	if len(token.Payload) < minLengthUnixTimestamp {
		return errors.New("invalid payload: insufficient length")
	}

	hashFunc := token.AuthAlgo.New()
	if hashFunc == nil {
		return fmt.Errorf("unsupported auth algorithm: %s", token.AuthAlgo)
	}

	// Peer-bound tokens (ADR 1021) sign peer_id || payload; unbound tokens
	// sign payload only. For peer-bound we require the claimed peer_id from
	// the Auth frame — without it we cannot verify the binding and must
	// reject rather than silently fall back to an unbound check.
	h := hmac.New(hashFunc, v.secret)
	if token.AuthAlgo == AuthAlgoHMACSHA256PeerBound {
		if len(peerID) == 0 {
			return errors.New("peer-bound token presented without peer id context")
		}
		h.Write(peerID)
	}
	h.Write(token.Payload)
	expectedMAC := h.Sum(nil)

	if !hmac.Equal(token.Signature, expectedMAC) {
		return errors.New("invalid signature")
	}

	timestamp, err := strconv.ParseInt(string(token.Payload), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if time.Now().Unix() > timestamp {
		return fmt.Errorf("expired token")
	}

	return nil
}
