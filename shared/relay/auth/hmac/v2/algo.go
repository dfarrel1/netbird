package v2

import (
	"crypto/sha256"
	"hash"
)

const (
	AuthAlgoUnknown AuthAlgo = iota
	AuthAlgoHMACSHA256
	// AuthAlgoHMACSHA256PeerBound is HMAC-SHA256 over peer_id || payload
	// (goat ADR 1021). Same hash as AuthAlgoHMACSHA256; the difference is
	// that the signature additionally binds the token to the relay
	// peer_id, so a token issued for one peer cannot be replayed as
	// another. The binding is enforced by the validator, which is given
	// the claimed peer_id from the Auth frame.
	AuthAlgoHMACSHA256PeerBound
)

type AuthAlgo uint8

func (a AuthAlgo) String() string {
	switch a {
	case AuthAlgoHMACSHA256:
		return "HMAC-SHA256"
	case AuthAlgoHMACSHA256PeerBound:
		return "HMAC-SHA256-PeerBound"
	default:
		return "Unknown"
	}
}

func (a AuthAlgo) New() func() hash.Hash {
	switch a {
	case AuthAlgoHMACSHA256, AuthAlgoHMACSHA256PeerBound:
		return sha256.New
	default:
		return nil
	}
}

func (a AuthAlgo) Size() int {
	switch a {
	case AuthAlgoHMACSHA256, AuthAlgoHMACSHA256PeerBound:
		return sha256.Size
	default:
		return 0
	}
}
