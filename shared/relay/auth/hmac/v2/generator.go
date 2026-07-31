package v2

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"strconv"
	"time"
)

type Generator struct {
	algo       func() hash.Hash
	algoType   AuthAlgo
	secret     []byte
	timeToLive time.Duration
}

func NewGenerator(algo AuthAlgo, secret []byte, timeToLive time.Duration) (*Generator, error) {
	algoFunc := algo.New()
	if algoFunc == nil {
		return nil, fmt.Errorf("unsupported auth algorithm: %s", algo)
	}
	return &Generator{
		algo:       algoFunc,
		algoType:   algo,
		secret:     secret,
		timeToLive: timeToLive,
	}, nil
}

func (g *Generator) GenerateToken() (*Token, error) {
	expirationTime := time.Now().Add(g.timeToLive).Unix()

	payload := []byte(strconv.FormatInt(expirationTime, 10))

	h := hmac.New(g.algo, g.secret)
	h.Write(payload)
	signature := h.Sum(nil)

	return &Token{
		AuthAlgo:  g.algoType,
		Signature: signature,
		Payload:   payload,
	}, nil
}

// GenerateTokenBound generates a peer-ID-bound token (goat ADR 1021): the
// signature is HMAC over binding || payload, where binding is the relay
// peer_id (messages.HashID(peerKey) wire bytes). The resulting token's
// AuthAlgo is AuthAlgoHMACSHA256PeerBound regardless of g.algoType — the
// hash is the same (SHA-256); only the signed message and the algo tag
// differ. The validator recomputes the MAC using the claimed peer_id from
// the Auth frame, so a token issued for one peer fails for any other.
func (g *Generator) GenerateTokenBound(binding []byte) (*Token, error) {
	expirationTime := time.Now().Add(g.timeToLive).Unix()

	payload := []byte(strconv.FormatInt(expirationTime, 10))

	h := hmac.New(g.algo, g.secret)
	h.Write(binding)
	h.Write(payload)
	signature := h.Sum(nil)

	return &Token{
		AuthAlgo:  AuthAlgoHMACSHA256PeerBound,
		Signature: signature,
		Payload:   payload,
	}, nil
}
