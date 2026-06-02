package v2

import (
	"strconv"
	"testing"
	"time"
)

func TestGenerateCredentials(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(token.Payload) == 0 {
		t.Fatalf("expected non-empty payload")
	}

	_, err = strconv.ParseInt(string(token.Payload), 10, 64)
	if err != nil {
		t.Fatalf("expected payload to be a valid unix timestamp, got %v", err)
	}
}

func TestValidateCredentials(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err != nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token.Signature = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestExpired(t *testing.T) {
	secret := "supersecret"
	timeToLive := -1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestInvalidPayload(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token.Payload = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected invalid token due to invalid payload")
	}
}

// --- Peer-ID-bound tokens (goat ADR 1021) ---------------------------------

func peerIDBytes(b byte) []byte {
	id := make([]byte, 36)
	copy(id, []byte("sha-"))
	for i := 4; i < 36; i++ {
		id[i] = b
	}
	return id
}

func TestPeerBoundValidate(t *testing.T) {
	secret := "supersecret"
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), time.Hour)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}
	peer := peerIDBytes(0xAA)

	token, err := g.GenerateTokenBound(peer)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token.AuthAlgo != AuthAlgoHMACSHA256PeerBound {
		t.Fatalf("expected peer-bound algo, got %s", token.AuthAlgo)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(PeerBoundCredentials{PeerID: peer, Token: token.Marshal()}); err != nil {
		t.Fatalf("expected valid peer-bound token: %s", err)
	}
}

func TestPeerBoundWrongPeerRejected(t *testing.T) {
	// The core impersonation defense: a token minted for peer A must not
	// validate when the Auth frame claims peer B.
	secret := "supersecret"
	g, _ := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), time.Hour)
	peerA := peerIDBytes(0xAA)
	peerB := peerIDBytes(0xBB)

	token, err := g.GenerateTokenBound(peerA)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(PeerBoundCredentials{PeerID: peerA, Token: token.Marshal()}); err != nil {
		t.Fatalf("expected valid token for peer A: %s", err)
	}
	if err := v.Validate(PeerBoundCredentials{PeerID: peerB, Token: token.Marshal()}); err == nil {
		t.Fatalf("expected peer A's token to be rejected when presented as peer B")
	}
}

func TestPeerBoundWithoutPeerIDRejected(t *testing.T) {
	// A peer-bound token validated with no peer_id context (raw []byte path)
	// must be rejected — we cannot verify the binding.
	secret := "supersecret"
	g, _ := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), time.Hour)
	token, err := g.GenerateTokenBound(peerIDBytes(0xAA))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected peer-bound token to be rejected without peer id context")
	}
}

func TestUnboundTokenViaPeerBoundCredentials(t *testing.T) {
	// An unbound (algo-1) token still validates when delivered through the
	// PeerBoundCredentials path; the peer_id is simply ignored.
	secret := "supersecret"
	g, _ := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), time.Hour)
	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(PeerBoundCredentials{PeerID: peerIDBytes(0x11), Token: token.Marshal()}); err != nil {
		t.Fatalf("expected valid unbound token via peer-bound path: %s", err)
	}
}
