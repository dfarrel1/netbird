package rosenpass

import (
	"sync"

	"golang.org/x/crypto/blake2s"
)

// DigestSize is the length of a Rosenpass static-public-key digest on the wire.
const DigestSize = blake2s.Size // 32

// KeyCache maps a Rosenpass static-public-key digest to the full key.
//
// WHY THIS EXISTS (F-338). A Rosenpass v1 static public key is Classic McEliece
// 460896: 524,160 bytes. NetBird historically placed that whole key in every
// signal OFFER and ANSWER, so a routine peer handshake cost half a megabyte and
// repeated for as long as the far peer stayed unreachable. On a live deployment
// that was 99.3% of all signal bytes, and it cost peers two thirds of their
// connections — the offers saturated the client's own uplink and starved ICE of
// the small CANDIDATE messages that actually establish a link.
//
// The key is generated once per process (Manager.spk, set in NewManager and
// returned unchanged by GetPubKey), so every re-send was a byte-identical
// re-upload of a constant. Caching it by digest turns an O(peer-pairs × time)
// cost into O(peers) once.
//
// Concurrency: safe for concurrent use. Entries are never evicted — a fleet of
// 10,000 peers holds ~5 GB, which is why callers should bound membership by the
// peer set they actually signal with rather than by cache policy. In practice a
// client holds one entry per peer it has handshaked with.
type KeyCache struct {
	mu   sync.RWMutex
	keys map[[DigestSize]byte][]byte
}

// NewKeyCache returns an empty cache.
func NewKeyCache() *KeyCache {
	return &KeyCache{keys: make(map[[DigestSize]byte][]byte)}
}

// Digest is the wire digest of a Rosenpass static public key.
//
// BLAKE2s-256 rather than SHA-256 because Rosenpass v1 already uses BLAKE2s
// throughout its own suite, so this adds no new primitive to the client.
func Digest(spk []byte) [DigestSize]byte {
	return blake2s.Sum256(spk)
}

// Put records a key under its own digest and returns that digest. Putting the
// same key twice is a no-op.
func (c *KeyCache) Put(spk []byte) [DigestSize]byte {
	d := Digest(spk)
	if len(spk) == 0 {
		return d
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.keys[d]; !ok {
		// Copy: the caller may reuse or mutate its buffer, and a cache holding
		// an aliased slice would hand out a key that silently changed.
		cp := make([]byte, len(spk))
		copy(cp, spk)
		c.keys[d] = cp
	}
	return d
}

// Get resolves a digest to the full key. ok is false on a miss, which is the
// caller's cue to send a ROSENPASS_KEY_REQUEST.
func (c *KeyCache) Get(digest []byte) ([]byte, bool) {
	if len(digest) != DigestSize {
		return nil, false
	}
	var d [DigestSize]byte
	copy(d[:], digest)
	c.mu.RLock()
	defer c.mu.RUnlock()
	k, ok := c.keys[d]
	return k, ok
}

// PutVerified records a key ONLY if it actually hashes to the digest we asked
// for. This is the trust boundary: a peer answering a ROSENPASS_KEY_REQUEST
// could return any bytes, and accepting them unchecked would let it swap the
// static key of the identity we are about to encapsulate to.
//
// Returns false if the key does not match, in which case the caller must
// discard it and must NOT complete a handshake against it.
func (c *KeyCache) PutVerified(digest, spk []byte) bool {
	if len(digest) != DigestSize || len(spk) == 0 {
		return false
	}
	got := Digest(spk)
	var want [DigestSize]byte
	copy(want[:], digest)
	if got != want {
		return false
	}
	c.Put(spk)
	return true
}

// Len reports how many distinct keys are held. Test and metrics use only.
func (c *KeyCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}
