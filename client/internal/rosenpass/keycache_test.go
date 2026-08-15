package rosenpass

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

// spk of the real size, so the tests exercise the actual memory shape.
func fakeSPK(t *testing.T, seed byte) []byte {
	t.Helper()
	b := make([]byte, 524160)
	if _, err := rand.Read(b[:64]); err != nil {
		t.Fatal(err)
	}
	b[0] = seed
	return b
}

func TestKeyCacheRoundTrip(t *testing.T) {
	c := NewKeyCache()
	spk := fakeSPK(t, 1)

	empty := Digest(spk)
	if _, ok := c.Get(empty[:]); ok {
		t.Fatal("empty cache returned a key")
	}

	d := c.Put(spk)
	got, ok := c.Get(d[:])
	if !ok {
		t.Fatal("key not found after Put")
	}
	if !bytes.Equal(got, spk) {
		t.Fatal("returned key differs from stored key")
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.Len())
	}
	c.Put(spk)
	if c.Len() != 1 {
		t.Fatalf("re-Put created a duplicate: %d entries", c.Len())
	}
}

// The cache must not alias the caller's buffer — a client that reuses a scratch
// slice would otherwise mutate a cached key and hand out something that hashes
// to a different digest than the one it is filed under.
func TestKeyCacheCopiesTheKey(t *testing.T) {
	c := NewKeyCache()
	spk := fakeSPK(t, 2)
	d := c.Put(spk)

	spk[0] ^= 0xFF // caller mutates its buffer

	got, ok := c.Get(d[:])
	if !ok {
		t.Fatal("key vanished")
	}
	if got[0] == spk[0] {
		t.Fatal("cache aliased the caller's slice")
	}
	if Digest(got) != d {
		t.Fatal("cached key no longer hashes to its own digest")
	}
}

// PutVerified is the trust boundary. A peer answering ROSENPASS_KEY_REQUEST can
// return anything; accepting it unchecked would let it substitute the static key
// of the identity we are about to encapsulate to.
func TestKeyCacheRejectsAKeyThatDoesNotMatchTheDigest(t *testing.T) {
	c := NewKeyCache()
	real := fakeSPK(t, 3)
	attacker := fakeSPK(t, 4)
	d := Digest(real)

	if c.PutVerified(d[:], attacker) {
		t.Fatal("accepted a key that does not hash to the requested digest")
	}
	if c.Len() != 0 {
		t.Fatal("a rejected key was stored anyway")
	}
	if _, ok := c.Get(d[:]); ok {
		t.Fatal("rejected key is resolvable")
	}

	if !c.PutVerified(d[:], real) {
		t.Fatal("rejected the genuine key")
	}
	got, ok := c.Get(d[:])
	if !ok || !bytes.Equal(got, real) {
		t.Fatal("genuine key not stored correctly")
	}
}

func TestKeyCacheRejectsMalformedInput(t *testing.T) {
	c := NewKeyCache()
	spk := fakeSPK(t, 5)
	d := Digest(spk)

	if c.PutVerified(d[:len(d)-1], spk) {
		t.Fatal("accepted a short digest")
	}
	if c.PutVerified(d[:], nil) {
		t.Fatal("accepted an empty key")
	}
	if _, ok := c.Get([]byte{1, 2, 3}); ok {
		t.Fatal("resolved a malformed digest")
	}
}

func TestKeyCacheConcurrent(t *testing.T) {
	c := NewKeyCache()
	keys := make([][]byte, 8)
	for i := range keys {
		keys[i] = fakeSPK(t, byte(i))
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := keys[i%len(keys)]
			d := c.Put(k)
			if _, ok := c.Get(d[:]); !ok {
				t.Error("key missing immediately after Put")
			}
		}(i)
	}
	wg.Wait()
	if c.Len() != len(keys) {
		t.Fatalf("expected %d distinct keys, got %d", len(keys), c.Len())
	}
}

// The whole point, stated in bytes.
func TestDigestIsTheWholeSaving(t *testing.T) {
	spk := fakeSPK(t, 9)
	d := Digest(spk)
	t.Logf("static public key %d bytes -> digest %d bytes (%.4f%% of the size)",
		len(spk), len(d), 100*float64(len(d))/float64(len(spk)))
	if len(d) != 32 {
		t.Fatalf("expected a 32-byte digest, got %d", len(d))
	}
	if len(spk) != 524160 {
		t.Fatalf("test fixture is not the real key size: %d", len(spk))
	}
}
