package client

import (
	"testing"

	"golang.org/x/crypto/blake2s"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	sigproto "github.com/netbirdio/netbird/shared/signal/proto"
)

// ADR 1134 D2/D3 — send the digest, resolve the key once.
//
// These tests assert the WIRE SIZE, because the wire size is the entire point.
// F-338: a 524,160-byte Classic McEliece static public key in every OFFER and
// ANSWER was 99.3% of signal bytes on a live deployment.

func spk(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 524160)
	for i := range b[:256] {
		b[i] = byte(i)
	}
	return b
}

func offer(t *testing.T, key []byte, remoteFeatures []uint32) *sigproto.Message {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	m, err := MarshalCredentialFor(k, r.PublicKey().String(), CredentialPayload{
		Type:            sigproto.Body_OFFER,
		WgListenPort:    51820,
		Credential:      &Credential{UFrag: "abcd1234", Pwd: "0123456789abcdef0123456789abcdef"},
		RosenpassPubKey: key,
		RosenpassAddr:   "100.64.0.5:9999",
		RelaySrvAddress: "rels://relay.example.net:443",
		SessionID:       []byte("session-id-16byt"),
	}, remoteFeatures)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func size(t *testing.T, m *sigproto.Message) int {
	t.Helper()
	b, err := proto.Marshal(m.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// A peer that has not advertised digest support gets the full key, unchanged.
// This is the interop guarantee: no flag day, no broken older clients.
func TestOfferToLegacyPeerStillCarriesTheFullKey(t *testing.T) {
	m := offer(t, spk(t), nil)
	if got := len(m.GetBody().GetRosenpassConfig().GetRosenpassPubKey()); got != 524160 {
		t.Fatalf("expected the full key for a legacy peer, got %d bytes", got)
	}
	if d := m.GetBody().GetRosenpassConfig().GetRosenpassPubKeyDigest(); len(d) != 0 {
		t.Fatalf("sent a digest to a peer that never asked for one")
	}
	t.Logf("legacy peer: offer body %d bytes", size(t, m))
}

// A peer that advertised the capability gets 32 bytes.
func TestOfferToCapablePeerCarriesOnlyTheDigest(t *testing.T) {
	key := spk(t)
	m := offer(t, key, []uint32{DirectCheck, RosenpassKeyByDigest})

	if got := len(m.GetBody().GetRosenpassConfig().GetRosenpassPubKey()); got != 0 {
		t.Fatalf("still sent %d bytes of key to a digest-capable peer", got)
	}
	want := blake2s.Sum256(key)
	got := m.GetBody().GetRosenpassConfig().GetRosenpassPubKeyDigest()
	if len(got) != 32 {
		t.Fatalf("expected a 32-byte digest, got %d", len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatal("digest does not match BLAKE2s of the key")
		}
	}
}

// The number the whole finding is about.
func TestDigestModeCutsTheOfferBy99Percent(t *testing.T) {
	key := spk(t)
	legacy := size(t, offer(t, key, nil))
	digest := size(t, offer(t, key, []uint32{RosenpassKeyByDigest}))

	reduction := 1 - float64(digest)/float64(legacy)
	t.Logf("offer body: %d bytes -> %d bytes (%.2f%% reduction)", legacy, digest, reduction*100)

	// Measured live on EFDI: 2.93 large offers/sec.
	const offersPerSec = 2.93
	t.Logf("at the live 2.93 offers/sec: %.2f Mbit/s -> %.4f Mbit/s",
		float64(legacy)*8*offersPerSec/1e6, float64(digest)*8*offersPerSec/1e6)

	if reduction < 0.98 {
		t.Fatalf("expected >=98%% reduction, got %.2f%%", reduction*100)
	}
}

// We must advertise, or no peer can ever choose digest mode for us.
func TestWeAdvertiseTheCapability(t *testing.T) {
	m := offer(t, spk(t), nil)
	if !SupportsFeature(m.GetBody().GetFeaturesSupported(), RosenpassKeyByDigest) {
		t.Fatal("offer does not advertise RosenpassKeyByDigest — no peer can negotiate with us")
	}
	if !SupportsFeature(m.GetBody().GetFeaturesSupported(), DirectCheck) {
		t.Fatal("dropped the pre-existing DirectCheck advertisement")
	}
}

// The key-request round trip: exactly one message may carry the full key.
func TestKeyRequestAndReply(t *testing.T) {
	key := spk(t)
	d := blake2s.Sum256(key)
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	req := MarshalRosenpassKeyRequest(k, r.PublicKey().String(), d[:])
	if req.GetBody().GetType() != sigproto.Body_ROSENPASS_KEY_REQUEST {
		t.Fatal("wrong request type")
	}
	reqSize := size(t, req)
	if reqSize > 500 {
		t.Fatalf("a key REQUEST should be tiny, got %d bytes", reqSize)
	}

	reply := MarshalRosenpassKey(k, r.PublicKey().String(), key)
	if reply.GetBody().GetType() != sigproto.Body_ROSENPASS_KEY {
		t.Fatal("wrong reply type")
	}
	if len(reply.GetBody().GetRosenpassConfig().GetRosenpassPubKey()) != 524160 {
		t.Fatal("reply must carry the full key")
	}
	t.Logf("key request %d bytes, key reply %d bytes — paid ONCE per peer-pair",
		reqSize, size(t, reply))
}
