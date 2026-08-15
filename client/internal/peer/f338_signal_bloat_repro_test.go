package peer

// F-338 reproduction — two independent defects that multiply into ~19 Mbit/s of
// wasted relay-ingress bandwidth on EFDI.
//
// Measured live on mgmt-efdi-01-thor 2026-08-15, from Traefik RequestContentSize
// (application layer, after TLS termination), 10,251 signal requests / 4 min:
//
//	93.2% of requests <1 KB        ->  0.7% of bytes
//	 6.8% of requests 100-600 KB   -> 99.3% of bytes
//	p50=260  p99=524435  max=524437
//
// These tests reproduce BOTH halves deterministically, offline, with no
// goatnet, and they are written to FAIL once each defect is fixed so the fix
// cannot silently regress.
//
// Defect 1 (size)      TestF338_OfferCarriesWholeMcElieceStaticKey
// Defect 2 (frequency) TestF338_BreakerCannotOpenWhenServerSilentlyDrops
// Fix validation       TestF338_Fix_* (both levers, showing the reduction)

import (
	"testing"
	"time"

	rp "cunicu.li/go-rosenpass"
	"golang.org/x/crypto/blake2s"
	"google.golang.org/protobuf/proto"

	sigclient "github.com/netbirdio/netbird/shared/signal/client"
	sigproto "github.com/netbirdio/netbird/shared/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// spkSizeMcEliece460896 is cunicu.li/go-rosenpass@v0.4.0 types.go:73 spkSize.
// Restated here rather than imported because it is unexported; if the library
// changes KEM this constant is what tells you.
const spkSizeMcEliece460896 = 524160

// buildOffer marshals a real OFFER exactly the way signaler.go does, so the
// size this test reports is the size that goes on the wire.
func buildOffer(t *testing.T, rosenpassPubKey []byte) []byte {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("wg keygen: %v", err)
	}
	remote, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("wg keygen: %v", err)
	}

	msg, err := sigclient.MarshalCredential(
		key,
		51820,
		remote.PublicKey().String(),
		&sigclient.Credential{UFrag: "abcd1234", Pwd: "0123456789abcdef0123456789abcdef"},
		sigproto.Body_OFFER,
		rosenpassPubKey,
		"100.64.0.5:9999",
		"rels://relay.example.net:443",
		[]byte("session-id-16byt"),
	)
	if err != nil {
		t.Fatalf("MarshalCredential: %v", err)
	}

	wire, err := proto.Marshal(msg.GetBody())
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return wire
}

// TestF338_OfferCarriesWholeMcElieceStaticKey reproduces defect 1.
//
// getRosenpassPubKey() (engine.go) returns manager.spk verbatim, which is the
// full Classic McEliece 460896 static public key, and signaler.go puts it in
// EVERY offer and answer.
func TestF338_OfferCarriesWholeMcElieceStaticKey(t *testing.T) {
	// Real keypair from the real library. McEliece keygen is slow (~seconds);
	// that cost is itself a hint about the size of the artefact.
	spk, _, err := rp.GenerateKeyPair()
	if err != nil {
		t.Fatalf("rosenpass keygen: %v", err)
	}

	if got := len(spk); got != spkSizeMcEliece460896 {
		t.Fatalf("rosenpass static public key is %d bytes, expected %d "+
			"(go-rosenpass types.go spkSize). If this changed, the KEM changed.",
			got, spkSizeMcEliece460896)
	}

	wire := buildOffer(t, spk)
	t.Logf("OFFER body on the wire with full Rosenpass spk: %d bytes", len(wire))

	// Live EFDI observed max RequestContentSize = 524437. The gRPC request adds
	// the EncryptedMessage envelope on top of this Body, so the Body alone is
	// slightly smaller; assert the order of magnitude, not an exact match.
	if len(wire) < 500_000 {
		t.Fatalf("expected a >500 KB offer reproducing the live 524,437-byte "+
			"requests, got %d bytes — defect 1 may be FIXED, in which case "+
			"delete this test and keep TestF338_Fix_HashInsteadOfKey", len(wire))
	}

	// This is the whole point: 99.3% of the bytes are one field.
	ratio := float64(len(spk)) / float64(len(wire))
	t.Logf("Rosenpass spk is %.2f%% of the offer body", ratio*100)
	if ratio < 0.98 {
		t.Fatalf("expected the spk to dominate the offer, got %.2f%%", ratio*100)
	}
}

// TestF338_Fix_HashInsteadOfKey validates fix lever 1.
//
// hashRosenpassKey already exists at client/internal/rosenpass/manager.go:52 and
// is used only for a log line. Sending the digest instead of the key, and
// resolving the full key once per peer-pair, removes ~99.3% of signal bytes.
func TestF338_Fix_HashInsteadOfKey(t *testing.T) {
	spk, _, err := rp.GenerateKeyPair()
	if err != nil {
		t.Fatalf("rosenpass keygen: %v", err)
	}

	before := buildOffer(t, spk)

	digest := blake2s.Sum256(spk)
	after := buildOffer(t, digest[:])

	reduction := 1 - float64(len(after))/float64(len(before))
	t.Logf("offer body: %d bytes -> %d bytes (%.2f%% reduction)",
		len(before), len(after), reduction*100)

	if reduction < 0.98 {
		t.Fatalf("expected >=98%% reduction, got %.2f%%", reduction*100)
	}

	// At the live rate of 2.93 offers/sec measured on EFDI.
	const offersPerSec = 2.93
	beforeMbit := float64(len(before)) * 8 * offersPerSec / 1e6
	afterMbit := float64(len(after)) * 8 * offersPerSec / 1e6
	t.Logf("at the live 2.93 offers/sec: %.2f Mbit/s -> %.4f Mbit/s", beforeMbit, afterMbit)
}

// TestF338_BreakerCannotOpenWhenServerSilentlyDrops reproduces defect 2.
//
// conn.go:626 calls breaker.OnResult(err == nil). The signal server returns OK
// with an empty payload when the recipient is unknown (exchange.go:60-73,
// preserving upstream's silent-drop contract so the vanilla daemon's
// IsHealthy() probe keeps working — F-105). So err is ALWAYS nil for an offer to
// an offline peer, and OnResult(true) resets the breaker to closed with
// failures=0 (breaker.go:88-91).
//
// The breaker built to suppress these offers is held open by the offers.
func TestF338_BreakerCannotOpenWhenServerSilentlyDrops(t *testing.T) {
	b := newPairBreaker()

	// The live shape: a peer that has been offline for hours. Every offer is
	// silently dropped and every one of them returns success to the client.
	const offers = 1000
	suppressed := 0
	for i := 0; i < offers; i++ {
		if !b.Allow() {
			suppressed++
			continue
		}
		// err == nil, because the server said OK. This is the bug.
		b.OnResult(true)
	}

	t.Logf("offers attempted=%d suppressed=%d", offers, suppressed)
	if suppressed != 0 {
		t.Fatalf("expected the breaker to suppress NOTHING (it cannot open when "+
			"every result is success), but it suppressed %d — defect 2 may be FIXED",
			suppressed)
	}

	// At the live cadence this is unbounded: ~2.4s per offer, forever.
	t.Logf("at the live ~2.4s cadence that is %.0f offers/day per dead peer-pair, "+
		"each carrying the full McEliece key", 24*3600/2.4)
}

// TestF338_Fix_BreakerOpensWhenToldTheTruth validates fix lever 2.
//
// If the handshaker could distinguish "delivered" from "silently dropped" —
// without breaking the F-105 health-probe contract, e.g. via a response field or
// trailer that IsHealthy() ignores — the EXISTING breaker works correctly and
// needs no change. This test proves the mechanism is sound and only its input
// is wrong.
func TestF338_Fix_BreakerOpensWhenToldTheTruth(t *testing.T) {
	b := newPairBreaker()

	const offers = 1000
	sent, suppressed := 0, 0
	for i := 0; i < offers; i++ {
		if !b.Allow() {
			suppressed++
			continue
		}
		sent++
		// A truthful signal: the recipient is offline, so this did NOT deliver.
		b.OnResult(false)
	}

	t.Logf("offers attempted=%d actually sent=%d suppressed=%d", offers, sent, suppressed)

	if sent > breakerFailureThreshold+2 {
		t.Fatalf("expected the breaker to open after %d consecutive failures and "+
			"suppress the rest, but %d offers went out", breakerFailureThreshold, sent)
	}

	reduction := 1 - float64(sent)/float64(offers)
	t.Logf("truthful signal alone cuts offer COUNT by %.1f%%", reduction*100)
}

// TestF338_BothLeversMultiply states the combined effect in the units the
// operator cares about, using only measured inputs.
func TestF338_BothLeversMultiply(t *testing.T) {
	// Measured on EFDI 2026-08-15.
	const (
		liveSignalMbit = 17.26 // traefik_service_requests_bytes_total, signal@file
		shedFraction   = 0.598 // relay_shed / (relay_shed + relay_total)
		bigMsgByteFrac = 0.993 // share of signal bytes in 100-600 KB requests
	)

	sizeOnly := liveSignalMbit * (1 - bigMsgByteFrac)
	t.Logf("lever 1 alone (ship the hash):        %.2f -> %.3f Mbit/s", liveSignalMbit, sizeOnly)

	countOnly := liveSignalMbit * (1 - shedFraction)
	t.Logf("lever 2 alone (truthful breaker):     %.2f -> %.2f Mbit/s", liveSignalMbit, countOnly)

	both := liveSignalMbit * (1 - bigMsgByteFrac) * (1 - shedFraction)
	t.Logf("both levers:                          %.2f -> %.4f Mbit/s", liveSignalMbit, both)

	if both > 0.1 {
		t.Fatalf("expected both levers to land under 0.1 Mbit/s, got %.4f", both)
	}
	_ = time.Second
}
