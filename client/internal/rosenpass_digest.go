package internal

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/rosenpass"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// Rosenpass key-by-digest wiring (ADR 1134 D2/D3, F-338).
//
// A Rosenpass v1 static public key is Classic McEliece 460896 — 524,160 bytes —
// and netbird put the whole key in every OFFER and ANSWER. On a live deployment
// that was 99.3% of all signal bytes and cost peers two thirds of their
// connections, because the offers saturated the client's own uplink and starved
// ICE of the small CANDIDATE messages that actually establish a link.
//
// This file holds everything the engine needs to send a 32-byte digest instead,
// and to resolve a digest it has not seen before. It is deliberately separate
// from engine.go so the change is reviewable and so an upstream cherry-pick is
// one file plus three call sites.

// rememberPeerFeatures records what a peer advertised. Called for EVERY inbound
// message, because features ride on all of them and the cheapest ones (a
// CANDIDATE) arrive most often.
//
// The caller must hold syncMsgMux.
func (e *Engine) rememberPeerFeatures(peerKey string, features []uint32) {
	if len(features) == 0 {
		return
	}
	if e.peerFeatures == nil {
		e.peerFeatures = make(map[string][]uint32)
	}
	e.peerFeatures[peerKey] = features
}

// peerSupportsDigest reports whether we may send this peer a digest instead of
// the full key.
//
// Defaults to FALSE for a peer we have never heard from, which is the whole
// interop guarantee: an older client that does not understand the digest still
// receives the key it needs. It also means the first offer to a silent peer
// still costs 512 KB — digest mode cannot fix offers to peers that never
// answer, and is not intended to. That case belongs to the ADR 1081 L1 breaker.
//
// The caller must hold syncMsgMux.
func (e *Engine) peerSupportsDigest(peerKey string) bool {
	return signal.SupportsFeature(e.peerFeatures[peerKey], signal.RosenpassKeyByDigest)
}

// resolveRosenpassKey fills in a message's full Rosenpass key when the sender
// supplied only a digest.
//
// Returns false when the key is not held, in which case the caller must NOT
// process the offer — it asks the sender for the key and waits for the next
// offer, which the sender is already retrying on its own cadence.
//
// The caller must hold syncMsgMux.
func (e *Engine) resolveRosenpassKey(msg *sProto.Message) bool {
	cfg := msg.GetBody().GetRosenpassConfig()
	if cfg == nil {
		return true // nothing to resolve; peer is not running Rosenpass
	}
	if len(cfg.GetRosenpassPubKey()) > 0 {
		// Full key on the wire — legacy peer, or a ROSENPASS_KEY reply. Cache
		// it so we never have to ask this peer again.
		if e.rpKeyCache != nil {
			e.rpKeyCache.Put(cfg.GetRosenpassPubKey())
		}
		return true
	}
	digest := cfg.GetRosenpassPubKeyDigest()
	if len(digest) == 0 {
		return true // peer sent neither; Rosenpass is off at their end
	}
	if e.rpKeyCache == nil {
		return true
	}
	if key, ok := e.rpKeyCache.Get(digest); ok {
		cfg.RosenpassPubKey = key
		return true
	}

	// Miss. Ask once; the sender's next offer carries the same digest and will
	// resolve from cache. Deliberately fire-and-forget: a failure here is not
	// fatal, the offer is retried anyway, and blocking the receive path on a
	// send is how a signal handler deadlocks.
	log.Debugf("rosenpass: key digest not held for peer %s, requesting full key", msg.Key)
	e.requestRosenpassKey(msg.Key, digest)
	return false
}

// requestRosenpassKey asks a peer for the key behind a digest.
func (e *Engine) requestRosenpassKey(peerKey string, digest []byte) {
	if e.signal == nil || e.config == nil {
		return
	}
	req := signal.MarshalRosenpassKeyRequest(e.config.WgPrivateKey, peerKey, digest)
	go func() {
		if err := e.signal.Send(req); err != nil {
			log.Debugf("rosenpass: key request to %s failed: %v", peerKey, err)
		}
	}()
}

// replyWithRosenpassKey answers a ROSENPASS_KEY_REQUEST with our full key.
//
// This is the ONLY message we ever send that carries the 512 KB key once the
// far end speaks digest mode, and it is sent at most once per peer-pair per
// key-lifetime because the key is generated once per process.
func (e *Engine) replyWithRosenpassKey(peerKey string) {
	if e.signal == nil || e.config == nil {
		return
	}
	pub := e.getRosenpassPubKey()
	if len(pub) == 0 {
		return // Rosenpass is off here; nothing to hand over
	}
	msg := signal.MarshalRosenpassKey(e.config.WgPrivateKey, peerKey, pub)
	go func() {
		if err := e.signal.Send(msg); err != nil {
			log.Debugf("rosenpass: key reply to %s failed: %v", peerKey, err)
		}
	}()
}

// acceptRosenpassKey stores a key received in a ROSENPASS_KEY reply.
//
// PutVerified, never Put: the reply could carry any bytes, and accepting them
// unchecked would let a peer substitute the static key of the identity we are
// about to encapsulate to.
func (e *Engine) acceptRosenpassKey(msg *sProto.Message) {
	cfg := msg.GetBody().GetRosenpassConfig()
	if cfg == nil || e.rpKeyCache == nil {
		return
	}
	if !e.rpKeyCache.PutVerified(cfg.GetRosenpassPubKeyDigest(), cfg.GetRosenpassPubKey()) {
		log.Warnf("rosenpass: peer %s answered a key request with a key that does not match the digest; discarded", msg.Key)
	}
}

// ensureRosenpassKeyCache is called during engine start.
func (e *Engine) ensureRosenpassKeyCache() {
	if e.rpKeyCache == nil {
		e.rpKeyCache = rosenpass.NewKeyCache()
	}
	// Our own key resolves locally without a round trip.
	if pub := e.getRosenpassPubKey(); len(pub) > 0 {
		e.rpKeyCache.Put(pub)
	}
}
