package peer

import (
	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

type Signaler struct {
	signal       signal.Client
	wgPrivateKey wgtypes.Key
	// peerSupportsDigest reports whether a peer advertised
	// RosenpassKeyByDigest. nil means "assume not", which yields the historical
	// full-key offer (ADR 1134 D3).
	peerSupportsDigest func(remoteKey string) bool
}

func NewSignaler(signal signal.Client, wgPrivateKey wgtypes.Key) *Signaler {
	return &Signaler{
		signal:       signal,
		wgPrivateKey: wgPrivateKey,
	}
}

// SetPeerFeatureLookup installs the callback that reports what a given peer has
// advertised in Body.featuresSupported.
//
// ADR 1134 D3. When it says a peer understands RosenpassKeyByDigest we send a
// 32-byte digest instead of the 524,160-byte Classic McEliece static public key
// (F-338). A nil lookup, or one that returns false, produces the historical
// full-key offer — so an older peer, and a goatnet that has not adopted this,
// are both unaffected.
func (s *Signaler) SetPeerFeatureLookup(f func(remoteKey string) bool) {
	s.peerSupportsDigest = f
}

func (s *Signaler) remoteFeatures(remoteKey string) []uint32 {
	if s.peerSupportsDigest != nil && s.peerSupportsDigest(remoteKey) {
		return []uint32{signal.RosenpassKeyByDigest}
	}
	return nil
}

func (s *Signaler) SignalOffer(offer OfferAnswer, remoteKey string) error {
	return s.signalOfferAnswer(offer, remoteKey, sProto.Body_OFFER)
}

func (s *Signaler) SignalAnswer(offer OfferAnswer, remoteKey string) error {
	return s.signalOfferAnswer(offer, remoteKey, sProto.Body_ANSWER)
}

func (s *Signaler) SignalICECandidate(candidate ice.Candidate, remoteKey string) error {
	return s.signal.Send(&sProto.Message{
		Key:       s.wgPrivateKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &sProto.Body{
			Type:    sProto.Body_CANDIDATE,
			Payload: candidate.Marshal(),
		},
	})
}

func (s *Signaler) Ready() bool {
	return s.signal.Ready()
}

// SignalOfferAnswer signals either an offer or an answer to remote peer
func (s *Signaler) signalOfferAnswer(offerAnswer OfferAnswer, remoteKey string, bodyType sProto.Body_Type) error {
	var sessionIDBytes []byte
	if offerAnswer.SessionID != nil {
		var err error
		sessionIDBytes, err = offerAnswer.SessionID.Bytes()
		if err != nil {
			log.Warnf("failed to get session ID bytes: %v", err)
		}
	}
	msg, err := signal.MarshalCredentialFor(
		s.wgPrivateKey,
		offerAnswer.WgListenPort,
		remoteKey,
		&signal.Credential{
			UFrag: offerAnswer.IceCredentials.UFrag,
			Pwd:   offerAnswer.IceCredentials.Pwd,
		},
		bodyType,
		offerAnswer.RosenpassPubKey,
		offerAnswer.RosenpassAddr,
		offerAnswer.RelaySrvAddress,
		sessionIDBytes,
		s.remoteFeatures(remoteKey))
	if err != nil {
		return err
	}

	if err = s.signal.Send(msg); err != nil {
		return err
	}

	return nil
}

func (s *Signaler) SignalIdle(remoteKey string) error {
	return s.signal.Send(&sProto.Message{
		Key:       s.wgPrivateKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &sProto.Body{
			Type: sProto.Body_GO_IDLE,
		},
	})
}
