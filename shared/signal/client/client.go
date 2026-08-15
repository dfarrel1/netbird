package client

import (
	"golang.org/x/crypto/blake2s"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/version"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

const (
	StreamConnected    Status = "Connected"
	StreamDisconnected Status = "Disconnected"

	// DirectCheck indicates support to direct mode checks
	DirectCheck uint32 = 1
	// RosenpassKeyByDigest indicates the peer can resolve a Rosenpass static
	// public key from its BLAKE2s digest, so offers and answers need not carry
	// the full 524,160-byte Classic McEliece key.
	//
	// A sender puts the full key on the wire UNLESS the remote advertised this,
	// which keeps a mixed-version fleet working with no flag day.
	RosenpassKeyByDigest uint32 = 2
)

// SupportsFeature reports whether a peer's advertised feature list contains f.
func SupportsFeature(features []uint32, f uint32) bool {
	for _, v := range features {
		if v == f {
			return true
		}
	}
	return false
}

// LocalFeatures is what this client advertises in every Body.
func LocalFeatures() []uint32 {
	return []uint32{DirectCheck, RosenpassKeyByDigest}
}

// Status is the status of the client
type Status string

type Client interface {
	io.Closer
	StreamConnected() bool
	GetStatus() Status
	Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error
	Ready() bool
	IsHealthy() bool
	WaitStreamConnected(context.Context)
	SendToStream(msg *proto.EncryptedMessage) error
	Send(msg *proto.Message) error
	SetOnReconnectedListener(func())
}

// Credential is an instance of a GrpcClient's Credential
type Credential struct {
	UFrag string
	Pwd   string
}

// CredentialPayload bundles the fields of a signal Body for MarshalCredential.
type CredentialPayload struct {
	Type            proto.Body_Type
	WgListenPort    int
	Credential      *Credential
	RosenpassPubKey []byte
	RosenpassAddr   string
	RelaySrvAddress string
	RelaySrvIP      netip.Addr
	SessionID       []byte
}

// UnMarshalCredential parses the credentials from the message and returns a Credential instance
func UnMarshalCredential(msg *proto.Message) (*Credential, error) {

	credential := strings.Split(msg.GetBody().GetPayload(), ":")
	if len(credential) != 2 {
		return nil, fmt.Errorf("error parsing message body %s", msg.Body)
	}
	return &Credential{
		UFrag: credential[0],
		Pwd:   credential[1],
	}, nil
}

// MarshalCredential marshal a Credential instance and returns a Message object
// MarshalCredentialFor builds an offer/answer body, choosing the Rosenpass key
// representation based on what the REMOTE peer has advertised.
//
// remoteFeatures is what we last saw that peer advertise. When it contains
// RosenpassKeyByDigest we send a 32-byte digest instead of the 524,160-byte
// Classic McEliece static public key; otherwise the full key, so a client that
// does not understand the digest is unaffected and there is no flag day.
//
// BOOTSTRAP LIMIT: features are learned from a message the peer SENT us, so for
// a peer we have never heard from we send the full key. That is unavoidable for
// interop, and it means digest mode does not help repeated offers to peers that
// never answer at all — those need the offer to stop, not to shrink.
func MarshalCredentialFor(myKey wgtypes.Key, remoteKey string, p CredentialPayload, remoteFeatures []uint32) (*proto.Message, error) {
	msg, err := MarshalCredential(myKey, remoteKey, p)
	if err != nil {
		return nil, err
	}
	msg.Body.FeaturesSupported = LocalFeatures()
	if len(p.RosenpassPubKey) > 0 && SupportsFeature(remoteFeatures, RosenpassKeyByDigest) {
		d := blake2s.Sum256(p.RosenpassPubKey)
		msg.Body.RosenpassConfig.RosenpassPubKeyDigest = d[:]
		msg.Body.RosenpassConfig.RosenpassPubKey = nil
	}
	return msg, nil
}

// MarshalRosenpassKey builds the ROSENPASS_KEY reply to a ROSENPASS_KEY_REQUEST.
// This is the only message carrying the full key once digest mode is in use.
func MarshalRosenpassKey(myKey wgtypes.Key, remoteKey string, rosenpassPubKey []byte) *proto.Message {
	d := blake2s.Sum256(rosenpassPubKey)
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &proto.Body{
			Type:              proto.Body_ROSENPASS_KEY,
			FeaturesSupported: LocalFeatures(),
			RosenpassConfig: &proto.RosenpassConfig{
				RosenpassPubKey:       rosenpassPubKey,
				RosenpassPubKeyDigest: d[:],
			},
		},
	}
}

// MarshalRosenpassKeyRequest asks a peer for the full key behind a digest.
func MarshalRosenpassKeyRequest(myKey wgtypes.Key, remoteKey string, digest []byte) *proto.Message {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &proto.Body{
			Type:              proto.Body_ROSENPASS_KEY_REQUEST,
			FeaturesSupported: LocalFeatures(),
			RosenpassConfig: &proto.RosenpassConfig{
				RosenpassPubKeyDigest: digest,
			},
		},
	}
}

func MarshalCredential(myKey wgtypes.Key, remoteKey string, p CredentialPayload) (*proto.Message, error) {
	body := &proto.Body{
		Type:           p.Type,
		Payload:        fmt.Sprintf("%s:%s", p.Credential.UFrag, p.Credential.Pwd),
		WgListenPort:   uint32(p.WgListenPort),
		NetBirdVersion: version.NetbirdVersion(),
		RosenpassConfig: &proto.RosenpassConfig{
			RosenpassPubKey:     p.RosenpassPubKey,
			RosenpassServerAddr: p.RosenpassAddr,
		},
		SessionId: p.SessionID,
	}
	if p.RelaySrvAddress != "" {
		body.RelayServerAddress = &p.RelaySrvAddress
	}
	if p.RelaySrvIP.IsValid() {
		body.RelayServerIP = p.RelaySrvIP.Unmap().AsSlice()
	}
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body:      body,
	}, nil
}
