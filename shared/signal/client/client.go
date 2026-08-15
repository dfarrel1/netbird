package client

import (
	"golang.org/x/crypto/blake2s"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/version"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

// Status is the status of the client
type Status string

const StreamConnected Status = "Connected"
const StreamDisconnected Status = "Disconnected"

const (
	// DirectCheck indicates support to direct mode checks
	DirectCheck uint32 = 1
	// RosenpassKeyByDigest indicates the peer can resolve a Rosenpass static
	// public key from its BLAKE2s digest, so offers and answers need not carry
	// the full 524,160-byte Classic McEliece key.
	//
	// A sender puts the full key on the wire UNLESS the remote has advertised
	// this; that keeps a mixed-version fleet working with no flag day. See
	// F-338 for what the full key costs in practice.
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

type Client interface {
	io.Closer
	StreamConnected() bool
	GetStatus() Status
	Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error
	Ready() bool
	IsHealthy() bool
	WaitStreamConnected()
	SendToStream(msg *proto.EncryptedMessage) error
	Send(msg *proto.Message) error
	SetOnReconnectedListener(func())
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
// RosenpassKeyByDigest we send a 32-byte digest; otherwise we send the full
// 524,160-byte key, so a peer running an older client is unaffected.
//
// BOOTSTRAP LIMIT, stated because it decides how much this actually saves:
// features are learned from a message the peer SENT us. For a peer we have
// never heard from, remoteFeatures is empty and we send the full key. That is
// correct and unavoidable for interop — and it means digest mode does NOT help
// the pathological case in F-338, which is repeated offers to peers that never
// answer at all. Those peers never advertise anything, so every retry pays full
// price. Fixing that case needs the offer to STOP, not to shrink: see the ADR
// 1081 L1 circuit breaker, which cannot currently open because the server
// returns OK for an unknown recipient (F-105).
//
// The two changes multiply: this one makes a successful handshake cheap, the
// breaker makes an unanswered one rare.
func MarshalCredentialFor(myKey wgtypes.Key, myPort int, remoteKey string, credential *Credential, t proto.Body_Type, rosenpassPubKey []byte, rosenpassAddr string, relaySrvAddress string, sessionID []byte, remoteFeatures []uint32) (*proto.Message, error) {
	msg, err := MarshalCredential(myKey, myPort, remoteKey, credential, t, rosenpassPubKey, rosenpassAddr, relaySrvAddress, sessionID)
	if err != nil {
		return nil, err
	}
	msg.Body.FeaturesSupported = LocalFeatures()
	if len(rosenpassPubKey) > 0 && SupportsFeature(remoteFeatures, RosenpassKeyByDigest) {
		d := blake2s.Sum256(rosenpassPubKey)
		msg.Body.RosenpassConfig.RosenpassPubKeyDigest = d[:]
		msg.Body.RosenpassConfig.RosenpassPubKey = nil
	}
	return msg, nil
}

// MarshalRosenpassKey builds the ROSENPASS_KEY reply to a ROSENPASS_KEY_REQUEST.
// This is the only message that carries the full key once digest mode is in use.
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

// MarshalRosenpassKeyRequest asks a peer for the full key behind a digest we
// received but do not hold.
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

func MarshalCredential(myKey wgtypes.Key, myPort int, remoteKey string, credential *Credential, t proto.Body_Type, rosenpassPubKey []byte, rosenpassAddr string, relaySrvAddress string, sessionID []byte) (*proto.Message, error) {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &proto.Body{
			Type:           t,
			Payload:        fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
			WgListenPort:   uint32(myPort),
			NetBirdVersion: version.NetbirdVersion(),
			RosenpassConfig: &proto.RosenpassConfig{
				RosenpassPubKey:     rosenpassPubKey,
				RosenpassServerAddr: rosenpassAddr,
			},
			RelayServerAddress: relaySrvAddress,
			SessionId:          sessionID,
		},
	}, nil
}

// Credential is an instance of a GrpcClient's Credential
type Credential struct {
	UFrag string
	Pwd   string
}
