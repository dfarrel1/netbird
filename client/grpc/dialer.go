package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

// goatOfflineCARoot is the offline-CA root cert (Block 22J / ADR 0407) that
// signs all goat-prod mgmt-API service certs. macOS Security framework
// rejects the Ed25519 root from the System keychain (`Unknown format in
// import`), so the netbird daemon's TLS verify needs an in-binary trust
// anchor to validate `https://198.18.0.1:443` (kwt-aj-A) and equivalent
// per-site mgmt endpoints.
//
//go:embed dogfood-trust/goat-offline-ca-root.pem
var goatOfflineCARoot []byte

// Backoff returns a backoff configuration for gRPC calls
func Backoff(ctx context.Context) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	b.Clock = backoff.SystemClock
	return backoff.WithContext(b, ctx)
}

// CreateConnection creates a gRPC client connection with the appropriate transport options.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
func CreateConnection(ctx context.Context, addr string, tlsEnabled bool, component string, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())
	// for js, the outer websocket layer takes care of tls
	if tlsEnabled && runtime.GOOS != "js" {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		// Always add the goat offline-CA root as a trust anchor so
		// goat-prod mgmt endpoints (https://198.18.0.X:443, signed by
		// the offline-CA per ADR 0407) validate without requiring a
		// per-laptop macOS keychain entry that's blocked by Ed25519.
		if ok := certPool.AppendCertsFromPEM(goatOfflineCARoot); !ok {
			log.Warn("goat offline-CA root failed to parse — goat-prod mgmt TLS will fail")
		}

		// gRPC's default ServerName-from-target behavior passes "host:port"
		// to the verifier, which fails IP-SAN match (Go's
		// Certificate.VerifyHostname tries to parse "198.18.0.1:443" as IP,
		// which fails). Strip the port so IP-SAN match works.
		serverName := addr
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			serverName = h
		}
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    certPool,
			ServerName: serverName,
		}))
	}

	connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := []grpc.DialOption{
		transportOption,
		WithCustomDialer(tlsEnabled, component),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	}
	opts = append(opts, extraOpts...)

	conn, err := grpc.DialContext(connCtx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial context: %w", err)
	}

	return conn, nil
}
