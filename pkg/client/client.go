// client/client.go
package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const roundRobin = `{ "loadBalancingConfig": [ { "round_robin": {} } ] }`

// Config for dialing the SPIRE server with SPIFFE-aware mTLS.
type Config struct {
	Address string                 // host:port (NodeIP:NodePort is fine)
	Domain  spiffeid.TrustDomain   // e.g., example.org
	// Callbacks provide the current trust bundle and agent SVID (cert+key)
	GetBundle          func() []*x509.Certificate
	GetAgentCertificate func() *tls.Certificate
	Policy             tlspolicy.Policy // optional; use tlspolicy.Default if unsure
	DialOpts           []grpc.DialOption
}

// NewServerGRPCClient dials the server and verifies its SPIFFE ID.
func NewServerGRPCClient(cfg Config) (*grpc.ClientConn, error) {
	// Expected server ID (spiffe://<td>/spire/server)
	serverID, err := spiffeid.FromSegments(cfg.Domain, "spire", "server")
	if err != nil {
		return nil, fmt.Errorf("build server ID: %w", err)
	}
	authorizer := tlsconfig.AuthorizeID(serverID)

	// TLS config: with or without client auth depending on whether agent SVID is provided
	var tlsCfg *tls.Config
	bundleSrc := &bundleSource{td: cfg.Domain, getter: cfg.GetBundle}
	if cfg.GetAgentCertificate == nil {
		tlsCfg = tlsconfig.TLSClientConfig(bundleSrc, authorizer)
	} else {
		tlsCfg = tlsconfig.MTLSClientConfig(&x509SVIDSource{getter: cfg.GetAgentCertificate}, bundleSrc, authorizer)
	}

	if err := tlspolicy.ApplyPolicy(tlsCfg, cfg.Policy); err != nil {
		return nil, fmt.Errorf("apply TLS policy: %w", err)
	}

	opts := cfg.DialOpts
	if len(opts) == 0 {
		opts = []grpc.DialOption{
			grpc.WithDefaultServiceConfig(roundRobin),
			grpc.WithDisableServiceConfig(),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		}
	}

	// gRPC v1.64: use grpc.NewClient; older versions use grpc.DialContext
	conn, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return conn, nil
}

// ---- Helpers for loading files (optional but handy) ----

// LoadCABundlePEM parses a PEM bundle into []*x509.Certificate.
func LoadCABundlePEM(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse cert: %w", err)
			}
			certs = append(certs, c)
		}
		pemBytes = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return certs, nil
}

// LoadX509KeyPair loads a cert+key from disk.
func LoadX509KeyPair(certPath, keyPath string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	return &c, nil
}

// WithTimeout wraps grpc.DialOption to set a per-RPC default timeout if desired.
// (Optional; you can also enforce timeouts at call-sites.)
func WithTimeout(d time.Duration) grpc.DialOption {
	return grpc.WithDefaultCallOptions(grpc.WaitForReady(true))
}

// ---- Implementations of go-spiffe Sources from simple getters ----

type bundleSource struct {
	td     spiffeid.TrustDomain
	getter func() []*x509.Certificate
}

func (s *bundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	b := x509bundle.FromX509Authorities(s.td, s.getter())
	return b.GetX509BundleForTrustDomain(td)
}

type x509SVIDSource struct {
	getter func() *tls.Certificate
}

func (s *x509SVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	tlsCert := s.getter()
	if tlsCert == nil {
		return nil, fmt.Errorf("no TLS certificate available")
	}
	certs, err := x509util.RawCertsToCertificates(tlsCert.Certificate)
	if err != nil {
		return nil, err
	}
	id, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return nil, err
	}
	signer, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a crypto.Signer (%T)", tlsCert.PrivateKey)
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: certs,
		PrivateKey:   signer,
	}, nil
}
