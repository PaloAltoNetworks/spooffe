// cmd/spooffe/bundle.go
package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

type BundleConfig struct {
	ServerAddress  string
	TrustDomainStr string
	CACertPath     string
	Timeout        time.Duration
	Format         string // info|json|pem
	OutputFile     string // Optional output file path
}

// sudo ./spooffe server bundle --ca-cert bundle.crt --server-address "192.168.109.131:32595"
/*
# Save certificates as PEM (what you want)
sudo ./spooffe server bundle --ca-cert bundle.crt --server-address "192.168.109.131:32595" --format pem --output my-bundle.crt

# Save readable info to text file
sudo ./spooffe server bundle --ca-cert bundle.crt --server-address "192.168.109.131:32595" --format info --output bundle-info.txt

# Save raw JSON data
sudo ./spooffe server bundle --ca-cert bundle.crt --server-address "192.168.109.131:32595" --format json --output bundle.json
*/

// /spire.api.server.bundle.v1.Bundle/GetBundle
func NewBundleCmd() *cobra.Command {
	var cfg BundleConfig

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Get the trust bundle for the trust domain",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundle(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.ServerAddress, "server-address", "localhost:8081", "SPIRE server address (host:port)")
	cmd.Flags().StringVar(&cfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.Flags().StringVar(&cfg.CACertPath, "ca-cert", "", "Path to server CA/bundle (PEM)")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "RPC timeout")
	cmd.Flags().StringVar(&cfg.Format, "format", "info", "Output format: info|json|pem")
	cmd.Flags().StringVar(&cfg.OutputFile, "output", "", "Output file path (default: stdout). For pem format, suggests bundle.crt")

	_ = cmd.MarkFlagRequired("ca-cert")
	return cmd
}

func runBundle(cfg BundleConfig) error {
	// Parse trust domain
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomainStr)
	if err != nil {
		return fmt.Errorf("invalid trust domain %q: %w", cfg.TrustDomainStr, err)
	}

	// Load trust bundle (server CA) for TLS verification
	bundleCerts, err := myclient.LoadCABundlePEM(cfg.CACertPath)
	if err != nil {
		return err
	}

	policy := tlspolicy.Policy{RequirePQKEM: false}

	// Dial server WITHOUT client mTLS (GetBundle doesn't require agent keys)
	conn, err := myclient.NewServerGRPCClient(myclient.Config{
		Address:   cfg.ServerAddress,
		Domain:    td,
		GetBundle: func() []*x509.Certificate { return bundleCerts },
		// Ensure no client cert is provided:
		GetAgentCertificate: nil,
		Policy:              policy,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	cli := bundlev1.NewBundleClient(conn)
	resp, err := cli.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return fmt.Errorf("GetBundle: %w", err)
	}

	bundle := resp

	// Determine output destination
	output := os.Stdout
	if cfg.OutputFile != "" {
		file, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %q: %w", cfg.OutputFile, err)
		}
		defer file.Close()
		output = file
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		enc := json.NewEncoder(output)
		enc.SetIndent("", "  ")
		err := enc.Encode(bundle)
		if cfg.OutputFile != "" && err == nil {
			fmt.Fprintf(os.Stderr, "Bundle saved to %s (JSON format)\n", cfg.OutputFile)
		}
		return err

	case "pem":
		// Emit X.509 authorities as standard PEM blocks
		for _, x509Auth := range bundle.X509Authorities {
			// x509Auth.Asn1 is []byte, not [][]byte, so we treat it as a single certificate
			err := pem.Encode(output, &pem.Block{Type: "CERTIFICATE", Bytes: x509Auth.Asn1})
			if err != nil {
				return fmt.Errorf("failed to encode certificate: %w", err)
			}
		}
		if cfg.OutputFile != "" {
			fmt.Fprintf(os.Stderr, "Bundle saved to %s (PEM format)\n", cfg.OutputFile)
		}
		return nil

	default: // "info"
		fmt.Fprintf(output, "Trust Domain: %s\n", bundle.TrustDomain)
		fmt.Fprintf(output, "Refresh Hint: %d seconds\n", bundle.RefreshHint)
		fmt.Fprintf(output, "Sequence Number: %d\n", bundle.SequenceNumber)

		if len(bundle.X509Authorities) > 0 {
			fmt.Fprintf(output, "\nX.509 Authorities (%d):\n", len(bundle.X509Authorities))
			for i, x509Auth := range bundle.X509Authorities {
				fmt.Fprintf(output, "  Authority %d: 1 certificate\n", i+1)
				cert, err := x509.ParseCertificate(x509Auth.Asn1)
				if err != nil {
					fmt.Fprintf(output, "    Cert 1: (parse error: %v)\n", err)
					continue
				}
				fmt.Fprintf(output, "    Cert 1: Subject=%s, NotAfter=%s\n",
					cert.Subject.String(), cert.NotAfter.Format(time.RFC3339))
			}
		}

		if len(bundle.JwtAuthorities) > 0 {
			fmt.Fprintf(output, "\nJWT Authorities (%d):\n", len(bundle.JwtAuthorities))
			for i, jwtAuth := range bundle.JwtAuthorities {
				fmt.Fprintf(output, "  Authority %d: KeyID=%s ExpiresAt=%d\n", i+1, jwtAuth.KeyId, jwtAuth.ExpiresAt)
			}
		}

		if cfg.OutputFile != "" {
			fmt.Fprintf(os.Stderr, "Bundle info saved to %s\n", cfg.OutputFile)
		}
		return nil
	}
}