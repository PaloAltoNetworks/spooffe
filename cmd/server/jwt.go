// cmd/spooffe/jwt.go
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

// Go's embedding rules. When you embed *CommonConfig in your struct
// All the fields from CommonConfig (like ServerAddress, TrustDomainStr, etc.) are promoted to the outer struct. 
// This means you can access them directly as if they were fields of JWTSVIDConfig.

type JWTSVIDConfig struct {
	*CommonConfig // Embed common config
	TrustDomainStr string        // e.g., "example.org"
	EntryID        string        // required
	Audience       []string      // required
	Timeout        time.Duration // default 30s
}

func NewJWTCmd(commonCfg *CommonConfig) *cobra.Command {
	var cfg JWTSVIDConfig
	cfg.CommonConfig = commonCfg // Use shared config 

	cmd := &cobra.Command{
		Use:   "jwt",
		Short: "Fetch a JWT-SVID from the SPIRE server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fetchJWTSVID(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.Flags().StringVar(&cfg.EntryID, "entry-id", "", "Registration Entry ID (required)")
	cmd.Flags().StringSliceVar(&cfg.Audience, "audience", nil, "JWT audience (comma or repeatable) (required)")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "RPC timeout")

	_ = cmd.MarkFlagRequired("entry-id")
	_ = cmd.MarkFlagRequired("audience")
	_ = cmd.MarkFlagRequired("ca-cert")

	return cmd
}

func fetchJWTSVID(cfg JWTSVIDConfig) error {
	// Parse trust domain
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomainStr)
	if err != nil {
		return fmt.Errorf("invalid trust domain %q: %w", cfg.TrustDomainStr, err)
	}

	// Load trust bundle
	bundleCerts, err := myclient.LoadCABundlePEM(cfg.CACertPath)
	if err != nil {
		return err
	}

	// Optionally load agent SVID (mTLS)
	var agent *tls.Certificate
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		agent, err = myclient.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return err
		}
	}

	policy := tlspolicy.Policy{
		RequirePQKEM: false,
	}

	// Wire the SPIFFE-aware dialer
	conn, err := myclient.NewServerGRPCClient(myclient.Config{
		Address: cfg.ServerAddress,
		Domain:  td,
		GetBundle: func() []*x509.Certificate {
			return bundleCerts
		},
		GetAgentCertificate: func() *tls.Certificate {
			return agent
		},
		Policy: policy,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	// Call NewJWTSVID
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	client := svidv1.NewSVIDClient(conn)
	resp, err := client.NewJWTSVID(ctx, &svidv1.NewJWTSVIDRequest{
		EntryId:  cfg.EntryID,
		Audience: cfg.Audience,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	s := resp.GetSvid()
	if s == nil {
		return fmt.Errorf("empty SVID response")
	}

	issued := time.Unix(s.IssuedAt, 0).UTC()
	expires := time.Unix(s.ExpiresAt, 0).UTC()

	fmt.Println("JWT SVID fetched successfully:")
	fmt.Println("  Entry ID: ", cfg.EntryID)
	fmt.Println("  Audience:", strings.Join(cfg.Audience, ", "))
	fmt.Println("  Issued:  ", issued.Format(time.RFC3339))
	fmt.Println("  Expires: ", expires.Format(time.RFC3339))
	fmt.Println("  TTL:     ", time.Until(expires).Truncate(time.Second))
	fmt.Println("  Token:   ", s.Token)

	return nil
}