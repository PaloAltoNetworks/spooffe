// cmd/spooffe/collect-jwts.go
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

type CollectJWTsConfig struct {
	*CommonConfig // Embed common config
	Audience      []string // required - audience for all JWTs
	OutputDir     string   // directory to save JWT files
	DryRun        bool     // just show what would be collected
}

/*
# Collect JWT SVIDs for all entries (saves to JWTSVIDs/ folder)
sudo ./spooffe server --server-address "192.168.109.131:32595" --client-cert agent.crt --client-key agent_ec.key --ca-cert bundle.crt collect-jwts --audience "your-audience"

# Use custom output directory
sudo ./spooffe server --server-address "192.168.109.131:32595" --client-cert agent.crt --client-key agent_ec.key --ca-cert bundle.crt collect-jwts --audience "your-audience" --output-dir "my-jwts"

# Dry run to see what entries would be processed
sudo ./spooffe server --server-address "192.168.109.131:32595" --client-cert agent.crt --client-key agent_ec.key --ca-cert bundle.crt collect-jwts --audience "your-audience" --dry-run

# Multiple audiences
sudo ./spooffe server --server-address "192.168.109.131:32595" --client-cert agent.crt --client-key agent_ec.key --ca-cert bundle.crt collect-jwts --audience "aud1,aud2,aud3"
*/

func NewCollectJWTsCmd(commonCfg *CommonConfig) *cobra.Command {
	var cfg CollectJWTsConfig
	cfg.CommonConfig = commonCfg // Use shared config

	cmd := &cobra.Command{
		Use:   "collect-jwts",
		Short: "Collect JWT-SVIDs for all authorized entries",
		Long: `Fetches all authorized entries and generates JWT-SVIDs for each one.
Saves each JWT to a file named <entry-id>.jwt in the specified directory.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return collectJWTSVIDs(cfg)
		},
	}

	// Only add collect-jwts specific flags
	cmd.Flags().StringSliceVar(&cfg.Audience, "audience", nil, "JWT audience for all tokens (comma or repeatable) (required)")
	cmd.Flags().StringVar(&cfg.OutputDir, "output-dir", "JWTSVIDs", "Directory to save JWT files")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Show entries that would be processed without fetching JWTs")

	_ = cmd.MarkFlagRequired("audience")

	return cmd
}

func collectJWTSVIDs(cfg CollectJWTsConfig) error {
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

	policy := tlspolicy.Policy{RequirePQKEM: false}

	// Dial server
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

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// First, get all authorized entries
	entryClient := entryv1.NewEntryClient(conn)
	entriesResp, err := entryClient.GetAuthorizedEntries(ctx, &entryv1.GetAuthorizedEntriesRequest{})
	if err != nil {
		return fmt.Errorf("GetAuthorizedEntries: %w", err)
	}

	entries := entriesResp.GetEntries()
	if len(entries) == 0 {
		fmt.Println("No authorized entries found")
		return nil
	}

	fmt.Printf("Found %d authorized entries\n", len(entries))
	fmt.Printf("Audience: %s\n", strings.Join(cfg.Audience, ", "))
	fmt.Printf("Output directory: %s\n", cfg.OutputDir)
	fmt.Println()

	if cfg.DryRun {
		fmt.Println("DRY RUN - Entries that would be processed:")
		for i, entry := range entries {
			fmt.Printf("  %d. Entry ID: %s\n", i+1, entry.Id)
			fmt.Printf("     SPIFFE ID: spiffe://%s%s\n", entry.SpiffeId.TrustDomain, entry.SpiffeId.Path)
			fmt.Printf("     Parent ID: spiffe://%s%s\n", entry.ParentId.TrustDomain, entry.ParentId.Path)
			
			var selectors []string
			for _, s := range entry.Selectors {
				selectors = append(selectors, s.Type+":"+s.Value)
			}
			fmt.Printf("     Selectors: %s\n", strings.Join(selectors, ", "))
			fmt.Println()
		}
		return nil
	}

	// Create output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %q: %w", cfg.OutputDir, err)
	}

	// Create SVID client for JWT requests
	svidClient := svidv1.NewSVIDClient(conn)

	successCount := 0
	errorCount := 0

	// Process each entry
	for i, entry := range entries {
		fmt.Printf("Processing entry %d/%d: %s\n", i+1, len(entries), entry.Id)
		
		// Create a new context with timeout for each JWT request
		jwtCtx, jwtCancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		// Fetch JWT SVID for this entry
		resp, err := svidClient.NewJWTSVID(jwtCtx, &svidv1.NewJWTSVIDRequest{
			EntryId:  entry.Id,
			Audience: cfg.Audience,
		})
		jwtCancel()

		if err != nil {
			fmt.Printf("  ❌ Failed to fetch JWT SVID: %v\n", err)
			errorCount++
			continue
		}

		svid := resp.GetSvid()
		if svid == nil {
			fmt.Printf("  ❌ Empty SVID response\n")
			errorCount++
			continue
		}

		// Save JWT to file
		filename := fmt.Sprintf("%s.jwt", entry.Id)
		filepath := filepath.Join(cfg.OutputDir, filename)
		
		err = os.WriteFile(filepath, []byte(svid.Token), 0644)
		if err != nil {
			fmt.Printf("  ❌ Failed to save JWT to file %s: %v\n", filename, err)
			errorCount++
			continue
		}

		// Print success info
		issued := time.Unix(svid.IssuedAt, 0).UTC()
		expires := time.Unix(svid.ExpiresAt, 0).UTC()
		
		fmt.Printf("  ✅ JWT SVID saved to %s\n", filename)
		fmt.Printf("     SPIFFE ID: spiffe://%s%s\n", entry.SpiffeId.TrustDomain, entry.SpiffeId.Path)
		fmt.Printf("     Issued: %s\n", issued.Format(time.RFC3339))
		fmt.Printf("     Expires: %s\n", expires.Format(time.RFC3339))
		fmt.Printf("     TTL: %s\n", time.Until(expires).Truncate(time.Second))
		
		successCount++
		fmt.Println()
	}

	// Print summary
	fmt.Println("=== Summary ===")
	fmt.Printf("Total entries processed: %d\n", len(entries))
	fmt.Printf("Successful JWT SVIDs: %d\n", successCount)
	fmt.Printf("Failed: %d\n", errorCount)
	fmt.Printf("JWT files saved in: %s\n", cfg.OutputDir)

	if errorCount > 0 {
		return fmt.Errorf("completed with %d errors", errorCount)
	}

	return nil
}