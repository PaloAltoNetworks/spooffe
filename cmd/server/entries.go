// cmd/spooffe/entries.go
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

type EntriesConfig struct {
	*CommonConfig // Embed common config
	//TrustDomainStr string
	// CACertPath     string
	// ClientCertPath string
	// ClientKeyPath  string
	Timeout        time.Duration
	Format         string // ids|table|json
}

// "/spire.api.server.entry.v1.Entry/GetAuthorizedEntries" 

func NewEntriesCmd(commonCfg *CommonConfig) *cobra.Command {
	var cfg EntriesConfig
	cfg.CommonConfig = commonCfg // Use shared config 

	cmd := &cobra.Command{
		Use:   "entries",
		Short: "List registration entries authorized for this agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEntries(cfg)
		},
	}

	//cmd.Flags().StringVar(&cfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "RPC timeout")
	cmd.Flags().StringVar(&cfg.Format, "format", "ids", "Output format: ids|table|json")

	_ = cmd.MarkFlagRequired("ca-cert")
	return cmd
}

func runEntries(cfg EntriesConfig) error {
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
		GetBundle: func() []*x509.Certificate { return bundleCerts },
		GetAgentCertificate: func() *tls.Certificate { return agent },
		Policy: policy,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	cli := entryv1.NewEntryClient(conn)
	resp, err := cli.GetAuthorizedEntries(ctx, &entryv1.GetAuthorizedEntriesRequest{})
	if err != nil {
		return fmt.Errorf("GetAuthorizedEntries: %w", err)
	}

	entries := resp.GetEntries()
	switch strings.ToLower(cfg.Format) {
	case "json":
		type outEntry struct {
			Id        string   `json:"id"`
			SPIFFEID  string   `json:"spiffe_id"`
			ParentID  string   `json:"parent_id"`
			Selectors []string `json:"selectors"`
		}
		out := make([]outEntry, 0, len(entries))
		for _, e := range entries {
			var sels []string
			for _, s := range e.Selectors {
				sels = append(sels, s.Type+":"+s.Value)
			}
			out = append(out, outEntry{
				Id:        e.Id,
				SPIFFEID:  "spiffe://" + e.SpiffeId.TrustDomain + e.SpiffeId.Path,
				ParentID:  "spiffe://" + e.ParentId.TrustDomain + e.ParentId.Path,
				Selectors: sels,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)

	case "table":
		if len(entries) == 0 {
			fmt.Fprintln(os.Stdout, "(no entries)")
			return nil
		}
		fmt.Fprintf(os.Stdout, "%-36s  %-40s  %-40s  %s\n", "ENTRY ID", "SPIFFE ID", "PARENT ID", "SELECTORS")
		for _, e := range entries {
			var sels []string
			for _, s := range e.Selectors {
				sels = append(sels, s.Type+":"+s.Value)
			}
			fmt.Fprintf(os.Stdout, "%-36s  %-40s  %-40s  %s\n",
				e.Id,
				"spiffe://"+e.SpiffeId.TrustDomain+e.SpiffeId.Path,
				"spiffe://"+e.ParentId.TrustDomain+e.ParentId.Path,
				strings.Join(sels, ","),
			)
		}

	default: // "ids"
		if len(entries) == 0 {
			fmt.Fprintln(os.Stdout, "(no entries)")
			return nil
		}
		for _, e := range entries {
			fmt.Fprintln(os.Stdout, e.Id)
		}
	}

	return nil
}
