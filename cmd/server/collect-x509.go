// cmd/server/collect-x509.go
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	myclient "spooffe/pkg/client"
)

type CollectX509Config struct {
	*CommonConfig

	OutputDir string        // where artifacts are written
	DryRun    bool          // list entries only (no mint)
	KeyType   string        // ec|rsa
	RSABits   int           // if --key-type=rsa
	Timeout   time.Duration // RPC timeout for listing entries
}

func NewCollectX509Cmd(commonCfg *CommonConfig) *cobra.Command {
	var cfg CollectX509Config
	cfg.CommonConfig = commonCfg

	cmd := &cobra.Command{
		Use:   "collect-x509",
		Short: "Collect X.509-SVIDs for all authorized entries (batch mint via server API)",
		Long: `Enumerates authorized entries, generates a CSR per entry with a SPIFFE URI SAN,
then calls BatchNewX509SVID to mint X.509-SVIDs. Writes <entry-id>.key and <entry-id>.crt.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return collectX509SVIDs(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.OutputDir, "output-dir", "X509SVIDs", "Directory to save keys/certs")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "List entries without minting X.509-SVIDs")
	cmd.Flags().StringVar(&cfg.KeyType, "key-type", "ec", "Private key type: ec|rsa")
	cmd.Flags().IntVar(&cfg.RSABits, "rsa-bits", 2048, "RSA key size (if --key-type=rsa)")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 60*time.Second, "RPC timeout for listing entries")

	_ = cmd.MarkFlagRequired("ca-cert")

	return cmd
}

func collectX509SVIDs(cfg CollectX509Config) error {
	// Guards
	if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
		return fmt.Errorf("collect-x509 requires --client-cert/--client-key (admin/authorized client for server SVID API)")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.KeyType == "" {
		cfg.KeyType = "ec"
	}
	if strings.EqualFold(cfg.KeyType, "rsa") && cfg.RSABits < 2048 {
		cfg.RSABits = 2048
	}

	// Trust domain
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomainStr)
	if err != nil {
		return fmt.Errorf("invalid trust domain %q: %w", cfg.TrustDomainStr, err)
	}

	// Load CA bundle and client SVID
	bundleCerts, err := myclient.LoadCABundlePEM(cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("load CA bundle: %w", err)
	}
	agent, err := myclient.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath) // returns *tls.Certificate
	if err != nil {
		return fmt.Errorf("load client cert/key: %w", err)
	}

	// Dial server
	policy := tlspolicy.Policy{RequirePQKEM: false}
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

	// List authorized entries
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
	fmt.Printf("Output directory: %s\n", cfg.OutputDir)
	fmt.Printf("Key type: %s\n", cfg.KeyType)
	if strings.EqualFold(cfg.KeyType, "rsa") {
		fmt.Printf("RSA bits: %d\n", cfg.RSABits)
	}
	fmt.Println()

	if cfg.DryRun {
		fmt.Println("DRY RUN - Entries that would be processed:")
		for i, e := range entries {
			fmt.Printf("  %d. Entry ID: %s\n", i+1, e.Id)
			fmt.Printf("     SPIFFE ID: spiffe://%s%s\n", e.SpiffeId.TrustDomain, e.SpiffeId.Path)
			fmt.Printf("     Parent ID: spiffe://%s%s\n", e.ParentId.TrustDomain, e.ParentId.Path)
			var sels []string
			for _, s := range e.Selectors {
				sels = append(sels, s.Type+":"+s.Value)
			}
			fmt.Printf("     Selectors: %s\n\n", strings.Join(sels, ", "))
		}
		return nil
	}

	// Prepare output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("mkdir %q: %w", cfg.OutputDir, err)
	}

	// Build CSR per entry and keep the key alongside it
	type toMint struct {
		EntryID string
		Key     any
		CSRDER  []byte
	}
	batch := make([]toMint, 0, len(entries))

	for _, e := range entries {
		spiffeURI := &url.URL{
			Scheme: "spiffe",
			Host:   e.SpiffeId.TrustDomain,
			Path:   e.SpiffeId.Path,
		}

		var priv any
		var csrDER []byte

		switch strings.ToLower(cfg.KeyType) {
		case "rsa":
			rk, err := rsa.GenerateKey(rand.Reader, cfg.RSABits)
			if err != nil {
				fmt.Printf("  ❌ RSA keygen failed for %s: %v\n", e.Id, err)
				continue
			}
			priv = rk
			template := x509.CertificateRequest{
				Subject: pkix.Name{CommonName: spiffeURI.String()},
				URIs:    []*url.URL{spiffeURI},
			}
			csrDER, err = x509.CreateCertificateRequest(rand.Reader, &template, rk)
			if err != nil {
				fmt.Printf("  ❌ CSR failed for %s: %v\n", e.Id, err)
				continue
			}
		default: // EC P-256
			sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				fmt.Printf("  ❌ EC keygen failed for %s: %v\n", e.Id, err)
				continue
			}
			priv = sk
			template := x509.CertificateRequest{
				Subject: pkix.Name{CommonName: spiffeURI.String()},
				URIs:    []*url.URL{spiffeURI},
			}
			csrDER, err = x509.CreateCertificateRequest(rand.Reader, &template, sk)
			if err != nil {
				fmt.Printf("  ❌ CSR failed for %s: %v\n", e.Id, err)
				continue
			}
		}

		batch = append(batch, toMint{
			EntryID: e.Id,
			Key:     priv,
			CSRDER:  csrDER,
		})
	}

	if len(batch) == 0 {
		return fmt.Errorf("no CSRs prepared (keygen/CSR may have failed for all entries)")
	}

	// Call BatchNewX509SVID in chunks
	svidClient := svidv1.NewSVIDClient(conn)
	const chunkSize = 64
	var okCount, errCount int

	for off := 0; off < len(batch); off += chunkSize {
		end := off + chunkSize
		if end > len(batch) {
			end = len(batch)
		}

		params := make([]*svidv1.NewX509SVIDParams, 0, end-off)
		for _, it := range batch[off:end] {
			params = append(params, &svidv1.NewX509SVIDParams{
				EntryId: it.EntryID,
				Csr:     it.CSRDER,
			})
		}

		rpcCtx, cancelMint := context.WithTimeout(context.Background(), 45*time.Second)
		resp, err := svidClient.BatchNewX509SVID(rpcCtx, &svidv1.BatchNewX509SVIDRequest{
			Params: params,
		})
		cancelMint()
		if err != nil {
			if status.Code(err) == codes.PermissionDenied {
				return fmt.Errorf("BatchNewX509SVID denied: your client identity is not authorized to mint X.509-SVIDs via server API")
			}
			return fmt.Errorf("BatchNewX509SVID failed: %w", err)
		}

		results := resp.GetResults() // []*svidv1.BatchNewX509SVIDResponse_Result
		if len(results) != len(params) {
			// Should align 1:1; warn and handle gracefully.
			fmt.Printf("⚠️  result count (%d) != param count (%d); mapping by min length\n", len(results), len(params))
		}

		n := len(results)
		if len(params) < n {
			n = len(params)
		}

		for i := 0; i < n; i++ {
			it := batch[off+i]
			r := results[i]

			// Per-item status
			if st := r.GetStatus(); st != nil && st.GetCode() != 0 {
				fmt.Printf("  ❌ %s: %s (code=%d)\n", it.EntryID, st.GetMessage(), st.GetCode())
				errCount++
				continue
			}

			svid := r.GetSvid()
			if svid == nil || len(svid.GetCertChain()) == 0 {
				fmt.Printf("  ❌ %s: empty SVID in result\n", it.EntryID)
				errCount++
				continue
			}

			// Write artifacts
			base := filepath.Join(cfg.OutputDir, it.EntryID)

			// key
			keyFile := base + ".key"
			var keyPEM *pem.Block
			switch k := it.Key.(type) {
			case *ecdsa.PrivateKey:
				der, err := x509.MarshalECPrivateKey(k)
				if err != nil {
					fmt.Printf("  ❌ %s: marshal EC key failed: %v\n", it.EntryID, err)
					errCount++
					continue
				}
				keyPEM = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
			case *rsa.PrivateKey:
				keyPEM = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
			default:
				fmt.Printf("  ❌ %s: unknown key type\n", it.EntryID)
				errCount++
				continue
			}
			if err := os.WriteFile(keyFile, pem.EncodeToMemory(keyPEM), 0600); err != nil {
				fmt.Printf("  ❌ %s: write key failed: %v\n", it.EntryID, err)
				errCount++
				continue
			}

			// certificate chain
			crtFile := base + ".crt"
			var crtPEM []byte
			for _, der := range svid.GetCertChain() {
				crtPEM = append(crtPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
			if err := os.WriteFile(crtFile, crtPEM, 0644); err != nil {
				fmt.Printf("  ❌ %s: write cert chain failed: %v\n", it.EntryID, err)
				errCount++
				continue
			}

			fmt.Printf("  ✅ %s → saved %s, %s\n", it.EntryID, filepath.Base(keyFile), filepath.Base(crtFile))
			okCount++
		}
	}

	fmt.Println("=== Summary ===")
	fmt.Printf("Total entries processed: %d\n", len(entries))
	fmt.Printf("Successful X.509-SVIDs: %d\n", okCount)
	fmt.Printf("Failed: %d\n", errCount)
	fmt.Printf("Artifacts saved in: %s\n", cfg.OutputDir)

	if errCount > 0 {
		return fmt.Errorf("completed with %d errors", errCount)
	}
	return nil
}
