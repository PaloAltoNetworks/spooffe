package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spf13/cobra"
)

func newFetchX509Cmd() *cobra.Command {
	var (
		socketURI     string
		outCertPath   string
		outKeyPath    string
		outBundlePath string
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "x509",
		Short: "Fetch the current X.509 SVID via the Workload API (spire-agent socket)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Build an X509Source which auto-tracks rotation
			src, err := workloadapi.NewX509Source(ctx,
				workloadapi.WithClientOptions(workloadapi.WithAddr(socketURI)))
			if err != nil {
				return fmt.Errorf("connect workload API: %w", err)
			}
			defer src.Close()

			// Default SVID (workload’s primary identity)
			svid, err := src.GetX509SVID()
			if err != nil {
				return fmt.Errorf("get default X509 SVID: %w", err)
			}

			fmt.Println("X.509 SVID fetched successfully")
			fmt.Println("  SPIFFE ID:", svid.ID.String())
			fmt.Println("  Expires  :", svid.Certificates[0].NotAfter.UTC().Format(time.RFC3339))
			fmt.Println("  Key type :", fmt.Sprintf("%T", svid.PrivateKey))

			// Optional outputs
			if outCertPath != "" {
				if err := writeCertChainPEM(outCertPath, svid.Certificates); err != nil {
					return fmt.Errorf("write cert: %w", err)
				}
				fmt.Println("  Wrote leaf+chain PEM :", outCertPath)
			}
			if outBundlePath != "" {
				bundle, err := src.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
				if err != nil {
					return fmt.Errorf("get X509 bundle: %w", err)
				}
				if err := writeBundlePEM(outBundlePath, bundle); err != nil {
					return fmt.Errorf("write bundle: %w", err)
				}
				fmt.Println("  Wrote bundle PEM     :", outBundlePath)
			}
			if outKeyPath != "" {
				der, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
				if err != nil {
					return fmt.Errorf("marshal PKCS#8: %w", err)
				}
				if err := os.MkdirAll(filepath.Dir(outKeyPath), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
					return err
				}
				fmt.Println("  Wrote private key PEM:", outKeyPath, "(0600)")
			}

			return nil
		},
	}

	// Note: URI form required by go-spiffe (keep the triple slash)
	cmd.Flags().StringVar(&socketURI, "socket", "unix:///run/spire/sockets/agent.sock", "Workload API socket URI (e.g., unix:///run/spire/sockets/agent.sock)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "Timeout for Workload API calls")

	cmd.Flags().StringVar(&outCertPath, "out-cert", "", "Write leaf+chain PEM to file")
	cmd.Flags().StringVar(&outKeyPath, "out-key", "", "Write private key PEM to file (0600)")
	cmd.Flags().StringVar(&outBundlePath, "out-bundle", "", "Write trust bundle PEM to file")

	return cmd
}

func writeCertChainPEM(path string, certs []*x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, c := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return nil
}

func writeBundlePEM(path string, b *x509bundle.Bundle) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, ca := range b.X509Authorities() {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
			return err
		}
	}
	return nil
}
