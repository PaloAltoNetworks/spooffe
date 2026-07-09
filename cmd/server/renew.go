// cmd/spooffe/renew.go
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

type RenewConfig struct {
	ServerAddress    string
	TrustDomainStr   string
	CACertPath       string
	AgentCertPath    string
	AgentKeyPath     string
	NewAgentKeyPath  string
	NewAgentCertPath string
	Timeout          time.Duration
	KeySize          int
}

func NewRenewCmd() *cobra.Command {
	var cfg RenewConfig

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew the agent SVID with a new key pair",
		Long: `Renew the agent SVID by generating a new key pair and requesting a new certificate.
This command will:
1. Load the current agent SVID for authentication
2. Generate a new RSA private key for the renewed agent SVID
3. Create a Certificate Signing Request (CSR) with the new key
4. Send the CSR to the SPIRE server using the current agent SVID for authentication
5. Save the new agent certificate and private key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRenew(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.ServerAddress, "server-address", "localhost:8081", "SPIRE server address (host:port)")
	cmd.Flags().StringVar(&cfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.Flags().StringVar(&cfg.CACertPath, "ca-cert", "", "Path to trust bundle (PEM)")
	cmd.Flags().StringVar(&cfg.AgentCertPath, "agent-cert", "agent.crt", "Path to current agent certificate")
	cmd.Flags().StringVar(&cfg.AgentKeyPath, "agent-key", "agent.key", "Path to current agent private key")
	cmd.Flags().StringVar(&cfg.NewAgentKeyPath, "new-agent-key", "agent-new.key", "Output path for new agent private key")
	cmd.Flags().StringVar(&cfg.NewAgentCertPath, "new-agent-cert", "agent-new.crt", "Output path for new agent certificate")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "RPC timeout")
	cmd.Flags().IntVar(&cfg.KeySize, "key-size", 2048, "RSA key size in bits")

	_ = cmd.MarkFlagRequired("ca-cert")
	_ = cmd.MarkFlagRequired("agent-cert")
	_ = cmd.MarkFlagRequired("agent-key")

	return cmd
}

func runRenew(cfg RenewConfig) error {
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

	// Load current agent SVID
	currentAgentCert, err := myclient.LoadX509KeyPair(cfg.AgentCertPath, cfg.AgentKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load current agent SVID: %w", err)
	}

	// Generate new agent key pair
	fmt.Println("Generating new agent key pair...")
	newAgentKey, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate new agent key: %w", err)
	}

	// Create CSR for new key
	fmt.Println("Creating certificate signing request...")
	csr, err := createCSR(newAgentKey, td)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	policy := tlspolicy.Policy{RequirePQKEM: false}

	// Connect to SPIRE server with current agent SVID for authentication
	conn, err := myclient.NewServerGRPCClient(myclient.Config{
		Address:             cfg.ServerAddress,
		Domain:              td,
		GetBundle:           func() []*x509.Certificate { return bundleCerts },
		GetAgentCertificate: func() *tls.Certificate { return currentAgentCert },
		Policy:              policy,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Perform SVID renewal
	fmt.Println("Renewing agent SVID with SPIRE server...")
	client := agentv1.NewAgentClient(conn)

	// Create renewal request
	req := &agentv1.RenewAgentRequest{
		Params: &agentv1.AgentX509SVIDParams{
			Csr: csr,
		},
	}

	resp, err := client.RenewAgent(ctx, req)
	if err != nil {
		return fmt.Errorf("agent renewal failed: %w", err)
	}

	agentSVID := resp.GetSvid()
	if agentSVID == nil {
		return fmt.Errorf("no agent SVID received in renewal response")
	}

	// Save new agent private key
	fmt.Printf("Saving new agent private key to %s...\n", cfg.NewAgentKeyPath)
	if err := savePrivateKey(newAgentKey, cfg.NewAgentKeyPath); err != nil {
		return fmt.Errorf("failed to save new agent key: %w", err)
	}

	// Save new agent certificate
	fmt.Printf("Saving new agent certificate to %s...\n", cfg.NewAgentCertPath)
	if err := saveCertificates(agentSVID.CertChain, cfg.NewAgentCertPath); err != nil {
		return fmt.Errorf("failed to save new agent certificate: %w", err)
	}

	fmt.Println("Agent SVID renewal completed successfully!")
	fmt.Printf("Agent SPIFFE ID: spiffe://%s%s\n", agentSVID.Id.TrustDomain, agentSVID.Id.Path)
	fmt.Printf("New certificate expires at: %s\n", time.Unix(agentSVID.ExpiresAt, 0).UTC())

	return nil
}

func createCSR(key *rsa.PrivateKey, trustDomain spiffeid.TrustDomain) ([]byte, error) {
	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "spiffe://agent", // This will be overridden by the server
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create and sign CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}

	return csrDER, nil
}

func savePrivateKey(key *rsa.PrivateKey, path string) error {
	// Convert private key to PKCS#1 ASN.1 DER format
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	// Create PEM block
	keyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	}

	// Write to file
	keyFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	// Set restrictive permissions
	if err := keyFile.Chmod(0600); err != nil {
		return err
	}

	return pem.Encode(keyFile, &keyPEM)
}

func saveCertificates(certChain [][]byte, path string) error {
	certFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer certFile.Close()

	// Save all certificates in the chain
	for i, certDER := range certChain {
		certPEM := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}

		if err := pem.Encode(certFile, &certPEM); err != nil {
			return fmt.Errorf("failed to encode certificate %d: %w", i, err)
		}
	}

	return nil
}

func loadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%q is empty", path)
	}
	return string(data), nil
}
