// cmd/spooffe/attest.go
package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/tlspolicy"

	myclient "spooffe/pkg/client"
)

type AttestConfig struct {
	ServerAddress  string
	TrustDomainStr string
	CACertPath     string
	PSATTokenPath  string
	Cluster        string
	AgentKeyPath   string
	AgentCertPath  string
	Timeout        time.Duration
	KeySize        int
}

// sudo ./spooffe agent attest --psat-token spire-agent.psat --ca-cert bundle.crt --cluster mars --server-address "192.168.109.131:32595"
func NewAttestCmd() *cobra.Command {
	var cfg AttestConfig

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Perform agent attestation to obtain agent SVID",
		Long: `Perform agent attestation using PSAT (Projected Service Account Token) to obtain an agent SVID.
This command will:
1. Generate a new RSA private key for the agent
2. Create a Certificate Signing Request (CSR)
3. Send the CSR and PSAT token to the SPIRE server for attestation
4. Save the resulting agent certificate and private key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.ServerAddress, "server-address", "localhost:8081", "SPIRE server address (host:port)")
	cmd.Flags().StringVar(&cfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.Flags().StringVar(&cfg.CACertPath, "ca-cert", "", "Path to trust bundle (PEM)")
	cmd.Flags().StringVar(&cfg.PSATTokenPath, "psat-token", "", "Path to PSAT token file")
	cmd.Flags().StringVar(&cfg.Cluster, "cluster", "", "Kubernetes cluster name")
	cmd.Flags().StringVar(&cfg.AgentKeyPath, "agent-key", "agent.key", "Output path for agent private key")
	cmd.Flags().StringVar(&cfg.AgentCertPath, "agent-cert", "agent.crt", "Output path for agent certificate")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "RPC timeout")
	cmd.Flags().IntVar(&cfg.KeySize, "key-size", 2048, "RSA key size in bits")

	_ = cmd.MarkFlagRequired("ca-cert")
	_ = cmd.MarkFlagRequired("psat-token")
	_ = cmd.MarkFlagRequired("cluster")

	return cmd
}

func runAttest(cfg AttestConfig) error {
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

	// Load PSAT token
	psatToken, err := loadTokenFromFile(cfg.PSATTokenPath)
	if err != nil {
		return fmt.Errorf("failed to load PSAT token: %w", err)
	}

	// Generate agent key pair
	fmt.Println("Generating agent key pair...")
	agentKey, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate agent key: %w", err)
	}

	// Create CSR
	fmt.Println("Creating certificate signing request...")
	csr, err := createCSR(agentKey, td)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	policy := tlspolicy.Policy{RequirePQKEM: false}

	// Connect to SPIRE server (without client certificate for initial attestation)
	conn, err := myclient.NewServerGRPCClient(myclient.Config{
		Address:             cfg.ServerAddress,
		Domain:              td,
		GetBundle:           func() []*x509.Certificate { return bundleCerts },
		GetAgentCertificate: nil, // No client cert for initial attestation
		Policy:              policy,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Prepare attestation data
	attestationData, err := json.Marshal(k8s.PSATAttestationData{
		Cluster: cfg.Cluster,
		Token:   psatToken,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	// Perform attestation
	fmt.Println("Performing attestation with SPIRE server...")
	client := agentv1.NewAgentClient(conn)

	// Start attestation stream
	stream, err := client.AttestAgent(ctx)
	if err != nil {
		return fmt.Errorf("failed to start attestation stream: %w", err)
	}

	// Send initial attestation request with PSAT data and CSR
	// Use the proper AttestationData type
	req := &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{
			Params: &agentv1.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    "k8s_psat",
					Payload: attestationData,
				},
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
	}

	if err := stream.Send(req); err != nil {
		return fmt.Errorf("failed to send attestation request: %w", err)
	}

	// Read responses and handle any challenges
	var finalResponse *agentv1.AttestAgentResponse
	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("failed to receive attestation response: %w", err)
		}

		// Check if we have a challenge
		if challenge := resp.GetChallenge(); challenge != nil {
			// For PSAT, we typically don't expect challenges, but handle just in case
			return fmt.Errorf("unexpected challenge received during PSAT attestation")
		}

		// Check if we have a result
		if result := resp.GetResult(); result != nil {
			finalResponse = resp
			break
		}
	}

	if finalResponse == nil {
		return fmt.Errorf("no final result received from attestation")
	}

	result := finalResponse.GetResult()
	if result == nil {
		return fmt.Errorf("no result in final response")
	}

	agentSVID := result.GetSvid()
	if agentSVID == nil {
		return fmt.Errorf("no agent SVID received")
	}

	// Close the stream
	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	// Save agent private key
	fmt.Printf("Saving agent private key to %s...\n", cfg.AgentKeyPath)
	if err := savePrivateKey(agentKey, cfg.AgentKeyPath); err != nil {
		return fmt.Errorf("failed to save agent key: %w", err)
	}

	// Save agent certificate
	fmt.Printf("Saving agent certificate to %s...\n", cfg.AgentCertPath)
	if err := saveCertificates(agentSVID.CertChain, cfg.AgentCertPath); err != nil {
		return fmt.Errorf("failed to save agent certificate: %w", err)
	}

	fmt.Println("Agent attestation completed successfully!")
	fmt.Printf("Agent SPIFFE ID: spiffe://%s%s\n", agentSVID.Id.TrustDomain, agentSVID.Id.Path)

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
