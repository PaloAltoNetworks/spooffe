package agentkey

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// KeyType represents the type of private key
type KeyType string

const (
	KeyTypeRSA  KeyType = "rsa"
	KeyTypeEC   KeyType = "ec"
	KeyTypeBoth KeyType = "both"
)

// ExtractedKey holds information about an extracted private key
type ExtractedKey struct {
	Key           interface{} // *rsa.PrivateKey or *ecdsa.PrivateKey
	Type          KeyType
	PEMData       []byte
	PublicKeyHash []byte
	Filename      string
	MatchedCert   *ExtractedCert // Reference to matched certificate
}

// ExtractedCert holds information about an extracted certificate
type ExtractedCert struct {
	Cert          *x509.Certificate
	PEMData       []byte
	PublicKeyHash []byte
	Filename      string
	IsExpired     bool
	MatchedKey    *ExtractedKey // Reference to matched key
}

// NewAgentKeyCmd creates and returns the agentkey command
func NewAgentKeyCmd() *cobra.Command {
	var pid int
	var outputDir string
	var keyOnly bool
	var bundleOnly bool
	var bundlePath string
	var extractCerts bool
	var keyType string

	cmd := &cobra.Command{
		Use:   "agentkey",
		Short: "Dump SPIRE agent RSA/EC keys and/or bundle certificates",
		Long: `Dump the RSA/EC private keys from a running SPIRE agent process and/or extract
the bundle certificates from the agent's filesystem namespace.
This command will search for the spire-agent process, dump its memory,
extract private keys, and read bundle certificates using nsenter.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var kt KeyType
			switch strings.ToLower(keyType) {
			case "rsa":
				kt = KeyTypeRSA
			case "ec":
				kt = KeyTypeEC
			case "both":
				kt = KeyTypeBoth
			default:
				return fmt.Errorf("invalid key type: %s (must be 'rsa', 'ec', or 'both')", keyType)
			}
			return runAgentKey(pid, outputDir, keyOnly, bundleOnly, bundlePath, extractCerts, kt)
		},
	}

	cmd.Flags().IntVarP(&pid, "pid", "p", 0, "Process ID of the spire-agent (if not provided, will search automatically)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output/agent_keys", "Output directory for the dumped files")
	cmd.Flags().BoolVar(&keyOnly, "key-only", false, "Extract only private keys (skip bundle certificate)")
	cmd.Flags().BoolVar(&bundleOnly, "bundle-only", false, "Extract only bundle certificates (skip private keys)")
	cmd.Flags().StringVar(&bundlePath, "bundle-path", "/run/spire/bundle/bundle.crt", "Path to bundle certificate inside the agent's namespace")
	cmd.Flags().BoolVar(&extractCerts, "extract-certs", false, "Extract all certificates found and save them in extracted_certs folder")
	cmd.Flags().StringVar(&keyType, "key-type", "both", "Type of keys to extract: 'rsa', 'ec', or 'both'")

	return cmd
}

const (
	processPattern = "spire-agent run"
)

func runAgentKey(pid int, outputDir string, keyOnly, bundleOnly bool, bundlePath string, extractCerts bool, keyType KeyType) error {
	// Validate flags
	if keyOnly && bundleOnly {
		return fmt.Errorf("cannot specify both --key-only and --bundle-only flags")
	}

	var targetPID int
	var err error

	if pid == 0 {
		fmt.Println("No PID provided, searching for spire-agent process...")
		targetPID, err = findSpireAgentPID()
		if err != nil {
			return fmt.Errorf("failed to find spire-agent process: %v", err)
		}
		fmt.Printf("Found spire-agent process with PID: %d\n", targetPID)
	} else {
		targetPID = pid
		fmt.Printf("Using provided PID: %d\n", targetPID)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	var extractedKeys []ExtractedKey
	var extractedCerts []ExtractedCert

	// Extract private keys unless bundle-only is specified
	if !bundleOnly {
		fmt.Println("\n=== Extracting Private Keys ===")
		extractedKeys, err = extractPrivateKeys(targetPID, outputDir, keyType)
		if err != nil {
			return fmt.Errorf("failed to extract private keys: %v", err)
		}
	}

	// Extract bundle certificate unless key-only is specified
	//var bundleContent []byte
	if !keyOnly {
		fmt.Println("\n=== Extracting Bundle Certificate ===")
		_, err = extractBundleCertificate(targetPID, outputDir, bundlePath)
		if err != nil {
			return fmt.Errorf("failed to extract bundle certificate: %v", err)
		}

		// Extract and process individual certificates
		// fmt.Println("\n=== Processing Individual Certificates ===")
		// extractedCerts, err = processCertificates(bundleContent, outputDir)
		// if err != nil {
		// 	return fmt.Errorf("failed to process certificates: %v", err)
		// }

	}

	var memCerts []ExtractedCert
	if !bundleOnly {
		fmt.Println("\n=== Extracting Certificates From Memory ===")
		coreFile := filepath.Join(outputDir, fmt.Sprintf("core.%d", targetPID))
		mc, err := extractCertificatesFromCore(coreFile, outputDir)
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
		} else {
			memCerts = mc
		}
	}

	allCerts := append(extractedCerts, memCerts...)

	// Match keys with certificates and rename them accordingly
	if len(extractedKeys) > 0 && len(allCerts) > 0 {
		fmt.Println("\n=== Matching Keys with Certificates ===")
		if err := matchKeysWithCertificates(extractedKeys, allCerts, outputDir); err != nil {
			return fmt.Errorf("failed to match keys with certificates: %v", err)
		}
	}

	fmt.Println("\nSuccessfully completed SPIRE agent extraction!")
	return nil
}

func extractCertificatesFromCore(coreFile, outputDir string) ([]ExtractedCert, error) {
	content, err := getStringsFromCore(coreFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(content, "\n")
	var certs []ExtractedCert
	var seen = make(map[string]bool)                // Track certificate content
	var certIdentifiersSeen = make(map[string]bool) // Track certificate identifiers
	var buf []string
	collecting := false

	begin := "-----BEGIN CERTIFICATE-----"
	end := "-----END CERTIFICATE-----"

	for _, ln := range lines {
		l := strings.TrimSpace(ln)
		if strings.Contains(l, begin) {
			collecting = true
			buf = []string{begin}
			continue
		}
		if collecting {
			buf = append(buf, l)
			if strings.Contains(l, end) {
				pemStr := strings.Join(buf, "\n")

				// Skip if we've seen this exact PEM content before
				if seen[pemStr] {
					collecting = false
					buf = nil
					continue
				}

				if blk, _ := pem.Decode([]byte(pemStr)); blk != nil && blk.Type == "CERTIFICATE" {
					if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
						// Create a unique identifier for this certificate
						certIdentifier := fmt.Sprintf("%s:%s",
							cert.Issuer.String(),
							cert.SerialNumber.String())

						// Skip if we've seen this certificate before (by content or identifier)
						if certIdentifiersSeen[certIdentifier] {
							collecting = false
							buf = nil
							continue
						}

						pubHash, _ := calculatePublicKeyHashFromCert(cert)
						c := ExtractedCert{
							Cert:          cert,
							PEMData:       []byte(pemStr),
							PublicKeyHash: pubHash,
							IsExpired:     time.Now().After(cert.NotAfter),
						}
						certs = append(certs, c)
						seen[pemStr] = true
						certIdentifiersSeen[certIdentifier] = true
					}
				}
				collecting = false
				buf = nil
			}
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in memory dump")
	}

	// Additional deduplication pass to be extra sure
	uniqueCerts := removeDuplicateCerts(certs)

	outDir := filepath.Join(outputDir, "extracted_certs_mem")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}

	for i := range uniqueCerts {
		p := filepath.Join(outDir, fmt.Sprintf("mem_cert_%03d.crt", i+1))
		uniqueCerts[i].Filename = p
		_ = os.WriteFile(p, uniqueCerts[i].PEMData, 0644)
		fmt.Printf("Memory cert -> %s (pubkey sha256: %x)\n", p, uniqueCerts[i].PublicKeyHash)
		if len(uniqueCerts[i].Cert.URIs) > 0 {
			fmt.Printf("  URI SANs: %v\n", uniqueCerts[i].Cert.URIs)
		}
	}
	return uniqueCerts, nil
}

func extractPrivateKeys(targetPID int, outputDir string, keyType KeyType) ([]ExtractedKey, error) {
	// Check if core file already exists and ask user
	coreFile := filepath.Join(outputDir, fmt.Sprintf("core.%d", targetPID))
	shouldDump := true

	if _, err := os.Stat(coreFile); err == nil {
		// Core file exists, ask user
		fmt.Printf("Core file %s already exists.\n", coreFile)
		fmt.Print("Do you want to overwrite it? (y/N): ")

		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			shouldDump = true
			fmt.Println("Will overwrite existing core file...")
		} else {
			shouldDump = false
			fmt.Println("Using existing core file...")
		}
	}

	// Dump memory using gcore if needed
	if shouldDump {
		fmt.Printf("Dumping memory to: %s\n", coreFile)
		if err := dumpMemory(targetPID, coreFile); err != nil {
			return nil, fmt.Errorf("failed to dump memory: %v", err)
		}
	}

	var extractedKeys []ExtractedKey

	// Extract RSA keys if requested
	if keyType == KeyTypeRSA || keyType == KeyTypeBoth {
		fmt.Println("Extracting RSA private keys from memory dump...")
		rsaKeys, err := extractRSAKeys(coreFile)
		if err != nil {
			fmt.Printf("Warning: failed to extract RSA keys: %v\n", err)
		} else {
			extractedKeys = append(extractedKeys, rsaKeys...)
		}
	}

	// Extract EC keys if requested
	if keyType == KeyTypeEC || keyType == KeyTypeBoth {
		fmt.Println("Extracting EC private keys from memory dump...")
		ecKeys, err := extractECKeys(coreFile)
		if err != nil {
			fmt.Printf("Warning: failed to extract EC keys: %v\n", err)
		} else {
			extractedKeys = append(extractedKeys, ecKeys...)
		}
	}

	if len(extractedKeys) == 0 {
		return nil, fmt.Errorf("no private keys found in memory dump")
	}

	// Save keys and calculate public key hashes
	for i := range extractedKeys {
		key := &extractedKeys[i]

		// Generate temporary filename for initial save
		var baseName string
		if key.Type == KeyTypeRSA {
			baseName = fmt.Sprintf("temp_rsa_%d", i)
		} else {
			baseName = fmt.Sprintf("temp_ec_%d", i)
		}

		key.Filename = filepath.Join(outputDir, baseName+".key")

		// Save key temporarily
		if err := savePrivateKey(key.Key, key.Filename, key.Type); err != nil {
			return nil, fmt.Errorf("failed to save private key %s: %v", key.Filename, err)
		}

		// Calculate public key hash from the private key
		pubKeyHash, err := calculatePublicKeyHashFromPrivateKey(key.Key, key.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate public key hash for key %s: %v", key.Filename, err)
		}
		key.PublicKeyHash = pubKeyHash

		fmt.Printf("Private key saved to: %s (public key hash: %x)\n", key.Filename, key.PublicKeyHash)
	}

	return extractedKeys, nil
}

func processCertificates(bundleContent []byte, outputDir string) ([]ExtractedCert, error) {
	fmt.Println("Extracting individual certificates from bundle...")

	// Parse all certificates from the bundle content
	var extractedCerts []ExtractedCert
	bundleStr := string(bundleContent)
	certPEMs := strings.Split(bundleStr, "-----BEGIN CERTIFICATE-----")

	// Track certificates we've already seen
	seenCerts := make(map[string]bool)           // PEM content
	seenCertIdentifiers := make(map[string]bool) // Issuer + Serial

	for i, certPEM := range certPEMs {
		if i == 0 && !strings.Contains(certPEM, "-----END CERTIFICATE-----") {
			continue // Skip the part before the first certificate
		}

		fullCertPEM := "-----BEGIN CERTIFICATE-----" + certPEM
		if !strings.Contains(fullCertPEM, "-----END CERTIFICATE-----") {
			continue
		}

		// Skip if we've seen this PEM content before
		if seenCerts[fullCertPEM] {
			continue
		}

		block, _ := pem.Decode([]byte(fullCertPEM))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("Warning: failed to parse certificate: %v\n", err)
			continue
		}

		// Create unique identifier for this certificate
		certIdentifier := fmt.Sprintf("%s:%s",
			cert.Issuer.String(),
			cert.SerialNumber.String())

		// Skip if we've seen this certificate before
		if seenCertIdentifiers[certIdentifier] {
			continue
		}

		// Calculate public key hash from certificate
		pubKeyHash, err := calculatePublicKeyHashFromCert(cert)
		if err != nil {
			fmt.Printf("Warning: failed to calculate public key hash for certificate: %v\n", err)
			continue
		}

		// Check if certificate is expired
		now := time.Now()
		isExpired := now.After(cert.NotAfter)

		extractedCert := ExtractedCert{
			Cert:          cert,
			PEMData:       []byte(fullCertPEM),
			PublicKeyHash: pubKeyHash,
			IsExpired:     isExpired,
		}

		extractedCerts = append(extractedCerts, extractedCert)
		seenCerts[fullCertPEM] = true
		seenCertIdentifiers[certIdentifier] = true
	}

	if len(extractedCerts) == 0 {
		return nil, fmt.Errorf("no valid certificates found in bundle")
	}

	// Create extracted_certs directory
	certsDir := filepath.Join(outputDir, "extracted_certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create extracted_certs directory: %v", err)
	}

	// Save individual certificates with temporary names
	for i := range extractedCerts {
		cert := &extractedCerts[i]

		filename := filepath.Join(certsDir, fmt.Sprintf("temp_cert_%d.crt", i))
		cert.Filename = filename

		if err := os.WriteFile(filename, cert.PEMData, 0644); err != nil {
			return nil, fmt.Errorf("failed to save certificate %s: %v", filename, err)
		}

		expiredStatus := ""
		if cert.IsExpired {
			expiredStatus = " [EXPIRED]"
		}

		fmt.Printf("Certificate saved to: %s (public key hash: %x)%s\n", filename, cert.PublicKeyHash, expiredStatus)

		// Display certificate information
		fmt.Printf("  Subject: %s\n", cert.Cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Cert.Issuer)
		fmt.Printf("  Valid from: %s to %s\n",
			cert.Cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
			cert.Cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

		if len(cert.Cert.URIs) > 0 {
			fmt.Printf("  URI SANs: %v\n", cert.Cert.URIs)
		}
		if len(cert.Cert.DNSNames) > 0 {
			fmt.Printf("  DNS SANs: %v\n", cert.Cert.DNSNames)
		}
		fmt.Println()
	}

	fmt.Printf("Extracted %d unique certificate(s) to %s/\n", len(extractedCerts), certsDir)
	return extractedCerts, nil
}

func matchKeysWithCertificates(keys []ExtractedKey, certs []ExtractedCert, outputDir string) error {
	matched := make(map[int]int) // key index -> cert index

	// Match keys with certificates based on public key hashes
	for keyIdx, key := range keys {
		for certIdx, cert := range certs {
			if compareHashes(key.PublicKeyHash, cert.PublicKeyHash) {
				matched[keyIdx] = certIdx
				keys[keyIdx].MatchedCert = &certs[certIdx]
				certs[certIdx].MatchedKey = &keys[keyIdx]
				fmt.Printf("Matched key %s with certificate %s (expired: %v)\n",
					filepath.Base(key.Filename), filepath.Base(cert.Filename), cert.IsExpired)
				break
			}
		}
	}

	fmt.Printf("Matched %d key-certificate pairs\n", len(matched))

	// Find the non-expired certificate with its matched key (if any) for primary naming
	var primaryRSAIdx, primaryECIdx int = -1, -1

	for keyIdx, certIdx := range matched {
		cert := &certs[certIdx]
		key := &keys[keyIdx]

		if !cert.IsExpired {
			if key.Type == KeyTypeRSA && primaryRSAIdx == -1 {
				primaryRSAIdx = keyIdx
			} else if key.Type == KeyTypeEC && primaryECIdx == -1 {
				primaryECIdx = keyIdx
			}
		}
	}

	// If no non-expired certificates found, use the first matched ones
	if primaryRSAIdx == -1 {
		for keyIdx := range matched {
			if keys[keyIdx].Type == KeyTypeRSA {
				primaryRSAIdx = keyIdx
				break
			}
		}
	}
	if primaryECIdx == -1 {
		for keyIdx := range matched {
			if keys[keyIdx].Type == KeyTypeEC {
				primaryECIdx = keyIdx
				break
			}
		}
	}

	// Rename matched pairs with proper naming scheme
	rsaCounter, ecCounter := 1, 1

	for keyIdx, certIdx := range matched {
		key := &keys[keyIdx]
		cert := &certs[certIdx]

		var newKeyName, newCertName string

		if key.Type == KeyTypeRSA {
			if keyIdx == primaryRSAIdx {
				newKeyName = "agent_rsa.key"
				newCertName = "agent.crt"
			} else {
				newKeyName = fmt.Sprintf("agent_rsa_%d.key", rsaCounter)
				newCertName = fmt.Sprintf("agent_%d.crt", rsaCounter)
				rsaCounter++
			}
		} else { // EC
			if keyIdx == primaryECIdx {
				newKeyName = "agent_ec.key"
				newCertName = "agent.crt"
			} else {
				newKeyName = fmt.Sprintf("agent_ec_%d.key", ecCounter)
				newCertName = fmt.Sprintf("agent_%d.crt", ecCounter)
				ecCounter++
			}
		}

		newKeyPath := filepath.Join(outputDir, newKeyName)
		newCertPath := filepath.Join(outputDir, newCertName)

		// Rename key file
		if err := os.Rename(key.Filename, newKeyPath); err != nil {
			fmt.Printf("Warning: failed to rename key file %s to %s: %v\n",
				key.Filename, newKeyPath, err)
		} else {
			fmt.Printf("Renamed %s -> %s\n", filepath.Base(key.Filename), newKeyName)
		}

		// Copy certificate file to main output directory
		if err := os.WriteFile(newCertPath, cert.PEMData, 0644); err != nil {
			fmt.Printf("Warning: failed to write certificate file %s: %v\n", newCertPath, err)
		} else {
			fmt.Printf("Created matched certificate: %s", newCertName)
			if cert.IsExpired {
				fmt.Printf(" [EXPIRED]")
			}
			fmt.Println()
		}
	}

	// Handle unmatched keys - save to unmatched subdirectory
	unmatchedDir := filepath.Join(outputDir, "unmatched")
	if err := os.MkdirAll(unmatchedDir, 0755); err != nil {
		fmt.Printf("Warning: failed to create unmatched directory: %v\n", err)
	}

	for keyIdx, key := range keys {
		if _, matched := matched[keyIdx]; !matched {
			var newKeyName string
			if key.Type == KeyTypeRSA {
				newKeyName = fmt.Sprintf("unmatched_rsa_%d.key", keyIdx)
			} else {
				newKeyName = fmt.Sprintf("unmatched_ec_%d.key", keyIdx)
			}

			newKeyPath := filepath.Join(unmatchedDir, newKeyName)
			if err := os.Rename(key.Filename, newKeyPath); err != nil {
				fmt.Printf("Warning: failed to rename unmatched key file %s to %s: %v\n",
					key.Filename, newKeyPath, err)
			} else {
				fmt.Printf("Renamed unmatched key: %s -> unmatched/%s\n", filepath.Base(key.Filename), newKeyName)
			}
		}
	}

	return nil
}

func calculatePublicKeyHashFromPrivateKey(privateKey interface{}, keyType KeyType) ([]byte, error) {
	var pubKeyBytes []byte
	var err error

	if keyType == KeyTypeRSA {
		rsaKey := privateKey.(*rsa.PrivateKey)
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA public key: %v", err)
		}
	} else if keyType == KeyTypeEC {
		ecKey := privateKey.(*ecdsa.PrivateKey)
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC public key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return hash[:], nil
}

func calculatePublicKeyHashFromCert(cert *x509.Certificate) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate public key: %v", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return hash[:], nil
}

// Keep all the existing helper functions unchanged below this point...

func extractECKeys(coreFile string) ([]ExtractedKey, error) {
	stringsOutput, err := getStringsFromCore(coreFile)
	if err != nil {
		return nil, err
	}

	var allKeys []ExtractedKey
	keySet := make(map[string]bool) // Track keys we've already processed

	// Try traditional EC format
	ecKeys, err := findPrivateKeysInStrings(stringsOutput, []string{
		"-----BEGIN EC PRIVATE KEY-----",
		"-----END EC PRIVATE KEY-----",
	}, KeyTypeEC)
	if err == nil {
		for _, key := range ecKeys {
			keyContent := string(key.PEMData)
			if !keySet[keyContent] {
				keySet[keyContent] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	// Try PKCS#8 format (which might contain EC keys)
	pkcs8Keys, err := findPKCS8KeysInStrings(stringsOutput, KeyTypeEC)
	if err == nil {
		for _, key := range pkcs8Keys {
			keyContent := string(key.PEMData)
			if !keySet[keyContent] {
				keySet[keyContent] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	// Try more aggressive search for EC keys - sometimes they appear without proper headers
	aggressiveKeys, err := findECKeysAggressive(stringsOutput)
	if err == nil {
		for _, key := range aggressiveKeys {
			keyContent := string(key.PEMData)
			if !keySet[keyContent] {
				keySet[keyContent] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	if len(allKeys) == 0 {
		return nil, fmt.Errorf("no EC private keys found in memory dump")
	}

	// Apply enhanced duplicate removal based on actual key content
	uniqueKeys := removeDuplicateKeys(allKeys)

	fmt.Printf("Found %d unique EC private key(s) in memory dump\n", len(uniqueKeys))
	return uniqueKeys, nil
}

// Enhanced duplicate removal for keys using content-based comparison
func removeDuplicateKeys(keys []ExtractedKey) []ExtractedKey {
	seen := make(map[string]bool)
	var uniqueKeys []ExtractedKey

	for _, key := range keys {
		// Use the actual key content for deduplication, not just PEM format
		var keyIdentifier string

		// Create a unique identifier based on the actual key material
		if key.Type == KeyTypeRSA {
			if rsaKey, ok := key.Key.(*rsa.PrivateKey); ok {
				// Use the modulus and private exponent to uniquely identify RSA keys
				keyIdentifier = fmt.Sprintf("rsa:%s:%s", rsaKey.N.String(), rsaKey.D.String())
			}
		} else if key.Type == KeyTypeEC {
			if ecKey, ok := key.Key.(*ecdsa.PrivateKey); ok {
				// Use the private key value and curve parameters to uniquely identify EC keys
				keyIdentifier = fmt.Sprintf("ec:%s:%s:%s",
					ecKey.Curve.Params().Name,
					ecKey.X.String(),
					ecKey.D.String())
			}
		}

		// Fallback to PEM content if we can't extract key material
		if keyIdentifier == "" {
			keyIdentifier = string(key.PEMData)
		}

		if !seen[keyIdentifier] {
			seen[keyIdentifier] = true
			uniqueKeys = append(uniqueKeys, key)
		}
	}

	fmt.Printf("Removed %d duplicate keys, keeping %d unique keys\n",
		len(keys)-len(uniqueKeys), len(uniqueKeys))
	return uniqueKeys
}

// Enhanced duplicate removal for certificates
func removeDuplicateCerts(certs []ExtractedCert) []ExtractedCert {
	seen := make(map[string]bool)
	var uniqueCerts []ExtractedCert

	for _, cert := range certs {
		// Use certificate serial number and issuer for deduplication
		certIdentifier := fmt.Sprintf("%s:%s",
			cert.Cert.Issuer.String(),
			cert.Cert.SerialNumber.String())

		if !seen[certIdentifier] {
			seen[certIdentifier] = true
			uniqueCerts = append(uniqueCerts, cert)
		}
	}

	fmt.Printf("Removed %d duplicate certificates, keeping %d unique certificates\n",
		len(certs)-len(uniqueCerts), len(uniqueCerts))
	return uniqueCerts
}

// Modified extractRSAKeys to use global duplicate removal
func extractRSAKeys(coreFile string) ([]ExtractedKey, error) {
	stringsOutput, err := getStringsFromCore(coreFile)
	if err != nil {
		return nil, err
	}

	var allKeys []ExtractedKey
	keySet := make(map[string]bool) // Track keys we've already processed

	// Try traditional RSA format
	rsaKeys, err := findPrivateKeysInStrings(stringsOutput, []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
	}, KeyTypeRSA)
	if err == nil {
		for _, key := range rsaKeys {
			keyContent := string(key.PEMData)
			if !keySet[keyContent] {
				keySet[keyContent] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	// Try PKCS#8 format (which might contain RSA keys)
	pkcs8Keys, err := findPKCS8KeysInStrings(stringsOutput, KeyTypeRSA)
	if err == nil {
		for _, key := range pkcs8Keys {
			keyContent := string(key.PEMData)
			if !keySet[keyContent] {
				keySet[keyContent] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	if len(allKeys) == 0 {
		return nil, fmt.Errorf("no RSA private keys found in memory dump")
	}

	// Apply enhanced duplicate removal
	uniqueKeys := removeDuplicateKeys(allKeys)

	fmt.Printf("Found %d unique RSA private key(s) in memory dump\n", len(uniqueKeys))
	return uniqueKeys, nil
}

func findECKeysAggressive(content string) ([]ExtractedKey, error) {
	var keys []ExtractedKey
	lines := strings.Split(content, "\n")

	// Look for base64 content that might be EC keys - common patterns in memory
	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Look for base64 strings that might be EC private keys
		// EC private keys in DER format when base64 encoded often start with certain patterns
		if len(line) > 40 && isBase64Like(line) {
			// Try to construct a PEM block around potential base64 content
			possibleKey := fmt.Sprintf("-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----", line)

			parsedKey, pemData, err := parsePrivateKey(possibleKey, KeyTypeEC)
			if err == nil {
				keys = append(keys, ExtractedKey{
					Key:     parsedKey,
					Type:    KeyTypeEC,
					PEMData: pemData,
				})
				continue
			}

			// Try PKCS#8 format too
			possibleKey = fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", line)
			parsedKey, pemData, err = parsePrivateKey(possibleKey, KeyTypeEC)
			if err == nil {
				keys = append(keys, ExtractedKey{
					Key:     parsedKey,
					Type:    KeyTypeEC,
					PEMData: pemData,
				})
			}
		}

		// Also try multi-line base64 content (look ahead)
		if len(line) > 20 && isBase64Like(line) && i < len(lines)-3 {
			var base64Lines []string
			base64Lines = append(base64Lines, line)

			// Collect subsequent base64-like lines
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				nextLine := strings.TrimSpace(lines[j])
				if len(nextLine) > 10 && isBase64Like(nextLine) {
					base64Lines = append(base64Lines, nextLine)
				} else if len(nextLine) < 10 {
					// Short line might be padding, continue
					if nextLine != "" {
						base64Lines = append(base64Lines, nextLine)
					}
					break
				} else {
					break
				}
			}

			if len(base64Lines) > 1 {
				combinedBase64 := strings.Join(base64Lines, "")

				// Try both EC and PKCS#8 formats
				possibleKey := fmt.Sprintf("-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----", combinedBase64)
				parsedKey, pemData, err := parsePrivateKey(possibleKey, KeyTypeEC)
				if err == nil {
					keys = append(keys, ExtractedKey{
						Key:     parsedKey,
						Type:    KeyTypeEC,
						PEMData: pemData,
					})
					continue
				}

				possibleKey = fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", combinedBase64)
				parsedKey, pemData, err = parsePrivateKey(possibleKey, KeyTypeEC)
				if err == nil {
					keys = append(keys, ExtractedKey{
						Key:     parsedKey,
						Type:    KeyTypeEC,
						PEMData: pemData,
					})
				}
			}
		}
	}

	return keys, nil
}

func isBase64Like(s string) bool {
	if len(s) < 10 {
		return false
	}
	// Check if string contains only base64 characters
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

func getStringsFromCore(coreFile string) (string, error) {
	// Check if strings file already exists
	stringsFile := coreFile + ".strings"

	if _, err := os.Stat(stringsFile); err == nil {
		fmt.Printf("Using existing strings file: %s\n", stringsFile)
		content, err := os.ReadFile(stringsFile)
		if err != nil {
			return "", fmt.Errorf("failed to read existing strings file: %v", err)
		}
		return string(content), nil
	}

	fmt.Printf("Extracting strings from core dump to: %s\n", stringsFile)

	// Create the output file first
	outFile, err := os.Create(stringsFile)
	if err != nil {
		return "", fmt.Errorf("failed to create strings output file: %v", err)
	}
	defer outFile.Close()

	// Run strings command and write directly to file to avoid memory issues
	stringsCmd := exec.Command("strings", coreFile)
	stringsCmd.Stdout = outFile
	stringsCmd.Stderr = os.Stderr // Show any errors

	if err := stringsCmd.Run(); err != nil {
		os.Remove(stringsFile) // Clean up partial file
		return "", fmt.Errorf("failed to run strings command: %v", err)
	}

	// Close the file before reading it back
	outFile.Close()

	fmt.Printf("Strings output saved to: %s\n", stringsFile)

	// Now read the complete file back
	content, err := os.ReadFile(stringsFile)
	if err != nil {
		return "", fmt.Errorf("failed to read strings output file: %v", err)
	}

	return string(content), nil
}

func findPrivateKeysInStrings(content string, markers []string, keyType KeyType) ([]ExtractedKey, error) {
	if len(markers) != 2 {
		return nil, fmt.Errorf("need exactly 2 markers (begin and end)")
	}

	beginMarker := markers[0]
	endMarker := markers[1]

	lines := strings.Split(content, "\n")
	var keys []ExtractedKey
	keySet := make(map[string]bool) // To avoid duplicates

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, beginMarker) {
			var keyLines []string
			keyLines = append(keyLines, beginMarker)

			// Find the end of this key
			found := false
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				keyLines = append(keyLines, nextLine)

				if strings.Contains(nextLine, endMarker) {
					found = true
					i = j // Skip to after this key
					break
				}
			}

			if !found {
				continue
			}

			// Try to parse the key
			pemKey := strings.Join(keyLines, "\n")

			// Skip if we've already seen this exact key
			if keySet[pemKey] {
				continue
			}

			parsedKey, pemData, err := parsePrivateKey(pemKey, keyType)
			if err != nil {
				fmt.Printf("Warning: failed to parse key: %v\n", err)
				continue
			}

			keySet[pemKey] = true
			keys = append(keys, ExtractedKey{
				Key:     parsedKey,
				Type:    keyType,
				PEMData: pemData,
			})
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no %s private keys found in memory dump", keyType)
	}

	return keys, nil
}

func findPKCS8KeysInStrings(content string, keyType KeyType) ([]ExtractedKey, error) {
	lines := strings.Split(content, "\n")
	var keys []ExtractedKey
	keySet := make(map[string]bool) // To avoid duplicates

	beginMarker := "-----BEGIN PRIVATE KEY-----"
	endMarker := "-----END PRIVATE KEY-----"

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, beginMarker) {
			var keyLines []string
			keyLines = append(keyLines, beginMarker)

			// Find the end of this key
			found := false
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				keyLines = append(keyLines, nextLine)

				if strings.Contains(nextLine, endMarker) {
					found = true
					i = j // Skip to after this key
					break
				}
			}

			if !found {
				continue
			}

			// Try to parse the key
			pemKey := strings.Join(keyLines, "\n")

			// Skip if we've already seen this exact key
			if keySet[pemKey] {
				continue
			}

			// Try to parse as the requested key type
			parsedKey, pemData, err := parsePrivateKey(pemKey, keyType)
			if err != nil {
				// This PKCS#8 key is not of the requested type, skip it
				continue
			}

			keySet[pemKey] = true
			keys = append(keys, ExtractedKey{
				Key:     parsedKey,
				Type:    keyType,
				PEMData: pemData,
			})
		}
	}

	return keys, nil
}

func parsePrivateKey(pemKey string, expectedType KeyType) (interface{}, []byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	if expectedType == KeyTypeRSA {
		// Try parsing as RSA key
		switch block.Type {
		case "RSA PRIVATE KEY":
			// Try PKCS1 first
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return key, []byte(pemKey), nil
			}
			// If PKCS1 fails, fall back to PKCS8
			if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rsaKey, ok := parsedKey.(*rsa.PrivateKey); ok {
					return rsaKey, []byte(pemKey), nil
				}
			}
			return nil, nil, fmt.Errorf("failed to parse RSA private key block")
		case "PRIVATE KEY":
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse PKCS8 key: %v", err)
			}
			if rsaKey, ok := parsedKey.(*rsa.PrivateKey); ok {
				return rsaKey, []byte(pemKey), nil
			}
			return nil, nil, fmt.Errorf("PKCS8 key is not RSA")
		}
	} else if expectedType == KeyTypeEC {
		// Try parsing as EC key
		if block.Type == "EC PRIVATE KEY" {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse EC key: %v", err)
			}
			return key, []byte(pemKey), nil
		} else if block.Type == "PRIVATE KEY" {
			// Try PKCS#8 format
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse PKCS8 key: %v", err)
			}
			ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("PKCS8 key is not an EC key, it's %T", parsedKey)
			}
			return ecKey, []byte(pemKey), nil
		}
	}

	return nil, nil, fmt.Errorf("unsupported key type: %s for expected type: %s", block.Type, expectedType)
}

func savePrivateKey(key interface{}, filename string, keyType KeyType) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if keyType == KeyTypeRSA {
		rsaKey := key.(*rsa.PrivateKey)
		privateKeyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
		privateKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyDER,
		}
		return pem.Encode(file, privateKeyBlock)
	} else if keyType == KeyTypeEC {
		ecKey := key.(*ecdsa.PrivateKey)
		privateKeyDER, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return err
		}
		privateKeyBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyDER,
		}
		return pem.Encode(file, privateKeyBlock)
	}

	return fmt.Errorf("unsupported key type")
}

func compareHashes(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	return true
}

func findSpireAgentPID() (int, error) {
	// Use ps to find the process
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to execute ps command: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, processPattern) {
			// Parse the PID from the ps output
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			return pid, nil
		}
	}

	return 0, fmt.Errorf("spire-agent process not found")
}

func dumpMemory(pid int, outputFile string) error {
	// Use gcore to dump memory
	cmd := exec.Command("gcore", "-o", strings.TrimSuffix(outputFile, fmt.Sprintf(".%d", pid)), strconv.Itoa(pid))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gcore failed: %v, output: %s", err, string(output))
	}

	return nil
}

func extractBundleCertificate(targetPID int, outputDir string, bundlePath string) ([]byte, error) {
	fmt.Printf("Reading bundle certificate from %s...\n", bundlePath)

	// Read the bundle certificate by accessing the process's mount namespace directly
	bundleContent, err := readFileFromProcessNamespace(targetPID, bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle certificate: %v", err)
	}

	if len(bundleContent) == 0 {
		return nil, fmt.Errorf("bundle certificate file is empty or not found at %s", bundlePath)
	}

	// Validate that the content looks like a certificate
	bundleStr := string(bundleContent)
	if !strings.Contains(bundleStr, "-----BEGIN CERTIFICATE-----") {
		return nil, fmt.Errorf("bundle file does not contain valid certificate data")
	}

	// Save the raw bundle file
	bundleFile := filepath.Join(outputDir, "bundle.crt")
	if err := os.WriteFile(bundleFile, bundleContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to save bundle certificate: %v", err)
	}

	fmt.Printf("Bundle certificate saved to: %s\n", bundleFile)

	// Parse and display certificate information from the bundle
	if err := displayCertificateInfo(bundleContent); err != nil {
		fmt.Printf("Warning: could not parse certificate info: %v\n", err)
	}

	return bundleContent, nil
}

func displayCertificateInfo(certData []byte) error {
	// Parse all certificates in the bundle
	certPEMs := strings.Split(string(certData), "-----END CERTIFICATE-----")
	certCount := 0

	for i, certPEM := range certPEMs {
		if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
			continue
		}

		// Add back the end marker
		if i < len(certPEMs)-1 {
			certPEM += "-----END CERTIFICATE-----"
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certCount++
		now := time.Now()
		isExpired := now.After(cert.NotAfter)

		expiredStatus := ""
		if isExpired {
			expiredStatus = " [EXPIRED]"
		}

		fmt.Printf("Certificate #%d%s:\n", certCount, expiredStatus)
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Valid from: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("  Valid until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

		// Display URI SANs if present (common in SPIRE)
		if len(cert.URIs) > 0 {
			fmt.Printf("  URI SANs:\n")
			for _, uri := range cert.URIs {
				fmt.Printf("    - %s\n", uri.String())
			}
		}

		// Display DNS SANs if present
		if len(cert.DNSNames) > 0 {
			fmt.Printf("  DNS SANs:\n")
			for _, dns := range cert.DNSNames {
				fmt.Printf("    - %s\n", dns)
			}
		}
		fmt.Println()
	}

	if certCount > 0 {
		fmt.Printf("Total certificates in bundle: %d\n", certCount)
	}

	return nil
}

func readFileFromProcessNamespace(pid int, filePath string) ([]byte, error) {
	// Method 1: Try to read directly from /proc/PID/root/path
	procPath := fmt.Sprintf("/proc/%d/root%s", pid, filePath)
	content, err := os.ReadFile(procPath)
	if err == nil {
		fmt.Printf("Successfully read file using /proc/%d/root method\n", pid)
		return content, nil
	}

	fmt.Printf("Failed to read via /proc/%d/root: %v\n", pid, err)
	fmt.Println("Trying alternative methods...")

	// Method 2: Use nsenter to switch to the mount namespace and read the file ourselves
	// First, we need to use nsenter to get into the namespace, but instead of running cat,
	// we'll read the file by accessing it through the /proc filesystem

	// Get the mount namespace ID
	nsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	// Check if we can access the namespace
	if _, err := os.Stat(nsPath); err != nil {
		return nil, fmt.Errorf("cannot access mount namespace %s: %v", nsPath, err)
	}

	// Method 3: Try to find the file by exploring common mount points
	// This is a fallback method where we try to find where the container's filesystem is mounted
	return findFileInContainerMounts(pid, filePath)
}

func findFileInContainerMounts(pid int, filePath string) ([]byte, error) {
	// Read the mount information for the process
	mountsPath := fmt.Sprintf("/proc/%d/mounts", pid)
	mountsContent, err := os.ReadFile(mountsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mounts for PID %d: %v", pid, err)
	}

	// Parse mounts to find potential locations
	lines := strings.Split(string(mountsContent), "\n")
	var candidatePaths []string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip special filesystems
		if strings.HasPrefix(device, "/dev") ||
			strings.HasPrefix(device, "tmpfs") ||
			strings.HasPrefix(device, "proc") ||
			strings.HasPrefix(device, "sysfs") ||
			strings.HasPrefix(device, "devpts") ||
			fsType == "proc" || fsType == "sysfs" || fsType == "devpts" {
			continue
		}

		// Try to construct the full path
		fullPath := filepath.Join(mountPoint, strings.TrimPrefix(filePath, "/"))
		candidatePaths = append(candidatePaths, fullPath)

		// Also try some common container paths
		if strings.Contains(mountPoint, "run") || strings.Contains(mountPoint, "spire") {
			candidatePaths = append(candidatePaths, filepath.Join(mountPoint, strings.TrimPrefix(filePath, "/")))
		}
	}

	// Try to read from candidate paths
	for _, path := range candidatePaths {
		if content, err := os.ReadFile(path); err == nil {
			fmt.Printf("Successfully found file at: %s\n", path)
			return content, nil
		}
	}

	// Method 4: Try using a simple shell approach with nsenter
	return readFileWithNsenter(pid, filePath)
}

func readFileWithNsenter(pid int, filePath string) ([]byte, error) {
	// Create a temporary script that just reads the file
	tempScript := fmt.Sprintf(`#!/bin/sh
if [ -f "%s" ]; then
    exec < "%s"
    while IFS= read -r line; do
        printf '%%s\n' "$line"
    done
else
    exit 1
fi
`, filePath, filePath)

	// Write the script to a temporary file
	tempFile, err := os.CreateTemp("", "read_bundle_*.sh")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp script: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := tempFile.WriteString(tempScript); err != nil {
		return nil, fmt.Errorf("failed to write temp script: %v", err)
	}

	if err := tempFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp script: %v", err)
	}

	// Make it executable
	if err := os.Chmod(tempFile.Name(), 0755); err != nil {
		return nil, fmt.Errorf("failed to make script executable: %v", err)
	}

	// Execute the script using nsenter
	cmd := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-m", "sh", tempFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read file with nsenter script: %v", err)
	}

	fmt.Printf("Successfully read file using nsenter with custom script\n")
	return output, nil
}
