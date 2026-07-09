package spiffe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"spooffe/extractor"
	"spooffe/utils"
)

// const (
// 	SpireSocket = "unix:///run/spire/sockets/agent.sock"
// )

// FetchJWT returns the JWT SVID as a string (without saving it to file)
// func FetchJWT(pair extractor.PodContainerPair) (string, error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	client, err := workloadapi.New(ctx, workloadapi.WithAddr(SpireSocket))
// 	if err != nil {
// 		return "", fmt.Errorf("failed to create workload API client: %w", err)
// 	}

// 	jwt, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "my-service"})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
// 	}

// 	return jwt.Marshal(), nil
// }

func FetchJWT(pair extractor.PodContainerPair, spireSocket string, timeoutSec int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(utils.NormalizeSocketPath(spireSocket)))
	if err != nil {
		return "", fmt.Errorf("failed to create workload API client: %w", err)
	}

	jwt, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "my-service"})
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}

	return jwt.Marshal(), nil
}


// FetchX509 returns the X.509 certificate and private key as byte slices (PEM-encoded)
func FetchX509(pair extractor.PodContainerPair, spireSocket string, timeoutSec int) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(utils.NormalizeSocketPath(spireSocket)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create workload API client: %w", err)
	}

	x509svid, err := client.FetchX509SVID(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch X.509-SVID: %w", err)
	}

	var certPEM []byte
	for _, cert := range x509svid.Certificates {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	keyPEM, err := encodePrivateKeyToPEM(x509svid.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return certPEM, keyPEM, nil
}


// encodePrivateKeyToPEM converts the private key to PEM format
func encodePrivateKeyToPEM(key crypto.Signer) ([]byte, error) {
	var privateKeyBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		privateKeyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
	default:
		return nil, errors.New("unsupported private key type")
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}), nil
}
