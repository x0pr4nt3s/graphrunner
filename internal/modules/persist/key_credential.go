package persist

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// KeyCredResult holds the result of adding a key credential to an app.
type KeyCredResult struct {
	AppObjectID string `json:"app_object_id"`
	DisplayName string `json:"display_name"`
	Thumbprint  string `json:"thumbprint"`
	KeyPEMFile  string `json:"key_pem_file"`
	CertPEM     string `json:"cert_pem"`
	NotAfter    string `json:"not_after"`
}

// GenerateSelfSignedCert creates a self-signed X.509 certificate for use as an app credential.
// Returns the certificate PEM, private key PEM, and SHA-1 thumbprint of the certificate.
func GenerateSelfSignedCert(cn string, validDays int) (certPEM, keyPEM []byte, thumbprint string, err error) {
	if validDays <= 0 {
		validDays = 365
	}

	// Generate RSA 2048 key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate RSA key: %w", err)
	}

	// Serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Compute SHA-1 thumbprint of the DER-encoded certificate
	hash := sha1.Sum(certDER)
	thumbprint = fmt.Sprintf("%X", hash)

	return certPEM, keyPEM, thumbprint, nil
}

// AddKeyCredential adds a certificate credential to an application.
// It generates a self-signed cert, patches the app's keyCredentials array, and saves the private key PEM to disk.
// This is more stealthy than addPassword because cert-based auth doesn't appear in sign-in logs the same way.
func AddKeyCredential(ctx context.Context, client *graph.Client, appObjectID, displayName string, validDays int) (*KeyCredResult, error) {
	if appObjectID == "" {
		return nil, fmt.Errorf("appObjectID is required (application object ID)")
	}
	if displayName == "" {
		displayName = "GraphRunner"
	}
	if validDays <= 0 {
		validDays = 365
	}

	cn := fmt.Sprintf("%s.graphrunner.local", displayName)

	// Step 1: Generate self-signed certificate
	output.Info("Generating self-signed certificate (CN=%s, valid=%d days)...", cn, validDays)
	certPEM, keyPEM, thumbprint, err := GenerateSelfSignedCert(cn, validDays)
	if err != nil {
		return nil, fmt.Errorf("generate certificate: %w", err)
	}

	// Step 2: Fetch existing keyCredentials to avoid overwriting them
	output.Info("Fetching existing keyCredentials for app %s...", appObjectID)
	endpoint := fmt.Sprintf("/applications/%s", appObjectID)
	appRaw, err := client.Get(ctx, endpoint, map[string]string{
		"$select": "id,keyCredentials",
	})
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	var appData map[string]interface{}
	if err := json.Unmarshal(appRaw, &appData); err != nil {
		return nil, fmt.Errorf("parse application response: %w", err)
	}

	// Extract existing keyCredentials array
	existingCreds, _ := appData["keyCredentials"].([]interface{})

	// Decode the cert PEM to get raw DER bytes for the key field
	block, _ := pem.Decode(certPEM)
	certBase64 := base64.StdEncoding.EncodeToString(block.Bytes)

	// Build new credential entry
	newCred := map[string]interface{}{
		"type":        "AsymmetricX509Cert",
		"usage":       "Verify",
		"key":         certBase64,
		"displayName": displayName,
	}

	// Append to existing credentials
	updatedCreds := append(existingCreds, newCred)

	// Step 3: PATCH the application with updated keyCredentials
	output.Info("Patching app with new keyCredential...")
	patchBody := map[string]interface{}{
		"keyCredentials": updatedCreds,
	}
	_, err = client.Patch(ctx, endpoint, patchBody)
	if err != nil {
		return nil, fmt.Errorf("patch keyCredentials: %w", err)
	}

	// Step 4: Save private key PEM to file
	keyFilename := fmt.Sprintf("%s_%s.pem", appObjectID, thumbprint[:8])
	if err := os.WriteFile(keyFilename, keyPEM, 0600); err != nil {
		output.Warn("Failed to write PEM file %s: %v", keyFilename, err)
	} else {
		output.Info("Private key saved: %s", keyFilename)
	}

	notAfter := time.Now().UTC().AddDate(0, 0, validDays).Format(time.RFC3339)

	result := &KeyCredResult{
		AppObjectID: appObjectID,
		DisplayName: displayName,
		Thumbprint:  thumbprint,
		KeyPEMFile:  keyFilename,
		CertPEM:     string(certPEM),
		NotAfter:    notAfter,
	}

	output.Success("Key credential added!")
	output.Info("  App Object ID: %s", appObjectID)
	output.Info("  Display Name:  %s", displayName)
	output.Info("  Thumbprint:    %s", thumbprint)
	output.Info("  PEM File:      %s", keyFilename)
	output.Info("  Expires:       %s", notAfter)
	output.Warn("  Use this cert + thumbprint with client_assertion auth flow.")

	return result, nil
}
