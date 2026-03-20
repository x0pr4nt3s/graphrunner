package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"
)

// CertLoginFlow implements client_credentials with a certificate (client_assertion).
type CertLoginFlow struct {
	TenantID string
	ClientID string
	CertPath string // path to PEM or PFX file
	KeyPath  string // path to private key PEM (if cert is PEM; empty for PFX)
	Password string // PFX password (if PFX)
}

// Authenticate acquires a token using certificate-based client credentials.
func (c *CertLoginFlow) Authenticate(ctx context.Context) (*AuthResult, error) {
	cert, key, err := c.loadCertAndKey()
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	assertion, err := buildClientAssertion(c.TenantID, c.ClientID, cert, key)
	if err != nil {
		return nil, fmt.Errorf("build client assertion: %w", err)
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.TenantID)
	data := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {c.ClientID},
		"scope":                 {"https://graph.microsoft.com/.default"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cert login request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("cert auth error: %s — %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access token in cert auth response: %s", body)
	}

	return &AuthResult{
		AccessToken: tr.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scopes:      strings.Fields(tr.Scope),
	}, nil
}

func (c *CertLoginFlow) loadCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	data, err := os.ReadFile(c.CertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}

	// Try PFX first
	if strings.HasSuffix(strings.ToLower(c.CertPath), ".pfx") || strings.HasSuffix(strings.ToLower(c.CertPath), ".p12") {
		return parsePFX(data, c.Password)
	}

	// PEM cert + separate key file
	cert, err := parsePEMCert(data)
	if err != nil {
		return nil, nil, err
	}

	if c.KeyPath == "" {
		// Try to find key in the same PEM file
		key, err := parsePEMKey(data)
		if err != nil {
			return nil, nil, fmt.Errorf("no key found in PEM file and --key-file not specified")
		}
		return cert, key, nil
	}

	keyData, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := parsePEMKey(keyData)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func parsePFX(data []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decode PFX: %w", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("PFX private key is not RSA")
	}
	return cert, rsaKey, nil
}

func parsePEMCert(data []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no certificate found in PEM data")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
}

func parsePEMKey(data []byte) (*rsa.PrivateKey, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no RSA private key found in PEM data")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key is not RSA")
			}
			return rsaKey, nil
		}
		data = rest
	}
}

// buildClientAssertion creates a signed JWT for client_assertion auth.
// Azure AD requires: iss=client_id, sub=client_id, aud=token_endpoint, x5t=thumbprint.
func buildClientAssertion(tenantID, clientID string, cert *x509.Certificate, key *rsa.PrivateKey) (string, error) {
	// x5t: base64url-encoded SHA-256 thumbprint of the cert
	thumbprint := sha256.Sum256(cert.Raw)
	x5t := base64.RawURLEncoding.EncodeToString(thumbprint[:])

	now := time.Now()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": x5t,
	}
	payload := map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

