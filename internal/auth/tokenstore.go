package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Session represents a stored authenticated session against an M365 tenant.
type Session struct {
	Name               string    `json:"name"`
	TenantID           string    `json:"tenant_id"`
	ClientID           string    `json:"client_id"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	Scopes             []string  `json:"scopes,omitempty"`
	AuthFlow           string    `json:"auth_flow"`
	Active             bool      `json:"active"`
	UserPrincipalName  string    `json:"upn,omitempty"`
	DisplayName        string    `json:"display_name,omitempty"`
	ObjectID           string    `json:"object_id,omitempty"`
}

// JWTClaims holds the decoded fields we care about from an access token.
type JWTClaims struct {
	UPN         string `json:"upn"`
	UniqueName  string `json:"unique_name"`
	Name        string `json:"name"`
	TenantID    string `json:"tid"`
	ObjectID    string `json:"oid"`
	AppID       string `json:"appid"`
}

// ParseJWT decodes the payload of a JWT and extracts common claims.
// Does NOT validate signature — for display purposes only.
func ParseJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	// JWTs use raw URL-safe base64 (no padding)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	// Prefer upn over unique_name
	if claims.UPN == "" {
		claims.UPN = claims.UniqueName
	}
	return &claims, nil
}

// IsExpired returns true if the access token has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// TokenStore manages multiple encrypted sessions on disk.
type TokenStore struct {
	mu       sync.RWMutex
	path     string
	key      []byte // AES-256 key derived from passphrase/machine seed
	sessions []*Session
}

// NewTokenStore creates or loads a token store.
// If passphrase is empty, a machine-specific key is derived.
func NewTokenStore(passphrase string) (*TokenStore, error) {
	dir, err := defaultStoreDir()
	if err != nil {
		return nil, err
	}
	storePath := filepath.Join(dir, "sessions.enc")

	key := deriveKey(passphrase)

	ts := &TokenStore{
		path: storePath,
		key:  key,
	}

	// Load existing sessions if the file exists
	if _, err := os.Stat(storePath); err == nil {
		if err := ts.load(); err != nil {
			return nil, fmt.Errorf("failed to open session store (wrong passphrase or corrupt file): %w", err)
		}
	}

	return ts, nil
}

// defaultStoreDir returns ~/.graphrunner/
func defaultStoreDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".graphrunner")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create store directory: %w", err)
	}
	return dir, nil
}

// kdfSalt is a fixed application-specific salt for PBKDF2.
// Using a fixed salt allows deterministic key derivation without storing the salt.
// A user-supplied --passphrase protects against offline dictionary attacks.
var kdfSalt = []byte("graphrunner-v1-kdf-salt-2024")

// deriveKey builds a 32-byte AES key from a passphrase using PBKDF2-SHA256.
// If passphrase is empty, uses hostname + username as seed (weaker; use --passphrase for sensitive stores).
func deriveKey(passphrase string) []byte {
	if passphrase == "" {
		hostname, _ := os.Hostname()
		username := os.Getenv("USER")
		if username == "" {
			username = os.Getenv("USERNAME")
		}
		passphrase = "graphrunner:" + hostname + ":" + username
	}
	return pbkdf2.Key([]byte(passphrase), kdfSalt, 600_000, 32, sha256.New)
}

// ---------- CRUD operations ----------

// Add inserts a new session. If a session with the same name exists, it is replaced.
func (ts *TokenStore) Add(s *Session) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Replace if exists
	for i, existing := range ts.sessions {
		if existing.Name == s.Name {
			ts.sessions[i] = s
			return ts.save()
		}
	}

	ts.sessions = append(ts.sessions, s)
	return ts.save()
}

// Remove deletes a session by name.
func (ts *TokenStore) Remove(name string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for i, s := range ts.sessions {
		if s.Name == name {
			ts.sessions = append(ts.sessions[:i], ts.sessions[i+1:]...)
			return ts.save()
		}
	}
	return fmt.Errorf("session %q not found", name)
}

// List returns all sessions (tokens are masked).
func (ts *TokenStore) List() []Session {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	out := make([]Session, len(ts.sessions))
	for i, s := range ts.sessions {
		out[i] = *s
		// Mask tokens for display
		out[i].AccessToken = maskToken(s.AccessToken)
		out[i].RefreshToken = maskToken(s.RefreshToken)
	}
	return out
}

// GetActive returns the currently active session, or an error if none.
func (ts *TokenStore) GetActive() (*Session, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, s := range ts.sessions {
		if s.Active {
			return s, nil
		}
	}
	return nil, fmt.Errorf("no active session — use 'graphrunner auth use <name>' to select one")
}

// Get returns a session by name.
func (ts *TokenStore) Get(name string) (*Session, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, s := range ts.sessions {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("session %q not found", name)
}

// SetActive marks a session as active (deactivating all others).
func (ts *TokenStore) SetActive(name string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	found := false
	for _, s := range ts.sessions {
		if s.Name == name {
			s.Active = true
			found = true
		} else {
			s.Active = false
		}
	}
	if !found {
		return fmt.Errorf("session %q not found", name)
	}
	return ts.save()
}

// Update replaces the tokens on an existing session (used after refresh).
func (ts *TokenStore) Update(name, accessToken, refreshToken string, expiresAt time.Time) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, s := range ts.sessions {
		if s.Name == name {
			s.AccessToken = accessToken
			if refreshToken != "" {
				s.RefreshToken = refreshToken
			}
			s.ExpiresAt = expiresAt
			return ts.save()
		}
	}
	return fmt.Errorf("session %q not found", name)
}

// Count returns the number of stored sessions.
func (ts *TokenStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.sessions)
}

// ---------- Encryption / persistence ----------

func (ts *TokenStore) save() error {
	plaintext, err := json.MarshalIndent(ts.sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sessions: %w", err)
	}

	ciphertext, err := encrypt(plaintext, ts.key)
	if err != nil {
		return fmt.Errorf("encrypt sessions: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(ts.path), 0700); err != nil {
		return err
	}
	return os.WriteFile(ts.path, ciphertext, 0600)
}

func (ts *TokenStore) load() error {
	ciphertext, err := os.ReadFile(ts.path)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(ciphertext, ts.key)
	if err != nil {
		return fmt.Errorf("decrypt sessions: %w", err)
	}

	return json.Unmarshal(plaintext, &ts.sessions)
}

// ---------- AES-256-GCM helpers ----------

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// maskToken returns a masked version of a token for display.
func maskToken(token string) string {
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-6:]
}
