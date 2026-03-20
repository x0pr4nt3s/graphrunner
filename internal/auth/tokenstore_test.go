package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func tempStoreDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "sessions.enc")
}

func newTestStore(t *testing.T) *TokenStore {
	t.Helper()
	dir := t.TempDir()
	ts := &TokenStore{
		path: filepath.Join(dir, "sessions.enc"),
		key:  deriveKey("test-passphrase"),
	}
	return ts
}

func makeSession(name string) *Session {
	return &Session{
		Name:        name,
		TenantID:    "tenant-123",
		ClientID:    "client-456",
		AccessToken: "eyJ0eXAiOiJKV1QiLCJub25jZSI6Ikh0cGc...",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		AuthFlow:    "device_code",
		Active:      false,
	}
}

func TestTokenStore_AddAndGet(t *testing.T) {
	ts := newTestStore(t)

	s := makeSession("test-session")
	if err := ts.Add(s); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := ts.Get("test-session")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "test-session" {
		t.Errorf("got name %q, want %q", got.Name, "test-session")
	}
	if got.TenantID != "tenant-123" {
		t.Errorf("got tenant %q, want %q", got.TenantID, "tenant-123")
	}
}

func TestTokenStore_AddReplace(t *testing.T) {
	ts := newTestStore(t)

	s1 := makeSession("session-1")
	s1.AccessToken = "token-old"
	ts.Add(s1)

	s2 := makeSession("session-1")
	s2.AccessToken = "token-new"
	ts.Add(s2)

	got, _ := ts.Get("session-1")
	if got.AccessToken != "token-new" {
		t.Errorf("expected replaced token, got %q", got.AccessToken)
	}

	if ts.Count() != 1 {
		t.Errorf("expected 1 session after replace, got %d", ts.Count())
	}
}

func TestTokenStore_Remove(t *testing.T) {
	ts := newTestStore(t)
	ts.Add(makeSession("s1"))
	ts.Add(makeSession("s2"))

	if err := ts.Remove("s1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if ts.Count() != 1 {
		t.Errorf("expected 1 session, got %d", ts.Count())
	}

	_, err := ts.Get("s1")
	if err == nil {
		t.Error("expected error getting removed session")
	}
}

func TestTokenStore_RemoveNotFound(t *testing.T) {
	ts := newTestStore(t)
	err := ts.Remove("nonexistent")
	if err == nil {
		t.Error("expected error removing nonexistent session")
	}
}

func TestTokenStore_SetActive(t *testing.T) {
	ts := newTestStore(t)
	ts.Add(makeSession("s1"))
	ts.Add(makeSession("s2"))

	if err := ts.SetActive("s2"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	active, err := ts.GetActive()
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.Name != "s2" {
		t.Errorf("expected active session s2, got %s", active.Name)
	}

	// s1 should not be active
	s1, _ := ts.Get("s1")
	if s1.Active {
		t.Error("s1 should not be active")
	}
}

func TestTokenStore_NoActiveSession(t *testing.T) {
	ts := newTestStore(t)
	_, err := ts.GetActive()
	if err == nil {
		t.Error("expected error when no active session")
	}
}

func TestTokenStore_List(t *testing.T) {
	ts := newTestStore(t)
	ts.Add(makeSession("s1"))
	ts.Add(makeSession("s2"))

	list := ts.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(list))
	}

	// Tokens should be masked
	for _, s := range list {
		if s.AccessToken == "eyJ0eXAiOiJKV1QiLCJub25jZSI6Ikh0cGc..." {
			t.Error("access token should be masked in List()")
		}
	}
}

func TestTokenStore_Update(t *testing.T) {
	ts := newTestStore(t)
	ts.Add(makeSession("s1"))

	newExpiry := time.Now().Add(2 * time.Hour)
	if err := ts.Update("s1", "new-token", "new-refresh", newExpiry); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := ts.Get("s1")
	if got.AccessToken != "new-token" {
		t.Errorf("access token not updated")
	}
	if got.RefreshToken != "new-refresh" {
		t.Errorf("refresh token not updated")
	}
}

func TestTokenStore_PersistenceAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.enc")
	key := deriveKey("persist-test")

	// Write
	ts1 := &TokenStore{path: path, key: key}
	ts1.Add(makeSession("persist-sess"))
	ts1.SetActive("persist-sess")

	// Read from new store instance
	ts2 := &TokenStore{path: path, key: key}
	if err := ts2.load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	got, err := ts2.GetActive()
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if got.Name != "persist-sess" {
		t.Errorf("expected persist-sess, got %s", got.Name)
	}
}

func TestTokenStore_WrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.enc")

	// Write with key A
	ts1 := &TokenStore{path: path, key: deriveKey("passA")}
	ts1.Add(makeSession("secret-sess"))

	// Read with key B
	ts2 := &TokenStore{path: path, key: deriveKey("passB")}
	err := ts2.load()
	if err == nil {
		t.Error("expected decryption error with wrong passphrase")
	}
}

func TestSession_IsExpired(t *testing.T) {
	s := makeSession("test")
	if s.IsExpired() {
		t.Error("session should not be expired")
	}

	s.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if !s.IsExpired() {
		t.Error("session should be expired")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := deriveKey("test-key")
	plaintext := []byte("hello world secret data 12345")

	ct, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(pt) != string(plaintext) {
		t.Errorf("decrypted %q != original %q", pt, plaintext)
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "***"},
		{"", "***"},
		{"abcdefghijklmnopqrs", "abcdef...nopqrs"},
	}
	for _, tt := range tests {
		got := maskToken(tt.input)
		if got != tt.want {
			t.Errorf("maskToken(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

