package auth

import (
	"context"
	"fmt"
	"time"
)

// AuthResult is returned by all authentication flows.
type AuthResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Scopes       []string
}

// Authenticator orchestrates auth flows and persists sessions.
type Authenticator struct {
	Store *TokenStore
}

// NewAuthenticator creates an Authenticator with the given token store.
func NewAuthenticator(store *TokenStore) *Authenticator {
	return &Authenticator{Store: store}
}

// LoginDeviceCode runs the device code flow, stores the session, and marks it active.
func (a *Authenticator) LoginDeviceCode(ctx context.Context, sessionName, tenantID, clientID string) (*Session, error) {
	dc := &DeviceCodeFlow{TenantID: tenantID, ClientID: clientID}
	result, err := dc.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("device code auth: %w", err)
	}
	return a.storeSession(sessionName, tenantID, clientID, "device_code", result)
}

// LoginClientCredentials runs the client credentials flow.
func (a *Authenticator) LoginClientCredentials(ctx context.Context, sessionName, tenantID, clientID, clientSecret string) (*Session, error) {
	cc := &ClientCredsFlow{TenantID: tenantID, ClientID: clientID, ClientSecret: clientSecret}
	result, err := cc.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("client credentials auth: %w", err)
	}
	return a.storeSession(sessionName, tenantID, clientID, "client_credentials", result)
}

// LoginROPC runs the Resource Owner Password Credentials flow.
func (a *Authenticator) LoginROPC(ctx context.Context, sessionName, tenantID, clientID, username, password string) (*Session, error) {
	ropc := &ROPCFlow{TenantID: tenantID, ClientID: clientID, Username: username, Password: password}
	result, err := ropc.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("ROPC auth: %w", err)
	}
	return a.storeSession(sessionName, tenantID, clientID, "ropc", result)
}

// ImportToken stores a raw token pair as a session.
func (a *Authenticator) ImportToken(sessionName, tenantID, clientID, accessToken, refreshToken string, expiresIn int) (*Session, error) {
	result := &AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	return a.storeSession(sessionName, tenantID, clientID, "imported", result)
}

// RefreshSession refreshes the token for a named session.
func (a *Authenticator) RefreshSession(ctx context.Context, name string) (*Session, error) {
	sess, err := a.Store.Get(name)
	if err != nil {
		return nil, err
	}
	if sess.RefreshToken == "" {
		return nil, fmt.Errorf("session %q has no refresh token (flow: %s)", name, sess.AuthFlow)
	}

	rf := &RefreshFlow{TenantID: sess.TenantID, ClientID: sess.ClientID}
	result, err := rf.Refresh(ctx, sess.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	if err := a.Store.Update(name, result.AccessToken, result.RefreshToken, result.ExpiresAt); err != nil {
		return nil, err
	}
	return a.Store.Get(name)
}

// EnsureValidToken returns a valid access token for the active session, refreshing if needed.
func (a *Authenticator) EnsureValidToken(ctx context.Context) (string, error) {
	sess, err := a.Store.GetActive()
	if err != nil {
		return "", err
	}

	if !sess.IsExpired() {
		return sess.AccessToken, nil
	}

	// Try refresh
	if sess.RefreshToken != "" {
		refreshed, err := a.RefreshSession(ctx, sess.Name)
		if err == nil {
			return refreshed.AccessToken, nil
		}
	}

	return "", fmt.Errorf("session %q expired and refresh failed — re-authenticate", sess.Name)
}

func (a *Authenticator) storeSession(name, tenantID, clientID, flow string, result *AuthResult) (*Session, error) {
	sess := &Session{
		Name:         name,
		TenantID:     tenantID,
		ClientID:     clientID,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
		Scopes:       result.Scopes,
		AuthFlow:     flow,
		Active:       true,
	}

	// Decode JWT to populate identity fields and resolve real tenant ID
	if claims, err := ParseJWT(result.AccessToken); err == nil {
		sess.UserPrincipalName = claims.UPN
		sess.DisplayName = claims.Name
		sess.ObjectID = claims.ObjectID
		if claims.TenantID != "" {
			sess.TenantID = claims.TenantID
		}
	}

	if err := a.Store.Add(sess); err != nil {
		return nil, err
	}
	if err := a.Store.SetActive(name); err != nil {
		return nil, err
	}
	return sess, nil
}
