package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RefreshFlow handles token refresh using a stored refresh_token.
type RefreshFlow struct {
	TenantID string
	ClientID string
}

// Refresh exchanges a refresh token for a new access + refresh token pair.
func (r *RefreshFlow) Refresh(ctx context.Context, refreshToken string) (*AuthResult, error) {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", r.TenantID)
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {r.ClientID},
		"refresh_token": {refreshToken},
		"scope":         {"https://graph.microsoft.com/.default offline_access"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("refresh error: %s — %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access token in refresh response")
	}

	return &AuthResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scopes:       strings.Fields(tr.Scope),
	}, nil
}

// AutoRefresher runs a background loop that refreshes a session's token before expiry.
type AutoRefresher struct {
	Auth     *Authenticator
	Session  string
	Interval time.Duration
	cancel   context.CancelFunc
}

// Start begins the auto-refresh loop in a goroutine.
func (ar *AutoRefresher) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	ar.cancel = cancel
	if ar.Interval == 0 {
		ar.Interval = 5 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(ar.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sess, err := ar.Auth.Store.Get(ar.Session)
				if err != nil {
					continue
				}
				// Refresh if token expires within 10 minutes
				if time.Until(sess.ExpiresAt) < 10*time.Minute {
					_, _ = ar.Auth.RefreshSession(context.Background(), ar.Session)
				}
			}
		}
	}()
}

// Stop cancels the auto-refresh loop.
func (ar *AutoRefresher) Stop() {
	if ar.cancel != nil {
		ar.cancel()
	}
}
