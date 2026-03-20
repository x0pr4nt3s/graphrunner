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

// ClientCredsFlow implements the OAuth2 client credentials grant (app-only).
type ClientCredsFlow struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

// Authenticate acquires a token using client credentials.
func (c *ClientCredsFlow) Authenticate(ctx context.Context) (*AuthResult, error) {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"https://graph.microsoft.com/.default"}
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.TenantID)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"scope":         {strings.Join(c.Scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client credentials request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("auth error: %s — %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response: %s", body)
	}

	return &AuthResult{
		AccessToken: tr.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scopes:      strings.Fields(tr.Scope),
	}, nil
}
