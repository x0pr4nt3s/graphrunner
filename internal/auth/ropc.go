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

// ROPCFlow implements the Resource Owner Password Credentials grant.
// Only works when MFA is not enforced on the target account.
type ROPCFlow struct {
	TenantID string
	ClientID string
	Username string
	Password string
	Scopes   []string
}

// Authenticate acquires a token using username and password.
func (r *ROPCFlow) Authenticate(ctx context.Context) (*AuthResult, error) {
	if len(r.Scopes) == 0 {
		r.Scopes = []string{"https://graph.microsoft.com/.default", "offline_access"}
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", r.TenantID)
	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {r.ClientID},
		"username":   {r.Username},
		"password":   {r.Password},
		"scope":      {strings.Join(r.Scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ROPC request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("ROPC error: %s — %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response: %s", body)
	}

	return &AuthResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scopes:       strings.Fields(tr.Scope),
	}, nil
}
