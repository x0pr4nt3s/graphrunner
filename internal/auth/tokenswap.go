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

// TokenSwapFlow exchanges a refresh token for a new access token targeting a different resource.
// This is the core of TokenTactics — one refresh token can access multiple Azure services.
type TokenSwapFlow struct {
	TenantID string
	ClientID string
}

// ResourceScopes maps friendly names to Azure resource scope URLs.
var ResourceScopes = map[string]string{
	"graph":     "https://graph.microsoft.com/.default",
	"azure":     "https://management.azure.com/.default",
	"outlook":   "https://outlook.office365.com/.default",
	"vault":     "https://vault.azure.net/.default",
	"storage":   "https://storage.azure.com/.default",
	"substrate": "https://substrate.office.com/.default",
	"teams":     "https://api.spaces.skype.com/.default",
	"office":    "https://officeapps.live.com/.default",
	"core-mgmt": "https://management.core.windows.net/.default",
}

// Swap exchanges a refresh_token for a new access_token targeting targetResource.
// targetResource can be a key from ResourceScopes (e.g. "vault") or a raw scope URL
// (e.g. "https://contoso.sharepoint.com/.default").
// The returned AuthResult is NOT stored automatically — the caller decides whether to persist it.
func (t *TokenSwapFlow) Swap(ctx context.Context, refreshToken, targetResource string) (*AuthResult, error) {
	// Resolve friendly name to scope URL
	scope := targetResource
	if s, ok := ResourceScopes[targetResource]; ok {
		scope = s
	}

	// Always request offline_access so we get a new refresh token back
	if !strings.Contains(scope, "offline_access") {
		scope = scope + " offline_access"
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", t.TenantID)
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {t.ClientID},
		"refresh_token": {refreshToken},
		"scope":         {scope},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token swap request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token swap response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token swap response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("token swap error: %s — %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access token in token swap response")
	}

	return &AuthResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scopes:       strings.Fields(tr.Scope),
	}, nil
}
