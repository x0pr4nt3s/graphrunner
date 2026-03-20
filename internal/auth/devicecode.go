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

// DeviceCodeFlow implements the OAuth2 device code grant for interactive login.
type DeviceCodeFlow struct {
	TenantID string
	ClientID string
	Scopes   []string // defaults to Graph .default
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// Authenticate starts the device code flow and waits for user completion.
func (d *DeviceCodeFlow) Authenticate(ctx context.Context) (*AuthResult, error) {
	if len(d.Scopes) == 0 {
		d.Scopes = []string{"https://graph.microsoft.com/.default", "offline_access"}
	}

	authority := fmt.Sprintf("https://login.microsoftonline.com/%s", d.TenantID)

	// Step 1: Request device code
	dcResp, err := d.requestDeviceCode(authority)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n[*] %s\n\n", dcResp.Message)

	// Step 2: Poll for token
	return d.pollForToken(ctx, authority, dcResp)
}

func (d *DeviceCodeFlow) requestDeviceCode(authority string) (*deviceCodeResponse, error) {
	endpoint := authority + "/oauth2/v2.0/devicecode"
	data := url.Values{
		"client_id": {d.ClientID},
		"scope":     {strings.Join(d.Scopes, " ")},
	}

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("device code request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (%d): %s", resp.StatusCode, body)
	}

	var dcResp deviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("parse device code response: %w", err)
	}
	return &dcResp, nil
}

func (d *DeviceCodeFlow) pollForToken(ctx context.Context, authority string, dcResp *deviceCodeResponse) (*AuthResult, error) {
	endpoint := authority + "/oauth2/v2.0/token"
	interval := time.Duration(dcResp.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device code expired — user did not authenticate in time")
		}

		time.Sleep(interval)

		data := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {d.ClientID},
			"device_code": {dcResp.DeviceCode},
		}

		resp, err := http.PostForm(endpoint, data)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			continue
		}

		switch tr.Error {
		case "":
			// Success
			return &AuthResult{
				AccessToken:  tr.AccessToken,
				RefreshToken: tr.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
				Scopes:       strings.Fields(tr.Scope),
			}, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return nil, fmt.Errorf("token error: %s — %s", tr.Error, tr.ErrorDesc)
		}
	}
}
