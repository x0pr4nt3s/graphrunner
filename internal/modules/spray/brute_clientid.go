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

// ClientIDResult holds brute-force client ID results.
type ClientIDResult struct {
	TotalTested int              `json:"total_tested"`
	Valid        []ClientIDHit   `json:"valid"`
	Invalid      []string        `json:"invalid,omitempty"`
}

// ClientIDHit represents a valid client ID found in the tenant.
type ClientIDHit struct {
	ClientID    string `json:"client_id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// WellKnownClientIDs contains commonly known public client IDs.
var WellKnownClientIDs = []ClientIDHit{
	{ClientID: "1950a258-227b-4e31-a9cf-717495945fc2", Name: "Azure PowerShell"},
	{ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", Name: "Azure CLI"},
	{ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office"},
	{ClientID: "00b41c95-dab0-4487-9791-b9d2c32c80f2", Name: "Office 365 Management"},
	{ClientID: "26a7ee05-5602-4d76-a7ba-eae8b7b67941", Name: "Windows Search"},
	{ClientID: "ab9b8c07-8f02-4f72-87fa-80105867a763", Name: "OneDrive Sync Engine"},
	{ClientID: "27922004-5251-4030-b22d-91ecd9a37ea4", Name: "Outlook Mobile"},
	{ClientID: "4813382a-8fa7-425e-ab75-3b753aab3abb", Name: "Microsoft Authenticator"},
	{ClientID: "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", Name: "Visual Studio"},
	{ClientID: "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", Name: "Microsoft Bing Search"},
	{ClientID: "cf36b471-5b44-428c-9ce7-313bf84528de", Name: "Microsoft Teams"},
	{ClientID: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", Name: "Microsoft Teams (alternate)"},
	{ClientID: "5e3ce6c0-2b1f-4285-8d4b-75ee78787346", Name: "Microsoft Teams Web Client"},
	{ClientID: "00000002-0000-0ff1-ce00-000000000000", Name: "Exchange Online"},
	{ClientID: "00000003-0000-0000-c000-000000000000", Name: "Microsoft Graph"},
	{ClientID: "00000009-0000-0000-c000-000000000000", Name: "Power BI"},
	{ClientID: "00000007-0000-0ff1-ce00-000000000000", Name: "SharePoint Online"},
}

// BruteClientID tests a list of client IDs against a tenant to find valid ones.
// Uses device code flow initiation — a valid client ID returns a user_code, invalid returns error.
func BruteClientID(ctx context.Context, tenantID string, candidates []ClientIDHit, delaySec int) (*ClientIDResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("--tenant-id is required for brute-clientid")
	}

	result := &ClientIDResult{}
	httpClient := &http.Client{Timeout: 10 * time.Second}

	deviceCodeURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenantID)

	output.Info("Testing %d client IDs against tenant %s...", len(candidates), tenantID)

	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		result.TotalTested++

		valid, err := testClientID(httpClient, deviceCodeURL, candidate.ClientID)
		if err != nil {
			output.Verbose("  %s (%s) — error: %v", candidate.ClientID, candidate.Name, err)
			continue
		}

		if valid {
			output.Success("  VALID: %s — %s", candidate.ClientID, candidate.Name)
			result.Valid = append(result.Valid, candidate)
		} else {
			output.Verbose("  invalid: %s (%s)", candidate.ClientID, candidate.Name)
			result.Invalid = append(result.Invalid, candidate.ClientID)
		}

		if delaySec > 0 {
			select {
			case <-ctx.Done():
				return result, nil
			case <-time.After(time.Duration(delaySec) * time.Second):
			}
		}
	}

	output.Success("Brute-clientid complete: %d tested | %d valid", result.TotalTested, len(result.Valid))
	return result, nil
}

// testClientID initiates a device code flow and checks if the client ID is valid in the tenant.
func testClientID(httpClient *http.Client, deviceCodeURL, clientID string) (bool, error) {
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"https://graph.microsoft.com/.default"},
	}

	resp, err := httpClient.PostForm(deviceCodeURL, data)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	bodyStr := string(body)

	if resp.StatusCode == 200 {
		// Got a device code — client ID is valid
		return true, nil
	}

	// Check for "application not found" vs other errors
	if strings.Contains(bodyStr, "AADSTS700016") ||
		strings.Contains(bodyStr, "application_not_found") ||
		strings.Contains(bodyStr, "invalid_client") {
		return false, nil
	}

	// Other errors (tenant issues, etc.) — still might be valid client
	if strings.Contains(bodyStr, "AADSTS") {
		// AADSTS error but not "app not found" — client ID exists
		return true, nil
	}

	return false, fmt.Errorf("unexpected response: HTTP %d", resp.StatusCode)
}
