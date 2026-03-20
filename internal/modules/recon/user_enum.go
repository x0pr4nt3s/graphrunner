package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/graphrunner/internal/output"
)

// GetCredentialType endpoint (unauthenticated).
const getCredentialTypeURL = "https://login.microsoftonline.com/common/GetCredentialType"

// UserEnumResult holds the full enumeration result set.
type UserEnumResult struct {
	Valid     []EnumEntry `json:"valid"`
	Invalid   []string    `json:"invalid"`
	Unknown   []EnumEntry `json:"unknown,omitempty"`
	Throttled []string    `json:"throttled,omitempty"`
	Total     int         `json:"total"`
}

// EnumEntry describes one validated user.
type EnumEntry struct {
	Username        string `json:"username"`
	IfExistsResult  int    `json:"if_exists_result"`
	DomainType      int    `json:"domain_type,omitempty"`      // 1=managed, 2=federated, 3=cloud-only
	PrefCredential  int    `json:"pref_credential,omitempty"`  // 1=password, 4=FIDO, 6=phone, ...
	HasPassword     bool   `json:"has_password,omitempty"`
	DesktopSSO      bool   `json:"desktop_sso,omitempty"`
	TenantBranding  bool   `json:"tenant_branding,omitempty"`
	FederationURL   string `json:"federation_url,omitempty"`
}

// credTypeRequest is the JSON body sent to GetCredentialType.
type credTypeRequest struct {
	Username                       string `json:"Username"`
	IsOtherIdpSupported            bool   `json:"isOtherIdpSupported"`
	CheckPhones                    bool   `json:"checkPhones"`
	IsRemoteNGCSupported           bool   `json:"isRemoteNGCSupported"`
	IsCookieBannerShown            bool   `json:"isCookieBannerShown"`
	IsFidoSupported                bool   `json:"isFidoSupported"`
	OriginalRequest                string `json:"originalRequest"`
	Country                        string `json:"country"`
	ForceOtcLogin                  bool   `json:"forceotclogin"`
	IsExternalFederationDisallowed bool   `json:"isExternalFederationDisallowed"`
	IsRemoteConnectSupported       bool   `json:"isRemoteConnectSupported"`
	FederationFlags                int    `json:"federationFlags"`
	IsSignup                       bool   `json:"isSignup"`
	FlowToken                      string `json:"flowToken"`
	IsAccessPassSupported          bool   `json:"isAccessPassSupported"`
}

// credTypeResponse captures the fields we care about from the API response.
type credTypeResponse struct {
	IfExistsResult int `json:"IfExistsResult"`
	ThrottleStatus int `json:"ThrottleStatus"`
	Credentials    struct {
		PrefCredential int `json:"PrefCredential"`
		HasPassword    bool `json:"HasPassword"`
		FederationRedirectURL string `json:"FederationRedirectUrl"`
	} `json:"Credentials"`
	EstsProperties struct {
		UserTenantBranding interface{} `json:"UserTenantBranding"`
		DomainType         int         `json:"DomainType"`
		DesktopSsoEnabled  bool        `json:"DesktopSsoEnabled"`
	} `json:"EstsProperties"`
}

// UserEnum enumerates a list of usernames against Microsoft's GetCredentialType
// API without authentication. Delay is seconds between requests. Use 0 for no delay
// (not recommended for large lists).
func UserEnum(ctx context.Context, usernames []string, delaySec int) (*UserEnumResult, error) {
	if len(usernames) == 0 {
		return nil, fmt.Errorf("no usernames provided")
	}

	result := &UserEnumResult{Total: len(usernames)}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	delay := time.Duration(delaySec) * time.Second
	throttleBackoff := 5 * time.Second

	output.Header("User Enumeration (GetCredentialType)")
	output.Info("Enumerating %d username(s), delay=%ds", len(usernames), delaySec)

	for i, username := range usernames {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			output.Warn("Cancelled after %d/%d usernames", i, len(usernames))
			return result, ctx.Err()
		default:
		}

		entry, throttled, err := checkCredentialType(ctx, httpClient, username)
		if err != nil {
			output.Error("Error checking %s: %v", username, err)
			result.Unknown = append(result.Unknown, EnumEntry{Username: username})
			continue
		}

		if throttled {
			output.Warn("Throttled on %s — backing off %v", username, throttleBackoff)
			result.Throttled = append(result.Throttled, username)
			if err := sleepCtx(ctx, throttleBackoff); err != nil {
				return result, err
			}
			// Retry once after backoff.
			entry, throttled, err = checkCredentialType(ctx, httpClient, username)
			if err != nil || throttled {
				output.Error("Still throttled/error on %s after backoff, skipping", username)
				continue
			}
		}

		switch entry.IfExistsResult {
		case 0, 5, 6:
			// User exists.
			result.Valid = append(result.Valid, *entry)
			output.Success("VALID: %s (exists=%d, domainType=%d, prefCred=%d)",
				username, entry.IfExistsResult, entry.DomainType, entry.PrefCredential)
			if entry.DesktopSSO {
				output.Verbose("  Desktop SSO enabled")
			}
			if entry.FederationURL != "" {
				output.Verbose("  Federation URL: %s", entry.FederationURL)
			}
		case 1:
			// User does not exist.
			result.Invalid = append(result.Invalid, username)
			output.Verbose("INVALID: %s", username)
		default:
			// Unexpected code — log it.
			result.Unknown = append(result.Unknown, *entry)
			output.Warn("UNKNOWN: %s (IfExistsResult=%d)", username, entry.IfExistsResult)
		}

		// Inter-request delay (skip after last item).
		if delay > 0 && i < len(usernames)-1 {
			if err := sleepCtx(ctx, delay); err != nil {
				return result, err
			}
		}
	}

	printUserEnumResults(result)
	return result, nil
}

func printUserEnumResults(result *UserEnumResult) {
	valid := len(result.Valid)
	invalid := len(result.Invalid)
	unknown := len(result.Unknown)
	throttled := len(result.Throttled)

	output.SearchResultHeader("User Enumeration",
		result.Total,
		fmt.Sprintf("%d valid / %d invalid / %d unknown", valid, invalid, unknown))

	if result.Total == 0 {
		output.Warn("No usernames checked")
		return
	}

	// Overview
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Total Checked")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.Total)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Valid")),
		output.StyleSuccess.Render(fmt.Sprintf("%d", valid)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Invalid")),
		output.StyleDim.Render(fmt.Sprintf("%d", invalid)))
	if unknown > 0 {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Unknown")),
			output.StyleMedium.Render(fmt.Sprintf("%d", unknown)))
	}
	if throttled > 0 {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Throttled")),
			output.StyleHigh.Render(fmt.Sprintf("%d", throttled)))
	}
	fmt.Println()

	// Success rate bar
	pct := 0
	if result.Total > 0 {
		pct = (valid * 100) / result.Total
	}
	bar := strings.Repeat("█", pct/5) + strings.Repeat("░", 20-pct/5)
	fmt.Printf("       Success Rate: %s %s\n\n",
		output.StyleProgress.Render(bar),
		output.StyleCounter.Render(fmt.Sprintf("%d%%", pct)))

	// Valid users section
	if valid > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Valid Users (%d) ", valid)))

		federatedCount := 0
		for i, entry := range result.Valid {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			tag := output.StyleSuccess.Render("[VALID]")

			// Domain type tag
			domainTag := ""
			switch entry.DomainType {
			case 1:
				domainTag = output.StyleInfo.Render("[Managed]")
			case 2:
				domainTag = output.StyleHighlight.Render("[Federated]")
				federatedCount++
			case 3:
				domainTag = output.StyleURLInfo.Render("[Cloud]")
			}

			// Credential tags
			credTags := ""
			switch entry.PrefCredential {
			case 1:
				credTags += " " + output.StyleDim.Render("[Password]")
			case 4:
				credTags += " " + output.StyleMedium.Render("[FIDO]")
			case 6:
				credTags += " " + output.StyleMedium.Render("[Phone]")
			}

			// SSO tag
			ssoTag := ""
			if entry.DesktopSSO {
				ssoTag = " " + output.StyleHighlight.Render("[SSO]")
			}

			// Line 1: number + VALID tag + username + domain type + creds + SSO
			fmt.Printf("  %s %s  %s  %s%s%s\n",
				num, tag,
				output.StyleUserInfo.Render(entry.Username),
				domainTag, credTags, ssoTag)

			// Line 2: federation URL if present
			if entry.FederationURL != "" {
				fmt.Printf("       %s\n", output.StyleDim.Render("Federation: "+entry.FederationURL))
			}
		}
		fmt.Println()

		// Store federated count for summary
		_ = federatedCount
	}

	// Throttled section
	if throttled > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Throttled (%d) ", throttled)))
		output.Warn("The following usernames were throttled by Microsoft:")
		for _, u := range result.Throttled {
			fmt.Printf("       %s  %s\n",
				output.StyleMedium.Render("[THROTTLED]"),
				output.StyleDim.Render(u))
		}
		fmt.Println()
	}

	// Summary and attack surface assessment
	output.SearchDivider()
	if valid > 0 {
		output.Critical("%d users confirmed to exist — potential password spray targets", valid)

		// Check for federated users
		fedCount := 0
		for _, e := range result.Valid {
			if e.DomainType == 2 {
				fedCount++
			}
		}
		if fedCount > 0 {
			output.Warn("%d federated users found — authentication may route to external IdP", fedCount)
		}

		ssoCount := 0
		for _, e := range result.Valid {
			if e.DesktopSSO {
				ssoCount++
			}
		}
		if ssoCount > 0 {
			output.Info("%d users have Desktop SSO enabled", ssoCount)
		}
	} else {
		output.Success("No valid users found in the provided list")
	}

	fmt.Println()
	output.Success("Enumeration: %d total | %d valid | %d invalid | %d throttled",
		result.Total, valid, invalid, throttled)
}

// checkCredentialType makes a single GetCredentialType request for one username.
// Returns the parsed entry, whether we were throttled, and any error.
func checkCredentialType(ctx context.Context, client *http.Client, username string) (*EnumEntry, bool, error) {
	body := credTypeRequest{
		Username:            username,
		IsOtherIdpSupported: true,
		CheckPhones:         false,
		IsRemoteNGCSupported: true,
		IsCookieBannerShown: false,
		IsFidoSupported:     true,
		OriginalRequest:     "",
		Country:             "US",
		ForceOtcLogin:       false,
		IsExternalFederationDisallowed: false,
		IsRemoteConnectSupported:       false,
		FederationFlags:                0,
		IsSignup:                       false,
		FlowToken:                      "",
		IsAccessPassSupported:          true,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, false, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, getCredentialTypeURL, bytes.NewReader(payload))
	if err != nil {
		return nil, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var ctr credTypeResponse
	if err := json.Unmarshal(respBody, &ctr); err != nil {
		return nil, false, fmt.Errorf("unmarshal response: %w", err)
	}

	// Check throttle first.
	if ctr.ThrottleStatus == 1 {
		return nil, true, nil
	}

	entry := &EnumEntry{
		Username:       username,
		IfExistsResult: ctr.IfExistsResult,
		DomainType:     ctr.EstsProperties.DomainType,
		PrefCredential: ctr.Credentials.PrefCredential,
		HasPassword:    ctr.Credentials.HasPassword,
		DesktopSSO:     ctr.EstsProperties.DesktopSsoEnabled,
		TenantBranding: ctr.EstsProperties.UserTenantBranding != nil,
		FederationURL:  ctr.Credentials.FederationRedirectURL,
	}

	return entry, false, nil
}

// sleepCtx sleeps for the given duration but respects context cancellation.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
