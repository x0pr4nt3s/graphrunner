package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SPCredential represents a password or certificate credential on a service principal or app.
type SPCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"` // "password" or "certificate"
	StartDate   string `json:"startDateTime"`
	EndDate     string `json:"endDateTime"`
	IsExpired   bool   `json:"is_expired"`
	DaysLeft    int    `json:"days_left"`
}

// SPWithSecrets represents a service principal or app with its credentials.
type SPWithSecrets struct {
	ID            string         `json:"id"`
	AppID         string         `json:"appId"`
	DisplayName   string         `json:"displayName"`
	SPObjectID    string         `json:"spObjectId,omitempty"`
	Credentials   []SPCredential `json:"credentials"`
	CredCount     int            `json:"credential_count"`
	ExpiredCount  int            `json:"expired_count"`
	HasSecrets    bool           `json:"has_secrets"`
	HasCerts      bool           `json:"has_certs"`
}

// SPSecretsResult holds the enumeration of all app/SP credentials.
type SPSecretsResult struct {
	Apps              []SPWithSecrets `json:"apps"`
	TotalApps         int             `json:"total_apps"`
	AppsWithCreds     int             `json:"apps_with_credentials"`
	TotalCredentials  int             `json:"total_credentials"`
	ExpiredCredentials int            `json:"expired_credentials"`
	ExpiringWithin30  int             `json:"expiring_within_30_days"`
}

// ServicePrincipalSecrets enumerates all app registrations and their password/certificate credentials.
// Highlights expired and soon-to-expire credentials — useful for identifying weak/stale secrets.
func ServicePrincipalSecrets(ctx context.Context, c *graph.Client) (*SPSecretsResult, error) {
	output.Info("Fetching application registrations with credentials...")

	params := map[string]string{
		"$select": "id,appId,displayName,passwordCredentials,keyCredentials",
	}
	raw, err := c.GetAll(ctx, "/applications", params)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	result := &SPSecretsResult{}

	for _, r := range raw {
		var app struct {
			ID          string `json:"id"`
			AppID       string `json:"appId"`
			DisplayName string `json:"displayName"`
			PasswordCreds []struct {
				KeyID       string `json:"keyId"`
				DisplayName string `json:"displayName"`
				StartDate   string `json:"startDateTime"`
				EndDate     string `json:"endDateTime"`
			} `json:"passwordCredentials"`
			KeyCreds []struct {
				KeyID       string `json:"keyId"`
				DisplayName string `json:"displayName"`
				StartDate   string `json:"startDateTime"`
				EndDate     string `json:"endDateTime"`
				Type        string `json:"type"`
			} `json:"keyCredentials"`
		}
		if err := json.Unmarshal(r, &app); err != nil {
			continue
		}

		spEntry := SPWithSecrets{
			ID:          app.ID,
			AppID:       app.AppID,
			DisplayName: app.DisplayName,
		}

		for _, pc := range app.PasswordCreds {
			cred := SPCredential{
				KeyID:       pc.KeyID,
				DisplayName: pc.DisplayName,
				Type:        "password",
				StartDate:   pc.StartDate,
				EndDate:     pc.EndDate,
			}
			fillExpiry(&cred, now)
			spEntry.Credentials = append(spEntry.Credentials, cred)
			spEntry.HasSecrets = true
			result.TotalCredentials++
			if cred.IsExpired {
				spEntry.ExpiredCount++
				result.ExpiredCredentials++
			} else if cred.DaysLeft <= 30 {
				result.ExpiringWithin30++
			}
		}

		for _, kc := range app.KeyCreds {
			cred := SPCredential{
				KeyID:       kc.KeyID,
				DisplayName: kc.DisplayName,
				Type:        "certificate",
				StartDate:   kc.StartDate,
				EndDate:     kc.EndDate,
			}
			fillExpiry(&cred, now)
			spEntry.Credentials = append(spEntry.Credentials, cred)
			spEntry.HasCerts = true
			result.TotalCredentials++
			if cred.IsExpired {
				spEntry.ExpiredCount++
				result.ExpiredCredentials++
			} else if cred.DaysLeft <= 30 {
				result.ExpiringWithin30++
			}
		}

		spEntry.CredCount = len(spEntry.Credentials)
		if spEntry.CredCount > 0 {
			result.AppsWithCreds++
			output.Verbose("[sp-secrets] %s (appId: %s) — %d creds (%d expired)",
				spEntry.DisplayName, spEntry.AppID, spEntry.CredCount, spEntry.ExpiredCount)
		}

		result.Apps = append(result.Apps, spEntry)
	}

	result.TotalApps = len(result.Apps)
	printSPSecretsResults(result)
	return result, nil
}

func printSPSecretsResults(result *SPSecretsResult) {
	// Count credential types
	passwordCount := 0
	certCount := 0
	for _, app := range result.Apps {
		for _, c := range app.Credentials {
			if c.Type == "password" {
				passwordCount++
			} else {
				certCount++
			}
		}
	}

	output.SearchResultHeader("Application Credentials",
		result.AppsWithCreds,
		fmt.Sprintf("%d total creds / %d expired / %d expiring <30d",
			result.TotalCredentials, result.ExpiredCredentials, result.ExpiringWithin30))

	if result.TotalCredentials == 0 {
		output.Warn("No application credentials found")
		return
	}

	// Overview section
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-30s", "Total Applications")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalApps)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-30s", "Apps with Credentials")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.AppsWithCreds)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-30s", "Total Credentials")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalCredentials)))

	if result.ExpiredCredentials > 0 {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-30s", "Expired")),
			output.StyleCritical.Render(fmt.Sprintf("%d", result.ExpiredCredentials)))
	} else {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-30s", "Expired")),
			output.StyleSuccess.Render("0"))
	}

	if result.ExpiringWithin30 > 0 {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-30s", "Expiring <30 days")),
			output.StyleMedium.Render(fmt.Sprintf("%d", result.ExpiringWithin30)))
	} else {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-30s", "Expiring <30 days")),
			output.StyleSuccess.Render("0"))
	}
	fmt.Println()

	// Credential type breakdown
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Credential Types "))
	if passwordCount > 0 {
		pct := (passwordCount * 100) / result.TotalCredentials
		bar := ""
		if pct > 0 {
			bar = strings.Repeat("█", pct/5)
		}
		fmt.Printf("       %s %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Secrets (password)")),
			output.StyleCounter.Render(fmt.Sprintf("%4d", passwordCount)),
			output.StyleProgress.Render(bar))
	}
	if certCount > 0 {
		pct := (certCount * 100) / result.TotalCredentials
		bar := ""
		if pct > 0 {
			bar = strings.Repeat("█", pct/5)
		}
		fmt.Printf("       %s %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Certificates")),
			output.StyleCounter.Render(fmt.Sprintf("%4d", certCount)),
			output.StyleURLInfo.Render(bar))
	}
	fmt.Println()

	// App list (only apps WITH credentials)
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Applications with Credentials (%d) ", result.AppsWithCreds)))

	idx := 0
	for _, app := range result.Apps {
		if app.CredCount == 0 {
			continue
		}
		idx++

		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", idx))
		nameStyled := output.StyleBold.Render(app.DisplayName)
		appIDStyled := output.StyleDim.Render("AppId: " + app.AppID)

		// Build tags
		tags := ""
		if app.ExpiredCount > 0 {
			tags += " " + output.StyleCritical.Render(fmt.Sprintf("[EXPIRED:%d]", app.ExpiredCount))
		}
		// Check for expiring credentials
		expiringCount := 0
		for _, c := range app.Credentials {
			if !c.IsExpired && c.DaysLeft > 0 && c.DaysLeft <= 30 {
				expiringCount++
			}
		}
		if expiringCount > 0 {
			tags += " " + output.StyleMedium.Render("[EXPIRING]")
		}
		if app.HasSecrets {
			tags += " " + output.StyleHighlight.Render("[SECRET]")
		}
		if app.HasCerts {
			tags += " " + output.StyleURLInfo.Render("[CERT]")
		}

		// Line 1: number + name + tags
		fmt.Printf("  %s %s %s\n", num, nameStyled, tags)
		// Line 2: appId + cred count
		fmt.Printf("       %s  %s\n", appIDStyled,
			output.StyleDim.Render(fmt.Sprintf("%d credential(s)", app.CredCount)))

		// Verbose: show each credential
		if output.VerboseEnabled {
			for _, c := range app.Credentials {
				typeTag := output.StyleHighlight.Render("[SECRET]")
				if c.Type == "certificate" {
					typeTag = output.StyleURLInfo.Render("[CERT]")
				}

				statusTag := ""
				if c.IsExpired {
					statusTag = output.StyleCritical.Render("[EXPIRED]")
				} else if c.DaysLeft > 0 && c.DaysLeft <= 30 {
					statusTag = output.StyleMedium.Render(fmt.Sprintf("[%dd left]", c.DaysLeft))
				} else if c.DaysLeft > 0 {
					statusTag = output.StyleSuccess.Render(fmt.Sprintf("[%dd left]", c.DaysLeft))
				}

				keyDisplay := c.KeyID
				if len(keyDisplay) > 8 {
					keyDisplay = keyDisplay[:8] + "..."
				}
				displayName := c.DisplayName
				if displayName == "" {
					displayName = "(unnamed)"
				}

				startDate := c.StartDate
				if len(startDate) > 10 {
					startDate = startDate[:10]
				}
				endDate := c.EndDate
				if len(endDate) > 10 {
					endDate = endDate[:10]
				}

				fmt.Printf("         %s %s %s  %s  %s → %s %s\n",
					output.StyleDim.Render("Key:"+keyDisplay),
					typeTag,
					output.StyleDim.Render(displayName),
					output.StyleDim.Render("Start:"+startDate),
					output.StyleDim.Render("End:"+endDate),
					"",
					statusTag)
			}
		}
		fmt.Println()
	}

	if !output.VerboseEnabled {
		output.Dim("Use -v to see individual credential details (key ID, dates, expiry)")
	}

	// Summary warnings
	output.SearchDivider()
	if result.ExpiredCredentials > 0 {
		output.Critical("%d credential(s) are EXPIRED — rotate or remove immediately", result.ExpiredCredentials)
	}
	if result.ExpiringWithin30 > 0 {
		output.Warn("%d credential(s) expiring within 30 days — schedule rotation", result.ExpiringWithin30)
	}

	fmt.Println()
	output.Success("SP secrets: %d apps, %d with credentials, %d total creds (%d expired, %d expiring <30d)",
		result.TotalApps, result.AppsWithCreds, result.TotalCredentials,
		result.ExpiredCredentials, result.ExpiringWithin30)
}

func fillExpiry(cred *SPCredential, now time.Time) {
	if cred.EndDate != "" {
		if end, err := time.Parse(time.RFC3339, cred.EndDate); err == nil {
			cred.DaysLeft = int(time.Until(end).Hours() / 24)
			cred.IsExpired = now.After(end)
		}
	}
}
