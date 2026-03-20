package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AppProxyApp represents an application configured with Azure AD Application Proxy.
type AppProxyApp struct {
	ID                    string `json:"id"`
	AppID                 string `json:"appId"`
	DisplayName           string `json:"displayName"`
	ExternalURL           string `json:"externalUrl"`
	InternalURL           string `json:"internalUrl"`
	ExternalAuthType      string `json:"externalAuthenticationType"`
	IsTranslateHostHeader bool   `json:"isTranslateHostHeaderEnabled"`
	IsTranslateLinks      bool   `json:"isTranslateLinksInBodyEnabled"`
	IsOnPremPublishing    bool   `json:"isOnPremPublishingEnabled"`
	IsBackendCertValid    bool   `json:"isBackendCertificateValidationEnabled"`
	ConnectorGroupName    string `json:"connectorGroupName,omitempty"`
}

// AppProxyResult holds all Application Proxy configurations.
type AppProxyResult struct {
	Apps  []AppProxyApp `json:"apps"`
	Total int           `json:"total"`
}

// AppProxy enumerates Azure AD Application Proxy configured applications.
// These expose internal/on-prem applications externally — high-value targets.
// Requires Directory.Read.All or Application.Read.All.
// Uses beta endpoint for onPremisesPublishing data.
func AppProxy(ctx context.Context, c *graph.Client) (*AppProxyResult, error) {
	output.Info("Fetching Application Proxy configurations...")

	c.UseBeta()
	defer c.UseV1()

	// Fetch all apps without $select — beta returns onPremisesPublishing in full objects
	raw, err := c.GetAll(ctx, "/applications", nil)
	if err != nil {
		return nil, err
	}

	result := &AppProxyResult{}

	output.Info("Scanning %d applications for App Proxy...", len(raw))

	for _, r := range raw {
		var app struct {
			ID          string `json:"id"`
			AppID       string `json:"appId"`
			DisplayName string `json:"displayName"`
			OnPrem      *struct {
				ExternalURL           string `json:"externalUrl"`
				InternalURL           string `json:"internalUrl"`
				ExternalAuthType      string `json:"externalAuthenticationType"`
				IsTranslateHostHeader bool   `json:"isTranslateHostHeaderEnabled"`
				IsTranslateLinks      bool   `json:"isTranslateLinksInBodyEnabled"`
				IsOnPremPublishing    bool   `json:"isOnPremPublishingEnabled"`
				IsBackendCertValid    bool   `json:"isBackendCertificateValidationEnabled"`
			} `json:"onPremisesPublishing"`
		}
		if err := json.Unmarshal(r, &app); err != nil {
			continue
		}

		// Only include apps with App Proxy configured
		if app.OnPrem == nil || app.OnPrem.ExternalURL == "" {
			continue
		}

		proxyApp := AppProxyApp{
			ID:                    app.ID,
			AppID:                 app.AppID,
			DisplayName:           app.DisplayName,
			ExternalURL:           app.OnPrem.ExternalURL,
			InternalURL:           app.OnPrem.InternalURL,
			ExternalAuthType:      app.OnPrem.ExternalAuthType,
			IsTranslateHostHeader: app.OnPrem.IsTranslateHostHeader,
			IsTranslateLinks:      app.OnPrem.IsTranslateLinks,
			IsOnPremPublishing:    app.OnPrem.IsOnPremPublishing,
			IsBackendCertValid:    app.OnPrem.IsBackendCertValid,
		}

		result.Apps = append(result.Apps, proxyApp)
	}

	result.Total = len(result.Apps)

	// Pretty output
	printAppProxyResults(result)

	return result, nil
}

func printAppProxyResults(result *AppProxyResult) {
	if result.Total == 0 {
		output.Success("No Application Proxy apps found in this tenant")
		return
	}

	output.SearchResultHeader(
		"Application Proxy Discovery",
		result.Total,
		"internal apps exposed externally",
	)

	for i, app := range result.Apps {
		// Auth type styling
		authTag := output.StyleSuccess.Render("[" + app.ExternalAuthType + "]")
		if strings.Contains(strings.ToLower(app.ExternalAuthType), "passthru") || app.ExternalAuthType == "passthrough" {
			authTag = output.StyleCritical.Render("[PASSTHROUGH]")
		}

		// Backend cert validation
		certStatus := output.StyleSuccess.Render("valid")
		if !app.IsBackendCertValid {
			certStatus = output.StyleMedium.Render("DISABLED")
		}

		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(app.DisplayName)

		// Line 1: number + name + auth type
		fmt.Printf("  %s %s  %s\n", num, nameStyled, authTag)

		// Line 2: external → internal URL mapping
		fmt.Printf("       %s %s\n",
			output.StyleHighlight.Render("External:"),
			output.StyleURLInfo.Render(app.ExternalURL))
		fmt.Printf("       %s %s\n",
			output.StyleHighlight.Render("Internal:"),
			output.StyleCritical.Render(app.InternalURL))

		// Line 3: IDs
		fmt.Printf("       %s %s  %s %s\n",
			output.StyleDim.Render("AppID:"), output.StyleDim.Render(app.AppID),
			output.StyleDim.Render("ObjectID:"), output.StyleDim.Render(app.ID))

		// Line 4: config flags
		flags := []string{}
		if app.IsOnPremPublishing {
			flags = append(flags, "OnPremPublishing")
		}
		if app.IsTranslateHostHeader {
			flags = append(flags, "TranslateHostHeader")
		}
		if app.IsTranslateLinks {
			flags = append(flags, "TranslateLinks")
		}
		fmt.Printf("       %s %s  %s %s\n",
			output.StyleDim.Render("BackendCert:"), certStatus,
			output.StyleDim.Render("Flags:"), output.StyleDim.Render(strings.Join(flags, ", ")))

		fmt.Println()
	}

	output.SearchDivider()
	output.Success("Found %d Application Proxy apps (internal apps exposed externally)", result.Total)

	// Highlight security concerns
	passthrough := 0
	noCertValidation := 0
	for _, app := range result.Apps {
		if strings.Contains(strings.ToLower(app.ExternalAuthType), "passthru") || app.ExternalAuthType == "passthrough" {
			passthrough++
		}
		if !app.IsBackendCertValid {
			noCertValidation++
		}
	}
	if passthrough > 0 {
		output.Warn("%d apps use passthrough auth (no AAD pre-authentication!)", passthrough)
	}
	if noCertValidation > 0 {
		output.Warn("%d apps have backend certificate validation DISABLED", noCertValidation)
	}
}
