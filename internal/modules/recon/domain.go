package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// DomainInfoResult holds all unauthenticated domain intelligence.
type DomainInfoResult struct {
	Domain          string           `json:"domain"`
	TenantID        string           `json:"tenant_id,omitempty"`
	TenantName      string           `json:"tenant_name,omitempty"`
	OpenIDConfig    *OpenIDConfig    `json:"openid_config,omitempty"`
	UserRealm       *UserRealmInfo   `json:"user_realm,omitempty"`
	TenantBrand     *TenantBranding  `json:"tenant_branding,omitempty"`
	AutodiscoverURL string           `json:"autodiscover_url,omitempty"`
	MXRecords       []string         `json:"mx_records,omitempty"`
}

// OpenIDConfig holds selected fields from the OpenID configuration endpoint.
type OpenIDConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	Issuer                string `json:"issuer,omitempty"`
	TenantRegionScope     string `json:"tenant_region_scope,omitempty"`
	CloudInstanceName     string `json:"cloud_instance_name,omitempty"`
}

// UserRealmInfo holds fields from the getuserrealm.srf response.
type UserRealmInfo struct {
	NameSpaceType       string `json:"NameSpaceType,omitempty"`
	DomainName          string `json:"DomainName,omitempty"`
	FederationBrandName string `json:"FederationBrandName,omitempty"`
	CloudInstanceName   string `json:"CloudInstanceName,omitempty"`
	AuthURL             string `json:"AuthURL,omitempty"`
	FederationMetadataURL string `json:"FederationMetadataUrl,omitempty"`
	FederationActiveAuthURL string `json:"FederationActiveAuthUrl,omitempty"`
	IsViral             bool   `json:"is_viral,omitempty"`
}

// DomainEntry represents a single domain registered in the tenant.
type DomainEntry struct {
	ID                    string   `json:"id"`
	IsDefault             bool     `json:"isDefault"`
	IsInitial             bool     `json:"isInitial"`
	IsVerified            bool     `json:"isVerified"`
	IsRoot                bool     `json:"isRoot"`
	IsAdminManaged        bool     `json:"isAdminManaged"`
	AuthenticationType    string   `json:"authenticationType"`
	SupportedServices     []string `json:"supportedServices"`
	PasswordValidityPeriod *int    `json:"passwordValidityPeriodInDays,omitempty"`
	PasswordNotification  *int     `json:"passwordNotificationWindowInDays,omitempty"`
}

// DomainListResult holds all domains for the authenticated tenant.
type DomainListResult struct {
	Domains        []DomainEntry `json:"domains"`
	Total          int           `json:"total"`
	DefaultDomain  string        `json:"default_domain"`
	InitialDomain  string        `json:"initial_domain"`
	Verified       int           `json:"verified"`
	Federated      int           `json:"federated"`
}

// DomainList fetches all registered domains from the authenticated tenant.
// Requires Domain.Read.All or Directory.Read.All.
func DomainList(ctx context.Context, c *graph.Client) (*DomainListResult, error) {
	output.Info("Fetching tenant domains...")

	raw, err := c.GetAll(ctx, graph.EndpointDomains, nil)
	if err != nil {
		return nil, fmt.Errorf("get domains: %w", err)
	}

	result := &DomainListResult{}

	for _, r := range raw {
		var d DomainEntry
		if err := json.Unmarshal(r, &d); err != nil {
			continue
		}
		result.Domains = append(result.Domains, d)
		if d.IsDefault {
			result.DefaultDomain = d.ID
		}
		if d.IsInitial {
			result.InitialDomain = d.ID
		}
		if d.IsVerified {
			result.Verified++
		}
		if d.AuthenticationType == "Federated" {
			result.Federated++
		}
	}
	result.Total = len(result.Domains)

	// Count users per domain from UPN suffix
	output.Info("Counting users per domain...")
	domainUserCounts := countUsersPerDomain(ctx, c)
	totalUsers := 0
	for _, count := range domainUserCounts {
		totalUsers += count
	}
	output.Success("Total users: %d across %d domains", totalUsers, len(domainUserCounts))

	httpClient := &http.Client{Timeout: 10 * time.Second}
	printDomainListResults(result, domainUserCounts, totalUsers, ctx, httpClient)

	return result, nil
}

// countUsersPerDomain fetches all UPNs and counts by domain suffix.
func countUsersPerDomain(ctx context.Context, c *graph.Client) map[string]int {
	counts := map[string]int{}
	raw, err := c.GetAll(ctx, graph.EndpointUsers, map[string]string{
		"$select": "userPrincipalName",
		"$top":    "999",
	})
	if err != nil {
		output.Warn("Could not fetch users for domain counts: %v", err)
		return counts
	}
	for _, r := range raw {
		var u struct {
			UPN string `json:"userPrincipalName"`
		}
		if json.Unmarshal(r, &u) == nil && u.UPN != "" {
			parts := strings.SplitN(u.UPN, "@", 2)
			if len(parts) == 2 {
				domain := strings.ToLower(parts[1])
				counts[domain]++
			}
		}
	}
	return counts
}

func printDomainListResults(result *DomainListResult, userCounts map[string]int, totalUsers int, ctx context.Context, httpClient *http.Client) {
	output.SearchResultHeader("Tenant Domains",
		result.Total,
		fmt.Sprintf("%d verified, %d federated, %d users", result.Verified, result.Federated, totalUsers))

	if result.Total == 0 {
		output.Warn("No domains found (missing Domain.Read.All?)")
		return
	}

	// Summary
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Domain Summary "))
	if result.DefaultDomain != "" {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Default Domain:")),
			output.StyleHighlight.Render(result.DefaultDomain))
	}
	if result.InitialDomain != "" {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Initial Domain:")),
			output.StyleDim.Render(result.InitialDomain))
	}
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Total Domains:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.Total)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Verified:")),
		output.StyleSuccess.Render(fmt.Sprintf("%d", result.Verified)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Total Users:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", totalUsers)))
	if result.Federated > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Federated:")),
			output.StyleHighlight.Render(fmt.Sprintf("%d", result.Federated)))
	}
	fmt.Println()

	// Service breakdown
	svcCounts := map[string]int{}
	for _, d := range result.Domains {
		for _, svc := range d.SupportedServices {
			svcCounts[svc]++
		}
	}
	if len(svcCounts) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Services Across Domains "))
		for svc, count := range svcCounts {
			svcStyled := svc
			switch svc {
			case "Email":
				svcStyled = output.StyleURLInfo.Render(svc)
			case "OfficeCommunicationsOnline":
				svcStyled = output.StyleUserInfo.Render("Teams/Skype")
			case "SharepointDefaultDomain":
				svcStyled = output.StyleHighlight.Render("SharePoint")
			case "Yammer", "Intune":
				svcStyled = output.StyleDim.Render(svc)
			}
			fmt.Printf("       %s  %s\n", svcStyled,
				output.StyleCounter.Render(fmt.Sprintf("%d domains", count)))
		}
		fmt.Println()
	}

	// Top domains by user count
	if len(userCounts) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Users by Domain (top 15) "))

		// Sort domains by count descending
		type domainCount struct {
			domain string
			count  int
		}
		sorted := []domainCount{}
		for d, c := range userCounts {
			sorted = append(sorted, domainCount{d, c})
		}
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j].count > sorted[i].count {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}

		maxCount := 0
		if len(sorted) > 0 {
			maxCount = sorted[0].count
		}
		limit := 15
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for i := 0; i < limit; i++ {
			dc := sorted[i]
			barLen := 0
			if maxCount > 0 {
				barLen = (dc.count * 30) / maxCount
			}
			if barLen < 1 && dc.count > 0 {
				barLen = 1
			}
			bar := strings.Repeat("█", barLen)
			pct := 0
			if totalUsers > 0 {
				pct = (dc.count * 100) / totalUsers
			}
			fmt.Printf("       %s %s %s  %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-35s", dc.domain)),
				output.StyleCounter.Render(fmt.Sprintf("%5d", dc.count)),
				output.StyleProgress.Render(bar),
				output.StyleDim.Render(fmt.Sprintf("%d%%", pct)))
		}
		if len(sorted) > limit {
			output.Dim("... and %d more domains with users", len(sorted)-limit)
		}
		fmt.Println()
	}

	// Per-domain detail
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" All Domains (%d) ", result.Total)))

	for i, d := range result.Domains {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(d.ID)

		// Tags
		tags := []string{}
		if d.IsDefault {
			tags = append(tags, output.StyleHighlight.Render("[DEFAULT]"))
		}
		if d.IsInitial {
			tags = append(tags, output.StyleDim.Render("[initial]"))
		}
		if !d.IsVerified {
			tags = append(tags, output.StyleCritical.Render("[UNVERIFIED]"))
		}
		if d.IsRoot {
			tags = append(tags, output.StyleDim.Render("[root]"))
		}
		if !d.IsAdminManaged {
			tags = append(tags, output.StyleMedium.Render("[self-service]"))
		}

		// Auth type
		authTag := output.StyleSuccess.Render("[Managed]")
		if d.AuthenticationType == "Federated" {
			authTag = output.StyleHighlight.Render("[Federated]")
		}

		// User count for this domain
		domainLower := strings.ToLower(d.ID)
		uCount := userCounts[domainLower]
		userTag := output.StyleDim.Render("0 users")
		if uCount > 0 {
			userTag = output.StyleCounter.Render(fmt.Sprintf("%d users", uCount))
		}

		// Line 1: number + domain + user count + tags
		fmt.Printf("  %s %s  %s  %s %s\n", num, nameStyled, userTag, authTag, strings.Join(tags, " "))

		// Line 2: services
		if len(d.SupportedServices) > 0 {
			fmt.Printf("       %s %s\n",
				output.StyleDim.Render("Services:"),
				output.StyleURLInfo.Render(strings.Join(d.SupportedServices, ", ")))
		} else {
			fmt.Printf("       %s\n", output.StyleDim.Render("No services"))
		}

		// Line 3: password policy (if set)
		if d.PasswordValidityPeriod != nil && *d.PasswordValidityPeriod > 0 {
			pwInfo := fmt.Sprintf("Password expires: %d days", *d.PasswordValidityPeriod)
			if d.PasswordNotification != nil {
				pwInfo += fmt.Sprintf(", notify: %d days before", *d.PasswordNotification)
			}
			fmt.Printf("       %s\n", output.StyleDim.Render(pwInfo))
		}

		// Quick unauth recon: UserRealm for federation details
		if d.AuthenticationType == "Federated" {
			realmURL := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=user@%s", d.ID)
			realmBody, err := httpGet(ctx, httpClient, realmURL)
			if err == nil {
				var raw map[string]interface{}
				if json.Unmarshal(realmBody, &raw) == nil {
					authURL, _ := raw["AuthURL"].(string)
					metaURL, _ := raw["FederationMetadataUrl"].(string)
					if authURL != "" {
						fmt.Printf("       %s %s\n",
							output.StyleBold.Render("Auth URL:"),
							output.StyleURLInfo.Render(authURL))
					}
					if metaURL != "" {
						fmt.Printf("       %s %s\n",
							output.StyleDim.Render("Metadata:"),
							output.StyleDim.Render(metaURL))
					}
				}
			}
		}

		fmt.Println()
	}

	// Warnings
	output.SearchDivider()

	unverified := 0
	for _, d := range result.Domains {
		if !d.IsVerified {
			unverified++
		}
	}
	if unverified > 0 {
		output.Warn("%d domains are UNVERIFIED", unverified)
	}
	if result.Federated > 0 {
		output.Warn("%d domains use Federated auth (on-prem IdP — Golden SAML risk)", result.Federated)
	}

	fmt.Println()
	output.Success("Enumerated %d domains (%d verified, %d federated)",
		result.Total, result.Verified, result.Federated)
	output.Dim("For deep recon on a specific domain: graphrunner recon domain-info -d <domain>")
}

// TenantBranding holds organization branding info from the unauth endpoint.
type TenantBranding struct {
	TenantID        string `json:"tenantId,omitempty"`
	DisplayName     string `json:"displayName,omitempty"`
	BannerLogoURL   string `json:"bannerLogoUrl,omitempty"`
	BgImageURL      string `json:"backgroundImageUrl,omitempty"`
	BoilerPlateText string `json:"boilerPlateText,omitempty"`
}

// DomainInfo performs unauthenticated domain reconnaissance by querying
// Microsoft's OpenID configuration, UserRealm, and tenant branding endpoints.
func DomainInfo(ctx context.Context, domain string) (*DomainInfoResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	result := &DomainInfoResult{Domain: domain}
	httpClient := &http.Client{Timeout: 15 * time.Second}

	output.Info("Target domain: %s", domain)

	// --- Step 1: OpenID Configuration ---
	output.Info("Fetching OpenID configuration...")
	oidcURL := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain)

	oidcBody, err := httpGet(ctx, httpClient, oidcURL)
	if err != nil {
		output.Warn("OpenID config fetch failed: %v", err)
	} else {
		var raw map[string]interface{}
		if err := json.Unmarshal(oidcBody, &raw); err != nil {
			output.Warn("OpenID config parse failed: %v", err)
		} else {
			oidc := &OpenIDConfig{}
			oidc.AuthorizationEndpoint, _ = raw["authorization_endpoint"].(string)
			oidc.TokenEndpoint, _ = raw["token_endpoint"].(string)
			oidc.Issuer, _ = raw["issuer"].(string)
			oidc.TenantRegionScope, _ = raw["tenant_region_scope"].(string)
			oidc.CloudInstanceName, _ = raw["cloud_instance_name"].(string)
			result.OpenIDConfig = oidc

			result.TenantID = extractTenantID(oidc.Issuer)
			if result.TenantID == "" {
				result.TenantID = extractTenantID(oidc.TokenEndpoint)
			}
		}
	}

	// --- Step 2: UserRealm (federation detection) ---
	output.Info("Fetching UserRealm (federation detection)...")
	realmURL := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=user@%s", domain)

	realmBody, err := httpGet(ctx, httpClient, realmURL)
	if err != nil {
		output.Warn("UserRealm fetch failed: %v", err)
	} else {
		var raw map[string]interface{}
		if err := json.Unmarshal(realmBody, &raw); err != nil {
			output.Warn("UserRealm parse failed: %v", err)
		} else {
			realm := &UserRealmInfo{}
			realm.NameSpaceType, _ = raw["NameSpaceType"].(string)
			realm.DomainName, _ = raw["DomainName"].(string)
			realm.FederationBrandName, _ = raw["FederationBrandName"].(string)
			realm.CloudInstanceName, _ = raw["CloudInstanceName"].(string)
			realm.AuthURL, _ = raw["AuthURL"].(string)
			realm.FederationMetadataURL, _ = raw["FederationMetadataUrl"].(string)
			realm.FederationActiveAuthURL, _ = raw["FederationActiveAuthUrl"].(string)
			if v, ok := raw["IsViral"].(bool); ok {
				realm.IsViral = v
			}
			result.UserRealm = realm
		}
	}

	// --- Step 3: Tenant branding (org name, logo) ---
	output.Info("Fetching tenant branding...")
	if result.TenantID != "" {
		brandURL := fmt.Sprintf("https://login.microsoftonline.com/%s/reprocess?ctx=rQIIAeNisOAyYDJiSjHkSGI0YjRhTDY0SjFNM0lMMTBMSjE0STQ0TDSwSDFPN7_EctCCa-b5i-sKizOKSvJhUiZyBWlpnEApEwMmAyYDANABFgIA&flowToken=AQABAAEAAAAmoFfGtYxvRrNriQdPKIZ-0dKZNzg1a_sP64Y6b6rYHy_ycLN1slIqQsxRKR9XPe4pTTXGCqadMO3lzH8xVp1T-RFH0lGaI3u8G9lTr4k8hLzSrXsQNaYqnAr0PBnV2HwEgGCAA", result.TenantID)
		brandBody, err := httpGet(ctx, httpClient, brandURL)
		if err == nil {
			var brandRaw map[string]interface{}
			if err := json.Unmarshal(brandBody, &brandRaw); err == nil {
				brand := &TenantBranding{}
				brand.DisplayName, _ = brandRaw["sFT"].(string) // not here
				result.TenantBrand = brand
			}
		}
	}

	// Try the common tenant brand endpoint
	if result.TenantID != "" {
		tenantInfoURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", result.TenantID)
		tenantBody, err := httpGet(ctx, httpClient, tenantInfoURL)
		if err == nil {
			var tenantRaw map[string]interface{}
			if err := json.Unmarshal(tenantBody, &tenantRaw); err == nil {
				// Try to get tenant name from issuer
				if issuer, ok := tenantRaw["issuer"].(string); ok {
					result.TenantName = extractTenantNameFromIssuer(issuer)
				}
			}
		}
	}

	// --- Step 4: Autodiscover check ---
	output.Info("Checking Autodiscover endpoint...")
	autodiscoverURL := fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain)
	autodiscoverReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, autodiscoverURL, nil)
	if autodiscoverReq != nil {
		autodiscoverReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		autodiscoverResp, err := httpClient.Do(autodiscoverReq)
		if err == nil {
			autodiscoverResp.Body.Close()
			if autodiscoverResp.StatusCode == 401 || autodiscoverResp.StatusCode == 403 || autodiscoverResp.StatusCode == 200 {
				result.AutodiscoverURL = autodiscoverURL
			}
		}
	}

	// --- Step 5: Check GetCredentialType (user enum possible?) ---
	output.Info("Checking GetCredentialType endpoint...")
	enumPossible := checkUserEnumEndpoint(ctx, httpClient, domain)

	// Pretty output
	printDomainInfoResults(result, enumPossible)

	return result, nil
}

func checkUserEnumEndpoint(ctx context.Context, httpClient *http.Client, domain string) bool {
	credURL := "https://login.microsoftonline.com/common/GetCredentialType"
	payload := fmt.Sprintf(`{"Username":"nonexistentuser12345@%s","isOtherIdpSupported":true,"checkPhones":false,"isRemoteNGCSupported":true,"isCookieBannerShown":false,"isFidoSupported":true,"forceotclogin":false,"otclogindisallowed":false,"isExternalFederationDisallowed":false,"isRemoteConnectSupported":false,"federationFlags":0}`, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credURL, strings.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	// If IfExistsResult is 0 or 1, user enum is possible
	if ifExists, ok := result["IfExistsResult"].(float64); ok {
		return ifExists == 0 || ifExists == 1 // 0=exists, 1=not exists, 5=blocked, 6=blocked
	}
	return false
}

func printDomainInfoResults(result *DomainInfoResult, enumPossible bool) {
	output.SearchResultHeader("Domain Intelligence (Unauthenticated)",
		1,
		result.Domain)

	// === IDENTITY ===
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Tenant Identity "))

	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-22s", "Domain:")),
		output.StyleHighlight.Render(result.Domain))

	if result.TenantID != "" {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-22s", "Tenant ID:")),
			output.StyleCounter.Render(result.TenantID))
	}

	if result.TenantName != "" {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-22s", "Tenant Name:")),
			output.StyleBold.Render(result.TenantName))
	}

	if result.OpenIDConfig != nil {
		if result.OpenIDConfig.CloudInstanceName != "" {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Cloud Instance:")),
				output.StyleURLInfo.Render(result.OpenIDConfig.CloudInstanceName))
		}
		if result.OpenIDConfig.TenantRegionScope != "" {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Region:")),
				output.StyleURLInfo.Render(result.OpenIDConfig.TenantRegionScope))
		}
	}
	fmt.Println()

	// === AUTH CONFIG ===
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Authentication Configuration "))

	if result.UserRealm != nil {
		realm := result.UserRealm

		// Namespace type with styling
		nsType := realm.NameSpaceType
		nsStyled := output.StyleDim.Render(nsType)
		switch nsType {
		case "Managed":
			nsStyled = output.StyleSuccess.Render("Managed (Cloud-only auth)")
		case "Federated":
			nsStyled = output.StyleHighlight.Render("Federated (On-prem IdP)")
		case "Unknown":
			nsStyled = output.StyleCritical.Render("Unknown (domain may not exist)")
		}

		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-22s", "Auth Type:")),
			nsStyled)

		if realm.FederationBrandName != "" {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Brand Name:")),
				output.StyleBold.Render(realm.FederationBrandName))
		}

		if realm.DomainName != "" && realm.DomainName != result.Domain {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Domain Name:")),
				output.StyleDim.Render(realm.DomainName))
		}

		if realm.CloudInstanceName != "" {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Cloud Instance:")),
				output.StyleDim.Render(realm.CloudInstanceName))
		}

		if realm.IsViral {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-22s", "Viral Signup:")),
				output.StyleMedium.Render("YES (self-service tenant)"))
		}
		fmt.Println()

		// Federation details
		if nsType == "Federated" {
			fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Federation Details "))

			if realm.AuthURL != "" {
				fmt.Printf("       %s\n       %s\n",
					output.StyleBold.Render("Auth URL:"),
					output.StyleURLInfo.Render(realm.AuthURL))
			}
			if realm.FederationMetadataURL != "" {
				fmt.Printf("       %s\n       %s\n",
					output.StyleBold.Render("Metadata URL:"),
					output.StyleURLInfo.Render(realm.FederationMetadataURL))
			}
			if realm.FederationActiveAuthURL != "" {
				fmt.Printf("       %s\n       %s\n",
					output.StyleBold.Render("Active Auth URL:"),
					output.StyleCritical.Render(realm.FederationActiveAuthURL))
			}
			fmt.Println()
		}
	}

	// === ENDPOINTS ===
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Endpoints & Services "))

	if result.OpenIDConfig != nil {
		if result.OpenIDConfig.AuthorizationEndpoint != "" {
			fmt.Printf("       %s\n       %s\n",
				output.StyleBold.Render("Authorization:"),
				output.StyleDim.Render(result.OpenIDConfig.AuthorizationEndpoint))
		}
		if result.OpenIDConfig.TokenEndpoint != "" {
			fmt.Printf("       %s\n       %s\n",
				output.StyleBold.Render("Token:"),
				output.StyleDim.Render(result.OpenIDConfig.TokenEndpoint))
		}
		if result.OpenIDConfig.Issuer != "" {
			fmt.Printf("       %s\n       %s\n",
				output.StyleBold.Render("Issuer:"),
				output.StyleDim.Render(result.OpenIDConfig.Issuer))
		}
	}

	if result.AutodiscoverURL != "" {
		fmt.Printf("       %s\n       %s  %s\n",
			output.StyleBold.Render("Autodiscover:"),
			output.StyleURLInfo.Render(result.AutodiscoverURL),
			output.StyleSuccess.Render("[ACTIVE]"))
	}
	fmt.Println()

	// === SECURITY ASSESSMENT ===
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Security Assessment "))

	// User enumeration
	if enumPossible {
		fmt.Printf("       %s %s\n",
			output.StyleCritical.Render("▸ User Enumeration:"),
			output.StyleCritical.Render("POSSIBLE via GetCredentialType"))
		fmt.Printf("         %s\n",
			output.StyleDim.Render("Attackers can verify if email addresses exist in this tenant"))
	} else {
		fmt.Printf("       %s %s\n",
			output.StyleSuccess.Render("▸ User Enumeration:"),
			output.StyleSuccess.Render("Blocked or inconclusive"))
	}

	// Federation risks
	if result.UserRealm != nil {
		if result.UserRealm.NameSpaceType == "Federated" {
			fmt.Printf("       %s %s\n",
				output.StyleHighlight.Render("▸ Federated Auth:"),
				output.StyleHighlight.Render("On-prem IdP in use — Golden SAML / federation abuse possible"))
			if result.UserRealm.FederationActiveAuthURL != "" {
				fmt.Printf("       %s %s\n",
					output.StyleCritical.Render("▸ Active Auth:"),
					output.StyleCritical.Render("WS-Trust endpoint exposed — password spray target"))
			}
		} else if result.UserRealm.NameSpaceType == "Managed" {
			fmt.Printf("       %s %s\n",
				output.StyleSuccess.Render("▸ Cloud Auth:"),
				output.StyleDim.Render("Managed domain — no federation to exploit"))
		}
	}

	// Autodiscover
	if result.AutodiscoverURL != "" {
		fmt.Printf("       %s %s\n",
			output.StyleHighlight.Render("▸ Autodiscover:"),
			output.StyleDim.Render("Exchange autodiscover active — NTLM relay / credential harvest vector"))
	}

	fmt.Println()

	// === ATTACK SURFACE SUMMARY ===
	output.SearchDivider()

	attackVectors := []string{}
	if enumPossible {
		attackVectors = append(attackVectors, "User enumeration (GetCredentialType)")
	}
	if result.UserRealm != nil && result.UserRealm.NameSpaceType == "Federated" {
		attackVectors = append(attackVectors, "Federation abuse (Golden SAML)")
		if result.UserRealm.FederationActiveAuthURL != "" {
			attackVectors = append(attackVectors, "Password spray via WS-Trust")
		}
	}
	if result.AutodiscoverURL != "" {
		attackVectors = append(attackVectors, "Autodiscover credential harvest")
	}

	if len(attackVectors) > 0 {
		output.Warn("Potential attack vectors identified:")
		for _, v := range attackVectors {
			fmt.Printf("    %s %s\n", output.StyleCritical.Render("•"), v)
		}
	} else {
		output.Success("No obvious unauthenticated attack vectors found")
	}

	fmt.Println()
	output.Success("Domain recon complete for %s", result.Domain)
}

func extractTenantNameFromIssuer(issuer string) string {
	// V2 issuer: https://login.microsoftonline.com/{tenantid}/v2.0
	// Not useful for name — try alternative approaches
	return ""
}

// httpGet is a small helper for unauthenticated GET requests.
func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// extractTenantID pulls a GUID-shaped tenant ID from a URL like
// https://login.microsoftonline.com/<tenant-id>/...
func extractTenantID(rawURL string) string {
	const prefix = "login.microsoftonline.com/"
	idx := strings.Index(rawURL, prefix)
	if idx == -1 {
		return ""
	}
	after := rawURL[idx+len(prefix):]
	// Tenant ID is the next path segment.
	if slash := strings.Index(after, "/"); slash > 0 {
		candidate := after[:slash]
		// Basic GUID check: 36 chars with hyphens at 8,13,18,23.
		if len(candidate) == 36 && candidate[8] == '-' && candidate[13] == '-' {
			return candidate
		}
	}
	return ""
}
