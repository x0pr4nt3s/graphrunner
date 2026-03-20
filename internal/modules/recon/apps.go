package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AppsResult holds app enumeration data.
type AppsResult struct {
	Applications      []map[string]interface{} `json:"applications"`
	ServicePrincipals []map[string]interface{} `json:"service_principals"`
	OAuthGrants       []map[string]interface{} `json:"oauth_grants"`
	AppCount          int                      `json:"app_count"`
	SPCount           int                      `json:"sp_count"`
	GrantCount        int                      `json:"grant_count"`
}

// Apps enumerates app registrations, service principals, and OAuth grants.
func Apps(ctx context.Context, client *graph.Client) (interface{}, error) {
	result := &AppsResult{}

	// App registrations
	output.Info("Fetching app registrations...")
	appRaw, err := client.GetAllWithProgress(ctx, graph.EndpointApplications, map[string]string{
		"$select": "id,appId,displayName,createdDateTime,requiredResourceAccess,passwordCredentials,keyCredentials,signInAudience,description,notes,web,spa,publicClient,identifierUris,tags,publisherDomain,homepage",
		"$top":    "999",
	}, "Applications")
	if err != nil {
		output.Error("Applications: %v", err)
	} else {
		result.Applications = unmarshalAll(appRaw)
		result.AppCount = len(result.Applications)
	}

	// Service principals
	output.Info("Fetching service principals...")
	spRaw, err := client.GetAllWithProgress(ctx, graph.EndpointServicePrincs, map[string]string{
		"$select": "id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,tags,description,homepage,loginUrl,replyUrls,servicePrincipalNames,accountEnabled,appDisplayName",
		"$top":    "999",
	}, "Service Principals")
	if err != nil {
		output.Error("Service principals: %v", err)
	} else {
		result.ServicePrincipals = unmarshalAll(spRaw)
		result.SPCount = len(result.ServicePrincipals)
	}

	// Build SP name lookup from already-fetched SPs
	spNameMap := map[string]string{}
	for _, sp := range result.ServicePrincipals {
		spID, _ := sp["id"].(string)
		spName, _ := sp["displayName"].(string)
		if spID != "" && spName != "" {
			spNameMap[spID] = spName
		}
	}

	// OAuth2 permission grants
	output.Info("Fetching OAuth2 permission grants...")
	grantRaw, err := client.GetAllWithProgress(ctx, graph.EndpointOAuth2Grants, map[string]string{
		"$select": "id,clientId,consentType,principalId,resourceId,scope",
		"$top":    "999",
	}, "OAuth Grants")
	if err != nil {
		output.Warn("OAuth grants: %v", err)
	} else {
		result.OAuthGrants = unmarshalAll(grantRaw)
		result.GrantCount = len(result.OAuthGrants)
	}

	// Pretty output
	printAppsResults(result, spNameMap)

	return result, nil
}

func printAppsResults(result *AppsResult, spNames map[string]string) {
	// Summary header
	output.SearchResultHeader("Application & Service Principal Enumeration",
		result.AppCount+result.SPCount,
		fmt.Sprintf("%d apps, %d SPs, %d OAuth grants", result.AppCount, result.SPCount, result.GrantCount))

	// === APP REGISTRATIONS ===
	if result.AppCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" App Registrations ("+fmt.Sprintf("%d", result.AppCount)+") "))

		appsWithCreds := 0
		appsMultiTenant := 0

		for i, a := range result.Applications {
			name, _ := a["displayName"].(string)
			appID, _ := a["appId"].(string)
			objID, _ := a["id"].(string)
			audience, _ := a["signInAudience"].(string)
			created, _ := a["createdDateTime"].(string)

			// Count credentials
			passCreds := countArrayField(a, "passwordCredentials")
			keyCreds := countArrayField(a, "keyCredentials")
			totalCreds := passCreds + keyCreds

			// Count required permissions
			permCount := countArrayField(a, "requiredResourceAccess")

			// Track stats
			if totalCreds > 0 {
				appsWithCreds++
			}
			if audience == "AzureADMultipleOrgs" || audience == "AzureADandPersonalMicrosoftAccount" {
				appsMultiTenant++
			}

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(name)

			// Audience tag
			audTag := output.StyleDim.Render("[" + audience + "]")
			if audience == "AzureADMultipleOrgs" || audience == "AzureADandPersonalMicrosoftAccount" {
				audTag = output.StyleHighlight.Render("[MULTI-TENANT]")
			}

			// Line 1: number + name + audience
			fmt.Printf("  %s %s  %s\n", num, nameStyled, audTag)

			// Line 2: IDs + created
			createdShort := created
			if len(createdShort) > 10 {
				createdShort = createdShort[:10]
			}
			fmt.Printf("       %s %s  %s %s  %s %s\n",
				output.StyleDim.Render("AppID:"), output.StyleDim.Render(appID),
				output.StyleDim.Render("ObjID:"), output.StyleDim.Render(objID),
				output.StyleDim.Render("Created:"), output.StyleDim.Render(createdShort))

			// Line 3: credentials + permissions
			details := ""
			if totalCreds > 0 {
				credStr := fmt.Sprintf("Secrets: %d, Certs: %d", passCreds, keyCreds)
				details += output.StyleCritical.Render(credStr) + "  "
			} else {
				details += output.StyleDim.Render("No credentials") + "  "
			}
			if permCount > 0 {
				details += output.StyleUserInfo.Render(fmt.Sprintf("API Permissions: %d resource(s)", permCount))
			}
			fmt.Printf("       %s\n", details)

			// Line 4: description (if any)
			desc, _ := a["description"].(string)
			if desc == "" {
				desc, _ = a["notes"].(string)
			}
			if desc != "" {
				if len(desc) > 120 {
					desc = desc[:117] + "..."
				}
				fmt.Printf("       %s %s\n", output.StyleDim.Render("Desc:"), output.StyleDim.Render(desc))
			}

			// Line 5: URLs (web redirects, homepage, identifierUris)
			urlInfo := []string{}
			if web, ok := a["web"].(map[string]interface{}); ok {
				if home, ok := web["homePageUrl"].(string); ok && home != "" {
					urlInfo = append(urlInfo, "Home: "+home)
				}
				if redirects, ok := web["redirectUris"].([]interface{}); ok && len(redirects) > 0 {
					first, _ := redirects[0].(string)
					if len(redirects) > 1 {
						urlInfo = append(urlInfo, fmt.Sprintf("Redirects: %s (+%d more)", first, len(redirects)-1))
					} else if first != "" {
						urlInfo = append(urlInfo, "Redirect: "+first)
					}
				}
			}
			if idUris, ok := a["identifierUris"].([]interface{}); ok && len(idUris) > 0 {
				first, _ := idUris[0].(string)
				if first != "" {
					urlInfo = append(urlInfo, "ID URI: "+first)
				}
			}
			if pubDomain, _ := a["publisherDomain"].(string); pubDomain != "" {
				urlInfo = append(urlInfo, "Publisher: "+pubDomain)
			}
			for _, u := range urlInfo {
				fmt.Printf("       %s\n", output.StyleURLInfo.Render(u))
			}

			// Line 6: tags
			if tags, ok := a["tags"].([]interface{}); ok && len(tags) > 0 {
				tagStrs := []string{}
				for _, t := range tags {
					if s, ok := t.(string); ok {
						tagStrs = append(tagStrs, s)
					}
				}
				if len(tagStrs) > 0 {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("Tags:"), output.StyleDim.Render(strings.Join(tagStrs, ", ")))
				}
			}

			fmt.Println()
		}

		// App stats
		output.SearchDivider()
		if appsWithCreds > 0 {
			output.Warn("%d apps have active credentials (secrets/certificates)", appsWithCreds)
		}
		if appsMultiTenant > 0 {
			output.Warn("%d apps are multi-tenant (accept external auth)", appsMultiTenant)
		}
		fmt.Println()
	}

	// === SERVICE PRINCIPALS ===
	if result.SPCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Service Principals ("+fmt.Sprintf("%d", result.SPCount)+") "))

		// Group by type
		typeCounts := map[string]int{}
		for _, sp := range result.ServicePrincipals {
			spType, _ := sp["servicePrincipalType"].(string)
			typeCounts[spType]++
		}

		// Show type summary
		for t, count := range typeCounts {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-25s", t+":")),
				output.StyleCounter.Render(fmt.Sprintf("%d", count)))
		}
		fmt.Println()

		// Show SPs with verbose
		shown := 0
		for i, sp := range result.ServicePrincipals {
			name, _ := sp["displayName"].(string)
			spType, _ := sp["servicePrincipalType"].(string)
			appID, _ := sp["appId"].(string)
			ownerOrg, _ := sp["appOwnerOrganizationId"].(string)
			enabled, _ := sp["accountEnabled"].(bool)
			desc, _ := sp["description"].(string)
			homepage, _ := sp["homepage"].(string)
			loginURL, _ := sp["loginUrl"].(string)

			// Only show detail in verbose, but always show Application type
			if spType != "Application" && !output.VerboseEnabled {
				continue
			}
			shown++

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(name)
			typeTag := output.StyleDim.Render("[" + spType + "]")

			// Enabled/disabled tag
			enabledTag := ""
			if !enabled {
				enabledTag = " " + output.StyleCritical.Render("[DISABLED]")
			}

			fmt.Printf("  %s %s  %s%s\n", num, nameStyled, typeTag, enabledTag)
			fmt.Printf("       %s %s", output.StyleDim.Render("AppID:"), output.StyleDim.Render(appID))
			if ownerOrg != "" {
				fmt.Printf("  %s %s", output.StyleDim.Render("OwnerOrg:"), output.StyleDim.Render(ownerOrg))
			}
			fmt.Println()

			// Description
			if desc != "" {
				if len(desc) > 120 {
					desc = desc[:117] + "..."
				}
				fmt.Printf("       %s %s\n", output.StyleDim.Render("Desc:"), output.StyleDim.Render(desc))
			}

			// URLs
			if homepage != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("Home:"), output.StyleURLInfo.Render(homepage))
			}
			if loginURL != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("Login:"), output.StyleURLInfo.Render(loginURL))
			}

			// Reply URLs
			if replyURLs, ok := sp["replyUrls"].([]interface{}); ok && len(replyURLs) > 0 {
				first, _ := replyURLs[0].(string)
				if len(replyURLs) > 1 {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("Replies:"),
						output.StyleURLInfo.Render(fmt.Sprintf("%s (+%d more)", first, len(replyURLs)-1)))
				} else if first != "" {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("Reply:"), output.StyleURLInfo.Render(first))
				}
			}

			// SPN names
			if spnNames, ok := sp["servicePrincipalNames"].([]interface{}); ok && len(spnNames) > 0 {
				spns := []string{}
				for _, s := range spnNames {
					if str, ok := s.(string); ok {
						spns = append(spns, str)
					}
				}
				if len(spns) > 0 && len(spns) <= 3 {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("SPNs:"), output.StyleDim.Render(strings.Join(spns, ", ")))
				} else if len(spns) > 3 {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("SPNs:"),
						output.StyleDim.Render(fmt.Sprintf("%s (+%d more)", strings.Join(spns[:2], ", "), len(spns)-2)))
				}
			}

			// Tags
			if tags, ok := sp["tags"].([]interface{}); ok && len(tags) > 0 {
				tagStrs := []string{}
				for _, t := range tags {
					if s, ok := t.(string); ok {
						tagStrs = append(tagStrs, s)
					}
				}
				if len(tagStrs) > 0 {
					fmt.Printf("       %s %s\n", output.StyleDim.Render("Tags:"), output.StyleURLInfo.Render(strings.Join(tagStrs, ", ")))
				}
			}
			fmt.Println()
		}
		_ = shown

		if !output.VerboseEnabled {
			output.Dim("Showing Application-type SPs only. Use -v for all %d service principals.", result.SPCount)
		}
		fmt.Println()
	}

	// === OAUTH GRANTS ===
	if result.GrantCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" OAuth2 Permission Grants ("+fmt.Sprintf("%d", result.GrantCount)+") "))

		allPrincipals := 0
		highRiskGrants := 0

		// Show only AllPrincipals by default, per-user with -v
		allPrincipalGrants := []map[string]interface{}{}
		perUserGrants := []map[string]interface{}{}

		for _, g := range result.OAuthGrants {
			consent, _ := g["consentType"].(string)
			scope, _ := g["scope"].(string)
			if consent == "AllPrincipals" {
				allPrincipals++
				allPrincipalGrants = append(allPrincipalGrants, g)
			} else {
				perUserGrants = append(perUserGrants, g)
			}
			if isHighRiskScope(scope) {
				highRiskGrants++
			}
		}

		// AllPrincipals grants (always show)
		if len(allPrincipalGrants) > 0 {
			fmt.Printf("    %s\n\n", output.StyleCritical.Render(fmt.Sprintf("▸ AllPrincipals (admin consent) — %d grants", len(allPrincipalGrants))))

			for i, g := range allPrincipalGrants {
				printOAuthGrant(i+1, g, spNames)
			}
			fmt.Println()
		}

		// Per-user grants
		if len(perUserGrants) > 0 {
			if output.VerboseEnabled {
				fmt.Printf("    %s\n\n", output.StyleDim.Render(fmt.Sprintf("▸ Per-User grants — %d", len(perUserGrants))))
				for i, g := range perUserGrants {
					printOAuthGrant(i+1, g, spNames)
				}
			} else {
				output.Dim("Hiding %d per-user grants. Use -v to show all.", len(perUserGrants))
			}
			fmt.Println()
		}

		output.SearchDivider()
		if allPrincipals > 0 {
			output.Warn("%d grants are AllPrincipals (admin consent — applies to ALL users)", allPrincipals)
		}
		if highRiskGrants > 0 {
			output.Warn("%d grants contain high-risk scopes (Mail, Files, Directory write)", highRiskGrants)
		}
	}

	fmt.Println()
	output.Success("Enumerated %d apps, %d service principals, %d OAuth grants",
		result.AppCount, result.SPCount, result.GrantCount)
}

func printOAuthGrant(index int, g map[string]interface{}, spNames map[string]string) {
	clientID, _ := g["clientId"].(string)
	resourceID, _ := g["resourceId"].(string)
	consent, _ := g["consentType"].(string)
	scope, _ := g["scope"].(string)
	principalID, _ := g["principalId"].(string)

	// Resolve names
	clientName := spNames[clientID]
	resourceName := spNames[resourceID]

	num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", index))

	// Client display
	clientDisplay := clientID
	if clientName != "" {
		clientDisplay = clientName
	}

	// Resource display
	resourceDisplay := ""
	if resourceName != "" {
		resourceDisplay = " → " + resourceName
	} else if resourceID != "" {
		resourceDisplay = " → " + resourceID
	}

	// Consent tag
	consentTag := output.StyleDim.Render("[" + consent + "]")
	isAllPrincipals := consent == "AllPrincipals"
	if isAllPrincipals {
		consentTag = output.StyleCritical.Render("[AllPrincipals]")
	}

	// Line 1: client → resource + consent
	fmt.Printf("  %s %s%s  %s\n", num,
		output.StyleBold.Render(clientDisplay),
		output.StyleURLInfo.Render(resourceDisplay),
		consentTag)

	// Line 2: IDs (dim)
	idLine := output.StyleDim.Render("ClientID: "+clientID)
	if resourceID != "" {
		idLine += "  " + output.StyleDim.Render("ResourceID: "+resourceID)
	}
	if principalID != "" {
		idLine += "  " + output.StyleDim.Render("Principal: "+principalID)
	}
	fmt.Printf("       %s\n", idLine)

	// Line 3: scopes with per-scope risk highlighting
	if scope != "" {
		scopes := strings.Fields(scope)
		styledScopes := []string{}
		for _, s := range scopes {
			if isHighRiskScopeStr(s) {
				styledScopes = append(styledScopes, output.StyleCritical.Render(s))
			} else {
				styledScopes = append(styledScopes, output.StyleDim.Render(s))
			}
		}
		fmt.Printf("       %s %s\n", output.StyleBold.Render("Scopes:"), strings.Join(styledScopes, " "))
	}

	fmt.Println()
}

func isHighRiskScopeStr(scope string) bool {
	highRisk := []string{
		"Mail.ReadWrite", "Mail.Send", "Mail.Read",
		"Files.ReadWrite.All", "Files.Read.All",
		"Directory.ReadWrite.All", "Directory.AccessAsUser.All",
		"User.ReadWrite.All", "Group.ReadWrite.All",
		"Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
		"AppRoleAssignment.ReadWrite.All", "Sites.FullControl.All",
		"Mail.ReadWrite.Shared", "Mail.Read.All", "Mail.Send.Shared",
	}
	for _, hr := range highRisk {
		if strings.EqualFold(scope, hr) {
			return true
		}
	}
	return false
}

func countArrayField(m map[string]interface{}, field string) int {
	arr, ok := m[field].([]interface{})
	if !ok {
		return 0
	}
	return len(arr)
}

func isHighRiskScope(scope string) bool {
	highRisk := []string{
		"Mail.ReadWrite", "Mail.Send", "Mail.Read",
		"Files.ReadWrite.All", "Files.Read.All",
		"Directory.ReadWrite.All", "Directory.AccessAsUser.All",
		"User.ReadWrite.All", "Group.ReadWrite.All",
		"Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
		"AppRoleAssignment.ReadWrite.All",
	}
	scopeLower := strings.ToLower(scope)
	for _, hr := range highRisk {
		if strings.Contains(scopeLower, strings.ToLower(hr)) {
			return true
		}
	}
	return false
}
