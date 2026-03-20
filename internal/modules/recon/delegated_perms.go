package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// OAuth2Grant represents an oauth2PermissionGrant (delegated permission consent).
type OAuth2Grant struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	ConsentType  string `json:"consentType"` // "AllPrincipals" or "Principal"
	PrincipalID  string `json:"principalId,omitempty"`
	ResourceID   string `json:"resourceId"`
	Scope        string `json:"scope"`
	ClientName   string `json:"client_name,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
}

// DelegatedPermsResult holds all oauth2PermissionGrants in the tenant.
type DelegatedPermsResult struct {
	Grants          []OAuth2Grant `json:"grants"`
	Total           int           `json:"total"`
	AllPrincipals   int           `json:"all_principals_count"`
	PerUser         int           `json:"per_user_count"`
	HighRiskGrants  []OAuth2Grant `json:"high_risk_grants"`
}

// highRiskScopes are delegated permissions that are especially dangerous with AllPrincipals consent.
var highRiskScopes = map[string]bool{
	"Mail.ReadWrite":           true,
	"Mail.Send":                true,
	"Mail.Read":                true,
	"Files.ReadWrite.All":      true,
	"Directory.ReadWrite.All":  true,
	"User.ReadWrite.All":       true,
	"Group.ReadWrite.All":      true,
	"RoleManagement.ReadWrite.Directory": true,
	"AppRoleAssignment.ReadWrite.All":    true,
	"Application.ReadWrite.All":          true,
}

// DelegatedPermissions enumerates all oauth2PermissionGrants (delegated permission consents).
// Identifies high-risk AllPrincipals grants — key for privilege escalation path analysis.
func DelegatedPermissions(ctx context.Context, c *graph.Client) (*DelegatedPermsResult, error) {
	output.Info("Fetching oauth2PermissionGrants (delegated permission consents)...")

	raw, err := c.GetAllWithProgress(ctx, "/oauth2PermissionGrants", nil, "OAuth Grants")
	if err != nil {
		return nil, err
	}

	// Build SP name cache for resolving IDs
	spNames := buildSPNameCache(ctx, c)

	result := &DelegatedPermsResult{}

	for _, r := range raw {
		var grant OAuth2Grant
		if err := json.Unmarshal(r, &grant); err != nil {
			continue
		}

		// Resolve display names
		if name, ok := spNames[grant.ClientID]; ok {
			grant.ClientName = name
		}
		if name, ok := spNames[grant.ResourceID]; ok {
			grant.ResourceName = name
		}

		if grant.ConsentType == "AllPrincipals" {
			result.AllPrincipals++
			// Check for high-risk scopes
			for _, scope := range splitScopes(grant.Scope) {
				if highRiskScopes[scope] {
					result.HighRiskGrants = append(result.HighRiskGrants, grant)
					output.Verbose("[delegated] HIGH RISK: %s → %s [%s] (AllPrincipals)",
						grant.ClientName, grant.ResourceName, grant.Scope)
					break
				}
			}
		} else {
			result.PerUser++
		}

		result.Grants = append(result.Grants, grant)
		output.Verbose("[delegated] %s → %s | %s | %s",
			grant.ClientName, grant.ResourceName, grant.ConsentType, grant.Scope)
	}

	result.Total = len(result.Grants)

	// Pretty output
	printDelegatedPermsResults(result)

	return result, nil
}

func printDelegatedPermsResults(result *DelegatedPermsResult) {
	output.SearchResultHeader("Delegated Permission Grants (oauth2PermissionGrants)",
		result.Total,
		fmt.Sprintf("%d AllPrincipals, %d per-user, %d high-risk", result.AllPrincipals, result.PerUser, len(result.HighRiskGrants)))

	if result.Total == 0 {
		output.Warn("No delegated permission grants found")
		return
	}

	// === HIGH RISK GRANTS (always show) ===
	if len(result.HighRiskGrants) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" HIGH-RISK AllPrincipals Grants (%d) ", len(result.HighRiskGrants))))

		for i, g := range result.HighRiskGrants {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			client := g.ClientName
			if client == "" {
				client = g.ClientID
			}
			resource := g.ResourceName
			if resource == "" {
				resource = g.ResourceID
			}

			clientStyled := output.StyleBold.Render(client)
			arrow := output.StyleCritical.Render(" → ")
			resourceStyled := output.StyleURLInfo.Render(resource)

			// Line 1: client → resource
			fmt.Printf("  %s %s%s%s  %s\n", num, clientStyled, arrow, resourceStyled,
				output.StyleCritical.Render("[AllPrincipals]"))

			// Line 2: scopes with high-risk highlighted
			scopes := splitScopes(g.Scope)
			scopeParts := []string{}
			for _, s := range scopes {
				if highRiskScopes[s] {
					scopeParts = append(scopeParts, output.StyleCritical.Render(s))
				} else {
					scopeParts = append(scopeParts, output.StyleDim.Render(s))
				}
			}
			fmt.Printf("       %s %s\n", output.StyleBold.Render("Scopes:"), strings.Join(scopeParts, " "))

			// Line 3: IDs
			fmt.Printf("       %s %s  %s %s\n",
				output.StyleDim.Render("ClientID:"), output.StyleDim.Render(g.ClientID),
				output.StyleDim.Render("ResourceID:"), output.StyleDim.Render(g.ResourceID))

			fmt.Println()
		}

		output.SearchDivider()
		output.Warn("%d grants give dangerous scopes to ALL users (admin consent)", len(result.HighRiskGrants))
		fmt.Println()
	}

	// === AllPrincipals summary ===
	if result.AllPrincipals > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" AllPrincipals Grants (%d) ", result.AllPrincipals)))

		shown := 0
		for _, g := range result.Grants {
			if g.ConsentType != "AllPrincipals" {
				continue
			}
			// Skip if already shown in high-risk
			isHR := false
			for _, hr := range result.HighRiskGrants {
				if hr.ID == g.ID {
					isHR = true
					break
				}
			}
			if isHR {
				continue
			}

			shown++
			client := g.ClientName
			if client == "" {
				client = g.ClientID[:12] + ".."
			}
			resource := g.ResourceName
			if resource == "" {
				resource = g.ResourceID[:12] + ".."
			}

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", shown))
			fmt.Printf("  %s %s → %s  %s\n", num,
				output.StyleBold.Render(fmt.Sprintf("%-30s", client)),
				output.StyleURLInfo.Render(resource),
				output.StyleDim.Render(g.Scope))
		}
		fmt.Println()
	}

	// === Per-user grants (verbose only) ===
	if result.PerUser > 0 && output.VerboseEnabled {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Per-User Grants (%d) ", result.PerUser)))

		shown := 0
		for _, g := range result.Grants {
			if g.ConsentType == "AllPrincipals" {
				continue
			}
			shown++
			client := g.ClientName
			if client == "" {
				client = g.ClientID
			}
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", shown))
			fmt.Printf("  %s %s  %s %s  %s\n", num,
				output.StyleDim.Render(fmt.Sprintf("%-30s", client)),
				output.StyleDim.Render("Principal:"), output.StyleDim.Render(g.PrincipalID),
				output.StyleDim.Render(g.Scope))
		}
		fmt.Println()
	} else if result.PerUser > 0 {
		output.Dim("Hiding %d per-user grants. Use -v to show all.", result.PerUser)
	}

	output.SearchDivider()
	output.Success("Delegated permissions: %d grants (%d AllPrincipals, %d per-user, %d high-risk)",
		result.Total, result.AllPrincipals, result.PerUser, len(result.HighRiskGrants))
}

func buildSPNameCache(ctx context.Context, c *graph.Client) map[string]string {
	cache := make(map[string]string)
	raw, err := c.GetAll(ctx, "/servicePrincipals", map[string]string{
		"$select": "id,displayName",
		"$top":    "999",
	})
	if err != nil {
		return cache
	}
	for _, r := range raw {
		var sp struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(r, &sp); err == nil {
			cache[sp.ID] = sp.DisplayName
		}
	}
	return cache
}

func splitScopes(scope string) []string {
	var scopes []string
	current := ""
	for _, ch := range scope {
		if ch == ' ' {
			if current != "" {
				scopes = append(scopes, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		scopes = append(scopes, current)
	}
	return scopes
}
