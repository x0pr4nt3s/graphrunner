package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// CAPsResult holds Conditional Access policy data.
type CAPsResult struct {
	Policies []map[string]interface{} `json:"policies"`
	Count    int                      `json:"count"`
	Enabled  int                      `json:"enabled"`
	Disabled int                      `json:"disabled"`
}

// ConditionalAccess dumps all Conditional Access policies.
func ConditionalAccess(ctx context.Context, client *graph.Client) (interface{}, error) {
	raw, err := client.GetAll(ctx, graph.EndpointCAPs, map[string]string{
		"$select": "id,displayName,state,conditions,grantControls,sessionControls",
	})
	if err != nil {
		return nil, err
	}

	policies := unmarshalAll(raw)
	result := &CAPsResult{
		Policies: policies,
		Count:    len(policies),
	}

	for _, p := range policies {
		state, _ := p["state"].(string)
		switch state {
		case "enabled":
			result.Enabled++
		case "disabled":
			result.Disabled++
		}
	}

	// Pretty output
	printCAPsResults(result)

	return result, nil
}

func printCAPsResults(result *CAPsResult) {
	output.SearchResultHeader("Conditional Access Policies",
		result.Count,
		fmt.Sprintf("%d enabled, %d disabled", result.Enabled, result.Disabled))

	if result.Count == 0 {
		output.Warn("No Conditional Access policies found (missing Policy.Read.All?)")
		return
	}

	// === ENABLED POLICIES ===
	enabledPolicies := []map[string]interface{}{}
	disabledPolicies := []map[string]interface{}{}
	for _, p := range result.Policies {
		state, _ := p["state"].(string)
		if state == "enabled" {
			enabledPolicies = append(enabledPolicies, p)
		} else {
			disabledPolicies = append(disabledPolicies, p)
		}
	}

	if len(enabledPolicies) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Enabled Policies ("+fmt.Sprintf("%d", len(enabledPolicies))+") "))

		for i, p := range enabledPolicies {
			printCAPolicy(i+1, p, true)
		}
		fmt.Println()
	}

	// === DISABLED POLICIES ===
	if len(disabledPolicies) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Disabled Policies ("+fmt.Sprintf("%d", len(disabledPolicies))+") "))

		for i, p := range disabledPolicies {
			printCAPPolicy(i+1, p, false)
		}
		fmt.Println()
	}

	output.SearchDivider()
	output.Success("Dumped %d CA policies (%d enabled, %d disabled)",
		result.Count, result.Enabled, result.Disabled)

	// Warnings
	mfaCount := 0
	blockCount := 0
	allUsersCount := 0
	for _, p := range enabledPolicies {
		grant := parseCAPGrant(p)
		if strings.Contains(strings.ToLower(grant), "mfa") || strings.Contains(grant, "authenticationStrength") {
			mfaCount++
		}
		if strings.Contains(grant, "block") {
			blockCount++
		}
		users := parseCAPUsers(p)
		if strings.Contains(users, "All") {
			allUsersCount++
		}
	}
	if mfaCount > 0 {
		output.Info("%d policies enforce MFA", mfaCount)
	}
	if blockCount > 0 {
		output.Warn("%d policies BLOCK access", blockCount)
	}
	if allUsersCount > 0 {
		output.Info("%d policies target All Users", allUsersCount)
	}
}

func printCAPolicy(index int, p map[string]interface{}, enabled bool) {
	printCAPPolicy(index, p, enabled)
}

func printCAPPolicy(index int, p map[string]interface{}, enabled bool) {
	name, _ := p["displayName"].(string)
	id, _ := p["id"].(string)

	num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", index))

	stateTag := output.StyleSuccess.Render("[ENABLED]")
	if !enabled {
		stateTag = output.StyleDim.Render("[disabled]")
	}
	nameStyled := output.StyleBold.Render(name)

	// Line 1: number + name + state
	fmt.Printf("  %s %s  %s\n", num, nameStyled, stateTag)
	fmt.Printf("       %s %s\n", output.StyleDim.Render("ID:"), output.StyleDim.Render(id))

	// Parse conditions
	users := parseCAPUsers(p)
	apps := parseCAPApps(p)
	platforms := parseCAPPlatforms(p)
	locations := parseCAPLocations(p)

	if users != "" {
		fmt.Printf("       %s %s\n", output.StyleBold.Render("Users:"), output.StyleUserInfo.Render(users))
	}
	if apps != "" {
		fmt.Printf("       %s %s\n", output.StyleBold.Render("Apps:"), output.StyleURLInfo.Render(apps))
	}
	if platforms != "" {
		fmt.Printf("       %s %s\n", output.StyleDim.Render("Platforms:"), output.StyleDim.Render(platforms))
	}
	if locations != "" {
		fmt.Printf("       %s %s\n", output.StyleDim.Render("Locations:"), output.StyleDim.Render(locations))
	}

	// Grant controls
	grant := parseCAPGrant(p)
	if grant != "" {
		grantStyled := output.StyleURLInfo.Render(grant)
		if strings.Contains(grant, "block") {
			grantStyled = output.StyleCritical.Render(grant)
		} else if strings.Contains(strings.ToLower(grant), "mfa") {
			grantStyled = output.StyleHighlight.Render(grant)
		}
		fmt.Printf("       %s %s\n", output.StyleBold.Render("Grant:"), grantStyled)
	}

	// Session controls
	session := parseCAPSession(p)
	if session != "" {
		fmt.Printf("       %s %s\n", output.StyleDim.Render("Session:"), output.StyleDim.Render(session))
	}

	fmt.Println()
}

func parseCAPUsers(p map[string]interface{}) string {
	cond, _ := p["conditions"].(map[string]interface{})
	if cond == nil {
		return ""
	}
	users, _ := cond["users"].(map[string]interface{})
	if users == nil {
		return ""
	}
	parts := []string{}
	if inc, ok := users["includeUsers"].([]interface{}); ok {
		for _, u := range inc {
			if s, ok := u.(string); ok {
				parts = append(parts, s)
			}
		}
	}
	if inc, ok := users["includeGroups"].([]interface{}); ok && len(inc) > 0 {
		parts = append(parts, fmt.Sprintf("+%d groups", len(inc)))
	}
	if inc, ok := users["includeRoles"].([]interface{}); ok && len(inc) > 0 {
		parts = append(parts, fmt.Sprintf("+%d roles", len(inc)))
	}
	if exc, ok := users["excludeUsers"].([]interface{}); ok && len(exc) > 0 {
		parts = append(parts, fmt.Sprintf("(excl %d users)", len(exc)))
	}
	if exc, ok := users["excludeGroups"].([]interface{}); ok && len(exc) > 0 {
		parts = append(parts, fmt.Sprintf("(excl %d groups)", len(exc)))
	}
	return strings.Join(parts, ", ")
}

func parseCAPApps(p map[string]interface{}) string {
	cond, _ := p["conditions"].(map[string]interface{})
	if cond == nil {
		return ""
	}
	apps, _ := cond["applications"].(map[string]interface{})
	if apps == nil {
		return ""
	}
	parts := []string{}
	if inc, ok := apps["includeApplications"].([]interface{}); ok {
		for _, a := range inc {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) > 3 {
		return fmt.Sprintf("%s + %d more", strings.Join(parts[:3], ", "), len(parts)-3)
	}
	return strings.Join(parts, ", ")
}

func parseCAPPlatforms(p map[string]interface{}) string {
	cond, _ := p["conditions"].(map[string]interface{})
	if cond == nil {
		return ""
	}
	plat, _ := cond["platforms"].(map[string]interface{})
	if plat == nil {
		return ""
	}
	if inc, ok := plat["includePlatforms"].([]interface{}); ok {
		parts := []string{}
		for _, v := range inc {
			if s, ok := v.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func parseCAPLocations(p map[string]interface{}) string {
	cond, _ := p["conditions"].(map[string]interface{})
	if cond == nil {
		return ""
	}
	loc, _ := cond["locations"].(map[string]interface{})
	if loc == nil {
		return ""
	}
	if inc, ok := loc["includeLocations"].([]interface{}); ok {
		parts := []string{}
		for _, v := range inc {
			if s, ok := v.(string); ok {
				parts = append(parts, s)
			}
		}
		return "include: " + strings.Join(parts, ", ")
	}
	return ""
}

func parseCAPGrant(p map[string]interface{}) string {
	gc, _ := p["grantControls"].(map[string]interface{})
	if gc == nil {
		return ""
	}
	parts := []string{}
	if op, ok := gc["operator"].(string); ok {
		parts = append(parts, op+":")
	}
	if builtIn, ok := gc["builtInControls"].([]interface{}); ok {
		for _, b := range builtIn {
			if s, ok := b.(string); ok {
				parts = append(parts, s)
			}
		}
	}
	if as, ok := gc["authenticationStrength"].(map[string]interface{}); ok {
		if dn, ok := as["displayName"].(string); ok {
			parts = append(parts, "authStrength:"+dn)
		}
	}
	return strings.Join(parts, " ")
}

func parseCAPSession(p map[string]interface{}) string {
	sc, _ := p["sessionControls"].(map[string]interface{})
	if sc == nil {
		return ""
	}
	raw, _ := json.Marshal(sc)
	s := string(raw)
	if s == "{}" || s == "null" {
		return ""
	}
	parts := []string{}
	if _, ok := sc["signInFrequency"]; ok {
		parts = append(parts, "signInFrequency")
	}
	if _, ok := sc["persistentBrowser"]; ok {
		parts = append(parts, "persistentBrowser")
	}
	if _, ok := sc["applicationEnforcedRestrictions"]; ok {
		parts = append(parts, "appRestrictions")
	}
	if _, ok := sc["cloudAppSecurity"]; ok {
		parts = append(parts, "cloudAppSecurity")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}
