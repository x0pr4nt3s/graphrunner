package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// MFAUserStatus holds MFA registration info for one user.
type MFAUserStatus struct {
	UserPrincipalName string   `json:"user_principal_name"`
	DisplayName       string   `json:"display_name"`
	AccountEnabled    bool     `json:"account_enabled"`
	Methods           []string `json:"methods"`
	HasStrongMFA      bool     `json:"has_strong_mfa"`
	MFACount          int      `json:"mfa_method_count"`
}

// MFAResult holds the full MFA status report.
type MFAResult struct {
	TotalUsers      int             `json:"total_users"`
	NoMFA           int             `json:"no_mfa"`
	WeakMFAOnly     int             `json:"weak_mfa_only"`
	StrongMFA       int             `json:"strong_mfa"`
	Users           []MFAUserStatus `json:"users"`
	NoMFAUsers      []string        `json:"no_mfa_users"`
}

// strongMethods are MFA methods that provide real protection.
var strongMethods = map[string]bool{
	"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": true,
	"#microsoft.graph.fido2AuthenticationMethod":                  true,
	"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": true,
	"#microsoft.graph.softwareOathAuthenticationMethod":           true,
	"#microsoft.graph.phoneAuthenticationMethod":                  true,
}

// MFAStatus enumerates MFA registration status for all users.
func MFAStatus(ctx context.Context, client *graph.Client) (*MFAResult, error) {
	output.Info("Enumerating users...")
	usersRaw, err := client.GetAll(ctx, graph.EndpointUsers, map[string]string{
		"$select": "id,displayName,userPrincipalName,accountEnabled",
		"$top":    "999",
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	result := &MFAResult{}

	output.Info("Checking MFA methods for %d users...", len(usersRaw))

	for _, uRaw := range usersRaw {
		var u map[string]interface{}
		json.Unmarshal(uRaw, &u)

		id, _ := u["id"].(string)
		upn, _ := u["userPrincipalName"].(string)
		displayName, _ := u["displayName"].(string)
		enabled, _ := u["accountEnabled"].(bool)

		if id == "" {
			continue
		}

		output.Verbose("checking %s", upn)

		status := MFAUserStatus{
			UserPrincipalName: upn,
			DisplayName:       displayName,
			AccountEnabled:    enabled,
		}

		endpoint := fmt.Sprintf(graph.EndpointUserAuthMethods, id)
		methodsRaw, err := client.GetAll(ctx, endpoint, nil)
		if err != nil {
			output.Verbose("  auth methods error for %s: %v", upn, err)
			// Count as no MFA if we can't read (likely access denied)
		} else {
			for _, mRaw := range methodsRaw {
				var m map[string]interface{}
				json.Unmarshal(mRaw, &m)
				odata, _ := m["@odata.type"].(string)
				if odata == "" {
					continue
				}
				// Shorten the type name for display
				short := odata
				if idx := strings.LastIndex(odata, "."); idx >= 0 {
					short = odata[idx+1:]
					short = strings.TrimSuffix(short, "AuthenticationMethod")
				}
				status.Methods = append(status.Methods, short)
				if strongMethods[odata] {
					status.HasStrongMFA = true
				}
			}
			status.MFACount = len(status.Methods)
		}

		result.TotalUsers++
		result.Users = append(result.Users, status)

		if status.MFACount == 0 {
			result.NoMFA++
			result.NoMFAUsers = append(result.NoMFAUsers, upn)
			output.Warn("  NO MFA: %s", upn)
		} else if !status.HasStrongMFA {
			result.WeakMFAOnly++
			output.Verbose("  weak MFA only: %s (%s)", upn, strings.Join(status.Methods, ","))
		} else {
			result.StrongMFA++
			output.Verbose("  strong MFA: %s (%s)", upn, strings.Join(status.Methods, ","))
		}
	}

	printMFAResults(result)
	return result, nil
}

func printMFAResults(result *MFAResult) {
	strongPct := 0
	weakPct := 0
	nonePct := 0
	if result.TotalUsers > 0 {
		strongPct = (result.StrongMFA * 100) / result.TotalUsers
		weakPct = (result.WeakMFAOnly * 100) / result.TotalUsers
		nonePct = (result.NoMFA * 100) / result.TotalUsers
	}

	output.SearchResultHeader("MFA Status",
		result.TotalUsers,
		fmt.Sprintf("%d strong / %d weak-only / %d none", result.StrongMFA, result.WeakMFAOnly, result.NoMFA))

	if result.TotalUsers == 0 {
		output.Warn("No users found")
		return
	}

	// Overview bar chart
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" MFA Coverage "))

	strongBar := ""
	if strongPct > 0 {
		strongBar = strings.Repeat("█", strongPct/5)
	}
	weakBar := ""
	if weakPct > 0 {
		weakBar = strings.Repeat("█", weakPct/5)
	}
	noneBar := ""
	if nonePct > 0 {
		noneBar = strings.Repeat("█", nonePct/5)
	}

	fmt.Printf("       %s %s %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Strong MFA")),
		output.StyleCounter.Render(fmt.Sprintf("%4d", result.StrongMFA)),
		output.StyleProgress.Render(strongBar),
		output.StyleSuccess.Render(fmt.Sprintf("%d%%", strongPct)))
	fmt.Printf("       %s %s %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Weak MFA Only")),
		output.StyleCounter.Render(fmt.Sprintf("%4d", result.WeakMFAOnly)),
		output.StyleMedium.Render(weakBar),
		output.StyleMedium.Render(fmt.Sprintf("%d%%", weakPct)))
	fmt.Printf("       %s %s %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "No MFA")),
		output.StyleCounter.Render(fmt.Sprintf("%4d", result.NoMFA)),
		output.StyleCritical.Render(noneBar),
		output.StyleCritical.Render(fmt.Sprintf("%d%%", nonePct)))
	fmt.Println()

	// Method breakdown
	methodCounts := map[string]int{}
	for _, u := range result.Users {
		for _, m := range u.Methods {
			methodCounts[m]++
		}
	}
	if len(methodCounts) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Method Breakdown "))
		for method, count := range methodCounts {
			pct := (count * 100) / result.TotalUsers
			bar := ""
			if pct > 0 {
				bar = strings.Repeat("█", pct/5)
			}
			fmt.Printf("       %s %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-35s", method)),
				output.StyleCounter.Render(fmt.Sprintf("%4d", count)),
				output.StyleProgress.Render(bar))
		}
		fmt.Println()
	}

	// NO MFA section (always shown)
	if result.NoMFA > 0 {
		fmt.Printf("  %s\n\n", output.StyleCritical.Render(fmt.Sprintf(" [NO MFA] Users Without MFA (%d) ", result.NoMFA)))
		idx := 0
		for _, u := range result.Users {
			if u.MFACount != 0 {
				continue
			}
			idx++
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", idx))
			nameStyled := output.StyleBold.Render(u.DisplayName)
			upnStyled := output.StyleDim.Render(u.UserPrincipalName)
			tag := output.StyleCritical.Render("[NO MFA]")
			enabledTag := ""
			if !u.AccountEnabled {
				enabledTag = output.StyleDim.Render("[disabled]")
			}
			fmt.Printf("  %s %s  %s  %s %s\n", num, nameStyled, upnStyled, tag, enabledTag)
		}
		fmt.Println()
	}

	// WEAK ONLY section (always shown)
	if result.WeakMFAOnly > 0 {
		fmt.Printf("  %s\n\n", output.StyleMedium.Render(fmt.Sprintf(" [WEAK ONLY] Users With Only Weak MFA (%d) ", result.WeakMFAOnly)))
		idx := 0
		for _, u := range result.Users {
			if u.MFACount == 0 || u.HasStrongMFA {
				continue
			}
			idx++
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", idx))
			nameStyled := output.StyleBold.Render(u.DisplayName)
			upnStyled := output.StyleDim.Render(u.UserPrincipalName)
			tag := output.StyleMedium.Render("[WEAK]")
			methods := output.StyleDim.Render(strings.Join(u.Methods, ", "))
			fmt.Printf("  %s %s  %s  %s\n", num, nameStyled, upnStyled, tag)
			fmt.Printf("       %s\n", methods)
		}
		fmt.Println()
	}

	// STRONG MFA section (verbose only)
	if output.VerboseEnabled && result.StrongMFA > 0 {
		fmt.Printf("  %s\n\n", output.StyleSuccess.Render(fmt.Sprintf(" [STRONG MFA] Users With Strong MFA (%d) ", result.StrongMFA)))
		idx := 0
		for _, u := range result.Users {
			if !u.HasStrongMFA {
				continue
			}
			idx++
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", idx))
			nameStyled := output.StyleBold.Render(u.DisplayName)
			upnStyled := output.StyleDim.Render(u.UserPrincipalName)
			tag := output.StyleSuccess.Render("[STRONG]")
			methods := output.StyleDim.Render(strings.Join(u.Methods, ", "))
			fmt.Printf("  %s %s  %s  %s\n", num, nameStyled, upnStyled, tag)
			fmt.Printf("       %s\n", methods)
		}
		fmt.Println()
	}

	if !output.VerboseEnabled && result.StrongMFA > 0 {
		output.Dim("Use -v to see %d users with strong MFA", result.StrongMFA)
	}

	// Risk summary
	output.SearchDivider()
	if result.NoMFA > 0 {
		output.Critical("%d user(s) (%d%%) have NO MFA — high risk for account takeover", result.NoMFA, nonePct)
	}
	if result.WeakMFAOnly > 0 {
		output.Warn("%d user(s) (%d%%) have only weak MFA methods", result.WeakMFAOnly, weakPct)
	}
	if result.NoMFA == 0 && result.WeakMFAOnly == 0 {
		output.Success("All users have strong MFA enabled")
	}

	fmt.Println()
	output.Success("MFA scan: %d users | strong: %d (%d%%) | weak: %d (%d%%) | none: %d (%d%%)",
		result.TotalUsers,
		result.StrongMFA, strongPct,
		result.WeakMFAOnly, weakPct,
		result.NoMFA, nonePct)
}
