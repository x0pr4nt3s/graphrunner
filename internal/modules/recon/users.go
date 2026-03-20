package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// All on-premises and identity attributes available via Graph API.
// Using $select=* is not supported — must enumerate fields explicitly.
var userSelectFields = strings.Join([]string{
	// Core identity
	"id",
	"displayName",
	"givenName",
	"surname",
	"userPrincipalName",
	"mail",
	"mailNickname",
	"proxyAddresses",
	"otherMails",
	"identities",

	// Account state
	"accountEnabled",
	"userType",
	"createdDateTime",
	"deletedDateTime",
	"externalUserState",
	"externalUserStateChangeDateTime",

	// On-premises sync — all fields
	"onPremisesDistinguishedName",
	"onPremisesDomainName",
	"onPremisesImmutableId",
	"onPremisesLastSyncDateTime",
	"onPremisesNetBiosName",
	"onPremisesSamAccountName",
	"onPremisesSecurityIdentifier",
	"onPremisesSyncEnabled",
	"onPremisesUserPrincipalName",
	"onPremisesExtensionAttributes",
	"onPremisesProvisioningErrors",

	// Job / org info
	"jobTitle",
	"department",
	"companyName",
	"division",
	"employeeId",
	"employeeType",
	"employeeHireDate",
	"employeeLeaveDateTime",
	"employeeOrgData",
	"officeLocation",
	"manager",

	// Contact
	"businessPhones",
	"mobilePhone",
	"faxNumber",
	"streetAddress",
	"city",
	"state",
	"postalCode",
	"country",
	"preferredLanguage",
	"usageLocation",

	// Security
	"passwordPolicies",
	"passwordProfile",
	"lastPasswordChangeDateTime",
	"signInSessionsValidFromDateTime",
	"refreshTokensValidFromDateTime",

	// Licenses & auth
	"assignedLicenses",
	"assignedPlans",
	"licenseAssignmentStates",
	"provisionedPlans",

	// Other
	"ageGroup",
	"consentProvidedForMinor",
	"legalAgeGroupClassification",
	"showInAddressList",
	"preferredDataLocation",
	"isResourceAccount",
}, ",")

// UsersResult holds user enumeration data.
type UsersResult struct {
	TotalCount int                      `json:"total_count"`
	Users      []map[string]interface{} `json:"users"`
}

// Users enumerates all directory users with full attribute set.
func Users(ctx context.Context, client *graph.Client) (interface{}, error) {
	params := map[string]string{
		"$select": userSelectFields,
		"$top":    "999",
	}

	output.Info("Fetching all users...")
	raw, err := client.GetAllWithProgress(ctx, graph.EndpointUsers, params, "Users")
	if err != nil {
		return nil, err
	}

	users := unmarshalAll(raw)
	for _, u := range users {
		upn, _ := u["userPrincipalName"].(string)
		sam, _ := u["onPremisesSamAccountName"].(string)
		enabled, _ := u["accountEnabled"].(bool)
		status := "disabled"
		if enabled {
			status = "enabled"
		}
		if sam != "" {
			output.Verbose("%s  [sam: %s]  [%s]", upn, sam, status)
		} else {
			output.Verbose("%s  [%s]", upn, status)
		}
	}
	result := &UsersResult{
		TotalCount: len(users),
		Users:      users,
	}

	printUsersResults(result)

	return result, nil
}

func printUsersResults(result *UsersResult) {
	output.SearchResultHeader("User Enumeration", result.TotalCount, "all attributes")

	if result.TotalCount == 0 {
		output.Warn("No users found")
		return
	}

	// Compute stats
	enabled := 0
	disabled := 0
	onPremSynced := 0
	cloudOnly := 0
	guestCount := 0
	externalCount := 0
	deptCounts := make(map[string]int)
	disabledWithLicense := 0
	noLastPwdChange := 0

	for _, u := range result.Users {
		accountEnabled, _ := u["accountEnabled"].(bool)
		if accountEnabled {
			enabled++
		} else {
			disabled++
			// Check if disabled but has licenses
			licenses, _ := u["assignedLicenses"].([]interface{})
			if len(licenses) > 0 {
				disabledWithLicense++
			}
		}

		syncEnabled, _ := u["onPremisesSyncEnabled"].(bool)
		if syncEnabled {
			onPremSynced++
		} else {
			cloudOnly++
		}

		userType, _ := u["userType"].(string)
		if userType == "Guest" {
			guestCount++
		}

		extState, _ := u["externalUserState"].(string)
		if extState != "" {
			externalCount++
		}

		dept, _ := u["department"].(string)
		if dept != "" {
			deptCounts[dept]++
		}

		lastPwd, _ := u["lastPasswordChangeDateTime"].(string)
		if lastPwd == "" {
			noLastPwdChange++
		}
	}

	// Summary table
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Summary "))
	output.TableRow("Total Users:", output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalCount)))
	output.TableRow("Enabled:", output.StyleSuccess.Render(fmt.Sprintf("%d", enabled)))
	if disabled > 0 {
		output.TableRow("Disabled:", output.StyleMedium.Render(fmt.Sprintf("%d", disabled)))
	}
	output.TableRow("On-Prem Synced:", output.StyleHighlight.Render(fmt.Sprintf("%d", onPremSynced)))
	output.TableRow("Cloud-Only:", output.StyleURLInfo.Render(fmt.Sprintf("%d", cloudOnly)))
	if guestCount > 0 {
		output.TableRow("Guest Users:", output.StyleUserInfo.Render(fmt.Sprintf("%d", guestCount)))
	}
	if externalCount > 0 {
		output.TableRow("External Users:", output.StyleUserInfo.Render(fmt.Sprintf("%d", externalCount)))
	}
	fmt.Println()

	// Department breakdown (top 10)
	if len(deptCounts) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Top Departments "))
		type deptEntry struct {
			name  string
			count int
		}
		var depts []deptEntry
		for name, count := range deptCounts {
			depts = append(depts, deptEntry{name, count})
		}
		// Sort by count descending (simple bubble sort, top 10)
		for i := 0; i < len(depts); i++ {
			for j := i + 1; j < len(depts); j++ {
				if depts[j].count > depts[i].count {
					depts[i], depts[j] = depts[j], depts[i]
				}
			}
		}
		limit := 10
		if len(depts) < limit {
			limit = len(depts)
		}
		for _, d := range depts[:limit] {
			pct := (d.count * 100) / result.TotalCount
			bar := ""
			if pct > 0 {
				bar = strings.Repeat("█", pct/5)
			}
			fmt.Printf("       %s %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-30s", d.name)),
				output.StyleCounter.Render(fmt.Sprintf("%4d", d.count)),
				output.StyleProgress.Render(bar))
		}
		if len(deptCounts) > 10 {
			output.Dim("... and %d more departments", len(deptCounts)-10)
		}
		fmt.Println()
	}

	output.SearchDivider()

	if disabledWithLicense > 0 {
		output.Warn("%d disabled account(s) still have license assignments — potential waste or ghost accounts", disabledWithLicense)
	}
	if guestCount > 0 {
		output.Warn("%d guest account(s) present — review external access permissions", guestCount)
	}
	if noLastPwdChange > 0 {
		output.Dim("%d accounts have no password change record", noLastPwdChange)
	}
	if !output.VerboseEnabled {
		output.Dim("Use -v to show per-user details (UPN, SAM, status)")
	}

	fmt.Println()
	output.Success("Users: %d total | %d enabled | %d disabled | %d on-prem synced | %d guests",
		result.TotalCount, enabled, disabled, onPremSynced, guestCount)
}
