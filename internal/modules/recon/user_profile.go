package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// UserProfile holds a user's roles and group memberships.
type UserProfile struct {
	UPN         string           `json:"upn"`
	DisplayName string           `json:"display_name"`
	ID          string           `json:"id"`
	Enabled     bool             `json:"account_enabled"`
	Roles       []UserRoleEntry  `json:"roles"`
	Groups      []UserGroupEntry `json:"groups"`
}

// UserRoleEntry is a role assigned to a user.
type UserRoleEntry struct {
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	IsBuiltIn bool   `json:"is_built_in"`
}

// UserGroupEntry is a group the user belongs to.
type UserGroupEntry struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	GroupType   string `json:"group_type"`
	Visibility  string `json:"visibility"`
}

// UserProfileResult holds results for one or many users.
type UserProfileResult struct {
	Profiles []UserProfile `json:"profiles"`
	Total    int           `json:"total"`
}

// UserProfileMe fetches roles + groups for the current user (the token owner).
// Uses /me + /me/transitiveMemberOf — 2 API calls, instant.
func UserProfileMe(ctx context.Context, client *graph.Client) (*UserProfileResult, error) {
	output.Info("Fetching current user identity...")

	// Get current user via /me
	meRaw, err := client.Get(ctx, graph.EndpointMe, map[string]string{
		"$select": "id,displayName,userPrincipalName,accountEnabled,jobTitle,department,companyName",
	})
	if err != nil {
		return nil, fmt.Errorf("get /me: %w", err)
	}
	var me struct {
		ID      string `json:"id"`
		Name    string `json:"displayName"`
		UPN     string `json:"userPrincipalName"`
		Enabled bool   `json:"accountEnabled"`
		Job     string `json:"jobTitle"`
		Dept    string `json:"department"`
		Company string `json:"companyName"`
	}
	if err := json.Unmarshal(meRaw, &me); err != nil {
		return nil, fmt.Errorf("parse /me: %w", err)
	}

	output.Info("Identity: %s (%s)", me.Name, me.UPN)

	// Get all memberships (groups + directory roles) in one call
	output.Info("Fetching roles and group memberships...")
	memberOfRaw, err := client.GetAll(ctx, "/me/transitiveMemberOf", map[string]string{
		"$top": "999",
	})
	if err != nil {
		return nil, fmt.Errorf("get /me/transitiveMemberOf: %w", err)
	}

	profile := UserProfile{
		UPN:         me.UPN,
		DisplayName: me.Name,
		ID:          me.ID,
		Enabled:     me.Enabled,
	}

	parseMemberOf(memberOfRaw, &profile)

	result := &UserProfileResult{
		Profiles: []UserProfile{profile},
		Total:    1,
	}

	printSingleProfile(profile, me.Job, me.Dept, me.Company)
	return result, nil
}

// UserProfileByUPN fetches a full profile for a specific user by UPN or Object ID.
// Like Get-ADUser -Properties * — shows all attributes, groups, roles, manager, direct reports.
func UserProfileByUPN(ctx context.Context, client *graph.Client, userID string) (*UserProfileResult, error) {
	output.Info("Fetching user: %s", userID)

	// 1. Get all user properties (reuse the full field list from users.go)
	userRaw, err := client.Get(ctx, fmt.Sprintf("/users/%s", userID), map[string]string{
		"$select": userSelectFields,
	})
	if err != nil {
		return nil, fmt.Errorf("get user %s: %w", userID, err)
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(userRaw, &userData); err != nil {
		return nil, fmt.Errorf("parse user: %w", err)
	}

	upn, _ := userData["userPrincipalName"].(string)
	displayName, _ := userData["displayName"].(string)
	id, _ := userData["id"].(string)
	enabled, _ := userData["accountEnabled"].(bool)
	jobTitle, _ := userData["jobTitle"].(string)
	dept, _ := userData["department"].(string)
	company, _ := userData["companyName"].(string)

	output.Info("Identity: %s (%s)", displayName, upn)

	// 2. Get manager
	output.Info("Fetching manager...")
	var managerName, managerUPN string
	managerRaw, err := client.Get(ctx, fmt.Sprintf("/users/%s/manager", userID), map[string]string{
		"$select": "displayName,userPrincipalName,jobTitle",
	})
	if err == nil {
		var mgr map[string]interface{}
		if json.Unmarshal(managerRaw, &mgr) == nil {
			managerName, _ = mgr["displayName"].(string)
			managerUPN, _ = mgr["userPrincipalName"].(string)
		}
	}

	// 3. Get direct reports
	output.Info("Fetching direct reports...")
	var directReports []directReport
	reportsRaw, err := client.GetAll(ctx, fmt.Sprintf("/users/%s/directReports", userID), map[string]string{
		"$select": "displayName,userPrincipalName",
		"$top":    "999",
	})
	if err == nil {
		for _, r := range reportsRaw {
			var dr directReport
			if json.Unmarshal(r, &dr) == nil && dr.Name != "" {
				directReports = append(directReports, dr)
			}
		}
	}

	// 4. Get all memberships (groups + directory roles)
	output.Info("Fetching roles and group memberships...")
	memberOfRaw, err := client.GetAll(ctx, fmt.Sprintf("/users/%s/transitiveMemberOf", userID), map[string]string{
		"$top": "999",
	})
	if err != nil {
		return nil, fmt.Errorf("get transitiveMemberOf: %w", err)
	}

	profile := UserProfile{
		UPN:         upn,
		DisplayName: displayName,
		ID:          id,
		Enabled:     enabled,
	}
	parseMemberOf(memberOfRaw, &profile)

	// 5. Get auth methods (if accessible)
	output.Info("Fetching authentication methods...")
	var authMethods []authMethod
	authRaw, err := client.GetAll(ctx, fmt.Sprintf("/users/%s/authentication/methods", userID), nil)
	if err == nil {
		for _, r := range authRaw {
			var am authMethod
			if json.Unmarshal(r, &am) == nil {
				authMethods = append(authMethods, am)
			}
		}
	}

	result := &UserProfileResult{
		Profiles: []UserProfile{profile},
		Total:    1,
	}

	// Pretty output — full Get-ADUser style
	printUserProfileFull(userData, profile, jobTitle, dept, company,
		managerName, managerUPN, directReports, authMethods)

	return result, nil
}

// directReport holds a direct report entry.
type directReport struct {
	Name string `json:"displayName"`
	UPN  string `json:"userPrincipalName"`
}

// authMethod holds an authentication method entry.
type authMethod struct {
	Type string `json:"@odata.type"`
	ID   string `json:"id"`
}

func printUserProfileFull(
	userData map[string]interface{},
	p UserProfile,
	job, dept, company, managerName, managerUPN string,
	directReports []directReport,
	authMethods []authMethod,
) {
	enabledTag := output.StyleSuccess.Render("[Enabled]")
	if !p.Enabled {
		enabledTag = output.StyleCritical.Render("[Disabled]")
	}

	output.SearchResultHeader("User Profile", len(p.Roles)+len(p.Groups),
		fmt.Sprintf("%d roles, %d groups", len(p.Roles), len(p.Groups)))

	// ── Identity ──
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Identity "))
	fmt.Printf("  %s %s  %s\n", output.StyleBold.Render(p.DisplayName),
		output.StyleDim.Render("("+p.UPN+")"), enabledTag)
	fmt.Printf("  %s %s\n", output.StyleDim.Render("Object ID:"), output.StyleDim.Render(p.ID))

	// Core identity fields
	printField("  ", "Mail", userData, "mail")
	printField("  ", "Mail Nickname", userData, "mailNickname")
	printField("  ", "User Type", userData, "userType")
	printField("  ", "Created", userData, "createdDateTime")

	if job != "" || dept != "" || company != "" {
		parts := []string{}
		if job != "" {
			parts = append(parts, job)
		}
		if dept != "" {
			parts = append(parts, dept)
		}
		if company != "" {
			parts = append(parts, company)
		}
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Position:"),
			output.StyleInfo.Render(strings.Join(parts, " · ")))
	}
	printField("  ", "Office", userData, "officeLocation")
	printField("  ", "Employee ID", userData, "employeeId")
	printField("  ", "Employee Type", userData, "employeeType")
	fmt.Println()

	// ── Manager & Reports ──
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Org Chart "))
	if managerName != "" {
		fmt.Printf("  %s %s %s\n", output.StyleDim.Render("Manager:"),
			output.StyleBold.Render(managerName),
			output.StyleDim.Render("("+managerUPN+")"))
	} else {
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Manager:"), output.StyleDim.Render("(none)"))
	}
	if len(directReports) > 0 {
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Direct Reports:"),
			output.StyleCounter.Render(fmt.Sprintf("%d", len(directReports))))
		for _, dr := range directReports {
			fmt.Printf("    %s %s %s\n", output.StyleDim.Render("·"),
				output.StyleBold.Render(dr.Name), output.StyleDim.Render("("+dr.UPN+")"))
		}
	} else {
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Direct Reports:"), output.StyleDim.Render("0"))
	}
	fmt.Println()

	// ── On-Premises (AD Sync) ──
	onPremSync, _ := userData["onPremisesSyncEnabled"].(bool)
	if onPremSync {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" On-Premises (AD Sync) "))
		printField("  ", "SAM Account", userData, "onPremisesSamAccountName")
		printField("  ", "Domain", userData, "onPremisesDomainName")
		printField("  ", "DN", userData, "onPremisesDistinguishedName")
		printField("  ", "SID", userData, "onPremisesSecurityIdentifier")
		printField("  ", "NetBIOS", userData, "onPremisesNetBiosName")
		printField("  ", "Immutable ID", userData, "onPremisesImmutableId")
		printField("  ", "Last Sync", userData, "onPremisesLastSyncDateTime")
		printField("  ", "On-Prem UPN", userData, "onPremisesUserPrincipalName")

		// Extension attributes
		if extAttrs, ok := userData["onPremisesExtensionAttributes"].(map[string]interface{}); ok {
			hasExt := false
			for k, v := range extAttrs {
				if v != nil {
					s, _ := v.(string)
					if s != "" {
						if !hasExt {
							fmt.Printf("  %s\n", output.StyleDim.Render("Extension Attrs:"))
							hasExt = true
						}
						fmt.Printf("    %s %s = %s\n", output.StyleDim.Render("·"),
							output.StyleDim.Render(k), output.StyleInfo.Render(s))
					}
				}
			}
		}
		fmt.Println()
	}

	// ── Contact ──
	hasContact := false
	for _, f := range []string{"streetAddress", "city", "state", "postalCode", "country", "mobilePhone", "businessPhones"} {
		if v, ok := userData[f]; ok && v != nil {
			if s, ok := v.(string); ok && s != "" {
				hasContact = true
				break
			}
			if a, ok := v.([]interface{}); ok && len(a) > 0 {
				hasContact = true
				break
			}
		}
	}
	if hasContact {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Contact "))
		printField("  ", "Street", userData, "streetAddress")
		printField("  ", "City", userData, "city")
		printField("  ", "State", userData, "state")
		printField("  ", "Postal Code", userData, "postalCode")
		printField("  ", "Country", userData, "country")
		printField("  ", "Mobile", userData, "mobilePhone")
		if phones, ok := userData["businessPhones"].([]interface{}); ok && len(phones) > 0 {
			for _, ph := range phones {
				s, _ := ph.(string)
				if s != "" {
					fmt.Printf("  %s %s\n", output.StyleDim.Render("Business Phone:"), output.StyleInfo.Render(s))
				}
			}
		}
		fmt.Println()
	}

	// ── Security ──
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Security "))
	printField("  ", "Password Policies", userData, "passwordPolicies")
	printField("  ", "Last Password Change", userData, "lastPasswordChangeDateTime")
	printField("  ", "Sign-in Valid From", userData, "signInSessionsValidFromDateTime")
	printField("  ", "Refresh Tokens From", userData, "refreshTokensValidFromDateTime")

	// Auth methods
	if len(authMethods) > 0 {
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Auth Methods:"),
			output.StyleCounter.Render(fmt.Sprintf("%d", len(authMethods))))
		for _, am := range authMethods {
			typeName := am.Type
			typeName = strings.TrimPrefix(typeName, "#microsoft.graph.")
			typeName = strings.TrimSuffix(typeName, "AuthenticationMethod")
			fmt.Printf("    %s %s\n", output.StyleDim.Render("·"), output.StyleInfo.Render(typeName))
		}
	}
	fmt.Println()

	// ── Directory Roles ──
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Directory Roles (%d) ", len(p.Roles))))
	if len(p.Roles) > 0 {
		for i, r := range p.Roles {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(r.RoleName)
			tag := ""
			if r.RoleID == GlobalAdminRoleID {
				tag = " " + output.StyleCritical.Render("[GLOBAL ADMIN]")
			} else if isPrivilegedRole(r.RoleName) {
				tag = " " + output.StyleHigh.Render("[PRIVILEGED]")
			}
			fmt.Printf("  %s %s%s\n", num, nameStyled, tag)
		}
	} else {
		fmt.Printf("  %s\n", output.StyleDim.Render("  (none)"))
	}
	fmt.Println()

	// ── Group Memberships ──
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Group Memberships (%d) ", len(p.Groups))))
	if len(p.Groups) > 0 {
		typeOrder := []string{"security", "dynamic", "m365", "mail-security", "distribution", "other"}
		for _, t := range typeOrder {
			var matching []UserGroupEntry
			for _, g := range p.Groups {
				if g.GroupType == t {
					matching = append(matching, g)
				}
			}
			if len(matching) == 0 {
				continue
			}
			typeLabel := strings.ToUpper(t)
			typeStyled := output.StyleDim.Render("[" + typeLabel + "]")
			switch t {
			case "security":
				typeStyled = output.StyleInfo.Render("[SECURITY]")
			case "dynamic":
				typeStyled = output.StyleHighlight.Render("[DYNAMIC]")
			case "m365":
				typeStyled = output.StyleURLInfo.Render("[M365]")
			}
			fmt.Printf("    %s %s\n", typeStyled,
				output.StyleCounter.Render(fmt.Sprintf("(%d)", len(matching))))
			for _, g := range matching {
				visTag := ""
				if g.Visibility == "Public" {
					visTag = " " + output.StyleMedium.Render("[Public]")
				}
				fmt.Printf("       %s %s%s\n", output.StyleDim.Render("·"),
					output.StyleBold.Render(g.DisplayName), visTag)
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("  %s\n\n", output.StyleDim.Render("  (none)"))
	}

	output.SearchDivider()
	fmt.Println()
	output.Success("Profile: %s | %d roles | %d groups | manager: %s | reports: %d",
		p.UPN, len(p.Roles), len(p.Groups), managerName, len(directReports))
}

// printField prints a labeled field from userData if it has a non-empty string value.
func printField(indent, label string, data map[string]interface{}, key string) {
	v, ok := data[key]
	if !ok || v == nil {
		return
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return
	}
	fmt.Printf("%s%s %s\n", indent, output.StyleDim.Render(label+":"),
		output.StyleInfo.Render(s))
}

// UserProfileAll fetches roles + groups for all users with role assignments.
// Strategy: bulk fetch roles, then only fetch memberOf for users that HAVE roles.
// Much faster than enumerating all 20K+ groups.
func UserProfileAll(ctx context.Context, client *graph.Client) (*UserProfileResult, error) {
	// 1. Fetch role definitions
	output.Info("Fetching role definitions...")
	defRaw, err := client.GetAll(ctx, graph.EndpointRoleDefinitions, map[string]string{
		"$select": "id,displayName,isBuiltIn",
	})
	if err != nil {
		return nil, fmt.Errorf("role definitions: %w", err)
	}
	roleNameMap := map[string]string{}
	roleBuiltIn := map[string]bool{}
	for _, r := range defRaw {
		var d map[string]interface{}
		if json.Unmarshal(r, &d) == nil {
			id, _ := d["id"].(string)
			name, _ := d["displayName"].(string)
			builtIn, _ := d["isBuiltIn"].(bool)
			roleNameMap[id] = name
			roleBuiltIn[id] = builtIn
		}
	}

	// 2. Fetch role assignments
	output.Info("Fetching role assignments...")
	assignRaw, err := client.GetAll(ctx, graph.EndpointRoleAssignments, map[string]string{
		"$expand": "principal",
		"$select": "id,roleDefinitionId,principalId,principal",
		"$top":    "999",
	})
	if err != nil {
		return nil, fmt.Errorf("role assignments: %w", err)
	}

	// Build: principalId -> user info + roles
	type userEntry struct {
		ID      string
		Name    string
		UPN     string
		Enabled bool
		Roles   []UserRoleEntry
		Groups  []UserGroupEntry
	}
	userMap := map[string]*userEntry{}

	for _, r := range assignRaw {
		var a map[string]interface{}
		if json.Unmarshal(r, &a) != nil {
			continue
		}
		pid, _ := a["principalId"].(string)
		rid, _ := a["roleDefinitionId"].(string)
		if pid == "" || rid == "" {
			continue
		}

		ue, exists := userMap[pid]
		if !exists {
			// Extract principal info
			principal, _ := a["principal"].(map[string]interface{})
			name := ""
			upn := ""
			enabled := true
			if principal != nil {
				name, _ = principal["displayName"].(string)
				upn, _ = principal["userPrincipalName"].(string)
				if e, ok := principal["accountEnabled"].(bool); ok {
					enabled = e
				}
			}
			ue = &userEntry{ID: pid, Name: name, UPN: upn, Enabled: enabled}
			userMap[pid] = ue
		}

		ue.Roles = append(ue.Roles, UserRoleEntry{
			RoleID:    rid,
			RoleName:  roleNameMap[rid],
			IsBuiltIn: roleBuiltIn[rid],
		})
	}

	output.Success("Found %d users/principals with role assignments", len(userMap))

	// 3. For each user with roles, fetch their group memberships
	// This is only N API calls where N = users with roles (typically <100, not 38K)
	output.Info("Fetching group memberships for %d privileged users...", len(userMap))
	idx := 0
	for pid, ue := range userMap {
		idx++
		fmt.Fprintf(output.Stderr(), "\r  %s memberOf: %d/%d — %s",
			output.StyleInfo.Render("[*]"), idx, len(userMap), ue.UPN)

		memberOfRaw, err := client.GetAll(ctx, fmt.Sprintf("/users/%s/transitiveMemberOf", pid), map[string]string{
			"$top": "999",
		})
		if err != nil {
			// Could be a service principal, not a user — skip groups
			output.Verbose("  memberOf failed for %s: %v", pid, err)
			continue
		}

		// We only need groups, roles already fetched from bulk
		for _, raw := range memberOfRaw {
			var obj map[string]interface{}
			if json.Unmarshal(raw, &obj) != nil {
				continue
			}
			odataType, _ := obj["@odata.type"].(string)
			if odataType == "#microsoft.graph.group" {
				name, _ := obj["displayName"].(string)
				id, _ := obj["id"].(string)
				vis, _ := obj["visibility"].(string)
				gType := classifyGroupType(obj)
				ue.Groups = append(ue.Groups, UserGroupEntry{
					ID:          id,
					DisplayName: name,
					GroupType:   gType,
					Visibility:  vis,
				})
			}
		}
	}
	fmt.Fprintf(output.Stderr(), "\r%s\r", strings.Repeat(" ", 80))

	// 4. Build result
	result := &UserProfileResult{Total: len(userMap)}
	for _, ue := range userMap {
		result.Profiles = append(result.Profiles, UserProfile{
			UPN:         ue.UPN,
			DisplayName: ue.Name,
			ID:          ue.ID,
			Enabled:     ue.Enabled,
			Roles:       ue.Roles,
			Groups:      ue.Groups,
		})
	}

	printAllProfiles(result)
	return result, nil
}

// parseMemberOf extracts roles and groups from transitiveMemberOf response.
func parseMemberOf(raw []json.RawMessage, profile *UserProfile) {
	for _, r := range raw {
		var obj map[string]interface{}
		if json.Unmarshal(r, &obj) != nil {
			continue
		}

		odataType, _ := obj["@odata.type"].(string)

		if odataType == "#microsoft.graph.directoryRole" {
			name, _ := obj["displayName"].(string)
			roleTemplateID, _ := obj["roleTemplateId"].(string)
			profile.Roles = append(profile.Roles, UserRoleEntry{
				RoleID:   roleTemplateID,
				RoleName: name,
			})
		} else if odataType == "#microsoft.graph.group" {
			name, _ := obj["displayName"].(string)
			id, _ := obj["id"].(string)
			vis, _ := obj["visibility"].(string)
			gType := classifyGroupType(obj)
			profile.Groups = append(profile.Groups, UserGroupEntry{
				ID:          id,
				DisplayName: name,
				GroupType:   gType,
				Visibility:  vis,
			})
		}
	}
}

func classifyGroupType(g map[string]interface{}) string {
	sec, _ := g["securityEnabled"].(bool)
	mail, _ := g["mailEnabled"].(bool)
	groupTypes, _ := g["groupTypes"].([]interface{})

	isDynamic := false
	isUnified := false
	for _, gt := range groupTypes {
		s, _ := gt.(string)
		if s == "DynamicMembership" {
			isDynamic = true
		}
		if s == "Unified" {
			isUnified = true
		}
	}

	switch {
	case isDynamic:
		return "dynamic"
	case isUnified:
		return "m365"
	case sec && !mail:
		return "security"
	case !sec && mail:
		return "distribution"
	case sec && mail:
		return "mail-security"
	default:
		return "other"
	}
}

// ── Pretty output ──

func printSingleProfile(p UserProfile, job, dept, company string) {
	enabledTag := output.StyleSuccess.Render("[Enabled]")
	if !p.Enabled {
		enabledTag = output.StyleCritical.Render("[Disabled]")
	}

	output.SearchResultHeader("whoami — Full Profile", len(p.Roles)+len(p.Groups),
		fmt.Sprintf("%d roles, %d groups", len(p.Roles), len(p.Groups)))

	// Identity
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Identity "))
	fmt.Printf("  %s %s  %s\n", output.StyleBold.Render(p.DisplayName),
		output.StyleDim.Render("("+p.UPN+")"), enabledTag)
	fmt.Printf("  %s %s\n", output.StyleDim.Render("Object ID:"), output.StyleDim.Render(p.ID))
	if job != "" || dept != "" || company != "" {
		extra := ""
		if job != "" {
			extra += job
		}
		if dept != "" {
			if extra != "" {
				extra += " · "
			}
			extra += dept
		}
		if company != "" {
			if extra != "" {
				extra += " · "
			}
			extra += company
		}
		fmt.Printf("  %s %s\n", output.StyleDim.Render("Position:"), output.StyleDim.Render(extra))
	}
	fmt.Println()

	// Roles
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Directory Roles (%d) ", len(p.Roles))))
	if len(p.Roles) > 0 {
		for i, r := range p.Roles {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(r.RoleName)
			tag := ""
			if r.RoleID == GlobalAdminRoleID {
				tag = " " + output.StyleCritical.Render("[GLOBAL ADMIN]")
			} else if isPrivilegedRole(r.RoleName) {
				tag = " " + output.StyleHigh.Render("[PRIVILEGED]")
			}
			fmt.Printf("  %s %s%s\n", num, nameStyled, tag)
		}
	} else {
		fmt.Printf("  %s\n", output.StyleDim.Render("  (none)"))
	}
	fmt.Println()

	// Groups by type
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Group Memberships (%d) ", len(p.Groups))))
	if len(p.Groups) > 0 {
		// Sort by type
		typeOrder := []string{"security", "dynamic", "m365", "mail-security", "distribution", "other"}
		for _, t := range typeOrder {
			var matching []UserGroupEntry
			for _, g := range p.Groups {
				if g.GroupType == t {
					matching = append(matching, g)
				}
			}
			if len(matching) == 0 {
				continue
			}
			typeLabel := strings.ToUpper(t)
			typeStyled := output.StyleDim.Render("[" + typeLabel + "]")
			switch t {
			case "security":
				typeStyled = output.StyleInfo.Render("[SECURITY]")
			case "dynamic":
				typeStyled = output.StyleHighlight.Render("[DYNAMIC]")
			case "m365":
				typeStyled = output.StyleURLInfo.Render("[M365]")
			}

			fmt.Printf("    %s %s\n", typeStyled,
				output.StyleCounter.Render(fmt.Sprintf("(%d)", len(matching))))
			for _, g := range matching {
				visTag := ""
				if g.Visibility == "Public" {
					visTag = " " + output.StyleMedium.Render("[Public]")
				}
				fmt.Printf("       %s %s%s\n",
					output.StyleDim.Render("·"),
					output.StyleBold.Render(g.DisplayName), visTag)
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("  %s\n\n", output.StyleDim.Render("  (none)"))
	}

	output.SearchDivider()

	// Risk assessment
	isGA := false
	isPriv := false
	for _, r := range p.Roles {
		if r.RoleID == GlobalAdminRoleID {
			isGA = true
		}
		if isPrivilegedRole(r.RoleName) {
			isPriv = true
		}
	}
	if isGA {
		output.Critical("You are a GLOBAL ADMIN — full tenant control")
	} else if isPriv {
		output.Warn("You have privileged role(s) — elevated access")
	} else if len(p.Roles) > 0 {
		output.Info("You have %d directory role(s)", len(p.Roles))
	} else {
		output.Dim("No directory roles — standard user")
	}

	secGroups := 0
	pubGroups := 0
	for _, g := range p.Groups {
		if g.GroupType == "security" {
			secGroups++
		}
		if g.Visibility == "Public" {
			pubGroups++
		}
	}
	if secGroups > 0 {
		output.Info("%d security group(s)", secGroups)
	}
	if pubGroups > 0 {
		output.Dim("%d public group(s)", pubGroups)
	}

	fmt.Println()
	output.Success("Profile: %s | %d roles | %d groups", p.UPN, len(p.Roles), len(p.Groups))
}

func printAllProfiles(result *UserProfileResult) {
	usersWithRoles := 0
	totalRoleAssignments := 0
	globalAdmins := 0
	privilegedUsers := 0

	for _, p := range result.Profiles {
		if len(p.Roles) > 0 {
			usersWithRoles++
			totalRoleAssignments += len(p.Roles)
		}
		for _, r := range p.Roles {
			if r.RoleID == GlobalAdminRoleID {
				globalAdmins++
			}
		}
		isPriv := false
		for _, r := range p.Roles {
			if isPrivilegedRole(r.RoleName) {
				isPriv = true
				break
			}
		}
		if isPriv {
			privilegedUsers++
		}
	}

	output.SearchResultHeader("All Privileged Users", result.Total,
		fmt.Sprintf("%d with roles, %d Global Admins", usersWithRoles, globalAdmins))

	// Overview
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	output.TableRow("Principals with roles:", fmt.Sprintf("%d", result.Total))
	output.TableRow("Total role assignments:", fmt.Sprintf("%d", totalRoleAssignments))
	if globalAdmins > 0 {
		fmt.Printf("  %-30s %s\n", output.StyleBold.Render("Global Admins:"),
			output.StyleCritical.Render(fmt.Sprintf("%d", globalAdmins)))
	}
	if privilegedUsers > 0 {
		fmt.Printf("  %-30s %s\n", output.StyleBold.Render("Privileged users:"),
			output.StyleHigh.Render(fmt.Sprintf("%d", privilegedUsers)))
	}
	fmt.Println()

	// List each user
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Privileged Users (%d) ", result.Total)))

	for i, p := range result.Profiles {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(p.DisplayName)
		upnStyled := output.StyleDim.Render(p.UPN)

		enabledTag := ""
		if !p.Enabled {
			enabledTag = " " + output.StyleCritical.Render("[Disabled]")
		}

		// Role tags inline
		roleTags := ""
		for _, r := range p.Roles {
			if r.RoleID == GlobalAdminRoleID {
				roleTags += " " + output.StyleCritical.Render("[GA]")
			} else if isPrivilegedRole(r.RoleName) {
				roleTags += " " + output.StyleHigh.Render("[" + shortRoleName(r.RoleName) + "]")
			} else {
				roleTags += " " + output.StyleInfo.Render("[" + shortRoleName(r.RoleName) + "]")
			}
		}

		fmt.Printf("  %s %s  %s%s%s\n", num, nameStyled, upnStyled, enabledTag, roleTags)

		// Groups summary line
		if len(p.Groups) > 0 {
			secCount := 0
			for _, g := range p.Groups {
				if g.GroupType == "security" {
					secCount++
				}
			}
			summary := fmt.Sprintf("%d groups", len(p.Groups))
			if secCount > 0 {
				summary += fmt.Sprintf(" (%d security)", secCount)
			}
			fmt.Printf("       %s %s\n", output.StyleDim.Render("└"),
				output.StyleDim.Render(summary))
		}

		// Verbose: all roles and groups
		if output.VerboseEnabled {
			for _, r := range p.Roles {
				tag := output.StyleInfo.Render("[Role]")
				if r.RoleID == GlobalAdminRoleID {
					tag = output.StyleCritical.Render("[Role]")
				} else if isPrivilegedRole(r.RoleName) {
					tag = output.StyleHigh.Render("[Role]")
				}
				fmt.Printf("       %s %s\n", tag, output.StyleBold.Render(r.RoleName))
			}
			for _, g := range p.Groups {
				typeTag := output.StyleDim.Render("[" + g.GroupType + "]")
				visTag := ""
				if g.Visibility == "Public" {
					visTag = " " + output.StyleMedium.Render("[Public]")
				}
				fmt.Printf("       %s %s %s%s\n",
					output.StyleURLInfo.Render("[Grp]"),
					g.DisplayName, typeTag, visTag)
			}
			fmt.Println()
		}
	}
	fmt.Println()

	if !output.VerboseEnabled {
		output.Dim("Use -v to show all roles and groups per user")
	}

	output.SearchDivider()

	if globalAdmins > 0 {
		output.Critical("%d Global Admin(s) — review for least privilege", globalAdmins)
	}
	if privilegedUsers > 0 {
		output.Warn("%d users with privileged roles", privilegedUsers)
	}

	fmt.Println()
	output.Success("Profiles: %d principals | %d role assignments | %d Global Admins",
		result.Total, totalRoleAssignments, globalAdmins)
}

// ── Helpers ──

func isPrivilegedRole(name string) bool {
	priv := []string{
		"Global Administrator", "Privileged Role Administrator",
		"Privileged Authentication Administrator", "Exchange Administrator",
		"SharePoint Administrator", "Application Administrator",
		"Cloud Application Administrator", "Intune Administrator",
		"User Administrator", "Authentication Administrator",
		"Security Administrator", "Conditional Access Administrator",
		"Hybrid Identity Administrator", "Password Administrator",
		"Helpdesk Administrator", "Groups Administrator",
	}
	for _, p := range priv {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

func shortRoleName(name string) string {
	replacer := strings.NewReplacer(
		" Administrator", " Admin",
		"Privileged ", "Priv. ",
		"Authentication ", "Auth ",
		"Application ", "App ",
		"Conditional Access ", "CA ",
	)
	short := replacer.Replace(name)
	if len(short) > 25 {
		short = short[:22] + "..."
	}
	return short
}
