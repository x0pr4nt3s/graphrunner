package recon

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// RolesResult holds role assignment enumeration data.
type RolesResult struct {
	Assignments    []map[string]interface{} `json:"assignments"`
	Definitions    []map[string]interface{} `json:"definitions"`
	TotalAssigned  int                      `json:"total_assigned"`
	GlobalAdmins   int                      `json:"global_admins"`
}

// GlobalAdminRoleID is the well-known template ID.
const GlobalAdminRoleID = "62e90394-69f5-4237-9190-012177145e10"

// Roles enumerates privileged role assignments.
func Roles(ctx context.Context, client *graph.Client) (interface{}, error) {
	result := &RolesResult{}

	// Role definitions
	defRaw, err := client.GetAll(ctx, graph.EndpointRoleDefinitions, map[string]string{
		"$select": "id,displayName,isBuiltIn",
	})
	if err != nil {
		output.Warn("Role definitions: %v", err)
	} else {
		result.Definitions = unmarshalAll(defRaw)
	}

	// Role assignments
	assignRaw, err := client.GetAll(ctx, graph.EndpointRoleAssignments, map[string]string{
		"$expand": "principal",
		"$select": "id,roleDefinitionId,principalId,principal",
	})
	if err != nil {
		return nil, err
	}

	result.Assignments = unmarshalAll(assignRaw)
	result.TotalAssigned = len(result.Assignments)

	// Build role definition name map for verbose output
	roleNames := make(map[string]string)
	for _, d := range result.Definitions {
		id, _ := d["id"].(string)
		name, _ := d["displayName"].(string)
		roleNames[id] = name
	}

	// Count Global Admins and print verbose
	for _, a := range result.Assignments {
		roleID, _ := a["roleDefinitionId"].(string)
		if roleID == GlobalAdminRoleID {
			result.GlobalAdmins++
		}
		roleName := roleNames[roleID]
		if roleName == "" {
			roleName = roleID
		}
		principal, _ := a["principal"].(map[string]interface{})
		principalName := ""
		if principal != nil {
			principalName, _ = principal["userPrincipalName"].(string)
			if principalName == "" {
				principalName, _ = principal["displayName"].(string)
			}
		}
		output.Verbose("%-45s → %s", principalName, roleName)
	}

	printRolesResults(result, roleNames)

	return result, nil
}

func printRolesResults(result *RolesResult, roleNames map[string]string) {
	subtitle := fmt.Sprintf("%d Global Admins", result.GlobalAdmins)
	output.SearchResultHeader("Role Assignments", result.TotalAssigned, subtitle)

	if result.TotalAssigned == 0 {
		output.Warn("No role assignments found")
		return
	}

	// Collect global admins
	var globalAdmins []string
	// Group by role: roleID -> list of principal names
	roleMembers := make(map[string][]string)

	for _, a := range result.Assignments {
		roleID, _ := a["roleDefinitionId"].(string)
		principal, _ := a["principal"].(map[string]interface{})
		principalName := ""
		if principal != nil {
			principalName, _ = principal["userPrincipalName"].(string)
			if principalName == "" {
				principalName, _ = principal["displayName"].(string)
			}
		}
		if principalName == "" {
			principalName = "(unknown)"
		}

		if roleID == GlobalAdminRoleID {
			globalAdmins = append(globalAdmins, principalName)
		} else {
			roleMembers[roleID] = append(roleMembers[roleID], principalName)
		}
	}

	// Global Admins section — critical finding
	if len(globalAdmins) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Global Admins (%d) — CRITICAL ", len(globalAdmins))))
		for i, name := range globalAdmins {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			fmt.Printf("  %s %s %s\n", num,
				output.StyleCritical.Render("»"),
				output.StyleCritical.Render(name))
		}
		fmt.Println()
	}

	// Other privileged roles grouped by role name
	if len(roleMembers) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Other Role Assignments (%d roles) ", len(roleMembers))))

		// Collect and sort role IDs for stable output
		roleIDs := make([]string, 0, len(roleMembers))
		for id := range roleMembers {
			roleIDs = append(roleIDs, id)
		}
		// Sort by role name for readability
		for i := 0; i < len(roleIDs); i++ {
			for j := i + 1; j < len(roleIDs); j++ {
				ni := roleNames[roleIDs[i]]
				nj := roleNames[roleIDs[j]]
				if ni > nj {
					roleIDs[i], roleIDs[j] = roleIDs[j], roleIDs[i]
				}
			}
		}

		for _, roleID := range roleIDs {
			members := roleMembers[roleID]
			roleName := roleNames[roleID]
			if roleName == "" {
				roleName = roleID
			}
			roleHeader := output.StyleBold.Render(roleName)
			memberCount := output.StyleCounter.Render(fmt.Sprintf("(%d)", len(members)))
			fmt.Printf("  %s %s\n", roleHeader, memberCount)
			for _, m := range members {
				fmt.Printf("       %s %s\n",
					output.StyleDim.Render("└"),
					output.StyleUserInfo.Render(m))
			}
			fmt.Println()
		}
	}

	output.SearchDivider()

	if result.GlobalAdmins > 0 {
		output.Critical("%d Global Admin(s) found — review each for necessity", result.GlobalAdmins)
	}

	total := result.TotalAssigned
	fmt.Println()
	output.Success("Role assignments: %d total | %d Global Admins | %d other roles",
		total, result.GlobalAdmins, len(roleMembers))

}
