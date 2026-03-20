package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// GroupsResult holds group enumeration data.
type GroupsResult struct {
	SecurityGroups []map[string]interface{} `json:"security_groups"`
	DynamicGroups  []DynamicGroup           `json:"dynamic_groups"`
	PublicGroups   []string                 `json:"public_groups,omitempty"`
	TotalCount     int                      `json:"total_count"`
}

// DynamicGroup is a group with a dynamic membership rule.
type DynamicGroup struct {
	ID             string `json:"id"`
	DisplayName    string `json:"display_name"`
	MembershipRule string `json:"membership_rule"`
}

// Groups enumerates security groups, dynamic groups, and public groups.
func Groups(ctx context.Context, client *graph.Client) (interface{}, error) {
	output.Info("Fetching all groups...")

	params := map[string]string{
		"$select": "id,displayName,groupTypes,visibility,mailEnabled,securityEnabled,createdDateTime,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState",
		"$top":    "999",
	}

	raw, err := client.GetAllWithProgress(ctx, graph.EndpointGroups, params, "Groups")
	if err != nil {
		return nil, err
	}

	output.Info("Classifying %d groups...", len(raw))
	result := &GroupsResult{TotalCount: len(raw)}

	// Single-pass classification: unmarshal + classify in one loop
	for _, r := range raw {
		var g map[string]interface{}
		if err := json.Unmarshal(r, &g); err != nil {
			continue
		}

		// Security groups
		sec, _ := g["securityEnabled"].(bool)
		if sec {
			result.SecurityGroups = append(result.SecurityGroups, g)
		}

		// Public groups
		visibility, _ := g["visibility"].(string)
		if visibility == "Public" {
			name, _ := g["displayName"].(string)
			result.PublicGroups = append(result.PublicGroups, name)
		}

		// Dynamic groups
		groupTypes, _ := g["groupTypes"].([]interface{})
		for _, gt := range groupTypes {
			if s, ok := gt.(string); ok && s == "DynamicMembership" {
				rule, _ := g["membershipRule"].(string)
				name, _ := g["displayName"].(string)
				id, _ := g["id"].(string)
				result.DynamicGroups = append(result.DynamicGroups, DynamicGroup{
					ID:             id,
					DisplayName:    name,
					MembershipRule: rule,
				})
				break
			}
		}
	}

	output.Success("Enumerated %d groups (%d security, %d dynamic, %d public)",
		result.TotalCount, len(result.SecurityGroups), len(result.DynamicGroups), len(result.PublicGroups))

	// Enumerate members only in verbose mode (avoids 1 API call per group)
	if output.VerboseEnabled {
		output.Info("Fetching members for %d security groups (-v enabled)...", len(result.SecurityGroups))
		for i, g := range result.SecurityGroups {
			id, ok := g["id"].(string)
			if !ok {
				continue
			}
			name, _ := g["displayName"].(string)
			endpoint := fmt.Sprintf(graph.EndpointGroupMembers, id)
			membersRaw, err := client.GetAll(ctx, endpoint, map[string]string{"$select": "id,displayName,userPrincipalName", "$top": "100"})
			if err == nil {
				members := unmarshalAll(membersRaw)
				result.SecurityGroups[i]["_members"] = members
				result.SecurityGroups[i]["_member_count"] = len(members)
				output.Verbose("  [%d/%d] %s — %d members", i+1, len(result.SecurityGroups), name, len(members))
			}
		}
	}

	printGroupsResults(result)

	return result, nil
}

func printGroupsResults(result *GroupsResult) {
	subtitle := fmt.Sprintf("%d security, %d dynamic, %d public",
		len(result.SecurityGroups), len(result.DynamicGroups), len(result.PublicGroups))
	output.SearchResultHeader("Group Enumeration", result.TotalCount, subtitle)

	if result.TotalCount == 0 {
		output.Warn("No groups found")
		return
	}

	// Security groups
	if len(result.SecurityGroups) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Security Groups (%d) ", len(result.SecurityGroups))))
		for i, g := range result.SecurityGroups {
			name, _ := g["displayName"].(string)
			visibility, _ := g["visibility"].(string)
			sync, _ := g["onPremisesSyncEnabled"].(bool)
			memberCount, _ := g["_member_count"].(int)

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(name)

			tags := ""
			if sync {
				tags += " " + output.StyleHighlight.Render("[OnPrem]")
			}
			if visibility != "" && visibility != "Private" {
				tags += " " + output.StyleMedium.Render("["+visibility+"]")
			}
			memberTag := output.StyleDim.Render(fmt.Sprintf("%d members", memberCount))
			fmt.Printf("  %s %s  %s%s\n", num, nameStyled, memberTag, tags)

			if output.VerboseEnabled {
				members, _ := g["_members"].([]map[string]interface{})
				for _, m := range members {
					upn, _ := m["userPrincipalName"].(string)
					mName, _ := m["displayName"].(string)
					if upn != "" {
						fmt.Printf("       %s %s\n",
							output.StyleDim.Render("└"),
							output.StyleURLInfo.Render(upn)+" "+output.StyleDim.Render("("+mName+")"))
					}
				}
			}
		}
		fmt.Println()
	}

	// Dynamic groups
	if len(result.DynamicGroups) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Dynamic Groups (%d) — membership rules ", len(result.DynamicGroups))))
		for i, dg := range result.DynamicGroups {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(dg.DisplayName)
			fmt.Printf("  %s %s\n", num, nameStyled)
			if dg.MembershipRule != "" {
				rule := dg.MembershipRule
				if len(rule) > 100 {
					rule = rule[:97] + "..."
				}
				fmt.Printf("       %s %s\n",
					output.StyleHighlight.Render("Rule:"),
					output.StyleTableRow.Render(rule))
			}
			fmt.Printf("       %s %s\n",
				output.StyleDim.Render("ID:"),
				output.StyleDim.Render(dg.ID))
		}
		fmt.Println()
	}

	// Public groups
	if len(result.PublicGroups) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Public Groups (%d) — joinable by anyone ", len(result.PublicGroups))))
		for _, name := range result.PublicGroups {
			fmt.Printf("       %s %s\n",
				output.StyleMedium.Render("»"),
				output.StyleBold.Render(name))
		}
		fmt.Println()
	}

	output.SearchDivider()

	if len(result.PublicGroups) > 0 {
		output.Warn("%d public groups are joinable by any tenant member", len(result.PublicGroups))
	}
	if len(result.DynamicGroups) > 0 {
		output.Warn("%d dynamic groups have membership rules — review for abuse potential", len(result.DynamicGroups))
	}
	if !output.VerboseEnabled && len(result.SecurityGroups) > 0 {
		output.Dim("Use -v to show group members")
	}

	fmt.Println()
	output.Success("Groups: %d total | %d security | %d dynamic | %d public",
		result.TotalCount, len(result.SecurityGroups), len(result.DynamicGroups), len(result.PublicGroups))

}
