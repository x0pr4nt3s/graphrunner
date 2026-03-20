package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// TenantInfo holds tenant recon data.
type TenantInfo struct {
	Organization interface{} `json:"organization"`
	AuthPolicy   interface{} `json:"authorization_policy,omitempty"`
	SKUs         interface{} `json:"subscribed_skus,omitempty"`
}

// Tenant enumerates tenant configuration and org info.
func Tenant(ctx context.Context, client *graph.Client) (interface{}, error) {
	info := &TenantInfo{}

	// Organization info
	orgRaw, err := client.GetAll(ctx, graph.EndpointOrganization, nil)
	if err != nil {
		output.Error("Organization: %v", err)
	} else {
		info.Organization = unmarshalAll(orgRaw)
	}

	// Authorization policy
	authRaw, err := client.Get(ctx, graph.EndpointAuthPolicy, nil)
	if err != nil {
		output.Warn("Authorization policy: %v", err)
	} else {
		var policy interface{}
		json.Unmarshal(authRaw, &policy)
		info.AuthPolicy = policy
	}

	// Subscribed SKUs (licenses)
	skuRaw, err := client.GetAll(ctx, graph.EndpointSubscribedSkus, nil)
	if err != nil {
		output.Warn("Subscribed SKUs: %v", err)
	} else {
		info.SKUs = unmarshalAll(skuRaw)
	}

	printTenantResults(info)

	return info, nil
}

func printTenantResults(info *TenantInfo) {
	output.SearchResultHeader("Tenant Configuration", 1, "organization, auth policy, SKUs")

	// Parse organization
	orgs, ok := info.Organization.([]map[string]interface{})
	if ok && len(orgs) > 0 {
		org := orgs[0]
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Organization "))

		if v, _ := org["displayName"].(string); v != "" {
			output.TableRow("Display Name:", output.StyleBold.Render(v))
		}
		if v, _ := org["id"].(string); v != "" {
			output.TableRow("Tenant ID:", output.StyleURLInfo.Render(v))
		}

		// Verified domains
		if domains, ok := org["verifiedDomains"].([]interface{}); ok && len(domains) > 0 {
			fmt.Printf("\n  %-30s\n", output.StyleBold.Render("Verified Domains:"))
			for _, d := range domains {
				dm, _ := d.(map[string]interface{})
				name, _ := dm["name"].(string)
				isDefault, _ := dm["isDefault"].(bool)
				isInitial, _ := dm["isInitial"].(bool)
				tag := ""
				if isDefault {
					tag = " " + output.StyleSuccess.Render("[default]")
				}
				if isInitial {
					tag += " " + output.StyleDim.Render("[initial]")
				}
				fmt.Printf("    %s%s\n", output.StyleURLInfo.Render(name), tag)
			}
		}

		// Technical notification mails
		if mails, ok := org["technicalNotificationMails"].([]interface{}); ok && len(mails) > 0 {
			fmt.Printf("\n  %-30s\n", output.StyleBold.Render("Technical Notification:"))
			for _, m := range mails {
				if ms, ok := m.(string); ok {
					fmt.Printf("    %s\n", output.StyleUserInfo.Render(ms))
				}
			}
		}

		fmt.Println()
	}

	// Parse auth policy
	if info.AuthPolicy != nil {
		authMap, _ := info.AuthPolicy.(map[string]interface{})
		if authMap != nil {
			fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Authorization Policy "))

			overpermissive := false

			allowEmailVerified, _ := authMap["allowEmailVerifiedUsersToJoinOrganization"].(bool)
			if allowEmailVerified {
				output.TableRow("Email-verified join:", output.StyleCritical.Render("ALLOWED — overpermissive"))
				overpermissive = true
			} else {
				output.TableRow("Email-verified join:", output.StyleSuccess.Render("Disabled"))
			}

			if allowInvites, ok := authMap["allowInvitesFrom"].(string); ok {
				tag := output.StyleSuccess.Render(allowInvites)
				if allowInvites == "everyone" || allowInvites == "adminsAndGuestInviters" {
					tag = output.StyleHighlight.Render(allowInvites)
				}
				output.TableRow("Allow invites from:", tag)
			}

			if defaultPerms, ok := authMap["defaultUserRolePermissions"].(map[string]interface{}); ok {
				if canCreate, _ := defaultPerms["allowedToCreateApps"].(bool); canCreate {
					output.TableRow("Users create apps:", output.StyleHighlight.Render("Allowed"))
					overpermissive = true
				}
				if canCreateTenant, _ := defaultPerms["allowedToCreateTenants"].(bool); canCreateTenant {
					output.TableRow("Users create tenants:", output.StyleHighlight.Render("Allowed"))
				}
				if canReadOthers, _ := defaultPerms["allowedToReadOtherUsers"].(bool); !canReadOthers {
					output.TableRow("Read other users:", output.StyleHighlight.Render("Restricted"))
				}
			}

			if guestRole, ok := authMap["guestUserRoleId"].(string); ok {
				roleLabel := guestRole
				switch guestRole {
				case "10dae51f-b6af-4016-8d66-8c2a99b929b3":
					roleLabel = "Guest (limited)"
				case "2af84b1e-32c8-42b7-82bc-daa82404023b":
					roleLabel = "Restricted Guest"
				case "a0b1b346-4d3e-4e8b-98f8-753987be4970":
					roleLabel = output.StyleHighlight.Render("Member (same as members!)")
					overpermissive = true
				}
				output.TableRow("Guest user role:", roleLabel)
			}

			if overpermissive {
				fmt.Println()
				output.Warn("Overpermissive authorization policy settings detected")
			}

			fmt.Println()
		}
	}

	// Parse SKUs (licenses)
	if info.SKUs != nil {
		skus, _ := info.SKUs.([]map[string]interface{})
		if len(skus) > 0 {
			fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Subscribed SKUs (%d) ", len(skus))))
			for _, sku := range skus {
				name, _ := sku["skuPartNumber"].(string)
				prepUnits, _ := sku["prepaidUnits"].(map[string]interface{})
				enabled := 0
				if prepUnits != nil {
					if v, ok := prepUnits["enabled"].(float64); ok {
						enabled = int(v)
					}
				}
				consumed := 0
				if v, ok := sku["consumedUnits"].(float64); ok {
					consumed = int(v)
				}
				pct := 0
				if enabled > 0 {
					pct = (consumed * 100) / enabled
				}
				bar := output.StyleProgress.Render(fmt.Sprintf("%d/%d", consumed, enabled))
				pctTag := output.StyleDim.Render(fmt.Sprintf("(%d%%)", pct))
				fmt.Printf("    %-45s %s %s\n", output.StyleBold.Render(name), bar, pctTag)
			}
			fmt.Println()
		}
	}

	output.SearchDivider()
	fmt.Println()
	output.Success("Tenant configuration enumerated")
}
