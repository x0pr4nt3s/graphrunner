package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// CrossTenantPolicy represents a cross-tenant access policy.
type CrossTenantPolicy struct {
	ID                          string          `json:"id,omitempty"`
	DisplayName                 string          `json:"displayName,omitempty"`
	TenantID                    string          `json:"tenantId,omitempty"`
	IsServiceDefault            bool            `json:"isServiceDefault,omitempty"`
	InboundTrust                json.RawMessage `json:"inboundTrust,omitempty"`
	B2BCollaborationInbound     json.RawMessage `json:"b2bCollaborationInbound,omitempty"`
	B2BCollaborationOutbound    json.RawMessage `json:"b2bCollaborationOutbound,omitempty"`
	B2BDirectConnectInbound     json.RawMessage `json:"b2bDirectConnectInbound,omitempty"`
	B2BDirectConnectOutbound    json.RawMessage `json:"b2bDirectConnectOutbound,omitempty"`
	AutomaticUserConsentSettings json.RawMessage `json:"automaticUserConsentSettings,omitempty"`
}

// CrossTenantResult holds cross-tenant access configuration.
type CrossTenantResult struct {
	DefaultPolicy  *CrossTenantPolicy  `json:"default_policy"`
	PartnerConfigs []CrossTenantPolicy `json:"partner_configs"`
	PartnerCount   int                 `json:"partner_count"`
}

// CrossTenantAccess enumerates cross-tenant access policies and B2B configuration.
// Requires Policy.Read.All permission.
func CrossTenantAccess(ctx context.Context, c *graph.Client) (*CrossTenantResult, error) {
	result := &CrossTenantResult{}

	// Default policy
	output.Info("Fetching default cross-tenant access policy...")
	defaultRaw, err := c.Get(ctx, "/policies/crossTenantAccessPolicy/default", nil)
	if err != nil {
		output.Warn("Default cross-tenant policy: %v", err)
	} else {
		var def CrossTenantPolicy
		if err := json.Unmarshal(defaultRaw, &def); err == nil {
			result.DefaultPolicy = &def
			output.Verbose("[cross-tenant] Default policy loaded")
		}
	}

	// Partner configurations
	output.Info("Fetching partner cross-tenant configurations...")
	partnersRaw, err := c.GetAll(ctx, "/policies/crossTenantAccessPolicy/partners", nil)
	if err != nil {
		output.Warn("Partner cross-tenant configs: %v", err)
	} else {
		for _, raw := range partnersRaw {
			var partner CrossTenantPolicy
			if err := json.Unmarshal(raw, &partner); err == nil {
				result.PartnerConfigs = append(result.PartnerConfigs, partner)
				output.Verbose("[cross-tenant] Partner: %s (tenant: %s)", partner.DisplayName, partner.TenantID)
			}
		}
		result.PartnerCount = len(result.PartnerConfigs)
	}

	// Pretty output
	printCrossTenantResults(result)

	return result, nil
}

func printCrossTenantResults(result *CrossTenantResult) {
	output.SearchResultHeader("Cross-Tenant Access Policies",
		result.PartnerCount+1,
		fmt.Sprintf("default policy + %d partners", result.PartnerCount))

	// === DEFAULT POLICY ===
	if result.DefaultPolicy != nil {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Default Cross-Tenant Policy "))

		def := result.DefaultPolicy
		fmt.Printf("       %s %s\n", output.StyleDim.Render("ID:"), output.StyleDim.Render(def.ID))

		// Parse B2B settings
		b2bInStr := parseCrossTenantAccess(def.B2BCollaborationInbound, "B2B Collab Inbound")
		b2bOutStr := parseCrossTenantAccess(def.B2BCollaborationOutbound, "B2B Collab Outbound")
		dcInStr := parseCrossTenantAccess(def.B2BDirectConnectInbound, "Direct Connect In")
		dcOutStr := parseCrossTenantAccess(def.B2BDirectConnectOutbound, "Direct Connect Out")
		trustStr := parseCrossTenantTrust(def.InboundTrust)

		if b2bInStr != "" {
			fmt.Printf("       %s %s\n", output.StyleBold.Render("B2B Collab Inbound: "), b2bInStr)
		}
		if b2bOutStr != "" {
			fmt.Printf("       %s %s\n", output.StyleBold.Render("B2B Collab Outbound:"), b2bOutStr)
		}
		if dcInStr != "" {
			fmt.Printf("       %s %s\n", output.StyleBold.Render("Direct Connect In:  "), dcInStr)
		}
		if dcOutStr != "" {
			fmt.Printf("       %s %s\n", output.StyleBold.Render("Direct Connect Out: "), dcOutStr)
		}
		if trustStr != "" {
			fmt.Printf("       %s %s\n", output.StyleHighlight.Render("Inbound Trust:"), trustStr)
		}
		fmt.Println()
	}

	// === PARTNER CONFIGS ===
	if result.PartnerCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Partner Configurations ("+fmt.Sprintf("%d", result.PartnerCount)+") "))

		for i, p := range result.PartnerConfigs {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			name := p.DisplayName
			if name == "" {
				name = "(unnamed)"
			}
			nameStyled := output.StyleBold.Render(name)
			tenantTag := ""
			if p.TenantID != "" {
				tenantTag = output.StyleDim.Render("[" + p.TenantID + "]")
			}

			// Line 1: number + name + tenant
			fmt.Printf("  %s %s  %s\n", num, nameStyled, tenantTag)

			// Parse B2B settings for this partner
			b2bIn := parseCrossTenantAccess(p.B2BCollaborationInbound, "")
			b2bOut := parseCrossTenantAccess(p.B2BCollaborationOutbound, "")
			dcIn := parseCrossTenantAccess(p.B2BDirectConnectInbound, "")
			dcOut := parseCrossTenantAccess(p.B2BDirectConnectOutbound, "")
			trust := parseCrossTenantTrust(p.InboundTrust)

			if b2bIn != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("B2B In:"), b2bIn)
			}
			if b2bOut != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("B2B Out:"), b2bOut)
			}
			if dcIn != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("DC In:"), dcIn)
			}
			if dcOut != "" {
				fmt.Printf("       %s %s\n", output.StyleDim.Render("DC Out:"), dcOut)
			}
			if trust != "" {
				fmt.Printf("       %s %s\n", output.StyleHighlight.Render("Trust:"), trust)
			}

			fmt.Println()
		}
	}

	output.SearchDivider()
	output.Success("Cross-tenant: default policy + %d partner configurations", result.PartnerCount)
}

func parseCrossTenantAccess(raw json.RawMessage, label string) string {
	if raw == nil || string(raw) == "null" {
		return ""
	}
	var access struct {
		UsersAndGroups *struct {
			AccessType string `json:"accessType"`
		} `json:"usersAndGroups"`
		Applications *struct {
			AccessType string `json:"accessType"`
		} `json:"applications"`
	}
	if err := json.Unmarshal(raw, &access); err != nil {
		return ""
	}
	parts := []string{}
	if access.UsersAndGroups != nil {
		tag := access.UsersAndGroups.AccessType
		if tag == "allowed" {
			parts = append(parts, output.StyleSuccess.Render("Users: allowed"))
		} else if tag == "blocked" {
			parts = append(parts, output.StyleCritical.Render("Users: BLOCKED"))
		} else {
			parts = append(parts, "Users: "+tag)
		}
	}
	if access.Applications != nil {
		tag := access.Applications.AccessType
		if tag == "allowed" {
			parts = append(parts, output.StyleSuccess.Render("Apps: allowed"))
		} else if tag == "blocked" {
			parts = append(parts, output.StyleCritical.Render("Apps: BLOCKED"))
		} else {
			parts = append(parts, "Apps: "+tag)
		}
	}
	if len(parts) == 0 {
		return output.StyleDim.Render("(default)")
	}
	return strings.Join(parts, "  ")
}

func parseCrossTenantTrust(raw json.RawMessage) string {
	if raw == nil || string(raw) == "null" {
		return ""
	}
	var trust struct {
		IsMfaAccepted              bool `json:"isMfaAccepted"`
		IsCompliantDeviceAccepted  bool `json:"isCompliantDeviceAccepted"`
		IsHybridJoinedDeviceAccepted bool `json:"isHybridAzureADJoinedDeviceAccepted"`
	}
	if err := json.Unmarshal(raw, &trust); err != nil {
		return ""
	}
	parts := []string{}
	if trust.IsMfaAccepted {
		parts = append(parts, output.StyleHighlight.Render("Trust MFA"))
	}
	if trust.IsCompliantDeviceAccepted {
		parts = append(parts, "Trust Compliant")
	}
	if trust.IsHybridJoinedDeviceAccepted {
		parts = append(parts, "Trust Hybrid-Joined")
	}
	if len(parts) == 0 {
		return output.StyleDim.Render("no trust")
	}
	return strings.Join(parts, ", ")
}
