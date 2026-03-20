package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// DevicesResult holds registered device enumeration results.
type DevicesResult struct {
	TotalDevices    int                      `json:"total_devices"`
	CompliantCount  int                      `json:"compliant"`
	ManagedCount    int                      `json:"managed"`
	Devices         []map[string]interface{} `json:"devices"`
}

// Devices enumerates all registered devices in the tenant.
func Devices(ctx context.Context, client *graph.Client) (*DevicesResult, error) {
	output.Info("Enumerating registered devices...")

	raw, err := client.GetAllWithProgress(ctx, graph.EndpointDevices, map[string]string{
		"$select": "id,displayName,operatingSystem,operatingSystemVersion,trustType," +
			"isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime," +
			"deviceId,manufacturer,model,profileType,enrollmentType," +
			"onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier," +
			"azureADDeviceId,mdmAppId,deviceOwnership,managementType," +
			"registeredOwners,registeredUsers",
		"$top": "999",
	}, "Devices")
	if err != nil {
		return nil, fmt.Errorf("get devices: %w", err)
	}

	result := &DevicesResult{TotalDevices: len(raw)}

	for _, r := range raw {
		var d map[string]interface{}
		json.Unmarshal(r, &d)

		compliant, _ := d["isCompliant"].(bool)
		managed, _ := d["isManaged"].(bool)

		if compliant {
			result.CompliantCount++
		}
		if managed {
			result.ManagedCount++
		}

		result.Devices = append(result.Devices, d)
	}

	// Pretty output
	printDevicesResults(result)

	return result, nil
}

func printDevicesResults(result *DevicesResult) {
	output.SearchResultHeader("Device Enumeration",
		result.TotalDevices,
		fmt.Sprintf("%d compliant, %d managed", result.CompliantCount, result.ManagedCount))

	if result.TotalDevices == 0 {
		output.Warn("No devices found")
		return
	}

	// Platform breakdown
	osCounts := map[string]int{}
	trustCounts := map[string]int{}
	ownerCounts := map[string]int{}
	nonCompliant := 0
	unmanaged := 0
	staleDevices := 0

	for _, d := range result.Devices {
		osName, _ := d["operatingSystem"].(string)
		if osName == "" {
			osName = "(unknown)"
		}
		osCounts[osName]++

		trust, _ := d["trustType"].(string)
		if trust == "" {
			trust = "(none)"
		}
		trustCounts[trust]++

		ownership, _ := d["deviceOwnership"].(string)
		if ownership != "" {
			ownerCounts[ownership]++
		}

		compliant, _ := d["isCompliant"].(bool)
		managed, _ := d["isManaged"].(bool)
		if !compliant {
			nonCompliant++
		}
		if !managed {
			unmanaged++
		}

		// Check for stale (no sign-in in 90+ days would need date parsing, just count missing)
		lastSignIn, _ := d["approximateLastSignInDateTime"].(string)
		if lastSignIn == "" {
			staleDevices++
		}
	}

	// Platform summary
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Platform Breakdown "))
	for osName, count := range osCounts {
		pct := (count * 100) / result.TotalDevices
		bar := ""
		if pct > 0 {
			bar = strings.Repeat("█", pct/5)
		}
		fmt.Printf("       %s %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", osName)),
			output.StyleCounter.Render(fmt.Sprintf("%4d", count)),
			output.StyleProgress.Render(bar))
	}
	fmt.Println()

	// Trust type summary
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Trust Types "))
	for trust, count := range trustCounts {
		trustStyled := output.StyleDim.Render(trust)
		if trust == "AzureAd" {
			trustStyled = output.StyleURLInfo.Render(trust)
		} else if trust == "ServerAd" {
			trustStyled = output.StyleHighlight.Render(trust)
		} else if trust == "Workplace" {
			trustStyled = output.StyleUserInfo.Render(trust)
		}
		fmt.Printf("       %s  %s\n", trustStyled, output.StyleCounter.Render(fmt.Sprintf("%d", count)))
	}
	fmt.Println()

	// Ownership
	if len(ownerCounts) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Device Ownership "))
		for owner, count := range ownerCounts {
			fmt.Printf("       %s  %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-20s", owner)),
				output.StyleCounter.Render(fmt.Sprintf("%d", count)))
		}
		fmt.Println()
	}

	// Show device list
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Devices (%d) ", result.TotalDevices)))

	for i, d := range result.Devices {
		name, _ := d["displayName"].(string)
		osName, _ := d["operatingSystem"].(string)
		osVer, _ := d["operatingSystemVersion"].(string)
		trust, _ := d["trustType"].(string)
		compliant, _ := d["isCompliant"].(bool)
		managed, _ := d["isManaged"].(bool)
		regTime, _ := d["registrationDateTime"].(string)
		lastSignIn, _ := d["approximateLastSignInDateTime"].(string)
		manufacturer, _ := d["manufacturer"].(string)
		model, _ := d["model"].(string)
		ownership, _ := d["deviceOwnership"].(string)
		mgmtType, _ := d["managementType"].(string)
		onPremSync, _ := d["onPremisesSyncEnabled"].(bool)

		if len(regTime) > 10 {
			regTime = regTime[:10]
		}
		if len(lastSignIn) > 10 {
			lastSignIn = lastSignIn[:10]
		}

		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(name)

		// OS tag
		osTag := output.StyleDim.Render("[" + osName + "]")
		if osName == "Windows" {
			osTag = output.StyleURLInfo.Render("[Windows]")
		} else if osName == "iOS" || osName == "Android" {
			osTag = output.StyleUserInfo.Render("[" + osName + "]")
		} else if osName == "MacMDM" || osName == "macOS" {
			osTag = output.StyleHighlight.Render("[macOS]")
		}

		// Compliance tag
		compTag := output.StyleSuccess.Render("[Compliant]")
		if !compliant {
			compTag = output.StyleCritical.Render("[NON-COMPLIANT]")
		}
		mgdTag := ""
		if !managed {
			mgdTag = output.StyleMedium.Render("[Unmanaged]")
		}

		// Line 1: number + name + OS + compliance
		fmt.Printf("  %s %s  %s %s %s\n", num, nameStyled, osTag, compTag, mgdTag)

		// Line 2: OS version + trust + registration
		details := ""
		if osVer != "" {
			details += output.StyleDim.Render("v"+osVer) + "  "
		}
		if trust != "" {
			trustStyled := trust
			if trust == "ServerAd" {
				trustStyled = output.StyleHighlight.Render("Hybrid-AD")
			}
			details += output.StyleDim.Render("Trust: ") + trustStyled + "  "
		}
		if regTime != "" {
			details += output.StyleDim.Render("Reg: "+regTime) + "  "
		}
		if lastSignIn != "" {
			details += output.StyleDim.Render("LastSign: "+lastSignIn)
		}
		if details != "" {
			fmt.Printf("       %s\n", details)
		}

		// Line 3: hardware + management (verbose only)
		if output.VerboseEnabled {
			extra := ""
			if manufacturer != "" || model != "" {
				extra += output.StyleDim.Render("HW: "+manufacturer+" "+model) + "  "
			}
			if ownership != "" {
				extra += output.StyleDim.Render("Owner: "+ownership) + "  "
			}
			if mgmtType != "" {
				extra += output.StyleDim.Render("Mgmt: "+mgmtType) + "  "
			}
			if onPremSync {
				extra += output.StyleHighlight.Render("[On-Prem Sync]")
			}
			if extra != "" {
				fmt.Printf("       %s\n", extra)
			}
		}

		fmt.Println()
	}

	if !output.VerboseEnabled {
		output.Dim("Use -v for hardware details, ownership, and management type")
	}

	output.SearchDivider()
	if nonCompliant > 0 {
		output.Warn("%d devices are NON-COMPLIANT", nonCompliant)
	}
	if unmanaged > 0 {
		output.Warn("%d devices are UNMANAGED", unmanaged)
	}
	if staleDevices > 0 {
		output.Dim("%d devices have no last sign-in date (possibly stale)", staleDevices)
	}

	fmt.Println()
	output.Success("Devices: %d total | %d compliant | %d managed",
		result.TotalDevices, result.CompliantCount, result.ManagedCount)
}
