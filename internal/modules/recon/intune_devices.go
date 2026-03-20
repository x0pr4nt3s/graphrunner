package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// IntuneDevice represents an Intune managed device.
type IntuneDevice struct {
	ID                       string `json:"id"`
	DeviceName               string `json:"deviceName"`
	UserDisplayName          string `json:"userDisplayName"`
	UserPrincipalName        string `json:"userPrincipalName"`
	OperatingSystem          string `json:"operatingSystem"`
	OSVersion                string `json:"osVersion"`
	ComplianceState          string `json:"complianceState"`
	IsEncrypted              bool   `json:"isEncrypted"`
	Model                    string `json:"model"`
	Manufacturer             string `json:"manufacturer"`
	SerialNumber             string `json:"serialNumber"`
	ManagementAgent          string `json:"managementAgent"`
	EnrolledDateTime         string `json:"enrolledDateTime"`
	LastSyncDateTime         string `json:"lastSyncDateTime"`
	AzureADDeviceID          string `json:"azureADDeviceId"`
	DeviceEnrollmentType     string `json:"deviceEnrollmentType"`
	JailBroken               string `json:"jailBroken"`
	ManagementState          string `json:"managementState"`
	AzureADRegistered        bool   `json:"azureADRegistered"`
	DeviceRegistrationState  string `json:"deviceRegistrationState"`
}

// IntuneDevicesResult holds all Intune managed devices.
type IntuneDevicesResult struct {
	Devices      []IntuneDevice `json:"devices"`
	Total        int            `json:"total"`
	Compliant    int            `json:"compliant"`
	NonCompliant int            `json:"non_compliant"`
	Encrypted    int            `json:"encrypted"`
	OSBreakdown  map[string]int `json:"os_breakdown"`
}

// IntuneDevices enumerates Intune managed devices.
// Requires DeviceManagementManagedDevices.Read.All permission.
// Uses beta endpoint for full device properties.
func IntuneDevices(ctx context.Context, c *graph.Client) (*IntuneDevicesResult, error) {
	output.Info("Fetching Intune managed devices...")

	c.UseBeta()
	defer c.UseV1()

	raw, err := c.GetAll(ctx, "/deviceManagement/managedDevices", nil)
	if err != nil {
		return nil, err
	}

	result := &IntuneDevicesResult{
		OSBreakdown: make(map[string]int),
	}

	for _, r := range raw {
		var dev IntuneDevice
		if err := json.Unmarshal(r, &dev); err != nil {
			continue
		}
		result.Devices = append(result.Devices, dev)

		if dev.ComplianceState == "compliant" {
			result.Compliant++
		} else if dev.ComplianceState == "noncompliant" {
			result.NonCompliant++
		}
		if dev.IsEncrypted {
			result.Encrypted++
		}
		if dev.OperatingSystem != "" {
			result.OSBreakdown[dev.OperatingSystem]++
		}

		output.Verbose("[intune] %s | %s | %s %s | compliance: %s | encrypted: %v",
			dev.DeviceName, dev.UserPrincipalName, dev.OperatingSystem, dev.OSVersion,
			dev.ComplianceState, dev.IsEncrypted)
	}
	result.Total = len(result.Devices)

	printIntuneResults(result)
	return result, nil
}

func printIntuneResults(result *IntuneDevicesResult) {
	subtitle := fmt.Sprintf("%d compliant, %d non-compliant, %d encrypted",
		result.Compliant, result.NonCompliant, result.Encrypted)
	output.SearchResultHeader("Intune Managed Devices", result.Total, subtitle)

	if result.Total == 0 {
		output.Warn("No Intune managed devices found")
		return
	}

	// OS breakdown with bar chart
	if len(result.OSBreakdown) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" OS Breakdown "))
		for osName, count := range result.OSBreakdown {
			pct := (count * 100) / result.Total
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
	}

	// Device list
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Devices (%d) ", result.Total)))

	jailbroken := 0
	unencrypted := 0

	for i, dev := range result.Devices {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(dev.DeviceName)

		// OS tag
		osTag := output.StyleDim.Render("[" + dev.OperatingSystem + "]")
		if dev.OperatingSystem == "Windows" {
			osTag = output.StyleURLInfo.Render("[Windows]")
		} else if dev.OperatingSystem == "iOS" || dev.OperatingSystem == "Android" {
			osTag = output.StyleUserInfo.Render("[" + dev.OperatingSystem + "]")
		} else if dev.OperatingSystem == "macOS" || dev.OperatingSystem == "MacMDM" {
			osTag = output.StyleHighlight.Render("[macOS]")
		}

		// Compliance tag
		compTag := output.StyleSuccess.Render("[Compliant]")
		if dev.ComplianceState == "noncompliant" {
			compTag = output.StyleCritical.Render("[NON-COMPLIANT]")
		} else if dev.ComplianceState != "compliant" && dev.ComplianceState != "" {
			compTag = output.StyleMedium.Render("[" + dev.ComplianceState + "]")
		}

		// Encryption tag
		encTag := output.StyleSuccess.Render("[Encrypted]")
		if !dev.IsEncrypted {
			encTag = output.StyleHigh.Render("[Unencrypted]")
			unencrypted++
		}

		// Jailbreak tag
		jailTag := ""
		if dev.JailBroken != "" && dev.JailBroken != "Unknown" && dev.JailBroken != "False" {
			jailTag = " " + output.StyleCritical.Render("[JAILBROKEN]")
			jailbroken++
		}

		// Line 1: number + name + OS + compliance + encryption + jailbreak
		fmt.Printf("  %s %s  %s %s %s%s\n", num, nameStyled, osTag, compTag, encTag, jailTag)

		// Line 2: user + OS version
		details := ""
		if dev.UserPrincipalName != "" {
			details += output.StyleUserInfo.Render(dev.UserPrincipalName) + "  "
		} else if dev.UserDisplayName != "" {
			details += output.StyleUserInfo.Render(dev.UserDisplayName) + "  "
		}
		if dev.OSVersion != "" {
			details += output.StyleDim.Render("v"+dev.OSVersion) + "  "
		}
		if dev.LastSyncDateTime != "" {
			ts := dev.LastSyncDateTime
			if len(ts) > 10 {
				ts = ts[:10]
			}
			details += output.StyleDim.Render("Sync: "+ts)
		}
		if details != "" {
			fmt.Printf("       %s\n", details)
		}

		// Verbose: serial, model, manufacturer, enrollment type, management agent
		if output.VerboseEnabled {
			extra := ""
			if dev.Manufacturer != "" || dev.Model != "" {
				extra += output.StyleDim.Render("HW: "+dev.Manufacturer+" "+dev.Model) + "  "
			}
			if dev.SerialNumber != "" {
				extra += output.StyleDim.Render("SN: "+dev.SerialNumber) + "  "
			}
			if dev.DeviceEnrollmentType != "" {
				extra += output.StyleDim.Render("Enroll: "+dev.DeviceEnrollmentType) + "  "
			}
			if dev.ManagementAgent != "" {
				extra += output.StyleDim.Render("Agent: "+dev.ManagementAgent)
			}
			if extra != "" {
				fmt.Printf("       %s\n", extra)
			}
		}

		fmt.Println()
	}

	if !output.VerboseEnabled {
		output.Dim("Use -v for serial, model, manufacturer, and enrollment details")
	}

	output.SearchDivider()

	if result.NonCompliant > 0 {
		output.Warn("%d devices are NON-COMPLIANT", result.NonCompliant)
	}
	if unencrypted > 0 {
		output.Warn("%d devices are UNENCRYPTED", unencrypted)
	}
	if jailbroken > 0 {
		output.Critical("%d devices are JAILBROKEN or ROOTED", jailbroken)
	}

	fmt.Println()
	output.Success("Intune devices: %d total | %d compliant | %d non-compliant | %d encrypted",
		result.Total, result.Compliant, result.NonCompliant, result.Encrypted)
}
