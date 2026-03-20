package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AuditLogEntry represents a directory audit log event.
type AuditLogEntry struct {
	ID                 string          `json:"id"`
	ActivityDateTime   string          `json:"activityDateTime"`
	ActivityDisplayName string         `json:"activityDisplayName"`
	Category           string          `json:"category"`
	Result             string          `json:"result"`
	InitiatedBy        json.RawMessage `json:"initiatedBy"`
	TargetResources    json.RawMessage `json:"targetResources"`
	LoggedByService    string          `json:"loggedByService"`
}

// SignInLogEntry represents a sign-in log event.
type SignInLogEntry struct {
	ID                     string          `json:"id"`
	CreatedDateTime        string          `json:"createdDateTime"`
	UserDisplayName        string          `json:"userDisplayName"`
	UserPrincipalName      string          `json:"userPrincipalName"`
	AppDisplayName         string          `json:"appDisplayName"`
	IPAddress              string          `json:"ipAddress"`
	ClientAppUsed          string          `json:"clientAppUsed"`
	IsInteractive          bool            `json:"isInteractive"`
	ResourceDisplayName    string          `json:"resourceDisplayName"`
	Status                 json.RawMessage `json:"status"`
	Location               json.RawMessage `json:"location"`
	ConditionalAccessStatus string        `json:"conditionalAccessStatus"`
	RiskState              string          `json:"riskState"`
	RiskLevelDuringSignIn  string          `json:"riskLevelDuringSignIn"`
	MfaDetail              json.RawMessage `json:"mfaDetail"`
}

// AuditLogsResult contains both audit and sign-in logs.
type AuditLogsResult struct {
	DirectoryAuditLogs []AuditLogEntry  `json:"directory_audit_logs"`
	SignInLogs         []SignInLogEntry  `json:"sign_in_logs"`
	AuditCount         int              `json:"audit_count"`
	SignInCount        int              `json:"sign_in_count"`
}

// AuditLogs retrieves directory audit logs and sign-in logs.
// Requires AuditLog.Read.All or Directory.Read.All permission.
// Uses beta endpoint for richer data.
func AuditLogs(ctx context.Context, c *graph.Client, top int, filter string) (*AuditLogsResult, error) {
	result := &AuditLogsResult{}

	// Switch to beta for richer audit log data
	c.UseBeta()
	defer c.UseV1()

	// Directory audit logs
	output.Info("Fetching directory audit logs...")
	auditParams := map[string]string{
		"$top":     fmt.Sprintf("%d", top),
		"$orderby": "activityDateTime desc",
	}
	if filter != "" {
		auditParams["$filter"] = filter
	}

	auditRaw, err := c.GetAll(ctx, "/auditLogs/directoryAudits", auditParams)
	if err != nil {
		output.Warn("Directory audit logs: %v", err)
	} else {
		for _, raw := range auditRaw {
			var entry AuditLogEntry
			if err := json.Unmarshal(raw, &entry); err == nil {
				result.DirectoryAuditLogs = append(result.DirectoryAuditLogs, entry)
				output.Verbose("[audit] %s | %s | %s", entry.ActivityDateTime, entry.ActivityDisplayName, entry.Result)
			}
		}
		result.AuditCount = len(result.DirectoryAuditLogs)
		output.Success("Directory audit logs: %d entries", result.AuditCount)
	}

	// Sign-in logs
	output.Info("Fetching sign-in logs...")
	signInParams := map[string]string{
		"$top":     fmt.Sprintf("%d", top),
		"$orderby": "createdDateTime desc",
	}

	signInRaw, err := c.GetAll(ctx, "/auditLogs/signIns", signInParams)
	if err != nil {
		output.Warn("Sign-in logs: %v (requires AuditLog.Read.All)", err)
	} else {
		for _, raw := range signInRaw {
			var entry SignInLogEntry
			if err := json.Unmarshal(raw, &entry); err == nil {
				result.SignInLogs = append(result.SignInLogs, entry)
				output.Verbose("[sign-in] %s | %s | %s | %s | risk:%s",
					entry.CreatedDateTime, entry.UserPrincipalName, entry.IPAddress,
					entry.AppDisplayName, entry.RiskState)
			}
		}
		result.SignInCount = len(result.SignInLogs)
		output.Success("Sign-in logs: %d entries", result.SignInCount)
	}

	// Pretty output
	printAuditLogsResults(result)

	return result, nil
}

func printAuditLogsResults(result *AuditLogsResult) {
	output.SearchResultHeader("Directory & Sign-In Audit Logs",
		result.AuditCount+result.SignInCount,
		fmt.Sprintf("%d audit events, %d sign-ins", result.AuditCount, result.SignInCount))

	// === DIRECTORY AUDIT LOGS ===
	if result.AuditCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Directory Audit Logs ("+fmt.Sprintf("%d", result.AuditCount)+") "))

		// Category and result stats
		catCounts := map[string]int{}
		resultCounts := map[string]int{}
		for _, e := range result.DirectoryAuditLogs {
			catCounts[e.Category]++
			resultCounts[e.Result]++
		}

		// Show category breakdown
		for cat, count := range catCounts {
			fmt.Printf("       %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-30s", cat+":")),
				output.StyleCounter.Render(fmt.Sprintf("%d", count)))
		}
		fmt.Println()

		// Show events
		for i, e := range result.DirectoryAuditLogs {
			ts := e.ActivityDateTime
			if len(ts) > 19 {
				ts = ts[:19]
			}

			// Result tag
			resultTag := output.StyleSuccess.Render("[" + e.Result + "]")
			if e.Result == "failure" {
				resultTag = output.StyleCritical.Render("[FAILURE]")
			}

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			activity := output.StyleBold.Render(e.ActivityDisplayName)

			// Line 1: number + activity + result
			fmt.Printf("  %s %s  %s\n", num, activity, resultTag)

			// Line 2: timestamp + category + service
			details := output.StyleDim.Render(ts)
			if e.Category != "" {
				details += "  " + output.StyleURLInfo.Render("["+e.Category+"]")
			}
			if e.LoggedByService != "" {
				details += "  " + output.StyleDim.Render("by "+e.LoggedByService)
			}
			fmt.Printf("       %s\n", details)

			// Line 3: initiated by
			initiator := parseInitiatedBy(e.InitiatedBy)
			if initiator != "" {
				fmt.Printf("       %s %s\n", output.StyleUserInfo.Render("Actor:"), initiator)
			}

			// Line 4: targets
			targets := parseTargetResources(e.TargetResources)
			if targets != "" {
				fmt.Printf("       %s %s\n", output.StyleHighlight.Render("Target:"), targets)
			}

			fmt.Println()
		}

		// Result stats
		output.SearchDivider()
		if failCount, ok := resultCounts["failure"]; ok && failCount > 0 {
			output.Warn("%d audit events resulted in FAILURE", failCount)
		}
		fmt.Println()
	}

	// === SIGN-IN LOGS ===
	if result.SignInCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Sign-In Logs ("+fmt.Sprintf("%d", result.SignInCount)+") "))

		// Stats
		riskCount := 0
		failCount := 0
		interactiveCount := 0
		appCounts := map[string]int{}
		ipCounts := map[string]int{}

		for _, e := range result.SignInLogs {
			if e.RiskState != "" && e.RiskState != "none" && e.RiskState != "remediated" {
				riskCount++
			}
			statusCode := parseSignInStatusCode(e.Status)
			if statusCode != "0" && statusCode != "" {
				failCount++
			}
			if e.IsInteractive {
				interactiveCount++
			}
			appCounts[e.AppDisplayName]++
			if e.IPAddress != "" {
				ipCounts[e.IPAddress]++
			}
		}

		// Show top apps
		fmt.Printf("       %s\n", output.StyleBold.Render("Top Applications:"))
		shown := 0
		for app, count := range appCounts {
			if shown >= 5 {
				break
			}
			fmt.Printf("         %s %s\n",
				output.StyleDim.Render(fmt.Sprintf("%-40s", app)),
				output.StyleCounter.Render(fmt.Sprintf("%d sign-ins", count)))
			shown++
		}
		fmt.Println()

		// Show entries
		for i, e := range result.SignInLogs {
			ts := e.CreatedDateTime
			if len(ts) > 19 {
				ts = ts[:19]
			}

			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			user := output.StyleBold.Render(e.UserDisplayName)

			// Risk styling
			riskTag := ""
			if e.RiskState != "" && e.RiskState != "none" {
				if e.RiskState == "atRisk" || e.RiskState == "confirmedCompromised" {
					riskTag = output.StyleCritical.Render("[" + e.RiskState + "]")
				} else {
					riskTag = output.StyleMedium.Render("[" + e.RiskState + "]")
				}
			}

			// Status
			statusCode := parseSignInStatusCode(e.Status)
			statusTag := output.StyleSuccess.Render("[OK]")
			if statusCode != "0" && statusCode != "" {
				statusTag = output.StyleCritical.Render("[FAIL:" + statusCode + "]")
			}

			// Line 1: number + user + status + risk
			fmt.Printf("  %s %s  %s %s\n", num, user, statusTag, riskTag)

			// Line 2: UPN + IP + timestamp
			fmt.Printf("       %s  %s %s  %s\n",
				output.StyleDim.Render(e.UserPrincipalName),
				output.StyleHighlight.Render("IP:"), output.StyleHighlight.Render(e.IPAddress),
				output.StyleDim.Render(ts))

			// Line 3: app + client + resource
			appInfo := ""
			if e.AppDisplayName != "" {
				appInfo += output.StyleURLInfo.Render("App: "+e.AppDisplayName) + "  "
			}
			if e.ClientAppUsed != "" {
				appInfo += output.StyleDim.Render("Client: "+e.ClientAppUsed) + "  "
			}
			if e.ResourceDisplayName != "" {
				appInfo += output.StyleDim.Render("→ "+e.ResourceDisplayName)
			}
			if appInfo != "" {
				fmt.Printf("       %s\n", appInfo)
			}

			// Line 4: CA status + interactive
			flags := ""
			if e.ConditionalAccessStatus != "" {
				if e.ConditionalAccessStatus == "failure" {
					flags += output.StyleCritical.Render("[CA:BLOCKED]") + "  "
				} else {
					flags += output.StyleDim.Render("[CA:"+e.ConditionalAccessStatus+"]") + "  "
				}
			}
			if !e.IsInteractive {
				flags += output.StyleDim.Render("[non-interactive]")
			}

			// Location
			loc := parseSignInLocation(e.Location)
			if loc != "" {
				flags += "  " + output.StyleDim.Render("📍 "+loc)
			}

			if flags != "" {
				fmt.Printf("       %s\n", flags)
			}

			fmt.Println()
		}

		output.SearchDivider()
		if riskCount > 0 {
			output.Warn("%d sign-ins flagged as RISKY", riskCount)
		}
		if failCount > 0 {
			output.Warn("%d sign-ins FAILED (possible spray/brute attempts?)", failCount)
		}
		output.Dim("%d interactive, %d non-interactive sign-ins", interactiveCount, result.SignInCount-interactiveCount)
	}

	fmt.Println()
	output.Success("Audit logs: %d directory events, %d sign-ins",
		result.AuditCount, result.SignInCount)
}

func parseInitiatedBy(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var ib struct {
		User *struct {
			DisplayName       string `json:"displayName"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"user"`
		App *struct {
			DisplayName string `json:"displayName"`
			AppID       string `json:"appId"`
		} `json:"app"`
	}
	if err := json.Unmarshal(raw, &ib); err != nil {
		return ""
	}
	if ib.User != nil && ib.User.DisplayName != "" {
		return ib.User.DisplayName + " (" + ib.User.UserPrincipalName + ")"
	}
	if ib.App != nil && ib.App.DisplayName != "" {
		return "[App] " + ib.App.DisplayName
	}
	return ""
}

func parseTargetResources(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var targets []struct {
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
	}
	if err := json.Unmarshal(raw, &targets); err != nil {
		return ""
	}
	parts := []string{}
	for _, t := range targets {
		if t.DisplayName != "" {
			parts = append(parts, t.DisplayName+" ["+t.Type+"]")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

func parseSignInStatusCode(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var s struct {
		ErrorCode int `json:"errorCode"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return fmt.Sprintf("%d", s.ErrorCode)
}

func parseSignInLocation(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var loc struct {
		City  string `json:"city"`
		State string `json:"state"`
		CC    string `json:"countryOrRegion"`
	}
	if err := json.Unmarshal(raw, &loc); err != nil {
		return ""
	}
	parts := []string{}
	if loc.City != "" {
		parts = append(parts, loc.City)
	}
	if loc.State != "" {
		parts = append(parts, loc.State)
	}
	if loc.CC != "" {
		parts = append(parts, loc.CC)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}
