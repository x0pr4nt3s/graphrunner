package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// OpenInboxResult holds accessible mailbox scan results.
type OpenInboxResult struct {
	Accessible   []string `json:"accessible"`
	Inaccessible int      `json:"inaccessible"`
	Errors       int      `json:"errors"`
}

// OpenInboxes scans for mailboxes accessible to the current token.
func OpenInboxes(ctx context.Context, client *graph.Client) (interface{}, error) {
	// First get user list
	usersData, err := Users(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate users for inbox scan: %w", err)
	}

	usersResult, ok := usersData.(*UsersResult)
	if !ok {
		return nil, fmt.Errorf("unexpected users result type")
	}

	result := &OpenInboxResult{}
	output.Info("Scanning %d mailboxes for open access...", len(usersResult.Users))

	for _, user := range usersResult.Users {
		upn, _ := user["userPrincipalName"].(string)
		id, _ := user["id"].(string)
		if id == "" {
			continue
		}

		output.Verbose("checking %s...", upn)
		endpoint := fmt.Sprintf(graph.EndpointUserInbox, id)
		_, err := client.Get(ctx, endpoint, map[string]string{"$top": "1", "$select": "subject"})
		if err == nil {
			result.Accessible = append(result.Accessible, upn)
			output.Success("Accessible: %s", upn)
		} else {
			result.Inaccessible++
			output.Verbose("  denied: %v", err)
		}
	}

	printOpenInboxResults(result, len(usersResult.Users))

	return result, nil
}

func printOpenInboxResults(result *OpenInboxResult, totalScanned int) {
	accessible := len(result.Accessible)
	inaccessible := result.Inaccessible

	output.SearchResultHeader("Open Inbox Scan",
		totalScanned,
		fmt.Sprintf("%d accessible / %d denied", accessible, inaccessible))

	if totalScanned == 0 {
		output.Warn("No users scanned")
		return
	}

	// Overview
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Total Scanned")),
		output.StyleCounter.Render(fmt.Sprintf("%d", totalScanned)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Accessible")),
		output.StyleSuccess.Render(fmt.Sprintf("%d", accessible)))
	fmt.Printf("       %s  %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-20s", "Inaccessible")),
		output.StyleDim.Render(fmt.Sprintf("%d", inaccessible)))
	if result.Errors > 0 {
		fmt.Printf("       %s  %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-20s", "Errors")),
			output.StyleError.Render(fmt.Sprintf("%d", result.Errors)))
	}
	fmt.Println()

	// Accessibility percentage bar
	pct := 0
	if totalScanned > 0 {
		pct = (accessible * 100) / totalScanned
	}
	bar := strings.Repeat("█", pct/5) + strings.Repeat("░", 20-pct/5)
	fmt.Printf("       Accessibility: %s %s\n\n",
		output.StyleProgress.Render(bar),
		output.StyleCounter.Render(fmt.Sprintf("%d%%", pct)))

	// Accessible mailboxes list
	if accessible > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Accessible Mailboxes (%d) ", accessible)))

		for i, upn := range result.Accessible {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			tag := output.StyleSuccess.Render("[OPEN]")
			fmt.Printf("  %s %s  %s\n", num, tag, output.StyleUserInfo.Render(upn))
		}
		fmt.Println()
	}

	// Risk assessment
	output.SearchDivider()
	if accessible > 0 {
		output.Critical("RISK: %d out of %d mailboxes (%d%%) are accessible to the current token",
			accessible, totalScanned, pct)
		output.Warn("Open mailboxes can be read, searched, and exfiltrated")
	} else {
		output.Success("No open mailboxes found — all %d mailboxes denied access", totalScanned)
	}

	fmt.Println()
	output.Success("Inbox Scan: %d scanned | %d open | %d denied",
		totalScanned, accessible, inaccessible)
}
