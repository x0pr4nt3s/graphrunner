package pillage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// MailboxResult holds mailbox search results.
type MailboxResult struct {
	Keywords     []string               `json:"keywords"`
	TotalHits    int                    `json:"total_hits"`
	Messages     []map[string]interface{} `json:"messages"`
}

// SearchMailbox searches mailbox content using the Graph search API.
func SearchMailbox(ctx context.Context, client *graph.Client, keywords []string, userID string, limit int) (*MailboxResult, error) {
	result := &MailboxResult{Keywords: keywords}

	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}

		output.Info("Searching mailbox for: %q", kw)

		searchReq := []map[string]interface{}{
			{
				"entityTypes": []string{"message"},
				"query": map[string]string{
					"queryString": kw,
				},
				"from": 0,
				"size": limit,
			},
		}

		raw, err := client.SearchQuery(ctx, searchReq)
		if err != nil {
			output.Warn("Search for %q: %v", kw, err)
			continue
		}

		hits := parseSearchHits(raw)
		for _, h := range hits {
			subject, _ := h["subject"].(string)
			from, _ := h["from"].(map[string]interface{})
			fromAddr := ""
			if ep, ok := from["emailAddress"].(map[string]interface{}); ok {
				fromAddr, _ = ep["address"].(string)
			}
			received, _ := h["receivedDateTime"].(string)
			if len(received) > 10 {
				received = received[:10]
			}
			output.Verbose("  [%s] %-35s %s", received, fromAddr, subject)
		}
		result.Messages = append(result.Messages, hits...)
		result.TotalHits += len(hits)

		output.Success("  Found %d messages for %q", len(hits), kw)
	}

	// If search API fails, fall back to direct mailbox read
	if result.TotalHits == 0 && userID != "" {
		output.Info("Falling back to direct mailbox read for user %s...", userID)
		endpoint := fmt.Sprintf(graph.EndpointUserMailbox, userID)
		raw, err := client.GetAll(ctx, endpoint, map[string]string{
			"$select": "subject,from,receivedDateTime,bodyPreview",
			"$top":    fmt.Sprintf("%d", limit),
			"$orderby": "receivedDateTime desc",
		})
		if err == nil {
			for _, r := range raw {
				var m map[string]interface{}
				json.Unmarshal(r, &m)
				// Filter by keywords in subject/body
				bodyPreview, _ := m["bodyPreview"].(string)
				subject, _ := m["subject"].(string)
				text := strings.ToLower(subject + " " + bodyPreview)
				for _, kw := range keywords {
					if strings.Contains(text, strings.ToLower(strings.TrimSpace(kw))) {
						result.Messages = append(result.Messages, m)
						result.TotalHits++
						break
					}
				}
			}
		}
	}

	output.Success("Mailbox search complete: %d total hits", result.TotalHits)
	return result, nil
}

// parseSearchHits extracts hit resources from a Graph search response.
func parseSearchHits(raw json.RawMessage) []map[string]interface{} {
	var resp map[string]interface{}
	json.Unmarshal(raw, &resp)

	var results []map[string]interface{}
	valueArr, _ := resp["value"].([]interface{})
	for _, v := range valueArr {
		vMap, _ := v.(map[string]interface{})
		hitsContainers, _ := vMap["hitsContainers"].([]interface{})
		for _, hc := range hitsContainers {
			hcMap, _ := hc.(map[string]interface{})
			hits, _ := hcMap["hits"].([]interface{})
			for _, hit := range hits {
				hitMap, _ := hit.(map[string]interface{})
				resource, _ := hitMap["resource"].(map[string]interface{})
				if resource != nil {
					results = append(results, resource)
				}
			}
		}
	}
	return results
}
