package pillage

import (
	"context"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// TeamsResult holds Teams search results.
type TeamsResult struct {
	Keywords  []string                 `json:"keywords"`
	TotalHits int                      `json:"total_hits"`
	Messages  []map[string]interface{} `json:"messages"`
}

// SearchTeams searches Teams messages by keywords using the search API.
func SearchTeams(ctx context.Context, client *graph.Client, keywords []string, limit int) (*TeamsResult, error) {
	result := &TeamsResult{Keywords: keywords}

	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}

		output.Info("Searching Teams for: %q", kw)

		searchReq := []map[string]interface{}{
			{
				"entityTypes": []string{"chatMessage"},
				"query": map[string]string{
					"queryString": kw,
				},
				"from": 0,
				"size": limit,
			},
		}

		raw, err := client.SearchQuery(ctx, searchReq)
		if err != nil {
			output.Warn("Teams search for %q: %v", kw, err)
			continue
		}

		hits := parseSearchHits(raw)
		result.Messages = append(result.Messages, hits...)
		result.TotalHits += len(hits)

		output.Success("  Found %d messages for %q", len(hits), kw)
	}

	output.Success("Teams search complete: %d total hits", result.TotalHits)
	return result, nil
}
