package pillage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SharePointResult holds SharePoint/OneDrive search results.
type SharePointResult struct {
	Keywords  []string                 `json:"keywords"`
	TotalHits int                      `json:"total_hits"`
	Files     []map[string]interface{} `json:"files"`
	Downloads []string                 `json:"downloads,omitempty"`
}

// SearchSharePoint searches SharePoint and OneDrive for files matching keywords.
func SearchSharePoint(ctx context.Context, client *graph.Client, keywords []string, limit int, downloadDir string) (*SharePointResult, error) {
	result := &SharePointResult{Keywords: keywords}

	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}

		output.Info("Searching SharePoint/OneDrive for: %q", kw)

		searchReq := []map[string]interface{}{
			{
				"entityTypes": []string{"driveItem"},
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
			name, _ := h["name"].(string)
			webURL, _ := h["webUrl"].(string)
			size, _ := h["size"].(float64)
			output.Verbose("  %-40s  %8.0f bytes  %s", name, size, webURL)
		}
		result.Files = append(result.Files, hits...)
		result.TotalHits += len(hits)

		output.Success("  Found %d files for %q", len(hits), kw)
	}

	// Download files if requested
	if downloadDir != "" && len(result.Files) > 0 {
		if err := os.MkdirAll(downloadDir, 0755); err != nil {
			output.Error("Cannot create download dir: %v", err)
		} else {
			for _, f := range result.Files {
				driveID, itemID, name := extractDriveInfo(f)
				if driveID == "" || itemID == "" {
					continue
				}
				endpoint := fmt.Sprintf(graph.EndpointDriveItem, driveID, itemID)
				data, err := client.Download(ctx, endpoint)
				if err != nil {
					output.Warn("Download %s: %v", name, err)
					continue
				}
				outPath := filepath.Join(downloadDir, name)
				if err := os.WriteFile(outPath, data, 0600); err == nil {
					result.Downloads = append(result.Downloads, outPath)
					output.Success("Downloaded: %s", outPath)
				}
			}
		}
	}

	output.Success("SharePoint search complete: %d total hits", result.TotalHits)
	return result, nil
}

func extractDriveInfo(resource map[string]interface{}) (driveID, itemID, name string) {
	// The resource from search has a "parentReference" with driveId
	parentRef, _ := resource["parentReference"].(map[string]interface{})
	if parentRef != nil {
		driveID, _ = parentRef["driveId"].(string)
	}
	itemID, _ = resource["id"].(string)
	name, _ = resource["name"].(string)
	if name == "" {
		name = "unnamed_file"
	}
	return
}

// SPSearchResult holds results from a direct Search API query with configurable entity types.
type SPSearchResult struct {
	Query       string                   `json:"query"`
	EntityTypes []string                 `json:"entity_types"`
	TotalHits   int                      `json:"total_hits"`
	Results     []map[string]interface{} `json:"results"`
}

// SearchSP performs a direct Graph Search API query with configurable entity types.
// Supported entity types: driveItem, listItem, drive, site, list.
func SearchSP(ctx context.Context, client *graph.Client, query string, entityTypes []string, limit int) (*SPSearchResult, error) {
	if len(entityTypes) == 0 {
		entityTypes = []string{"driveItem", "listItem"}
	}

	result := &SPSearchResult{
		Query:       query,
		EntityTypes: entityTypes,
	}

	output.Info("SP Search: %q (types: %s, limit: %d)", query, strings.Join(entityTypes, ","), limit)

	searchReq := []map[string]interface{}{
		{
			"entityTypes": entityTypes,
			"query": map[string]string{
				"queryString": query,
			},
			"from": 0,
			"size": limit,
		},
	}

	raw, err := client.SearchQuery(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}

	hits := parseSearchHits(raw)
	result.Results = hits
	result.TotalHits = len(hits)

	output.Success("Found %d results for %q", result.TotalHits, query)
	return result, nil
}
