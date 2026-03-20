package pillage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// KQLHit represents a single search result with all info needed to download.
type KQLHit struct {
	Name             string `json:"name"`
	DriveID          string `json:"drive_id"`
	ItemID           string `json:"item_id"`
	SiteID           string `json:"site_id,omitempty"`
	WebURL           string `json:"web_url"`
	Size             int64  `json:"size"`
	SizeHuman        string `json:"size_human"`
	CreatedBy        string `json:"created_by,omitempty"`
	LastModifiedBy   string `json:"last_modified_by,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	MimeType         string `json:"mime_type,omitempty"`
	Summary          string `json:"summary,omitempty"`
	DownloadCmd      string `json:"download_cmd"`
}

// KQLSearchResult holds KQL search results.
type KQLSearchResult struct {
	Query       string   `json:"query"`
	EntityTypes []string `json:"entity_types"`
	TotalHits   int      `json:"total_hits"`
	Hits        []KQLHit `json:"hits"`
	Downloaded  []string `json:"downloaded,omitempty"`
}

// KQLSearchOpts holds options for KQL search.
type KQLSearchOpts struct {
	Query       string
	EntityTypes []string // driveItem, listItem, site, drive, list, message
	Limit       int
	From        int      // pagination offset
	SiteID      string   // scope search to a specific site
	Extensions  []string // filter by extension
}

// KQLSearch performs a KQL search across SharePoint/OneDrive via Graph Search API.
// Returns structured results with driveID + itemID ready for download.
//
// KQL examples:
//   - "password filetype:xlsx"
//   - "confidential AND (filetype:docx OR filetype:pdf)"
//   - "author:admin@contoso.com"
//   - "created>2024-01-01 filetype:pptx"
//   - "path:\"https://contoso.sharepoint.com/sites/hr\""
//   - "*.config OR *.env OR *.key"
func KQLSearch(ctx context.Context, c *graph.Client, opts KQLSearchOpts) (*KQLSearchResult, error) {
	if opts.Query == "" {
		return nil, fmt.Errorf("query is required")
	}
	if opts.Limit <= 0 {
		opts.Limit = 25
	}
	if len(opts.EntityTypes) == 0 {
		opts.EntityTypes = []string{"driveItem"}
	}

	// Normalize extensions
	for i, ext := range opts.Extensions {
		opts.Extensions[i] = strings.TrimPrefix(strings.ToLower(ext), ".")
	}

	result := &KQLSearchResult{
		Query:       opts.Query,
		EntityTypes: opts.EntityTypes,
	}

	output.Info("KQL Search: %s", opts.Query)
	output.Info("  Entity types: %s | Limit: %d | Offset: %d", strings.Join(opts.EntityTypes, ", "), opts.Limit, opts.From)

	// Build search request
	searchBody := map[string]interface{}{
		"entityTypes": opts.EntityTypes,
		"query": map[string]string{
			"queryString": opts.Query,
		},
		"from": opts.From,
		"size": opts.Limit,
	}

	// Scope to specific site/region if specified
	if opts.SiteID != "" {
		searchBody["region"] = opts.SiteID
		output.Info("  Scoped to site: %s", opts.SiteID)
	}

	searchReq := []interface{}{searchBody}
	raw, err := c.SearchQuery(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}

	// Parse response
	var searchResp struct {
		Value []struct {
			HitsContainers []struct {
				Hits []struct {
					HitID    string          `json:"hitId"`
					Summary  string          `json:"summary"`
					Resource json.RawMessage `json:"resource"`
				} `json:"hits"`
				Total          int  `json:"total"`
				MoreResultsAvailable bool `json:"moreResultsAvailable"`
			} `json:"hitsContainers"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &searchResp); err != nil {
		return nil, fmt.Errorf("parse search response: %w", err)
	}

	for _, val := range searchResp.Value {
		for _, hc := range val.HitsContainers {
			for _, hit := range hc.Hits {
				kqlHit := parseKQLHit(hit.Resource, hit.Summary)
				if kqlHit == nil {
					continue
				}

				// Extension filter
				if len(opts.Extensions) > 0 {
					ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(kqlHit.Name)), ".")
					if !containsStr(opts.Extensions, ext) {
						continue
					}
				}

				result.Hits = append(result.Hits, *kqlHit)
			}

			if hc.MoreResultsAvailable {
				output.Info("  More results available — use --from %d to paginate", opts.From+opts.Limit)
			}
		}
	}

	result.TotalHits = len(result.Hits)

	// Pretty search results
	output.SearchResultHeader(opts.Query, result.TotalHits, strings.Join(opts.EntityTypes, ", "))

	for i, hit := range result.Hits {
		icon := output.FileIcon(hit.Name)
		modified := hit.LastModified
		if len(modified) > 10 {
			modified = modified[:10]
		}
		name := hit.Name

		// Extract site name from URL
		siteName := extractSiteName(hit.WebURL)

		// Clean summary snippet
		snippet := cleanSummary(hit.Summary)

		output.SearchResultRow(i+1, icon, name, hit.SizeHuman,
			hit.CreatedBy, hit.LastModifiedBy, modified,
			hit.WebURL, siteName, hit.DriveID, hit.ItemID, snippet)
	}

	if result.TotalHits == 0 {
		output.Warn("No results found for: %s", opts.Query)
	} else {
		output.SearchDivider()
		output.Success("Found %d results for KQL: %s", result.TotalHits, opts.Query)

		// Show download hints
		hasDownloadable := false
		for _, h := range result.Hits {
			if h.DriveID != "" && h.ItemID != "" {
				hasDownloadable = true
				break
			}
		}
		if hasDownloadable {
			fmt.Println()
			output.Dim("Download: --download 3 or --download 1,3,6 or --download all")
			output.Dim("Save to:  --download-dir ./loot (default: current dir)")
		}
	}

	return result, nil
}

func parseKQLHit(raw json.RawMessage, summary string) *KQLHit {
	var resource map[string]interface{}
	if err := json.Unmarshal(raw, &resource); err != nil {
		return nil
	}

	name, _ := resource["name"].(string)
	webURL, _ := resource["webUrl"].(string)
	id, _ := resource["id"].(string)
	size, _ := resource["size"].(float64)
	lastModified, _ := resource["lastModifiedDateTime"].(string)
	mimeType := ""

	// Get driveID from parentReference
	driveID := ""
	siteID := ""
	parentPath := ""
	parentRef, _ := resource["parentReference"].(map[string]interface{})
	if parentRef != nil {
		driveID, _ = parentRef["driveId"].(string)
		siteID, _ = parentRef["siteId"].(string)
		path, _ := parentRef["path"].(string)
		parentPath = path
	}

	// Get file mime type
	fileInfo, _ := resource["file"].(map[string]interface{})
	if fileInfo != nil {
		mimeType, _ = fileInfo["mimeType"].(string)
	}

	// Get created/modified by
	createdBy := extractUserName(resource, "createdBy")
	modifiedBy := extractUserName(resource, "lastModifiedBy")

	hit := &KQLHit{
		Name:           name,
		DriveID:        driveID,
		ItemID:         id,
		SiteID:         siteID,
		WebURL:         webURL,
		Size:           int64(size),
		SizeHuman:      humanFileSize(int64(size)),
		CreatedBy:      createdBy,
		LastModifiedBy: modifiedBy,
		LastModified:   lastModified,
		ParentPath:     parentPath,
		MimeType:       mimeType,
		Summary:        summary,
	}

	// Build download command hint
	if driveID != "" && id != "" {
		hit.DownloadCmd = fmt.Sprintf("graphrunner pillage download --drive-id %s --item-id %s --output \"%s\"", driveID, id, name)
	}

	return hit
}

func extractUserName(resource map[string]interface{}, field string) string {
	by, _ := resource[field].(map[string]interface{})
	if by == nil {
		return ""
	}
	user, _ := by["user"].(map[string]interface{})
	if user == nil {
		return ""
	}
	name, _ := user["displayName"].(string)
	if name == "" {
		name, _ = user["email"].(string)
	}
	return name
}

func truncID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:8] + ".."
}

// cleanSummary removes HTML-like tags from search hit summaries and makes them readable.
func cleanSummary(s string) string {
	if s == "" {
		return ""
	}
	// Replace highlight tags with brackets
	s = strings.ReplaceAll(s, "<c0>", "[")
	s = strings.ReplaceAll(s, "</c0>", "]")
	// Remove ellipsis tags
	s = strings.ReplaceAll(s, "<ddd/>", "...")
	// Remove any remaining HTML-ish tags
	result := strings.Builder{}
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	out := strings.TrimSpace(result.String())
	// Collapse multiple spaces
	for strings.Contains(out, "  ") {
		out = strings.ReplaceAll(out, "  ", " ")
	}
	if len(out) > 150 {
		out = out[:147] + "..."
	}
	return out
}

// extractSiteName extracts the site name from a SharePoint URL.
func extractSiteName(url string) string {
	// https://tenant.sharepoint.com/sites/SiteName/...
	idx := strings.Index(url, "/sites/")
	if idx == -1 {
		idx = strings.Index(url, "/personal/")
		if idx == -1 {
			return ""
		}
		rest := url[idx+len("/personal/"):]
		if slash := strings.Index(rest, "/"); slash > 0 {
			rest = rest[:slash]
		}
		return rest
	}
	rest := url[idx+len("/sites/"):]
	if slash := strings.Index(rest, "/"); slash > 0 {
		rest = rest[:slash]
	}
	return rest
}

func humanFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	case bytes > 0:
		return fmt.Sprintf("%d B", bytes)
	default:
		return "-"
	}
}
