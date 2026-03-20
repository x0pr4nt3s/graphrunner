package pillage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// NotebooksResult holds OneNote enumeration results.
type NotebooksResult struct {
	TotalNotebooks int                      `json:"total_notebooks"`
	TotalSections  int                      `json:"total_sections"`
	TotalPages     int                      `json:"total_pages"`
	Notebooks      []map[string]interface{} `json:"notebooks"`
}

// ReadNotebooks enumerates OneNote notebooks, sections, and pages.
// If keywords is non-empty, page content is fetched and filtered.
func ReadNotebooks(ctx context.Context, client *graph.Client, userID string, keywords []string) (*NotebooksResult, error) {
	var nbEndpoint, sectEndpoint, pagesEndpoint string

	if userID == "" || userID == "me" {
		nbEndpoint = graph.EndpointMeNotebooks
		sectEndpoint = graph.EndpointMeSections
		pagesEndpoint = graph.EndpointMePages
	} else {
		nbEndpoint = fmt.Sprintf(graph.EndpointUserNotebooks, userID)
		sectEndpoint = fmt.Sprintf(graph.EndpointUserSections, userID)
		pagesEndpoint = fmt.Sprintf(graph.EndpointUserPages, userID)
	}

	output.Info("Enumerating OneNote notebooks...")

	nbRaw, err := client.GetAll(ctx, nbEndpoint, map[string]string{"$top": "100"})
	if err != nil {
		return nil, fmt.Errorf("list notebooks: %w", err)
	}

	result := &NotebooksResult{TotalNotebooks: len(nbRaw)}

	// Build notebook map for cross-reference
	nbMap := make(map[string]map[string]interface{})
	for _, r := range nbRaw {
		var nb map[string]interface{}
		json.Unmarshal(r, &nb)
		id, _ := nb["id"].(string)
		name, _ := nb["displayName"].(string)
		output.Verbose("  notebook: %s (%s)", name, id)
		nbMap[id] = nb
		result.Notebooks = append(result.Notebooks, nb)
	}

	// Enumerate all sections
	output.Info("Enumerating sections...")
	sectRaw, err := client.GetAll(ctx, sectEndpoint, map[string]string{"$top": "200"})
	if err != nil {
		output.Warn("sections: %v", err)
	} else {
		result.TotalSections = len(sectRaw)
		// Attach sections to their parent notebook
		for _, r := range sectRaw {
			var sect map[string]interface{}
			json.Unmarshal(r, &sect)
			name, _ := sect["displayName"].(string)
			parentNB, _ := sect["parentNotebook"].(map[string]interface{})
			nbID := ""
			if parentNB != nil {
				nbID, _ = parentNB["id"].(string)
			}
			output.Verbose("    section: %s (nb: %s)", name, nbID)
			if nb, ok := nbMap[nbID]; ok {
				sects, _ := nb["sections"].([]interface{})
				nb["sections"] = append(sects, sect)
			}
		}
	}

	// Enumerate all pages
	output.Info("Enumerating pages...")
	pagesRaw, err := client.GetAll(ctx, pagesEndpoint, map[string]string{
		"$select": "id,title,createdDateTime,lastModifiedDateTime,parentSection,parentNotebook",
		"$top":    "500",
	})
	if err != nil {
		output.Warn("pages: %v", err)
	} else {
		result.TotalPages = len(pagesRaw)
		for _, r := range pagesRaw {
			var page map[string]interface{}
			json.Unmarshal(r, &page)
			title, _ := page["title"].(string)
			pageID, _ := page["id"].(string)
			output.Verbose("    page: %s", title)

			// If keywords provided, fetch page content and filter
			if len(keywords) > 0 && pageID != "" {
				var contentEndpoint string
				if userID == "" || userID == "me" {
					contentEndpoint = fmt.Sprintf(graph.EndpointMePageContent, pageID)
				} else {
					contentEndpoint = fmt.Sprintf(graph.EndpointUserPageContent, userID, pageID)
				}
				content, err := client.Download(ctx, contentEndpoint)
				if err == nil {
					contentStr := string(content)
					lower := strings.ToLower(contentStr)
					for _, kw := range keywords {
						if strings.Contains(lower, strings.ToLower(strings.TrimSpace(kw))) {
							page["content_snippet"] = contentStr[:min(500, len(contentStr))]
							output.Warn("  KEYWORD HIT in page %q (kw=%s)", title, kw)
							break
						}
					}
				}
			}

			// Attach page to notebook
			parentNB, _ := page["parentNotebook"].(map[string]interface{})
			nbID := ""
			if parentNB != nil {
				nbID, _ = parentNB["id"].(string)
			}
			if nb, ok := nbMap[nbID]; ok {
				pages, _ := nb["pages"].([]interface{})
				nb["pages"] = append(pages, page)
			}
		}
	}

	output.Success("OneNote: %d notebooks | %d sections | %d pages",
		result.TotalNotebooks, result.TotalSections, result.TotalPages)
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
