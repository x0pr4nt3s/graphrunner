package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SPSiteEntry holds a discovered SharePoint drive/site.
type SPSiteEntry struct {
	SiteID string `json:"site_id"`
	WebURL string `json:"web_url"`
}

// SharePointResult holds discovered SharePoint sites.
type SharePointResult struct {
	Sites []SPSiteEntry `json:"sites"`
	Count int           `json:"count"`
}

// SharePoint discovers SharePoint site URLs via the Search API.
// Same technique as PowerShell GraphRunner Get-SharePointSiteURLs:
//
//	Search entityTypes=["drive"] with query "*", extract unique site URLs
//	from each drive's webUrl and parentReference.siteId.
//	Works with Files.Read.All — does NOT need Sites.Read.All.
func SharePoint(ctx context.Context, client *graph.Client) (interface{}, error) {
	output.Info("Searching for SharePoint drives (entityTypes: drive)...")

	seenSiteIDs := map[string]bool{}
	var entries []SPSiteEntry
	pageSize := 500

	// Paginate through search results (Search API caps at 500 per page)
	for from := 0; ; from += pageSize {
		searchReq := []map[string]interface{}{
			{
				"entityTypes": []string{"drive"},
				"query":       map[string]string{"queryString": "*"},
				"from":        from,
				"size":        pageSize,
				"fields":      []string{"parentReference", "webUrl"},
			},
		}

		raw, err := client.SearchQuery(ctx, searchReq)
		if err != nil {
			if from == 0 {
				return nil, fmt.Errorf("drive search failed: %w", err)
			}
			break // partial results are fine
		}

		var searchResp map[string]interface{}
		if err := json.Unmarshal(raw, &searchResp); err != nil {
			if from == 0 {
				return nil, fmt.Errorf("parse search response: %w", err)
			}
			break
		}

		hitsThisPage := 0
		valueArr, _ := searchResp["value"].([]interface{})
		for _, v := range valueArr {
			vMap, _ := v.(map[string]interface{})
			hitsContainers, _ := vMap["hitsContainers"].([]interface{})
			for _, hc := range hitsContainers {
				hcMap, _ := hc.(map[string]interface{})
				moreAvailable, _ := hcMap["moreResultsAvailable"].(bool)
				hits, _ := hcMap["hits"].([]interface{})
				hitsThisPage += len(hits)
				for _, hit := range hits {
					hitMap, _ := hit.(map[string]interface{})
					if hitMap == nil {
						continue
					}
					resource, _ := hitMap["resource"].(map[string]interface{})
					if resource == nil {
						continue
					}

					webURL, _ := resource["webUrl"].(string)
					parentRef, _ := resource["parentReference"].(map[string]interface{})
					siteID := ""
					if parentRef != nil {
						siteID, _ = parentRef["siteId"].(string)
					}

					key := siteID
					if key == "" {
						key = webURL
					}
					if seenSiteIDs[key] {
						continue
					}
					seenSiteIDs[key] = true

					entries = append(entries, SPSiteEntry{
						SiteID: siteID,
						WebURL: webURL,
					})
				}

				// Stop if API says no more results
				if !moreAvailable {
					hitsThisPage = 0 // signal to break outer loop
				}
			}
		}

		if hitsThisPage == 0 {
			break
		}
		output.Verbose("  Page %d: %d hits, %d unique sites so far", (from/pageSize)+1, hitsThisPage, len(entries))
	}

	// Sort by webUrl (same as GraphRunner PS)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].WebURL < entries[j].WebURL
	})

	result := &SharePointResult{
		Sites: entries,
		Count: len(entries),
	}

	printSharePointResults(result)
	return result, nil
}


func printSharePointResults(result *SharePointResult) {
	output.SearchResultHeader("SharePoint Site URLs", result.Count, "via Search API (drive entity)")

	if result.Count == 0 {
		output.Warn("No SharePoint sites discovered")
		return
	}

	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Site URLs (%d) ", result.Count)))

	for i, site := range result.Sites {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		fmt.Printf("  %s %s\n", num, output.StyleURLInfo.Render(site.WebURL))

		if output.VerboseEnabled && site.SiteID != "" {
			fmt.Printf("       %s %s\n", output.StyleDim.Render("SiteID:"), output.StyleDim.Render(site.SiteID))
		}
	}
	fmt.Println()

	output.SearchDivider()
	fmt.Println()
	output.Success("Found %d SharePoint site URLs", result.Count)
}
