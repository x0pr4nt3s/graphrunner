package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SPAuditSite holds the audit info for a single SharePoint site.
type SPAuditSite struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"display_name"`
	WebURL            string   `json:"web_url"`
	Description       string   `json:"description,omitempty"`
	IsPublic          bool     `json:"is_public"`
	GroupVisibility   string   `json:"group_visibility,omitempty"`
	SharingCapability string   `json:"sharing_capability,omitempty"`
	ExternalSharing   bool     `json:"external_sharing_enabled"`
	DriveCount        int      `json:"drive_count"`
	ListCount         int      `json:"list_count"`
	FileCount         int      `json:"file_count"`
	TotalSize         int64    `json:"total_size_bytes,omitempty"`
	TotalSizeHuman    string   `json:"total_size,omitempty"`
	OwnerGroup        string   `json:"owner_group,omitempty"`
	OwnerGroupID      string   `json:"owner_group_id,omitempty"`
	Risks             []string `json:"risks,omitempty"`
}

// SPAuditResult holds the full SharePoint audit report.
type SPAuditResult struct {
	Sites            []SPAuditSite `json:"sites"`
	TotalSites       int           `json:"total_sites"`
	AccessibleSites  int           `json:"accessible_sites"`
	PublicSites      int           `json:"public_sites"`
	ExternalSharing  int           `json:"external_sharing_enabled"`
	TotalDrives      int           `json:"total_drives"`
	TotalFiles       int           `json:"total_files"`
	TotalSizeBytes   int64         `json:"total_size_bytes"`
	TotalSizeHuman   string        `json:"total_size"`
	RiskySites       []SPAuditSite `json:"risky_sites"`
}

// SPAudit performs a comprehensive SharePoint site audit from the current user's perspective.
// Discovers all sites visible to the token, checks access, group visibility, sharing settings,
// drive stats, and file counts. Reports exposure and risks.
func SPAudit(ctx context.Context, c *graph.Client) (*SPAuditResult, error) {
	result := &SPAuditResult{}
	siteMap := make(map[string]*SPAuditSite)

	// Phase 1: Discover all sites visible to us
	output.Info("Phase 1: Discovering all visible SharePoint sites...")

	// Method A: /sites?search=* (broadest)
	sitesRaw, err := c.GetAll(ctx, "/sites", map[string]string{
		"search":  "*",
		"$select": "id,displayName,webUrl,description",
		"$top":    "999",
	})
	if err != nil {
		// Fallback without search param
		sitesRaw, err = c.GetAll(ctx, "/sites", map[string]string{
			"$select": "id,displayName,webUrl,description",
			"$top":    "999",
		})
		if err != nil {
			output.Warn("Sites endpoint: %v", err)
		}
	}
	for _, r := range sitesRaw {
		var s struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			WebURL      string `json:"webUrl"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(r, &s); err == nil && s.ID != "" {
			siteMap[s.ID] = &SPAuditSite{
				ID:          s.ID,
				DisplayName: s.DisplayName,
				WebURL:      s.WebURL,
				Description: s.Description,
			}
		}
	}
	output.Success("  /sites endpoint: %d sites", len(siteMap))

	// Method B: Search API — try "site" first, fallback to "drive"
	searchBefore := len(siteMap)
	for _, entityType := range []string{"site", "drive"} {
		if entityType == "drive" && len(siteMap)-searchBefore > 0 {
			break // "site" worked, skip drive fallback
		}
		for from := 0; ; from += 500 {
			searchReq := []map[string]interface{}{
				{
					"entityTypes": []string{entityType},
					"query":       map[string]string{"queryString": "*"},
					"from":        from,
					"size":        500,
				},
			}
			if entityType == "drive" {
				searchReq[0]["fields"] = []string{"parentReference", "webUrl"}
			}
			searchRaw, sErr := c.SearchQuery(ctx, searchReq)
			if sErr != nil {
				break
			}
			var searchResp map[string]interface{}
			json.Unmarshal(searchRaw, &searchResp)

			hitsThisPage := 0
			valueArr, _ := searchResp["value"].([]interface{})
			for _, v := range valueArr {
				vMap, _ := v.(map[string]interface{})
				hitsContainers, _ := vMap["hitsContainers"].([]interface{})
				for _, hc := range hitsContainers {
					hcMap, _ := hc.(map[string]interface{})
					hits, _ := hcMap["hits"].([]interface{})
					hitsThisPage += len(hits)
					for _, hit := range hits {
						hitMap, _ := hit.(map[string]interface{})
						resource, _ := hitMap["resource"].(map[string]interface{})
						if resource == nil {
							continue
						}
						var id, name, webURL string
						if entityType == "site" {
							id = getString(resource, "id")
							name = getString(resource, "displayName")
							webURL = getString(resource, "webUrl")
						} else {
							// drive: deduplicate by parentReference.siteId
							parentRef, _ := resource["parentReference"].(map[string]interface{})
							if parentRef != nil {
								id, _ = parentRef["siteId"].(string)
							}
							webURL, _ = resource["webUrl"].(string)
							name = webURL
						}
						if id == "" {
							id = webURL
						}
						if id != "" {
							if _, exists := siteMap[id]; !exists {
								siteMap[id] = &SPAuditSite{
									ID:          id,
									DisplayName: name,
									WebURL:      webURL,
								}
							}
						}
					}
				}
			}
			if hitsThisPage == 0 {
				break
			}
			output.Verbose("  Search (%s): page %d, %d hits", entityType, (from/500)+1, hitsThisPage)
		}
	}
	output.Success("  Search API: %d new sites", len(siteMap)-searchBefore)
	output.Success("  Total unique sites discovered: %d", len(siteMap))

	// Method C: Root site
	rootRaw, err := c.Get(ctx, "/sites/root", map[string]string{"$select": "id,displayName,webUrl"})
	if err == nil {
		var root struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			WebURL      string `json:"webUrl"`
		}
		if json.Unmarshal(rootRaw, &root) == nil && root.ID != "" {
			if _, exists := siteMap[root.ID]; !exists {
				siteMap[root.ID] = &SPAuditSite{
					ID:          root.ID,
					DisplayName: root.DisplayName,
					WebURL:      root.WebURL,
				}
			}
		}
	}

	// Method D: M365 Groups → associated SharePoint sites (10 concurrent workers)
	beforeGroups := len(siteMap)
	output.Info("  Discovering via M365 Groups (concurrent)...")
	groupsRaw, gErr := c.GetAll(ctx, graph.EndpointGroups, map[string]string{
		"$filter": "groupTypes/any(g:g eq 'Unified')",
		"$select": "id,displayName,visibility",
		"$top":    "999",
	})
	if gErr == nil {
		// Parse groups
		type grpEntry struct {
			ID, DisplayName, Visibility string
		}
		var groups []grpEntry
		for _, gr := range groupsRaw {
			var g grpEntry
			if json.Unmarshal(gr, &g) == nil && g.ID != "" {
				groups = append(groups, g)
			}
		}
		output.Verbose("  Found %d M365 Groups, resolving sites (10 workers)...", len(groups))

		type grpSiteResult struct {
			site       SPAuditSite
			ok         bool
		}
		const workers = 20
		jobs := make(chan grpEntry, len(groups))
		results := make(chan grpSiteResult, len(groups))

		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for grp := range jobs {
					siteRaw, sErr := c.Get(ctx, fmt.Sprintf(graph.EndpointGroupSiteRoot, grp.ID), map[string]string{
						"$select": "id,displayName,webUrl",
					})
					if sErr != nil {
						results <- grpSiteResult{ok: false}
						continue
					}
					var gs struct {
						ID          string `json:"id"`
						DisplayName string `json:"displayName"`
						WebURL      string `json:"webUrl"`
					}
					if json.Unmarshal(siteRaw, &gs) != nil || gs.ID == "" {
						results <- grpSiteResult{ok: false}
						continue
					}
					site := SPAuditSite{
						ID:              gs.ID,
						DisplayName:     gs.DisplayName,
						WebURL:          gs.WebURL,
						OwnerGroup:      grp.DisplayName,
						OwnerGroupID:    grp.ID,
						GroupVisibility: grp.Visibility,
					}
					if strings.EqualFold(grp.Visibility, "Public") {
						site.IsPublic = true
						site.Risks = append(site.Risks, "Public group — all tenant users can access")
					}
					results <- grpSiteResult{site: site, ok: true}
				}
			}()
		}
		go func() {
			for _, grp := range groups {
				jobs <- grp
			}
			close(jobs)
		}()
		go func() {
			wg.Wait()
			close(results)
		}()

		resolved := 0
		for r := range results {
			resolved++
			if resolved%500 == 0 {
				output.Verbose("  [groups] %d/%d resolved", resolved, len(groups))
			}
			if !r.ok {
				continue
			}
			if _, exists := siteMap[r.site.ID]; !exists {
				s := r.site
				siteMap[s.ID] = &s
			}
		}
	}
	output.Success("  M365 Groups: %d new sites", len(siteMap)-beforeGroups)

	// Method E: /sites/getAllSites (admin — requires Sites.Read.All application permission)
	beforeAdmin := len(siteMap)
	allSitesRaw, aErr := c.GetAll(ctx, graph.EndpointAllSites, map[string]string{
		"$select": "id,displayName,webUrl",
		"$top":    "999",
	})
	if aErr == nil {
		for _, r := range allSitesRaw {
			var as struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				WebURL      string `json:"webUrl"`
			}
			if json.Unmarshal(r, &as) != nil || as.ID == "" || strings.Contains(as.WebURL, "/personal/") || strings.Contains(as.WebURL, "-my.sharepoint.com") {
				continue
			}
			if _, exists := siteMap[as.ID]; !exists {
				siteMap[as.ID] = &SPAuditSite{
					ID:          as.ID,
					DisplayName: as.DisplayName,
					WebURL:      as.WebURL,
				}
			}
		}
		output.Success("  Admin getAllSites: %d new sites", len(siteMap)-beforeAdmin)
	} else {
		output.Verbose("  getAllSites not available: %v", aErr)
	}

	output.Success("  Total unique sites after all methods: %d", len(siteMap))

	// Phase 2: Audit each site
	output.Info("Phase 2: Auditing %d sites (access, groups, sharing, drives)...", len(siteMap))
	idx := 0
	for _, site := range siteMap {
		idx++
		output.Verbose("[%d/%d] Auditing: %s", idx, len(siteMap), site.DisplayName)
		auditSingleSite(ctx, c, site)

		result.TotalDrives += site.DriveCount
		result.TotalFiles += site.FileCount
		result.TotalSizeBytes += site.TotalSize
		if site.IsPublic {
			result.PublicSites++
		}
		if site.ExternalSharing {
			result.ExternalSharing++
		}
		result.AccessibleSites++
	}

	// Phase 3: Build report
	output.Info("Phase 3: Building audit report...")
	for _, site := range siteMap {
		result.Sites = append(result.Sites, *site)
		if len(site.Risks) > 0 {
			result.RiskySites = append(result.RiskySites, *site)
		}
	}
	result.TotalSites = len(result.Sites)
	result.TotalSizeHuman = humanSize(result.TotalSizeBytes)

	// Pretty output
	printSPAuditResults(result)

	return result, nil
}

func auditSingleSite(ctx context.Context, c *graph.Client, site *SPAuditSite) {
	// 1. Enumerate drives and get stats
	drivesRaw, err := c.GetAll(ctx, fmt.Sprintf("/sites/%s/drives", site.ID), map[string]string{
		"$select": "id,name,driveType,quota,owner",
	})
	if err != nil {
		output.Verbose("  [!] Cannot access drives for %s: %v", site.DisplayName, err)
		return
	}
	site.DriveCount = len(drivesRaw)

	for _, dr := range drivesRaw {
		var drive struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Quota *struct {
				Used  int64 `json:"used"`
				Total int64 `json:"total"`
			} `json:"quota"`
			Owner *struct {
				Group *struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
				} `json:"group"`
			} `json:"owner"`
		}
		if err := json.Unmarshal(dr, &drive); err != nil {
			continue
		}

		// Get quota/size
		if drive.Quota != nil {
			site.TotalSize += drive.Quota.Used
		}

		// Get owner group info
		if drive.Owner != nil && drive.Owner.Group != nil && site.OwnerGroupID == "" {
			site.OwnerGroup = drive.Owner.Group.DisplayName
			site.OwnerGroupID = drive.Owner.Group.ID
		}

		// Count files in this drive (top-level count via children)
		childrenRaw, err := c.GetAll(ctx, fmt.Sprintf("/drives/%s/root/children", drive.ID), map[string]string{
			"$select": "id,folder,file",
			"$top":    "999",
		})
		if err == nil {
			for _, ch := range childrenRaw {
				var child struct {
					Folder *struct{} `json:"folder"`
				}
				if json.Unmarshal(ch, &child) == nil {
					if child.Folder == nil {
						site.FileCount++
					}
				}
			}
			// If we can count root children, also count recursively (just top 2 levels for speed)
			countDriveFiles(ctx, c, drive.ID, "root", 0, 2, site)
		}
	}
	site.TotalSizeHuman = humanSize(site.TotalSize)

	// 2. Count lists
	listsRaw, err := c.GetAll(ctx, fmt.Sprintf("/sites/%s/lists", site.ID), map[string]string{
		"$select": "id",
		"$top":    "100",
	})
	if err == nil {
		site.ListCount = len(listsRaw)
	}

	// 3. Check group visibility (if we have owner group)
	if site.OwnerGroupID != "" {
		groupRaw, err := c.Get(ctx, fmt.Sprintf("/groups/%s", site.OwnerGroupID), map[string]string{
			"$select": "id,displayName,visibility",
		})
		if err == nil {
			var grp struct {
				Visibility string `json:"visibility"`
			}
			if json.Unmarshal(groupRaw, &grp) == nil {
				site.GroupVisibility = grp.Visibility
				if strings.EqualFold(grp.Visibility, "Public") {
					site.IsPublic = true
					site.Risks = append(site.Risks, "Public group — all tenant users can access")
				}
			}
		}
	}

	// 4. Check sharing capability (beta)
	c.UseBeta()
	sharingRaw, err := c.Get(ctx, fmt.Sprintf("/sites/%s", site.ID), map[string]string{
		"$select": "sharingCapability",
	})
	c.UseV1()
	if err == nil {
		var sharing struct {
			Capability string `json:"sharingCapability"`
		}
		if json.Unmarshal(sharingRaw, &sharing) == nil && sharing.Capability != "" {
			site.SharingCapability = sharing.Capability
			if strings.Contains(sharing.Capability, "External") {
				site.ExternalSharing = true
				site.Risks = append(site.Risks, fmt.Sprintf("External sharing: %s", sharing.Capability))
			}
		}
	}

	// 5. Check permissions for Everyone access
	permsRaw, err := c.GetAll(ctx, fmt.Sprintf("/sites/%s/permissions", site.ID), nil)
	if err == nil {
		for _, p := range permsRaw {
			var perm map[string]interface{}
			if json.Unmarshal(p, &perm) != nil {
				continue
			}
			checkEveryoneAccess(perm, site)
		}
	}
}

func checkEveryoneAccess(perm map[string]interface{}, site *SPAuditSite) {
	// Check grantedToIdentitiesV2 (array)
	identities, _ := perm["grantedToIdentitiesV2"].([]interface{})
	for _, id := range identities {
		idMap, _ := id.(map[string]interface{})
		user, _ := idMap["user"].(map[string]interface{})
		name, _ := user["displayName"].(string)
		if name == "Everyone" || name == "Everyone except external users" {
			site.IsPublic = true
			site.Risks = appendUnique(site.Risks, fmt.Sprintf("Permission grant to '%s'", name))
		}
	}
	// Check grantedToV2 (single)
	grantedTo, _ := perm["grantedToV2"].(map[string]interface{})
	if grantedTo != nil {
		user, _ := grantedTo["user"].(map[string]interface{})
		name, _ := user["displayName"].(string)
		if name == "Everyone" || name == "Everyone except external users" {
			site.IsPublic = true
			site.Risks = appendUnique(site.Risks, fmt.Sprintf("Permission grant to '%s'", name))
		}
	}
}

func countDriveFiles(ctx context.Context, c *graph.Client, driveID, itemID string, depth, maxDepth int, site *SPAuditSite) {
	if depth >= maxDepth {
		return
	}
	childrenRaw, err := c.GetAll(ctx, fmt.Sprintf("/drives/%s/items/%s/children", driveID, itemID), map[string]string{
		"$select": "id,folder,file",
		"$top":    "999",
	})
	if err != nil {
		return
	}
	for _, ch := range childrenRaw {
		var child struct {
			ID     string   `json:"id"`
			Folder *struct{} `json:"folder"`
		}
		if json.Unmarshal(ch, &child) != nil {
			continue
		}
		if child.Folder != nil {
			countDriveFiles(ctx, c, driveID, child.ID, depth+1, maxDepth, site)
		} else {
			site.FileCount++
		}
	}
}

func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

func printSPAuditResults(result *SPAuditResult) {
	subtitle := fmt.Sprintf("%d drives, %d files, %s", result.TotalDrives, result.TotalFiles, result.TotalSizeHuman)
	output.SearchResultHeader("SharePoint Audit", result.TotalSites, subtitle)

	if result.TotalSites == 0 {
		output.Warn("No SharePoint sites found")
		return
	}

	// Overview section
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Total sites:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalSites)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Accessible:")),
		output.StyleSuccess.Render(fmt.Sprintf("%d", result.AccessibleSites)))
	if result.PublicSites > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "Public:")),
			output.StyleCritical.Render(fmt.Sprintf("%d", result.PublicSites)))
	} else {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "Public:")),
			output.StyleDim.Render("0"))
	}
	if result.ExternalSharing > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "External sharing:")),
			output.StyleMedium.Render(fmt.Sprintf("%d", result.ExternalSharing)))
	} else {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "External sharing:")),
			output.StyleDim.Render("0"))
	}
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Total drives:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalDrives)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Total files:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalFiles)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Total size:")),
		output.StyleHighlight.Render(result.TotalSizeHuman))
	fmt.Println()

	// Risk summary section
	riskySiteCount := len(result.RiskySites)
	if riskySiteCount > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Risk Summary "))
		if result.PublicSites > 0 {
			fmt.Printf("       %s %s\n",
				output.StyleCritical.Render(fmt.Sprintf("%-4d", result.PublicSites)),
				output.StyleCritical.Render("PUBLIC sites (accessible to all tenant users)"))
		}
		if result.ExternalSharing > 0 {
			fmt.Printf("       %s %s\n",
				output.StyleMedium.Render(fmt.Sprintf("%-4d", result.ExternalSharing)),
				output.StyleMedium.Render("sites with EXTERNAL SHARING enabled"))
		}
		fmt.Printf("       %s %s\n",
			output.StyleHigh.Render(fmt.Sprintf("%-4d", riskySiteCount)),
			output.StyleHigh.Render("total sites with identified risks"))
		fmt.Println()
	}

	// Site list
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Sites (%d) ", result.TotalSites)))

	for i, site := range result.Sites {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(site.DisplayName)

		// Tags
		tags := ""
		if site.IsPublic {
			tags += " " + output.StyleCritical.Render("[PUBLIC]")
		}
		if site.ExternalSharing {
			tags += " " + output.StyleMedium.Render("[EXT-SHARE]")
		}
		if len(site.Risks) > 0 {
			tags += " " + output.StyleHigh.Render(fmt.Sprintf("[%d risks]", len(site.Risks)))
		}

		// Stats inline
		stats := ""
		if site.FileCount > 0 {
			stats += output.StyleCounter.Render(fmt.Sprintf("%d", site.FileCount)) + output.StyleDim.Render(" files") + "  "
		}
		if site.TotalSizeHuman != "" && site.TotalSizeHuman != "0 B" {
			stats += output.StyleSizeInfo.Render(site.TotalSizeHuman) + "  "
		}
		if site.DriveCount > 0 {
			stats += output.StyleDim.Render(fmt.Sprintf("%d drives", site.DriveCount))
		}

		// Line 1: number + name + tags
		fmt.Printf("  %s %s%s\n", num, nameStyled, tags)

		// Line 2: stats
		if stats != "" {
			fmt.Printf("       %s\n", stats)
		}

		// Line 3: URL dimmed
		if site.WebURL != "" {
			urlDisplay := site.WebURL
			if len(urlDisplay) > 100 {
				urlDisplay = urlDisplay[:97] + "..."
			}
			fmt.Printf("       %s\n", output.StyleDim.Render(urlDisplay))
		}

		// Verbose: group visibility, sharing capability, owner group
		if output.VerboseEnabled {
			extra := ""
			if site.GroupVisibility != "" {
				visStyle := output.StyleDim.Render(site.GroupVisibility)
				if strings.EqualFold(site.GroupVisibility, "Public") {
					visStyle = output.StyleCritical.Render("Public")
				}
				extra += output.StyleDim.Render("Group: ") + visStyle + "  "
			}
			if site.SharingCapability != "" {
				extra += output.StyleDim.Render("Sharing: ") + output.StyleInfo.Render(site.SharingCapability) + "  "
			}
			if site.OwnerGroup != "" {
				extra += output.StyleDim.Render("Owner: ") + output.StyleUserInfo.Render(site.OwnerGroup)
			}
			if extra != "" {
				fmt.Printf("       %s\n", extra)
			}
		}

		fmt.Println()
	}

	if !output.VerboseEnabled {
		output.Dim("Use -v for group visibility, sharing capability, and owner details")
	}

	// Bar chart: top 10 sites by file count
	type siteFiles struct {
		name  string
		count int
	}
	var ranked []siteFiles
	for _, site := range result.Sites {
		if site.FileCount > 0 {
			ranked = append(ranked, siteFiles{name: site.DisplayName, count: site.FileCount})
		}
	}
	// Simple insertion sort
	for i := 1; i < len(ranked); i++ {
		for j := i; j > 0 && ranked[j].count > ranked[j-1].count; j-- {
			ranked[j], ranked[j-1] = ranked[j-1], ranked[j]
		}
	}
	if len(ranked) > 10 {
		ranked = ranked[:10]
	}
	if len(ranked) > 0 {
		fmt.Println()
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Top Sites by File Count "))
		maxCount := ranked[0].count
		for _, sf := range ranked {
			barLen := 0
			if maxCount > 0 {
				barLen = (sf.count * 30) / maxCount
			}
			if barLen < 1 {
				barLen = 1
			}
			name := sf.name
			if len(name) > 25 {
				name = name[:23] + ".."
			}
			fmt.Printf("       %s %s %s\n",
				output.StyleBold.Render(fmt.Sprintf("%-25s", name)),
				output.StyleProgress.Render(strings.Repeat("█", barLen)),
				output.StyleCounter.Render(fmt.Sprintf("%d", sf.count)))
		}
		fmt.Println()
	}

	// Risky sites section
	if len(result.RiskySites) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Risky Sites (%d) ", len(result.RiskySites))))
		for i, site := range result.RiskySites {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(site.DisplayName)
			fmt.Printf("  %s %s\n", num, nameStyled)
			if site.WebURL != "" {
				fmt.Printf("       %s\n", output.StyleDim.Render(site.WebURL))
			}
			for _, risk := range site.Risks {
				fmt.Printf("       %s %s\n", output.StyleHigh.Render(">>"), risk)
			}
			fmt.Println()
		}
	}

	output.SearchDivider()
	if result.PublicSites > 0 {
		output.Critical("%d site(s) are PUBLIC — accessible to all tenant users", result.PublicSites)
	}
	if result.ExternalSharing > 0 {
		output.Warn("%d site(s) have EXTERNAL SHARING enabled", result.ExternalSharing)
	}

	fmt.Println()
	output.Success("SharePoint Audit: %d sites | %d drives | %d files | %s",
		result.TotalSites, result.TotalDrives, result.TotalFiles, result.TotalSizeHuman)
}

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.1f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
