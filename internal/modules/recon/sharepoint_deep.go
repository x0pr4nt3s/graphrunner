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

// SiteInfo holds detailed SharePoint site information.
type SiteInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	WebURL      string `json:"web_url"`
	Description string `json:"description,omitempty"`
	IsPublic    bool   `json:"is_public"`
	Accessible  bool   `json:"accessible"`

	// Sharing / external access
	SharingCapability string `json:"sharing_capability,omitempty"`

	// Sub-resources
	Lists  []map[string]interface{} `json:"lists,omitempty"`
	Drives []map[string]interface{} `json:"drives,omitempty"`

	// Permissions (if readable)
	Permissions []map[string]interface{} `json:"permissions,omitempty"`

	// Access error if the site is not accessible
	AccessError string `json:"access_error,omitempty"`
}

// SharePointDeepResult holds deep SharePoint enumeration results.
type SharePointDeepResult struct {
	TotalSites     int        `json:"total_sites"`
	AccessibleCount int       `json:"accessible_count"`
	PublicCount    int        `json:"public_count"`
	Sites          []SiteInfo `json:"sites"`
}

// SharePointDeep performs a comprehensive SharePoint site enumeration:
// 1. Discovers all sites via search API
// 2. Also enumerates via /sites?search= for broader coverage
// 3. Checks each site's accessibility, permissions, drives, and lists
// 4. Identifies publicly accessible / externally shared sites
func SharePointDeep(ctx context.Context, client *graph.Client) (interface{}, error) {
	result := &SharePointDeepResult{}
	siteMap := make(map[string]*SiteInfo) // deduplicate by ID

	// Method 1: Search API (gets sites user has interacted with)
	output.Info("Discovering SharePoint sites via search API...")
	searchSites, _ := discoverViaSearch(ctx, client)
	for _, s := range searchSites {
		if _, exists := siteMap[s.ID]; !exists {
			siteMap[s.ID] = &s
		}
	}
	output.Info("  Search API: found %d sites", len(searchSites))

	// Method 2: /sites?search= (broader, gets all sites the token can see)
	output.Info("Discovering SharePoint sites via /sites endpoint...")
	listSites, _ := discoverViaListEndpoint(ctx, client)
	for _, s := range listSites {
		if _, exists := siteMap[s.ID]; !exists {
			siteMap[s.ID] = &s
		}
	}
	output.Info("  Sites endpoint: found %d additional sites", len(listSites))

	// Method 3: Try root site
	output.Info("Checking root site...")
	rootSite, err := discoverRootSite(ctx, client)
	if err == nil && rootSite.ID != "" {
		if _, exists := siteMap[rootSite.ID]; !exists {
			siteMap[rootSite.ID] = rootSite
		}
	}

	// Method 4: M365 Groups → associated SharePoint sites
	beforeGroups := len(siteMap)
	output.Info("Discovering SharePoint sites via M365 Groups...")
	groupSites, _ := discoverViaGroups(ctx, client)
	for _, s := range groupSites {
		if _, exists := siteMap[s.ID]; !exists {
			siteMap[s.ID] = &s
		}
	}
	output.Info("  M365 Groups: found %d sites (%d new)", len(groupSites), len(siteMap)-beforeGroups)

	// Method 5: /sites/getAllSites (admin — requires Sites.Read.All application permission)
	beforeAdmin := len(siteMap)
	output.Info("Trying admin endpoint /sites/getAllSites...")
	adminSites, adminErr := discoverViaGetAllSites(ctx, client)
	if adminErr != nil {
		output.Verbose("  getAllSites not available (expected with delegated tokens): %v", adminErr)
	} else {
		for _, s := range adminSites {
			if _, exists := siteMap[s.ID]; !exists {
				siteMap[s.ID] = &s
			}
		}
		output.Info("  Admin endpoint: found %d sites (%d new)", len(adminSites), len(siteMap)-beforeAdmin)
	}

	// Now deep-inspect each site
	output.Info("Deep inspecting %d sites...", len(siteMap))
	externalCount := 0
	inspIdx := 0
	for id, site := range siteMap {
		inspIdx++
		inspectSite(ctx, client, site)
		siteMap[id] = site

		if site.Accessible {
			result.AccessibleCount++
		}
		if site.IsPublic {
			result.PublicCount++
		}
		if site.SharingCapability != "" && strings.Contains(site.SharingCapability, "External") {
			externalCount++
		}

		output.Verbose("[%d/%d] %s — %s", inspIdx, len(siteMap), site.DisplayName, site.WebURL)
	}

	// Collect into slice, sorted (accessible first)
	for _, site := range siteMap {
		result.Sites = append(result.Sites, *site)
	}
	result.TotalSites = len(result.Sites)

	// Pretty output
	printSharePointDeepResults(result, externalCount)

	return result, nil
}

// discoverViaSearch uses the Graph search API to find sites.
// Tries entityTypes "site" first, then falls back to "drive" (which works with
// more token audiences) and extracts unique sites from drive results.
func discoverViaSearch(ctx context.Context, client *graph.Client) ([]SiteInfo, error) {
	var sites []SiteInfo
	seenIDs := map[string]bool{}

	// Attempt 1: search for "site" entities (ideal — returns site metadata directly)
	for from := 0; ; from += 500 {
		searchReq := []map[string]interface{}{
			{
				"entityTypes": []string{"site"},
				"query":       map[string]string{"queryString": "*"},
				"from":        from,
				"size":        500,
			},
		}
		raw, err := client.SearchQuery(ctx, searchReq)
		if err != nil {
			break
		}
		n := extractSiteHits(raw, seenIDs, &sites)
		if n == 0 {
			break
		}
		output.Verbose("  Search (site): page %d, %d hits, %d unique", (from/500)+1, n, len(sites))
	}

	// Attempt 2: if "site" returned nothing, try "drive" (works with Files.Read.All tokens)
	if len(sites) == 0 {
		output.Verbose("  Search (site) returned 0 — falling back to drive entity search")
		for from := 0; ; from += 500 {
			searchReq := []map[string]interface{}{
				{
					"entityTypes": []string{"drive"},
					"query":       map[string]string{"queryString": "*"},
					"from":        from,
					"size":        500,
					"fields":      []string{"parentReference", "webUrl"},
				},
			}
			raw, err := client.SearchQuery(ctx, searchReq)
			if err != nil {
				break
			}
			n := extractDriveHits(raw, seenIDs, &sites)
			if n == 0 {
				break
			}
			output.Verbose("  Search (drive): page %d, %d hits, %d unique sites", (from/500)+1, n, len(sites))
		}
	}

	return sites, nil
}

// extractSiteHits parses search results with entityTypes=["site"].
func extractSiteHits(raw []byte, seen map[string]bool, out *[]SiteInfo) int {
	var resp map[string]interface{}
	json.Unmarshal(raw, &resp)

	count := 0
	valueArr, _ := resp["value"].([]interface{})
	for _, v := range valueArr {
		vMap, _ := v.(map[string]interface{})
		hitsContainers, _ := vMap["hitsContainers"].([]interface{})
		for _, hc := range hitsContainers {
			hcMap, _ := hc.(map[string]interface{})
			hits, _ := hcMap["hits"].([]interface{})
			count += len(hits)
			for _, hit := range hits {
				hitMap, _ := hit.(map[string]interface{})
				resource, _ := hitMap["resource"].(map[string]interface{})
				if resource == nil {
					continue
				}
				id := getString(resource, "id")
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				*out = append(*out, SiteInfo{
					ID:          id,
					DisplayName: getString(resource, "displayName"),
					WebURL:      getString(resource, "webUrl"),
					Description: getString(resource, "description"),
					Accessible:  true,
				})
			}
		}
	}
	return count
}

// extractDriveHits parses search results with entityTypes=["drive"] and
// deduplicates by parentReference.siteId, resolving the site URL from the drive webUrl.
func extractDriveHits(raw []byte, seen map[string]bool, out *[]SiteInfo) int {
	var resp map[string]interface{}
	json.Unmarshal(raw, &resp)

	count := 0
	valueArr, _ := resp["value"].([]interface{})
	for _, v := range valueArr {
		vMap, _ := v.(map[string]interface{})
		hitsContainers, _ := vMap["hitsContainers"].([]interface{})
		for _, hc := range hitsContainers {
			hcMap, _ := hc.(map[string]interface{})
			hits, _ := hcMap["hits"].([]interface{})
			count += len(hits)
			for _, hit := range hits {
				hitMap, _ := hit.(map[string]interface{})
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
				if key == "" || seen[key] {
					continue
				}
				seen[key] = true

				*out = append(*out, SiteInfo{
					ID:          siteID, // siteId from parentReference (may differ from site resource id)
					DisplayName: webURL, // best we have from drive results
					WebURL:      webURL,
					Accessible:  true,
				})
			}
		}
	}
	return count
}

// discoverViaListEndpoint uses /sites?search= to find sites.
func discoverViaListEndpoint(ctx context.Context, client *graph.Client) ([]SiteInfo, error) {
	var sites []SiteInfo

	// Search with wildcard
	raw, err := client.GetAll(ctx, graph.EndpointSites, map[string]string{
		"search":  "*",
		"$select": "id,displayName,webUrl,description,isPersonalSpace",
		"$top":    "999",
	})
	if err != nil {
		// Try without search param (some tenants don't allow it)
		raw, err = client.GetAll(ctx, graph.EndpointSites, map[string]string{
			"$select": "id,displayName,webUrl,description",
			"$top":    "999",
		})
		if err != nil {
			return nil, err
		}
	}

	for _, r := range raw {
		var site map[string]interface{}
		json.Unmarshal(r, &site)

		// Skip personal sites (OneDrive)
		isPersonal, _ := site["isPersonalSpace"].(bool)
		if isPersonal {
			continue
		}

		sites = append(sites, SiteInfo{
			ID:          getString(site, "id"),
			DisplayName: getString(site, "displayName"),
			WebURL:      getString(site, "webUrl"),
			Description: getString(site, "description"),
			Accessible:  true,
		})
	}

	return sites, nil
}

// discoverRootSite gets the root SharePoint site.
func discoverRootSite(ctx context.Context, client *graph.Client) (*SiteInfo, error) {
	raw, err := client.Get(ctx, graph.EndpointSiteRoot, map[string]string{
		"$select": "id,displayName,webUrl,description",
	})
	if err != nil {
		return nil, err
	}

	var site map[string]interface{}
	json.Unmarshal(raw, &site)

	return &SiteInfo{
		ID:          getString(site, "id"),
		DisplayName: getString(site, "displayName"),
		WebURL:      getString(site, "webUrl"),
		Description: getString(site, "description"),
		Accessible:  true,
	}, nil
}

// inspectSite checks a site's permissions, drives, lists, and sharing settings.
// Detects public sites by checking the associated M365 group visibility and permission grants.
func inspectSite(ctx context.Context, client *graph.Client, site *SiteInfo) {
	if site.ID == "" {
		return
	}

	// Check if site is still accessible by fetching it directly
	siteEndpoint := fmt.Sprintf(graph.EndpointSiteByID, site.ID)
	siteRaw, err := client.Get(ctx, siteEndpoint, map[string]string{
		"$select": "id,displayName,webUrl,description,siteCollection",
	})
	if err != nil {
		site.Accessible = false
		site.AccessError = err.Error()
		return
	}
	site.Accessible = true

	var siteData map[string]interface{}
	json.Unmarshal(siteRaw, &siteData)

	// Enumerate drives (document libraries)
	drivesEndpoint := fmt.Sprintf(graph.EndpointSiteDrives, site.ID)
	drivesRaw, err := client.GetAll(ctx, drivesEndpoint, map[string]string{
		"$select": "id,name,webUrl,driveType,quota",
	})
	if err == nil {
		site.Drives = unmarshalAll(drivesRaw)
	}

	// Enumerate lists
	listsEndpoint := fmt.Sprintf(graph.EndpointSiteLists, site.ID)
	listsRaw, err := client.GetAll(ctx, listsEndpoint, map[string]string{
		"$select": "id,displayName,webUrl,list",
		"$top":    "100",
	})
	if err == nil {
		site.Lists = unmarshalAll(listsRaw)
	}

	// Check permissions (requires Sites.FullControl.All for detailed perms, but try anyway)
	permsEndpoint := fmt.Sprintf(graph.EndpointSitePermissions, site.ID)
	permsRaw, err := client.GetAll(ctx, permsEndpoint, nil)
	if err == nil {
		site.Permissions = unmarshalAll(permsRaw)
		// Check if "Everyone" or "Everyone except external users" has access
		for _, perm := range site.Permissions {
			grantedTo, _ := perm["grantedToIdentitiesV2"].([]interface{})
			for _, gt := range grantedTo {
				gtMap, _ := gt.(map[string]interface{})
				user, _ := gtMap["user"].(map[string]interface{})
				displayName, _ := user["displayName"].(string)
				if displayName == "Everyone" || displayName == "Everyone except external users" {
					site.IsPublic = true
					output.Verbose("[sharepoint-deep] PUBLIC via permissions: %s (%s)", site.DisplayName, displayName)
				}
			}
			// Also check grantedToV2 (single identity)
			grantedToV2, _ := perm["grantedToV2"].(map[string]interface{})
			if grantedToV2 != nil {
				user, _ := grantedToV2["user"].(map[string]interface{})
				displayName, _ := user["displayName"].(string)
				if displayName == "Everyone" || displayName == "Everyone except external users" {
					site.IsPublic = true
				}
			}
		}
	}

	// Method 2: Check associated M365 group visibility
	// Site IDs look like: contoso.sharepoint.com,guid1,guid2 — we need the group associated with the site
	detectPublicViaGroup(ctx, client, site)

	// Method 3: Check sharing capability via beta endpoint
	detectSharingCapability(ctx, client, site)
}

// detectPublicViaGroup checks if the M365 group backing this site has visibility "Public".
func detectPublicViaGroup(ctx context.Context, client *graph.Client, site *SiteInfo) {
	// Try to get the site's associated group via /sites/{id}/groups (beta)
	// This doesn't work for all sites, so we try a different approach:
	// Search groups whose mailNickname matches the site name pattern
	if site.WebURL == "" {
		return
	}

	// Extract group by checking /groups and matching the site URL pattern
	// More reliable: use the sites/{id} endpoint with $expand=sites (not available)
	// Best approach: check all groups with visibility=Public and resourceProvisioningOptions contains "Team"
	// But that's expensive. Instead, just try /sites/{id}/drive and check owner info.

	// Simplest reliable method: fetch drives and check if the drive owner is a public group
	for _, drv := range site.Drives {
		owner, _ := drv["owner"].(map[string]interface{})
		if owner == nil {
			continue
		}
		group, _ := owner["group"].(map[string]interface{})
		if group == nil {
			continue
		}
		groupID, _ := group["id"].(string)
		if groupID == "" {
			continue
		}
		// Fetch group visibility
		groupRaw, err := client.Get(ctx, fmt.Sprintf("/groups/%s", groupID), map[string]string{
			"$select": "id,displayName,visibility",
		})
		if err != nil {
			continue
		}
		var grp map[string]interface{}
		if err := json.Unmarshal(groupRaw, &grp); err != nil {
			continue
		}
		visibility, _ := grp["visibility"].(string)
		if strings.EqualFold(visibility, "Public") {
			site.IsPublic = true
			output.Verbose("[sharepoint-deep] PUBLIC via group visibility: %s (group: %s)",
				site.DisplayName, getString(grp, "displayName"))
		}
		break // Only need to check one drive owner
	}
}

// detectSharingCapability checks the site's sharing settings via the beta API.
func detectSharingCapability(ctx context.Context, client *graph.Client, site *SiteInfo) {
	// Use beta endpoint to get sharingCapability
	client.UseBeta()
	defer client.UseV1()

	siteEndpoint := fmt.Sprintf("/sites/%s", site.ID)
	raw, err := client.Get(ctx, siteEndpoint, map[string]string{
		"$select": "sharingCapability",
	})
	if err != nil {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	capability, _ := data["sharingCapability"].(string)
	if capability != "" {
		site.SharingCapability = capability
		// "ExternalUserAndGuestSharing" or "ExternalUserSharingOnly" = externally shared
		if strings.Contains(capability, "External") {
			output.Verbose("[sharepoint-deep] External sharing enabled: %s (%s)", site.DisplayName, capability)
		}
	}
}

// discoverViaGroups enumerates M365 (Unified) Groups and fetches each group's SharePoint site.
// This catches Team sites and group-connected sites that may not appear in search or /sites.
// groupInfo holds parsed M365 group metadata for concurrent resolution.
type groupInfo struct {
	ID          string
	DisplayName string
	Visibility  string
}

func discoverViaGroups(ctx context.Context, client *graph.Client) ([]SiteInfo, error) {
	// Get all Unified Groups (M365 Groups)
	groupsRaw, err := client.GetAll(ctx, graph.EndpointGroups, map[string]string{
		"$filter": "groupTypes/any(g:g eq 'Unified')",
		"$select": "id,displayName,visibility,mailNickname",
		"$top":    "999",
	})
	if err != nil {
		return nil, fmt.Errorf("list M365 groups: %w", err)
	}

	// Parse all groups
	var groups []groupInfo
	for _, gr := range groupsRaw {
		var grp groupInfo
		if err := json.Unmarshal(gr, &grp); err != nil || grp.ID == "" {
			continue
		}
		groups = append(groups, grp)
	}
	output.Verbose("  Found %d M365 Groups, resolving SharePoint sites (10 workers)...", len(groups))

	// Concurrent resolution with 10 workers
	const workers = 20
	type result struct {
		info SiteInfo
		ok   bool
	}

	jobs := make(chan groupInfo, len(groups))
	results := make(chan result, len(groups))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for grp := range jobs {
				siteRaw, err := client.Get(ctx, fmt.Sprintf(graph.EndpointGroupSiteRoot, grp.ID), map[string]string{
					"$select": "id,displayName,webUrl,description",
				})
				if err != nil {
					results <- result{ok: false}
					continue
				}
				var site map[string]interface{}
				if err := json.Unmarshal(siteRaw, &site); err != nil {
					results <- result{ok: false}
					continue
				}
				id := getString(site, "id")
				if id == "" {
					results <- result{ok: false}
					continue
				}
				info := SiteInfo{
					ID:          id,
					DisplayName: getString(site, "displayName"),
					WebURL:      getString(site, "webUrl"),
					Description: getString(site, "description"),
					Accessible:  true,
					IsPublic:    strings.EqualFold(grp.Visibility, "Public"),
				}
				results <- result{info: info, ok: true}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, grp := range groups {
			jobs <- grp
		}
		close(jobs)
	}()

	// Close results when all workers done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var sites []SiteInfo
	resolved, skipped, public := 0, 0, 0
	for r := range results {
		resolved++
		if resolved%500 == 0 {
			output.Verbose("  [groups] %d/%d resolved (%d sites found, %d public)", resolved, len(groups), len(sites), public)
		}
		if !r.ok {
			skipped++
			continue
		}
		if r.info.IsPublic {
			public++
			output.Verbose("  [PUBLIC] %s", r.info.DisplayName)
		}
		sites = append(sites, r.info)
	}
	output.Verbose("  [groups] Done: %d resolved, %d accessible, %d skipped, %d public", resolved, len(sites), skipped, public)

	return sites, nil
}

// discoverViaGetAllSites uses the admin endpoint /sites/getAllSites.
// Requires Sites.Read.All application permission — will fail with delegated tokens.
func discoverViaGetAllSites(ctx context.Context, client *graph.Client) ([]SiteInfo, error) {
	var sites []SiteInfo

	raw, err := client.GetAll(ctx, graph.EndpointAllSites, map[string]string{
		"$select": "id,displayName,webUrl",
		"$top":    "999",
	})
	if err != nil {
		return nil, err
	}

	for _, r := range raw {
		var site struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			WebURL      string `json:"webUrl"`
		}
		if err := json.Unmarshal(r, &site); err != nil || site.ID == "" {
			continue
		}
		// Skip OneDrive personal sites (contain /personal/ in URL)
		if strings.Contains(site.WebURL, "/personal/") || strings.Contains(site.WebURL, "-my.sharepoint.com") {
			continue
		}
		sites = append(sites, SiteInfo{
			ID:          site.ID,
			DisplayName: site.DisplayName,
			WebURL:      site.WebURL,
			Accessible:  true,
		})
	}

	return sites, nil
}

func getString(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func printSharePointDeepResults(result *SharePointDeepResult, externalCount int) {
	subtitle := fmt.Sprintf("%d accessible, %d public", result.AccessibleCount, result.PublicCount)
	if externalCount > 0 {
		subtitle += fmt.Sprintf(", %d external sharing", externalCount)
	}
	output.SearchResultHeader("SharePoint Deep Scan", result.TotalSites, subtitle)

	if result.TotalSites == 0 {
		output.Warn("No SharePoint sites found")
		return
	}

	// Summary box
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(" Overview "))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Total sites:")),
		output.StyleCounter.Render(fmt.Sprintf("%d", result.TotalSites)))
	fmt.Printf("       %s %s\n",
		output.StyleBold.Render(fmt.Sprintf("%-25s", "Accessible:")),
		output.StyleSuccess.Render(fmt.Sprintf("%d", result.AccessibleCount)))
	if result.PublicCount > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "Public:")),
			output.StyleCritical.Render(fmt.Sprintf("%d", result.PublicCount)))
	} else {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "Public:")),
			output.StyleDim.Render("0"))
	}
	if externalCount > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "External sharing:")),
			output.StyleMedium.Render(fmt.Sprintf("%d", externalCount)))
	}
	denied := result.TotalSites - result.AccessibleCount
	if denied > 0 {
		fmt.Printf("       %s %s\n",
			output.StyleBold.Render(fmt.Sprintf("%-25s", "Access denied:")),
			output.StyleError.Render(fmt.Sprintf("%d", denied)))
	}
	fmt.Println()

	// Site list
	fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Sites (%d) ", result.TotalSites)))

	for i, site := range result.Sites {
		num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
		nameStyled := output.StyleBold.Render(site.DisplayName)

		// Accessibility tag
		accessTag := output.StyleSuccess.Render("[ACCESSIBLE]")
		if !site.Accessible {
			accessTag = output.StyleError.Render("[DENIED]")
		}

		// Public tag
		publicTag := ""
		if site.IsPublic {
			publicTag = " " + output.StyleCritical.Render("[PUBLIC]")
		}

		// External sharing tag
		extTag := ""
		if site.SharingCapability != "" && strings.Contains(site.SharingCapability, "External") {
			extTag = " " + output.StyleMedium.Render("[EXT-SHARE]")
		}

		// Line 1: number + name + tags
		fmt.Printf("  %s %s  %s%s%s\n", num, nameStyled, accessTag, publicTag, extTag)

		// Line 2: URL dimmed
		if site.WebURL != "" {
			urlDisplay := site.WebURL
			if len(urlDisplay) > 100 {
				urlDisplay = urlDisplay[:97] + "..."
			}
			fmt.Printf("       %s\n", output.StyleDim.Render(urlDisplay))
		}

		// Line 3: stats inline
		stats := ""
		if len(site.Drives) > 0 {
			stats += output.StyleDim.Render("Drives: ") + output.StyleCounter.Render(fmt.Sprintf("%d", len(site.Drives))) + "  "
		}
		if len(site.Lists) > 0 {
			stats += output.StyleDim.Render("Lists: ") + output.StyleCounter.Render(fmt.Sprintf("%d", len(site.Lists))) + "  "
		}
		if len(site.Permissions) > 0 {
			stats += output.StyleDim.Render("Perms: ") + output.StyleCounter.Render(fmt.Sprintf("%d", len(site.Permissions))) + "  "
		}
		if site.SharingCapability != "" {
			stats += output.StyleDim.Render("Sharing: ") + output.StyleInfo.Render(site.SharingCapability)
		}
		if stats != "" {
			fmt.Printf("       %s\n", stats)
		}

		// Verbose: show drive/list details
		if output.VerboseEnabled {
			for _, drv := range site.Drives {
				drvName, _ := drv["name"].(string)
				drvType, _ := drv["driveType"].(string)
				drvURL, _ := drv["webUrl"].(string)
				fmt.Printf("         %s %s  %s  %s\n",
					output.StyleFolderIcon.Render("[DRV]"),
					output.StyleBold.Render(drvName),
					output.StyleDim.Render(drvType),
					output.StyleDim.Render(drvURL))
			}
			for _, lst := range site.Lists {
				lstName, _ := lst["displayName"].(string)
				lstURL, _ := lst["webUrl"].(string)
				fmt.Printf("         %s %s  %s\n",
					output.StyleFileIcon.Render("[LST]"),
					output.StyleBold.Render(lstName),
					output.StyleDim.Render(lstURL))
			}
		}

		// Access error if denied
		if site.AccessError != "" && output.VerboseEnabled {
			fmt.Printf("       %s %s\n", output.StyleError.Render("Error:"), output.StyleDim.Render(site.AccessError))
		}

		fmt.Println()
	}

	if !output.VerboseEnabled {
		output.Dim("Use -v for drive/list details per site")
	}

	// Risk summary
	output.SearchDivider()
	if result.PublicCount > 0 {
		output.Critical("%d site(s) are PUBLIC — accessible to all tenant users", result.PublicCount)
	}
	if externalCount > 0 {
		output.Warn("%d site(s) have EXTERNAL SHARING enabled", externalCount)
	}
	denied2 := result.TotalSites - result.AccessibleCount
	if denied2 > 0 {
		output.Dim("%d site(s) returned access denied", denied2)
	}

	fmt.Println()
	output.Success("SharePoint Deep Scan: %d sites | %d accessible | %d public",
		result.TotalSites, result.AccessibleCount, result.PublicCount)
}
