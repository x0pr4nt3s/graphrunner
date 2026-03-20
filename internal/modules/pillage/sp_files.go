package pillage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SPFileItem represents a file or folder in a SharePoint drive.
type SPFileItem struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	WebURL           string `json:"webUrl"`
	CreatedDateTime  string `json:"createdDateTime"`
	ModifiedDateTime string `json:"lastModifiedDateTime"`
	IsFolder         bool   `json:"is_folder"`
	MimeType         string `json:"mimeType,omitempty"`
	Path             string `json:"path"`
	DriveID          string `json:"driveId"`
	SiteID           string `json:"siteId,omitempty"`
}

// SPFilesOpts holds options for SP file listing.
type SPFilesOpts struct {
	SiteID      string   // SharePoint site ID
	DriveID     string   // specific drive ID (if empty, lists all drives for site)
	MaxDepth    int
	DownloadDir string
	Extensions  []string
}

// SPFilesResult holds SharePoint file listing results.
type SPFilesResult struct {
	SiteID      string       `json:"site_id"`
	Drives      []SPDrive    `json:"drives"`
	Files       []SPFileItem `json:"files"`
	FileCount   int          `json:"file_count"`
	FolderCount int          `json:"folder_count"`
	TotalSize   int64        `json:"total_size_bytes"`
	Downloaded  []string     `json:"downloaded,omitempty"`
	DownloadErr []string     `json:"download_errors,omitempty"`
}

// SPDrive represents a document library in a SharePoint site.
type SPDrive struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	DriveType string `json:"driveType"`
	WebURL    string `json:"webUrl"`
	ItemCount int    `json:"item_count"`
}

// ListSPFiles enumerates files in SharePoint site drives by direct API traversal.
// This does NOT depend on the Search API — it walks drives directly.
func ListSPFiles(ctx context.Context, c *graph.Client, opts SPFilesOpts) (*SPFilesResult, error) {
	result := &SPFilesResult{SiteID: opts.SiteID}

	// Normalize extensions
	for i, ext := range opts.Extensions {
		if !strings.HasPrefix(ext, ".") {
			opts.Extensions[i] = "." + ext
		}
		opts.Extensions[i] = strings.ToLower(opts.Extensions[i])
	}

	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 10
	}

	if opts.DownloadDir != "" {
		if err := os.MkdirAll(opts.DownloadDir, 0700); err != nil {
			return nil, fmt.Errorf("create download dir: %w", err)
		}
	}

	if opts.DriveID != "" {
		// Single drive mode
		output.Info("Listing files in drive %s...", opts.DriveID)
		drive := SPDrive{ID: opts.DriveID, Name: "specified"}
		result.Drives = append(result.Drives, drive)
		listSPDriveFiles(ctx, c, opts.DriveID, "root", "", opts, result)
	} else if opts.SiteID != "" {
		// Enumerate all drives for the site
		output.Info("Discovering drives for site %s...", opts.SiteID)
		drivesEndpoint := fmt.Sprintf("/sites/%s/drives", opts.SiteID)
		drivesRaw, err := c.GetAll(ctx, drivesEndpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("list site drives: %w", err)
		}

		for _, dr := range drivesRaw {
			var d struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				DriveType string `json:"driveType"`
				WebURL    string `json:"webUrl"`
			}
			if err := json.Unmarshal(dr, &d); err != nil {
				continue
			}
			output.Info("Drive: %s (%s) — %s", d.Name, d.DriveType, d.ID)
			drive := SPDrive{ID: d.ID, Name: d.Name, DriveType: d.DriveType, WebURL: d.WebURL}
			result.Drives = append(result.Drives, drive)
			listSPDriveFiles(ctx, c, d.ID, "root", d.Name, opts, result)
		}
	} else {
		return nil, fmt.Errorf("provide --site-id or --drive-id")
	}

	result.FileCount = 0
	result.FolderCount = 0
	result.TotalSize = 0
	for _, f := range result.Files {
		if f.IsFolder {
			result.FolderCount++
		} else {
			result.FileCount++
			result.TotalSize += f.Size
		}
	}

	output.Success("SP files: %d files, %d folders, %s total across %d drives",
		result.FileCount, result.FolderCount, formatSize(result.TotalSize), len(result.Drives))
	if len(result.Downloaded) > 0 {
		output.Success("Downloaded: %d files", len(result.Downloaded))
	}
	return result, nil
}

func listSPDriveFiles(ctx context.Context, c *graph.Client, driveID, itemID, pathPrefix string, opts SPFilesOpts, result *SPFilesResult) {
	listSPDriveFilesRecursive(ctx, c, driveID, itemID, pathPrefix, opts.MaxDepth, 0, &opts, result)
}

func listSPDriveFilesRecursive(ctx context.Context, c *graph.Client, driveID, itemID, parentPath string, maxDepth, depth int, opts *SPFilesOpts, result *SPFilesResult) {
	if depth >= maxDepth {
		return
	}

	endpoint := fmt.Sprintf("/drives/%s/items/%s/children", driveID, itemID)
	raw, err := c.GetAll(ctx, endpoint, nil)
	if err != nil {
		output.Verbose("[sp-files] error listing %s: %v", parentPath, err)
		return
	}

	for _, r := range raw {
		var item struct {
			ID                   string `json:"id"`
			Name                 string `json:"name"`
			Size                 int64  `json:"size"`
			WebURL               string `json:"webUrl"`
			CreatedDateTime      string `json:"createdDateTime"`
			LastModifiedDateTime string `json:"lastModifiedDateTime"`
			Folder               *struct {
				ChildCount int `json:"childCount"`
			} `json:"folder"`
			File *struct {
				MimeType string `json:"mimeType"`
			} `json:"file"`
		}
		if err := json.Unmarshal(r, &item); err != nil {
			continue
		}

		currentPath := parentPath + "/" + item.Name
		isFolder := item.Folder != nil
		mimeType := ""
		if item.File != nil {
			mimeType = item.File.MimeType
		}

		// Extension filter
		if !isFolder && len(opts.Extensions) > 0 {
			ext := strings.ToLower(filepath.Ext(item.Name))
			if !containsStr(opts.Extensions, ext) {
				continue
			}
		}

		spFile := SPFileItem{
			ID:               item.ID,
			Name:             item.Name,
			Size:             item.Size,
			WebURL:           item.WebURL,
			CreatedDateTime:  item.CreatedDateTime,
			ModifiedDateTime: item.LastModifiedDateTime,
			IsFolder:         isFolder,
			MimeType:         mimeType,
			Path:             currentPath,
			DriveID:          driveID,
			SiteID:           opts.SiteID,
		}
		result.Files = append(result.Files, spFile)

		if isFolder {
			output.Verbose("[sp-files] dir:  %s", currentPath)
			listSPDriveFilesRecursive(ctx, c, driveID, item.ID, currentPath, maxDepth, depth+1, opts, result)
		} else {
			output.Verbose("[sp-files] file: %s (%s)", currentPath, formatSize(item.Size))

			if opts.DownloadDir != "" {
				dlPath := filepath.Join(opts.DownloadDir, sanitizePath(currentPath))
				if err := downloadDriveItem(ctx, c, driveID, item.ID, dlPath); err != nil {
					output.Warn("[sp-files] download failed: %s — %v", item.Name, err)
					result.DownloadErr = append(result.DownloadErr, item.Name+": "+err.Error())
				} else {
					result.Downloaded = append(result.Downloaded, dlPath)
					output.Success("[sp-files] downloaded: %s (%s)", dlPath, formatSize(item.Size))
				}
			}
		}
	}
}
