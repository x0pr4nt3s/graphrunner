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

// OneDriveItem represents a file or folder in OneDrive.
type OneDriveItem struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	WebURL           string `json:"webUrl"`
	CreatedDateTime  string `json:"createdDateTime"`
	ModifiedDateTime string `json:"lastModifiedDateTime"`
	IsFolder         bool   `json:"is_folder"`
	MimeType         string `json:"mimeType,omitempty"`
	Path             string `json:"path"`
	DriveID          string `json:"driveId,omitempty"`
}

// OneDriveOpts holds options for OneDrive listing.
type OneDriveOpts struct {
	UserID      string
	MaxDepth    int
	DownloadDir string   // if set, download files to this directory
	Extensions  []string // if set, only include/download files with these extensions (e.g. ".docx", ".xlsx")
}

// OneDriveResult holds the recursive listing of a user's OneDrive.
type OneDriveResult struct {
	UserID      string         `json:"user_id"`
	Items       []OneDriveItem `json:"items"`
	FileCount   int            `json:"file_count"`
	FolderCount int            `json:"folder_count"`
	TotalSize   int64          `json:"total_size_bytes"`
	Downloaded  []string       `json:"downloaded,omitempty"`
	DownloadErr []string       `json:"download_errors,omitempty"`
}

// ListOneDrive recursively lists a user's OneDrive files and folders.
// If opts.DownloadDir is set, matching files are downloaded.
// If opts.Extensions is set, only files with those extensions are included.
func ListOneDrive(ctx context.Context, c *graph.Client, opts OneDriveOpts) (*OneDriveResult, error) {
	result := &OneDriveResult{UserID: opts.UserID}

	var driveEndpoint string
	if opts.UserID == "" {
		driveEndpoint = "/me/drive"
		result.UserID = "me"
	} else {
		driveEndpoint = fmt.Sprintf("/users/%s/drive", opts.UserID)
	}

	// Get drive info
	driveRaw, err := c.Get(ctx, driveEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("get drive: %w", err)
	}
	var driveInfo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(driveRaw, &driveInfo); err != nil {
		return nil, fmt.Errorf("parse drive info: %w", err)
	}
	output.Info("Drive ID: %s", driveInfo.ID)

	// Normalize extensions
	for i, ext := range opts.Extensions {
		if !strings.HasPrefix(ext, ".") {
			opts.Extensions[i] = "." + ext
		}
		opts.Extensions[i] = strings.ToLower(opts.Extensions[i])
	}

	// Create download dir if needed
	if opts.DownloadDir != "" {
		if err := os.MkdirAll(opts.DownloadDir, 0700); err != nil {
			return nil, fmt.Errorf("create download dir: %w", err)
		}
		output.Info("Download dir: %s", opts.DownloadDir)
	}
	if len(opts.Extensions) > 0 {
		output.Info("Extension filter: %v", opts.Extensions)
	}

	// Recursive listing from root
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 10
	}
	err = listDriveFolder(ctx, c, driveInfo.ID, "root", "", maxDepth, 0, &opts, result)
	if err != nil {
		output.Warn("Listing error (partial results may be available): %v", err)
	}

	output.Success("OneDrive listing: %d files, %d folders, %s total",
		result.FileCount, result.FolderCount, formatSize(result.TotalSize))
	if len(result.Downloaded) > 0 {
		output.Success("Downloaded: %d files", len(result.Downloaded))
	}
	if len(result.DownloadErr) > 0 {
		output.Warn("Download errors: %d", len(result.DownloadErr))
	}
	return result, nil
}

func listDriveFolder(ctx context.Context, c *graph.Client, driveID, itemID, parentPath string, maxDepth, currentDepth int, opts *OneDriveOpts, result *OneDriveResult) error {
	if currentDepth >= maxDepth {
		return nil
	}

	endpoint := fmt.Sprintf("/drives/%s/items/%s/children", driveID, itemID)
	raw, err := c.GetAll(ctx, endpoint, nil)
	if err != nil {
		return err
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

		// Extension filter (only for files)
		if !isFolder && len(opts.Extensions) > 0 {
			ext := strings.ToLower(filepath.Ext(item.Name))
			if !containsStr(opts.Extensions, ext) {
				continue
			}
		}

		odItem := OneDriveItem{
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
		}
		result.Items = append(result.Items, odItem)

		if isFolder {
			result.FolderCount++
			output.Verbose("[onedrive] dir:  %s", currentPath)
			if err := listDriveFolder(ctx, c, driveID, item.ID, currentPath, maxDepth, currentDepth+1, opts, result); err != nil {
				output.Verbose("[onedrive] error listing %s: %v", currentPath, err)
			}
		} else {
			result.FileCount++
			result.TotalSize += item.Size
			output.Verbose("[onedrive] file: %s (%s)", currentPath, formatSize(item.Size))

			// Download if requested
			if opts.DownloadDir != "" {
				dlPath := filepath.Join(opts.DownloadDir, sanitizePath(currentPath))
				if err := downloadDriveItem(ctx, c, driveID, item.ID, dlPath); err != nil {
					output.Warn("[onedrive] download failed: %s — %v", item.Name, err)
					result.DownloadErr = append(result.DownloadErr, item.Name+": "+err.Error())
				} else {
					result.Downloaded = append(result.Downloaded, dlPath)
					output.Success("[onedrive] downloaded: %s (%s)", dlPath, formatSize(item.Size))
				}
			}
		}
	}
	return nil
}

func downloadDriveItem(ctx context.Context, c *graph.Client, driveID, itemID, outPath string) error {
	// Ensure parent dirs exist
	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return err
	}
	endpoint := fmt.Sprintf("/drives/%s/items/%s/content", driveID, itemID)
	data, err := c.Download(ctx, endpoint)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0600)
}

// sanitizePath removes leading slashes and replaces problematic characters.
func sanitizePath(p string) string {
	p = strings.TrimPrefix(p, "/")
	// Replace characters that are problematic on filesystems
	replacer := strings.NewReplacer(":", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return replacer.Replace(p)
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func formatSize(bytes int64) string {
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
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
