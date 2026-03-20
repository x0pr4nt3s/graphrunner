package pillage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// DownloadFile downloads a file from a drive by driveID and itemID.
func DownloadFile(ctx context.Context, client *graph.Client, driveID, itemID, outPath string) error {
	endpoint := fmt.Sprintf(graph.EndpointDriveItem, driveID, itemID)

	output.Info("Downloading drive=%s item=%s...", driveID, itemID)
	data, err := client.Download(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	output.Success("Downloaded %d bytes to %s", len(data), outPath)
	return nil
}

// BulkDownloadResult holds results from a bulk download operation.
type BulkDownloadResult struct {
	Downloaded []string `json:"downloaded"`
	Failed     []string `json:"failed"`
	TotalBytes int64    `json:"total_bytes"`
}

// BulkDownload searches SharePoint via the Graph Search API for driveItems matching
// query and downloads all results into downloadDir.
func BulkDownload(ctx context.Context, client *graph.Client, query string, limit int, downloadDir string) (*BulkDownloadResult, error) {
	result := &BulkDownloadResult{}

	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return nil, fmt.Errorf("create download dir: %w", err)
	}

	sr, err := SearchSP(ctx, client, query, []string{"driveItem"}, limit)
	if err != nil {
		return nil, err
	}

	for _, f := range sr.Results {
		driveID, itemID, name := extractDriveInfo(f)
		if driveID == "" || itemID == "" {
			continue
		}
		endpoint := fmt.Sprintf(graph.EndpointDriveItem, driveID, itemID)
		data, dlErr := client.Download(ctx, endpoint)
		if dlErr != nil {
			output.Warn("Download %s: %v", name, dlErr)
			result.Failed = append(result.Failed, name)
			continue
		}
		outPath := filepath.Join(downloadDir, name)
		if writeErr := os.WriteFile(outPath, data, 0600); writeErr != nil {
			output.Warn("Write %s: %v", outPath, writeErr)
			result.Failed = append(result.Failed, name)
			continue
		}
		result.Downloaded = append(result.Downloaded, outPath)
		result.TotalBytes += int64(len(data))
		output.Success("Downloaded: %s (%d bytes)", outPath, len(data))
	}

	output.Success("Bulk download complete: %d files, %d bytes, %d failed",
		len(result.Downloaded), result.TotalBytes, len(result.Failed))
	return result, nil
}
