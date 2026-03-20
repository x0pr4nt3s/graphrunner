package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteJSON writes any data structure as formatted JSON to a file.
func WriteJSON(path string, data interface{}) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	return os.WriteFile(path, out, 0600)
}

// AutoSaveDir is the base directory for automatic result storage.
// Defaults to ./output (current working directory).
var AutoSaveDir string

// AutoSave writes result to AutoSaveDir/<command>-<timestamp>.json automatically.
// Returns the path written, or empty string if AutoSaveDir is not set.
func AutoSave(command string, data interface{}) string {
	if AutoSaveDir == "" {
		return ""
	}
	if err := os.MkdirAll(AutoSaveDir, 0700); err != nil {
		return ""
	}
	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("%s-%s.json", command, ts)
	path := filepath.Join(AutoSaveDir, name)
	if err := WriteJSON(path, data); err != nil {
		Warn("auto-save failed: %v", err)
		return ""
	}
	// Also update <command>-latest.json
	latest := filepath.Join(AutoSaveDir, command+"-latest.json")
	_ = WriteJSON(latest, data)
	return path
}
