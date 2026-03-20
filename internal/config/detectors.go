package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// DetectorPresets maps preset names to keyword lists.
type DetectorPresets struct {
	Presets map[string][]string `json:"presets"`
}

// DefaultDetectors returns the built-in detector keyword presets.
func DefaultDetectors() *DetectorPresets {
	return &DetectorPresets{
		Presets: map[string][]string{
			"credentials": {"password", "secret", "credential", "key", "token", "apikey", "api_key", "api-key"},
			"finance":     {"invoice", "payment", "bank", "wire", "routing", "account number", "credit card", "budget"},
			"pii":         {"ssn", "social security", "passport", "date of birth", "driver license", "tax id"},
			"infra":       {"vpn", "firewall", "admin", "root", "certificate", "private key", "ssh", "rdp"},
			"m365":        {"teams", "sharepoint", "onedrive", "azure", "intune", "conditional access", "mfa"},
			"all":         {"password", "secret", "credential", "key", "token", "apikey", "ssn", "vpn", "admin", "certificate", "invoice", "bank"},
		},
	}
}

// LoadDetectors loads detectors from a JSON file, falling back to defaults.
func LoadDetectors(path string) (*DetectorPresets, error) {
	if path == "" {
		// Try default locations
		candidates := []string{
			"detectors.json",
			filepath.Join(homeDir(), ".graphrunner", "detectors.json"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	if path == "" {
		return DefaultDetectors(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var presets DetectorPresets
	if err := json.Unmarshal(data, &presets); err != nil {
		return nil, err
	}

	// Merge with defaults (custom overrides, defaults fill gaps)
	defaults := DefaultDetectors()
	for k, v := range defaults.Presets {
		if _, exists := presets.Presets[k]; !exists {
			presets.Presets[k] = v
		}
	}

	return &presets, nil
}

// GetKeywords returns keywords for a preset name, or the input split by commas if not a preset.
func (d *DetectorPresets) GetKeywords(preset string) []string {
	if kw, ok := d.Presets[preset]; ok {
		return kw
	}
	return nil
}

// SaveDetectors writes the presets to a JSON file.
func SaveDetectors(path string, presets *DetectorPresets) error {
	data, err := json.MarshalIndent(presets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}
