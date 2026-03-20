package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := map[string]interface{}{
		"name":  "test",
		"count": 42,
	}

	if err := WriteJSON(path, data); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if len(content) == 0 {
		t.Error("expected non-empty JSON file")
	}
}

func TestWriteHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.html")

	sections := []HTMLSection{
		{Title: "Test Section", Content: "Hello World"},
		{Title: "Another Section", Content: "More content here"},
	}

	if err := WriteHTML(path, sections); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	html := string(content)
	if len(html) == 0 {
		t.Error("expected non-empty HTML file")
	}
	if !contains(html, "<!DOCTYPE html>") {
		t.Error("expected HTML doctype")
	}
	if !contains(html, "Test Section") {
		t.Error("expected section title in HTML")
	}
	if !contains(html, "GraphRunner") {
		t.Error("expected GraphRunner branding in HTML")
	}
}

func TestPrettyJSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	result := PrettyJSON(data)
	if result == "" {
		t.Error("expected non-empty pretty JSON")
	}
	if !contains(result, "key") {
		t.Error("expected key in output")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
