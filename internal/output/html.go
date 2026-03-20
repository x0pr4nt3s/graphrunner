package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GraphRunner Report</title>
<style>
  :root{--critical:#d32f2f;--high:#e64a19;--medium:#f57c00;--low:#388e3c;--info:#1976d2}
  body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f5f5f5;color:#212121}
  header{background:#1a237e;color:#fff;padding:1.5rem 2rem}
  header h1{margin:0;font-size:1.8rem}
  header p{margin:.3rem 0 0;opacity:.8}
  .container{max-width:1100px;margin:2rem auto;padding:0 1rem}
  .section{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);margin-bottom:1.5rem;overflow:hidden}
  .section-header{padding:1rem 1.5rem;background:#e8eaf6;font-weight:bold;font-size:1.1rem}
  pre{background:#eee;padding:.8rem;border-radius:4px;font-size:.8rem;overflow-x:auto;white-space:pre-wrap;margin:.5rem 1rem}
  footer{text-align:center;padding:2rem;color:#888;font-size:.85rem}
</style>
</head>
<body>
<header>
  <h1>GraphRunner — M365 Report</h1>
  <p>Generated: {{.GeneratedAt}}</p>
</header>
<div class="container">
  {{range .Sections}}
  <div class="section">
    <div class="section-header">{{.Title}}</div>
    <pre>{{.Content}}</pre>
  </div>
  {{end}}
</div>
<footer>GraphRunner — M365 Post-Exploitation Framework (Go)</footer>
</body>
</html>`

// HTMLSection is a section in the HTML report.
type HTMLSection struct {
	Title   string
	Content string
}

// HTMLReport holds all data for the HTML report.
type HTMLReport struct {
	GeneratedAt string
	Sections    []HTMLSection
}

// WriteHTML writes a report as a standalone HTML file.
func WriteHTML(path string, sections []HTMLSection) error {
	report := HTMLReport{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Sections:    sections,
	}
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, report)
}

// PrettyJSON formats data as indented JSON string.
func PrettyJSON(data interface{}) string {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", data)
	}
	return string(out)
}
