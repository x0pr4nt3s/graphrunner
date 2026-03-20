package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// VerboseEnabled controls whether Verbose() calls produce output.
var VerboseEnabled bool

// Styles for terminal output.
var (
	StyleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	StyleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600"))
	StyleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAA00"))
	StyleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CC00"))
	StyleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("#0088FF"))
	StyleSuccess  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
	StyleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	StyleBanner   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6C63FF")).Bold(true)
	StyleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	StyleBold     = lipgloss.NewStyle().Bold(true)
	StyleHeader   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#1A237E")).Bold(true).Padding(0, 1)
)

// Banner prints the GraphRunner ASCII banner.
func Banner() {
	banner := `
   ____                 _     ____
  / ___|_ __ __ _ _ __ | |__ |  _ \ _   _ _ __  _ __   ___ _ __
 | |  _| '__/ _' | '_ \| '_ \| |_) | | | | '_ \| '_ \ / _ \ '__|
 | |_| | | | (_| | |_) | | | |  _ <| |_| | | | | | | |  __/ |
  \____|_|  \__,_| .__/|_| |_|_| \_\\__,_|_| |_|_| |_|\___|_|
                 |_|
                    M365 Post-Exploitation Framework (Go)
`
	fmt.Println(StyleBanner.Render(banner))
}

// Info prints an informational message.
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := StyleInfo.Render("[*] ") + msg
	fmt.Println(line)
	teeWrite("[*] " + msg + "\n")
}

// Success prints a success message.
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(StyleSuccess.Render("[+] ") + msg)
	teeWrite("[+] " + msg + "\n")
}

// Warn prints a warning message.
func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(StyleMedium.Render("[!] ") + msg)
	teeWrite("[!] " + msg + "\n")
}

// Error prints an error message to stderr.
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, StyleError.Render("[-] ")+msg)
	teeWrite("[-] " + msg + "\n")
}

// Critical prints a critical message.
func Critical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(StyleCritical.Render("[!!] ") + msg)
	teeWrite("[!!] " + msg + "\n")
}

// Verbose prints only when --verbose is active.
func Verbose(format string, args ...interface{}) {
	if !VerboseEnabled {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Println(StyleDim.Render("    » ") + msg)
	teeWrite("    » " + msg + "\n")
}

// Header prints a section header.
func Header(title string) {
	fmt.Println()
	fmt.Println(StyleHeader.Render(title))
	fmt.Println()
}

// Dim prints a dimmed message (secondary info).
func Dim(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(StyleDim.Render("    " + msg))
}

// TableRow prints a key-value row.
func TableRow(key, value string) {
	fmt.Printf("  %-30s %s\n", StyleBold.Render(key), value)
}

// Styles for pretty tables and progress output.
var (
	StyleTableHeader = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#5C6BC0")).Bold(true).Padding(0, 1)
	StyleTableBorder = lipgloss.NewStyle().Foreground(lipgloss.Color("#5C6BC0"))
	StyleTableRow    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	StyleTableRowAlt = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0BEC5"))
	StyleHighlight   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF9800")).Bold(true)
	StyleFileIcon    = lipgloss.NewStyle().Foreground(lipgloss.Color("#42A5F5"))
	StyleFolderIcon  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA726"))
	StyleSizeInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("#78909C"))
	StyleUserInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("#AB47BC"))
	StyleURLInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("#26A69A"))
	StyleProgress    = lipgloss.NewStyle().Foreground(lipgloss.Color("#66BB6A"))
	StyleCounter     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD54F")).Bold(true)
)

// FileIcon returns an icon string based on file extension.
func FileIcon(name string) string {
	ext := ""
	if idx := len(name) - 1; idx >= 0 {
		for i := len(name) - 1; i >= 0; i-- {
			if name[i] == '.' {
				ext = name[i+1:]
				break
			}
		}
	}
	ext = strings.ToLower(ext)
	switch ext {
	case "xlsx", "xls", "csv":
		return StyleFileIcon.Render("[XLS]")
	case "docx", "doc":
		return StyleFileIcon.Render("[DOC]")
	case "pptx", "ppt":
		return StyleFileIcon.Render("[PPT]")
	case "pdf":
		return StyleFileIcon.Render("[PDF]")
	case "png", "jpg", "jpeg", "gif", "bmp", "svg":
		return StyleFileIcon.Render("[IMG]")
	case "zip", "rar", "7z", "tar", "gz":
		return StyleFileIcon.Render("[ZIP]")
	case "txt", "log", "md":
		return StyleFileIcon.Render("[TXT]")
	case "json", "xml", "yaml", "yml":
		return StyleFileIcon.Render("[CFG]")
	case "py", "go", "js", "ts", "sh", "ps1":
		return StyleFileIcon.Render("[COD]")
	case "env", "config", "conf", "ini", "key", "pem", "pfx":
		return StyleHighlight.Render("[SEC]")
	case "one":
		return StyleFileIcon.Render("[ONE]")
	case "msg", "eml":
		return StyleFileIcon.Render("[EML]")
	case "":
		return StyleFolderIcon.Render("[DIR]")
	default:
		return StyleFileIcon.Render("[---]")
	}
}

// SearchResultHeader prints a styled search result header.
func SearchResultHeader(query string, total int, entityTypes string) {
	fmt.Println()
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#5C6BC0")).
		Padding(0, 2).
		Width(72)
	content := fmt.Sprintf(
		"%s  %s\n%s  %s\n%s  %s",
		StyleBold.Render("Query:"), StyleHighlight.Render(query),
		StyleBold.Render("Types:"), entityTypes,
		StyleBold.Render("Hits: "), StyleCounter.Render(fmt.Sprintf("%d results", total)),
	)
	fmt.Println(box.Render(content))
	fmt.Println()
}

// SearchResultRow prints a single pretty search result with full details.
func SearchResultRow(index int, icon, name, size, createdBy, modifiedBy, modified, webURL, siteName, driveID, itemID, summary string) {
	num := StyleCounter.Render(fmt.Sprintf(" %-3d", index))
	nameStyled := StyleBold.Render(name)
	sizeStyled := StyleSizeInfo.Render("[" + size + "]")

	// Line 1: number + icon + name + size
	fmt.Printf("  %s %s %s  %s\n", num, icon, nameStyled, sizeStyled)

	// Line 2: site + author + date
	details := ""
	if siteName != "" {
		details += StyleURLInfo.Render("Site: "+siteName) + "  "
	}
	if createdBy != "" && createdBy != modifiedBy {
		details += StyleDim.Render("Created: "+createdBy) + "  "
	}
	if modifiedBy != "" {
		details += StyleUserInfo.Render("Modified: "+modifiedBy) + "  "
	}
	if modified != "" {
		details += StyleDim.Render("("+modified+")")
	}
	if details != "" {
		fmt.Printf("       %s\n", details)
	}

	// Line 3: URL
	if webURL != "" {
		urlShort := webURL
		if len(urlShort) > 100 {
			urlShort = urlShort[:97] + "..."
		}
		fmt.Printf("       %s\n", StyleDim.Render(urlShort))
	}

	// Line 4: Drive/Item IDs for download
	if driveID != "" && itemID != "" {
		fmt.Printf("       %s %s  %s %s\n",
			StyleBold.Render("DriveID:"), StyleDim.Render(driveID),
			StyleBold.Render("ItemID:"), StyleDim.Render(itemID))
	}

	// Line 5: Summary/snippet (cleaned)
	if summary != "" {
		fmt.Printf("       %s %s\n", StyleHighlight.Render(">>"), StyleTableRow.Render(summary))
	}

	fmt.Println()
}

// SearchDivider prints a visual separator for search results.
func SearchDivider() {
	fmt.Println(StyleTableBorder.Render("  " + strings.Repeat("─", 70)))
}

// ProgressBar prints a simple text-based progress indicator.
func ProgressBar(current, total int, label string) {
	pct := 0
	if total > 0 {
		pct = (current * 100) / total
	}
	bar := strings.Repeat("█", pct/5) + strings.Repeat("░", 20-pct/5)
	fmt.Printf("\r  %s %s %s",
		StyleProgress.Render(bar),
		StyleCounter.Render(fmt.Sprintf("%d%%", pct)),
		StyleDim.Render(label))
}

// ProgressDone finishes a progress bar with newline.
func ProgressDone(label string) {
	bar := strings.Repeat("█", 20)
	fmt.Printf("\r  %s %s %s\n",
		StyleProgress.Render(bar),
		StyleCounter.Render("100%"),
		StyleSuccess.Render("[+] ")+label)
}
