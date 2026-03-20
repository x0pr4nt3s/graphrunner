package output

import (
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

var (
	teeFile   *os.File
	teeMu     sync.Mutex
	ansiStrip = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
)

// InitTee opens path for append and starts mirroring all output (plain text, no colors).
func InitTee(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	teeMu.Lock()
	teeFile = f
	teeMu.Unlock()
	teeWrite(fmt.Sprintf("=== session started %s ===\n", time.Now().Format(time.RFC3339)))
	return nil
}

// CloseTee flushes and closes the tee file.
func CloseTee() {
	teeMu.Lock()
	defer teeMu.Unlock()
	if teeFile != nil {
		teeFile.WriteString(fmt.Sprintf("=== session ended %s ===\n\n", time.Now().Format(time.RFC3339)))
		teeFile.Close()
		teeFile = nil
	}
}

// teeWrite strips ANSI codes and writes plain text to the log file.
func teeWrite(s string) {
	teeMu.Lock()
	defer teeMu.Unlock()
	if teeFile == nil {
		return
	}
	plain := ansiStrip.ReplaceAllString(s, "")
	teeFile.WriteString(plain)
}

// Log writes a plain line to the tee file (for structured data like results).
func Log(level, msg string, _ interface{}) {
	teeWrite(fmt.Sprintf("[%s] %s: %s\n", time.Now().Format("15:04:05"), level, msg))
}

// Stderr returns os.Stderr for progress output that should be overwritten.
func Stderr() *os.File { return os.Stderr }

// InitLogger is kept for backwards compatibility — calls InitTee.
func InitLogger(path string) error { return InitTee(path) }

// CloseLogger is kept for backwards compatibility — calls CloseTee.
func CloseLogger() { CloseTee() }
