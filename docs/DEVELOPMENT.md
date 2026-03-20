# GraphRunner — Development Guide

## Prerequisites

- Go 1.21+ (developed with Go 1.25)
- Git

## Project Setup

```bash
git clone <repo-url> graphrunner
cd graphrunner
go mod download
```

## Building

```bash
# Standard build
go build -o graphrunner ./cmd/graphrunner

# With version info
go build -ldflags "-s -w" -o graphrunner ./cmd/graphrunner

# Cross-compile
GOOS=windows GOARCH=amd64 go build -o graphrunner.exe ./cmd/graphrunner
GOOS=linux GOARCH=amd64 go build -o graphrunner-linux ./cmd/graphrunner
GOOS=darwin GOARCH=arm64 go build -o graphrunner-macos ./cmd/graphrunner
```

## Testing

```bash
# Run all tests (individual packages)
go test ./internal/auth/...
go test ./internal/graph/...
go test ./internal/output/...

# With verbose output
go test -v ./internal/auth/...

# With race detection
go test -race ./internal/...
```

> **Note:** `go test ./...` may fail with a permission error due to the `output/` directory in the project root conflicting with the `output` package. Run tests per-package instead.

## Dependencies

GraphRunner is deliberately minimal in its dependencies:

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/charmbracelet/lipgloss` | Terminal styling |
| `golang.org/x/crypto` | PBKDF2-SHA256 for key derivation |

No Microsoft auth libraries, no Graph SDK, no heavy frameworks.

## Project Structure

```
cmd/graphrunner/main.go     # All CLI command definitions (~2300 lines)
internal/
├── auth/                   # Authentication flows and token storage
├── config/                 # App configuration and keyword detectors
├── graph/                  # HTTP client for Microsoft Graph API
├── modules/
│   ├── recon/              # Reconnaissance modules
│   ├── pillage/            # Data exfiltration modules
│   ├── persist/            # Persistence modules
│   ├── escalate/           # Privilege escalation modules
│   ├── cleanup/            # Cleanup/removal operations
│   └── spray/              # Password spray and enumeration
└── output/                 # Output formatters (console, JSON, HTML, CSV)
```

## Adding a New Module

### 1. Create the module file

Create a new file in the appropriate package (e.g., `internal/modules/recon/my_module.go`):

```go
package recon

import (
    "context"
    "github.com/graphrunner/internal/graph"
    "github.com/graphrunner/internal/output"
)

type MyModuleResult struct {
    Items []MyItem `json:"items"`
    Total int      `json:"total"`
}

type MyItem struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

func MyModule(ctx context.Context, c *graph.Client) (*MyModuleResult, error) {
    result := &MyModuleResult{}

    output.Info("Running my module...")

    raw, err := c.GetAll(ctx, "/some/endpoint", map[string]string{
        "$select": "id,displayName",
    })
    if err != nil {
        return nil, err
    }

    // Parse results...
    result.Total = len(result.Items)
    output.Success("Found %d items", result.Total)
    return result, nil
}
```

### 2. Wire it into the CLI

Add the command in `cmd/graphrunner/main.go`:

```go
// In the appropriate parent command function (reconCmd, pillageCmd, etc.)
reconSubCmd("my-module", "Description of my module", func(c *graph.Client) (interface{}, error) {
    return recon.MyModule(context.Background(), c)
}),
```

For commands with custom flags, create a dedicated function:

```go
func reconMyModuleCmd() *cobra.Command {
    var someFlag string
    cmd := &cobra.Command{
        Use:   "my-module",
        Short: "Description",
        RunE: func(cmd *cobra.Command, args []string) error {
            client, err := app.GraphClient()
            if err != nil {
                return err
            }
            output.Header("Recon: My Module")
            result, err := recon.MyModule(context.Background(), client, someFlag)
            if err != nil {
                return err
            }
            printAndSave("recon-my-module", result)
            return nil
        },
    }
    cmd.Flags().StringVar(&someFlag, "flag-name", "", "Description")
    return cmd
}
```

### 3. Build and test

```bash
go build -o graphrunner ./cmd/graphrunner
./graphrunner recon my-module -v
```

## Graph Client API

The `graph.Client` provides these methods:

```go
// GET a single resource
raw, err := c.Get(ctx, "/endpoint", params)

// GET all items with auto-pagination
items, err := c.GetAll(ctx, "/endpoint", params)

// POST request
raw, err := c.Post(ctx, "/endpoint", body)

// PATCH request
raw, err := c.Patch(ctx, "/endpoint", body)

// DELETE request
err := c.Delete(ctx, "/endpoint")

// Download file content
data, err := c.Download(ctx, "/drives/x/items/y/content")

// Search API
raw, err := c.SearchQuery(ctx, searchRequests)

// Switch API version
c.UseBeta()
defer c.UseV1()
```

All methods automatically:
- Add the `Authorization: Bearer <token>` header
- Follow `@odata.nextLink` for pagination (in `GetAll`)
- Retry on HTTP 429 with `Retry-After` backoff
- Route through proxy if configured

## Output Helpers

```go
output.Info("message %s", arg)       // Blue info
output.Success("message %s", arg)    // Green success
output.Warn("message %s", arg)       // Yellow warning
output.Error("message %s", arg)      // Red error
output.Critical("message %s", arg)   // Bold red
output.Verbose("message %s", arg)    // Only prints with -v flag
output.Header("Section Title")       // Styled section header
output.Dim("subtle text")            // Gray/dim text
output.Banner()                      // ASCII art banner
output.TableRow("Label:", "Value")   // Aligned key-value
output.PrettyJSON(data)              // Formatted JSON string
output.AutoSave("name", data)        // Save to output dir
```

## Security Considerations

When contributing, keep these in mind:

- **Never log tokens** — access tokens and refresh tokens must never appear in output
- **File permissions** — downloaded files use `0600`, directories use `0700`
- **Error propagation** — always propagate `json.Unmarshal` errors, don't silently ignore
- **Body reset on retry** — HTTP request bodies must be reset via `req.GetBody()` before retry
- **Context cancellation** — use `context.Context` everywhere, check `ctx.Err()` in loops
- **Input validation** — validate user input at the CLI layer before passing to modules
