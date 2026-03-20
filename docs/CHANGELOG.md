# Changelog

All notable changes to GraphRunner are documented in this file.

## [0.2.0] — 2026-03-19

### Added — Authentication
- `auth cert-login` — PFX/PEM certificate authentication with client_assertion JWT (RS256)
- `auth token-swap` — Cross-resource token pivoting (TokenTactics-style, 9 resource targets)
- `auth watch` — Background auto-refresh loop (Ctrl+C to stop)
- `auth whoami` — Show identity decoded from JWT claims
- `auth token` — Print raw access token (`-r` for piping to curl)

### Added — Reconnaissance
- `recon user-enum` — GetCredentialType user enumeration (NO AUTH, AADInternals-style)
- `recon domain-info` — OpenID config + UserRealm federation recon (NO AUTH)
- `recon audit-logs` — Directory audit + sign-in logs (beta endpoint, OData filter)
- `recon named-locations` — CA trusted IPs/countries
- `recon intune-devices` — Intune managed devices (compliance, encryption, OS breakdown)
- `recon cross-tenant` — Cross-tenant access policies, B2B partner configurations
- `recon sp-secrets` — App/SP credential enumeration with expiry analysis
- `recon delegated-perms` — All oauth2PermissionGrants with high-risk scope flagging
- `recon app-proxy` — Azure AD Application Proxy discovery (beta)
- `recon sp-audit` — Full SharePoint audit: public sites, external sharing, file counts, risks
- `recon mfa-status` — MFA registration status per user
- `recon devices` — Registered/joined device enumeration

### Added — Pillage
- `pillage kql-search` — KQL search with structured driveID+itemID output, pagination, download
- `pillage sp-files` — Direct SharePoint drive file listing + download (no Search API dependency)
- `pillage sp-search` — Graph Search with configurable entity types
- `pillage sp-download` — Bulk download matching driveItems
- `pillage onedrive` — Recursive OneDrive listing with `--download-dir` and `--extensions`
- `pillage notebooks` — OneNote notebooks, sections, pages with keyword filter
- `pillage calendar` — Calendar events + meeting link extraction (Teams/Zoom/Webex)
- `pillage send-mail` — Send email as a user (HTML/text, multiple recipients)
- `pillage planner` — Planner plans + tasks enumeration
- `pillage contacts` — Outlook contacts enumeration

### Added — Persistence
- `persist add-key-cred` — Shadow certificate credential on apps (self-signed X.509, RSA 2048)
- `persist mail-rule` — Create inbox forwarding rules for email exfiltration
- `persist list-mail-rules` — List existing inbox rules

### Added — Escalation
- `escalate assign-role` — Assign directory roles to users/SPs
- `escalate list-roles` — List all role definitions
- `escalate grant-app-perm` — Grant application permissions (auto-resolve Graph SP)
- `escalate admin-consent` — AllPrincipals oauth2PermissionGrant
- `escalate reset-password` — Reset user passwords
- `escalate add-owner` — Add owner to apps or groups
- `escalate add-sp-secret` — Inject password secret into service principal

### Added — Cleanup
- `cleanup remove-secret` — Remove password credential from app or SP
- `cleanup remove-key-cred` — Remove certificate credential from app
- `cleanup remove-mail-rule` — Delete inbox rules

### Added — Spray
- `spray password` — Password spray via ROPC
- `spray brute-clientid` — Client ID enumeration (well-known + custom lists)

### Added — Infrastructure
- `--proxy` global flag for Burp/ZAP/mitmproxy (auto TLS skip)
- `--output-csv` global flag for tabular CSV export (auto-flatten nested JSON)
- `--log-file` global flag to tee output to plain-text file
- `--output-dir` global flag for auto-save directory
- `-v/--verbose` global flag for per-item progress output
- Keyword detector preset system (6 built-in presets: credentials, finance, pii, infra, m365, all)
- HTML report generation
- Auto-save JSON results (`<command>-<timestamp>.json` + `<command>-latest.json`)

### Fixed
- JWT parsing: use `base64.RawURLEncoding` (was `URLEncoding`, silently failing)
- `group_clone.go`: 3 `json.Unmarshal` errors now propagated; `mailNickname` validated
- `teams.go`: removed unused variable + dead `json.Unmarshal`
- `sharepoint_deep.go`: `IsPublic` was never set to `true`; added 3 detection methods
- File download permissions: 0644 → 0600
- HTTP client: body reset on retry via `req.GetBody()`
- Token store: silent corruption → proper error returns
- `oauth_inject.go`: `json.Unmarshal` errors propagated

### Security
- PBKDF2-SHA256 KDF (600k iterations) replacing direct SHA-256
- Proper file permissions on all downloaded content
- `InsecureSkipVerify` only when `--proxy` is explicitly set

## [0.1.0] — 2026-03-01

### Added
- Initial release — full M365 post-exploitation framework in Go
- Authentication: device code, client credentials, ROPC, token import, auto-refresh
- Encrypted multi-session token store (AES-256-GCM)
- Graph HTTP client with auto-pagination and rate limit handling
- Reconnaissance: tenant, users, groups, apps, caps, roles, sharepoint, open-inboxes
- Persistence: inject-app, clone-group, invite-guest, add-member
- Pillage: mailbox, sharepoint, teams, user-attrs, inbox, chats, download
- Cleanup: delete-app, delete-group, remove-member
- Orchestrator (`run` command) with keyword detectors
- JSON + HTML reporters
- Cobra CLI with 30+ subcommands
- 24 unit tests
