package config

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/auth"
	"github.com/graphrunner/internal/graph"
)

// App holds the global application state shared between commands.
type App struct {
	Store         *auth.TokenStore
	Authenticator *auth.Authenticator
	SessionFlag   string // set by --session/-s global flag
	ProxyURL      string // set by --proxy global flag
}

// NewApp initializes the application state.
func NewApp(passphrase string) (*App, error) {
	store, err := auth.NewTokenStore(passphrase)
	if err != nil {
		return nil, err
	}
	return &App{
		Store:         store,
		Authenticator: auth.NewAuthenticator(store),
	}, nil
}

// GraphClient returns a Graph API client.
// If SessionFlag is set, uses that session; otherwise uses the active session.
// Automatically refreshes expired tokens when a refresh token is available.
func (a *App) GraphClient() (*graph.Client, error) {
	var sess *auth.Session
	var err error

	if a.SessionFlag != "" {
		sess, err = a.Store.Get(a.SessionFlag)
		if err != nil {
			return nil, fmt.Errorf("session %q: %w", a.SessionFlag, err)
		}
	} else {
		sess, err = a.Store.GetActive()
		if err != nil {
			return nil, err
		}
	}

	// Auto-refresh if expired
	if sess.IsExpired() && sess.RefreshToken != "" {
		refreshed, refreshErr := a.Authenticator.RefreshSession(context.Background(), sess.Name)
		if refreshErr == nil {
			sess = refreshed
		} else {
			return nil, fmt.Errorf("session %q expired and refresh failed: %w — re-authenticate with 'graphrunner auth login'", sess.Name, refreshErr)
		}
	} else if sess.IsExpired() {
		return nil, fmt.Errorf("session %q expired (no refresh token) — re-authenticate with 'graphrunner auth login'", sess.Name)
	}

	client := graph.NewClient(sess.AccessToken)
	if a.ProxyURL != "" {
		if err := client.SetProxy(a.ProxyURL); err != nil {
			return nil, fmt.Errorf("proxy setup: %w", err)
		}
	}
	return client, nil
}
