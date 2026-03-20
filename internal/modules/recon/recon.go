package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// ReconResults holds all recon module results.
type ReconResults struct {
	Tenant   interface{} `json:"tenant,omitempty"`
	Users    interface{} `json:"users,omitempty"`
	Groups   interface{} `json:"groups,omitempty"`
	Apps     interface{} `json:"apps,omitempty"`
	CAPs     interface{} `json:"conditional_access,omitempty"`
	Roles    interface{} `json:"roles,omitempty"`
	SP       interface{} `json:"sharepoint,omitempty"`
	Inboxes  interface{} `json:"open_inboxes,omitempty"`
	Errors   []string    `json:"errors,omitempty"`
}

// All runs every recon module and collects results.
// Note: open-inboxes is excluded from All() because it is slow (N+1 API calls).
// Run it separately with 'graphrunner recon open-inboxes'.
func All(ctx context.Context, client *graph.Client) *ReconResults {
	r := &ReconResults{}

	modules := []struct {
		name string
		fn   func(context.Context, *graph.Client) (interface{}, error)
	}{
		{"tenant", func(ctx context.Context, c *graph.Client) (interface{}, error) { return Tenant(ctx, c) }},
		{"users", func(ctx context.Context, c *graph.Client) (interface{}, error) { return Users(ctx, c) }},
		{"groups", func(ctx context.Context, c *graph.Client) (interface{}, error) { return Groups(ctx, c) }},
		{"apps", func(ctx context.Context, c *graph.Client) (interface{}, error) { return Apps(ctx, c) }},
		{"caps", func(ctx context.Context, c *graph.Client) (interface{}, error) { return ConditionalAccess(ctx, c) }},
		{"roles", func(ctx context.Context, c *graph.Client) (interface{}, error) { return Roles(ctx, c) }},
		{"sharepoint", func(ctx context.Context, c *graph.Client) (interface{}, error) { return SharePoint(ctx, c) }},
	}

	for _, m := range modules {
		output.Info("Running recon module: %s", m.name)
		data, err := m.fn(ctx, client)
		if err != nil {
			output.Error("%s: %v", m.name, err)
			r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", m.name, err))
		}
		switch m.name {
		case "tenant":
			r.Tenant = data
		case "users":
			r.Users = data
		case "groups":
			r.Groups = data
		case "apps":
			r.Apps = data
		case "caps":
			r.CAPs = data
		case "roles":
			r.Roles = data
		case "sharepoint":
			r.SP = data
		}
	}

	return r
}

// unmarshalAll is a helper that decodes []json.RawMessage into []map[string]interface{}.
func unmarshalAll(raw []json.RawMessage) []map[string]interface{} {
	var out []map[string]interface{}
	for _, r := range raw {
		var m map[string]interface{}
		if err := json.Unmarshal(r, &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}
