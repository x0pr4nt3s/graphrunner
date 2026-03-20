package escalate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// ConsentResult holds the result of granting admin consent.
type ConsentResult struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	ConsentType string `json:"consent_type"`
	ResourceID  string `json:"resource_id"`
	Scope       string `json:"scope"`
}

// GrantAdminConsent creates an admin consent grant (AllPrincipals) for a service principal.
// This grants delegated permissions on behalf of all users in the tenant.
// Uses POST /oauth2PermissionGrants
func GrantAdminConsent(ctx context.Context, client *graph.Client, clientSPID, resourceSPID, scopes string) (*ConsentResult, error) {
	body := map[string]interface{}{
		"clientId":    clientSPID,
		"consentType": "AllPrincipals",
		"resourceId":  resourceSPID,
		"scope":       scopes,
	}

	output.Info("Granting admin consent for SP %s...", clientSPID)
	output.Info("  Scopes: %s", scopes)

	respRaw, err := client.Post(ctx, graph.EndpointOAuth2Grants, body)
	if err != nil {
		return nil, fmt.Errorf("grant admin consent: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(respRaw, &data); err != nil {
		return nil, fmt.Errorf("parse consent response: %w", err)
	}

	grantID, _ := data["id"].(string)

	result := &ConsentResult{
		ID:          grantID,
		ClientID:    clientSPID,
		ConsentType: "AllPrincipals",
		ResourceID:  resourceSPID,
		Scope:       scopes,
	}

	output.Success("Admin consent granted!")
	output.Info("  Grant ID       : %s", grantID)
	output.Info("  Client SP      : %s", clientSPID)
	output.Info("  Resource SP    : %s", resourceSPID)
	output.Info("  Consent Type   : AllPrincipals")
	output.Info("  Scopes         : %s", scopes)

	return result, nil
}
