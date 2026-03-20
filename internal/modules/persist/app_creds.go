package persist

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AppCredsResult holds the result of adding credentials to an app.
type AppCredsResult struct {
	AppObjectID  string `json:"app_object_id"`
	AppID        string `json:"app_id,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	KeyID        string `json:"key_id"`
	SecretText   string `json:"secret_text"`
	ExpiresAt    string `json:"expires_at"`
}

// AddAppCredentials adds a new client secret to an existing app registration.
// appObjectID must be the application object ID (not the appId/client_id).
func AddAppCredentials(ctx context.Context, client *graph.Client, appObjectID, hint string, expireDays int) (*AppCredsResult, error) {
	if expireDays <= 0 {
		expireDays = 365
	}

	endDateTime := time.Now().UTC().AddDate(0, 0, expireDays).Format(time.RFC3339)

	body := map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": hint,
			"endDateTime": endDateTime,
		},
	}

	output.Info("Adding password credential to app %s (expires: %s)...", appObjectID, endDateTime[:10])

	endpoint := fmt.Sprintf(graph.EndpointAppAddPassword, appObjectID)
	respRaw, err := client.Post(ctx, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("add password: %w", err)
	}

	var cred map[string]interface{}
	if err := json.Unmarshal(respRaw, &cred); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	keyID, _ := cred["keyId"].(string)
	secretText, _ := cred["secretText"].(string)
	expiresAt, _ := cred["endDateTime"].(string)

	result := &AppCredsResult{
		AppObjectID: appObjectID,
		KeyID:       keyID,
		SecretText:  secretText,
		ExpiresAt:   expiresAt,
	}

	output.Success("Credential added!")
	output.Warn("  Key ID    : %s", keyID)
	output.Warn("  Secret    : %s", secretText)
	output.Warn("  Expires   : %s", expiresAt)
	output.Warn("  *** Save this secret — it will NOT be shown again ***")

	return result, nil
}

// FindAppByDisplayName searches for an application by display name and returns its object ID.
func FindAppByDisplayName(ctx context.Context, client *graph.Client, displayName string) (objectID, appID, name string, err error) {
	raw, err := client.GetAll(ctx, graph.EndpointApplications, map[string]string{
		"$filter": fmt.Sprintf("displayName eq '%s'", displayName),
		"$select": "id,appId,displayName",
		"$top":    "10",
	})
	if err != nil {
		return "", "", "", fmt.Errorf("search apps: %w", err)
	}
	if len(raw) == 0 {
		return "", "", "", fmt.Errorf("no app found with displayName %q", displayName)
	}
	var app map[string]interface{}
	json.Unmarshal(raw[0], &app)
	objectID, _ = app["id"].(string)
	appID, _ = app["appId"].(string)
	name, _ = app["displayName"].(string)
	return
}
