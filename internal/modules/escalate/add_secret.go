package escalate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AddSecretResult contains the result of adding a password secret to a service principal.
type AddSecretResult struct {
	SPObjectID  string `json:"sp_object_id"`
	KeyID       string `json:"key_id"`
	DisplayName string `json:"display_name"`
	SecretText  string `json:"secret_text"`
	StartDate   string `json:"start_date"`
	EndDate     string `json:"end_date"`
}

// AddSPSecret adds a password credential directly to a service principal.
// Different from app-level addPassword — this targets the SP in the tenant.
// Requires Application.ReadWrite.All or owner of the SP.
func AddSPSecret(ctx context.Context, c *graph.Client, spObjectID, displayName string, validDays int) (*AddSecretResult, error) {
	if validDays <= 0 {
		validDays = 365
	}

	endDate := time.Now().AddDate(0, 0, validDays).UTC().Format(time.RFC3339)

	payload := map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": displayName,
			"endDateTime": endDate,
		},
	}

	endpoint := fmt.Sprintf("/servicePrincipals/%s/addPassword", spObjectID)
	output.Info("Adding password secret to SP %s...", spObjectID)

	raw, err := c.Post(ctx, endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("add SP secret: %w", err)
	}

	var resp struct {
		KeyID       string `json:"keyId"`
		DisplayName string `json:"displayName"`
		SecretText  string `json:"secretText"`
		StartDate   string `json:"startDateTime"`
		EndDate     string `json:"endDateTime"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	result := &AddSecretResult{
		SPObjectID:  spObjectID,
		KeyID:       resp.KeyID,
		DisplayName: resp.DisplayName,
		SecretText:  resp.SecretText,
		StartDate:   resp.StartDate,
		EndDate:     resp.EndDate,
	}

	output.Success("Secret added to SP %s", spObjectID)
	output.Info("  Key ID:  %s", result.KeyID)
	output.Info("  Secret:  %s", result.SecretText)
	output.Info("  Expires: %s", result.EndDate)
	output.Warn("Save the secret — it cannot be retrieved again!")

	return result, nil
}
