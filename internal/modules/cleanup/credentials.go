package cleanup

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// RemoveAppSecret removes a password credential from an application by keyId.
func RemoveAppSecret(ctx context.Context, c *graph.Client, appObjectID, keyID string) error {
	payload := map[string]string{
		"keyId": keyID,
	}
	endpoint := fmt.Sprintf("/applications/%s/removePassword", appObjectID)
	output.Info("Removing password credential %s from app %s...", keyID, appObjectID)

	_, err := c.Post(ctx, endpoint, payload)
	if err != nil {
		return fmt.Errorf("remove app secret: %w", err)
	}

	output.Success("Removed password credential %s from app %s", keyID, appObjectID)
	return nil
}

// RemoveSPSecret removes a password credential from a service principal by keyId.
func RemoveSPSecret(ctx context.Context, c *graph.Client, spObjectID, keyID string) error {
	payload := map[string]string{
		"keyId": keyID,
	}
	endpoint := fmt.Sprintf("/servicePrincipals/%s/removePassword", spObjectID)
	output.Info("Removing password credential %s from SP %s...", keyID, spObjectID)

	_, err := c.Post(ctx, endpoint, payload)
	if err != nil {
		return fmt.Errorf("remove SP secret: %w", err)
	}

	output.Success("Removed password credential %s from SP %s", keyID, spObjectID)
	return nil
}

// RemoveAppKeyCred removes a certificate credential from an application by keyId.
func RemoveAppKeyCred(ctx context.Context, c *graph.Client, appObjectID, keyID string) error {
	payload := map[string]string{
		"keyId": keyID,
	}
	endpoint := fmt.Sprintf("/applications/%s/removeKey", appObjectID)
	output.Info("Removing key credential %s from app %s...", keyID, appObjectID)

	_, err := c.Post(ctx, endpoint, payload)
	if err != nil {
		return fmt.Errorf("remove key credential: %w", err)
	}

	output.Success("Removed key credential %s from app %s", keyID, appObjectID)
	return nil
}

// RemoveMailRule deletes an inbox rule from a user's mailbox by rule ID.
func RemoveMailRule(ctx context.Context, c *graph.Client, userID, ruleID string) error {
	endpoint := fmt.Sprintf("/users/%s/mailFolders/inbox/messageRules/%s", userID, ruleID)
	output.Info("Removing mail rule %s from user %s...", ruleID, userID)

	if err := c.Delete(ctx, endpoint); err != nil {
		return fmt.Errorf("remove mail rule: %w", err)
	}

	output.Success("Removed mail rule %s from user %s", ruleID, userID)
	return nil
}
