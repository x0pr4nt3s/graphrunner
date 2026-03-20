package escalate

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Endpoint for patching a user.
const endpointUser = "/users/%s"

// ResetPassword resets a user's password.
// Requires User Administrator, Password Administrator, or Helpdesk Administrator role.
// Uses PATCH /users/{userId}
func ResetPassword(ctx context.Context, client *graph.Client, userID, newPassword string) error {
	body := map[string]interface{}{
		"passwordProfile": map[string]interface{}{
			"password":                             newPassword,
			"forceChangePasswordNextSignIn":        false,
			"forceChangePasswordNextSignInWithMfa": false,
		},
	}

	endpoint := fmt.Sprintf(endpointUser, userID)

	output.Info("Resetting password for user %s...", userID)

	_, err := client.Patch(ctx, endpoint, body)
	if err != nil {
		return fmt.Errorf("reset password for %s: %w", userID, err)
	}

	output.Success("Password reset for user %s", userID)
	return nil
}
