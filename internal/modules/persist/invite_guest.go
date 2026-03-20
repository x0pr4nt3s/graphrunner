package persist

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// GuestResult holds the result of a guest invitation.
type GuestResult struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	InviteURL   string `json:"invite_redeem_url"`
	Status      string `json:"status"`
	UserID      string `json:"user_id"`
}

// InviteGuest invites an external guest user to the tenant.
func InviteGuest(ctx context.Context, client *graph.Client, email, displayName, redirectURL string) (*GuestResult, error) {
	if displayName == "" {
		displayName = email
	}

	payload := map[string]interface{}{
		"invitedUserEmailAddress": email,
		"invitedUserDisplayName":  displayName,
		"inviteRedirectUrl":       redirectURL,
		"sendInvitationMessage":   false,
	}

	output.Info("Inviting guest: %s (%s)", email, displayName)
	resp, err := client.Post(ctx, graph.EndpointInvitations, payload)
	if err != nil {
		return nil, fmt.Errorf("invite guest: %w", err)
	}

	var data map[string]interface{}
	json.Unmarshal(resp, &data)

	inviteURL, _ := data["inviteRedeemUrl"].(string)
	status, _ := data["status"].(string)

	invitedUser, _ := data["invitedUser"].(map[string]interface{})
	userID := ""
	if invitedUser != nil {
		userID, _ = invitedUser["id"].(string)
	}

	result := &GuestResult{
		Email:       email,
		DisplayName: displayName,
		InviteURL:   inviteURL,
		Status:      status,
		UserID:      userID,
	}

	output.Success("Guest invited! User ID: %s, Status: %s", userID, status)
	if inviteURL != "" {
		output.Info("Redeem URL: %s", inviteURL)
	}

	return result, nil
}
