package pillage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// InboxResult holds inbox messages.
type InboxResult struct {
	UserID   string                   `json:"user_id"`
	Count    int                      `json:"count"`
	Messages []map[string]interface{} `json:"messages"`
}

// ReadInbox reads inbox messages for a user.
func ReadInbox(ctx context.Context, client *graph.Client, userID string, top int) (*InboxResult, error) {
	var endpoint string
	if userID == "" {
		// Current user
		endpoint = "/me/mailFolders/Inbox/messages"
		userID = "me"
	} else {
		endpoint = fmt.Sprintf(graph.EndpointUserInbox, userID)
	}

	output.Info("Reading inbox for %s (top %d)...", userID, top)

	raw, err := client.GetAll(ctx, endpoint, map[string]string{
		"$select":  "subject,from,receivedDateTime,bodyPreview,hasAttachments,importance",
		"$top":     fmt.Sprintf("%d", top),
		"$orderby": "receivedDateTime desc",
	})
	if err != nil {
		return nil, err
	}

	result := &InboxResult{UserID: userID, Count: len(raw)}
	for _, r := range raw {
		var m map[string]interface{}
		json.Unmarshal(r, &m)
		result.Messages = append(result.Messages, m)
		subject, _ := m["subject"].(string)
		from, _ := m["from"].(map[string]interface{})
		fromAddr := ""
		if ep, ok := from["emailAddress"].(map[string]interface{}); ok {
			fromAddr, _ = ep["address"].(string)
		}
		received, _ := m["receivedDateTime"].(string)
		output.Verbose("[%s] from=%-35s  %s", received[:10], fromAddr, subject)
	}

	output.Success("Read %d messages from %s inbox", result.Count, userID)
	return result, nil
}
