package pillage

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// SendMailResult contains the result of sending an email.
type SendMailResult struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Status  string   `json:"status"`
}

// SendMail sends an email as the specified user (or current user if userID is empty).
// Requires Mail.Send permission (delegated or application).
func SendMail(ctx context.Context, c *graph.Client, userID, subject, body string, toAddresses []string, isHTML bool) (*SendMailResult, error) {
	if len(toAddresses) == 0 {
		return nil, fmt.Errorf("at least one recipient required")
	}
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}

	// Build recipients
	recipients := make([]map[string]interface{}, len(toAddresses))
	for i, addr := range toAddresses {
		recipients[i] = map[string]interface{}{
			"emailAddress": map[string]string{
				"address": addr,
			},
		}
	}

	contentType := "text"
	if isHTML {
		contentType = "html"
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"subject": subject,
			"body": map[string]string{
				"contentType": contentType,
				"content":     body,
			},
			"toRecipients": recipients,
		},
		"saveToSentItems": false,
	}

	var endpoint string
	if userID == "" {
		endpoint = "/me/sendMail"
	} else {
		endpoint = fmt.Sprintf("/users/%s/sendMail", userID)
	}

	output.Info("Sending mail via %s...", endpoint)
	_, err := c.Post(ctx, endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("send mail: %w", err)
	}

	result := &SendMailResult{
		From:    userID,
		To:      toAddresses,
		Subject: subject,
		Status:  "sent",
	}
	if userID == "" {
		result.From = "me"
	}

	output.Success("Email sent: \"%s\" → %v", subject, toAddresses)
	return result, nil
}
