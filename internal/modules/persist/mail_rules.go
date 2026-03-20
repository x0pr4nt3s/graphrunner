package persist

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// MailRuleResult holds the result of creating an inbox rule.
type MailRuleResult struct {
	RuleID      string   `json:"rule_id"`
	DisplayName string   `json:"display_name"`
	UserID      string   `json:"user_id"`
	ForwardTo   string   `json:"forward_to"`
	Keywords    []string `json:"keywords,omitempty"`
	IsEnabled   bool     `json:"is_enabled"`
}

// MailRule represents a single inbox rule from Graph API.
type MailRule struct {
	ID          string      `json:"id"`
	DisplayName string      `json:"displayName"`
	Sequence    int         `json:"sequence"`
	IsEnabled   bool        `json:"isEnabled"`
	Conditions  interface{} `json:"conditions,omitempty"`
	Actions     interface{} `json:"actions,omitempty"`
}

// MailRulesListResult holds the result of listing inbox rules.
type MailRulesListResult struct {
	UserID string     `json:"user_id"`
	Rules  []MailRule `json:"rules"`
	Count  int        `json:"count"`
}

// CreateMailRule creates an inbox rule that forwards matching emails to an external address.
// Uses POST /users/{userId}/mailFolders/inbox/messageRules
//
// If keywords is empty, the rule matches all incoming messages.
// If keywords is provided, the rule only matches messages whose subject contains any of the keywords.
func CreateMailRule(ctx context.Context, client *graph.Client, userID, ruleName, forwardTo string, keywords []string) (*MailRuleResult, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required (UPN or object ID)")
	}
	if ruleName == "" {
		ruleName = "Inbox Organizer"
	}
	if forwardTo == "" {
		return nil, fmt.Errorf("forwardTo email address is required")
	}

	// Build the rule payload
	actions := map[string]interface{}{
		"forwardTo": []map[string]interface{}{
			{
				"emailAddress": map[string]interface{}{
					"address": forwardTo,
				},
			},
		},
		"stopProcessingRules": true,
	}

	body := map[string]interface{}{
		"displayName": ruleName,
		"sequence":    1,
		"isEnabled":   true,
		"actions":     actions,
	}

	// Add subject keyword conditions if provided
	if len(keywords) > 0 {
		body["conditions"] = map[string]interface{}{
			"subjectContains": keywords,
		}
	}

	endpoint := fmt.Sprintf("/users/%s/mailFolders/inbox/messageRules", userID)

	output.Info("Creating inbox rule for %s...", userID)
	output.Info("  Rule name:  %s", ruleName)
	output.Info("  Forward to: %s", forwardTo)
	if len(keywords) > 0 {
		output.Info("  Keywords:   %v", keywords)
	} else {
		output.Info("  Keywords:   (all messages)")
	}

	respRaw, err := client.Post(ctx, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("create mail rule: %w", err)
	}

	var ruleData map[string]interface{}
	if err := json.Unmarshal(respRaw, &ruleData); err != nil {
		return nil, fmt.Errorf("parse rule response: %w", err)
	}

	ruleID, _ := ruleData["id"].(string)

	result := &MailRuleResult{
		RuleID:      ruleID,
		DisplayName: ruleName,
		UserID:      userID,
		ForwardTo:   forwardTo,
		Keywords:    keywords,
		IsEnabled:   true,
	}

	output.Success("Inbox rule created!")
	output.Info("  Rule ID:    %s", ruleID)
	output.Info("  User:       %s", userID)
	output.Info("  Forward to: %s", forwardTo)
	output.Warn("  Emails matching this rule will be silently forwarded.")

	return result, nil
}

// ListMailRules enumerates existing inbox rules for a user.
// Uses GET /users/{userId}/mailFolders/inbox/messageRules
func ListMailRules(ctx context.Context, client *graph.Client, userID string) (*MailRulesListResult, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required (UPN or object ID)")
	}

	endpoint := fmt.Sprintf("/users/%s/mailFolders/inbox/messageRules", userID)

	output.Info("Listing inbox rules for %s...", userID)

	raw, err := client.GetAll(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("list mail rules: %w", err)
	}

	var rules []MailRule
	for _, item := range raw {
		var rule MailRule
		if err := json.Unmarshal(item, &rule); err != nil {
			output.Warn("Failed to parse rule: %v", err)
			continue
		}
		rules = append(rules, rule)
		output.Verbose("  [%s] %s (enabled=%v, seq=%d)", rule.ID, rule.DisplayName, rule.IsEnabled, rule.Sequence)
	}

	result := &MailRulesListResult{
		UserID: userID,
		Rules:  rules,
		Count:  len(rules),
	}

	output.Info("Found %d inbox rules for %s", len(rules), userID)

	return result, nil
}
