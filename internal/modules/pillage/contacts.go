package pillage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Contact represents a user's Outlook contact.
type Contact struct {
	ID               string   `json:"id"`
	DisplayName      string   `json:"displayName"`
	GivenName        string   `json:"givenName,omitempty"`
	Surname          string   `json:"surname,omitempty"`
	EmailAddresses   []Email  `json:"emailAddresses,omitempty"`
	BusinessPhones   []string `json:"businessPhones,omitempty"`
	MobilePhone      string   `json:"mobilePhone,omitempty"`
	CompanyName      string   `json:"companyName,omitempty"`
	JobTitle         string   `json:"jobTitle,omitempty"`
	Department       string   `json:"department,omitempty"`
}

// Email is an email address entry in a contact.
type Email struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// ContactsResult holds the contacts enumeration.
type ContactsResult struct {
	UserID   string    `json:"user_id"`
	Contacts []Contact `json:"contacts"`
	Total    int       `json:"total"`
}

// ReadContacts enumerates Outlook contacts for a user.
// If userID is empty, uses /me/contacts.
func ReadContacts(ctx context.Context, c *graph.Client, userID string) (*ContactsResult, error) {
	var endpoint string
	if userID == "" {
		endpoint = "/me/contacts"
		output.Info("Fetching contacts for current user...")
	} else {
		endpoint = fmt.Sprintf("/users/%s/contacts", userID)
		output.Info("Fetching contacts for %s...", userID)
	}

	raw, err := c.GetAll(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}

	result := &ContactsResult{UserID: userID}
	if userID == "" {
		result.UserID = "me"
	}

	for _, r := range raw {
		var contact Contact
		if err := json.Unmarshal(r, &contact); err != nil {
			continue
		}
		result.Contacts = append(result.Contacts, contact)

		emails := ""
		for _, e := range contact.EmailAddresses {
			if emails != "" {
				emails += ", "
			}
			emails += e.Address
		}
		output.Verbose("[contact] %s | %s | %s | %s",
			contact.DisplayName, emails, contact.CompanyName, contact.JobTitle)
	}

	result.Total = len(result.Contacts)
	output.Success("Contacts: %d entries", result.Total)
	return result, nil
}
