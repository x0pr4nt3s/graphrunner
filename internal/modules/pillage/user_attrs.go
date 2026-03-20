package pillage

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// UserAttrHit represents a user whose attributes contain a keyword match.
type UserAttrHit struct {
	UserPrincipalName string            `json:"user_principal_name"`
	Matches           map[string]string `json:"matches"` // field -> value
}

// UserAttrsResult holds user attribute search results.
type UserAttrsResult struct {
	Keywords   []string      `json:"keywords"`
	TotalHits  int           `json:"total_hits"`
	Hits       []UserAttrHit `json:"hits"`
}

// SearchUserAttributes searches all user attributes for sensitive data matching keywords.
func SearchUserAttributes(ctx context.Context, client *graph.Client, keywords []string) (*UserAttrsResult, error) {
	result := &UserAttrsResult{Keywords: keywords}

	output.Info("Enumerating users for attribute search...")
	usersRaw, err := client.GetAll(ctx, graph.EndpointUsers, map[string]string{
		"$select": "id,displayName,userPrincipalName,mail,jobTitle,department,officeLocation,mobilePhone,businessPhones,streetAddress,city,state,postalCode,country,companyName,aboutMe,mySite,preferredLanguage,employeeId,onPremisesExtensionAttributes",
		"$top":    "999",
	})
	if err != nil {
		return nil, err
	}

	output.Info("Scanning %d users for keywords: %s", len(usersRaw), strings.Join(keywords, ", "))

	for _, uRaw := range usersRaw {
		var user map[string]interface{}
		json.Unmarshal(uRaw, &user)

		upn, _ := user["userPrincipalName"].(string)
		output.Verbose("scanning %s", upn)
		hit := UserAttrHit{
			UserPrincipalName: upn,
			Matches:           make(map[string]string),
		}

		for field, val := range user {
			valStr := stringify(val)
			if valStr == "" {
				continue
			}
			lower := strings.ToLower(valStr)
			for _, kw := range keywords {
				if strings.Contains(lower, strings.ToLower(strings.TrimSpace(kw))) {
					hit.Matches[field] = valStr
					output.Verbose("  MATCH  %s.%s = %s", upn, field, valStr)
					break
				}
			}
		}

		if len(hit.Matches) > 0 {
			result.Hits = append(result.Hits, hit)
			result.TotalHits++
			output.Success("  Hit: %s (%d fields matched)", upn, len(hit.Matches))
		}
	}

	output.Success("User attribute search complete: %d users with matches", result.TotalHits)
	return result, nil
}

func stringify(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case nil:
		return ""
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}
