package escalate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Well-known Azure AD directory role definition IDs.
const (
	RoleGlobalAdmin        = "62e90394-69f5-4237-9190-012177145e10"
	RoleApplicationAdmin   = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
	RoleCloudAppAdmin      = "158c047a-c907-4556-b7ef-446551a6b5f7"
	RolePrivilegedRoleAdmin = "e8611ab8-c189-46e8-94e1-60213ab1f814"
	RoleUserAdmin          = "fe930be7-5e62-47db-91af-98c3a49a38b1"
	RoleExchangeAdmin      = "29232cdf-9323-42fd-ade2-1d097af3e4de"
	RoleSecurityAdmin      = "194ae4cb-b126-40b2-bd5b-6091b380977d"
)

// RoleAssignResult holds the result of a directory role assignment.
type RoleAssignResult struct {
	ID               string `json:"id"`
	RoleDefinitionID string `json:"role_definition_id"`
	PrincipalID      string `json:"principal_id"`
	DirectoryScopeID string `json:"directory_scope_id"`
}

// RoleDefinition represents an Azure AD directory role definition.
type RoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	IsBuiltIn   bool   `json:"is_built_in"`
	IsEnabled   bool   `json:"is_enabled"`
}

// AssignRole assigns a directory role to a principal (user or service principal).
// Uses POST /roleManagement/directory/roleAssignments
func AssignRole(ctx context.Context, client *graph.Client, roleDefinitionID, principalID string) (*RoleAssignResult, error) {
	body := map[string]interface{}{
		"@odata.type":      "#microsoft.graph.unifiedRoleAssignment",
		"roleDefinitionId": roleDefinitionID,
		"principalId":      principalID,
		"directoryScopeId": "/",
	}

	output.Info("Assigning role %s to principal %s...", roleDefinitionID, principalID)

	respRaw, err := client.Post(ctx, graph.EndpointRoleAssignments, body)
	if err != nil {
		return nil, fmt.Errorf("assign role: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(respRaw, &data); err != nil {
		return nil, fmt.Errorf("parse role assignment response: %w", err)
	}

	assignmentID, _ := data["id"].(string)

	result := &RoleAssignResult{
		ID:               assignmentID,
		RoleDefinitionID: roleDefinitionID,
		PrincipalID:      principalID,
		DirectoryScopeID: "/",
	}

	output.Success("Role assigned!")
	output.Info("  Assignment ID    : %s", assignmentID)
	output.Info("  Role Definition  : %s", roleDefinitionID)
	output.Info("  Principal        : %s", principalID)

	return result, nil
}

// ListRoleDefinitions enumerates all available directory role definitions.
// Uses GET /roleManagement/directory/roleDefinitions
func ListRoleDefinitions(ctx context.Context, client *graph.Client) ([]RoleDefinition, error) {
	output.Info("Enumerating directory role definitions...")

	raw, err := client.GetAll(ctx, graph.EndpointRoleDefinitions, map[string]string{
		"$select": "id,displayName,description,isBuiltIn,isEnabled",
	})
	if err != nil {
		return nil, fmt.Errorf("list role definitions: %w", err)
	}

	var roles []RoleDefinition
	for _, item := range raw {
		var rd map[string]interface{}
		if err := json.Unmarshal(item, &rd); err != nil {
			output.Warn("Skip malformed role definition: %v", err)
			continue
		}

		role := RoleDefinition{
			ID:          strVal(rd, "id"),
			DisplayName: strVal(rd, "displayName"),
			Description: strVal(rd, "description"),
		}
		if v, ok := rd["isBuiltIn"].(bool); ok {
			role.IsBuiltIn = v
		}
		if v, ok := rd["isEnabled"].(bool); ok {
			role.IsEnabled = v
		}
		roles = append(roles, role)
		output.Verbose("  [%s] %s", role.ID, role.DisplayName)
	}

	output.Success("Found %d role definitions", len(roles))
	return roles, nil
}

// strVal safely extracts a string value from a map.
func strVal(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
