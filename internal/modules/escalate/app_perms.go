package escalate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Well-known Microsoft Graph application permission (appRole) IDs.
const (
	AppRoleMailReadWrite           = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"
	AppRoleMailRead                = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
	AppRoleFilesReadWriteAll       = "75359482-378d-4052-8f01-80520e7db3cd"
	AppRoleUserReadWriteAll        = "741f803b-c850-494e-b5df-cde7c675a1ca"
	AppRoleDirectoryReadWriteAll   = "19dbc75e-c2e2-444c-a770-ec596d67b1ff"
	AppRoleApplicationReadWriteAll = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
	AppRoleRoleMgmtReadWriteDir    = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
)

// Microsoft Graph resource application ID (same across all tenants).
const graphResourceAppID = "00000003-0000-0000-c000-000000000000"

// Endpoint for appRoleAssignments on a service principal.
const endpointSPAppRoleAssignments = "/servicePrincipals/%s/appRoleAssignments"

// AppPermResult holds the result of granting an application permission.
type AppPermResult struct {
	ID           string `json:"id"`
	PrincipalID  string `json:"principal_id"`
	ResourceID   string `json:"resource_id"`
	AppRoleID    string `json:"app_role_id"`
}

// GrantAppPermission assigns an app role (application permission) to a service principal.
// Uses POST /servicePrincipals/{spId}/appRoleAssignments
func GrantAppPermission(ctx context.Context, client *graph.Client, targetSPID, resourceSPID, appRoleID string) (*AppPermResult, error) {
	body := map[string]interface{}{
		"principalId": targetSPID,
		"resourceId":  resourceSPID,
		"appRoleId":   appRoleID,
	}

	endpoint := fmt.Sprintf(endpointSPAppRoleAssignments, targetSPID)

	output.Info("Granting app role %s to SP %s (resource: %s)...", appRoleID, targetSPID, resourceSPID)

	respRaw, err := client.Post(ctx, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("grant app permission: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(respRaw, &data); err != nil {
		return nil, fmt.Errorf("parse app role assignment response: %w", err)
	}

	assignmentID, _ := data["id"].(string)

	result := &AppPermResult{
		ID:          assignmentID,
		PrincipalID: targetSPID,
		ResourceID:  resourceSPID,
		AppRoleID:   appRoleID,
	}

	output.Success("App permission granted!")
	output.Info("  Assignment ID  : %s", assignmentID)
	output.Info("  Target SP      : %s", targetSPID)
	output.Info("  Resource SP    : %s", resourceSPID)
	output.Info("  App Role       : %s", appRoleID)

	return result, nil
}

// FindGraphSPID finds the Microsoft Graph service principal in the tenant.
// Searches for the well-known appId 00000003-0000-0000-c000-000000000000.
func FindGraphSPID(ctx context.Context, client *graph.Client) (string, error) {
	output.Info("Looking up Microsoft Graph service principal...")

	raw, err := client.GetAll(ctx, graph.EndpointServicePrincs, map[string]string{
		"$filter": fmt.Sprintf("appId eq '%s'", graphResourceAppID),
		"$select": "id,appId,displayName",
		"$top":    "1",
	})
	if err != nil {
		return "", fmt.Errorf("find Graph SP: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("Microsoft Graph service principal not found in tenant")
	}

	var sp map[string]interface{}
	if err := json.Unmarshal(raw[0], &sp); err != nil {
		return "", fmt.Errorf("parse Graph SP response: %w", err)
	}

	spID, _ := sp["id"].(string)
	if spID == "" {
		return "", fmt.Errorf("Microsoft Graph SP has empty id")
	}

	displayName, _ := sp["displayName"].(string)
	output.Success("Found Microsoft Graph SP: %s (%s)", spID, displayName)

	return spID, nil
}
