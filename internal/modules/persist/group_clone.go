package persist

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// CloneResult holds the result of a group clone operation.
type CloneResult struct {
	SourceGroupID string `json:"source_group_id"`
	NewGroupID    string `json:"new_group_id"`
	DisplayName   string `json:"display_name"`
	MembersCopied int    `json:"members_copied"`
	SelfAdded     bool   `json:"self_added"`
}

// CloneGroup clones a security group and optionally adds the current user.
func CloneGroup(ctx context.Context, client *graph.Client, sourceGroupID string, addSelf bool) (*CloneResult, error) {
	// Get source group details
	output.Info("Reading source group %s...", sourceGroupID)
	groupRaw, err := client.Get(ctx, fmt.Sprintf("/groups/%s", sourceGroupID), map[string]string{
		"$select": "displayName,description,mailEnabled,securityEnabled,mailNickname,visibility",
	})
	if err != nil {
		return nil, fmt.Errorf("read source group: %w", err)
	}

	var sourceGroup map[string]interface{}
	if err := json.Unmarshal(groupRaw, &sourceGroup); err != nil {
		return nil, fmt.Errorf("parse source group: %w", err)
	}

	displayName, _ := sourceGroup["displayName"].(string)
	description, _ := sourceGroup["description"].(string)
	mailNickname, _ := sourceGroup["mailNickname"].(string)
	if mailNickname == "" {
		mailNickname = "group"
	}

	// Get source group members
	membersRaw, err := client.GetAll(ctx, fmt.Sprintf(graph.EndpointGroupMembers, sourceGroupID), map[string]string{
		"$select": "id",
	})
	if err != nil {
		output.Warn("Could not read source members: %v", err)
	}

	// Create clone group
	output.Info("Creating cloned group: %s", displayName)
	newGroupPayload := map[string]interface{}{
		"displayName":     displayName,
		"description":     description,
		"mailEnabled":     false,
		"securityEnabled": true,
		"mailNickname":    mailNickname + "-clone",
	}

	newGroupRaw, err := client.Post(ctx, graph.EndpointGroups, newGroupPayload)
	if err != nil {
		return nil, fmt.Errorf("create clone group: %w", err)
	}

	var newGroup map[string]interface{}
	if err := json.Unmarshal(newGroupRaw, &newGroup); err != nil {
		return nil, fmt.Errorf("parse new group response: %w", err)
	}
	newGroupID, _ := newGroup["id"].(string)
	if newGroupID == "" {
		return nil, fmt.Errorf("group creation succeeded but returned no ID: %s", newGroupRaw)
	}

	result := &CloneResult{
		SourceGroupID: sourceGroupID,
		NewGroupID:    newGroupID,
		DisplayName:   displayName,
	}

	// Copy members
	for _, mRaw := range membersRaw {
		var member map[string]interface{}
		json.Unmarshal(mRaw, &member)
		memberID, _ := member["id"].(string)
		if memberID == "" {
			continue
		}
		ref := map[string]interface{}{
			"@odata.id": fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", memberID),
		}
		endpoint := fmt.Sprintf(graph.EndpointGroupMemberRef, newGroupID)
		_, err := client.Post(ctx, endpoint, ref)
		if err == nil {
			result.MembersCopied++
		}
	}

	// Add self
	if addSelf {
		meRaw, err := client.Get(ctx, graph.EndpointMe, map[string]string{"$select": "id"})
		if err == nil {
			var me map[string]interface{}
			json.Unmarshal(meRaw, &me)
			myID, _ := me["id"].(string)
			if myID != "" {
				ref := map[string]interface{}{
					"@odata.id": fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", myID),
				}
				endpoint := fmt.Sprintf(graph.EndpointGroupMemberRef, newGroupID)
				_, err := client.Post(ctx, endpoint, ref)
				result.SelfAdded = (err == nil)
			}
		}
	}

	output.Success("Group cloned! New ID: %s (%d members copied, self added: %v)",
		newGroupID, result.MembersCopied, result.SelfAdded)

	return result, nil
}
