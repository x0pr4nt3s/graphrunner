package escalate

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// Endpoints for adding owners via $ref.
const (
	endpointAppOwnerRef   = "/applications/%s/owners/$ref"
	endpointGroupOwnerRef = "/groups/%s/owners/$ref"
)

// directoryObjectRef builds the @odata.id reference for a directory object.
func directoryObjectRef(principalID string) map[string]interface{} {
	return map[string]interface{}{
		"@odata.id": fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", principalID),
	}
}

// AddAppOwner adds a principal as owner of an application.
// Uses POST /applications/{appObjectId}/owners/$ref
func AddAppOwner(ctx context.Context, client *graph.Client, appObjectID, principalID string) error {
	ref := directoryObjectRef(principalID)
	endpoint := fmt.Sprintf(endpointAppOwnerRef, appObjectID)

	output.Info("Adding owner %s to application %s...", principalID, appObjectID)

	_, err := client.Post(ctx, endpoint, ref)
	if err != nil {
		return fmt.Errorf("add owner %s to app %s: %w", principalID, appObjectID, err)
	}

	output.Success("Added owner %s to application %s", principalID, appObjectID)
	return nil
}

// AddGroupOwner adds a principal as owner of a group.
// Uses POST /groups/{groupId}/owners/$ref
func AddGroupOwner(ctx context.Context, client *graph.Client, groupID, principalID string) error {
	ref := directoryObjectRef(principalID)
	endpoint := fmt.Sprintf(endpointGroupOwnerRef, groupID)

	output.Info("Adding owner %s to group %s...", principalID, groupID)

	_, err := client.Post(ctx, endpoint, ref)
	if err != nil {
		return fmt.Errorf("add owner %s to group %s: %w", principalID, groupID, err)
	}

	output.Success("Added owner %s to group %s", principalID, groupID)
	return nil
}
