package persist

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// AddGroupMember adds a user or service principal to a group by ID.
func AddGroupMember(ctx context.Context, client *graph.Client, groupID, memberID string) error {
	ref := map[string]interface{}{
		"@odata.id": fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", memberID),
	}

	endpoint := fmt.Sprintf(graph.EndpointGroupMemberRef, groupID)
	_, err := client.Post(ctx, endpoint, ref)
	if err != nil {
		return fmt.Errorf("add member %s to group %s: %w", memberID, groupID, err)
	}

	output.Success("Added member %s to group %s", memberID, groupID)
	return nil
}
