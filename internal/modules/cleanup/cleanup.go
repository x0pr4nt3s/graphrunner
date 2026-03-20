package cleanup

import (
	"context"
	"fmt"

	"github.com/graphrunner/internal/graph"
)

// DeleteApp removes an application registration by object ID.
func DeleteApp(ctx context.Context, client *graph.Client, appObjectID string) error {
	endpoint := fmt.Sprintf(graph.EndpointDeleteApp, appObjectID)
	return client.Delete(ctx, endpoint)
}

// DeleteGroup removes a group by object ID.
func DeleteGroup(ctx context.Context, client *graph.Client, groupID string) error {
	endpoint := fmt.Sprintf(graph.EndpointDeleteGroup, groupID)
	return client.Delete(ctx, endpoint)
}

// RemoveMember removes a member from a group.
func RemoveMember(ctx context.Context, client *graph.Client, groupID, memberID string) error {
	endpoint := fmt.Sprintf(graph.EndpointRemoveGroupMember, groupID, memberID)
	return client.Delete(ctx, endpoint)
}
