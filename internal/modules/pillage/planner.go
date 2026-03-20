package pillage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// PlannerPlan represents a Planner plan.
type PlannerPlan struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Owner     string `json:"owner"`
	CreatedBy struct {
		User struct {
			DisplayName string `json:"displayName"`
			ID          string `json:"id"`
		} `json:"user"`
	} `json:"createdBy"`
	CreatedDateTime string `json:"createdDateTime"`
}

// PlannerTask represents a task within a Planner plan.
type PlannerTask struct {
	ID               string `json:"id"`
	PlanID           string `json:"planId"`
	Title            string `json:"title"`
	PercentComplete  int    `json:"percentComplete"`
	Priority         int    `json:"priority"`
	StartDateTime    string `json:"startDateTime,omitempty"`
	DueDateTime      string `json:"dueDateTime,omitempty"`
	CompletedDateTime string `json:"completedDateTime,omitempty"`
	CreatedDateTime  string `json:"createdDateTime"`
	AssignedTo       []string `json:"assigned_to,omitempty"`
}

// PlannerResult holds all Planner data for enumeration.
type PlannerResult struct {
	Plans     []PlannerPlan `json:"plans"`
	Tasks     []PlannerTask `json:"tasks"`
	PlanCount int           `json:"plan_count"`
	TaskCount int           `json:"task_count"`
}

// ReadPlanner enumerates Planner plans and tasks.
// If groupID is provided, lists plans for that group. Otherwise uses /me/planner/plans.
func ReadPlanner(ctx context.Context, c *graph.Client, groupID string) (*PlannerResult, error) {
	result := &PlannerResult{}

	var plansEndpoint string
	if groupID != "" {
		plansEndpoint = fmt.Sprintf("/groups/%s/planner/plans", groupID)
		output.Info("Fetching Planner plans for group %s...", groupID)
	} else {
		plansEndpoint = "/me/planner/plans"
		output.Info("Fetching Planner plans for current user...")
	}

	plansRaw, err := c.GetAll(ctx, plansEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch plans: %w", err)
	}

	for _, raw := range plansRaw {
		var plan PlannerPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			continue
		}
		result.Plans = append(result.Plans, plan)
		output.Verbose("[planner] Plan: %s (owner: %s)", plan.Title, plan.Owner)

		// Fetch tasks for each plan
		tasksEndpoint := fmt.Sprintf("/planner/plans/%s/tasks", plan.ID)
		tasksRaw, err := c.GetAll(ctx, tasksEndpoint, nil)
		if err != nil {
			output.Verbose("[planner] Error fetching tasks for plan %s: %v", plan.ID, err)
			continue
		}

		for _, taskRaw := range tasksRaw {
			var task PlannerTask
			if err := json.Unmarshal(taskRaw, &task); err != nil {
				continue
			}

			// Extract assignment keys (user IDs)
			var assignments map[string]json.RawMessage
			var raw2 map[string]json.RawMessage
			if err := json.Unmarshal(taskRaw, &raw2); err == nil {
				if assignRaw, ok := raw2["assignments"]; ok {
					if err := json.Unmarshal(assignRaw, &assignments); err == nil {
						for userID := range assignments {
							task.AssignedTo = append(task.AssignedTo, userID)
						}
					}
				}
			}

			result.Tasks = append(result.Tasks, task)
			output.Verbose("[planner]   Task: %s (%d%% complete, priority: %d)",
				task.Title, task.PercentComplete, task.Priority)
		}
	}

	result.PlanCount = len(result.Plans)
	result.TaskCount = len(result.Tasks)

	output.Success("Planner: %d plans, %d tasks", result.PlanCount, result.TaskCount)
	return result, nil
}
