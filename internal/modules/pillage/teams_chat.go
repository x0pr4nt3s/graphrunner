package pillage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// ChatResult holds Teams chat data.
type ChatResult struct {
	TotalChats int                      `json:"total_chats"`
	Chats      []map[string]interface{} `json:"chats"`
}

// ReadChats reads Teams chats and their messages.
func ReadChats(ctx context.Context, client *graph.Client, limit int) (*ChatResult, error) {
	output.Info("Reading Teams chats...")

	chatsRaw, err := client.GetAll(ctx, graph.EndpointMeChats, map[string]string{
		"$expand": "members,lastMessagePreview",
		"$top":    fmt.Sprintf("%d", limit),
	})
	if err != nil {
		return nil, err
	}

	result := &ChatResult{TotalChats: len(chatsRaw)}

	for _, cRaw := range chatsRaw {
		var chat map[string]interface{}
		json.Unmarshal(cRaw, &chat)

		chatID, _ := chat["id"].(string)
		chatType, _ := chat["chatType"].(string)
		topic, _ := chat["topic"].(string)
		if topic == "" {
			topic = chatType
		}
		if chatID == "" {
			continue
		}

		output.Verbose("chat  %s  [%s]", topic, chatID)

		// Fetch messages for this chat
		endpoint := fmt.Sprintf(graph.EndpointChatMessages, chatID)
		msgsRaw, err := client.GetAll(ctx, endpoint, map[string]string{
			"$top": "50",
		})
		if err != nil {
			output.Warn("Chat %s messages: %v", chatID, err)
			chat["messages"] = []interface{}{}
		} else {
			var msgs []interface{}
			for _, mRaw := range msgsRaw {
				var m interface{}
				json.Unmarshal(mRaw, &m)
				if mMap, ok := m.(map[string]interface{}); ok {
					body, _ := mMap["body"].(map[string]interface{})
					content, _ := body["content"].(string)
					from, _ := mMap["from"].(map[string]interface{})
					sender := ""
					if user, ok := from["user"].(map[string]interface{}); ok {
						sender, _ = user["displayName"].(string)
					}
					if len(content) > 80 {
						content = content[:80] + "…"
					}
					output.Verbose("  [%s] %s", sender, content)
				}
				msgs = append(msgs, m)
			}
			chat["messages"] = msgs
			output.Verbose("  → %d messages", len(msgs))
		}

		result.Chats = append(result.Chats, chat)
	}

	output.Success("Read %d chats with messages", result.TotalChats)
	return result, nil
}
