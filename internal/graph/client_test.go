package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Get(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]string{"id": "123", "name": "test"})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	var data map[string]string
	json.Unmarshal(resp, &data)
	if data["id"] != "123" {
		t.Errorf("expected id=123, got %s", data["id"])
	}
}

func TestClient_GetAll_Pagination(t *testing.T) {
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			// First page with nextLink
			resp := map[string]interface{}{
				"value":          []map[string]string{{"id": "1"}, {"id": "2"}},
				"@odata.nextLink": "", // will be set below
			}
			resp["@odata.nextLink"] = "" // No more pages actually
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]string{{"id": "1"}, {"id": "2"}},
			})
		default:
			t.Error("unexpected request")
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	items, err := client.GetAll(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}

	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
}

func TestClient_GetAll_MultiPage(t *testing.T) {
	var server *httptest.Server
	callCount := 0

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			resp := map[string]interface{}{
				"value":           []map[string]string{{"id": "1"}},
				"@odata.nextLink": server.URL + "/page2",
			}
			json.NewEncoder(w).Encode(resp)
		case 2:
			resp := map[string]interface{}{
				"value": []map[string]string{{"id": "2"}, {"id": "3"}},
			}
			json.NewEncoder(w).Encode(resp)
		default:
			t.Error("unexpected third request")
		}
	})
	server = httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	items, err := client.GetAll(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}

	if len(items) != 3 {
		t.Errorf("expected 3 items across 2 pages, got %d", len(items))
	}
}

func TestClient_Post(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "new-123"})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	resp, err := client.Post(context.Background(), server.URL, map[string]string{"name": "test"})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}

	var data map[string]string
	json.Unmarshal(resp, &data)
	if data["id"] != "new-123" {
		t.Errorf("expected id=new-123, got %s", data["id"])
	}
}

func TestClient_Delete(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	err := client.Delete(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestClient_RateLimitRetry(t *testing.T) {
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"throttled"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("test-token")
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get after rate limit: %v", err)
	}

	var data map[string]string
	json.Unmarshal(resp, &data)
	if data["status"] != "ok" {
		t.Errorf("expected ok after retry, got %s", data["status"])
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls (1 retry), got %d", callCount)
	}
}

func TestClient_Unauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewClient("bad-token")
	_, err := client.Get(context.Background(), server.URL, nil)
	if err == nil {
		t.Error("expected error for 401")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("short string should not be truncated")
	}
	result := truncate("this is a long string", 10)
	if len(result) > 14 { // 10 + "..."
		t.Errorf("truncated string too long: %q", result)
	}
}

func TestBuildURL(t *testing.T) {
	client := NewClient("token")
	if url := client.buildURL("/users"); url != GraphBaseV1+"/users" {
		t.Errorf("expected prefixed URL, got %s", url)
	}
	if url := client.buildURL("https://example.com/api"); url != "https://example.com/api" {
		t.Errorf("expected raw URL, got %s", url)
	}
}
