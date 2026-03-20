package graph

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/graphrunner/internal/output"
)

// Client wraps net/http with Graph API auth, pagination, and retry logic.
type Client struct {
	httpClient  *http.Client
	accessToken string
	baseURL     string
	maxRetries  int
}

// NewClient creates a Graph API client with the given access token.
func NewClient(accessToken string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		accessToken: accessToken,
		baseURL:     GraphBaseV1,
		maxRetries:  3,
	}
}

// SetProxy configures an HTTP proxy (e.g. http://127.0.0.1:8080 for Burp/ZAP).
// TLS verification is disabled when a proxy is set (required for intercepting proxies).
func (c *Client) SetProxy(proxyURL string) error {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	c.httpClient.Transport = &http.Transport{
		Proxy:           http.ProxyURL(parsed),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 — required for intercepting proxies
	}
	return nil
}

// SetToken updates the access token (used after refresh).
func (c *Client) SetToken(token string) {
	c.accessToken = token
}

// UseBeta switches the client to the beta endpoint.
func (c *Client) UseBeta() {
	c.baseURL = GraphBaseBeta
}

// UseV1 switches the client back to v1.0.
func (c *Client) UseV1() {
	c.baseURL = GraphBaseV1
}

// GraphResponse wraps a raw Graph API JSON response.
type GraphResponse struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
	Context  string            `json:"@odata.context"`
}

// ---- HTTP Methods ----

// Get performs a single GET request and returns the parsed JSON.
func (c *Client) Get(ctx context.Context, endpoint string, params map[string]string) (json.RawMessage, error) {
	url := c.buildURL(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if len(params) > 0 {
		q := req.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	c.setHeaders(req)
	return c.doWithRetry(req)
}

// GetAll performs a paginated GET and returns all items from the "value" array.
func (c *Client) GetAll(ctx context.Context, endpoint string, params map[string]string) ([]json.RawMessage, error) {
	return c.GetAllWithProgress(ctx, endpoint, params, "")
}

// GetAllWithProgress performs a paginated GET with a live progress indicator.
// If label is non-empty, a progress line is printed after each page showing item count.
func (c *Client) GetAllWithProgress(ctx context.Context, endpoint string, params map[string]string, label string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	url := c.buildURL(endpoint)
	page := 0

	for url != "" {
		page++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		// Only set params on the first request; nextLink has its own
		if params != nil {
			q := req.URL.Query()
			for k, v := range params {
				q.Set(k, v)
			}
			req.URL.RawQuery = q.Encode()
		}

		c.setHeaders(req)
		body, err := c.doWithRetry(req)
		if err != nil {
			return all, fmt.Errorf("pagination request: %w", err)
		}

		var gr GraphResponse
		if err := json.Unmarshal(body, &gr); err != nil {
			return all, fmt.Errorf("parse graph response: %w", err)
		}

		all = append(all, gr.Value...)

		if label != "" {
			fmt.Fprintf(output.Stderr(), "\r  %s %s",
				output.StyleInfo.Render("[*]"),
				fmt.Sprintf("%s: page %d — %d items fetched...", label, page, len(all)))
		}
		output.Verbose("page %d — %d items so far", page, len(all))
		url = gr.NextLink
		params = nil // nextLink already includes query params
	}

	if label != "" {
		fmt.Fprintf(output.Stderr(), "\r%s\r", strings.Repeat(" ", 80))
	}

	return all, nil
}

// Post sends a POST request with a JSON body.
func (c *Client) Post(ctx context.Context, endpoint string, payload interface{}) (json.RawMessage, error) {
	return c.mutate(ctx, http.MethodPost, endpoint, payload)
}

// Patch sends a PATCH request with a JSON body.
func (c *Client) Patch(ctx context.Context, endpoint string, payload interface{}) (json.RawMessage, error) {
	return c.mutate(ctx, http.MethodPatch, endpoint, payload)
}

// Delete sends a DELETE request.
func (c *Client) Delete(ctx context.Context, endpoint string) error {
	url := c.buildURL(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	_, err = c.doWithRetry(req)
	return err
}

// Download fetches raw bytes (for file downloads).
func (c *Client) Download(ctx context.Context, endpoint string) ([]byte, error) {
	url := c.buildURL(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed (%d): %s", resp.StatusCode, body)
	}

	return io.ReadAll(resp.Body)
}

// SearchQuery performs a POST to /search/query.
func (c *Client) SearchQuery(ctx context.Context, requests interface{}) (json.RawMessage, error) {
	payload := map[string]interface{}{
		"requests": requests,
	}
	return c.Post(ctx, EndpointSearchQuery, payload)
}

// ---- Internal helpers ----

func (c *Client) mutate(ctx context.Context, method, endpoint string, payload interface{}) (json.RawMessage, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.buildURL(endpoint)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	return c.doWithRetry(req)
}

func (c *Client) buildURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http") {
		return endpoint
	}
	return c.baseURL + endpoint
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
}

func (c *Client) doWithRetry(req *http.Request) (json.RawMessage, error) {
	ctx := req.Context()
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Reset body for retry attempts (POST/PATCH bodies are consumed after first read)
		if attempt > 0 && req.GetBody != nil {
			newBody, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("reset request body for retry: %w", err)
			}
			req.Body = newBody
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if err := sleepWithContext(ctx, time.Duration(attempt+1)*time.Second); err != nil {
				return nil, err
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response body: %w", err)
			continue
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if len(body) == 0 {
				return json.RawMessage("{}"), nil
			}
			return body, nil
		case resp.StatusCode == 429:
			// Rate limited — respect Retry-After
			retryAfter := resp.Header.Get("Retry-After")
			wait := parseRetryAfter(retryAfter, attempt)
			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, err
			}
			continue
		case resp.StatusCode == 401:
			return nil, fmt.Errorf("unauthorized (401) — token may be expired or invalid")
		case resp.StatusCode == 403:
			return nil, fmt.Errorf("forbidden (403) — insufficient permissions: %s", truncate(string(body), 200))
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("server error (%d): %s", resp.StatusCode, truncate(string(body), 200))
			if err := sleepWithContext(ctx, time.Duration(attempt+1)*2*time.Second); err != nil {
				return nil, err
			}
			continue
		default:
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
		}
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// sleepWithContext waits for d or returns ctx.Err() if the context is cancelled first.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func parseRetryAfter(header string, attempt int) time.Duration {
	if header != "" {
		if secs, err := strconv.Atoi(header); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	// Exponential backoff fallback
	return time.Duration(attempt+1) * 5 * time.Second
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
