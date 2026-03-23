package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookChannel delivers notifications as raw JSON POST requests.
type WebhookChannel struct {
	url        string
	authHeader string
	client     *http.Client
}

// NewWebhookChannel creates a webhook channel that POSTs raw JSON to url.
// If authHeader is non-empty, it is sent as the Authorization header.
func NewWebhookChannel(url, authHeader string) *WebhookChannel {
	return &WebhookChannel{
		url:        url,
		authHeader: authHeader,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookChannel) Name() string { return "webhook" }

func (w *WebhookChannel) Send(ctx context.Context, notification Notification) error {
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("marshaling notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mirage-notify/1.0")
	if w.authHeader != "" {
		req.Header.Set("Authorization", w.authHeader)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return &httpError{StatusCode: resp.StatusCode}
	}
	return nil
}
