package sdk

import "strings"

// API route paths. The server registers these with a method prefix
// (e.g. "GET " + RouteSessions). The client resolves {param} placeholders
// using Resolve before making requests.
const (
	// Sessions
	RouteSessionsStream = "/api/sessions/stream"
	RouteSessionExport  = "/api/sessions/{id}/export"
	RouteSession        = "/api/sessions/{id}"
	RouteSessions       = "/api/sessions"

	// Lures
	RouteLureURL   = "/api/lures/{id}/url"
	RouteLurePause = "/api/lures/{id}/pause"
	RouteLure      = "/api/lures/{id}"
	RouteLures     = "/api/lures"

	// Phishlets
	RoutePhishletHosts   = "/api/phishlets/{name}/hosts"
	RoutePhishletEnable  = "/api/phishlets/{name}/enable"
	RoutePhishletDisable = "/api/phishlets/{name}/disable"
	RoutePhishletHide    = "/api/phishlets/{name}/hide"
	RoutePhishletUnhide  = "/api/phishlets/{name}/unhide"
	RoutePhishlet        = "/api/phishlets/{name}"
	RoutePhishlets       = "/api/phishlets"

	// Blacklist
	RouteBlacklistEntry = "/api/blacklist/{entry}"
	RouteBlacklist      = "/api/blacklist"

	// DNS
	RouteDNSZones = "/api/dns/zones"
	RouteDNSSync  = "/api/dns/sync"

	// BotGuard
	RouteBotSignature  = "/api/botguard/signatures/{hash}"
	RouteBotSignatures = "/api/botguard/signatures"
	RouteBotThreshold  = "/api/botguard/threshold"

	// Notifications
	RouteNotificationTest     = "/api/notifications/channels/{id}/test"
	RouteNotificationChannel  = "/api/notifications/channels/{id}"
	RouteNotificationChannels = "/api/notifications/channels"

	// Operators
	RouteOperatorInvite = "/api/operators/invite"
	RouteOperator       = "/api/operators/{name}"
	RouteOperators      = "/api/operators"
	RouteEnroll         = "/api/enroll"

	// System
	RouteStatus = "/api/status"
	RouteReload = "/api/reload"

	// Campaigns
	RouteCampaignSync = "/api/campaigns/sync"
	RouteCampaigns    = "/api/campaigns"
)

// ResolveRoute replaces {param} placeholders in a route pattern with concrete values.
// Parameters are passed as alternating name/value pairs:
//
//	ResolveRoute(RouteSession, "id", "abc123")  →  "/api/sessions/abc123"
func ResolveRoute(route string, pairs ...string) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		route = strings.Replace(route, "{"+pairs[i]+"}", pairs[i+1], 1)
	}

	return route
}
