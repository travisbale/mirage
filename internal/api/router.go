package api

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// Router is the HTTP handler for the management API.
type Router struct {
	Sessions      *aitm.SessionService
	Lures         *aitm.LureService
	Phishlets     *aitm.PhishletService
	Blacklist     *aitm.BlacklistService
	Botguard      *aitm.BotGuardService
	Notifications *aitm.NotificationService
	Operators     *aitm.OperatorService
	DNS           *aitm.DNSService
	HTTPSPort     int // Included in lure URLs when non-standard (not 443)
	Version       string
	Logger        *slog.Logger

	once      sync.Once
	mux       *http.ServeMux
	startedAt time.Time
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.once.Do(func() {
		r.mux = http.NewServeMux()
		r.startedAt = time.Now()
		r.registerRoutes()
	})

	r.mux.ServeHTTP(w, req)
}

func (r *Router) registerRoutes() {
	h := func(method, route string, handler http.HandlerFunc) {
		r.mux.HandleFunc(method+" "+route, r.authMiddleware(r.auditMiddleware(handler)))
	}

	// Sessions
	h("GET", sdk.RouteSessionsStream, r.streamSessions)
	h("GET", sdk.RouteSessionExport, r.exportSessionCookies)
	h("GET", sdk.RouteSession, r.getSession)
	h("DELETE", sdk.RouteSession, r.deleteSession)
	h("GET", sdk.RouteSessions, r.listSessions)

	// Lures
	h("GET", sdk.RouteLures, r.listLures)
	h("POST", sdk.RouteLures, r.createLure)
	h("PATCH", sdk.RouteLure, r.updateLure)
	h("DELETE", sdk.RouteLure, r.deleteLure)
	h("POST", sdk.RouteLureURL, r.generateLureURL)
	h("POST", sdk.RouteLurePause, r.pauseLure)
	h("DELETE", sdk.RouteLurePause, r.unpauseLure)

	// Phishlets
	h("GET", sdk.RoutePhishletHosts, r.getPhishletHosts)
	h("POST", sdk.RoutePhishletEnable, r.enablePhishlet)
	h("POST", sdk.RoutePhishletDisable, r.disablePhishlet)
	h("POST", sdk.RoutePhishlets, r.pushPhishlet)
	h("GET", sdk.RoutePhishlet, r.getPhishlet)
	h("GET", sdk.RoutePhishlets, r.listPhishlets)

	// Blacklist
	h("GET", sdk.RouteBlacklist, r.listBlacklist)
	h("POST", sdk.RouteBlacklist, r.addBlacklistEntry)
	h("DELETE", sdk.RouteBlacklistEntry, r.removeBlacklistEntry)

	// DNS
	h("GET", sdk.RouteDNSProviders, r.listDNSProviders)
	h("GET", sdk.RouteDNSZones, r.listDNSZones)
	h("POST", sdk.RouteDNSSync, r.syncDNS)

	// BotGuard
	h("GET", sdk.RouteBotSignatures, r.listBotSignatures)
	h("POST", sdk.RouteBotSignatures, r.addBotSignature)
	h("DELETE", sdk.RouteBotSignature, r.removeBotSignature)
	h("PATCH", sdk.RouteBotThreshold, r.updateBotThreshold)

	// Notifications
	h("GET", sdk.RouteNotificationChannels, r.listNotificationChannels)
	h("POST", sdk.RouteNotificationChannels, r.createNotificationChannel)
	h("DELETE", sdk.RouteNotificationChannel, r.deleteNotificationChannel)
	h("POST", sdk.RouteNotificationTest, r.testNotificationChannel)

	// Operators (authenticated)
	h("POST", sdk.RouteOperatorInvite, r.inviteOperator)
	h("GET", sdk.RouteOperators, r.listOperators)
	h("DELETE", sdk.RouteOperator, r.deleteOperator)

	// Enrollment (unauthenticated — token-based auth)
	r.mux.HandleFunc("POST "+sdk.RouteEnroll, r.enrollOperator)

	// System
	h("GET", sdk.RouteStatus, r.getStatus)
	h("POST", sdk.RouteReload, r.reload)
}
