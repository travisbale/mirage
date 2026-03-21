package api

import (
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) getStatus(w http.ResponseWriter, req *http.Request) {
	uptime := time.Since(r.startedAt)

	total, err := r.Sessions.Count(aitm.SessionFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get session count")
		return
	}
	active, err := r.Sessions.Count(aitm.SessionFilter{
		IncompleteOnly: true,
		After:          time.Now().Add(-time.Hour),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get active session count")
		return
	}

	writeJSON(w, http.StatusOK, sdk.StatusResponse{
		Version:        r.Version,
		Uptime:         uptime.Round(time.Second).String(),
		UptimeSeconds:  uptime.Seconds(),
		GoRoutines:     runtime.NumGoroutine(),
		TotalSessions:  total,
		ActiveSessions: active,
		StartedAt:      r.startedAt,
	})
}

func (r *Router) reload(w http.ResponseWriter, req *http.Request) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "process not found")
		return
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send reload signal")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "reload signal sent"})
}
