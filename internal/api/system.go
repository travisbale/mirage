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

	total, _ := r.sessions.Count(aitm.SessionFilter{})
	active, _ := r.sessions.Count(aitm.SessionFilter{
		IncompleteOnly: true,
		After:          time.Now().Add(-time.Hour),
	})

	writeJSON(w, http.StatusOK, sdk.StatusResponse{
		Version:        r.version,
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
		writeError(w, http.StatusInternalServerError, "process not found", "INTERNAL_ERROR")
		return
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		writeError(w, http.StatusInternalServerError, "signal failed: "+err.Error(), "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "reload signal sent"})
}
