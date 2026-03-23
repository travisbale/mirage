package api

import (
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listNotificationChannels(w http.ResponseWriter, req *http.Request) {
	channels, err := r.Notifications.List()
	if err != nil {
		r.writeError(w, http.StatusInternalServerError, "failed to list notification channels", err)
		return
	}

	items := make([]sdk.NotificationChannelResponse, len(channels))
	for i, ch := range channels {
		items[i] = notificationChannelToResponse(ch)
	}
	writeJSON(w, http.StatusOK, sdk.NotificationChannelList{Channels: items})
}

func (r *Router) createNotificationChannel(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.CreateNotificationChannelRequest](w, req)
	if !ok {
		return
	}

	filter := make([]sdk.EventType, len(body.Filter))
	for i, name := range body.Filter {
		filter[i] = sdk.EventType(name)
	}

	channel := &aitm.NotificationChannel{
		Type:       body.Type,
		URL:        body.URL,
		AuthHeader: body.AuthHeader,
		Filter:     filter,
	}

	if err := r.Notifications.Create(channel); err != nil {
		r.writeError(w, http.StatusUnprocessableEntity, err.Error(), err)
		return
	}

	writeJSON(w, http.StatusCreated, notificationChannelToResponse(channel))
}

func (r *Router) deleteNotificationChannel(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.Notifications.Delete(id); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "notification channel not found", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to delete notification channel", err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) testNotificationChannel(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.Notifications.Test(req.Context(), id); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "notification channel not found", err)
		} else {
			r.writeError(w, http.StatusBadGateway, "test delivery failed: "+err.Error(), err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func notificationChannelToResponse(ch *aitm.NotificationChannel) sdk.NotificationChannelResponse {
	filter := make([]string, len(ch.Filter))
	for i, f := range ch.Filter {
		filter[i] = string(f)
	}
	return sdk.NotificationChannelResponse{
		ID:        ch.ID,
		Type:      ch.Type,
		URL:       ch.URL,
		Filter:    filter,
		Enabled:   ch.Enabled,
		CreatedAt: ch.CreatedAt,
	}
}
