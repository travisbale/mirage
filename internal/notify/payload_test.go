package notify

import (
	"net/http"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func TestBuildNotification_Session(t *testing.T) {
	session := &aitm.Session{
		ID:         "sess-1",
		Phishlet:   "microsoft",
		RemoteAddr: "1.2.3.4",
		Username:   "victim@example.com",
		Password:   "hunter2",
		StartedAt:  time.Now(),
	}

	event := aitm.Event{
		Type:       sdk.EventCredsCaptured,
		OccurredAt: time.Now(),
		Payload:    session,
	}

	notification := buildNotification(event)

	if notification.Event != sdk.EventCredsCaptured {
		t.Errorf("Event = %q, want %q", notification.Event, sdk.EventCredsCaptured)
	}
	if notification.Session == nil {
		t.Fatal("Session is nil")
	}
	if notification.Session.Username != "victim@example.com" {
		t.Errorf("Username = %q, want %q", notification.Session.Username, "victim@example.com")
	}
	if notification.Session.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", notification.Session.Password, "hunter2")
	}
}

func TestBuildNotification_BotDetected(t *testing.T) {
	event := aitm.Event{
		Type:       sdk.EventBotDetected,
		OccurredAt: time.Now(),
		Payload: aitm.BotDetectedPayload{
			SessionID:  "sess-1",
			RemoteAddr: "5.6.7.8",
			BotScore:   0.95,
			Verdict:    "spoof",
			Reason:     "JA4 match: zgrab2",
		},
	}

	notification := buildNotification(event)

	if notification.Bot == nil {
		t.Fatal("Bot is nil")
	}
	if notification.Bot.Verdict != "spoof" {
		t.Errorf("Verdict = %q, want %q", notification.Bot.Verdict, "spoof")
	}
}

func TestBuildNotification_DNSSynced(t *testing.T) {
	event := aitm.Event{
		Type:       sdk.EventDNSRecordSynced,
		OccurredAt: time.Now(),
		Payload: aitm.DNSSyncPayload{
			Zone:     "phish.example.com",
			Name:     "login.phish.example.com",
			Type:     "A",
			Action:   "create",
			Provider: "cloudflare",
		},
	}

	notification := buildNotification(event)

	if notification.DNS == nil {
		t.Fatal("DNS is nil")
	}
	if notification.DNS.Action != "create" {
		t.Errorf("Action = %q, want %q", notification.DNS.Action, "create")
	}
}

func TestBuildNotification_Phishlet(t *testing.T) {
	event := aitm.Event{
		Type:       sdk.EventPhishletEnabled,
		OccurredAt: time.Now(),
		Payload:    &aitm.Phishlet{Name: "microsoft"},
	}

	notification := buildNotification(event)

	if notification.Phishlet != "microsoft" {
		t.Errorf("Phishlet = %q, want %q", notification.Phishlet, "microsoft")
	}
}

func TestFlattenCookies(t *testing.T) {
	cookies := map[string]map[string]*http.Cookie{
		".example.com": {
			"session": {Name: "session", Value: "abc123"},
			"csrf":    {Name: "csrf", Value: "xyz"},
		},
	}

	flat := flattenCookies(cookies)

	if flat[".example.com"]["session"] != "abc123" {
		t.Errorf("session cookie = %q, want %q", flat[".example.com"]["session"], "abc123")
	}
	if flat[".example.com"]["csrf"] != "xyz" {
		t.Errorf("csrf cookie = %q, want %q", flat[".example.com"]["csrf"], "xyz")
	}
}
