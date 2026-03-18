package request_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

type stubCredentialCapturer struct{}

func (s *stubCredentialCapturer) CaptureCredentials(_ *aitm.Session) error { return nil }

func TestCredentialExtractor_ExtractsUsername(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			Credentials: aitm.CredentialRules{
				Username: aitm.CredentialRule{
					Key:    regexp.MustCompile(`^username$`),
					Search: regexp.MustCompile(`^(.+)$`),
					Type:   "post",
				},
				Password: aitm.CredentialRule{
					Key:    regexp.MustCompile(`^password$`),
					Search: regexp.MustCompile(`^(.+)$`),
					Type:   "post",
				},
			},
		},
	}
	body := strings.NewReader("username=victim%40example.com&password=s3cr3t")
	req := newReq(http.MethodPost, "https://login.example.com/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(ctx.Session.Username, "victim") {
		t.Errorf("expected username to be extracted, got %q", ctx.Session.Username)
	}
}

func TestCredentialExtractor_HostWithPort_StillMatches(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			Login: aitm.LoginSpec{Domain: "login.example.com", Path: "/login"},
			Credentials: aitm.CredentialRules{
				Username: aitm.CredentialRule{
					Key:    regexp.MustCompile(`^username$`),
					Search: regexp.MustCompile(`^(.+)$`),
					Type:   "post",
				},
			},
		},
	}
	body := strings.NewReader("username=victim%40example.com")
	req := newReq(http.MethodPost, "https://login.example.com:8443/login", body)
	req.Host = "login.example.com:8443"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(ctx.Session.Username, "victim") {
		t.Errorf("expected credentials extracted when host includes port, got %q", ctx.Session.Username)
	}
}

func TestCredentialExtractor_NonPost_Skips(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session:  &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{},
	}
	req := newReq(http.MethodGet, "https://login.example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session.Username != "" {
		t.Error("expected no extraction for non-POST request")
	}
}

func TestCredentialExtractor_NoPhishlet_Skips(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "sess-1"}} // no Phishlet
	req := newReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("username=x"))
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCredentialExtractor_NoRuleMatch_NoUpdate(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			Credentials: aitm.CredentialRules{
				Username: aitm.CredentialRule{
					Key:  regexp.MustCompile(`^user$`),
					Type: "post",
				},
			},
		},
	}
	// Body has "login" key, not "user" — no match.
	req := newReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("login=victim"))
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session.Username != "" {
		t.Error("expected no username extracted when key does not match")
	}
}
