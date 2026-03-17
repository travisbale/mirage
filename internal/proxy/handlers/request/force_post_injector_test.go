package request_test

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestForcePostInjector_InjectsParam(t *testing.T) {
	h := &request.ForcePostInjector{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ForcePosts: []aitm.ForcePost{
				{
					Path:   regexp.MustCompile(`^/login$`),
					Params: []aitm.ForcePostParam{{Key: "persist", Value: "true"}},
				},
			},
		},
	}
	body := strings.NewReader("username=victim")
	req := newReq(http.MethodPost, "https://login.example.com/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(modified), "persist=true") {
		t.Errorf("expected injected param, got %q", string(modified))
	}
	if !strings.Contains(string(modified), "username=victim") {
		t.Errorf("expected original param preserved, got %q", string(modified))
	}
}

func TestForcePostInjector_NonPost_Skips(t *testing.T) {
	h := &request.ForcePostInjector{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ForcePosts: []aitm.ForcePost{
				{
					Path:   regexp.MustCompile(`/login`),
					Params: []aitm.ForcePostParam{{Key: "persist", Value: "true"}},
				},
			},
		},
	}
	req := newReq(http.MethodGet, "https://login.example.com/login", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestForcePostInjector_PathMismatch_Skips(t *testing.T) {
	h := &request.ForcePostInjector{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ForcePosts: []aitm.ForcePost{
				{
					Path:   regexp.MustCompile(`^/login$`),
					Params: []aitm.ForcePostParam{{Key: "persist", Value: "true"}},
				},
			},
		},
	}
	body := strings.NewReader("username=victim")
	req := newReq(http.MethodPost, "https://login.example.com/logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	if strings.Contains(string(result), "persist") {
		t.Error("expected no injection when path doesn't match")
	}
}

func TestForcePostInjector_ConditionNotMet_Skips(t *testing.T) {
	h := &request.ForcePostInjector{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ForcePosts: []aitm.ForcePost{
				{
					Path: regexp.MustCompile(`^/login$`),
					Conditions: []aitm.ForcePostCondition{
						{Key: regexp.MustCompile(`^type$`), Search: regexp.MustCompile(`^oauth$`)},
					},
					Params: []aitm.ForcePostParam{{Key: "persist", Value: "true"}},
				},
			},
		},
	}
	body := strings.NewReader("type=saml&username=victim")
	req := newReq(http.MethodPost, "https://login.example.com/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	if strings.Contains(string(result), "persist") {
		t.Error("expected no injection when condition not met")
	}
}

func TestForcePostInjector_NilPhishlet_Skips(t *testing.T) {
	h := &request.ForcePostInjector{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("x=1"))
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
