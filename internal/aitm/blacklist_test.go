package aitm_test

import (
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

func TestBlacklistService_BlockThenIsBlocked(t *testing.T) {
	svc := aitm.NewBlacklistService()
	svc.Block("1.2.3.4")

	if !svc.IsBlocked("1.2.3.4") {
		t.Error("expected blocked IP to be reported as blocked")
	}
}

func TestBlacklistService_UnblockedIP(t *testing.T) {
	svc := aitm.NewBlacklistService()

	if svc.IsBlocked("1.2.3.4") {
		t.Error("expected unblocked IP to not be reported as blocked")
	}
}

func TestBlacklistService_BlockThenUnblock(t *testing.T) {
	svc := aitm.NewBlacklistService()
	svc.Block("1.2.3.4")
	svc.Unblock("1.2.3.4")

	if svc.IsBlocked("1.2.3.4") {
		t.Error("expected unblocked IP to not be reported as blocked after Unblock")
	}
}

func TestBlacklistService_WhitelistOverridesBlock(t *testing.T) {
	svc := aitm.NewBlacklistService()
	svc.Block("1.2.3.4")
	svc.WhitelistTemporary("1.2.3.4", time.Hour)

	if svc.IsBlocked("1.2.3.4") {
		t.Error("expected whitelisted IP to not be blocked")
	}
}

func TestBlacklistService_WhitelistExpires(t *testing.T) {
	svc := aitm.NewBlacklistService()
	svc.Block("1.2.3.4")
	svc.WhitelistTemporary("1.2.3.4", time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	if !svc.IsBlocked("1.2.3.4") {
		t.Error("expected whitelist to expire and IP to be blocked again")
	}
}

func TestBlacklistService_ListEmpty(t *testing.T) {
	svc := aitm.NewBlacklistService()
	entries := svc.List()

	if len(entries) != 0 {
		t.Errorf("expected empty list, got %d entries", len(entries))
	}
}

func TestBlacklistService_ListReturnsBlockedIPs(t *testing.T) {
	svc := aitm.NewBlacklistService()
	svc.Block("1.2.3.4")
	svc.Block("5.6.7.8")

	entries := svc.List()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	found := map[string]bool{}
	for _, entry := range entries {
		found[entry] = true
	}
	if !found["1.2.3.4"] || !found["5.6.7.8"] {
		t.Errorf("expected both IPs in list, got %v", entries)
	}
}
