package adapters

import (
	"context"
	"testing"

	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestAdaptersRegistrationAndDryRun(t *testing.T) {
	registry := NewAdapterRegistry()

	mock := NewMemoryMockAdapter("mock_test")
	tc := NewLinuxTCAdapter("eth0")
	nft := NewLinuxNFTablesAdapter("test_table", "test_chain")

	registry.Register(mock)
	registry.Register(tc)
	registry.Register(nft)

	if len(registry.List()) != 3 {
		t.Fatalf("expected 3 registered adapters, got %d", len(registry.List()))
	}

	// Test Linux TC DryRun
	eTC := &models.Enforcement{
		ID:           "enf-tc-1",
		TargetIP:     "192.168.1.155",
		RateDownload: 2000000,
		DryRun:       true,
	}
	if err := tc.ApplyRateLimit(context.Background(), eTC); err != nil {
		t.Fatalf("TC dry-run failed: %v", err)
	}
	if eTC.ActualState != models.StateApplied {
		t.Errorf("expected TC actual state applied, got %s", eTC.ActualState)
	}
}

func TestMemoryMockAdapterStateTransitions(t *testing.T) {
	mock := NewMemoryMockAdapter("mock_state")
	ctx := context.Background()

	e := &models.Enforcement{
		ID:        "enf-1",
		TargetMAC: "11:22:33:44:55:66",
		TargetIP:  "192.168.1.99",
	}

	// Quarantine
	if err := mock.ApplyQuarantine(ctx, e); err != nil {
		t.Fatalf("quarantine error: %v", err)
	}
	if e.ActualState != models.StateApplied {
		t.Errorf("expected applied, got %s", e.ActualState)
	}
	if e.AppliedAt == nil {
		t.Error("expected AppliedAt timestamp to be set")
	}

	// Remove quarantine
	if err := mock.RemoveQuarantine(ctx, e); err != nil {
		t.Fatalf("remove quarantine error: %v", err)
	}
	if e.ActualState != models.StateRolledBack {
		t.Errorf("expected rolled_back, got %s", e.ActualState)
	}

	// Rate Limit
	e.RateDownload = 5000000
	e.RateUpload = 1000000
	if err := mock.ApplyRateLimit(ctx, e); err != nil {
		t.Fatalf("rate limit error: %v", err)
	}
	if e.ActualState != models.StateApplied {
		t.Errorf("expected applied, got %s", e.ActualState)
	}

	// Remove Rate Limit
	if err := mock.RemoveRateLimit(ctx, e); err != nil {
		t.Fatalf("remove rate limit error: %v", err)
	}
	if e.ActualState != models.StateRolledBack {
		t.Errorf("expected rolled_back, got %s", e.ActualState)
	}
}
