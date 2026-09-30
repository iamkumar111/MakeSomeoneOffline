package policy

import (
	"context"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestDryRunEnforcementDoesNotSuppressRealFreezeOrEvaluator(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{})
	defer pe.Stop()

	dev := &models.Device{
		ID: "dry-dedupe", PrimaryIP: "192.168.1.88", PrimaryMAC: "00:11:22:33:44:01",
		IsOnline: true,
	}
	if _, err := pe.ApplyQuarantine(context.Background(), dev, "mock_simulator", time.Minute, "test", true); err != nil {
		t.Fatal(err)
	}

	pol := &models.Policy{
		ID: "real-rule", Name: "real cut", Enabled: true, Priority: 1,
		Selector: models.PolicySelector{DeviceID: dev.ID},
		Action:   models.PolicyAction{Type: models.ActionQuarantine},
	}
	pe.RestorePolicies([]*models.Policy{pol})
	ev := NewEvaluator(pe, func() []*models.Device { return []*models.Device{dev} }, time.Hour)
	defer ev.Stop()
	ev.EvaluateOnce()

	fc := NewFreezeController(pe, bus, func() []*models.Device { return []*models.Device{dev} }, func(id string, state models.TrustState) error { return nil }, pe.IsProtected)
	defer fc.Stop()
	applied, skipped, failed := fc.Activate("mock_simulator", time.Minute, "dry dedupe", false, SelfExclusion{})
	// The evaluator already cut this device above, so freeze must skip it as
	// a real active enforcement — not as a stale dry run.
	if failed != nil || applied != 0 || skipped != 1 {
		t.Fatalf("freeze should skip only the real cut, applied=%d skipped=%d failed=%v", applied, skipped, failed)
	}

	var real int
	for _, e := range pe.ListEnforcements() {
		if !e.DryRun && e.ActualState == models.StateApplied {
			real++
		}
	}
	if real != 1 { // evaluator-fired; freeze must not pile up a second
		t.Fatalf("expected exactly 1 real enforcement after evaluator+freeze, got %d", real)
	}
}
