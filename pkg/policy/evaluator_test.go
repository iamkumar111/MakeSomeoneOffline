package policy

import (
	"context"
	"testing"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func setupEvaluator(t *testing.T) (*PolicyEngine, *Evaluator, func()) {
	t.Helper()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{})
	devs := map[string]*models.Device{
		"dev-bad": {ID: "dev-bad", PrimaryMAC: "aa:bb:cc:dd:ee:ff", PrimaryIP: "192.168.1.50", TrustState: models.TrustStateUnknown, RiskScore: 80, IsOnline: true},
		"dev-ok":  {ID: "dev-ok", PrimaryMAC: "11:22:33:44:55:66", PrimaryIP: "192.168.1.51", TrustState: models.TrustStateTrusted, RiskScore: 5, IsOnline: true},
		"dev-off": {ID: "dev-off", PrimaryMAC: "77:88:99:aa:bb:cc", PrimaryIP: "192.168.1.52", TrustState: models.TrustStateUnknown, RiskScore: 90, IsOnline: false},
	}
	ev := NewEvaluator(pe, func() []*models.Device {
		return []*models.Device{devs["dev-bad"], devs["dev-ok"], devs["dev-off"]}
	}, 0)
	t.Cleanup(ev.Stop)
	return pe, ev, func() {}
}

func TestEvaluatorFiresAndDedupes(t *testing.T) {
	pe, ev, _ := setupEvaluator(t)
	pe.SavePolicy(&models.Policy{
		ID: "pol-1", Name: "quarantine unknowns", Enabled: true, Priority: 100,
		Selector: models.PolicySelector{TrustState: models.TrustStateUnknown},
		Action:   models.PolicyAction{Type: models.ActionQuarantine},
	})
	if n := ev.EvaluateOnce(); n != 1 {
		t.Fatalf("expected 1 action (offline skipped, trusted skipped), got %d", n)
	}
	enfs := pe.ListEnforcements()
	if len(enfs) != 1 || enfs[0].PolicyID != "pol-1" || enfs[0].DeviceID != "dev-bad" {
		t.Fatalf("unexpected enforcements: %+v", enfs)
	}
	// Second pass: existing enforcement suppresses re-fire.
	if n := ev.EvaluateOnce(); n != 0 {
		t.Fatalf("expected 0 (dedupe), got %d", n)
	}
}

func TestEvaluatorEmptySelectorMatchesNothing(t *testing.T) {
	pe, ev, _ := setupEvaluator(t)
	pe.SavePolicy(&models.Policy{
		ID: "pol-blank", Name: "blank", Enabled: true, Priority: 1,
		Action: models.PolicyAction{Type: models.ActionQuarantine},
	})
	if n := ev.EvaluateOnce(); n != 0 {
		t.Fatalf("blank selector must never fire, got %d", n)
	}
	if len(pe.ListEnforcements()) != 0 {
		t.Fatal("no enforcements expected")
	}
}

func TestEvaluatorAllowOverrides(t *testing.T) {
	pe, ev, _ := setupEvaluator(t)
	pe.SavePolicy(&models.Policy{
		ID: "pol-allow", Name: "allow it", Enabled: true, Priority: 10,
		Selector: models.PolicySelector{MAC: "AA-BB-CC-DD-EE-FF"},
		Action:   models.PolicyAction{Type: models.ActionAllow},
	})
	pe.SavePolicy(&models.Policy{
		ID: "pol-q", Name: "quarantine unknowns", Enabled: true, Priority: 100,
		Selector: models.PolicySelector{TrustState: models.TrustStateUnknown},
		Action:   models.PolicyAction{Type: models.ActionQuarantine},
	})
	if n := ev.EvaluateOnce(); n != 0 {
		t.Fatalf("allow rule should suppress, got %d", n)
	}
}

func TestMatchesPolicyFields(t *testing.T) {
	dev := &models.Device{ID: "d", PrimaryMAC: "aa:bb:cc:dd:ee:ff", PrimaryIP: "192.168.1.5",
		TrustState: models.TrustStateRestricted, RiskScore: 40, Labels: map[string]string{"segment": "iot"}}
	cases := []struct {
		sel  models.PolicySelector
		want bool
	}{
		{models.PolicySelector{DeviceID: "d"}, true},
		{models.PolicySelector{DeviceID: "x"}, false},
		{models.PolicySelector{MAC: "AA:BB:CC:DD:EE:FF"}, true},
		{models.PolicySelector{IP: "192.168.1.5"}, true},
		{models.PolicySelector{TrustState: models.TrustStateRestricted}, true},
		{models.PolicySelector{TrustState: models.TrustStateTrusted}, false},
		{models.PolicySelector{MinRiskScore: 40}, true},
		{models.PolicySelector{MinRiskScore: 41}, false},
		{models.PolicySelector{Segment: "iot"}, true},
		{models.PolicySelector{Segment: "corp"}, false},
	}
	for i, c := range cases {
		if got := matchesPolicy(dev, &c.sel); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestBreakGlassNeedsReasonAndBypassesAllowlist(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{GatewayIPs: []string{"192.168.1.1"}})
	defer pe.Stop()
	gw := &models.Device{ID: "gw", PrimaryIP: "192.168.1.1", PrimaryMAC: "00:11:22:33:44:55"}

	// Normal path stays blocked.
	if _, err := pe.ApplyQuarantine(context.Background(), gw, "mock_simulator", 0, "admin", false); err == nil {
		t.Fatal("expected allowlist rejection")
	}
	// Break-glass without reason stays blocked.
	if _, err := pe.ApplyQuarantineBreakGlass(context.Background(), gw, "mock_simulator", 0, "admin", false, "  "); err == nil {
		t.Fatal("expected reason requirement")
	}
	// With reason it applies and audits the override.
	enf, err := pe.ApplyQuarantineBreakGlass(context.Background(), gw, "mock_simulator", 0, "admin", false, "whole-LAN maintenance")
	if err != nil || enf == nil {
		t.Fatalf("break-glass failed: %v", err)
	}
	found := false
	for _, l := range pe.ListAuditLogs() {
		if l.Action == "break_glass" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected break_glass audit entry")
	}
}
