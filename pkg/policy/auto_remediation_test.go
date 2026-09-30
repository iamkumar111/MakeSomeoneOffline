package policy

import (
	"context"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestAutoRemediationEngineWorkflow(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	mock := adapters.NewMemoryMockAdapter("mock_auto")
	registry.Register(mock)

	bus := events.NewEventBus()
	allowlist := models.Allowlist{
		GatewayIPs:  []string{"192.168.1.1"},
		GatewayMACs: []string{"00:11:22:33:44:55"},
	}

	pe := NewPolicyEngine(registry, bus, allowlist)
	ar := NewAutoRemediationEngine(pe, bus, "mock_auto", 5*time.Minute)
	defer ar.Stop()

	// 1. Critical Alert for Rogue Attacker
	criticalAlert := &models.Alert{
		ID:        "alert-crit-1",
		Type:      models.AlertGatewayImpersonation,
		Severity:  models.SeverityCritical,
		TargetIP:  "192.168.1.199",
		TargetMAC: "de:ad:be:ef:13:37",
		FirstSeen: time.Now().UTC(),
	}

	handled := ar.HandleAlert(context.Background(), criticalAlert)
	if !handled {
		t.Fatal("expected critical alert on rogue attacker to trigger auto remediation")
	}

	if criticalAlert.AutomaticActionTaken == "" {
		t.Error("expected AutomaticActionTaken to be populated")
	}

	// Verify enforcement exists in PolicyEngine
	enfs := pe.ListEnforcements()
	if len(enfs) == 0 {
		t.Fatal("expected active enforcement created by auto remediation")
	}
	if enfs[0].TargetMAC != "de:ad:be:ef:13:37" {
		t.Errorf("expected target MAC de:ad:be:ef:13:37, got %s", enfs[0].TargetMAC)
	}

	// 2. Allowlist Protected Target (cannot be auto-quarantined)
	gwAlert := &models.Alert{
		ID:        "alert-gw",
		Type:      models.AlertGatewayImpersonation,
		Severity:  models.SeverityCritical,
		TargetIP:  "192.168.1.1",
		TargetMAC: "00:11:22:33:44:55",
	}

	handledGW := ar.HandleAlert(context.Background(), gwAlert)
	if handledGW {
		t.Fatal("expected auto-remediation to reject quarantining protected gateway")
	}

	// 3. Medium severity alert (should not trigger auto remediation)
	medAlert := &models.Alert{
		ID:        "alert-med",
		Type:      models.AlertPortScanDetected,
		Severity:  models.SeverityMedium,
		TargetIP:  "192.168.1.150",
		TargetMAC: "44:55:66:77:88:99",
	}

	handledMed := ar.HandleAlert(context.Background(), medAlert)
	if handledMed {
		t.Fatal("expected medium alert to not trigger automatic quarantine")
	}
}
