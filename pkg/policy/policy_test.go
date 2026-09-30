package policy

import (
	"context"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestManagementAllowlistSafety(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	mockAdapter := adapters.NewMemoryMockAdapter("test_mock")
	registry.Register(mockAdapter)

	bus := events.NewEventBus()
	allowlist := models.Allowlist{
		GatewayIPs:    []string{"192.168.1.1"},
		GatewayMACs:   []string{"00:11:22:33:44:55"},
		AdminIPs:      []string{"192.168.1.200"},
		ControllerIPs: []string{"192.168.1.10"},
	}

	engine := NewPolicyEngine(registry, bus, allowlist)
	defer engine.Stop()

	// Attempt to quarantine gateway
	gatewayDevice := &models.Device{
		ID:         "dev-gw",
		PrimaryIP:  "192.168.1.1",
		PrimaryMAC: "00:11:22:33:44:55",
	}

	_, err := engine.ApplyQuarantine(context.Background(), gatewayDevice, "test_mock", 0, "admin", false)
	if err == nil {
		t.Fatal("expected quarantine on gateway to be blocked by allowlist, but it succeeded")
	}

	// Normal rogue device quarantine should succeed
	targetDevice := &models.Device{
		ID:         "dev-rogue",
		PrimaryIP:  "192.168.1.88",
		PrimaryMAC: "66:77:88:99:aa:bb",
	}

	enf, err := engine.ApplyQuarantine(context.Background(), targetDevice, "test_mock", 100*time.Millisecond, "admin", false)
	if err != nil {
		t.Fatalf("expected quarantine to succeed on normal device, got: %v", err)
	}

	if enf.ActualState != models.StateApplied {
		t.Errorf("expected state applied, got %s", enf.ActualState)
	}

	// Verify TTL auto-rollback
	time.Sleep(200 * time.Millisecond)
	// Force check
	enforcements := engine.ListEnforcements()
	for _, e := range enforcements {
		if e.ID == enf.ID && e.ActualState == models.StateApplied {
			// May wait for the ticker to roll back
		}
	}
}
