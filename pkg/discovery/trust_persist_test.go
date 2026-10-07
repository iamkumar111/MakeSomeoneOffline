package discovery

import (
	"testing"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// Quarantine labels are enforcement-derived and must not survive a restart:
// live enforcements die with the process, so a restored label could never
// match a real cut.
func TestQuarantineTrustNeverPersistsOrRestores(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewIdentityFusionEngine("test-site", bus)
	defer engine.Stop()

	dev := engine.IngestObservation(models.Observation{
		Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.50",
	})
	if err := engine.SetTrustState(dev.ID, models.TrustStateQuarantined); err != nil {
		t.Fatal(err)
	}

	snap := engine.SnapshotDevices()
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshotted device, got %d", len(snap))
	}
	if snap[0].TrustState == models.TrustStateQuarantined {
		t.Fatal("snapshot must not persist quarantined trust")
	}

	bus2 := events.NewEventBus()
	engine2 := NewIdentityFusionEngine("test-site", bus2)
	defer engine2.Stop()
	// Simulate an old snapshot that still carries the label.
	stale := *snap[0]
	stale.TrustState = models.TrustStateQuarantined
	engine2.RestoreDevices([]*models.Device{&stale})
	got, ok := engine2.GetDevice(dev.ID)
	if !ok {
		t.Fatal("expected restored device")
	}
	if got.TrustState == models.TrustStateQuarantined {
		t.Fatal("restore must downgrade quarantined to unknown")
	}

	// Manual decisions still survive the round-trip.
	if err := engine.SetTrustState(dev.ID, models.TrustStateTrusted); err != nil {
		t.Fatal(err)
	}
	snap = engine.SnapshotDevices()
	engine2.RestoreDevices(snap)
	got, _ = engine2.GetDevice(dev.ID)
	if got.TrustState != models.TrustStateTrusted {
		t.Fatalf("trusted must persist, got %s", got.TrustState)
	}
}
