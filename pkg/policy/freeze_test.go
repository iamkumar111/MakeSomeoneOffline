package policy

import (
	"sync"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// freezeTestTrustMu serializes trust-state writes from the freeze goroutine
// against test reads.
var freezeTestTrustMu sync.Mutex

func setupFreeze(t *testing.T, devs []*models.Device) (*PolicyEngine, *FreezeController, map[string]*models.Device) {
	t.Helper()
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{GatewayIPs: []string{"192.168.1.1"}})
	byID := map[string]*models.Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	fc := NewFreezeController(pe, bus,
		func() []*models.Device {
			out := make([]*models.Device, 0, len(byID))
			for _, d := range byID {
				out = append(out, d)
			}
			return out
		},
		func(id string, state models.TrustState) error {
			freezeTestTrustMu.Lock()
			defer freezeTestTrustMu.Unlock()
			if d, ok := byID[id]; ok {
				d.TrustState = state
			}
			return nil
		},
		pe.IsProtected,
	)
	t.Cleanup(func() {
		fc.Stop()
		pe.Stop()
	})
	return pe, fc, byID
}

func onlineDev(id, mac, ip string) *models.Device {
	return &models.Device{ID: id, PrimaryMAC: mac, PrimaryIP: ip, TrustState: models.TrustStateUnknown, IsOnline: true}
}

func TestFreezeActivateDryRunNeverLatches(t *testing.T) {
	_, fc, _ := setupFreeze(t, []*models.Device{onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50")})
	applied, _, failed := fc.Activate("mock_simulator", time.Minute, "drill", true, SelfExclusion{})
	if fc.IsActive() {
		t.Fatal("dry run must not arm the latch")
	}
	if applied != 1 || len(failed) != 0 {
		t.Fatalf("dry run should cut current devices once: applied=%d failed=%v", applied, failed)
	}
}

func TestFreezeRequiresReason(t *testing.T) {
	_, fc, _ := setupFreeze(t, []*models.Device{onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50")})
	_, _, failed := fc.Activate("mock_simulator", time.Minute, "  ", false, SelfExclusion{})
	if len(failed) == 0 {
		t.Fatal("expected rejection without reason")
	}
	if fc.IsActive() {
		t.Fatal("must not latch without reason")
	}
}

func TestFreezeCutsCurrentAndSkipsProtected(t *testing.T) {
	_, fc, byID := setupFreeze(t, []*models.Device{
		onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50"),
		onlineDev("gw", "00:11:22:33:44:55", "192.168.1.1"), // allowlisted
		{ID: "off", PrimaryMAC: "aa:bb:cc:dd:ee:02", PrimaryIP: "192.168.1.51", TrustState: models.TrustStateUnknown, IsOnline: false},
	})
	applied, skipped, failed := fc.Activate("mock_simulator", time.Minute, "test", false, SelfExclusion{})
	if applied != 1 || skipped != 2 || len(failed) != 0 {
		t.Fatalf("applied=%d skipped=%d failed=%v", applied, skipped, failed)
	}
	if byID["d1"].TrustState != models.TrustStateQuarantined {
		t.Fatal("expected quarantined trust")
	}
	if !fc.IsActive() {
		t.Fatal("expected latch on")
	}
}

func TestFreezeWatcherCutsNewcomers(t *testing.T) {
	pe, fc, byID := setupFreeze(t, []*models.Device{
		onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50"),
	})
	fc.Activate("mock_simulator", time.Minute, "test", false, SelfExclusion{})

	// A device joining later must be cut automatically.
	late := onlineDev("late", "aa:bb:cc:dd:ee:09", "192.168.1.59")
	byID["late"] = late
	pe.eventBus.Publish(events.EventDeviceSeen, "test-site", late)

	deadline := time.Now().Add(3 * time.Second)
	for {
		cut := false
		for _, e := range pe.ListEnforcements() {
			if e.DeviceID == "late" && e.ActualState == models.StateApplied {
				cut = true
			}
		}
		if cut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("newcomer was not auto-cut within 3s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	freezeTestTrustMu.Lock()
	gotTrust := late.TrustState
	freezeTestTrustMu.Unlock()
	if gotTrust != models.TrustStateQuarantined {
		t.Fatal("expected newcomer trust quarantined")
	}
}

func TestFreezeDeactivateLiftsAll(t *testing.T) {
	pe, fc, _ := setupFreeze(t, []*models.Device{
		onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50"),
	})
	fc.Activate("mock_simulator", time.Minute, "test", false, SelfExclusion{})
	if lifted := fc.Deactivate("tester"); lifted != 1 {
		t.Fatalf("expected 1 lifted, got %d", lifted)
	}
	if fc.IsActive() {
		t.Fatal("expected latch off")
	}
	if len(pe.ListEnforcements()) != 0 {
		t.Fatal("expected no remaining enforcements")
	}
}

func TestFreezeSnapshotRestore(t *testing.T) {
	_, fc, _ := setupFreeze(t, []*models.Device{
		onlineDev("d1", "aa:bb:cc:dd:ee:01", "192.168.1.50"),
	})
	fc.Activate("mock_simulator", 5*time.Minute, "night", false, SelfExclusion{})
	snap := fc.Snapshot()
	if !snap.Active || snap.Adapter != "mock_simulator" || snap.TTLSeconds != 300 || snap.Reason != "night" {
		t.Fatalf("bad snapshot: %+v", snap)
	}

	_, fc2, _ := setupFreeze(t, nil)
	fc2.Restore(snap)
	if !fc2.IsActive() {
		t.Fatal("expected restored latch on")
	}
	// Inactive snapshots stay off.
	_, fc3, _ := setupFreeze(t, nil)
	fc3.Restore(FreezeSnapshot{})
	if fc3.IsActive() {
		t.Fatal("empty snapshot must not arm")
	}
}

func TestFreezeSelfExclusion(t *testing.T) {
	_, fc, byID := setupFreeze(t, []*models.Device{
		onlineDev("me", "aa:bb:cc:dd:ee:10", "192.168.1.60"),
		onlineDev("other", "aa:bb:cc:dd:ee:11", "192.168.1.61"),
	})
	// Excluded by IP: admin stays online, other is cut.
	applied, skipped, failed := fc.Activate("mock_simulator", time.Minute, "test", false,
		SelfExclusion{IP: "192.168.1.60", Exclude: true})
	if applied != 1 || skipped != 1 || len(failed) != 0 {
		t.Fatalf("applied=%d skipped=%d failed=%v", applied, skipped, failed)
	}
	if byID["me"].TrustState == models.TrustStateQuarantined {
		t.Fatal("admin must not be cut when excluded")
	}
	if !fc.IsActive() {
		t.Fatal("latch must be on")
	}
	// A newcomer reusing... a different device is still cut.
	byID["late"] = onlineDev("late", "aa:bb:cc:dd:ee:12", "192.168.1.62")
	fc.mu.RLock()
	_, _, _ = fc.adapter, fc.ttl, fc.reason
	fc.mu.RUnlock()
}

func TestFreezeIncludeSelfCutsAdminToo(t *testing.T) {
	_, fc, byID := setupFreeze(t, []*models.Device{
		onlineDev("me", "aa:bb:cc:dd:ee:10", "192.168.1.60"),
	})
	applied, _, _ := fc.Activate("mock_simulator", time.Minute, "test", false,
		SelfExclusion{IP: "192.168.1.60", MAC: "aa-bb-cc-dd-ee-10", Exclude: false})
	if applied != 1 {
		t.Fatalf("expected admin cut when included, applied=%d", applied)
	}
	if byID["me"].TrustState != models.TrustStateQuarantined {
		t.Fatal("expected admin quarantined")
	}
	// MAC matching tolerates separators/case.
	if !isSelfDevice("9.9.9.9", "AA:BB:CC:DD:EE:10", "", "aa-bb-cc-dd-ee-10") {
		t.Fatal("MAC match must ignore separators and case")
	}
	if isSelfDevice("9.9.9.9", "00:11:22:33:44:55", "", "aa-bb-cc-dd-ee-10") {
		t.Fatal("different MAC must not match")
	}
}

func TestFreezeWatcherSkipsExcludedSelf(t *testing.T) {
	pe, fc, byID := setupFreeze(t, []*models.Device{
		onlineDev("other", "aa:bb:cc:dd:ee:11", "192.168.1.61"),
	})
	fc.Activate("mock_simulator", time.Minute, "test", false,
		SelfExclusion{IP: "192.168.1.60", Exclude: true})
	// Admin joins later with the excluded IP: must stay online.
	admin := onlineDev("me", "aa:bb:cc:dd:ee:10", "192.168.1.60")
	byID["me"] = admin
	pe.eventBus.Publish(events.EventDeviceSeen, "test-site", admin)
	// A stranger joining at the same time must be cut.
	stranger := onlineDev("stranger", "aa:bb:cc:dd:ee:13", "192.168.1.63")
	byID["stranger"] = stranger
	pe.eventBus.Publish(events.EventDeviceSeen, "test-site", stranger)

	deadline := time.Now().Add(3 * time.Second)
	for {
		strangerCut := false
		for _, e := range pe.ListEnforcements() {
			if e.DeviceID == "stranger" && e.ActualState == models.StateApplied {
				strangerCut = true
			}
			if e.DeviceID == "me" {
				t.Fatal("excluded admin was cut by watcher")
			}
		}
		if strangerCut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stranger was not auto-cut within 3s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
