package policy

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestScheduleFiresAndLifts(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{})
	defer pe.Stop()

	devQ := &models.Device{ID: "dev-q", PrimaryMAC: "aa:bb:cc:dd:ee:01", PrimaryIP: "192.168.1.60", TrustState: models.TrustStateUnknown, IsOnline: true}
	devR := &models.Device{ID: "dev-r", PrimaryMAC: "aa:bb:cc:dd:ee:02", PrimaryIP: "192.168.1.61", TrustState: models.TrustStateUnknown, IsOnline: true}
	byID := map[string]*models.Device{"dev-q": devQ, "dev-r": devR}

	sm := NewScheduleManager(pe)
	defer sm.Stop()
	sm.SetResolver(func(id string) *models.Device { return byID[id] })

	sm.AddSchedule(&PolicySchedule{
		ID: "sched-q", DeviceID: "dev-q", StartHour: 0, StartMin: 0,
		EndHour: 23, EndMin: 59, Action: models.ActionQuarantine, Active: true,
	})
	sm.AddSchedule(&PolicySchedule{
		ID: "sched-r", DeviceID: "dev-r", StartHour: 0, StartMin: 0,
		EndHour: 23, EndMin: 59, Action: models.ActionRateLimit,
		DownloadBps: 1000000, UploadBps: 500000, Active: true,
	})

	inside := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	sm.evaluateSchedules(inside)

	enfs := pe.ListEnforcements()
	if len(enfs) != 2 {
		t.Fatalf("expected 2 enforcements, got %d", len(enfs))
	}
	byDev := map[string]*models.Enforcement{}
	for _, e := range enfs {
		byDev[e.DeviceID] = e
	}
	if q, ok := byDev["dev-q"]; !ok || q.Action != models.ActionQuarantine || q.ActualState != models.StateApplied {
		t.Fatalf("bad quarantine enforcement: %+v", byDev["dev-q"])
	}
	if r, ok := byDev["dev-r"]; !ok || r.Action != models.ActionRateLimit || r.RateDownload != 1000000 {
		t.Fatalf("bad rate-limit enforcement: %+v", byDev["dev-r"])
	}

	// Outside every window both must lift (window 09:00-09:01, now noon).
	for _, s := range sm.ListSchedules() {
		s.StartHour, s.StartMin, s.EndHour, s.EndMin = 9, 0, 9, 1
		sm.AddSchedule(s)
	}
	outside := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	sm.evaluateSchedules(outside)
	if len(pe.ListEnforcements()) != 0 {
		t.Fatalf("expected all lifted, got %d left", len(pe.ListEnforcements()))
	}
}

func TestScheduleSkipsUnknownDevice(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	registry.Register(adapters.NewMemoryMockAdapter("mock_simulator"))
	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{})
	defer pe.Stop()

	sm := NewScheduleManager(pe)
	defer sm.Stop()
	sm.SetResolver(func(id string) *models.Device { return nil }) // nothing known

	sm.AddSchedule(&PolicySchedule{
		ID: "sched-ghost", DeviceID: "nope", StartHour: 0, StartMin: 0,
		EndHour: 23, EndMin: 59, Action: models.ActionQuarantine, Active: true,
	})
	sm.evaluateSchedules(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	if len(pe.ListEnforcements()) != 0 {
		t.Fatal("must not enforce against unresolvable devices")
	}
}
