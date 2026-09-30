package policy

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestScheduleWindowEvaluation(t *testing.T) {
	registry := adapters.NewAdapterRegistry()
	mock := adapters.NewMemoryMockAdapter("mock_sched")
	registry.Register(mock)

	bus := events.NewEventBus()
	pe := NewPolicyEngine(registry, bus, models.Allowlist{})
	sm := NewScheduleManager(pe)
	defer sm.Stop()

	// Normal daytime schedule (09:00 - 17:00 on Monday)
	daySched := &PolicySchedule{
		ID:        "sched-work",
		Days:      []time.Weekday{time.Monday},
		StartHour: 9,
		StartMin:  0,
		EndHour:   17,
		EndMin:    0,
		Active:    true,
	}

	// Monday at 12:30 -> Inside
	tMonNoon := time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC) // 2026-10-05 is Monday
	if !sm.IsInsideWindow(daySched, tMonNoon) {
		t.Errorf("expected Monday 12:30 to be inside window")
	}

	// Monday at 18:00 -> Outside
	tMonEve := time.Date(2026, 10, 5, 18, 0, 0, 0, time.UTC)
	if sm.IsInsideWindow(daySched, tMonEve) {
		t.Errorf("expected Monday 18:00 to be outside window")
	}

	// Overnight schedule (22:00 - 06:00, all days)
	nightSched := &PolicySchedule{
		ID:        "sched-bedtime",
		StartHour: 22,
		StartMin:  0,
		EndHour:   6,
		EndMin:    0,
		Active:    true,
	}

	// 23:30 -> Inside
	tNight := time.Date(2026, 10, 5, 23, 30, 0, 0, time.UTC)
	if !sm.IsInsideWindow(nightSched, tNight) {
		t.Errorf("expected 23:30 to be inside overnight window")
	}

	// 03:15 -> Inside
	tEarlyMorn := time.Date(2026, 10, 6, 3, 15, 0, 0, time.UTC)
	if !sm.IsInsideWindow(nightSched, tEarlyMorn) {
		t.Errorf("expected 03:15 to be inside overnight window")
	}

	// 14:00 -> Outside
	tAfternoon := time.Date(2026, 10, 6, 14, 0, 0, 0, time.UTC)
	if sm.IsInsideWindow(nightSched, tAfternoon) {
		t.Errorf("expected 14:00 to be outside overnight window")
	}
}
