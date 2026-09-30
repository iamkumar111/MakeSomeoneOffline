package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

type failingAdapter struct {
	*adapters.MemoryMockAdapter
}

func (f *failingAdapter) Name() string { return "failing" }
func (f *failingAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	return errors.New("stale nft rule survived removal")
}

func timePtr(t time.Time) *time.Time { return &t }

func TestRemoveQuarantineErrorPreservesVisibleFailure(t *testing.T) {
	reg := adapters.NewAdapterRegistry()
	reg.Register(adapters.NewMemoryMockAdapter("test_mock"))
	reg.Register(&failingAdapter{MemoryMockAdapter: adapters.NewMemoryMockAdapter("failing")})
	bus := events.NewEventBus()
	pe := NewPolicyEngine(reg, bus, models.Allowlist{})
	defer pe.Stop()

	dev := &models.Device{ID: "fail-remove", PrimaryIP: "192.168.1.91", PrimaryMAC: "00:11:22:33:44:91", IsOnline: true}
	enf, err := pe.ApplyQuarantine(context.Background(), dev, "failing", time.Minute, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	err = pe.RemoveQuarantine(context.Background(), enf.ID, "test")
	if err == nil {
		t.Fatal("expected remove failure")
	}
	list := pe.ListEnforcements()
	if len(list) != 1 {
		t.Fatalf("stale enforcement should remain visible, got %d", len(list))
	}
	if list[0].ActualState != models.StateApplied || list[0].ErrorMessage == "" {
		t.Fatalf("expected actual_state=applied with error, got %+v", list[0])
	}
}
