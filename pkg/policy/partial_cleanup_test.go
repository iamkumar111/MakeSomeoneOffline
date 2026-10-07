package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

type partialCleanupAdapter struct{ *adapters.MemoryMockAdapter }

func (a partialCleanupAdapter) ApplyQuarantine(_ context.Context, e *models.Enforcement) error {
	e.ActualState = models.StateApplied
	return fmt.Errorf("partial injection; cleanup failed")
}

func TestPartialCleanupRemainsVisibleAndRetryable(t *testing.T) {
	r := adapters.NewAdapterRegistry()
	r.Register(partialCleanupAdapter{adapters.NewMemoryMockAdapter("macos_sidehost")})
	engine := NewPolicyEngine(r, events.NewEventBus(), models.Allowlist{})
	defer engine.Stop()
	e, err := engine.ApplyQuarantine(context.Background(), &models.Device{ID: "target", PrimaryIP: "192.168.1.24", PrimaryMAC: "02:00:00:00:00:24"}, "macos_sidehost", time.Minute, "test", false)
	if err == nil || e == nil || e.ActualState != models.StateApplied || len(engine.ListEnforcements()) != 1 || e.ErrorMessage == "" {
		t.Fatal("cleanup owner lost")
	}
	if err := engine.RemoveQuarantine(context.Background(), e.ID, "test"); err != nil {
		t.Fatal(err)
	}
}
