package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// AutoRemediationEngine autonomously isolates threats based on active alerts.
type AutoRemediationEngine struct {
	mu             sync.RWMutex
	enabled        bool
	defaultAdapter string
	defaultTTL     time.Duration
	policyEngine   *PolicyEngine
	eventBus       *events.EventBus
	stopCh         chan struct{}
}

// NewAutoRemediationEngine initializes the autonomous remediation controller.
func NewAutoRemediationEngine(pe *PolicyEngine, bus *events.EventBus, defaultAdapter string, defaultTTL time.Duration) *AutoRemediationEngine {
	// Empty adapter = policy engine safe default (nftables/router/mock, never l2_arp).
	if defaultTTL <= 0 {
		defaultTTL = 10 * time.Minute
	}

	ar := &AutoRemediationEngine{
		enabled:        true,
		defaultAdapter: defaultAdapter,
		defaultTTL:     defaultTTL,
		policyEngine:   pe,
		eventBus:       bus,
		stopCh:         make(chan struct{}),
	}

	if bus != nil {
		ar.startListener()
	}

	return ar
}

// SetEnabled toggles autonomous remediation on or off.
func (ar *AutoRemediationEngine) SetEnabled(enabled bool) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	ar.enabled = enabled
}

// IsEnabled returns whether autonomous remediation is active.
func (ar *AutoRemediationEngine) IsEnabled() bool {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.enabled
}

func (ar *AutoRemediationEngine) startListener() {
	sub := ar.eventBus.Subscribe(50)
	go func() {
		for {
			select {
			case <-ar.stopCh:
				return
			case evt, ok := <-sub:
				if !ok {
					return
				}
				if evt.Type == events.EventAlertCreated {
					if alert, ok := evt.Data.(*models.Alert); ok {
						ar.HandleAlert(context.Background(), alert)
					}
				}
			}
		}
	}()
}

// HandleAlert checks if an alert warrants immediate automatic quarantine.
func (ar *AutoRemediationEngine) HandleAlert(ctx context.Context, alert *models.Alert) bool {
	ar.mu.RLock()
	enabled := ar.enabled
	adapter := ar.defaultAdapter
	ttl := ar.defaultTTL
	ar.mu.RUnlock()

	if !enabled {
		return false
	}

	// Only automatically isolate Critical severity attacks (Gateway Impersonation, Mass ARP Poisoning, Rogue IPv6 RA)
	if alert.Severity != models.SeverityCritical {
		return false
	}

	if alert.TargetMAC == "" && alert.TargetIP == "" {
		return false
	}

	// Verify not on allowlist
	if protected, _ := ar.policyEngine.IsProtected(alert.TargetIP, alert.TargetMAC); protected {
		return false
	}

	targetDev := &models.Device{
		ID:         fmt.Sprintf("threat-%s", alert.ID[:8]),
		PrimaryIP:  alert.TargetIP,
		PrimaryMAC: alert.TargetMAC,
	}

	actor := fmt.Sprintf("auto_defense:%s", alert.Type)
	enf, err := ar.policyEngine.ApplyQuarantine(ctx, targetDev, adapter, ttl, actor, false)
	if err != nil {
		return false
	}

	alert.AutomaticActionTaken = fmt.Sprintf("Autonomous quarantine applied via %s (TTL: %v, Enforcement ID: %s)", adapter, ttl, enf.ID)
	return true
}

// Stop terminates the remediation listener.
func (ar *AutoRemediationEngine) Stop() {
	close(ar.stopCh)
}
