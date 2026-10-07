package policy

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// PolicyEngine orchestrates policies, enforcements, safety allowlists, and TTL rollbacks.
type PolicyEngine struct {
	mu           sync.RWMutex
	allowlist    models.Allowlist
	adapters     *adapters.AdapterRegistry
	eventBus     *events.EventBus
	policies     map[string]*models.Policy
	enforcements map[string]*models.Enforcement // keyed by enforcement ID
	auditLogs    []models.AuditLog
	stopCh       chan struct{}
}

// NewPolicyEngine creates a PolicyEngine with default allowlist protections.
func NewPolicyEngine(registry *adapters.AdapterRegistry, eventBus *events.EventBus, allowlist models.Allowlist) *PolicyEngine {
	pe := &PolicyEngine{
		allowlist:    allowlist,
		adapters:     registry,
		eventBus:     eventBus,
		policies:     make(map[string]*models.Policy),
		enforcements: make(map[string]*models.Enforcement),
		auditLogs:    make([]models.AuditLog, 0),
		stopCh:       make(chan struct{}),
	}

	go pe.ttlWorker()
	return pe
}

// Stop cleanly terminates background workers.
func (pe *PolicyEngine) Stop() {
	close(pe.stopCh)
}

// IsProtected checks whether a given IP or MAC is on the management allowlist.
func (pe *PolicyEngine) IsProtected(ip, mac string) (bool, string) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	cleanMAC := strings.ToLower(strings.TrimSpace(mac))
	cleanIP := strings.TrimSpace(ip)

	for _, gIP := range pe.allowlist.GatewayIPs {
		if gIP != "" && gIP == cleanIP {
			return true, "Default Gateway IP is protected"
		}
	}
	for _, gMAC := range pe.allowlist.GatewayMACs {
		if gMAC != "" && strings.ToLower(gMAC) == cleanMAC {
			return true, "Default Gateway MAC is protected"
		}
	}
	for _, aIP := range pe.allowlist.AdminIPs {
		if aIP != "" && aIP == cleanIP {
			return true, "Administrator Management IP is protected"
		}
	}
	for _, cIP := range pe.allowlist.ControllerIPs {
		if cIP != "" && cIP == cleanIP {
			return true, "Controller Host IP is protected"
		}
	}
	for _, dIP := range pe.allowlist.DNSIPs {
		if dIP != "" && dIP == cleanIP {
			return true, "Core DNS/DHCP server is protected"
		}
	}

	return false, ""
}

// UpdateAllowlist allows updating protected infrastructure IPs/MACs.
func (pe *PolicyEngine) UpdateAllowlist(al models.Allowlist) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.allowlist = al
}

// GetAllowlist returns the current allowlist.
func (pe *PolicyEngine) GetAllowlist() models.Allowlist {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.allowlist
}

// ListAdapters exposes registered enforcement adapters (for /integrations API).
func (pe *PolicyEngine) ListAdapters() []adapters.NetworkAdapter {
	if pe.adapters == nil {
		return nil
	}
	return pe.adapters.List()
}

// GetAdapter returns a single adapter by name.
func (pe *PolicyEngine) GetAdapter(name string) (adapters.NetworkAdapter, error) {
	return pe.adapters.Get(name)
}

// RankedAdapters returns adapters sorted + recommended for an action
// ("quarantine" or "rate_limit"). Powers the modal dropdown guidance.
func (pe *PolicyEngine) RankedAdapters(ctx context.Context, action string) []adapters.RankedAdapter {
	if pe.adapters == nil {
		return nil
	}
	return adapters.MarkRecommended(pe.adapters.Ranked(ctx, action))
}

// BestAdapter returns the recommended adapter name for an action, or "" if none usable.
func (pe *PolicyEngine) BestAdapter(ctx context.Context, action string) string {
	for _, r := range pe.RankedAdapters(ctx, action) {
		if r.Recommended && r.Available && r.SupportsAction {
			return r.Info.Name
		}
	}
	return ""
}

// ApplyQuarantine enforces a quarantine action on a device with safety checks.
func (pe *PolicyEngine) ApplyQuarantine(ctx context.Context, device *models.Device, adapterName string, ttl time.Duration, actor string, dryRun bool) (*models.Enforcement, error) {
	return pe.applyQuarantineInner(ctx, device, adapterName, ttl, actor, dryRun, "")
}

// ApplyQuarantineBreakGlass cuts a protected (allowlisted) device — typically
// the gateway itself. Explicit-only: callers must pass a human reason, which
// is audit-logged. Automated paths (scheduler, evaluator, auto-remediation)
// must NEVER call this; they use ApplyQuarantine and stay blocked.
func (pe *PolicyEngine) ApplyQuarantineBreakGlass(ctx context.Context, device *models.Device, adapterName string, ttl time.Duration, actor string, dryRun bool, reason string) (*models.Enforcement, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("break-glass requires a non-empty reason")
	}
	return pe.applyQuarantineInner(ctx, device, adapterName, ttl, actor, dryRun, strings.TrimSpace(reason))
}

func (pe *PolicyEngine) applyQuarantineInner(ctx context.Context, device *models.Device, adapterName string, ttl time.Duration, actor string, dryRun bool, breakGlassReason string) (*models.Enforcement, error) {
	if runtime.GOOS == "darwin" && !dryRun {
		return nil, fmt.Errorf("macOS live quarantine is not available; enable Dry Run or use a Linux enforcement host")
	}
	if protected, why := pe.IsProtected(device.PrimaryIP, device.PrimaryMAC); protected && breakGlassReason == "" {
		pe.recordAudit(actor, "quarantine_rejected", "device", device.ID, fmt.Sprintf("Rejected: %s", why), "failed")
		return nil, fmt.Errorf("safety violation: cannot quarantine protected device: %s", why)
	}

	var adapter adapters.NetworkAdapter
	var err error
	if adapterName != "" {
		adapter, err = pe.adapters.Get(adapterName)
	}
	if adapter == nil || err != nil {
		all := pe.adapters.List()
		if len(all) == 0 {
			return nil, fmt.Errorf("no enforcement adapters available")
		}
		// Prefer infrastructure-native enforcement (nftables shaping),
		// then mock simulator. l2_arp (ARP spoofing) is last resort and
		// only when explicitly requested — never the silent default.
		// Order: linux_nftables > linux_tc > mock > l2_arp
		priority := []string{"linux_nftables", "linux_tc", "mock_simulator", "mock_adapter"}
		byName := make(map[string]adapters.NetworkAdapter, len(all))
		for _, a := range all {
			byName[a.Name()] = a
		}
		for _, want := range priority {
			if a, ok := byName[want]; ok {
				adapter = a
				break
			}
		}
		if adapter == nil {
			// Fall back to any non-l2_arp adapter before l2_arp.
			for _, a := range all {
				if a.Name() != "l2_arp" {
					adapter = a
					break
				}
			}
		}
		if adapter == nil {
			adapter = all[0]
		}
	}

	enf := &models.Enforcement{
		ID:           uuid.New().String(),
		DeviceID:     device.ID,
		TargetIP:     device.PrimaryIP,
		TargetMAC:    device.PrimaryMAC,
		Adapter:      adapter.Name(),
		Action:       models.ActionQuarantine,
		DesiredState: models.StateApplied,
		ActualState:  models.StatePending,
		DryRun:       dryRun,
	}

	if ttl > 0 {
		exp := time.Now().UTC().Add(ttl)
		enf.ExpiresAt = &exp
	}

	pe.eventBus.Publish(events.EventEnforcementRequested, device.SiteID, enf)

	// Execute through adapter
	if err := adapter.ApplyQuarantine(ctx, enf); err != nil {
		enf.ActualState = models.StateFailed
		enf.ErrorMessage = err.Error()
		pe.recordAudit(actor, "quarantine", "device", device.ID, fmt.Sprintf("Failed: %v", err), "failed")
		pe.eventBus.Publish(events.EventEnforcementFailed, device.SiteID, enf)
		return enf, fmt.Errorf("adapter failed to apply quarantine: %w", err)
	}

	pe.mu.Lock()
	pe.enforcements[enf.ID] = enf
	pe.mu.Unlock()

	pe.recordAudit(actor, "quarantine", "device", device.ID, fmt.Sprintf("Quarantine applied via %s (TTL: %v)", adapter.Name(), ttl), "success")
	if breakGlassReason != "" {
		pe.recordAudit(actor, "break_glass", "device", device.ID, fmt.Sprintf("Allowlist overridden: %s", breakGlassReason), "success")
	}
	pe.eventBus.Publish(events.EventEnforcementApplied, device.SiteID, enf)
	return enf, nil
}

// RemoveQuarantine rolls back quarantine for a device.
func (pe *PolicyEngine) RemoveQuarantine(ctx context.Context, enforcementID, actor string) error {
	pe.mu.Lock()
	enf, ok := pe.enforcements[enforcementID]
	pe.mu.Unlock()

	if !ok {
		return fmt.Errorf("enforcement %q not found", enforcementID)
	}

	adapter, err := pe.adapters.Get(enf.Adapter)
	if err != nil {
		return fmt.Errorf("adapter %q not found: %w", enf.Adapter, err)
	}

	work := *enf
	work.DesiredState = models.StateRolledBack
	if err := adapter.RemoveQuarantine(ctx, &work); err != nil {
		// Preserve the live block: ActualState comes from the adapter. Keep the
		// enforcement visible so TTL retries can fire and the UI can show the
		// intervention needed instead of silently pretending it worked.
		enf.DesiredState = work.DesiredState
		enf.ActualState = models.StateApplied
		enf.ErrorMessage = err.Error()
		pe.mu.Lock()
		pe.enforcements[enf.ID] = enf
		pe.mu.Unlock()
		pe.recordAudit(actor, "remove_quarantine", "device", enf.DeviceID, fmt.Sprintf("Failed: %v", err), "failed")
		pe.eventBus.Publish(events.EventEnforcementFailed, "", enf)
		return err
	}

	enf.DesiredState = work.DesiredState
	enf.ActualState = models.StateRolledBack
	enf.ErrorMessage = ""
	if work.AppliedAt != nil {
		enf.AppliedAt = work.AppliedAt
	}
	pe.mu.Lock()
	delete(pe.enforcements, enforcementID)
	pe.mu.Unlock()

	pe.recordAudit(actor, "remove_quarantine", "device", enf.DeviceID, "Quarantine lifted", "success")
	pe.eventBus.Publish(events.EventEnforcementRemoved, "", enf)
	return nil
}

// ApplyRateLimit restricts download/upload bandwidth for a target device.
func (pe *PolicyEngine) ApplyRateLimit(ctx context.Context, device *models.Device, adapterName string, dlBps, ulBps uint64, ttl time.Duration, actor string, dryRun bool) (*models.Enforcement, error) {
	if runtime.GOOS == "darwin" && !dryRun {
		return nil, fmt.Errorf("macOS live rate limiting is not available; enable Dry Run or use a Linux enforcement host")
	}
	if protected, reason := pe.IsProtected(device.PrimaryIP, device.PrimaryMAC); protected {
		return nil, fmt.Errorf("safety violation: cannot rate-limit protected infrastructure: %s", reason)
	}

	var adapter adapters.NetworkAdapter
	var err error
	if adapterName != "" {
		adapter, err = pe.adapters.Get(adapterName)
	}
	if adapter == nil || err != nil {
		all := pe.adapters.List()
		if len(all) == 0 {
			return nil, fmt.Errorf("no enforcement adapters available")
		}
		for _, a := range all {
			if a.Name() != "mock_simulator" && a.Name() != "mock_adapter" {
				adapter = a
				break
			}
		}
		if adapter == nil {
			adapter = all[0]
		}
	}

	enf := &models.Enforcement{
		ID:           uuid.New().String(),
		DeviceID:     device.ID,
		TargetIP:     device.PrimaryIP,
		TargetMAC:    device.PrimaryMAC,
		Adapter:      adapter.Name(),
		Action:       models.ActionRateLimit,
		RateDownload: dlBps,
		RateUpload:   ulBps,
		DesiredState: models.StateApplied,
		ActualState:  models.StatePending,
		DryRun:       dryRun,
	}

	if ttl > 0 {
		exp := time.Now().UTC().Add(ttl)
		enf.ExpiresAt = &exp
	}

	if err := adapter.ApplyRateLimit(ctx, enf); err != nil {
		enf.ActualState = models.StateFailed
		enf.ErrorMessage = err.Error()
		pe.recordAudit(actor, "rate_limit", "device", device.ID, fmt.Sprintf("Failed: %v", err), "failed")
		return enf, fmt.Errorf("adapter failed to apply rate limit: %w", err)
	}

	pe.mu.Lock()
	pe.enforcements[enf.ID] = enf
	pe.mu.Unlock()

	pe.recordAudit(actor, "rate_limit", "device", device.ID, fmt.Sprintf("Rate limit applied (%d down / %d up)", dlBps, ulBps), "success")
	pe.eventBus.Publish(events.EventEnforcementApplied, device.SiteID, enf)
	return enf, nil
}

// ListEnforcements returns all active enforcements.
func (pe *PolicyEngine) ListEnforcements() []*models.Enforcement {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	res := make([]*models.Enforcement, 0, len(pe.enforcements))
	for _, e := range pe.enforcements {
		cp := *e
		res = append(res, &cp)
	}
	return res
}

// --- Policy CRUD (backed by in-memory map; persisted via Store by server layer) ---

// SavePolicy creates or updates a policy rule.
func (pe *PolicyEngine) SavePolicy(p *models.Policy) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	pe.policies[p.ID] = p
}

// GetPolicy returns a policy by ID.
func (pe *PolicyEngine) GetPolicy(id string) (*models.Policy, bool) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	p, ok := pe.policies[id]
	return p, ok
}

// ListPolicies returns all policy rules.
func (pe *PolicyEngine) ListPolicies() []*models.Policy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	res := make([]*models.Policy, 0, len(pe.policies))
	for _, p := range pe.policies {
		res = append(res, p)
	}
	return res
}

// DeletePolicy removes a policy rule.
func (pe *PolicyEngine) DeletePolicy(id string) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if _, ok := pe.policies[id]; !ok {
		return false
	}
	delete(pe.policies, id)
	return true
}

// RemoveRateLimit rolls back a rate-limit enforcement.
func (pe *PolicyEngine) RemoveRateLimit(ctx context.Context, enforcementID, actor string) error {
	pe.mu.Lock()
	enf, ok := pe.enforcements[enforcementID]
	pe.mu.Unlock()

	if !ok {
		return fmt.Errorf("enforcement %q not found", enforcementID)
	}

	adapter, err := pe.adapters.Get(enf.Adapter)
	if err != nil {
		return fmt.Errorf("adapter %q not found: %w", enf.Adapter, err)
	}

	work := *enf
	work.DesiredState = models.StateRolledBack
	if err := adapter.RemoveRateLimit(ctx, &work); err != nil {
		enf.DesiredState = work.DesiredState
		enf.ErrorMessage = err.Error()
		pe.mu.Lock()
		pe.enforcements[enf.ID] = enf
		pe.mu.Unlock()
		pe.recordAudit(actor, "remove_rate_limit", "device", enf.DeviceID, fmt.Sprintf("Failed: %v", err), "failed")
		return err
	}

	enf.DesiredState = work.DesiredState
	enf.ActualState = work.ActualState
	enf.ErrorMessage = ""
	if work.AppliedAt != nil {
		enf.AppliedAt = work.AppliedAt
	}
	pe.mu.Lock()
	delete(pe.enforcements, enforcementID)
	pe.mu.Unlock()

	pe.recordAudit(actor, "remove_rate_limit", "device", enf.DeviceID, "Rate limit lifted", "success")
	pe.eventBus.Publish(events.EventEnforcementRemoved, "", enf)
	return nil
}

// ListAuditLogs returns the history of audited operations.
func (pe *PolicyEngine) ListAuditLogs() []models.AuditLog {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	res := make([]models.AuditLog, len(pe.auditLogs))
	copy(res, pe.auditLogs)
	return res
}

// Audit records an operator or system action. Exposed so API handlers can
// audit operations (trust changes, schedules, webhooks) the engine doesn't
// natively perform.
func (pe *PolicyEngine) Audit(actor, action, targetType, targetID, details, status string) {
	pe.recordAudit(actor, action, targetType, targetID, details, status)
}

// TagEnforcement links an enforcement to its source policy (concurrency-safe).
func (pe *PolicyEngine) TagEnforcement(enforcementID, policyID string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if enf, ok := pe.enforcements[enforcementID]; ok {
		enf.PolicyID = policyID
	}
}

// SnapshotPolicies returns copies of all policy rules for persistence.
func (pe *PolicyEngine) SnapshotPolicies() []*models.Policy {
	return pe.ListPolicies()
}

// RestorePolicies replaces the policy set (used at startup from snapshot).
func (pe *PolicyEngine) RestorePolicies(pols []*models.Policy) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.policies = make(map[string]*models.Policy, len(pols))
	for _, p := range pols {
		if p != nil && p.ID != "" {
			pe.policies[p.ID] = p
		}
	}
}

// SnapshotAudit returns the audit trail for persistence.
func (pe *PolicyEngine) SnapshotAudit() []models.AuditLog {
	return pe.ListAuditLogs()
}

// RestoreAudit replaces the audit trail (used at startup from snapshot).
func (pe *PolicyEngine) RestoreAudit(logs []models.AuditLog) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.auditLogs = append([]models.AuditLog(nil), logs...)
	if len(pe.auditLogs) > 1000 {
		pe.auditLogs = pe.auditLogs[len(pe.auditLogs)-1000:]
	}
}

func (pe *PolicyEngine) recordAudit(actor, action, targetType, targetID, details, status string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	log := models.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Details:    details,
		Status:     status,
	}
	pe.auditLogs = append(pe.auditLogs, log)
	if len(pe.auditLogs) > 1000 {
		pe.auditLogs = pe.auditLogs[len(pe.auditLogs)-1000:]
	}
}

// ttlWorker checks every 5 seconds for expired enforcements and automatically rolls them back.
func (pe *PolicyEngine) ttlWorker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pe.stopCh:
			return
		case now := <-ticker.C:
			pe.mu.RLock()
			var expiredIDs []string
			for id, enf := range pe.enforcements {
				if enf.ExpiresAt != nil && now.After(*enf.ExpiresAt) && enf.ActualState == models.StateApplied {
					expiredIDs = append(expiredIDs, id)
				}
			}
			pe.mu.RUnlock()

			for _, id := range expiredIDs {
				// Roll back with the correct remover per action type.
				pe.mu.RLock()
				enf, ok := pe.enforcements[id]
				pe.mu.RUnlock()
				if !ok {
					continue
				}
				if enf.Action == models.ActionRateLimit {
					_ = pe.RemoveRateLimit(context.Background(), id, "system_ttl_expiration")
				} else {
					_ = pe.RemoveQuarantine(context.Background(), id, "system_ttl_expiration")
				}
			}
		}
	}
}
