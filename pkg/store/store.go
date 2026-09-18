package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
	"github.com/open-netcut/open-netcut/pkg/notify"
	"github.com/open-netcut/open-netcut/pkg/policy"
)

// Store defines persistence operations for all domain entities.
type Store interface {
	SaveDevice(ctx context.Context, device *models.Device) error
	GetDevice(ctx context.Context, id string) (*models.Device, error)
	ListDevices(ctx context.Context, siteID string) ([]*models.Device, error)

	SaveAlert(ctx context.Context, alert *models.Alert) error
	ListAlerts(ctx context.Context) ([]*models.Alert, error)

	SavePolicy(ctx context.Context, policy *models.Policy) error
	ListPolicies(ctx context.Context) ([]*models.Policy, error)

	SaveEnforcement(ctx context.Context, enf *models.Enforcement) error
	ListEnforcements(ctx context.Context) ([]*models.Enforcement, error)

	SaveAuditLog(ctx context.Context, log *models.AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]models.AuditLog, error)
}

// MemoryStore provides a concurrent-safe in-memory store for development and testing.
type MemoryStore struct {
	mu           sync.RWMutex
	devices      map[string]*models.Device
	alerts       map[string]*models.Alert
	policies     map[string]*models.Policy
	enforcements map[string]*models.Enforcement
	auditLogs    []models.AuditLog
	schedules    []*policy.PolicySchedule
	webhooks     []*notify.WebhookEndpoint
	freeze       policy.FreezeSnapshot
}

// SetSchedules replaces the persisted schedule list (synced from the engine).
func (s *MemoryStore) SetSchedules(list []*policy.PolicySchedule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules = list
}

// GetSchedules returns the persisted schedule list.
func (s *MemoryStore) GetSchedules() []*policy.PolicySchedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*policy.PolicySchedule(nil), s.schedules...)
}

// SetFreeze replaces the persisted freeze latch snapshot.
func (s *MemoryStore) SetFreeze(f policy.FreezeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.freeze = f
}

// GetFreeze returns the persisted freeze latch snapshot.
func (s *MemoryStore) GetFreeze() policy.FreezeSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.freeze
}

// SetWebhooks replaces the persisted webhook list (synced from the engine).
func (s *MemoryStore) SetWebhooks(list []*notify.WebhookEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks = list
}

// GetWebhooks returns the persisted webhook list.
func (s *MemoryStore) GetWebhooks() []*notify.WebhookEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*notify.WebhookEndpoint(nil), s.webhooks...)
}

// NewMemoryStore creates an initialized in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		devices:      make(map[string]*models.Device),
		alerts:       make(map[string]*models.Alert),
		policies:     make(map[string]*models.Policy),
		enforcements: make(map[string]*models.Enforcement),
		auditLogs:    make([]models.AuditLog, 0),
	}
}

func (s *MemoryStore) SaveDevice(ctx context.Context, d *models.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
	return nil
}

func (s *MemoryStore) GetDevice(ctx context.Context, id string) (*models.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	if !ok {
		return nil, fmt.Errorf("device %q not found", id)
	}
	return d, nil
}

func (s *MemoryStore) ListDevices(ctx context.Context, siteID string) ([]*models.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.Device, 0, len(s.devices))
	for _, d := range s.devices {
		if siteID == "" || d.SiteID == siteID {
			list = append(list, d)
		}
	}
	return list, nil
}

func (s *MemoryStore) SaveAlert(ctx context.Context, a *models.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts[a.ID] = a
	return nil
}

func (s *MemoryStore) ListAlerts(ctx context.Context) ([]*models.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		list = append(list, a)
	}
	return list, nil
}

func (s *MemoryStore) SavePolicy(ctx context.Context, p *models.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryStore) ListPolicies(ctx context.Context) ([]*models.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		list = append(list, p)
	}
	return list, nil
}

func (s *MemoryStore) SaveEnforcement(ctx context.Context, e *models.Enforcement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforcements[e.ID] = e
	return nil
}

func (s *MemoryStore) ListEnforcements(ctx context.Context) ([]*models.Enforcement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.Enforcement, 0, len(s.enforcements))
	for _, e := range s.enforcements {
		list = append(list, e)
	}
	return list, nil
}

func (s *MemoryStore) SaveAuditLog(ctx context.Context, l *models.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, *l)
	return nil
}

func (s *MemoryStore) ListAuditLogs(ctx context.Context, limit int) ([]models.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.auditLogs) {
		limit = len(s.auditLogs)
	}
	res := make([]models.AuditLog, limit)
	start := len(s.auditLogs) - limit
	copy(res, s.auditLogs[start:])
	return res, nil
}

// snapshot is the JSON file format for -db persistence.
type snapshot struct {
	Version      int                          `json:"version"`
	Devices      map[string]*models.Device      `json:"devices"`
	Alerts       map[string]*models.Alert       `json:"alerts"`
	Policies     map[string]*models.Policy      `json:"policies"`
	Enforcements map[string]*models.Enforcement `json:"enforcements"`
	AuditLogs    []models.AuditLog              `json:"audit_logs"`
	Schedules    []*policy.PolicySchedule       `json:"schedules,omitempty"`
	Webhooks     []*notify.WebhookEndpoint      `json:"webhooks,omitempty"`
	Freeze       policy.FreezeSnapshot          `json:"freeze,omitempty"`
}

const snapshotVersion = 1
const maxAuditLogsFile = 1000

// SaveToFile persists atomically: write tmp + fsync + rename, keep .bak.
// Crash-safe: a kill -9 mid-save never leaves a half-written db file.
func (s *MemoryStore) SaveToFile(path string) error {
	s.mu.RLock()
	audit := s.auditLogs
	if len(audit) > maxAuditLogsFile {
		audit = audit[len(audit)-maxAuditLogsFile:]
	}
	snap := snapshot{
		Version:      snapshotVersion,
		Devices:      s.devices,
		Alerts:       s.alerts,
		Policies:     s.policies,
		Enforcements: s.enforcements,
		AuditLogs:    audit,
		Schedules:    s.schedules,
		Webhooks:     s.webhooks,
		Freeze:       s.freeze,
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, path+".bak")
	}
	return os.Rename(tmp, path)
}

// LoadFromFile restores a snapshot, falling back to .bak on corruption.
func (s *MemoryStore) LoadFromFile(path string) error {
	if err := s.loadPath(path); err == nil {
		return nil
	} else {
		if bakErr := s.loadPath(path + ".bak"); bakErr == nil {
			return fmt.Errorf("primary db corrupt, loaded backup (.bak)")
		}
		if data, rerr := os.ReadFile(path); rerr == nil {
			_ = os.WriteFile(path+".corrupt", data, 0600)
		}
		return err
	}
}

func (s *MemoryStore) loadPath(path string) error {	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Devices != nil {
		s.devices = snap.Devices
	}
	if snap.Alerts != nil {
		s.alerts = snap.Alerts
	}
	if snap.Policies != nil {
		s.policies = snap.Policies
	}
	if snap.Enforcements != nil {
		s.enforcements = snap.Enforcements
	}
	if snap.AuditLogs != nil {
		if len(snap.AuditLogs) > maxAuditLogsFile {
			snap.AuditLogs = snap.AuditLogs[len(snap.AuditLogs)-maxAuditLogsFile:]
		}
		s.auditLogs = snap.AuditLogs
	}
	if snap.Schedules != nil {
		s.schedules = snap.Schedules
	}
	if snap.Webhooks != nil {
		s.webhooks = snap.Webhooks
	}
	s.freeze = snap.Freeze
	return nil
}

// StartAutoSave persists every interval (debounced crash protection).
// preSave, when non-nil, runs before each save so engine state (policies,
// audit, schedules, webhooks) lands in the snapshot too. Final save should
// still run on shutdown.
func (s *MemoryStore) StartAutoSave(path string, interval time.Duration, preSave func()) func() {
	if interval < 5*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				if preSave != nil {
					preSave()
				}
				_ = s.SaveToFile(path)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}
