package adapters

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// NetworkAdapter defines the interface that all enforcement backends must satisfy.
type NetworkAdapter interface {
	Name() string
	Capabilities() []string
	IsAvailable(ctx context.Context) bool
	Describe() AdapterInfo

	// Quarantine blocks network access for a given device IP / MAC.
	ApplyQuarantine(ctx context.Context, enforcement *models.Enforcement) error
	RemoveQuarantine(ctx context.Context, enforcement *models.Enforcement) error

	// RateLimit restricts throughput for a given device.
	ApplyRateLimit(ctx context.Context, enforcement *models.Enforcement) error
	RemoveRateLimit(ctx context.Context, enforcement *models.Enforcement) error
}

// AdapterKind groups what an adapter is good at.
type AdapterKind string

const (
	KindQuarantine AdapterKind = "quarantine"
	KindShaping    AdapterKind = "shaping"
	KindBoth       AdapterKind = "both"
	KindLab        AdapterKind = "lab"
)

// AdapterInfo is user-facing guidance: what to pick and why.
// Effectiveness is 1-5 for a Linux-gateway deployment (5 = use this).
type AdapterInfo struct {
	Name            string   `json:"name"`
	Label           string   `json:"label"`
	Kind            AdapterKind `json:"kind"`
	Effectiveness   int      `json:"effectiveness_1_5"`
	Capabilities    []string `json:"capabilities"`
	RecommendedWhen string   `json:"recommended_when"`
	Requires        string   `json:"requires"`
	Description     string   `json:"description"`
	Warning         string   `json:"warning,omitempty"`
	LabOnly         bool     `json:"lab_only,omitempty"`
	TestOnly        bool     `json:"test_only,omitempty"`
	SupportsQuarantine bool `json:"supports_quarantine"`
	SupportsShaping    bool `json:"supports_shaping"`
}

// MemoryMockAdapter provides an in-memory enforcement implementation for testing and dry-run modes.
type MemoryMockAdapter struct {
	mu           sync.Mutex
	name         string
	quarantined  map[string]*models.Enforcement // keyed by MAC or IP
	rateLimited  map[string]*models.Enforcement
	simulatedErr error
}

// NewMemoryMockAdapter creates an instance of the mock adapter.
func NewMemoryMockAdapter(name string) *MemoryMockAdapter {
	if name == "" {
		name = "mock_adapter"
	}
	return &MemoryMockAdapter{
		name:        name,
		quarantined: make(map[string]*models.Enforcement),
		rateLimited: make(map[string]*models.Enforcement),
	}
}

func (m *MemoryMockAdapter) Name() string {
	return m.name
}

func (m *MemoryMockAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name: m.name, Label: "Mock Simulator (lab / dry-run)",
		Kind: KindLab, Effectiveness: 1,
		Capabilities: m.Capabilities(),
		RecommendedWhen: "Testing UI and policy flow only — touches no real packets.",
		Requires: "Nothing (always available).",
		Description: "In-memory fake. Use Dry Run to preview policy without dropping traffic.",
		Warning: "Does NOT block or shape real traffic.",
		LabOnly: true, TestOnly: true,
		SupportsQuarantine: true, SupportsShaping: true,
	}
}

func (m *MemoryMockAdapter) Capabilities() []string {
	return []string{"quarantine", "rate_limit", "dry_run"}
}

func (m *MemoryMockAdapter) IsAvailable(ctx context.Context) bool {
	return true
}

func (m *MemoryMockAdapter) SetSimulatedError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulatedErr = err
}

func (m *MemoryMockAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.simulatedErr != nil {
		return m.simulatedErr
	}
	key := e.TargetMAC
	if key == "" {
		key = e.TargetIP
	}
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	m.quarantined[key] = e
	return nil
}

func (m *MemoryMockAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.simulatedErr != nil {
		return m.simulatedErr
	}
	key := e.TargetMAC
	if key == "" {
		key = e.TargetIP
	}
	delete(m.quarantined, key)
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}

func (m *MemoryMockAdapter) ApplyRateLimit(ctx context.Context, e *models.Enforcement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.simulatedErr != nil {
		return m.simulatedErr
	}
	key := e.TargetMAC
	if key == "" {
		key = e.TargetIP
	}
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	m.rateLimited[key] = e
	return nil
}

func (m *MemoryMockAdapter) RemoveRateLimit(ctx context.Context, e *models.Enforcement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.simulatedErr != nil {
		return m.simulatedErr
	}
	key := e.TargetMAC
	if key == "" {
		key = e.TargetIP
	}
	delete(m.rateLimited, key)
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}

// AdapterRegistry manages multiple registered router and firewall adapters.
type AdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[string]NetworkAdapter
}

// NewAdapterRegistry returns a new registry.
func NewAdapterRegistry() *AdapterRegistry {
	return &AdapterRegistry{
		adapters: make(map[string]NetworkAdapter),
	}
}

// Register adds an adapter to the registry.
func (r *AdapterRegistry) Register(adapter NetworkAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[adapter.Name()] = adapter
}

// Get finds an adapter by name.
func (r *AdapterRegistry) Get(name string) (NetworkAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("adapter %q not found", name)
	}
	return a, nil
}

// List returns all registered adapters.
func (r *AdapterRegistry) List() []NetworkAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]NetworkAdapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		list = append(list, a)
	}
	return list
}

// Ranked returns adapter infos sorted for the given action on a Linux gateway:
// available first, then by effectiveness desc, lab/test-only last.
func (r *AdapterRegistry) Ranked(ctx context.Context, action string) []RankedAdapter {
	all := r.List()
	out := make([]RankedAdapter, 0, len(all))
	for _, a := range all {
		info := a.Describe()
		avail := a.IsAvailable(ctx)
		supports := false
		switch action {
		case "quarantine":
			supports = info.SupportsQuarantine
		case "rate_limit", "shaping":
			supports = info.SupportsShaping
		default:
			supports = info.SupportsQuarantine || info.SupportsShaping
		}
		out = append(out, RankedAdapter{Info: info, Available: avail, SupportsAction: supports})
	}
	// Sort: supports action first, available first, effectiveness desc, non-lab first.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if rankedLess(out[j], out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// RankedAdapter pairs metadata with live health.
type RankedAdapter struct {
	Info           AdapterInfo `json:"info"`
	Available      bool        `json:"available"`
	SupportsAction bool        `json:"supports_action"`
	Recommended    bool        `json:"recommended"`
	Reason         string      `json:"reason"`
}

// rankedLess reports whether a should sort before b.
func rankedLess(a, b RankedAdapter) bool {
	if a.SupportsAction != b.SupportsAction {
		return a.SupportsAction
	}
	if a.Available != b.Available {
		return a.Available
	}
	aLab := a.Info.LabOnly || a.Info.TestOnly
	bLab := b.Info.LabOnly || b.Info.TestOnly
	if aLab != bLab {
		return !aLab
	}
	return a.Info.Effectiveness > b.Info.Effectiveness
}

// MarkRecommended flags the single best pick (first available+supporting after sort).
func MarkRecommended(ranked []RankedAdapter) []RankedAdapter {
	for i := range ranked {
		ranked[i].Recommended = false
		ranked[i].Reason = recommendReason(ranked[i])
	}
	for i := range ranked {
		if ranked[i].SupportsAction && ranked[i].Available && !ranked[i].Info.LabOnly && !ranked[i].Info.TestOnly {
			ranked[i].Recommended = true
			ranked[i].Reason = "Recommended for this gateway — " + ranked[i].Info.RecommendedWhen
			break
		}
	}
	// Fallback: if nothing available, recommend top supporting (user must fix Requires).
	if !anyRecommended(ranked) {
		for i := range ranked {
			if ranked[i].SupportsAction {
				ranked[i].Recommended = true
				ranked[i].Reason = "Best option once online — " + ranked[i].Info.Requires
				break
			}
		}
	}
	return ranked
}

func anyRecommended(r []RankedAdapter) bool {
	for _, x := range r {
		if x.Recommended {
			return true
		}
	}
	return false
}

func recommendReason(r RankedAdapter) string {
	if !r.SupportsAction {
		return "Does not support this action."
	}
	if !r.Available {
		return "Offline — " + r.Info.Requires
	}
	if r.Info.LabOnly || r.Info.TestOnly {
		return "Lab/test only — " + r.Info.Warning
	}
	return r.Info.RecommendedWhen
}
