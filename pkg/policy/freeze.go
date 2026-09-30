package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// FreezeSnapshot is the persistable part of the freeze latch.
type FreezeSnapshot struct {
	Active      bool   `json:"active"`
	Adapter     string `json:"adapter"`
	TTLSeconds  int64  `json:"ttl_seconds"`
	Reason      string `json:"reason"`
	SelfIP      string `json:"self_ip,omitempty"`
	SelfMAC     string `json:"self_mac,omitempty"`
	ExcludeSelf bool   `json:"exclude_self,omitempty"`
}

// SelfExclusion identifies the operator's own device (the browser hitting the
// API) so a freeze can spare it. Same-LAN dashboard traffic never uses the
// gateway, so excluding yourself never locks you out of the UI.
type SelfExclusion struct {
	// IP and MAC of the operator's device, resolved server-side.
	IP, MAC string
	// Exclude=true keeps the operator online; false cuts them like everyone.
	Exclude bool
}

// FreezeController is a latch: while active, every newly seen (or newly
// online) device is quarantined automatically, so devices joining AFTER a
// freeze can't walk onto the open LAN. A one-shot freeze without this would
// only ever cover devices known at click time.
type FreezeController struct {
	mu           sync.RWMutex
	active       bool
	adapter      string
	ttl          time.Duration
	reason       string
	selfIP       string
	selfMAC      string
	excludeSelf  bool
	policyEngine *PolicyEngine
	listDevices  func() []*models.Device
	setTrust     func(id string, state models.TrustState) error
	protectedFn  func(ip, mac string) (bool, string)
	eventBus     *events.EventBus
	stopCh       chan struct{}
}

// NewFreezeController creates the latch (initially OFF) and subscribes it to
// device observations. Callbacks keep the policy package decoupled from
// discovery: listDevices enumerates the inventory, setTrust flips trust
// state, isProtected enforces the allowlist.
func NewFreezeController(
	pe *PolicyEngine,
	bus *events.EventBus,
	listDevices func() []*models.Device,
	setTrust func(id string, state models.TrustState) error,
	protectedFn func(ip, mac string) (bool, string),
) *FreezeController {
	fc := &FreezeController{
		policyEngine: pe,
		listDevices:  listDevices,
		setTrust:     setTrust,
		protectedFn:  protectedFn,
		eventBus:     bus,
		stopCh:       make(chan struct{}),
	}
	if bus != nil {
		// Subscribe synchronously: events published immediately after
		// construction must not be lost to a not-yet-running goroutine.
		sub := bus.Subscribe(100)
		go fc.watchSub(sub)
	}
	return fc
}

// IsActive reports whether the latch is on.
func (fc *FreezeController) IsActive() bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.active
}

// Snapshot captures the latch for persistence.
func (fc *FreezeController) Snapshot() FreezeSnapshot {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return FreezeSnapshot{
		Active:      fc.active,
		Adapter:     fc.adapter,
		TTLSeconds:  int64(fc.ttl / time.Second),
		Reason:      fc.reason,
		SelfIP:      fc.selfIP,
		SelfMAC:     fc.selfMAC,
		ExcludeSelf: fc.excludeSelf,
	}
}

// Restore re-arms a persisted latch (e.g. after restart). Newly discovered
// devices are cut as they appear; nothing retroactive is needed.
func (fc *FreezeController) Restore(snap FreezeSnapshot) {
	if !snap.Active {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.active = true
	fc.adapter = snap.Adapter
	fc.ttl = time.Duration(snap.TTLSeconds) * time.Second
	if fc.ttl <= 0 {
		fc.ttl = DefaultPolicyTTL
	}
	fc.reason = snap.Reason
	fc.selfIP = snap.SelfIP
	fc.selfMAC = snap.SelfMAC
	fc.excludeSelf = snap.ExcludeSelf
}

// Activate turns the latch on and cuts every currently online,
// non-allowlisted device without an active enforcement. self describes the
// operator's own device: excluded unless the operator chose to be cut too.
// Dry runs never latch: latching a drill would cut REAL newcomers later.
func (fc *FreezeController) Activate(adapter string, ttl time.Duration, reason string, dryRun bool, self SelfExclusion) (applied, skipped int, failed []string) {
	if err := fc.Arm(adapter, ttl, reason, self, dryRun); err != nil {
		return 0, 0, []string{err.Error()}
	}
	return fc.CutCurrent(adapter, ttl, reason, dryRun, self)
}

// Arm validates and switches the latch on synchronously (fast: no I/O), so
// device events arriving right after are caught by the watcher. Dry runs
// never arm.
func (fc *FreezeController) Arm(adapter string, ttl time.Duration, reason string, self SelfExclusion, dryRun bool) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("a reason is required to freeze the whole LAN")
	}
	if ttl <= 0 {
		ttl = DefaultPolicyTTL
	}
	if dryRun {
		return nil
	}
	fc.mu.Lock()
	fc.active = true
	fc.adapter = adapter
	fc.ttl = ttl
	fc.reason = reason
	fc.selfIP = strings.TrimSpace(self.IP)
	fc.selfMAC = strings.ToLower(strings.TrimSpace(self.MAC))
	fc.excludeSelf = self.Exclude
	fc.mu.Unlock()
	return nil
}

// CutCurrent cuts every currently online device once. Slow path: each device
// costs nftables/NDP subprocess calls, so HTTP handlers run this in the
// background and answer 202 immediately.
func (fc *FreezeController) CutCurrent(adapter string, ttl time.Duration, reason string, dryRun bool, self SelfExclusion) (applied, skipped int, failed []string) {
	reason = strings.TrimSpace(reason)
	if ttl <= 0 {
		ttl = DefaultPolicyTTL
	}
	for _, dev := range fc.currentDevices() {
		if !dev.IsOnline || dev.PrimaryIP == "" {
			skipped++ // offline/absent: nothing to cut
			continue
		}
		if fc.isProtected(dev.PrimaryIP, dev.PrimaryMAC) {
			skipped++
			continue
		}
		if fc.isSelf(dev.PrimaryIP, dev.PrimaryMAC, self) {
			skipped++
			continue
		}
		if fc.hasActive(dev.ID) {
			skipped++
			continue
		}
		enf, err := fc.policyEngine.ApplyQuarantine(context.Background(), dev, adapter, ttl, "freeze:"+reason, dryRun)
		if err != nil || enf == nil {
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			failed = append(failed, fmt.Sprintf("%s: %s", dev.PrimaryIP, msg))
			continue
		}
		_ = fc.setTrustState(dev.ID, models.TrustStateQuarantined)
		applied++
	}
	return applied, skipped, failed
}

// Deactivate turns the latch off first (no new cuts), then lifts every active
// quarantine — including manual ones, since freeze membership isn't tagged.
// Callers must surface that scope in the UI.
func (fc *FreezeController) Deactivate(actor string) (lifted int) {
	fc.Unlatch()
	return fc.LiftAll(actor)
}

// Unlatch switches the latch off synchronously (fast: no I/O) so no new cuts
// start after this returns.
func (fc *FreezeController) Unlatch() {
	fc.mu.Lock()
	fc.active = false
	fc.mu.Unlock()
}

// LiftAll removes every active quarantine. Slow path (one adapter round-trip
// per enforcement); HTTP handlers run it in the background.
func (fc *FreezeController) LiftAll(actor string) (lifted int) {
	affected := map[string]bool{}
	for _, e := range fc.policyEngine.ListEnforcements() {
		if e.Action != models.ActionQuarantine {
			continue
		}
		if err := fc.policyEngine.RemoveQuarantine(context.Background(), e.ID, actor); err == nil {
			lifted++
			affected[e.DeviceID] = true
		}
	}
	for id := range affected {
		_ = fc.setTrustState(id, models.TrustStateUnknown)
	}
	return lifted
}

// Stop terminates the watcher.
func (fc *FreezeController) Stop() {
	select {
	case <-fc.stopCh:
	default:
		close(fc.stopCh)
	}
}

// watch cuts newcomers while the latch is on.
func (fc *FreezeController) watchSub(sub chan events.Event) {
	defer fc.eventBus.Unsubscribe(sub)
	for {
		select {
		case <-fc.stopCh:
			return
		case evt, ok := <-sub:
			if !ok {
				return
			}
			if evt.Type != events.EventDeviceSeen && evt.Type != events.EventDeviceUpdated {
				continue
			}
			dev, ok := evt.Data.(*models.Device)
			if !ok || dev == nil || !dev.IsOnline {
				continue
			}
			fc.mu.RLock()
			active, adapter, ttl, reason := fc.active, fc.adapter, fc.ttl, fc.reason
			excludeSelf, selfIP, selfMAC := fc.excludeSelf, fc.selfIP, fc.selfMAC
			fc.mu.RUnlock()
			if !active {
				continue
			}
			if fc.isProtected(dev.PrimaryIP, dev.PrimaryMAC) {
				continue
			}
			if excludeSelf && isSelfDevice(dev.PrimaryIP, dev.PrimaryMAC, selfIP, selfMAC) {
				continue
			}
			if fc.hasActive(dev.ID) {
				continue
			}
			enf, err := fc.policyEngine.ApplyQuarantine(context.Background(), dev, adapter, ttl, "freeze:"+reason, false)
			if err != nil || enf == nil {
				continue
			}
			_ = fc.setTrustState(dev.ID, models.TrustStateQuarantined)
		}
	}
}

func (fc *FreezeController) isSelf(devIP, devMAC string, self SelfExclusion) bool {
	return self.Exclude && isSelfDevice(devIP, devMAC, self.IP, self.MAC)
}

// isSelfDevice matches a device against the operator's address by IP or MAC.
// MAC comparison tolerates : vs - separators and case.
func isSelfDevice(devIP, devMAC, selfIP, selfMAC string) bool {
	if selfIP != "" && strings.TrimSpace(devIP) == strings.TrimSpace(selfIP) {
		return true
	}
	norm := func(m string) string {
		m = strings.ToLower(strings.TrimSpace(m))
		return strings.ReplaceAll(m, "-", ":")
	}
	return selfMAC != "" && norm(devMAC) != "" && norm(devMAC) == norm(selfMAC)
}

func (fc *FreezeController) currentDevices() []*models.Device {
	if fc.listDevices == nil {
		return nil
	}
	return fc.listDevices()
}

func (fc *FreezeController) isProtected(ip, mac string) bool {
	if fc.protectedFn == nil {
		return false
	}
	protected, _ := fc.protectedFn(ip, mac)
	return protected
}

func (fc *FreezeController) setTrustState(id string, state models.TrustState) error {
	if fc.setTrust == nil {
		return nil
	}
	return fc.setTrust(id, state)
}

func (fc *FreezeController) hasActive(deviceID string) bool {
	for _, e := range fc.policyEngine.ListEnforcements() {
		// Dry runs record intent without touching the wire; they must never
		// block a real cut (otherwise one drill silently disables all future
		// enforcement for the device).
		if e.DryRun {
			continue
		}
		if e.DeviceID == deviceID && e.Action == models.ActionQuarantine && e.ActualState == models.StateApplied {
			return true
		}
	}
	return false
}
