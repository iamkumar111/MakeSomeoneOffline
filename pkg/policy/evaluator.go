package policy

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// DefaultPolicyTTL is the safe quarantine/rate-limit duration for policy-fired
// enforcements when the rule sets no TTL.
const DefaultPolicyTTL = 15 * time.Minute

// Evaluator periodically matches live devices against enabled policy rules
// and fires their actions. Without this, policies are inert records.
type Evaluator struct {
	engine      *PolicyEngine
	listDevices func() []*models.Device
	interval    time.Duration
	stopCh      chan struct{}
}

// NewEvaluator creates and starts the evaluation loop.
func NewEvaluator(pe *PolicyEngine, listDevices func() []*models.Device, interval time.Duration) *Evaluator {
	if interval < 10*time.Second {
		interval = 60 * time.Second
	}
	ev := &Evaluator{
		engine:      pe,
		listDevices: listDevices,
		interval:    interval,
		stopCh:      make(chan struct{}),
	}
	go ev.loop()
	return ev
}

// Stop terminates the loop.
func (ev *Evaluator) Stop() {
	select {
	case <-ev.stopCh:
	default:
		close(ev.stopCh)
	}
}

func (ev *Evaluator) loop() {
	ticker := time.NewTicker(ev.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ev.stopCh:
			return
		case <-ticker.C:
			ev.EvaluateOnce()
		}
	}
}

// EvaluateOnce runs one matching pass. Returns actions taken. Safe to call
// directly (used by tests and the first pass at startup is skipped by design
// — the loop drives it).
func (ev *Evaluator) EvaluateOnce() int {
	if ev.listDevices == nil {
		return 0
	}
	pols := ev.engine.ListPolicies()
	if len(pols) == 0 {
		return 0
	}
	sort.SliceStable(pols, func(i, j int) bool { return pols[i].Priority < pols[j].Priority })

	taken := 0
	for _, dev := range ev.listDevices() {
		if dev == nil || !dev.IsOnline {
			continue // pointless (and noisy) to enforce on offline devices
		}
		if ev.hasActiveEnforcement(dev.ID) {
			continue // one active enforcement per device; prevents pile-up
		}
		for _, p := range pols {
			if p == nil || !p.Enabled {
				continue
			}
			if !matchesPolicy(dev, &p.Selector) {
				continue
			}
			// First match in priority order wins; explicit allow stops
			// lower-priority rules from firing on this device.
			if p.Action.Type == models.ActionAllow {
				ev.engine.Audit("policy_engine", "policy_allow", "device", dev.ID, "allowed by "+p.Name, "success")
				break
			}
			if ev.fire(dev, p) {
				taken++
			}
			break
		}
	}
	return taken
}

// hasActiveEnforcement reports a real (non-dry-run) applied enforcement
// already covering a device. Dry runs must not suppress real enforcement.
func (ev *Evaluator) hasActiveEnforcement(deviceID string) bool {
	for _, e := range ev.engine.ListEnforcements() {
		if e.DryRun {
			continue
		}
		if e.DeviceID == deviceID && e.ActualState == models.StateApplied {
			return true
		}
	}
	return false
}

// fire executes a matched rule's action. Returns true if an enforcement or
// audit record resulted.
func (ev *Evaluator) fire(dev *models.Device, p *models.Policy) bool {
	ctx := context.Background()
	actor := "policy:" + p.Name
	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultPolicyTTL
	}
	switch p.Action.Type {
	case models.ActionQuarantine, models.ActionIsolate:
		enf, err := ev.engine.ApplyQuarantine(ctx, dev, "", ttl, actor, false)
		if err != nil || enf == nil {
			return false
		}
		ev.engine.TagEnforcement(enf.ID, p.ID)
		return true
	case models.ActionRateLimit:
		dl, ul := p.Action.DownloadBps, p.Action.UploadBps
		if dl == 0 {
			dl = 2000000
		}
		if ul == 0 {
			ul = 1000000
		}
		enf, err := ev.engine.ApplyRateLimit(ctx, dev, "", dl, ul, ttl, actor, false)
		if err != nil || enf == nil {
			return false
		}
		ev.engine.TagEnforcement(enf.ID, p.ID)
		return true
	case models.ActionAlertOnly:
		ev.engine.Audit(actor, "policy_match", "device", dev.ID, "matched "+p.Name+" (alert only)", "success")
		return true
	default:
		return false
	}
}

// matchesPolicy reports whether a device satisfies every set selector field.
// A completely empty selector matches NOTHING: a blank rule must never
// quarantine the whole LAN by accident.
func matchesPolicy(dev *models.Device, sel *models.PolicySelector) bool {
	if sel == nil {
		return false
	}
	empty := sel.DeviceID == "" && sel.MAC == "" && sel.IP == "" &&
		sel.Segment == "" && sel.TrustState == "" && sel.MinRiskScore <= 0
	if empty {
		return false
	}
	if sel.DeviceID != "" && dev.ID != sel.DeviceID {
		return false
	}
	if sel.MAC != "" && !macEqual(dev.PrimaryMAC, sel.MAC) {
		return false
	}
	if sel.IP != "" && strings.TrimSpace(dev.PrimaryIP) != strings.TrimSpace(sel.IP) {
		return false
	}
	if sel.TrustState != "" && dev.TrustState != sel.TrustState {
		return false
	}
	if sel.MinRiskScore > 0 && dev.RiskScore < sel.MinRiskScore {
		return false
	}
	if sel.Segment != "" && dev.Labels["segment"] != sel.Segment {
		return false
	}
	return true
}

func macEqual(a, b string) bool {
	norm := func(m string) string {
		m = strings.ToLower(strings.TrimSpace(m))
		m = strings.ReplaceAll(m, "-", ":")
		return m
	}
	return norm(a) != "" && norm(a) == norm(b)
}
