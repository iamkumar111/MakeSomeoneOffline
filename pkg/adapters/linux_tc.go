package adapters

import (
	"context"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// LinuxTCAdapter controls bandwidth shaping using Linux Traffic Control (tc) and HTB qdiscs.
type LinuxTCAdapter struct {
	mu           sync.Mutex
	iface        string
	isAvailable  bool
	checkedAvail bool
	classByIP    map[string]string // targetIP -> classid (e.g. "1:10")
}

// NewLinuxTCAdapter creates a tc bandwidth shaper on the given network interface.
func NewLinuxTCAdapter(iface string) *LinuxTCAdapter {
	if iface == "" {
		iface = "eth0"
	}
	return &LinuxTCAdapter{
		iface:     iface,
		classByIP: make(map[string]string),
	}
}

func (a *LinuxTCAdapter) Name() string {
	return "linux_tc"
}

func (a *LinuxTCAdapter) Capabilities() []string {
	return []string{"rate_limit", "tc_htb", "bandwidth_shaping"}
}

func (a *LinuxTCAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name: "linux_tc", Label: "Linux Gateway — Traffic Control HTB (Recommended for shaping)",
		Kind: KindShaping, Effectiveness: 5,
		Capabilities: a.Capabilities(),
		RecommendedWhen: "Linux gateway deployment: real per-IP bandwidth cap via tc HTB class + u32 filter.",
		Requires: "tc (iproute2) + root on gateway; set TC_IFACE (default eth0).",
		Description: "Queues device traffic to e.g. 2 Mbps down / 1 Mbps up instead of dropping it. Pair with nftables quarantine for full block.",
		SupportsQuarantine: false, SupportsShaping: true,
	}
}

func (a *LinuxTCAdapter) IsAvailable(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkedAvail {
		return a.isAvailable
	}

	_, err := exec.LookPath("tc")
	a.isAvailable = (err == nil)
	a.checkedAvail = true
	return a.isAvailable
}

func (a *LinuxTCAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	return fmt.Errorf("quarantine should be applied via LinuxNFTablesAdapter")
}

func (a *LinuxTCAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	return nil
}

// classIDForIP derives a stable per-device HTB classid to avoid collisions.
// Range 1:10 .. 1:4999 reserved for shaped devices; 1:30 is default.
func classIDForIP(ip string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	n := 10 + int(h.Sum32()%4980) // 10..4989
	if n == 30 {
		n = 31 // keep default class free
	}
	return fmt.Sprintf("1:%d", n)
}

// ApplyRateLimit applies real rate shaping via tc HTB classes and u32 filters.
func (a *LinuxTCAdapter) ApplyRateLimit(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}

	if !a.IsAvailable(ctx) {
		return fmt.Errorf("tc command not available in PATH")
	}

	if e.TargetIP == "" {
		return fmt.Errorf("target IP is required for tc rate shaping")
	}

	rateKbps := e.RateDownload / 1000
	if rateKbps < 64 {
		rateKbps = 64 // Minimum 64 Kbps
	}

	classID := classIDForIP(e.TargetIP)

	// 1. Ensure root qdisc exists (htb) — ignore "File exists"
	_ = exec.CommandContext(ctx, "tc", "qdisc", "add", "dev", a.iface, "root", "handle", "1:", "htb", "default", "30").Run()

	// 2. Add/replace class with rate limit (replace is idempotent)
	classCmd := exec.CommandContext(ctx, "tc", "class", "replace", "dev", a.iface, "parent", "1:", "classid", classID, "htb", "rate", fmt.Sprintf("%dkbit", rateKbps), "ceil", fmt.Sprintf("%dkbit", rateKbps))
	if out, err := classCmd.CombinedOutput(); err != nil {
		e.ActualState = models.StateFailed
		e.ErrorMessage = fmt.Sprintf("tc class error: %s", strings.TrimSpace(string(out)))
		return fmt.Errorf("%s", e.ErrorMessage)
	}

	// 3. Add u32 filter matching target IP (dedupe: delete same match first)
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", a.iface, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", e.TargetIP).Run()
	filterCmd := exec.CommandContext(ctx, "tc", "filter", "add", "dev", a.iface, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", e.TargetIP, "flowid", classID)
	out, err := filterCmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		e.ActualState = models.StateFailed
		e.ErrorMessage = fmt.Sprintf("tc filter error: %s", strings.TrimSpace(string(out)))
		return fmt.Errorf("%s", e.ErrorMessage)
	}
	a.classByIP[e.TargetIP] = classID

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	return nil
}

// RemoveRateLimit rolls back only this device's tc filter + class (never the root qdisc).
func (a *LinuxTCAdapter) RemoveRateLimit(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateRolledBack
		return nil
	}

	if !a.IsAvailable(ctx) {
		return fmt.Errorf("tc command not available in PATH")
	}

	classID := a.classByIP[e.TargetIP]
	if classID == "" {
		classID = classIDForIP(e.TargetIP)
	}
	// Delete only this IP's filter, then its class. Keep root qdisc for others.
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", a.iface, "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", e.TargetIP).Run()
	_ = exec.CommandContext(ctx, "tc", "class", "del", "dev", a.iface, "parent", "1:", "classid", classID).Run()
	delete(a.classByIP, e.TargetIP)

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}
