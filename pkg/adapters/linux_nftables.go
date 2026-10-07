package adapters

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// LinuxNFTablesAdapter implements network quarantine and filtering using Linux nftables.
type LinuxNFTablesAdapter struct {
	mu           sync.Mutex
	tableName    string
	chainName    string
	isAvailable  bool
	checkedAvail bool
	// rules tracks per-enforcement nft rules so removal is surgical.
	rules map[string][]string // enforcementID -> []rule-spec (without "nft add rule " prefix)
}

// NewLinuxNFTablesAdapter initializes an nftables adapter.
func NewLinuxNFTablesAdapter(tableName, chainName string) *LinuxNFTablesAdapter {
	if tableName == "" {
		tableName = "open_netcut"
	}
	if chainName == "" {
		chainName = "quarantine"
	}
	return &LinuxNFTablesAdapter{
		tableName: tableName,
		chainName: chainName,
		rules:     make(map[string][]string),
	}
}

func (a *LinuxNFTablesAdapter) Name() string {
	return "linux_nftables"
}

func (a *LinuxNFTablesAdapter) Capabilities() []string {
	return []string{"quarantine", "l2_mac_drop", "l3_ip_drop"}
}

func (a *LinuxNFTablesAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name: "linux_nftables", Label: "Linux Gateway — nftables (Recommended for quarantine)",
		Kind: KindQuarantine, Effectiveness: 5,
		Capabilities: a.Capabilities(),
		RecommendedWhen: "Linux gateway deployment: kernel-level drop of device IP+MAC in forward/input chains.",
		Requires: "nft binary + root/CAP_NET_ADMIN on the gateway.",
		Description: "Surgical per-device drop rules with per-enforcement rollback. Most effective quarantine on this box.",
		SupportsQuarantine: true, SupportsShaping: false,
	}
}

func (a *LinuxNFTablesAdapter) isAvailableLocked() bool {
	if a.checkedAvail {
		return a.isAvailable
	}
	_, err := exec.LookPath("nft")
	a.isAvailable = (err == nil)
	a.checkedAvail = true
	return a.isAvailable
}

func (a *LinuxNFTablesAdapter) IsAvailable(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isAvailableLocked()
}

// EnsureTable ensures our dedicated table and base chains exist.
func (a *LinuxNFTablesAdapter) EnsureTable(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ensureTableLocked(ctx)
}

func (a *LinuxNFTablesAdapter) ensureTableLocked(ctx context.Context) error {
	if !a.isAvailableLocked() {
		return fmt.Errorf("nft executable not found in PATH")
	}

	// Create table and chain if not exists:
	// nft add table inet open_netcut
	// nft add chain inet open_netcut forward '{ type filter hook forward priority -10; policy accept; }'
	// nft add chain inet open_netcut input '{ type filter hook input priority -10; policy accept; }'
	commands := []string{
		fmt.Sprintf("nft add table inet %s", a.tableName),
		fmt.Sprintf("nft 'add chain inet %s forward { type filter hook forward priority -10; policy accept; }'", a.tableName),
		fmt.Sprintf("nft 'add chain inet %s input { type filter hook input priority -10; policy accept; }'", a.tableName),
	}

	for _, cmdStr := range commands {
		cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
		_ = cmd.Run() // ignore if already exists
	}

	return nil
}

func (a *LinuxNFTablesAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}

	if !a.isAvailableLocked() {
		return fmt.Errorf("nft command not available on this host")
	}

	_ = a.ensureTableLocked(ctx)

	// Add drop rules for target IP and MAC in both forward and input chains.
	// Rule specs are stored per-enforcement so removal deletes only these rules.
	ruleSpecs := quarantineSpecs(a.tableName, e)
	if len(ruleSpecs) == 0 {
		return fmt.Errorf("no target IP or MAC specified for quarantine")
	}

	for _, spec := range ruleSpecs {
		// Dedupe: an identical rule from an earlier enforcement (or a
		// previous run) must not pile up — duplicates survive single
		// `nft delete rule` calls and keep blocking after release.
		if a.ruleExistsLocked(ctx, spec) {
			continue
		}
		cmd := exec.CommandContext(ctx, "sh", "-c", "nft add rule "+spec)
		output, err := cmd.CombinedOutput()
		if err != nil {
			e.ActualState = models.StateFailed
			e.ErrorMessage = fmt.Sprintf("nft error: %s (%v)", strings.TrimSpace(string(output)), err)
			return fmt.Errorf("%s", e.ErrorMessage)
		}
	}
	a.rules[e.ID] = ruleSpecs

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	return nil
}

func (a *LinuxNFTablesAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateRolledBack
		return nil
	}

	if !a.isAvailableLocked() {
		return fmt.Errorf("nft command not available on this host")
	}

	// Surgical removal: delete only rules added for this enforcement.
	// Never flush the whole chain (would drop other devices' quarantines).
	// Two passes: spec-delete first (works on older nft), then an
	// unconditional handle-delete sweep. The sweep is required, not a
	// fallback: current nft rejects spec-delete for ether matches
	// ("syntax error, unexpected ether, expecting handle"), so MAC rules
	// would otherwise survive every release.
	if specs, ok := a.rules[e.ID]; ok && len(specs) > 0 {
		for _, spec := range specs {
			a.deleteRuleAllLocked(ctx, spec)
		}
		delete(a.rules, e.ID)
	} else {
		// Fallback for enforcements created before restart: delete by matching IP/MAC.
		for _, spec := range quarantineSpecs(a.tableName, e) {
			a.deleteRuleAllLocked(ctx, spec)
		}
	}
	a.deleteRuleHandlesLocked(ctx, e)

	// Verify: no rule may still reference this target. A leftover drop is
	// exactly the "release doesn't work until reconnect" symptom.
	if remnant := a.remnantRuleLocked(ctx, e); remnant != "" {
		e.ErrorMessage = fmt.Sprintf("stale nft rule survived removal: %s", remnant)
		return fmt.Errorf("%s (re-run removal or delete the rule manually)", e.ErrorMessage)
	}

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}

// quarantineSpecs builds the drop-rule specs for an enforcement.
// IPv6 targets get ip6 matches so dual-stack victims can't bypass over v6.
func quarantineSpecs(table string, e *models.Enforcement) []string {
	var specs []string
	family := "ip"
	if ip := net.ParseIP(e.TargetIP); ip != nil && ip.To4() == nil {
		family = "ip6"
	}
	if e.TargetIP != "" {
		specs = append(specs,
			fmt.Sprintf("inet %s forward %s saddr %s drop", table, family, e.TargetIP),
			fmt.Sprintf("inet %s forward %s daddr %s drop", table, family, e.TargetIP),
			fmt.Sprintf("inet %s input %s saddr %s drop", table, family, e.TargetIP),
		)
	}
	if e.TargetMAC != "" {
		specs = append(specs,
			fmt.Sprintf("inet %s forward ether saddr %s drop", table, e.TargetMAC),
			fmt.Sprintf("inet %s input ether saddr %s drop", table, e.TargetMAC),
		)
	}
	return specs
}

// specChain splits "inet <table> <chain> <match...>" into chain + match text.
func specChain(spec string) (chain, match string) {
	fields := strings.Fields(spec)
	if len(fields) < 4 || fields[0] != "inet" {
		return "", ""
	}
	return fields[2], strings.Join(fields[3:], " ")
}

// ruleExistsLocked reports whether an identical rule is already installed.
func (a *LinuxNFTablesAdapter) ruleExistsLocked(ctx context.Context, spec string) bool {
	chain, match := specChain(spec)
	if chain == "" {
		return false
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("nft list chain inet %s %s", a.tableName, chain)).CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if normalizeRuleLine(line) == match {
			return true
		}
	}
	return false
}

// deleteRuleAllLocked deletes every instance of a spec (bounded loop).
func (a *LinuxNFTablesAdapter) deleteRuleAllLocked(ctx context.Context, spec string) {
	for i := 0; i < 32; i++ {
		cmd := exec.CommandContext(ctx, "sh", "-c", "nft delete rule "+spec)
		if err := cmd.Run(); err != nil {
			return // no more instances (or chain gone)
		}
		if !a.ruleExistsLocked(ctx, spec) {
			return
		}
	}
}

// deleteRuleHandlesLocked deletes leftover drop rules referencing the target
// by kernel handle. Handles are exact: this catches anything spec-delete
// missed. Scoped to drop rules mentioning the target IP/MAC only —
// accounting (accept) rules are never touched.
func (a *LinuxNFTablesAdapter) deleteRuleHandlesLocked(ctx context.Context, e *models.Enforcement) {
	for _, chain := range []string{"forward", "input"} {
		for _, h := range a.matchingHandlesLocked(ctx, chain, e) {
			cmd := exec.CommandContext(ctx, "sh", "-c",
				fmt.Sprintf("nft delete rule inet %s %s handle %s", a.tableName, chain, h))
			_ = cmd.Run()
		}
	}
}

// matchingHandlesLocked returns kernel handles of drop rules referencing the target.
func (a *LinuxNFTablesAdapter) matchingHandlesLocked(ctx context.Context, chain string, e *models.Enforcement) []string {
	out, err := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("nft --handle list chain inet %s %s", a.tableName, chain)).CombinedOutput()
	if err != nil {
		return nil
	}
	var handles []string
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "table ") || strings.HasPrefix(t, "chain ") || t == "}" {
			continue
		}
		if !strings.Contains(t, "drop") {
			continue
		}
		matched := false
		if e.TargetIP != "" && strings.Contains(t, e.TargetIP) {
			matched = true
		}
		if e.TargetMAC != "" && strings.Contains(strings.ToLower(t), strings.ToLower(e.TargetMAC)) {
			matched = true
		}
		if !matched {
			continue
		}
		if i := strings.LastIndex(t, "# handle"); i >= 0 {
			if h := strings.TrimSpace(t[i+len("# handle"):]); h != "" {
				handles = append(handles, h)
			}
		}
	}
	return handles
}

// remnantRuleLocked returns a leftover rule line referencing the target, if any.
func (a *LinuxNFTablesAdapter) remnantRuleLocked(ctx context.Context, e *models.Enforcement) string {
	for _, chain := range []string{"forward", "input"} {
		out, err := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("nft list chain inet %s %s", a.tableName, chain)).CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "table ") || strings.HasPrefix(t, "chain ") || t == "}" {
				continue
			}
			if e.TargetIP != "" && strings.Contains(t, e.TargetIP) {
				return chain + ": " + t
			}
			if e.TargetMAC != "" && strings.Contains(strings.ToLower(t), strings.ToLower(e.TargetMAC)) {
				return chain + ": " + t
			}
		}
	}
	return ""
}

// normalizeRuleLine canonicalizes `nft list chain` output for comparison with
// a spec match part (collapses whitespace; nft prints no trailing semicolon).
func normalizeRuleLine(line string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(line)), " ")
}

// FlushQuarantineChains removes all rules from our quarantine chains
// (forward + input). Used at startup: live enforcements die with the process
// but kernel drops would otherwise block devices forever with no record.
// Accounting chains (different names) are never touched.
func (a *LinuxNFTablesAdapter) FlushQuarantineChains(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.isAvailableLocked() {
		return fmt.Errorf("nft command not available on this host")
	}
	_ = a.ensureTableLocked(ctx)
	for _, chain := range []string{"forward", "input"} {
		cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("nft flush chain inet %s %s", a.tableName, chain))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("flush %s: %s: %w", chain, strings.TrimSpace(string(out)), err)
		}
	}
	a.rules = make(map[string][]string)
	return nil
}

func (a *LinuxNFTablesAdapter) ApplyRateLimit(ctx context.Context, e *models.Enforcement) error {
	// Rate limiting should be paired with tc for real shaping; nftables can police burst/rate limit
	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}
	return fmt.Errorf("bandwidth rate limiting requires LinuxTCAdapter")
}

func (a *LinuxNFTablesAdapter) RemoveRateLimit(ctx context.Context, e *models.Enforcement) error {
	return nil
}
