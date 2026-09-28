package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Per-IP accounting without conntrack.
//
// On a Linux gateway WITHOUT the nf_conntrack module there is no kernel
// source for per-IP byte counters — /proc/net/dev only has interface totals.
// This poller creates its own source: an `accounting` nftables chain with one
// counter+accept rule per known device IP (both directions). Accept verdicts
// keep traffic flowing; quarantine chains (priority -10) still drop first.
//
// Needs: nft binary + root/CAP_NET_ADMIN. Degrades silently otherwise
// (conntrack or interface totals still work).
const (
	SourceNftAccounting = "nft-accounting"

	nftTable      = "open_netcut"
	nftAcctChainF = "accounting_fwd" // hook forward (routed LAN traffic)
	nftAcctChainI = "accounting_in"  // hook input  (traffic to the gateway itself)

	acctCommentPrefix = "netcut-acct-"
	acctStaleAfter    = 30 * time.Minute // keep rules for departed IPs this long
	nftTimeout        = 5 * time.Second
)

// NftAccountingPoller maintains per-IP nft counter rules and records deltas.
type NftAccountingPoller struct {
	mu       sync.Mutex
	te       *TelemetryEngine
	knownIPs func() []string // callback into the device inventory
	interval time.Duration

	installed map[string]time.Time // ip -> last seen in inventory
	lastRx    map[string]uint64    // ip -> cumulative download bytes (daddr)
	lastTx    map[string]uint64    // ip -> cumulative upload bytes (saddr)
	chainsOK  bool
	noPriv    bool
	noPrivAt  time.Time
	stopCh    chan struct{}
}

// NewNftAccountingPoller creates the poller; interval floors at 2s.
// knownIPs may be nil (then existing counters are still polled, no sync).
func NewNftAccountingPoller(te *TelemetryEngine, knownIPs func() []string, interval time.Duration) *NftAccountingPoller {
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	return &NftAccountingPoller{
		te:        te,
		knownIPs:  knownIPs,
		interval:  interval,
		installed: make(map[string]time.Time),
		lastRx:    make(map[string]uint64),
		lastTx:    make(map[string]uint64),
		stopCh:    make(chan struct{}),
	}
}

// Start begins periodic sync+poll until ctx done or Stop called.
func (p *NftAccountingPoller) Start(ctx context.Context) {
	p.PollOnce(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.PollOnce(ctx)
		}
	}
}

// Stop terminates polling.
func (p *NftAccountingPoller) Stop() {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
}

// PollOnce syncs accounting rules for known IPs, then records byte deltas.
func (p *NftAccountingPoller) PollOnce(ctx context.Context) {
	if _, err := exec.LookPath("nft"); err != nil {
		return // nft binary missing — leave source untouched
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Back off after permission failures (non-root): retry every 60s, quiet.
	if p.noPriv && time.Since(p.noPrivAt) < 60*time.Second {
		return
	}

	if !p.chainsOK {
		if err := p.ensureChainsLocked(ctx); err != nil {
			p.noteNoPriv(err)
			return
		}
		p.chainsOK = true
		p.loadInstalledLocked(ctx) // adopt rules from a previous run (no dupes)
	}
	p.noPriv = false

	if p.knownIPs != nil {
		p.syncRulesLocked(ctx)
	}
	rx, tx := p.dumpCountersLocked(ctx)
	if len(rx)+len(tx) == 0 {
		return // nothing countable yet — don't clobber a conntrack source
	}
	now := time.Now().UTC()
	recorded := false
	for ip, total := range tx {
		if d := deltaUpdate(p.lastTx, ip, total); d > 0 {
			p.te.RecordFlow(FlowRecord{Timestamp: now, SourceIP: ip, DestIP: "__gateway__", Protocol: "nft-accounting", Bytes: d, Packets: 1})
			recorded = true
		}
	}
	for ip, total := range rx {
		if d := deltaUpdate(p.lastRx, ip, total); d > 0 {
			p.te.RecordFlow(FlowRecord{Timestamp: now, SourceIP: "__gateway__", DestIP: ip, Protocol: "nft-accounting", Bytes: d, Packets: 1})
			recorded = true
		}
	}
	if recorded {
		p.te.SetTrafficSource(SourceNftAccounting)
	}
	pollInterfaceTotals(p.te)
}

// deltaUpdate returns bytes since last sample (0 on first sight or reset)
// and stores the new cumulative value.
func deltaUpdate(last map[string]uint64, ip string, total uint64) uint64 {
	prev, seen := last[ip]
	last[ip] = total
	if !seen || total < prev {
		return 0 // first sight or counter reset — rebase, no spike
	}
	return total - prev
}

func (p *NftAccountingPoller) noteNoPriv(err error) {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission") || strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "could not") {
		if !p.noPriv {
			p.noPriv = true
			p.noPrivAt = time.Now()
		}
	}
}

func nftRun(ctx context.Context, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "nft", args...)
	return cmd.CombinedOutput()
}

func (p *NftAccountingPoller) ensureChainsLocked(ctx context.Context) error {
	cmds := [][]string{
		{"add", "table", "inet", nftTable},
		{"add", "chain", "inet", nftTable, nftAcctChainF, "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"},
		{"add", "chain", "inet", nftTable, nftAcctChainI, "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"},
	}
	for _, args := range cmds {
		if out, err := nftRun(ctx, args...); err != nil {
			// "File exists" is fine (idempotent); anything else may be fatal.
			if !strings.Contains(strings.ToLower(string(out)), "file exists") &&
				!strings.Contains(strings.ToLower(string(out)), "already exists") {
				// Table-create failing usually means no privilege; chain-create
				// failing after table exists is also fatal for us.
				return fmt.Errorf("nft %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
			}
		}
	}
	return nil
}

// loadInstalledLocked adopts already-present accounting rules (restart safety).
func (p *NftAccountingPoller) loadInstalledLocked(ctx context.Context) {
	for _, chain := range []string{nftAcctChainF, nftAcctChainI} {
		rx, tx := parseNftJSON(dumpChainJSON(ctx, chain))
		for ip := range rx {
			if _, ok := p.installed[ip]; !ok {
				p.installed[ip] = time.Now()
			}
		}
		for ip := range tx {
			if _, ok := p.installed[ip]; !ok {
				p.installed[ip] = time.Now()
			}
		}
	}
}

// syncRulesLocked adds counter rules for new IPs and removes long-departed ones.
func (p *NftAccountingPoller) syncRulesLocked(ctx context.Context) {
	now := time.Now()
	current := make(map[string]bool)
	for _, ip := range p.knownIPs() {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		current[ip] = true
		if _, ok := p.installed[ip]; ok {
			p.installed[ip] = now
			continue
		}
		if p.addIPRules(ctx, ip) {
			p.installed[ip] = now
		}
	}
	for ip, lastSeen := range p.installed {
		if !current[ip] && now.Sub(lastSeen) > acctStaleAfter {
			p.delIPRules(ctx, ip)
			delete(p.installed, ip)
			delete(p.lastRx, ip)
			delete(p.lastTx, ip)
		}
	}
}

// addIPRules installs saddr+daddr counter rules in both chains. True on success.
func (p *NftAccountingPoller) addIPRules(ctx context.Context, ip string) bool {
	ok := true
	for _, chain := range []string{nftAcctChainF, nftAcctChainI} {
		for _, dir := range []string{"saddr", "daddr"} {
			comment := fmt.Sprintf("%s%s-%s", acctCommentPrefix, dir, ip)
			args := []string{"add", "rule", "inet", nftTable, chain, "ip", dir, ip, "counter", "accept", "comment", `"` + comment + `"`}
			if out, err := nftRun(ctx, args...); err != nil {
				if !strings.Contains(strings.ToLower(string(out)), "file exists") {
					p.noteNoPriv(fmt.Errorf("%s", string(out)))
					ok = false
				}
			}
		}
	}
	return ok
}

// delIPRules removes all accounting rules for an IP (best effort).
func (p *NftAccountingPoller) delIPRules(ctx context.Context, ip string) {
	for _, chain := range []string{nftAcctChainF, nftAcctChainI} {
		for _, dir := range []string{"saddr", "daddr"} {
			comment := fmt.Sprintf("%s%s-%s", acctCommentPrefix, dir, ip)
			// Delete by full spec; nft matches the rule to remove.
			args := []string{"delete", "rule", "inet", nftTable, chain, "ip", dir, ip, "counter", "accept", "comment", `"` + comment + `"`}
			_, _ = nftRun(ctx, args...)
		}
	}
}

// dumpCountersLocked returns cumulative rx (daddr) and tx (saddr) bytes per IP.
func (p *NftAccountingPoller) dumpCountersLocked(ctx context.Context) (rx, tx map[string]uint64) {
	rx, tx = make(map[string]uint64), make(map[string]uint64)
	for _, chain := range []string{nftAcctChainF, nftAcctChainI} {
		raw := dumpChainJSON(ctx, chain)
		crx, ctx_ := parseNftJSON(raw)
		if len(crx)+len(ctx_) > 0 {
			mergeBytes(rx, crx)
			mergeBytes(tx, ctx_)
			continue
		}
		// JSON unavailable (older nft?) — fall back to text format.
		crx, ctx_ = parseNftText(dumpChainText(ctx, chain))
		mergeBytes(rx, crx)
		mergeBytes(tx, ctx_)
	}
	return rx, tx
}

func mergeBytes(dst, src map[string]uint64) {
	for ip, b := range src {
		dst[ip] += b
	}
}

func dumpChainJSON(ctx context.Context, chain string) []byte {
	out, err := nftRun(ctx, "--json", "list", "chain", "inet", nftTable, chain)
	if err != nil {
		return nil
	}
	return out
}

func dumpChainText(ctx context.Context, chain string) string {
	out, err := nftRun(ctx, "list", "chain", "inet", nftTable, chain)
	if err != nil {
		return ""
	}
	return string(out)
}

// parseNftJSON extracts per-IP counter bytes from `nft --json list chain`.
// rx = daddr rules (download to device), tx = saddr rules (upload from device).
func parseNftJSON(raw []byte) (rx, tx map[string]uint64) {
	rx, tx = make(map[string]uint64), make(map[string]uint64)
	if len(raw) == 0 {
		return rx, tx
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return rx, tx
	}
	for _, entry := range doc.Nftables {
		rawRule, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string `json:"comment"`
			Expr    []struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				} `json:"counter"`
			} `json:"expr"`
		}
		if err := json.Unmarshal(rawRule, &rule); err != nil {
			continue
		}
		dir, ip := splitAcctComment(rule.Comment)
		if ip == "" {
			continue
		}
		var bytes uint64
		for _, e := range rule.Expr {
			if e.Counter != nil {
				bytes = e.Counter.Bytes
				break
			}
		}
		if bytes == 0 {
			continue
		}
		if dir == "saddr" {
			tx[ip] += bytes
		} else {
			rx[ip] += bytes
		}
	}
	return rx, tx
}

// splitAcctComment parses "netcut-acct-<saddr|daddr>-<ip>".
func splitAcctComment(comment string) (dir, ip string) {
	comment = strings.Trim(strings.TrimSpace(comment), `"`)
	if !strings.HasPrefix(comment, acctCommentPrefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(comment, acctCommentPrefix)
	if strings.HasPrefix(rest, "saddr-") {
		return "saddr", strings.TrimPrefix(rest, "saddr-")
	}
	if strings.HasPrefix(rest, "daddr-") {
		return "daddr", strings.TrimPrefix(rest, "daddr-")
	}
	return "", ""
}

// parseNftText extracts counters from `nft list chain` text output, e.g:
// ip saddr 192.168.1.10 counter packets 5 bytes 400 accept comment "netcut-acct-saddr-192.168.1.10"
func parseNftText(raw string) (rx, tx map[string]uint64) {
	rx, tx = make(map[string]uint64), make(map[string]uint64)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, acctCommentPrefix) || !strings.Contains(line, "counter") {
			continue
		}
		fields := strings.Fields(line)
		var dir string
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "saddr" || fields[i] == "daddr" {
				dir = fields[i]
				break
			}
		}
		var bytes uint64
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "bytes" {
				var v uint64
				if _, err := fmt.Sscanf(fields[i+1], "%d", &v); err == nil {
					bytes = v
				}
				break
			}
		}
		// IP comes from the comment (robust against match-format variations).
		start := strings.Index(line, acctCommentPrefix)
		_, ip := splitAcctComment(line[start:])
		if ip == "" || bytes == 0 {
			continue
		}
		if dir == "saddr" {
			tx[ip] += bytes
		} else {
			rx[ip] += bytes
		}
	}
	return rx, tx
}
