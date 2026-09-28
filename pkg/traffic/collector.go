package traffic

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CollectorSources reports which per-IP accounting source is active.
const (
	SourceConntrackFile = "nf_conntrack"
	SourceConntrackCmd  = "conntrack-cmd"
	SourceUnavailable   = "unavailable"
)

// ConntrackPoller attributes bytes to IPs by periodically sampling
// connection-tracking counters and recording DELTAS as flows.
// Without it RecordFlow is never called and TopTalkers stays all-zeros.
type ConntrackPoller struct {
	te       *TelemetryEngine
	interval time.Duration
	last     map[string]uint64 // ip -> cumulative bytes seen
	source   string
	stopCh   chan struct{}
}

// NewConntrackPoller creates a poller; interval floors at 2s.
func NewConntrackPoller(te *TelemetryEngine, interval time.Duration) *ConntrackPoller {
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	return &ConntrackPoller{te: te, interval: interval, last: make(map[string]uint64), stopCh: make(chan struct{})}
}

// Source returns the active accounting source (or "unavailable").
func (p *ConntrackPoller) Source() string {
	if p.source == "" {
		return SourceUnavailable
	}
	return p.source
}

// Start begins periodic polling until ctx done or Stop called.
func (p *ConntrackPoller) Start(ctx context.Context) {
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
func (p *ConntrackPoller) Stop() {
	select {
	case <-p.stopCh:
		// already closed
	default:
		close(p.stopCh)
	}
}

// PollOnce samples counters and records per-IP deltas.
func (p *ConntrackPoller) PollOnce(ctx context.Context) {
	cumulative, src, err := readConntrackBytes(ctx)
	if err != nil || len(cumulative) == 0 {
		if p.source == "" {
			p.source = SourceUnavailable
		}
		p.te.SetTrafficSource(p.source)
		// Still poll interface totals so the header shows real gateway throughput.
		pollInterfaceTotals(p.te)
		return
	}
	p.source = src
	p.te.SetTrafficSource(src)
	now := time.Now().UTC()
	for ip, total := range cumulative {
		prev, seen := p.last[ip]
		if !seen {
			p.last[ip] = total
			continue
		}
		if total < prev {
			// Counter reset (reboot/flush) — rebase without recording spike.
			p.last[ip] = total
			continue
		}
		if delta := total - prev; delta > 0 {
			p.te.RecordFlow(FlowRecord{
				Timestamp: now,
				SourceIP:  ip,
				DestIP:    "__gateway__",
				Protocol:  "conntrack",
				Bytes:     delta,
				Packets:   1,
			})
			// Attribute upload direction too: conntrack bytes are bidirectional
			// per entry; RecordFlow credits Tx to src and Rx to dst. To also
			// credit the LAN IP on the dst side, record a mirrored flow.
			p.te.RecordFlow(FlowRecord{
				Timestamp: now,
				SourceIP:  "__gateway__",
				DestIP:    ip,
				Protocol:  "conntrack",
				Bytes:     delta,
				Packets:   1,
			})
		}
		p.last[ip] = total
	}
	// Drop IPs that vanished (lease expired) to bound memory.
	if len(p.last) > 4096 {
		seen := make(map[string]bool, len(cumulative))
		for ip := range cumulative {
			seen[ip] = true
		}
		for ip := range p.last {
			if !seen[ip] {
				delete(p.last, ip)
			}
		}
	}
	pollInterfaceTotals(p.te)
}

// readConntrackBytes returns cumulative bytes per IP from conntrack sources.
// Tries kernel files first, then the `conntrack` CLI.
func readConntrackBytes(ctx context.Context) (map[string]uint64, string, error) {
	for _, path := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack", "/proc/net/stat/nf_conntrack"} {
		if _, err := os.Stat(path); err == nil {
			out, err := parseConntrackFile(path)
			if err == nil && len(out) > 0 {
				return out, SourceConntrackFile, nil
			}
		}
	}
	if _, err := exec.LookPath("conntrack"); err == nil {
		out, err := parseConntrackCmd(ctx)
		if err == nil && len(out) > 0 {
			return out, SourceConntrackCmd, nil
		}
		return nil, "", fmt.Errorf("conntrack cmd produced no entries")
	}
	return nil, "", fmt.Errorf("no conntrack source (need nf_conntrack module or conntrack-tools)")
}

func parseConntrackFile(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		ip, bytes := parseConntrackLine(line)
		if ip != "" && bytes > 0 {
			out[ip] += bytes
		}
	}
	return out, sc.Err()
}

func parseConntrackCmd(ctx context.Context) (map[string]uint64, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "conntrack", "-L", "-o", "extended")
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		ip, bytes := parseConntrackLine(line)
		if ip != "" && bytes > 0 {
			out[ip] += bytes
		}
	}
	return out, nil
}

// parseConntrackLine handles both formats:
// new: "ipv4 ... src=1.2.3.4 dst=5.6.7.8 ... bytes=1234 ..."
// old: "tcp 6 431982 ESTABLISHED src=1.2.3.4 dst=... [ASSURED] use=1" (no bytes -> 0)
func parseConntrackLine(line string) (string, uint64) {
	if !strings.Contains(line, "src=") {
		return "", 0
	}
	var srcIP string
	var bytes uint64
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "src=") {
			ip := strings.TrimPrefix(field, "src=")
			// Prefer the LAN-side (first/origin) address; skip gateway reflection later.
			if srcIP == "" && ip != "" && !strings.HasPrefix(ip, "127.") {
				srcIP = ip
			}
		}
		if strings.HasPrefix(field, "bytes=") {
			if v, err := strconv.ParseUint(strings.TrimPrefix(field, "bytes="), 10, 64); err == nil {
				bytes += v
			}
		}
	}
	return srcIP, bytes
}

// pollInterfaceTotals reads /proc/net/dev and stores gateway-wide rates.
func pollInterfaceTotals(te *TelemetryEngine) {
	rx, tx, err := readProcNetDev()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	prev := te.GetInterfaceTotals()
	tot := InterfaceTotals{RxBytes: rx, TxBytes: tx, LastUpdated: now}
	if !prev.LastUpdated.IsZero() {
		if dt := now.Sub(prev.LastUpdated).Seconds(); dt >= 0.5 {
			if rx >= prev.RxBytes {
				tot.RxRateBps = float64(rx-prev.RxBytes) * 8 / dt
			}
			if tx >= prev.TxBytes {
				tot.TxRateBps = float64(tx-prev.TxBytes) * 8 / dt
			}
			tot.lastRx = rx
			tot.lastTx = tx
			tot.lastSample = now
		} else {
			tot.RxRateBps = prev.RxRateBps
			tot.TxRateBps = prev.TxRateBps
		}
	} else {
		tot.lastRx = rx
		tot.lastTx = tx
		tot.lastSample = now
	}
	te.SetInterfaceTotals(tot)
}

// readProcNetDev sums Rx/Tx bytes across non-loopback interfaces.
func readProcNetDev() (uint64, uint64, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var rxTotal, txTotal uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue // header lines
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rxTotal += rx
		txTotal += tx
	}
	return rxTotal, txTotal, sc.Err()
}
